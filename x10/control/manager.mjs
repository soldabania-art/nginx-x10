// Local Linux controller for one explicitly managed native NGINX HTTP server.
// No daemon is started here and no administrative network endpoint is exposed.
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, realpath, rename, rm } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { promisify } from 'node:util';
import { captureTcpListeners, inspectTcpListeners } from './listeners.mjs';
import { inspectNativeGenerations } from './generations.mjs';

const execute = promisify(execFile);
const uid = process.getuid?.();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const now = () => new Date().toISOString();
const idPattern = /^[a-f0-9]{32}$/;
const safePath = value => typeof value === 'string' && /^\/[A-Za-z0-9_./+-]+$/.test(value);
const message = error => String(error?.message || error).slice(0, 4096);
function fail(code, text) { throw Object.assign(new Error(text), { code }); }

async function owned(file, directory = false, privateDirectory = false) {
  const s = await lstat(file);
  if (s.isSymbolicLink() || (directory ? !s.isDirectory() : !s.isFile()) || s.uid !== uid)
    fail('unsafe_path', `Expected an owned regular ${directory ? 'directory' : 'file'}: ${file}`);
  if (privateDirectory ? (s.mode & 0o077) !== 0 : (s.mode & 0o022) !== 0)
    fail('unsafe_permissions', `Unsafe group/other permissions: ${file}`);
  return s;
}

async function syncDirectory(directory) {
  const handle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function syncFile(file) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function durableEvent(operation) {
  try { return await operation(); }
  catch (error) {
    if (error.code === 'event_commit_incomplete') throw error;
    throw Object.assign(new Error(`Durable event or cleanup requires explicit recovery: ${message(error)}`),
      { code: 'event_commit_incomplete', cause: error });
  }
}

async function atomic(file, bytes, mode = 0o600) {
  const temporary = `${file}.tmp-${randomBytes(8).toString('hex')}`;
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { await handle.writeFile(bytes); await handle.sync(); }
  catch (error) { await rm(temporary, { force: true }); throw error; }
  finally { await handle.close(); }
  try { await rename(temporary, file); await syncDirectory(path.dirname(file)); }
  catch (error) { await rm(temporary, { force: true }); throw error; }
}

async function json(file) { await owned(file); return JSON.parse(await readFile(file, 'utf8')); }
async function save(file, value) { await atomic(file, encode(value)); }
async function exists(file) { try { await lstat(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }

function canonicalState(state) {
  state = path.resolve(state);
  if (!safePath(state) || path.basename(state) !== '.x10-control') fail('invalid_state', 'State must be a private prefix/.x10-control directory with a simple absolute path');
  return state;
}

async function lock(state, operation) {
  if (process.platform !== 'linux' || uid === undefined) fail('unsupported', 'This controller currently requires Linux and a numeric uid');
  state = canonicalState(state);
  if (await realpath(path.dirname(state)) !== path.dirname(state)) fail('unsafe_path', 'Prefix must remain canonical without symlink ancestors');
  await owned(path.dirname(state), true, true);
  await owned(state, true, true);
  const file = path.join(state, 'lock');
  let handle;
  try { handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') fail('locked', 'Controller is locked. A stale lock requires operator inspection; it is never removed automatically'); throw error; }
  try {
    await handle.writeFile(encode({ pid: process.pid, at: now() })); await handle.sync();
    return await operation(state);
  } finally { await handle.close(); await rm(file); await syncDirectory(state); }
}

function httpsInput(value) {
  const keys = ['port', 'certificate', 'certificateKey'];
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))
      || !Number.isInteger(value.port) || value.port < 1024 || value.port > 65535)
    fail('invalid_https', 'HTTPS requires exactly port 1024..65535, certificate and certificateKey');
  for (const file of [value.certificate, value.certificateKey]) {
    if (!safePath(file) || /[^A-Za-z0-9_./+-]/.test(file) || file.length > 4096 || path.normalize(file) !== file || file.endsWith('/'))
      fail('invalid_https', 'HTTPS certificate paths must be simple canonical absolute file paths');
  }
  if (value.certificate === value.certificateKey)
    fail('invalid_https', 'HTTPS certificate and private key must use distinct files');
  return { port: value.port, certificate: value.certificate, certificateKey: value.certificateKey };
}

async function verifyHttps(settings, input) {
  if (!Object.hasOwn(input, 'https')) return;
  const tls = httpsInput(input.https);
  if (tls.port === settings.port || tls.port === Number(new URL(input.healthURL).port))
    fail('invalid_https', 'HTTPS port must differ from the HTTP listener and health backend');
  // Paths are operator-owned versioned references, not secret copies or pinned
  // certificate identities. The trusted operator must retain old versions for
  // revert/restart and must not race replacement with native validation/reload.
  for (const [file, secret] of [[tls.certificate, false], [tls.certificateKey, true]]) {
    try {
      let directory = path.dirname(file), levels = 0;
      const parent = await owned(directory, true, true);
      if ((parent.mode & 0o7777) !== 0o700) fail('unsafe_https_file', 'HTTPS parent directory must have mode 0700');
      // A private leaf does not protect against another UID replacing a
      // writable ancestor. Root/operator-owned sticky temporary roots are OK.
      while (true) {
        if (++levels > 128) fail('unsafe_https_file', 'HTTPS path exceeds the ancestor inspection bound');
        const ancestor = await lstat(directory);
        if (!ancestor.isDirectory() || ![0, uid].includes(ancestor.uid)
            || ((ancestor.mode & 0o022) !== 0 && !(ancestor.mode & 0o1000)))
          fail('unsafe_https_file', 'HTTPS path has an unsafe ancestor');
        if (directory === '/') break;
        directory = path.dirname(directory);
      }
      const s = await lstat(file), mode = s.mode & 0o7777;
      if (await realpath(file) !== file || !s.isFile() || s.uid !== uid
          || s.size < 1 || s.size > 256 * 1024
          || !(secret ? [0o400, 0o600] : [0o400, 0o600, 0o644]).includes(mode))
        fail('unsafe_https_file', 'Unsafe HTTPS certificate or key file');
    } catch {
      fail('unsafe_https_file', 'HTTPS requires owned bounded regular files in private canonical directories and safe file modes');
    }
  }
}

function candidate(value) {
  if (!value || typeof value !== 'object' || Object.keys(value).some(k => !['serverBody', 'healthURL', 'healthExpectedStatus', 'healthExpectedBody', 'https'].includes(k)))
    fail('invalid_candidate', 'Candidate contains unsupported fields');
  if (typeof value.serverBody !== 'string' || Buffer.byteLength(value.serverBody) > 1024 * 1024)
    fail('invalid_candidate', 'serverBody must be a string of at most 1 MiB');
  let parsed;
  try { parsed = new URL(value.healthURL); } catch { fail('invalid_health_url', 'healthURL must be an explicit HTTP loopback URL'); }
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/[A-Za-z0-9/_.~%-]*$/.test(value.healthURL)
      || parsed.hostname !== '127.0.0.1' || parsed.port === '' || Number(parsed.port) > 65535
      || parsed.username || parsed.password || parsed.search || parsed.hash)
    fail('invalid_health_url', 'healthURL must be http://127.0.0.1:port/path without credentials, query or fragment');
  const explicitStatus = Object.hasOwn(value, 'healthExpectedStatus'), explicitBody = Object.hasOwn(value, 'healthExpectedBody');
  if (explicitStatus !== explicitBody)
    fail('invalid_candidate', 'Explicit readiness requires both healthExpectedStatus and healthExpectedBody');
  if (explicitStatus && (!Number.isInteger(value.healthExpectedStatus) || value.healthExpectedStatus < 200 || value.healthExpectedStatus > 299
      || typeof value.healthExpectedBody !== 'string' || Buffer.byteLength(value.healthExpectedBody) > 4096
      || Buffer.from(value.healthExpectedBody, 'utf8').toString('utf8') !== value.healthExpectedBody))
    fail('invalid_candidate', 'Explicit readiness requires status 200..299 and a well-formed UTF-8 body of at most 4096 bytes');
  // This is a containment check, not an NGINX parser. Native -t remains required.
  let quote = '', comment = false, escaped = false, depth = 0, token = '', start = true;
  function finish() {
    if (start && ['include', 'listen'].includes(token)) fail('invalid_candidate', `${token} is owned by the controller or outside this self-contained fragment boundary`);
    if (token) start = false;
    token = '';
  }
  for (const char of value.serverBody) {
    if (comment) { if (char === '\n') comment = false; continue; }
    if (escaped) { escaped = false; if (!quote) token += 'x'; continue; }
    if (char === '\\') { if (start) fail('invalid_candidate', 'Directive names must be unquoted and unescaped'); escaped = true; continue; }
    if (quote) { if (char === quote) quote = ''; continue; }
    if (char === '"' || char === "'") { if (start) fail('invalid_candidate', 'Directive names must be unquoted and unescaped'); quote = char; token += 'x'; continue; }
    if (char === '#') { finish(); comment = true; continue; }
    if (/\s/.test(char)) { finish(); continue; }
    if ('{};'.includes(char)) {
      finish();
      if (char === '{') depth++;
      if (char === '}' && --depth < 0) fail('invalid_candidate', 'serverBody escapes its enclosing server');
      start = true; continue;
    }
    token += char;
  }
  finish();
  if (quote || escaped || depth !== 0) fail('invalid_candidate', 'serverBody has unbalanced quotes or braces');
  // Preserve the exact shape and key order of legacy revision inputs: their
  // existing hashes must not gain absent/defaulted readiness properties.
  const input = { serverBody: value.serverBody, healthURL: value.healthURL };
  if (explicitStatus) { input.healthExpectedStatus = value.healthExpectedStatus; input.healthExpectedBody = value.healthExpectedBody; }
  if (Object.hasOwn(value, 'https')) input.https = httpsInput(value.https);
  return input;
}

function render(settings, revision) {
  return `# Managed by NGINX X10; revision ${revision.id}\nserver {\n`
    + `listen 127.0.0.1:${settings.port};\nserver_name localhost;\n`
    + (revision.input.https ? `listen 127.0.0.1:${revision.input.https.port} ssl;\nssl_protocols TLSv1.2 TLSv1.3;\nssl_certificate \"${revision.input.https.certificate}\";\nssl_certificate_key \"${revision.input.https.certificateKey}\";\n` : '')
    + `location = /__x10_revision { add_header X-X10-Revision "${revision.id}" always; return 200 "${revision.id}"; }\n`
    + `location = /__x10_health { proxy_pass "${revision.input.healthURL}"; proxy_method GET; proxy_pass_request_body off; proxy_pass_request_headers off; proxy_set_header Host $proxy_host; proxy_set_header Connection close; proxy_set_header Content-Length ""; proxy_cache off; proxy_store off; proxy_buffering off; proxy_ignore_client_abort off; proxy_connect_timeout 1s; proxy_send_timeout 1s; proxy_read_timeout 1s; proxy_next_upstream off; proxy_intercept_errors off; proxy_hide_header X-X10-Revision; add_header X-X10-Revision "${revision.id}" always; }\n`
    + `${revision.input.serverBody}\n}\n`;
}

async function makeRevision(settings, input, parent, sourceRevision = null) {
  const revision = { schemaVersion: 1, id: randomBytes(16).toString('hex'), createdAt: now(), parent, sourceRevision, input: candidate(input) };
  if (Number(new URL(revision.input.healthURL).port) === settings.port) fail('invalid_health_url', 'Health backend must use a different loopback port from the managed server');
  await verifyHttps(settings, revision.input);
  revision.inputSha256 = hash(JSON.stringify(revision.input));
  revision.fragmentSha256 = hash(render(settings, revision));
  revision.recordSha256 = hash(JSON.stringify(revision));
  const file = path.join(settings.state, 'revisions', `${revision.id}.json`);
  const handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o400);
  try { await handle.writeFile(encode(revision)); await handle.sync(); } finally { await handle.close(); }
  await syncDirectory(path.dirname(file));
  return revision;
}

async function readRevision(settings, id) {
  if (!idPattern.test(id)) fail('invalid_revision', 'Invalid revision identifier');
  const value = await json(path.join(settings.state, 'revisions', `${id}.json`));
  const { recordSha256, ...record } = value;
  if (recordSha256 !== hash(JSON.stringify(record)) || value.id !== id || value.inputSha256 !== hash(JSON.stringify(candidate(value.input))) || value.fragmentSha256 !== hash(render(settings, value)))
    fail('revision_integrity', `Revision ${id} failed its integrity checks`);
  return value;
}

function stateShape(value) {
  const keys = ['schemaVersion', 'activeRevision', 'previousRevision', 'binding', 'historyHead'];
  if (!value || value.schemaVersion !== 1 || Object.keys(value).some(k => !keys.includes(k))
      || keys.some(k => !Object.hasOwn(value, k)) || !idPattern.test(value.activeRevision)
      || (value.previousRevision !== null && !idPattern.test(value.previousRevision))
      || (value.historyHead !== null && !/^[a-f0-9]{64}$/.test(value.historyHead))
      || (value.binding !== null && (typeof value.binding !== 'object' || Array.isArray(value.binding))))
    fail('state_integrity', 'Unsupported or inconsistent controller state');
  return value;
}

function transactionShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 1 || !idPattern.test(value.previous) || !idPattern.test(value.candidate)
      || (value.rollbackRevision !== undefined && !idPattern.test(value.rollbackRevision))
      || !['prepared', 'installed', 'reload_requested', 'restoring', 'ambiguous'].includes(value.stage))
    fail('journal_integrity', 'Pending transaction is inconsistent');
  return value;
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const commitFile = settings => path.join(settings.state, 'event-commit.json');
async function clearCommit(settings) { await rm(commitFile(settings)); await syncDirectory(settings.state); }

async function load(state, allowCommit = false) {
  const settings = await json(path.join(state, 'settings.json'));
  if (settings.schemaVersion !== 1 || settings.state !== state || settings.prefix !== path.dirname(state)) fail('settings_integrity', 'Controller path identity changed');
  if (await readlink('/proc/self/ns/pid') !== settings.pidNamespace) fail('runtime_namespace', 'Controller must run in its initialized PID namespace');
  for (const p of [settings.config, settings.fragment, settings.pidFile]) {
    if (!safePath(p) || path.dirname(p) !== settings.prefix) fail('settings_integrity', 'Controlled paths must be direct children of the private prefix');
  }
  await owned(settings.prefix, true, true); await owned(path.join(state, 'revisions'), true, true);
  const current = stateShape(await json(path.join(state, 'state.json')));
  const hasCommit = await exists(commitFile(settings));
  const commit = hasCommit ? await json(commitFile(settings)) : null;
  if (hasCommit && (!commit || typeof commit !== 'object' || Array.isArray(commit))) fail('commit_integrity', 'Invalid event commit envelope');
  if (hasCommit && !allowCommit) fail('commit_pending', 'Interrupted event commit requires explicit recover');
  const history = await readHistory(settings, current, hasCommit && allowCommit);
  const pending = await exists(path.join(state, 'pending.json')) ? transactionShape(await json(path.join(state, 'pending.json'))) : null;
  return { settings, current, history, pending, commit };
}

function eventShape(row) {
  const keys = ['sequence', 'at', 'type', 'details', 'previousHash', 'hash'];
  return row && typeof row === 'object' && !Array.isArray(row) && Object.keys(row).length === keys.length
    && keys.every(k => Object.hasOwn(row, k)) && Number.isSafeInteger(row.sequence) && row.sequence > 0
    && typeof row.at === 'string' && typeof row.type === 'string' && row.details && typeof row.details === 'object'
    && !Array.isArray(row.details) && (row.previousHash === null || /^[a-f0-9]{64}$/.test(row.previousHash))
    && typeof row.hash === 'string' && /^[a-f0-9]{64}$/.test(row.hash);
}

async function readHistory(settings, current, allowHeadMismatch = false) {
  const file = path.join(settings.state, 'history.jsonl'); await owned(file);
  const s = await lstat(file); if (s.size > 16 * 1024 * 1024) fail('history_limit', 'History exceeds this controller version\'s 16 MiB limit');
  const bytes = await readFile(file, 'utf8');
  let records;
  try {
    if (bytes && !bytes.endsWith('\n')) throw new Error('Incomplete history line');
    records = bytes ? bytes.slice(0, -1).split('\n').map(line => {
      const record = JSON.parse(line);
      if (line !== JSON.stringify(record)) throw new Error('Noncanonical history line');
      return record;
    }) : [];
  } catch { fail('history_integrity', 'History contains a partial, malformed or noncanonical record'); }
  let previous = null;
  for (let i = 0; i < records.length; i++) {
    const row = records[i];
    if (!eventShape(row)) fail('history_integrity', 'History record shape is inconsistent');
    const { hash: digest, ...body } = row;
    if (body.sequence !== i + 1 || body.previousHash !== previous || hash(JSON.stringify(body)) !== digest) fail('history_integrity', 'History hash chain is inconsistent');
    previous = digest;
  }
  if (!allowHeadMismatch && current.historyHead !== previous) fail('history_integrity', 'State and history head disagree; operator inspection is required');
  return records;
}

async function appendEvent(settings, record) {
  const handle = await open(path.join(settings.state, 'history.jsonl'), constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  try { await handle.writeFile(`${JSON.stringify(record)}\n`); await handle.sync(); } finally { await handle.close(); }
}

async function event(settings, current, type, details) {
  if (await exists(commitFile(settings))) fail('commit_pending', 'Interrupted event commit requires explicit recover');
  const before = stateShape(await json(path.join(settings.state, 'state.json')));
  const history = await readHistory(settings, before);
  if (current.historyHead !== before.historyHead) fail('state_integrity', 'Event uses a stale state head');
  const body = { sequence: history.length + 1, at: now(), type, details, previousHash: before.historyHead };
  const record = { ...body, hash: hash(JSON.stringify(body)) };
  const after = { ...current, historyHead: record.hash };
  const intent = { schemaVersion: 1, before, after, record };
  intent.sha256 = hash(JSON.stringify(intent));
  if ((await lstat(path.join(settings.state, 'history.jsonl'))).size + Buffer.byteLength(JSON.stringify(record)) + 1 > 16 * 1024 * 1024)
    fail('history_limit', 'Next event would exceed the history limit');
  await durableEvent(async () => {
    await save(commitFile(settings), intent);
    await appendEvent(settings, record);
    await save(path.join(settings.state, 'state.json'), after);
    Object.assign(current, after);
    await clearCommit(settings);
  });
}

async function validateCommit(settings, intent, current, records, transaction) {
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) fail('commit_integrity', 'Invalid event commit envelope');
  const { sha256, ...envelope } = intent;
  if (intent.schemaVersion !== 1 || Object.keys(envelope).join(',') !== 'schemaVersion,before,after,record'
      || hash(JSON.stringify(envelope)) !== sha256) fail('commit_integrity', 'Event commit envelope is inconsistent');
  const before = stateShape(intent.before), after = stateShape(intent.after), record = intent.record;
  if (!eventShape(record)) fail('commit_integrity', 'Invalid event record shape');
  if (!same(current, before) && !same(current, after)) fail('commit_integrity', 'State matches neither recorded event boundary');
  const { hash: digest, ...body } = record;
  if (hash(JSON.stringify(body)) !== digest || record.previousHash !== before.historyHead || after.historyHead !== digest)
    fail('commit_integrity', 'Event commit hash linkage is inconsistent');
  const appended = records.at(-1)?.hash === digest;
  if (appended ? !same(records.at(-1), record) || record.sequence !== records.length
      : before.historyHead !== (records.at(-1)?.hash || null) || record.sequence !== records.length + 1)
    fail('commit_integrity', 'History does not match either exact event boundary');
  if (appended && (records.at(-2)?.hash || null) !== before.historyHead)
    fail('commit_integrity', 'Event commit has an unexpected history predecessor');
  if (!appended && same(current, after)) fail('commit_integrity', 'State advanced without its history record');
  const old = await readRevision(settings, before.activeRevision), active = await readRevision(settings, after.activeRevision);
  for (const id of [before.previousRevision, after.previousRevision, transaction?.rollbackRevision].filter(Boolean)) await readRevision(settings, id);
  if (transaction) {
    const previous = await readRevision(settings, transaction.previous), target = await readRevision(settings, transaction.candidate);
    if (target.parent !== previous.id) fail('commit_integrity', 'Pending candidate does not descend from its recorded previous revision');
  }
  const unchanged = same({ ...before, historyHead: null }, { ...after, historyHead: null });
  const bindingUnchanged = same(before.binding, after.binding);
  const d = record.details;
  let valid = false;
  if (record.type === 'initialized_unbound')
    valid = unchanged && before.binding === null && before.previousRevision === null && record.sequence === 1 && d.revision === active.id && !transaction;
  if (record.type === 'bound')
    valid = before.binding === null && after.binding !== null && before.activeRevision === after.activeRevision
      && before.previousRevision === after.previousRevision && d.revision === active.id && d.pid === after.binding.pid && !transaction;
  if (record.type === 'apply_started') {
    const target = transaction && await readRevision(settings, transaction.candidate);
    valid = unchanged && Boolean(before.binding) && transaction?.stage === 'prepared' && transaction.previous === old.id
      && d.previous === old.id && d.revision === target?.id && target.parent === old.id;
  }
  if (record.type === 'applied')
    valid = bindingUnchanged && Boolean(after.binding) && after.previousRevision === old.id && active.parent === old.id
      && d.previous === old.id && d.revision === active.id && transaction?.previous === old.id
      && transaction?.candidate === active.id && transaction.stage === 'reload_requested';
  if (record.type === 'rejected') {
    const target = transaction && await readRevision(settings, transaction.candidate);
    valid = unchanged && Boolean(after.binding) && transaction?.previous === old.id && d.revision === target?.id
      && target.parent === old.id && ['installed', 'reload_requested'].includes(transaction.stage) && typeof d.reason === 'string';
  }
  if (record.type === 'rolled_back')
    valid = bindingUnchanged && Boolean(after.binding) && after.previousRevision === old.id && active.parent === old.id
      && active.sourceRevision === old.id && active.inputSha256 === old.inputSha256 && d.revision === active.id
      && d.restoredContentFrom === old.id && d.failedRevision === transaction?.candidate && transaction?.previous === old.id
      && transaction?.rollbackRevision === active.id && transaction.stage === 'restoring' && typeof d.reason === 'string';
  if (!valid) fail('commit_integrity', 'Event transition does not match its state, revisions and pending transaction');
  await verifyConfirmed(settings, after, active);
  return { after, record, appended };
}

async function verifyConfirmed(settings, current, revision) {
  await guard(settings, current, [revision.fragmentSha256]);
  if (current.binding) {
    await acknowledged(settings, revision);
    await guard(settings, current, [revision.fragmentSha256]);
  } else await nativeTest(settings, revision);
}

async function reconcileCommit(context) {
  const { settings, current, history, pending: transaction, commit } = context;
  const checked = await validateCommit(settings, commit, current, history, transaction);
  return durableEvent(async () => {
    // Seeing a complete line does not prove that a previous fsync succeeded.
    if (!checked.appended) await appendEvent(settings, checked.record);
    else await syncFile(path.join(settings.state, 'history.jsonl'));
    if (!same(current, checked.after)) await save(path.join(settings.state, 'state.json'), checked.after);
    else {
      await syncFile(path.join(settings.state, 'state.json'));
      await syncDirectory(settings.state);
    }
    await clearCommit(settings);
    return checked.record;
  });
}

function terminalEvent(current, transaction, records) {
  const record = records.at(-1), d = record?.details;
  if (!transaction || record?.hash !== current.historyHead) return null;
  if (record.type === 'applied' && d.revision === current.activeRevision && d.previous === transaction.previous
      && transaction.candidate === current.activeRevision && current.previousRevision === transaction.previous
      && transaction.stage === 'reload_requested') return record;
  if (record.type === 'rejected' && d.revision === transaction.candidate && current.activeRevision === transaction.previous
      && ['installed', 'reload_requested'].includes(transaction.stage)) return record;
  if (record.type === 'rolled_back' && d.failedRevision === transaction.candidate && d.revision === current.activeRevision
      && d.restoredContentFrom === transaction.previous && current.previousRevision === transaction.previous
      && transaction.rollbackRevision === current.activeRevision && transaction.stage === 'restoring') return record;
  return null;
}

async function guard(settings, current, allowFragments) {
  await owned(settings.config); await owned(settings.fragment);
  if (hash(await readFile(settings.config)) !== settings.configSha256) fail('operator_config_changed', 'Operator nginx.conf changed after initialization');
  if (hash(await readFile(settings.binary)) !== settings.binarySha256) fail('binary_changed', 'Registered NGINX binary changed');
  const active = hash(await readFile(settings.fragment));
  if (!allowFragments.includes(active)) fail('fragment_changed', 'Managed fragment differs from the journal');
  if (current.binding) await runtime(settings, current.binding);
}

async function nativeTest(settings, revision) {
  try {
    await verifyHttps(settings, revision.input);
    await execute(settings.binary, ['-p', `${settings.prefix}/`, '-c', settings.config, '-t'], { timeout: 5000, maxBuffer: 256 * 1024 });
    await verifyHttps(settings, revision.input);
  }
  catch (error) { fail('native_config_rejected', message(error.stderr || error)); }
}

async function runtime(settings, binding = null) {
  await owned(settings.pidFile);
  const text = await readFile(settings.pidFile, 'utf8');
  if (!/^[1-9][0-9]*\n?$/.test(text)) fail('runtime_identity', 'Invalid native pid file');
  const pid = Number(text.trim());
  if (!Number.isSafeInteger(pid) || pid < 2 || pid === process.pid) fail('runtime_identity', 'Unsafe native pid');
  const pidNamespace = await readlink('/proc/self/ns/pid');
  if (pidNamespace !== settings.pidNamespace) fail('runtime_namespace', 'Controller PID namespace changed');
  // Work-mode /proc can be mounted from an ancestor PID namespace. Resolve the
  // pid-file's local PID by both NSpid and the PID namespace inode, never by
  // assuming /proc/<local-pid> names the same process.
  const entries = (await readdir('/proc')).filter(name => /^[1-9][0-9]*$/.test(name));
  if (entries.length > 10000) fail('runtime_identity', 'Too many /proc entries for bounded identity resolution');
  const matches = [];
  for (let start = 0; start < entries.length; start += 32) {
    const values = await Promise.all(entries.slice(start, start + 32).map(async name => {
      try {
        const text = await readFile(`/proc/${name}/status`, 'utf8');
        const nspid = /^NSpid:\s+([0-9\s]+)$/m.exec(text)?.[1].trim().split(/\s+/).map(Number);
        if (!nspid || nspid.at(-1) !== pid || Number(/^Uid:\s+(\d+)/m.exec(text)?.[1]) !== uid) return null;
        if (await readlink(`/proc/${name}/ns/pid`) !== pidNamespace) return null;
        return { procPid: Number(name), status: text };
      } catch { return null; }
    }));
    matches.push(...values.filter(Boolean));
  }
  if (matches.length !== 1) fail('runtime_identity', 'Native PID could not be uniquely resolved in this PID namespace');
  const procPid = matches[0].procPid;
  let status = matches[0].status, stat, cmdline, executable;
  try {
    [stat, cmdline, executable] = await Promise.all([
      readFile(`/proc/${procPid}/stat`, 'utf8'),
      readFile(`/proc/${procPid}/cmdline`, 'utf8'), readlink(`/proc/${procPid}/exe`),
    ]);
  } catch { fail('runtime_identity', 'Native process disappeared or /proc is inaccessible'); }
  const processUid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]);
  const fields = stat.slice(stat.lastIndexOf(') ') + 2).split(' ');
  const title = cmdline.split('\0')[0];
  const tokens = title.replace(/^nginx: master process /, '').trim().split(/\s+/);
  const pair = (flag, expected) => tokens.filter(v => v === flag).length === 1 && tokens[tokens.indexOf(flag) + 1]?.replace(/\/$/, '') === expected.replace(/\/$/, '');
  if (processUid !== uid || executable !== settings.binary || fields[0] === 'Z'
      || !title.startsWith('nginx: master process ') || tokens[0] !== settings.binary
      || !pair('-p', settings.prefix) || !pair('-c', settings.config))
    fail('runtime_identity', 'PID is not the expected owned NGINX master with explicit -p and -c arguments');
  const observed = { pid, procPid, pidNamespace, startTicks: fields[19], uid: processUid, executable, commandSha256: hash(title) };
  if (binding && JSON.stringify(observed) !== JSON.stringify(binding)) fail('runtime_identity', 'Native master identity changed; refusing to signal');
  return observed;
}

async function signal(settings, current) {
  // Node has no pidfd_send_signal. A residual PID-reuse race remains between these syscalls.
  const identity = await runtime(settings, current.binding);
  process.kill(identity.pid, 'SIGHUP');
}

function request(settings, target, bodyLimitBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: settings.port, path: target, agent: false, headers: { connection: 'close' } }, res => {
      let bytes = 0; const chunks = [];
      res.on('data', chunk => { bytes += chunk.length; if (bytes > bodyLimitBytes) req.destroy(new Error('Probe response exceeded allowed byte limit')); else chunks.push(chunk); });
      res.once('error', reject);
      res.once('end', () => { const bodyBytes = Buffer.concat(chunks); resolve({ status: res.statusCode, revision: res.headers['x-x10-revision'], body: bodyBytes.toString('utf8'), bodyBytes }); });
    });
    const timer = setTimeout(() => req.destroy(new Error('Probe absolute deadline exceeded')), 350);
    req.once('close', () => clearTimeout(timer));
    req.setTimeout(350, () => req.destroy(new Error('Probe idle deadline exceeded')));
    req.once('error', reject);
  });
}

async function acknowledged(settings, revision) {
  await verifyHttps(settings, revision.input);
  const deadline = Date.now() + settings.gateTimeoutMs;
  const explicit = Object.hasOwn(revision.input, 'healthExpectedStatus');
  const expectedStatus = explicit ? revision.input.healthExpectedStatus : 200;
  const expectedBody = explicit ? Buffer.from(revision.input.healthExpectedBody, 'utf8') : null;
  let consecutive = 0, last = 'no response';
  while (Date.now() < deadline) {
    try {
      const probe = await request(settings, '/__x10_revision');
      const health = await request(settings, '/__x10_health', explicit ? 4096 : 64 * 1024);
      if (probe.status === 200 && probe.body === revision.id && probe.revision === revision.id && health.status === expectedStatus
          && health.revision === revision.id && (!explicit || health.bodyBytes.equals(expectedBody))) {
        if (++consecutive === 2) { await verifyHttps(settings, revision.input); return; }
      } else { consecutive = 0; last = `revision=${probe.revision}, health=${health.status}/${health.revision}`; }
    } catch (error) { consecutive = 0; last = message(error); }
    await delay(40);
  }
  fail('health_gate_failed', `No fresh acknowledged healthy revision ${revision.id}: ${last}`);
}

async function pending(settings, value) { await save(path.join(settings.state, 'pending.json'), value); }
async function clearPending(settings) {
  return durableEvent(async () => {
    await rm(path.join(settings.state, 'pending.json'));
    await syncDirectory(settings.state);
  });
}

export async function initialize(spec, input) {
  if (process.platform !== 'linux' || uid === undefined) fail('unsupported', 'Linux is required');
  const prefix = path.resolve(spec.prefix || '');
  if (!safePath(prefix) || await realpath(prefix) !== prefix) fail('unsafe_prefix', 'Prefix must be a simple canonical absolute path');
  await owned(prefix, true, true);
  const state = canonicalState(path.join(prefix, '.x10-control'));
  const settings = { schemaVersion: 1, prefix, state, config: path.resolve(prefix, spec.config || 'nginx.conf'), fragment: path.resolve(prefix, spec.fragment || 'managed.conf'), pidFile: path.resolve(prefix, spec.pidFile || 'nginx.pid'), binary: await realpath(spec.binary), port: Number(spec.port), gateTimeoutMs: Number(spec.gateTimeoutMs ?? 3000), pidNamespace: await readlink('/proc/self/ns/pid') };
  for (const file of [settings.config, settings.fragment, settings.pidFile]) if (!safePath(file) || path.dirname(file) !== prefix || file === state) fail('invalid_path', 'Config, fragment and pidFile must be distinct direct children of prefix, outside state');
  if (new Set([settings.config, settings.fragment, settings.pidFile]).size !== 3 || !Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535 || !Number.isInteger(settings.gateTimeoutMs) || settings.gateTimeoutMs < 500 || settings.gateTimeoutMs > 30000)
    fail('invalid_settings', 'Distinct paths, a valid port and gateTimeoutMs 500..30000 are required');
  await owned(settings.config);
  const executable = await lstat(settings.binary);
  if (!safePath(settings.binary) || !executable.isFile() || !(executable.mode & 0o111)) fail('invalid_binary', 'Binary must be a canonical executable regular file with a simple path');
  const config = await readFile(settings.config, 'utf8');
  const exact = `include ${settings.fragment};`;
  if (config.split('\n').filter(line => line.trim() === exact).length !== 1) fail('include_boundary', `nginx.conf must contain exactly one separate line: ${exact}`);
  if (await exists(settings.fragment) || await exists(settings.pidFile)) fail('already_exists', 'Initialize before starting NGINX; managed fragment and pid file must not exist');
  candidate(input);
  settings.configSha256 = hash(config); settings.binarySha256 = hash(await readFile(settings.binary));
  await mkdir(state, { mode: 0o700 });
  try {
    await mkdir(path.join(state, 'revisions'), { mode: 0o700 });
    await atomic(path.join(state, 'history.jsonl'), '');
    await save(path.join(state, 'settings.json'), settings);
    const revision = await makeRevision(settings, input, null);
    await atomic(settings.fragment, render(settings, revision));
    await nativeTest(settings, revision);
    const current = { schemaVersion: 1, activeRevision: revision.id, previousRevision: null, binding: null, historyHead: null };
    await save(path.join(state, 'state.json'), current);
    await event(settings, current, 'initialized_unbound', { revision: revision.id });
    return { ok: true, outcome: 'initialized_unbound', state, revision: revision.id };
  } catch (error) {
    // No daemon was running at initialization and the fragment did not preexist.
    await rm(settings.fragment, { force: true }); await rm(state, { recursive: true, force: true }); throw error;
  }
}

export async function bind(state) {
  return lock(state, async state => {
    const { settings, current, pending: unresolved } = await load(state);
    if (unresolved) fail('pending', 'Unresolved transaction requires recover');
    if (current.binding) fail('already_bound', 'Controller is already bound to a master');
    const revision = await readRevision(settings, current.activeRevision);
    await guard(settings, current, [revision.fragmentSha256]);
    const identity = await runtime(settings);
    await acknowledged(settings, revision);
    await runtime(settings, identity);
    await guard(settings, current, [revision.fragmentSha256]);
    current.binding = identity;
    await event(settings, current, 'bound', { pid: identity.pid, revision: revision.id });
    return { ok: true, outcome: 'bound', revision: revision.id, pid: identity.pid };
  });
}

async function rollback(settings, current, transaction, reason) {
  const old = await readRevision(settings, current.activeRevision);
  const allowed = await Promise.all([old.id, transaction.previous, transaction.candidate, transaction.rollbackRevision].filter(Boolean).map(id => readRevision(settings, id)));
  await guard(settings, current, allowed.map(r => r.fragmentSha256));
  const restored = await makeRevision(settings, old.input, old.id, old.id);
  transaction.stage = 'restoring'; transaction.rollbackRevision = restored.id; transaction.reason = reason;
  await pending(settings, transaction);
  await atomic(settings.fragment, render(settings, restored));
  await nativeTest(settings, restored);
  await guard(settings, current, [restored.fragmentSha256]);
  await verifyHttps(settings, restored.input);
  await signal(settings, current); await acknowledged(settings, restored);
  await guard(settings, current, [restored.fragmentSha256]);
  current.previousRevision = old.id; current.activeRevision = restored.id;
  await event(settings, current, 'rolled_back', { failedRevision: transaction.candidate, restoredContentFrom: old.id, revision: restored.id, reason });
  await clearPending(settings);
  return { ok: false, outcome: 'rolled_back', revision: restored.id, failedRevision: transaction.candidate, restoredContentFrom: old.id, reason };
}

async function activate(state, getInput) {
  return lock(state, async state => {
    const { settings, current, pending: unresolved } = await load(state);
    if (unresolved) fail('pending', 'Unresolved transaction requires recover before another apply');
    if (!current.binding) fail('unbound', 'Bind an already running, healthy master before applying');
    const old = await readRevision(settings, current.activeRevision);
    await guard(settings, current, [old.fragmentSha256]);
    const requested = await getInput(settings);
    const revision = await makeRevision(settings, requested.input, old.id, requested.sourceRevision);
    const transaction = { schemaVersion: 1, startedAt: now(), previous: old.id, candidate: revision.id, stage: 'prepared' };
    await pending(settings, transaction);
    await event(settings, current, 'apply_started', { revision: revision.id, previous: old.id });
    let signalled = false;
    try {
      await atomic(settings.fragment, render(settings, revision));
      transaction.stage = 'installed'; await pending(settings, transaction);
      await nativeTest(settings, revision);
      await guard(settings, current, [revision.fragmentSha256]);
      transaction.stage = 'reload_requested'; await pending(settings, transaction);
      await verifyHttps(settings, revision.input);
      await signal(settings, current); signalled = true;
      await acknowledged(settings, revision);
      await guard(settings, current, [revision.fragmentSha256]);
      current.previousRevision = old.id; current.activeRevision = revision.id;
      await event(settings, current, 'applied', { revision: revision.id, previous: old.id });
      await clearPending(settings);
      return { ok: true, outcome: 'applied', revision: revision.id, previous: old.id };
    } catch (error) {
      if (error.code === 'event_commit_incomplete') throw error;
      // If state/history may already have committed, leave pending for explicit recovery.
      if (current.activeRevision !== old.id) throw error;
      try {
        if (!signalled && error.code === 'native_config_rejected') {
          await guard(settings, current, [revision.fragmentSha256]);
          await atomic(settings.fragment, render(settings, old));
          await event(settings, current, 'rejected', { revision: revision.id, reason: message(error) });
          await clearPending(settings);
          return { ok: false, outcome: 'rejected', revision: old.id, rejectedRevision: revision.id, reason: message(error) };
        }
        return await rollback(settings, current, transaction, message(error));
      } catch (restoreError) {
        if (restoreError.code === 'event_commit_incomplete') throw restoreError;
        transaction.stage = 'ambiguous'; transaction.reason = message(restoreError);
        await pending(settings, transaction).catch(() => {});
        fail('ambiguous', `Transaction requires explicit recovery/inspection: ${message(restoreError)}`);
      }
    }
  });
}

export async function apply(state, input) { return activate(state, async () => ({ input: candidate(input), sourceRevision: null })); }
export async function revert(state, revision) {
  return activate(state, async settings => ({ input: (await readRevision(settings, revision)).input, sourceRevision: revision }));
}

export async function recover(state) {
  return lock(state, async state => {
    let context = await load(state, true), reconciled;
    if (context.commit) {
      reconciled = await reconcileCommit(context);
      context = await load(state);
    }
    const { settings, current, pending: transaction, history: records } = context;
    const terminal = terminalEvent(current, transaction, records);
    if (terminal) {
      const revision = await readRevision(settings, current.activeRevision);
      const previous = await readRevision(settings, transaction.previous), target = await readRevision(settings, transaction.candidate);
      const transitionValid = terminal.type === 'applied'
        ? revision.parent === previous.id
        : terminal.type === 'rejected' ? target.parent === previous.id
        : revision.parent === previous.id && revision.sourceRevision === previous.id && revision.inputSha256 === previous.inputSha256;
      if (!transitionValid || target.parent !== previous.id || !current.binding) fail('commit_integrity', 'Terminal history does not match its revision relationship and binding');
      await verifyConfirmed(settings, current, revision);
      await clearPending(settings);
      return { ok: true, outcome: 'reconciled', recordedOutcome: terminal.type, revision: revision.id, historyHead: current.historyHead, pendingCleared: true };
    }
    if (!transaction) return reconciled
      ? { ok: true, outcome: 'reconciled', recordedOutcome: reconciled.type, revision: current.activeRevision, historyHead: current.historyHead, pendingCleared: false }
      : { ok: true, outcome: 'nothing_pending' };
    if (!current.binding) fail('unbound', 'Cannot recover an unbound controller');
    const ids = [current.activeRevision, transaction.previous, transaction.candidate, transaction.rollbackRevision].filter(Boolean);
    const revisions = await Promise.all(ids.map(id => readRevision(settings, id)));
    await guard(settings, current, revisions.map(r => r.fragmentSha256));
    return rollback(settings, current, transaction, 'explicit_recovery');
  });
}

export async function status(state) {
  return lock(state, async state => {
    const { settings, current, pending: unresolved, history } = await load(state);
    const confirmed = await readRevision(settings, current.activeRevision);
    let identityValid = false, observed = null, runtimeError = null;
    if (current.binding) {
      try { await runtime(settings, current.binding); identityValid = true; observed = await request(settings, '/__x10_revision'); }
      catch (error) { runtimeError = message(error); }
    }
    return { ok: true, state, lastConfirmedRevision: confirmed.id, binding: current.binding, pending: unresolved,
      configUnchanged: hash(await readFile(settings.config)) === settings.configSha256,
      fragmentMatchesLastConfirmed: hash(await readFile(settings.fragment)) === confirmed.fragmentSha256,
      history: { entries: history.length, head: current.historyHead, integrity: true },
      runtime: { identityValid, observedRevision: observed?.revision || null, error: runtimeError } };
  });
}

export async function history(state) { return lock(state, async state => ({ ok: true, records: (await load(state)).history })); }

// Explicit diagnostics only. These observations do not alter apply/recovery
// acceptance or identify a complete configuration generation.
async function listenerDiagnostic(state, operation) {
  return lock(state, async state => {
    const { settings, current, pending: unresolved } = await load(state);
    if (unresolved) fail('pending', 'Resolve the pending transaction before inspecting listeners');
    if (!current.binding) fail('unbound', 'Bind a native master before inspecting listeners');
    const revision = await readRevision(settings, current.activeRevision);
    await guard(settings, current, [revision.fragmentSha256]);
    const master = await runtime(settings, current.binding);
    const result = await operation({ master, port: settings.port, binary: settings.binary });
    await guard(settings, current, [revision.fragmentSha256]);
    return result;
  });
}

export async function snapshotListeners(state) {
  const snapshot = await listenerDiagnostic(state, captureTcpListeners);
  return { ok: true, snapshot };
}

export async function inspectListeners(state, snapshot) {
  const observation = await listenerDiagnostic(state, options => inspectTcpListeners(snapshot, options));
  return { ok: true, observation };
}

// This explicit query is diagnostic only; it never opens a native API socket.
export async function inspectGenerations(state, endpoint) {
  const observation = await listenerDiagnostic(state, ({ master }) => inspectNativeGenerations(endpoint, master));
  return { ok: true, observation };
}
