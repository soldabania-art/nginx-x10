// Local Linux controller for one explicitly managed native NGINX HTTP server.
// No daemon is started here and no administrative network endpoint is exposed.
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, realpath, rename, rm } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { promisify } from 'node:util';

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

function candidate(value) {
  if (!value || typeof value !== 'object' || Object.keys(value).some(k => !['serverBody', 'healthURL'].includes(k)))
    fail('invalid_candidate', 'Candidate must contain only serverBody and healthURL');
  if (typeof value.serverBody !== 'string' || Buffer.byteLength(value.serverBody) > 1024 * 1024)
    fail('invalid_candidate', 'serverBody must be a string of at most 1 MiB');
  let parsed;
  try { parsed = new URL(value.healthURL); } catch { fail('invalid_health_url', 'healthURL must be an explicit HTTP loopback URL'); }
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/[A-Za-z0-9/_.~%-]*$/.test(value.healthURL)
      || parsed.hostname !== '127.0.0.1' || parsed.port === '' || Number(parsed.port) > 65535
      || parsed.username || parsed.password || parsed.search || parsed.hash)
    fail('invalid_health_url', 'healthURL must be http://127.0.0.1:port/path without credentials, query or fragment');
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
  return { serverBody: value.serverBody, healthURL: value.healthURL };
}

function render(settings, revision) {
  return `# Managed by NGINX X10; revision ${revision.id}\nserver {\n`
    + `listen 127.0.0.1:${settings.port};\nserver_name localhost;\n`
    + `location = /__x10_revision { add_header X-X10-Revision "${revision.id}" always; return 200 "${revision.id}"; }\n`
    + `location = /__x10_health { proxy_pass "${revision.input.healthURL}"; proxy_method GET; proxy_pass_request_body off; proxy_pass_request_headers off; proxy_set_header Host $proxy_host; proxy_set_header Connection close; proxy_set_header Content-Length ""; proxy_cache off; proxy_store off; proxy_buffering off; proxy_ignore_client_abort off; proxy_connect_timeout 1s; proxy_send_timeout 1s; proxy_read_timeout 1s; proxy_next_upstream off; proxy_intercept_errors off; proxy_hide_header X-X10-Revision; add_header X-X10-Revision "${revision.id}" always; }\n`
    + `${revision.input.serverBody}\n}\n`;
}

async function makeRevision(settings, input, parent, sourceRevision = null) {
  const revision = { schemaVersion: 1, id: randomBytes(16).toString('hex'), createdAt: now(), parent, sourceRevision, input: candidate(input) };
  if (Number(new URL(revision.input.healthURL).port) === settings.port) fail('invalid_health_url', 'Health backend must use a different loopback port from the managed server');
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

async function load(state) {
  const settings = await json(path.join(state, 'settings.json'));
  if (settings.schemaVersion !== 1 || settings.state !== state || settings.prefix !== path.dirname(state)) fail('settings_integrity', 'Controller path identity changed');
  if (await readlink('/proc/self/ns/pid') !== settings.pidNamespace) fail('runtime_namespace', 'Controller must run in its initialized PID namespace');
  for (const p of [settings.config, settings.fragment, settings.pidFile]) {
    if (!safePath(p) || path.dirname(p) !== settings.prefix) fail('settings_integrity', 'Controlled paths must be direct children of the private prefix');
  }
  await owned(settings.prefix, true, true); await owned(path.join(state, 'revisions'), true, true);
  const current = await json(path.join(state, 'state.json'));
  const history = await readHistory(settings, current);
  const pending = await exists(path.join(state, 'pending.json')) ? await json(path.join(state, 'pending.json')) : null;
  return { settings, current, history, pending };
}

async function readHistory(settings, current) {
  const file = path.join(settings.state, 'history.jsonl'); await owned(file);
  const s = await lstat(file); if (s.size > 16 * 1024 * 1024) fail('history_limit', 'History exceeds this controller version\'s 16 MiB limit');
  const records = (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
  let previous = null;
  for (let i = 0; i < records.length; i++) {
    const { hash: digest, ...body } = records[i];
    if (body.sequence !== i + 1 || body.previousHash !== previous || hash(JSON.stringify(body)) !== digest) fail('history_integrity', 'History hash chain is inconsistent');
    previous = digest;
  }
  if (current.historyHead !== previous) fail('history_integrity', 'State and history head disagree; operator inspection is required');
  return records;
}

async function event(settings, current, type, details) {
  const history = await readHistory(settings, current);
  const body = { sequence: history.length + 1, at: now(), type, details, previousHash: current.historyHead };
  const record = { ...body, hash: hash(JSON.stringify(body)) };
  const handle = await open(path.join(settings.state, 'history.jsonl'), constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  try { await handle.writeFile(`${JSON.stringify(record)}\n`); await handle.sync(); } finally { await handle.close(); }
  current.historyHead = record.hash;
  await save(path.join(settings.state, 'state.json'), current);
}

async function guard(settings, current, allowFragments) {
  await owned(settings.config); await owned(settings.fragment);
  if (hash(await readFile(settings.config)) !== settings.configSha256) fail('operator_config_changed', 'Operator nginx.conf changed after initialization');
  if (hash(await readFile(settings.binary)) !== settings.binarySha256) fail('binary_changed', 'Registered NGINX binary changed');
  const active = hash(await readFile(settings.fragment));
  if (!allowFragments.includes(active)) fail('fragment_changed', 'Managed fragment differs from the journal');
  if (current.binding) await runtime(settings, current.binding);
}

async function nativeTest(settings) {
  try { await execute(settings.binary, ['-p', `${settings.prefix}/`, '-c', settings.config, '-t'], { timeout: 5000, maxBuffer: 256 * 1024 }); }
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

function request(settings, target) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: settings.port, path: target, agent: false, headers: { connection: 'close' } }, res => {
      let bytes = 0, body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { bytes += Buffer.byteLength(chunk); if (bytes > 64 * 1024) req.destroy(new Error('Probe response exceeded 64 KiB')); else body += chunk; });
      res.once('error', reject);
      res.once('end', () => resolve({ status: res.statusCode, revision: res.headers['x-x10-revision'], body }));
    });
    const timer = setTimeout(() => req.destroy(new Error('Probe absolute deadline exceeded')), 350);
    req.once('close', () => clearTimeout(timer));
    req.setTimeout(350, () => req.destroy(new Error('Probe idle deadline exceeded')));
    req.once('error', reject);
  });
}

async function acknowledged(settings, revision) {
  const deadline = Date.now() + settings.gateTimeoutMs;
  let consecutive = 0, last = 'no response';
  while (Date.now() < deadline) {
    try {
      const probe = await request(settings, '/__x10_revision');
      const health = await request(settings, '/__x10_health');
      if (probe.status === 200 && probe.body === revision.id && probe.revision === revision.id && health.status === 200 && health.revision === revision.id) {
        if (++consecutive === 2) return;
      } else { consecutive = 0; last = `revision=${probe.revision}, health=${health.status}/${health.revision}`; }
    } catch (error) { consecutive = 0; last = message(error); }
    await delay(40);
  }
  fail('health_gate_failed', `No fresh acknowledged healthy revision ${revision.id}: ${last}`);
}

async function pending(settings, value) { await save(path.join(settings.state, 'pending.json'), value); }
async function clearPending(settings) { await rm(path.join(settings.state, 'pending.json')); await syncDirectory(settings.state); }

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
    await nativeTest(settings);
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
  await nativeTest(settings);
  await guard(settings, current, [restored.fragmentSha256]);
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
      await nativeTest(settings);
      await guard(settings, current, [revision.fragmentSha256]);
      transaction.stage = 'reload_requested'; await pending(settings, transaction);
      await signal(settings, current); signalled = true;
      await acknowledged(settings, revision);
      await guard(settings, current, [revision.fragmentSha256]);
      current.previousRevision = old.id; current.activeRevision = revision.id;
      await event(settings, current, 'applied', { revision: revision.id, previous: old.id });
      await clearPending(settings);
      return { ok: true, outcome: 'applied', revision: revision.id, previous: old.id };
    } catch (error) {
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
    const { settings, current, pending: transaction } = await load(state);
    if (!transaction) return { ok: true, outcome: 'nothing_pending' };
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
