// Bounded read-only observation of already-readable, exactly attributed journal
// records. A launcher marker is readable output, not readiness or ownership.
import { execFile } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';

export const JOURNAL_TIMEOUT_MS = 2500;
export const JOURNAL_MAX_BYTES = 256 * 1024;
export const JOURNAL_MAX_RECORDS = 128;
export const JOURNAL_MAX_ATTEMPTS = 3;
const TOOL = '/usr/bin/journalctl';
const KEYS = ['MESSAGE', '_UID', '_SYSTEMD_USER_UNIT', '_SYSTEMD_INVOCATION_ID'];
const METADATA = ['__CURSOR', '__REALTIME_TIMESTAMP', '__MONOTONIC_TIMESTAMP', '_BOOT_ID'];
const LIMITATIONS = Object.freeze({ scope: 'owned-user-unit-journal-readability',
  serviceAccepted: false, productionAccepted: false });
const validUid = uid => Number.isSafeInteger(uid) && uid > 0 && uid <= 4294967294;
export const JOURNAL_RESULT_CODES = Object.freeze(['journal_invalid', 'journal_local_prerequisites_unavailable',
  'journal_query_failed', 'journal_query_timeout', 'journal_output_limit',
  'journal_unavailable', 'journal_response_invalid', 'journal_empty',
  'journal_record_limit', 'journal_identity_mismatch', 'journal_running_marker_missing']);
const codes = new Set(JOURNAL_RESULT_CODES);
const outcome = (ok, code, attempts, records = 0, markers = 0) => ({ ok, code,
  queryAttempts: attempts, recordsObserved: records, runningMarkers: markers,
  journalReadabilityObserved: ok, ...LIMITATIONS });
const refuse = code => { throw Object.assign(new Error(code), { code }); };
function data(value, names) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse('journal_invalid');
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) refuse('journal_invalid');
  const result = Object.create(null);
  for (const key of names) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, 'value')) refuse('journal_invalid');
    result[key] = d.value;
  }
  return result;
}
function context(value) {
  const c = data(value, ['unitName', 'uid', 'invocationId']);
  if (!validUid(c.uid) || typeof c.unitName !== 'string'
      || !/^x10-lifecycle-[a-f0-9]{32}\.service$/.test(c.unitName)
      || typeof c.invocationId !== 'string' || !/^[a-f0-9]{32}$/.test(c.invocationId)
      || /^0+$/.test(c.invocationId)) refuse('journal_invalid');
  return c;
}

// Private query specification: callers must never publish its input identities
// or argv. Different-field matches are ANDed; --user-unit would add OR matches.
// --user is deliberately absent: it requires persistent user journals. No ACL,
// group, journal configuration or privilege is changed to obtain visibility.
export function journalQuerySpec(value) {
  const c = context(value);
  return { file: TOOL, args: ['--no-pager', '--quiet', '--output=json',
    `--output-fields=${KEYS.join(',')}`, `--lines=${JOURNAL_MAX_RECORDS + 1}`,
    `_UID=${c.uid}`, `_SYSTEMD_USER_UNIT=${c.unitName}`, `_SYSTEMD_INVOCATION_ID=${c.invocationId}`],
  options: { cwd: '/', timeout: JOURNAL_TIMEOUT_MS, maxBuffer: JOURNAL_MAX_BYTES,
    killSignal: 'SIGKILL', encoding: 'utf8', env: { PATH: '/usr/bin:/bin', LANG: 'C',
      LC_ALL: 'C', XDG_RUNTIME_DIR: `/run/user/${c.uid}` } } };
}

function flatRecord(line) {
  let value;
  try { value = JSON.parse(line); } catch { refuse('journal_response_invalid'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) refuse('journal_response_invalid');
  const keys = Object.keys(value), allowed = [...KEYS, ...METADATA];
  if (!KEYS.every(key => Object.hasOwn(value, key)) || keys.some(key => !allowed.includes(key))
      || keys.some(key => typeof value[key] !== 'string' || Buffer.byteLength(value[key]) > 4096
        || /[\x00-\x1f\x7f]/.test(value[key]))) refuse('journal_response_invalid');
  // Flat string-valued output permits a string-token scan to detect duplicate
  // JSON keys and noncanonical escaped spellings before their last value wins.
  const seen = new Set();
  for (const match of line.matchAll(/"(?:\\.|[^"\\])*"/g)) {
    if (!/^\s*:/.test(line.slice(match.index + match[0].length))) continue;
    const key = JSON.parse(match[0]);
    if (seen.has(key) || !allowed.includes(key) || match[0] !== JSON.stringify(key)) refuse('journal_response_invalid');
    seen.add(key);
  }
  if (seen.size !== keys.length) refuse('journal_response_invalid');
  return value;
}

// Pure transcript assessment grants no query, unit, process or signal authority.
// Never copy raw fields, error strings or fingerprints into its finite result.
export function assessJournalQuery(record, value) {
  try {
    const c = context(value), r = data(record, ['exitCode', 'signal', 'stdout', 'stderr', 'timedOut', 'outputLimitExceeded']);
    if (r.timedOut === true) refuse('journal_query_timeout');
    if (r.outputLimitExceeded === true) refuse('journal_output_limit');
    if (r.timedOut !== false || r.outputLimitExceeded !== false) refuse('journal_invalid');
    if (r.signal !== null || r.exitCode !== 0) refuse('journal_unavailable');
    if (typeof r.stdout !== 'string' || typeof r.stderr !== 'string') refuse('journal_invalid');
    if (Buffer.byteLength(r.stdout) + Buffer.byteLength(r.stderr) > JOURNAL_MAX_BYTES) refuse('journal_output_limit');
    if (r.stderr !== '' || /[^\x20-\x7e\n]/.test(r.stdout)) refuse('journal_response_invalid');
    if (r.stdout === '') refuse('journal_empty');
    if (!r.stdout.endsWith('\n')) refuse('journal_response_invalid');
    const rows = r.stdout.slice(0, -1).split('\n');
    if (rows.length > JOURNAL_MAX_RECORDS) refuse('journal_record_limit');
    let markers = 0;
    for (const line of rows) {
      const row = flatRecord(line);
      if (row._UID !== String(c.uid) || row._SYSTEMD_USER_UNIT !== c.unitName
          || row._SYSTEMD_INVOCATION_ID !== c.invocationId) refuse('journal_identity_mismatch');
      if (/^\s*"outcome": "running",?\s*$/.test(row.MESSAGE)) markers++;
    }
    if (markers === 0) refuse('journal_running_marker_missing');
    return outcome(true, 'owned_journal_observed', 1, rows.length, markers);
  } catch (error) {
    const d = error && Object.getOwnPropertyDescriptor(error, 'code');
    return outcome(false, d && Object.hasOwn(d, 'value') && codes.has(d.value) ? d.value : 'journal_invalid', 1);
  }
}

async function localTool(uid) {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function'
      || typeof process.geteuid !== 'function' || process.getuid() !== uid || process.geteuid() !== uid) refuse('journal_local_prerequisites_unavailable');
  for (const parent of ['/', '/usr', '/usr/bin']) {
    const s = await lstat(parent);
    if (!s.isDirectory() || s.uid !== 0 || (s.mode & 0o7022) !== 0 || await realpath(parent) !== parent) refuse('journal_local_prerequisites_unavailable');
  }
  const s = await lstat(TOOL);
  if (!s.isFile() || s.uid !== 0 || (s.mode & 0o7022) !== 0 || !(s.mode & 0o111) || await realpath(TOOL) !== TOOL) refuse('journal_local_prerequisites_unavailable');
}
function query(spec) {
  return new Promise(resolve => execFile(spec.file, spec.args, spec.options, (error, stdout, stderr) => resolve({
    exitCode: error ? (Number.isInteger(error.code) ? error.code : null) : 0,
    signal: error?.signal ?? null, stdout, stderr,
    timedOut: Boolean(error?.killed && error?.code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'),
    outputLimitExceeded: error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
  })));
}

// The caller must bracket this await with fresh owned-unit, invocation, launcher
// and cancellation checks. Limited re-observation permits asynchronous delivery
// only after an empty/marker-missing result; malformed/foreign/query errors stop.
export async function observeOwnedJournal(value) {
  let attempts = 0;
  try {
    const c = context(value), spec = journalQuerySpec(c);
    await localTool(c.uid);
    while (attempts < JOURNAL_MAX_ATTEMPTS) {
      attempts++;
      const result = assessJournalQuery(await query(spec), c);
      if (result.ok || !['journal_empty', 'journal_running_marker_missing'].includes(result.code)
          || attempts === JOURNAL_MAX_ATTEMPTS) return { ...result, queryAttempts: attempts };
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } catch {
    return outcome(false, attempts === 0 ? 'journal_local_prerequisites_unavailable' : 'journal_query_failed', attempts);
  }
}
