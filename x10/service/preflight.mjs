#!/usr/bin/env node
// Read-only prerequisite observation, never service activation or acceptance.
import { execFile } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export const QUERY_TIMEOUT_MS = 2500;
export const QUERY_MAX_BYTES = 16384;
export const PREFLIGHT_LIMITATIONS = Object.freeze({
  scope: 'user-manager-readonly-preflight', serviceActivated: false,
  startupHealthAccepted: false, serviceAccepted: false, productionAccepted: false,
});
const TOOL = '/usr/bin/systemctl';
const ARGS = Object.freeze(['--user', 'show', '--no-pager', '--no-ask-password',
  '--property=Version', '--property=SystemState', '--property=ControlGroup']);
const validUid = uid => Number.isSafeInteger(uid) && uid > 0 && uid <= 4294967294;
const refusal = code => ({ ok: false, managerAvailable: false, code, ...PREFLIGHT_LIMITATIONS });

// Pure transcript assessment is useful for refusal tests. It does not query a
// manager or confer authority; preflight() alone observes the current process.
export function assessManagerQuery(record, uid) {
  const fail = code => ({ managerAvailable: false, code });
  if (!validUid(uid) || !record || typeof record !== 'object' || Array.isArray(record)) return fail('query_invalid');
  if (record.timedOut === true) return fail('query_timeout');
  if (record.outputLimitExceeded === true) return fail('query_output_limit');
  if (record.timedOut !== false || record.outputLimitExceeded !== false) return fail('query_invalid');
  if (record.signal !== null || record.exitCode !== 0) return fail('manager_unavailable');
  if (typeof record.stdout !== 'string' || typeof record.stderr !== 'string') return fail('query_invalid');
  if (Buffer.byteLength(record.stdout) + Buffer.byteLength(record.stderr) > QUERY_MAX_BYTES) return fail('query_output_limit');
  if (record.stderr !== '' || !record.stdout.endsWith('\n') || /[^\x20-\x7e\n]/.test(record.stdout)) return fail('manager_response_invalid');
  const rows = record.stdout.slice(0, -1).split('\n'), wanted = ['Version', 'SystemState', 'ControlGroup'];
  if (rows.length !== wanted.length) return fail('manager_response_invalid');
  const fields = Object.create(null);
  for (const row of rows) {
    const separator = row.indexOf('='), key = row.slice(0, separator), value = row.slice(separator + 1);
    if (separator < 1 || !wanted.includes(key) || Object.hasOwn(fields, key) || !value) return fail('manager_response_invalid');
    fields[key] = value;
  }
  if (!wanted.every(key => Object.hasOwn(fields, key))
      || fields.Version.length > 128 || !/^[1-9][0-9]{2,5}(?:[.\-+~][A-Za-z0-9][A-Za-z0-9_.+~\-]*)?$/.test(fields.Version)
      || !['running', 'degraded'].includes(fields.SystemState)
      || fields.ControlGroup !== `/user.slice/user-${uid}.slice/user@${uid}.service`)
    return fail('manager_response_invalid');
  return { managerAvailable: true, managerState: fields.SystemState,
    managerDegraded: fields.SystemState === 'degraded', managerVersion: fields.Version };
}

async function localPrerequisites(uid) {
  const runtime = `/run/user/${uid}`, bus = `${runtime}/bus`;
  if (await realpath(TOOL) !== TOOL || await realpath(runtime) !== runtime || await realpath(bus) !== bus) throw new Error('unsafe_local_prerequisites');
  for (const parent of ['/', '/usr', '/usr/bin', '/run', '/run/user']) {
    const stat = await lstat(parent);
    if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o7022) !== 0) throw new Error('unsafe_local_prerequisites');
  }
  const [tool, directory, socket] = await Promise.all([lstat(TOOL), lstat(runtime), lstat(bus)]);
  if (!tool.isFile() || tool.uid !== 0 || (tool.mode & 0o7022) !== 0 || !(tool.mode & 0o111)
      || !directory.isDirectory() || directory.uid !== uid || (directory.mode & 0o7777) !== 0o700
      || !socket.isSocket() || socket.uid !== uid) throw new Error('unsafe_local_prerequisites');
  return { runtime, bus };
}
function query({ runtime, bus }) {
  return new Promise(resolve => {
    // No PATH lookup, shell, inherited bus/remote address, dynamic-loader
    // variables, pager or interactive authentication. The current UID's local
    // bus is the only target. Its existence is not acceptance of a service.
    execFile(TOOL, ARGS, { cwd: '/', timeout: QUERY_TIMEOUT_MS, maxBuffer: QUERY_MAX_BYTES,
      killSignal: 'SIGKILL', encoding: 'utf8', env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C',
        XDG_RUNTIME_DIR: runtime, DBUS_SESSION_BUS_ADDRESS: `unix:path=${bus}` } }, (error, stdout, stderr) => resolve({
      exitCode: error ? (Number.isInteger(error.code) ? error.code : null) : 0,
      signal: error?.signal ?? null, stdout, stderr,
      timedOut: Boolean(error?.killed && error?.code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'),
      outputLimitExceeded: error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
    }));
  });
}

export async function preflight() {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function') return { ...refusal('linux_required'), probeExecuted: false };
  const uid = process.getuid();
  if (typeof process.geteuid !== 'function' || process.geteuid() !== uid) return { ...refusal('uid_mismatch'), probeExecuted: false };
  if (!validUid(uid)) return { ...refusal('nonroot_required'), probeExecuted: false };
  let target;
  try { target = await localPrerequisites(uid); }
  catch { return { ...refusal('local_manager_prerequisites_unavailable'), probeExecuted: false }; }
  let assessed;
  try { assessed = assessManagerQuery(await query(target), uid); }
  catch { return { ...refusal('manager_query_failed'), probeExecuted: true }; }
  if (!assessed.managerAvailable) return { ...refusal(assessed.code), probeExecuted: true };
  return { ok: true, ...assessed, probeExecuted: true, ...PREFLIGHT_LIMITATIONS };
}
export async function main(argv = process.argv.slice(2)) {
  if (!Array.isArray(argv) || argv.length !== 0) return { ...refusal('usage_invalid'), probeExecuted: false };
  return preflight();
}
let cli = false;
try { cli = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* Imports perform no probe. */ }
if (cli) {
  const result = await main(); process.stdout.write(`${JSON.stringify(result)}\n`); process.exitCode = result.ok ? 0 : 1;
}
