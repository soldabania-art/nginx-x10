#!/usr/bin/env node
// A bounded recipe generator. It never activates, installs or supervises a service.
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const RECIPE_LIMITATIONS = Object.freeze({
  scope: 'systemd-user-recipe-only', readinessAutomated: false,
  startupHealthAccepted: false, serviceAccepted: false, productionAccepted: false,
});
const HEX = /^[a-f0-9]{64}$/;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function refuse() { throw new Error('service_recipe_invalid'); }
function safePath(value) {
  if (typeof value !== 'string' || value.length > 1024 || !/^\/[A-Za-z0-9_./+-]+$/.test(value)
      || path.posix.normalize(value) !== value || value === '/' || value.endsWith('/')) refuse();
  return value;
}
function inputs(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(k => !['prefix', 'nodeExecutable'].includes(k))) refuse();
  const prefix = safePath(value.prefix), nodeExecutable = safePath(value.nodeExecutable);
  if (path.posix.dirname(prefix) === '/' || prefix.length + 13 > 107) refuse();
  return { prefix, nodeExecutable };
}

export function renderUserUnit(value) {
  const { prefix, nodeExecutable } = inputs(value);
  const command = `${nodeExecutable} ${prefix}/bin/x10`;
  return `# X10 systemd --user recipe only; no activation performed.\n`
    + `# Type=exec confirms process exec, not native startup or application readiness.\n`
    + `# readinessAutomated:false startupHealthAccepted:false serviceAccepted:false\n`
    + `# Run the explicit pinned-node launcher bind after native startup, before use.\n`
    + `[Unit]\nDescription=NGINX X10 private operator service\n\n`
    + `[Service]\nType=exec\nWorkingDirectory=${prefix}\n`
    + `ExecStart=${command} run --control-socket ${prefix}/control.sock\n`
    + `ExecStop=${command} stop\n`
    + `Restart=no\nKillMode=process\nKillSignal=SIGTERM\nSendSIGKILL=no\n`
    + `TimeoutStartSec=30s\nTimeoutStopSec=30s\nUMask=0077\n`
    + `UnsetEnvironment=NODE_OPTIONS NODE_PATH NGINX_CTRL\n`
    + `StandardOutput=journal\nStandardError=journal\n\n`
    + `[Install]\nWantedBy=default.target\n`;
}

async function readRegular(file, maxBytes, { uid, privateFile = false, executable = false } = {}) {
  if (await realpath(file) !== file) refuse();
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat(), mode = stat.mode & 0o7777;
    if (!stat.isFile() || stat.size < 1 || stat.size > maxBytes
        || (uid !== undefined && stat.uid !== uid)
        || (mode & (privateFile ? 0o077 : 0o022)) !== 0
        || (mode & 0o7000) !== 0 || (executable && (mode & 0o100) === 0)) refuse();
    const bytes = Buffer.alloc(stat.size + 1); let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    const after = await handle.stat();
    if (used !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) refuse();
    return { bytes: bytes.subarray(0, used), stat, mode };
  } finally { await handle.close(); }
}

// Read-only checks bind a recipe to an existing local installation and recorded Node.
// Runtime lifecycle, dependency integrity and health are checked by the installed CLI,
// not accepted by this generator. Trust is limited to the existing same-UID operator.
export async function inspectInstallation(value) {
  const { prefix, nodeExecutable } = inputs(value);
  if (process.platform !== 'linux' || typeof process.getuid !== 'function' || await realpath(prefix) !== prefix) refuse();
  const directory = await open(prefix, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let stat;
  try { stat = await directory.stat(); } finally { await directory.close(); }
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) refuse();
  const record = await readRegular(`${prefix}/.alpha-install.json`, 2 * 1024 * 1024, { uid: stat.uid, privateFile: true });
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(record.bytes));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) refuse();
  const { sha256, ...manifest } = parsed;
  if (!HEX.test(sha256 || '') || digest(JSON.stringify(manifest)) !== sha256
      || manifest.schemaVersion !== 1 || manifest.kind !== 'nginx-x10-local-alpha' || manifest.prefix !== prefix
      || !/^[a-f0-9]{32}$/.test(manifest.installationId || '')
      || manifest.rootIdentity?.uid !== stat.uid || manifest.rootIdentity?.dev !== stat.dev || manifest.rootIdentity?.ino !== stat.ino) refuse();
  const launcher = await readRegular(`${prefix}/bin/x10`, 64 * 1024, { uid: stat.uid, privateFile: true, executable: true });
  const expected = manifest.immutable?.['bin/x10'];
  if (!expected || !HEX.test(expected.sha256 || '') || expected.sha256 !== digest(launcher.bytes)
      || expected.bytes !== launcher.bytes.length || expected.mode !== launcher.mode.toString(8).padStart(4, '0')
      || launcher.mode !== 0o500) refuse();
  const node = manifest.nodeRuntime;
  if (!node || node.executable !== nodeExecutable || !HEX.test(node.sha256 || '')
      || !/^v(?:2[2-9]|[3-9][0-9])\.[0-9]+\.[0-9]+$/.test(node.version || '')) refuse();
  const actual = await readRegular(nodeExecutable, 256 * 1024 * 1024, { executable: true });
  if (![0, stat.uid].includes(actual.stat.uid) || digest(actual.bytes) !== node.sha256) refuse();
  return { installationChecked: true, launcherChecked: true, recordedNodeChecked: true,
    fullInstallationAccepted: false, targetRuntimeAccepted: false, ...RECIPE_LIMITATIONS };
}

export async function main(argv = process.argv.slice(2)) {
  try {
    if (argv.length !== 4 || argv[0] !== '--prefix' || argv[2] !== '--node') refuse();
    const value = { prefix: argv[1], nodeExecutable: argv[3] };
    await inspectInstallation(value);
    return { ok: true, unit: renderUserUnit(value), ...RECIPE_LIMITATIONS };
  } catch { return { ok: false, code: 'service_recipe_invalid', ...RECIPE_LIMITATIONS }; }
}
let cli = false;
try { cli = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* Imports have no CLI authority. */ }
if (cli) {
  const result = await main();
  process.stdout.write(result.ok ? result.unit : JSON.stringify(result) + '\n');
  process.exitCode = result.ok ? 0 : 1;
}
