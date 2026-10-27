#!/usr/bin/env node
// Separate ephemeral managed HTTP operator-package fixture. No Git, persistent
// service, application-data rollback or native/TLS-library upgrade is performed.
import { constants } from 'node:fs';
import { open, lstat, realpath, readFile, readlink, readdir, mkdir, mkdtemp, chmod, copyFile, writeFile, rm, rmdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import net from 'node:net';
import { preflight } from './preflight.mjs';
import { verifyAlphaArchive, MAX_ARCHIVE_BYTES } from '../release/verify-alpha-archive.mjs';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';
import { parseUnitProperties, parseInvocationProperty, fixtureUnitName, managerEnvironment,
  assessInstalledServiceRecipeCommand, observeNodePrerequisites, verifyKnownUnitFragmentPaths } from './lifecycle-check.mjs';
import { observeOwnedJournal } from './journal-check.mjs';
import { verifiedRouteExchange } from '../test/tls-verified-route.mjs';
import { checkManagedOperatorReturnProof } from './operator-package-return-proof.mjs';

const execute = promisify(execFile), TOOL = '/usr/bin/systemctl';
export const HISTORICAL_OPERATOR = Object.freeze({ bytes: 68551,
  commit: 'acb648392e745b5246a5620f2ea6a6286dc06d42', blob: 'f036791f3e843c3628964f5c61b0bc0ab903d6f9',
  sha256: '4560b8b2503f109f210599a6277bdf5497118e3220c1d2fb6a0c041283c3810d' });
const controls = ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'];
const alphas = ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'];
const PROPERTIES = ['LoadState', 'ActiveState', 'SubState', 'Result', 'FragmentPath', 'MainPID', 'ControlGroup'];
const hex = (value, length) => typeof value === 'string' && value.length === length && !/[^a-f0-9]/.test(value);
const simple = value => typeof value === 'string' && value.length <= 4096 && value.startsWith('/') && !/[^A-Za-z0-9_./+-]/.test(value)
  && value !== '/' && !value.endsWith('/') && path.posix.normalize(value) === value;
const refuse = code => { throw Object.assign(new Error('Managed operator package fixture refused'), { code }); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function fields(value, names) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse('input_refused');
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) refuse('input_refused');
  return Object.fromEntries(names.map(name => { const d = Object.getOwnPropertyDescriptor(value, name);
    if (!d || !Object.hasOwn(d, 'value') || d.enumerable !== true) refuse('input_refused'); return [name, d.value]; }));
}
export function parseOperatorReturnArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 6 || argv[0] !== '--archive' || argv[2] !== '--sha256' || argv[4] !== '--historical-cli'
      || !simple(argv[1]) || !argv[1].endsWith('.tar.gz') || !hex(argv[3], 64) || !simple(argv[5])) refuse('usage_refused');
  return { archive: argv[1], sha256: argv[3], historicalCli: argv[5] };
}
export function assessHistoricalOperatorBytes(bytes) {
  const valid = Buffer.isBuffer(bytes) && bytes.length === HISTORICAL_OPERATOR.bytes && digest(bytes) === HISTORICAL_OPERATOR.sha256;
  return { valid, bytes: valid ? HISTORICAL_OPERATOR.bytes : 0, sha256: valid ? HISTORICAL_OPERATOR.sha256 : null };
}
export function createImmutableUnitContext(value) {
  const v = fields(value, ['prefix', 'node', 'unitName', 'unitFile', 'runtimeLink', 'unitSha256']);
  if (![v.prefix, v.node, v.unitFile, v.runtimeLink].every(simple) || path.dirname(v.prefix) === '/' || v.prefix.length + 13 > 107
      || !/^x10-lifecycle-[a-f0-9]{32}\.service$/.test(v.unitName || '') || v.unitName.length !== 54
      || path.dirname(v.unitFile) !== path.dirname(v.prefix) || path.basename(v.unitFile) !== v.unitName
      || v.runtimeLink !== `/run/user/${process.getuid()}/systemd/user/${v.unitName}` || !hex(v.unitSha256, 64)) refuse('unit_context_refused');
  return Object.freeze({ ...v, binary: `${v.prefix}/bin/nginx`, launcher: `${v.prefix}/bin/x10` });
}
export function assessStoppedServiceUnit(value) {
  try { return Object.values(fields(value, ['unitInactive', 'mainPidZero', 'unitResultSuccess', 'launchersAbsent',
    'nativeGroupsAbsent', 'listenersClosed', 'controlSocketAbsent', 'runtimeLinkAbsent', 'unitNotFound'])).every(v => v === true); } catch { return false; }
}
const fileIdentity = stat => ({ dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode, nlink: stat.nlink,
  size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs });
async function regularBytes(file, limit, { mode, owned = true } = {}) {
  if (!simple(file) || await realpath(file) !== file) refuse('file_refused');
  const selected = await lstat(file);
  if (!selected.isFile() || selected.isSymbolicLink() || selected.nlink !== 1 || selected.size < 1 || selected.size > limit
      || (owned && selected.uid !== process.getuid()) || (mode !== undefined && (selected.mode & 0o7777) !== mode)) refuse('file_refused');
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > limit
        || (owned && before.uid !== process.getuid()) || (mode !== undefined && (before.mode & 0o7777) !== mode)
        || !same(fileIdentity(before), fileIdentity(selected))) refuse('file_refused');
    const bytes = Buffer.alloc(before.size + 1); let used = 0;
    while (used < bytes.length) { const result = await handle.read(bytes, used, bytes.length - used, null); if (!result.bytesRead) break; used += result.bytesRead; }
    if (used !== before.size || !same(fileIdentity(before), fileIdentity(await handle.stat()))
        || !same(fileIdentity(before), fileIdentity(await lstat(file)))) refuse('file_refused');
    return { bytes: bytes.subarray(0, used), identity: fileIdentity(before) };
  } finally { await handle.close(); }
}
export async function readHistoricalOperatorFile(file) {
  const value = await regularBytes(file, HISTORICAL_OPERATOR.bytes, { mode: 0o400 });
  if (!assessHistoricalOperatorBytes(value.bytes).valid) refuse('historical_cli_refused');
  return value.bytes;
}
async function record(file) {
  const value = JSON.parse((await regularBytes(file, 2 * 1024 * 1024, { mode: 0o600 })).bytes), { sha256, ...body } = value;
  if (!hex(sha256, 64) || digest(JSON.stringify(body)) !== sha256) refuse('record_refused'); return body;
}
export async function readManagedReturnRevision(file) {
  const value = JSON.parse((await regularBytes(file, 2 * 1024 * 1024, { mode: 0o400 })).bytes), { recordSha256, ...body } = value;
  if (!hex(recordSha256, 64) || digest(JSON.stringify(body)) !== recordSha256 || digest(JSON.stringify(value.input)) !== value.inputSha256) refuse('record_refused');
  return value;
}
async function absent(file) { try { await lstat(file); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; } }
async function until(fn, budget = 10000) { const end = performance.now() + budget; while (performance.now() < end) { if (await fn()) return; await pause(25); } refuse('observation_timeout'); }
async function closedPort(port) {
  return new Promise(resolve => { const socket = net.createConnection({ host: '127.0.0.1', port }); let done = false;
    const finish = value => { if (done) return; done = true; socket.destroy(); resolve(value); };
    socket.once('connect', () => finish(false)); socket.once('error', error => finish(error.code === 'ECONNREFUSED')); socket.setTimeout(1000, () => finish(false)); });
}
async function listen(server) { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); return server.address().port; }
async function unusedPort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function snapshot(prefix) {
  const rows = [], stack = ['']; let total = 0;
  while (stack.length) {
    const relative = stack.pop(), file = path.join(prefix, relative), stat = await lstat(file);
    if (stat.uid !== process.getuid() || stat.isSymbolicLink() || rows.length >= 4096) refuse('snapshot_refused');
    if (stat.isDirectory()) {
      if ((stat.mode & 0o7777) !== 0o700) refuse('snapshot_refused');
      rows.push({ path: relative, directory: true, dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode });
      for (const name of await readdir(file)) stack.push(path.posix.join(relative, name));
    } else {
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 64 * 1024 * 1024) refuse('snapshot_refused');
      total += stat.size; if (total > 256 * 1024 * 1024) refuse('snapshot_refused');
      // Empty known native PID/log files are included without using a JSON reader.
      const bytes = await readFile(file); if (bytes.length !== stat.size || !same(fileIdentity(stat), fileIdentity(await lstat(file)))) refuse('snapshot_refused');
      rows.push({ path: relative, directory: false, ...fileIdentity(stat), sha256: digest(bytes) });
    }
  }
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
async function packageIdentity(prefix) {
  const names = ['bin/nginx', 'bin/x10', ...controls.map(name => `lib/control/${name}`), ...alphas.map(name => `lib/alpha/${name}`), 'lib/service/user-unit.mjs'].sort();
  const rows = await Promise.all(names.map(async name => { const value = await regularBytes(`${prefix}/${name}`, 64 * 1024 * 1024, { mode: name.startsWith('bin/') ? 0o500 : 0o400 });
    return { path: name, bytes: value.bytes.length, sha256: digest(value.bytes), mode: name.startsWith('bin/') ? '0500' : '0400' }; }));
  const hash = files => digest(JSON.stringify({ schemaVersion: 1, files }));
  return { runtimePayloadSha256: hash(rows), operatorPayloadSha256: hash(rows.filter(v => v.path !== 'bin/nginx')), nativeBinarySha256: rows.find(v => v.path === 'bin/nginx').sha256 };
}

export async function main(argv = process.argv.slice(2)) {
  const report = { schemaVersion: 2, kind: 'nginx-x10-managed-operator-return-report', ok: false, code: 'not_started', phase: 'arguments',
    proof: null, primaryFailure: null, cleanupFailures: [], cleanupFailureCount: 0, cleanupFailuresTruncated: false,
    serviceAccepted: false, productionAccepted: false, subprocessOutputsPublished: false };
  let input, parent, node, env, app, appPort, gatewayPort, healthPort, bundle, oldBundle, savedOldBundle, savedBundle;
  let cancelled = false, inCleanup = false, ownAppClosed = false, finished = false;
  const contexts = [], states = new Map(), sockets = new Set(), retainedFiles = new Map(), phases = [], legs = [], effects = [];
  const maps = Object.fromEntries(['installation', 'unit', 'session', 'revision', 'binding', 'invocation'].map(key => [key, new Map()]));
  const ordinal = (key, value) => { const m = maps[key], s = JSON.stringify(value); if (!m.has(s)) m.set(s, m.size + 1); return m.get(s); };
  let journalChecks = 0, streams = 0, initialBGetChecks = 0;
  const cancel = () => { cancelled = true; };
  const check = () => { if (cancelled && !inCleanup) refuse('cancelled'); };
  const noteCleanup = code => { report.cleanupFailureCount++; if (report.cleanupFailures.length < 8) report.cleanupFailures.push(code); else report.cleanupFailuresTruncated = true; };
  const command = async (file, args, timeout = 15000) => {
    check();
    try { const r = await execute(file, args, { cwd: '/', env, timeout, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
      return { ok: true, exitCode: 0, stdout: r.stdout, stderr: r.stderr, termination: 'none' }; }
    catch (error) { return { ok: false, exitCode: Number.isInteger(error.code) ? error.code : null, stdout: typeof error.stdout === 'string' ? error.stdout : '',
      stderr: typeof error.stderr === 'string' ? error.stderr : '', termination: error.signal ? 'signal' : 'exit_nonzero' }; }
  };
  const ctl = (args, timeout = 10000) => command(TOOL, ['--user', '--no-pager', '--no-ask-password', ...args], timeout);
  const cli = async (file, args) => {
    const result = await command(node, [file, ...args]);
    if (!result.ok || result.stderr !== '') refuse('installed_command_failed');
    let value; try { value = JSON.parse(result.stdout); } catch { refuse('installed_response_invalid'); }
    if (!value || value.ok !== true) refuse('installed_response_invalid'); return value;
  };
  const dependenciesUnchanged = async () => {
    for (const [relative, expected] of [
      ['./lifecycle-check.mjs', 'e88ef9604b1d955ca3235b04faf4e0cb37266bfef3255e68e27d75dc63ce1370'],
      ['../test/tls-verified-route.mjs', '2b62f31e33a4b3e419f014254b8cc891068783d376f4fe8b931c853240cb3478']])
      if (digest(await readFile(new URL(relative, import.meta.url))) !== expected) refuse('dependency_source_refused');
  };
  const rememberFile = async file => { retainedFiles.set(file, await snapshot(file)); };
  const current = async ctx => {
    const manifest = await record(`${ctx.prefix}/.alpha-install.json`), registry = await record(`${ctx.prefix}/.alpha-registry.json`);
    if (manifest.prefix !== ctx.prefix || !hex(manifest.installationId, 32) || registry.installationId !== manifest.installationId || !hex(registry.current, 32)
        || !Array.isArray(registry.sessions) || registry.sessions.length < 1 || registry.sessions.length > 256
        || registry.sessions.some(value => !hex(value, 32)) || new Set(registry.sessions).size !== registry.sessions.length || !registry.sessions.includes(registry.current)) refuse('session_identity');
    const sessionPrefix = `${ctx.prefix}/runs/${registry.current}`, life = await record(`${sessionPrefix}/lifecycle.json`);
    if (life.prefix !== sessionPrefix || life.session !== registry.current || life.installationId !== manifest.installationId) refuse('session_identity');
    const status = await cli(ctx.launcher, ['status']);
    if (status.pending !== null || status.configUnchanged !== true || status.fragmentMatchesLastConfirmed !== true || status.history?.integrity !== true
        || !hex(status.lastConfirmedRevision, 32)) refuse('controller_state');
    const rev = await readManagedReturnRevision(`${sessionPrefix}/.x10-control/revisions/${status.lastConfirmedRevision}.json`);
    if (rev.id !== status.lastConfirmedRevision) refuse('controller_state');
    return { manifest, registry, sessionPrefix, life, status, revision: rev };
  };
  const prepared = async ctx => {
    const value = await current(ctx);
    if (value.life.stage !== 'prepared' || value.life.runtime !== null || value.life.controlSocket !== null || value.status.binding !== null
        || value.status.history.entries !== 1 || value.registry.sessions.length !== 1 || value.revision.parent !== null || value.revision.sourceRevision !== null
        || value.manifest.port !== gatewayPort || value.manifest.healthPort !== healthPort) refuse('preparation_refused');
    return value;
  };
  const runtimeParents = async () => {
    for (const directory of [`${env.XDG_RUNTIME_DIR}/systemd`, `${env.XDG_RUNTIME_DIR}/systemd/user`]) {
      if (await absent(directory)) continue;
      const stat = await lstat(directory);
      if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7022) !== 0 || await realpath(directory) !== directory) refuse('unit_directory');
    }
  };
  const linkAuthority = async ctx => {
    await runtimeParents(); const link = await lstat(ctx.runtimeLink);
    if (!link.isSymbolicLink() || link.uid !== process.getuid() || await readlink(ctx.runtimeLink) !== ctx.unitFile
        || digest((await regularBytes(ctx.unitFile, 8192, { mode: 0o600 })).bytes) !== ctx.unitSha256) refuse('unit_authority');
  };
  const properties = async (ctx, requireLink = states.get(ctx)?.linked === true) => {
    if (requireLink) await linkAuthority(ctx);
    const result = await ctl(['show', ctx.unitName, ...PROPERTIES.map(key => `--property=${key}`)], 2500);
    if (![0, 1].includes(result.exitCode) || result.termination === 'signal') refuse('manager_query');
    const p = parseUnitProperties(result.stdout);
    if (p.LoadState === 'loaded' && (!result.ok || result.stderr !== '')) refuse('manager_query');
    if (p.LoadState === 'not-found' && (p.MainPID !== '0' || p.ActiveState !== 'inactive' || p.FragmentPath !== '' || p.ControlGroup !== '')) refuse('unit_authority');
    if (requireLink) { await verifyKnownUnitFragmentPaths(p, { unitFile: ctx.unitFile, runtimeLink: ctx.runtimeLink }); await linkAuthority(ctx); }
    if (p.ControlGroup !== '' && (!p.ControlGroup.startsWith(`/user.slice/user-${process.getuid()}.slice/user@${process.getuid()}.service/`)
        || !p.ControlGroup.endsWith(`/${ctx.unitName}`))) refuse('unit_cgroup');
    return p;
  };
  const launcherIdentity = async (ctx, p) => {
    const pid = Number(p.MainPID); if (pid < 2 || !p.ControlGroup) refuse('launcher_identity');
    const base = `/proc/${pid}`;
    const [status, stat, executable, bytes, pidNamespace, networkNamespace, cgroup] = await Promise.all([
      readFile(`${base}/status`, 'utf8'), readFile(`${base}/stat`, 'utf8'), readlink(`${base}/exe`), readFile(`${base}/cmdline`),
      readlink(`${base}/ns/pid`), readlink(`${base}/ns/net`), readFile(`${base}/cgroup`, 'utf8')]);
    if (Buffer.byteLength(status) + Buffer.byteLength(stat) + bytes.length + Buffer.byteLength(cgroup) > 128 * 1024) refuse('launcher_identity');
    const args = bytes.toString('utf8').split('\0'); if (args.at(-1) === '') args.pop();
    const parsed = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
    if (Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]) !== process.getuid() || executable !== ctx.node
        || !same(args, [ctx.node, ctx.launcher, 'run', '--control-socket', `${ctx.prefix}/control.sock`]) || ['Z', 'X'].includes(parsed[0])
        || !/^[0-9]+$/.test(parsed[19]) || pidNamespace !== await readlink('/proc/self/ns/pid') || networkNamespace !== await readlink('/proc/self/ns/net')
        || !cgroup.split('\n').includes(`0::${p.ControlGroup}`)) refuse('launcher_identity');
    return { pid, startTicks: parsed[19], pidNamespace, networkNamespace };
  };
  const invocation = async ctx => {
    const before = await properties(ctx), selected = await launcherIdentity(ctx, before);
    if (before.ActiveState !== 'active' || before.SubState !== 'running' || before.Result !== 'success') refuse('unit_not_active');
    const result = await ctl(['show', ctx.unitName, '--property=InvocationID'], 2500), after = await properties(ctx);
    if (!result.ok || result.stderr !== '' || after.ActiveState !== 'active' || after.SubState !== 'running'
        || after.Result !== 'success' || !same(selected, await launcherIdentity(ctx, after))) refuse('invocation_changed');
    return { id: parseInvocationProperty(result.stdout), launcher: selected };
  };
  const observe = async ctx => {
    const inv = await invocation(ctx), value = await current(ctx), state = states.get(ctx);
    if (value.life.stage !== 'running' || !value.life.runtime || value.status.runtime?.identityValid !== true
        || value.status.runtime.observedRevision !== value.revision.id) refuse('native_identity');
    const identity = await inspectMaster(ctx.binary, value.sessionPrefix, value.life.runtime);
    if (!identity || identity.executable !== ctx.binary) refuse('native_identity');
    const { networkNamespace, ...binding } = identity;
    if (!same(value.status.binding, binding)) refuse('binding_identity');
    const existing = state.sessions.find(v => v.id === value.registry.current);
    if (existing ? !same(existing.identity, identity) : false) refuse('native_identity');
    if (!existing) state.sessions.push({ id: value.registry.current, prefix: value.sessionPrefix, identity });
    if (!state.launchers.some(v => same(v, inv.launcher))) state.launchers.push(inv.launcher);
    return { ...value, invocation: inv.id, launcher: inv.launcher, identity };
  };
  const journal = async ctx => {
    const before = await invocation(ctx), observed = await observeOwnedJournal({ unitName: ctx.unitName, uid: process.getuid(), invocationId: before.id });
    const after = await invocation(ctx);
    if (!same(before, after) || !observed || observed.ok !== true || observed.code !== 'owned_journal_observed'
        || observed.journalReadabilityObserved !== true || !Number.isInteger(observed.queryAttempts) || observed.queryAttempts < 1 || observed.queryAttempts > 3
        || !Number.isInteger(observed.recordsObserved) || observed.recordsObserved < 1 || observed.recordsObserved > 128
        || !Number.isInteger(observed.runningMarkers) || observed.runningMarkers < 1 || observed.runningMarkers > observed.recordsObserved) refuse('journal_unconfirmed');
    journalChecks++;
  };
  const allRetired = async ctx => {
    const state = states.get(ctx);
    for (const launcher of state.launchers) if (!await absent(`/proc/${launcher.pid}`)) return false;
    for (const session of state.sessions) if (await inspectMaster(ctx.binary, session.prefix, session.identity, false) !== null
        || (await remainingNativeGroup(ctx.binary, session.identity)).length !== 0) return false;
    return true;
  };
  const operatorLocksAbsent = async ctx => {
    const state = states.get(ctx);
    if (!await absent(`${ctx.prefix}/.alpha-lock`)) return false;
    for (const session of state.sessions) if (!await absent(`${session.prefix}/.x10-control/lock`)) return false;
    return true;
  };
  const stop = async ctx => {
    const state = states.get(ctx); await linkAuthority(ctx); const before = await properties(ctx);
    if (before.ActiveState === 'active') await observe(ctx);
    const result = await ctl(['stop', ctx.unitName], 35000), after = await properties(ctx);
    if (!result.ok || after.ActiveState !== 'inactive' || after.MainPID !== '0' || after.Result !== 'success') refuse('unit_stop');
    await until(() => allRetired(ctx));
    const value = await current(ctx);
    if (value.life.stage !== 'stopped' || value.life.lastExit?.code !== 0 || value.life.lastExit?.signal !== null || !state.sessions.length
        || !await absent(`${ctx.prefix}/control.sock`) || !await operatorLocksAbsent(ctx)
        || !await closedPort(gatewayPort) || !await closedPort(healthPort)) refuse('unit_stop');
    return { unitInactive: true, invocationRetired: true, launcherExited: true, masterAbsent: true, nativeGroupsAbsent: true,
      portsClosed: true, controlSocketAbsent: true, operatorLocksAbsent: true, pendingAbsent: true };
  };
  const retireUnit = async ctx => {
    const state = states.get(ctx), p = await properties(ctx);
    if (p.ActiveState !== 'inactive' || p.MainPID !== '0' || p.Result !== 'success' || !state.sessions.length || !await allRetired(ctx) || !await operatorLocksAbsent(ctx)
        || !await closedPort(gatewayPort) || !await closedPort(healthPort) || !await absent(`${ctx.prefix}/control.sock`)) refuse('unit_retirement');
    await linkAuthority(ctx); await rm(ctx.runtimeLink); state.linked = false;
    const reload = await ctl(['daemon-reload']); if (!reload.ok) refuse('unit_retirement');
    const after = await properties(ctx, false);
    if (!assessStoppedServiceUnit({ unitInactive: after.ActiveState === 'inactive', mainPidZero: after.MainPID === '0', unitResultSuccess: p.Result === 'success',
      launchersAbsent: await allRetired(ctx), nativeGroupsAbsent: await allRetired(ctx), listenersClosed: await closedPort(gatewayPort) && await closedPort(healthPort),
      controlSocketAbsent: await absent(`${ctx.prefix}/control.sock`), runtimeLinkAbsent: await absent(ctx.runtimeLink), unitNotFound: after.LoadState === 'not-found' })) refuse('unit_retirement');
    state.retired = true; return { runtimeLinkAbsent: await absent(ctx.runtimeLink), unitNotFound: after.LoadState === 'not-found' };
  };
  const createContext = async prefix => {
    const prerequisites = await observeNodePrerequisites(prefix, node);
    if (Object.values(prerequisites).some(value => value !== true)) refuse('preparation_refused');
    const recipe = await command(node, [`${prefix}/bin/x10`, 'service-unit', '--auto-readiness']);
    const unit = assessInstalledServiceRecipeCommand(recipe, prefix, node), unitName = fixtureUnitName(randomBytes(16).toString('hex'));
    const ctx = createImmutableUnitContext({ prefix, node, unitName, unitFile: `${parent}/${unitName}`,
      runtimeLink: `${env.XDG_RUNTIME_DIR}/systemd/user/${unitName}`, unitSha256: digest(unit) });
    const state = { linked: false, retired: false, installed: true, sessions: [], launchers: [], startRequested: false };
    contexts.push(ctx); states.set(ctx, state); await runtimeParents();
    if (!await absent(ctx.runtimeLink)) refuse('unit_collision');
    const before = await properties(ctx, false);
    if (before.LoadState !== 'not-found' || before.ActiveState !== 'inactive' || before.MainPID !== '0' || before.FragmentPath !== '') refuse('unit_collision');
    await writeFile(ctx.unitFile, unit, { mode: 0o600, flag: 'wx' });
    const linked = await ctl(['--runtime', 'link', ctx.unitFile]); state.linked = !await absent(ctx.runtimeLink);
    if (!linked.ok) refuse('unit_link'); await linkAuthority(ctx); state.linked = true; return ctx;
  };
  const start = async ctx => {
    check(); const state = states.get(ctx), before = await properties(ctx);
    if (before.ActiveState !== 'inactive' || before.MainPID !== '0') refuse('unit_start');
    state.startRequested = true; const result = await ctl(['start', ctx.unitName], 35000);
    if (!result.ok) refuse('unit_start'); return observe(ctx);
  };
  const probe = async () => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: gatewayPort, path: '/', method: 'GET', agent: false }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) req.destroy(new Error('bound')); else chunks.push(chunk); });
      res.once('error', reject); res.once('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }));
    });
    const timer = setTimeout(() => req.destroy(new Error('deadline')), 2500); req.once('close', () => clearTimeout(timer)); req.once('error', reject); req.end();
  });
  const traffic = async (ctx, name, expectedInput, expectedTag, initialBindingAbsent) => {
    check(); const value = await observe(ctx);
    if (!same(value.revision.input, expectedInput) || value.revision.inputSha256 !== digest(JSON.stringify(expectedInput))) refuse('input_mismatch');
    const before = effects.length, upload = Buffer.alloc(65551); for (let i = 0; i < upload.length; i++) upload[i] = (i * 37 + 81 + before) & 255;
    const expectedEffect = { bytes: upload.length, sha256: digest(upload) }, previous = effects.map(v => ({ ...v })), beforeStreams = streams;
    const proof = await verifiedRouteExchange({ port: gatewayPort, tag: expectedTag, origin: 'managed-return-http-origin', body: Buffer.from('managed HTTP application\n'),
      postBody: upload, streamBody: Buffer.alloc(65537, 0x62) });
    if (proof.postAttempts !== 1 || proof.postRetried !== false || proof.sameSocket !== true || proof.agentDestroyed !== true
        || !same(effects, [...previous, expectedEffect]) || streams !== beforeStreams + 1
        || new Set(effects.map(v => v.sha256)).size !== effects.length) refuse('traffic_unconfirmed');
    const after = await observe(ctx);
    if (after.invocation !== value.invocation || !same(after.identity, value.identity) || after.revision.id !== value.revision.id) refuse('traffic_identity_changed');
    legs.push({ name, identityOrdinals: { installation: ordinal('installation', value.manifest.installationId), unit: ordinal('unit', ctx.unitName),
      session: ordinal('session', value.registry.current), revision: ordinal('revision', value.revision.id), binding: ordinal('binding', value.status.binding),
      invocation: ordinal('invocation', value.invocation) }, inputSha256: value.revision.inputSha256, initialBindingAbsent,
      readinessAccepted: true, bindingMatchesOwnedRuntime: true, getExact: true, postExact: true, streamExact: true,
      postEffectsBefore: before, postEffectsAfter: effects.length });
    return after;
  };
  const applyInput = async (ctx, value, filename) => {
    const file = `${parent}/${filename}`; await writeFile(file, encode(value), { mode: 0o600, flag: 'wx' }); await rememberFile(file);
    const result = await cli(ctx.launcher, ['apply', '--file', file]); if (result.outcome !== 'applied') refuse('apply_refused');
    const observed = await observe(ctx); if (!same(observed.revision.input, value)) refuse('input_mismatch'); return observed;
  };
  const backup = async (ctx, file) => {
    const result = await cli(ctx.launcher, ['backup', '--output', file]);
    const captured = await regularBytes(file, 2 * 1024 * 1024, { mode: 0o600 }), value = JSON.parse(captured.bytes);
    if (result.outcome !== 'declarative_backup_created' || result.nativeStarted !== false || result.sha256 !== digest(captured.bytes)) refuse('backup_refused');
    const { sha256, ...body } = value;
    if (!hex(sha256, 64) || digest(JSON.stringify(body)) !== sha256 || value.inputSha256 !== digest(JSON.stringify(value.input))) refuse('backup_refused');
    await rememberFile(file); return value;
  };
  const requireRetained = async (ctx, retained) => {
    if (!same(await snapshot(ctx.prefix), retained)) refuse('source_preservation');
    for (const [file, expected] of retainedFiles) if (!same(await snapshot(file), expected)) refuse('backup_preservation');
  };
  const assertTransition = async ctx => {
    const state = states.get(ctx), p = await properties(ctx, false), value = await current(ctx);
    if (!state.retired || p.LoadState !== 'not-found' || p.ActiveState !== 'inactive' || p.MainPID !== '0' || !await absent(ctx.runtimeLink)
        || !await allRetired(ctx) || value.life.stage !== 'stopped' || !await closedPort(gatewayPort) || !await closedPort(healthPort)
        || !await absent(`${ctx.prefix}/control.sock`) || !await operatorLocksAbsent(ctx)) refuse('transition_refused');
  };
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  try {
    input = parseOperatorReturnArguments(argv); report.phase = 'preflight';
    await dependenciesUnchanged();
    const prerequisites = await preflight(); if (!prerequisites.ok || prerequisites.managerAvailable !== true) refuse('manager_unavailable');
    env = managerEnvironment(process.getuid()); node = await realpath(process.execPath);
    const historical = await readHistoricalOperatorFile(input.historicalCli);
    report.phase = 'archive'; const archive = await regularBytes(input.archive, MAX_ARCHIVE_BYTES, { owned: false });
    const checked = verifyAlphaArchive(archive.bytes, input.sha256); if (!checked.valid || checked.schemaVersion !== 2) refuse('archive_refused');
    parent = await mkdtemp(path.join(os.tmpdir(), 'x10-mret-')); await chmod(parent, 0o700);
    const archiveCopy = `${parent}/candidate.tar.gz`; await writeFile(archiveCopy, archive.bytes, { mode: 0o600, flag: 'wx' }); await rememberFile(archiveCopy);
    const unpack = await command('/usr/bin/tar', ['-xzf', archiveCopy, '-C', parent]); if (!unpack.ok) refuse('archive_refused');
    bundle = `${parent}/nginx-x10-alpha`; savedBundle = await snapshot(bundle);
    report.phase = 'historical'; oldBundle = `${parent}/historical`;
    for (const entry of savedBundle.filter(v => v.directory).sort((a, b) => a.path.length - b.path.length)) await mkdir(path.join(oldBundle, entry.path), { mode: 0o700 });
    for (const entry of savedBundle.filter(v => !v.directory)) { await copyFile(path.join(bundle, entry.path), path.join(oldBundle, entry.path), constants.COPYFILE_EXCL); await chmod(path.join(oldBundle, entry.path), entry.mode & 0o7777); }
    const oldCli = `${oldBundle}/x10/alpha/cli.mjs`; await chmod(oldCli, 0o600); await writeFile(oldCli, historical); await chmod(oldCli, 0o400);
    const oldManifest = await record(`${oldBundle}/bundle.json`);
    oldManifest.files['x10/alpha/cli.mjs'] = { bytes: historical.length, sha256: HISTORICAL_OPERATOR.sha256, mode: '0400' };
    await writeFile(`${oldBundle}/bundle.json`, encode({ ...oldManifest, sha256: digest(JSON.stringify(oldManifest)) }));
    for (const row of savedBundle.filter(v => !v.directory && !['bundle.json', 'x10/alpha/cli.mjs'].includes(v.path)))
      if (digest((await regularBytes(`${oldBundle}/${row.path}`, 64 * 1024 * 1024)).bytes) !== row.sha256) refuse('historical_cli_refused');
    savedOldBundle = await snapshot(oldBundle);
    report.phase = 'application';
    app = http.createServer((req, res) => {
      res.setHeader('X-TLS-App', 'managed-return-http-origin');
      if (req.method === 'GET' && req.url === '/ready') { res.end('ready\n'); return; }
      if (req.method === 'GET' && req.url === '/stream') { streams++; res.write(Buffer.alloc(32768, 0x62)); res.end(Buffer.alloc(32769, 0x62)); return; }
      if (req.method === 'POST' && req.url === '/echo') {
        const chunks = []; let size = 0;
        req.on('error', () => res.destroy()); req.on('data', bytes => { size += bytes.length; if (size > 1024 * 1024) req.destroy(); else chunks.push(bytes); });
        req.on('end', () => { const bytes = Buffer.concat(chunks); if (effects.length >= 8) { res.destroy(); return; } effects.push({ bytes: bytes.length, sha256: digest(bytes) }); res.end(bytes); }); return;
      }
      res.end('managed HTTP application\n');
    });
    app.requestTimeout = 4000; app.headersTimeout = 4000; app.keepAliveTimeout = 1000;
    app.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    appPort = await listen(app); do { gatewayPort = await unusedPort(); } while (gatewayPort === appPort);
    do { healthPort = await unusedPort(); } while ([gatewayPort, appPort].includes(healthPort));
    const tagP = randomBytes(16).toString('hex'), tagQ = randomBytes(16).toString('hex');
    const inputFor = tag => ({ serverBody: `client_max_body_size 16m;\nlocation / { proxy_pass http://127.0.0.1:${appPort}; proxy_http_version 1.1; proxy_next_upstream off; proxy_hide_header X-X10-TLS-Probe; add_header X-X10-TLS-Probe "${tag}" always; }`,
      healthURL: `http://127.0.0.1:${appPort}/ready`, healthExpectedStatus: 200, healthExpectedBody: 'ready\n' });
    const inputP = inputFor(tagP), inputQ = inputFor(tagQ); // HTTP state tags, never TLS keys.
    report.phase = 'install_a'; const prefixA = `${parent}/a`, oldInstaller = `${oldBundle}/install.mjs`, installer = `${bundle}/install.mjs`;
    await cli(oldInstaller, ['install', '--prefix', prefixA, '--port', String(gatewayPort), '--health-port', String(healthPort), '--upstream-port', String(appPort)]);
    const ctxA = await createContext(prefixA); await prepared(ctxA); const identityA = await packageIdentity(prefixA);
    if (digest((await regularBytes(`${prefixA}/lib/alpha/cli.mjs`, HISTORICAL_OPERATOR.bytes, { mode: 0o400 })).bytes) !== HISTORICAL_OPERATOR.sha256) refuse('historical_cli_refused');
    report.phase = 'start_a'; await start(ctxA); phases.push('a_started'); await applyInput(ctxA, inputP, 'input-p.json');
    const legA = await traffic(ctxA, 'a', inputP, tagP, true); phases.push('a_served'); await journal(ctxA);
    report.phase = 'stop_a'; const beforeB = await stop(ctxA); Object.assign(beforeB, await retireUnit(ctxA)); phases.push('a_stopped');
    const backupA = await backup(ctxA, `${parent}/backup-a.json`); if (!same(backupA.input, inputP)) refuse('backup_refused');
    const retainedA = await snapshot(ctxA.prefix); await assertTransition(ctxA);
    report.phase = 'stage_b'; const prefixB = `${parent}/b`;
    const staged = await cli(installer, ['stage', '--source-prefix', ctxA.prefix, '--prefix', prefixB, '--expected-source-payload', identityA.runtimePayloadSha256,
      '--expected-bundle-manifest', digest((await regularBytes(`${bundle}/bundle.json`, 256 * 1024, { mode: 0o600 })).bytes)]);
    if (staged.outcome !== 'package_staged' || staged.nativeStarted !== false || staged.activationPerformed !== false) refuse('stage_refused');
    const ctxB = await createContext(prefixB), prepB = await prepared(ctxB), identityB = await packageIdentity(prefixB);
    if (!same(prepB.revision.input, inputP) || identityA.runtimePayloadSha256 === identityB.runtimePayloadSha256
        || identityA.operatorPayloadSha256 === identityB.operatorPayloadSha256 || identityA.nativeBinarySha256 !== identityB.nativeBinarySha256) refuse('package_identity');
    phases.push('b_staged'); await requireRetained(ctxA, retainedA); await assertTransition(ctxA);
    report.phase = 'start_b'; await start(ctxB); phases.push('b_started');
    const initialB = await probe(); if (initialB.status !== 200 || initialB.body.toString() !== 'managed HTTP application\n'
        || initialB.headers['x-tls-app'] !== 'managed-return-http-origin' || initialB.headers['x-x10-tls-probe'] !== tagP) refuse('initial_b_unconfirmed');
    initialBGetChecks++; phases.push('b_initial_p_observed'); await journal(ctxB);
    report.phase = 'apply_q'; await applyInput(ctxB, inputQ, 'input-q.json'); phases.push('b_q_applied');
    const legB = await traffic(ctxB, 'b', inputQ, tagQ, true); phases.push('b_served'); await journal(ctxB);
    report.phase = 'restart_b'; const oldB = await observe(ctxB); phases.push('b_restart_started');
    const restarted = await ctl(['restart', ctxB.unitName], 35000); if (!restarted.ok) refuse('unit_restart');
    await until(async () => await absent(`/proc/${oldB.launcher.pid}`) && await inspectMaster(ctxB.binary, oldB.sessionPrefix, oldB.identity, false) === null
      && (await remainingNativeGroup(ctxB.binary, oldB.identity)).length === 0);
    const newB = await observe(ctxB);
    if (newB.registry.current === oldB.registry.current || newB.invocation === oldB.invocation || same(newB.status.binding, oldB.status.binding)
        || same(newB.launcher, oldB.launcher) || !same(newB.revision.input, inputQ)) refuse('restart_identity');
    const legRestart = await traffic(ctxB, 'b_restart', inputQ, tagQ, null); phases.push('b_restarted_served'); await journal(ctxB);
    report.phase = 'stop_b'; const beforeA2 = await stop(ctxB); Object.assign(beforeA2, await retireUnit(ctxB)); phases.push('b_stopped');
    const backupB = await backup(ctxB, `${parent}/backup-b.json`); if (!same(backupB.input, inputQ)) refuse('backup_refused');
    await requireRetained(ctxA, retainedA); await assertTransition(ctxB);
    report.phase = 'restore_a2'; const prefixA2 = `${parent}/a2`;
    const restored = await cli(oldInstaller, ['install', '--prefix', prefixA2, '--restore', `${parent}/backup-b.json`]);
    if (restored.declarativeRestored !== true || restored.nativeStarted !== false) refuse('restore_refused');
    const ctxA2 = await createContext(prefixA2), prepA2 = await prepared(ctxA2), identityA2 = await packageIdentity(prefixA2);
    if (!same(identityA, identityA2) || !same(prepA2.revision.input, inputQ) || prepA2.revision.inputSha256 !== backupB.inputSha256) refuse('restore_refused');
    phases.push('a2_restored'); await assertTransition(ctxB); await requireRetained(ctxA, retainedA);
    report.phase = 'start_a2'; await start(ctxA2); phases.push('a2_started'); await traffic(ctxA2, 'a2', inputQ, tagQ, true); phases.push('a2_served'); await journal(ctxA2);
    report.phase = 'stop_a2'; await stop(ctxA2); await retireUnit(ctxA2); phases.push('a2_stopped');
    await requireRetained(ctxA, retainedA);
    if (!same(await snapshot(bundle), savedBundle) || !same(await snapshot(oldBundle), savedOldBundle) || effects.length !== 4 || streams !== 4 || journalChecks !== 5) refuse('final_observation');
    report.phase = 'cleanup';
    for (const ctx of [...contexts].reverse()) {
      await assertTransition(ctx); await cli(ctx.launcher, ['uninstall']);
      if (!await absent(ctx.prefix)) refuse('uninstall_unconfirmed'); states.get(ctx).installed = false;
      if (digest((await regularBytes(ctx.unitFile, 8192, { mode: 0o600 })).bytes) !== ctx.unitSha256) refuse('unit_authority'); await rm(ctx.unitFile);
    }
    if (!same(await snapshot(oldBundle), savedOldBundle)) refuse('snapshot_refused'); await rm(oldBundle, { recursive: true });
    for (const [file, expected] of retainedFiles) { if (!same(await snapshot(file), expected)) refuse('snapshot_refused'); await rm(file); }
    for (const socket of sockets) socket.destroy();
    ownAppClosed = await new Promise(resolve => { const timer = setTimeout(() => resolve(false), 2000); app.close(error => { clearTimeout(timer); resolve(!error); }); });
    await until(() => sockets.size === 0, 2000); if (!ownAppClosed || !await closedPort(appPort)) refuse('origin_cleanup');
    if (!same(await snapshot(bundle), savedBundle)) refuse('snapshot_refused'); await rm(bundle, { recursive: true });
    if ((await readdir(parent)).length !== 0) refuse('snapshot_refused'); await rmdir(parent);
    phases.push('cleanup'); await dependenciesUnchanged();
    report.proof = { schemaVersion: 1, kind: 'nginx-x10-managed-operator-package-return-proof', packages: { a: identityA, b: identityB, a2: identityA2 },
      inputs: { pSha256: legA.revision.inputSha256, qSha256: legB.revision.inputSha256, a2RestoredSha256: prepA2.revision.inputSha256 }, phases, legs,
      transitions: { beforeB, beforeA2 },
      restart: { commandExercised: true, oldLauncherExited: true, oldMasterAbsent: true, oldNativeGroupsAbsent: true, oldInvocationRetired: true,
        freshSession: true, freshBinding: true, freshInvocation: true, sameUnit: true, samePackage: true, inputPreserved: true, unitActive: true },
      retention: { retainedAAllFilesPreserved: true, retainedABackupPreserved: true, oldAInstallerRestoredQ: true, bInitialPObservedBeforeQ: true },
      counts: { units: 3, invocations: 4, restarts: 1, journalChecks, trafficGets: 4, posts: effects.length, streams, bInitialPGetChecks: initialBGetChecks },
      cleanup: { known: true, ownedProcessesAbsent: true, ownedLaunchersAbsent: true, ownedListenersClosed: true, ownedUnitsRemoved: 3,
        ownedInstallationsRemoved: 3, historicalBundleRemoved: true, backupFilesRemoved: true },
      limits: { consistencyOnly: true, nativeBinaryUpgradeAccepted: false, liveConnectionPreserved: false, applicationSideEffectsReversed: false,
        productionAccepted: false, automaticMigrationAccepted: false, allTrafficFenceAccepted: false, restartPreparedBindingObserved: false } };
    if (checkManagedOperatorReturnProof(report.proof).ok !== true) refuse('proof_refused');
    report.ok = true; report.code = 'managed_operator_return_verified'; report.phase = 'complete'; finished = true;
  } catch (error) {
    const allowed = new Set(['usage_refused', 'input_refused', 'file_refused', 'historical_cli_refused', 'dependency_source_refused', 'manager_unavailable',
      'archive_refused', 'session_identity', 'controller_state', 'preparation_refused', 'unit_directory', 'unit_authority', 'manager_query', 'unit_cgroup', 'launcher_identity',
      'unit_not_active', 'invocation_changed', 'native_identity', 'binding_identity', 'journal_unconfirmed', 'unit_stop', 'unit_retirement', 'unit_collision', 'unit_link',
      'unit_start', 'input_mismatch', 'traffic_unconfirmed', 'traffic_identity_changed', 'apply_refused', 'backup_refused', 'source_preservation', 'backup_preservation',
      'transition_refused', 'stage_refused', 'package_identity', 'initial_b_unconfirmed', 'unit_restart', 'restart_identity', 'restore_refused', 'final_observation',
      'uninstall_unconfirmed', 'snapshot_refused', 'origin_cleanup', 'proof_refused', 'cancelled', 'observation_timeout', 'installed_command_failed', 'installed_response_invalid']);
    let originalCode;
    try { const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
      if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string') originalCode = descriptor.value;
    } catch { /* Untrusted exception metadata is never evaluated or published. */ }
    const primary = allowed.has(originalCode) ? originalCode : 'managed_operator_return_refused';
    // Keep the first finite failure even if conservative cleanup later refuses.
    report.primaryFailure = primary; report.ok = false; report.code = primary; report.proof = null;
  } finally {
    inCleanup = true;
    if (!finished) {
      // Only current link/fragment/launcher-verified manager stops are allowed.
      // No raw PID/group signal and no recursive removal on any failed run.
      for (const ctx of [...contexts].reverse()) {
        const state = states.get(ctx);
        if (!state.linked) continue;
        try { await stop(ctx); await retireUnit(ctx); } catch { noteCleanup('owned_unit_cleanup_unconfirmed'); }
      }
      if (app && !ownAppClosed) {
        try { for (const socket of sockets) socket.destroy(); ownAppClosed = await new Promise(resolve => { const timer = setTimeout(() => resolve(false), 2000);
          app.close(error => { clearTimeout(timer); resolve(!error); }); }); if (!ownAppClosed || sockets.size) noteCleanup('owned_origin_cleanup_unconfirmed'); }
        catch { noteCleanup('owned_origin_cleanup_unconfirmed'); }
      }
    }
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  }
  if (report.cleanupFailureCount) {
    report.primaryFailure ??= 'managed_operator_return_refused';
    report.ok = false; report.code = 'cleanup_unconfirmed'; report.proof = null;
  }
  if (Buffer.byteLength(encode(report)) > 12288)
    return { ...report, ok: false, code: 'report_bound', primaryFailure: report.primaryFailure ?? 'report_bound', proof: null };
  return report;
}
let invoked = false;
try { invoked = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* Import never starts a fixture. */ }
if (invoked) { const result = await main(); process.stdout.write(encode(result)); process.exitCode = result.ok ? 0 : 1; }
