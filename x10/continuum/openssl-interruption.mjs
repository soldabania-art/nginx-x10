// Test-only interruption control. Private IPC contains resource identities;
// public results contain only fixed labels, counts and cleanup observations.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, rm, access, stat, readdir, readFile } from 'node:fs/promises';
import { createServer, createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUNNER = fileURLToPath(new URL('./openssl-probe-run.mjs', import.meta.url));
const BUILD_PARENT = resolve(dirname(RUNNER), '../.build');
const sha256 = value => createHash('sha256').update(value).digest('hex');
// Bind cooperative source checks to module evaluation, not a later function
// call that could otherwise describe changed disk bytes for a cached module.
// This detects live edits in this harness; it is not execution attestation.
const HELPER_SHA256 = sha256(await readFile(fileURLToPath(import.meta.url)));
const requireFact = (value, code) => { if (!value) throw new Error(code); };
const limit = async (promise, ms, code) => {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(code)), ms); })]); }
  finally { clearTimeout(timer); }
};
async function exists(path) { try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw new Error('resource_access_failed'); } }
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw new Error('process_observation_failed'); } }
function killOwned(pid, group = false) { try { process.kill(group ? -pid : pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw new Error('owned_process_cleanup_failed'); } }
// /proc may be mounted from an ancestor PID namespace. Signal local PIDs,
// but resolve birth through NSpid plus namespace and UID, never path equality.
// Shared verbatim with the private preload; this is an owned-child guard,
// not a pidfd or a general atomic PID-reuse fence.
function resolveBirth(pid) {
  const deadline = Date.now() + 2000;
  const namespace = readlinkSync('/proc/self/ns/pid');
  const uid = process.getuid();
  const entries = readdirSync('/proc').filter(name => /^[1-9][0-9]*$/.test(name));
  if (!Number.isInteger(pid) || pid <= 1 || entries.length > 10000) throw new Error('process_identity_unavailable');
  const matches = [];
  for (const name of entries) {
    if (Date.now() >= deadline) throw new Error('process_identity_budget');
    try {
      const status = readFileSync('/proc/' + name + '/status', 'utf8');
      const local = /^NSpid:[ \t]+([0-9 \t]+)$/m.exec(status)?.[1].trim().split(/[ \t]+/).at(-1);
      const owner = /^Uid:[ \t]+([0-9]+)/m.exec(status)?.[1];
      if (local !== String(pid) || owner !== String(uid) || readlinkSync('/proc/' + name + '/ns/pid') !== namespace) continue;
      const stat = readFileSync('/proc/' + name + '/stat', 'utf8');
      const token = stat.slice(stat.lastIndexOf(') ') + 2).split(' ')[19];
      if (typeof token !== 'string' || !/^[0-9]+$/.test(token)) throw new Error('process_identity_unavailable');
      matches.push(token);
    } catch (error) {
      if (!['ENOENT', 'ESRCH', 'EACCES', 'EPERM'].includes(error.code)) throw new Error('process_identity_unavailable');
    }
  }
  if (Date.now() >= deadline || matches.length > 1) throw new Error('process_identity_unavailable');
  return matches[0] ?? null;
}
const birth = async pid => resolveBirth(pid);
async function rebind(port) {
  const server = createServer();
  const controller = new AbortController();
  try {
    await limit(new Promise((resolveReady, reject) => { server.once('error', () => reject(new Error('port_rebind_failed'))); server.listen({ port, host: '127.0.0.1', signal: controller.signal }, resolveReady); }), 2000, 'port_rebind_timeout');
  } finally {
    controller.abort();
    await limit(new Promise(resolveClosed => server.close(() => resolveClosed())), 2000, 'port_close_timeout');
  }
}
async function refusedConnection(port) {
  const socket = createConnection({ port, host: '127.0.0.1' });
  const closed = new Promise(resolveClosed => socket.once('close', resolveClosed));
  try {
    await limit(new Promise((resolveRefused, reject) => {
      socket.once('connect', () => reject(new Error('native_listener_survived')));
      socket.once('error', error => error.code === 'ECONNREFUSED' ? resolveRefused() : reject(new Error('native_listener_probe_failed')));
    }), 2000, 'native_listener_probe_timeout');
  } finally { socket.destroy(); await limit(closed, 2000, 'native_listener_probe_close_timeout'); }
}

// Intercept calls to real builtins without altering fixture source, binary,
// TLS calls or their arguments. The C process already waits for STEP after
// retry-completed; withholding that progress line gives a stable live point.
const PRELOAD = `
import cp from 'node:child_process';
import tls from 'node:tls';
import net from 'node:net';
import { syncBuiltinESMExports } from 'node:module';
import { dirname } from 'node:path';
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
const resolveBirth = ${resolveBirth.toString()};
const send = value => { if (process.connected) process.send(value); };
const roots = {};
const active = new Map();
let authorized = false, clientBytes = 0, clientApplicationWrites = 0;
let serverPort, relayPort, relayServer, tlsSocket, sawHandshake = false, sawRetryReady = false;
const originalServer = net.createServer;
net.createServer = function(...args) {
  const server = originalServer.apply(this, args);
  relayServer = server;
  server.on('listening', () => { const address = server.address(); if (address && typeof address === 'object') relayPort = address.port; });
  return server;
};
const originalConnect = tls.connect;
tls.connect = function(...args) {
  const socket = originalConnect.apply(this, args);
  tlsSocket = socket;
  socket.on('secureConnect', () => {
    authorized = socket.authorized && socket.getProtocol() === 'TLSv1.3' &&
      socket.getCipher()?.standardName === 'TLS_AES_128_GCM_SHA256' && socket.alpnProtocol === 'continuum-c1' && !socket.isSessionReused();
  });
  socket.on('data', chunk => { clientBytes += chunk.length; });
  const originalWrite = socket.write;
  socket.write = function(...values) { clientApplicationWrites++; return originalWrite.apply(this, values); };
  return socket;
};
const originalSpawn = cp.spawn;
cp.spawn = function(command, args = [], options = {}) {
  const child = originalSpawn.call(this, command, args, options);
  if (child.pid) {
    let birth = null;
    try { birth = resolveBirth(child.pid); } catch {}
    active.set(child.pid, { pid: child.pid, detached: options.detached === true, birth });
    send({ kind: 'spawn', pid: child.pid, detached: options.detached === true, birth });
    child.once('close', () => { active.delete(child.pid); send({ kind: 'closed', pid: child.pid }); });
  }
  const prefixMap = args.find(value => typeof value === 'string' && value.startsWith('-ffile-prefix-map=') && value.endsWith('=/continuum-build'));
  if (prefixMap) { roots.openssl = prefixMap.slice('-ffile-prefix-map='.length, -'=/continuum-build'.length); send({ kind: 'roots', roots }); }
  if (args.some(value => typeof value === 'string' && value.endsWith('/openssl-probe-fixture.c')) && args.includes('-o')) {
    roots.fixture = dirname(args[args.indexOf('-o') + 1]); send({ kind: 'roots', roots });
  }
  if (args.includes('--challenge') && args.includes('--cert')) {
    roots.pki = dirname(args[args.indexOf('--cert') + 1]); send({ kind: 'roots', roots });
    const originalEmit = child.stdout.emit;
    let pending = '', holding = false, sent = false;
    child.stdout.emit = function(event, ...values) {
      if (event !== 'data') return originalEmit.call(this, event, ...values);
      if (holding) return true;
      pending += values[0].toString('utf8');
      if (pending.length > 65536) throw new Error('control_native_output_limit');
      while (pending.includes('\\n')) {
        const end = pending.indexOf('\\n');
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        const message = JSON.parse(line);
        if (message.event === 'listening') serverPort = message.port;
        if (message.event === 'handshake') sawHandshake = message.version === 'TLSv1.3' && message.cipher === 'TLS_AES_128_GCM_SHA256' && message.alpn === 'continuum-c1' && message.resumed === false;
        if (message.event === 'retry-ready') sawRetryReady = message.scenario === 'completed-read-retry' && message.outcome === 2 && message.retryCall === 2 && message.applicationBytesRead === 0;
        if (message.event === 'retry-completed') {
          holding = true;
          if (!sent) { sent = true; send({ kind: 'checkpoint', pid: child.pid, serverPort, relayPort, roots,
            active: [...active.values()], authorized, sawHandshake, sawRetryReady,
            relayListening: relayServer?.listening === true, tlsSocketLive: tlsSocket?.destroyed === false,
            clientBytes, clientApplicationWrites, completed: message }); }
          return true;
        }
        originalEmit.call(this, 'data', Buffer.from(line + '\\n'));
      }
      return true;
    };
  }
  return child;
};
syncBuiltinESMExports();
`;

/** Fresh pinned build and actual authenticated TLS read, then handled signal.
 * No graceful TLS closure, state transfer, crash safety or zeroization claim. */
export async function runProbeInterruption({ interruption, payloadBytes = 4097, checkpoint = 'retry-completed' } = {}) {
  requireFact(['SIGTERM', 'SIGINT'].includes(interruption) && checkpoint === 'retry-completed' &&
    Number.isInteger(payloadBytes) && payloadBytes >= 2 && payloadBytes <= 65536, 'interruption_options');
  requireFact(HELPER_SHA256 === sha256(await readFile(fileURLToPath(import.meta.url))), 'interruption_helper_changed');
  const control = await mkdtemp(join(tmpdir(), 'x10-c2a-interruption-control-'));
  const helperSha256 = HELPER_SHA256;
  const runs = join(control, 'runs');
  const roots = {}, active = new Map();
  let child, closed, result, preparedIdentity, stdoutBytes = 0, stderrBytes = 0, stderr = '';
  try {
    await mkdir(runs, { mode: 0o700 });
    requireFact(((await stat(control)).mode & 0o077) === 0, 'control_permissions');
    const preload = join(control, 'hold-read-completed.mjs');
    await writeFile(preload, PRELOAD, { mode: 0o600 });
    // The CLI has no payload-length option. A tiny private launcher imports
    // the unmodified module and uses its existing API, preserving CLI cleanup.
    const launcher = join(control, 'run.mjs');
    await writeFile(launcher, `
import { prepareProbeHarness, runProbeScenario, cleanupProbeHarness, ProbeFixtureError } from ${JSON.stringify(new URL('./openssl-probe-run.mjs', import.meta.url).href)};
try {
  try { const identity = await prepareProbeHarness(); process.send({ kind: 'identity', identity }); await runProbeScenario({ scenario: 'completed-read-retry', payloadBytes: ${payloadBytes} }); console.log(JSON.stringify({ outcome: 'unexpected_pass' })); }
  finally { await cleanupProbeHarness(); }
} catch (error) {
  console.error(JSON.stringify({ outcome: 'fail', reason: error instanceof ProbeFixtureError ? error.code : 'probe_dependency_failed' }));
  process.exitCode = [130, 143].includes(error?.exitCode) ? error.exitCode : 1;
}
`, { mode: 0o600 });
    child = spawn(process.execPath, ['--import', preload, launcher], {
      detached: true, env: { ...process.env, NODE_OPTIONS: '', TMPDIR: runs }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.on('error', () => {});
    closed = new Promise(resolveClosed => child.once('close', (code, signal) => resolveClosed({ code, signal })));
    let rejectReady;
    const ready = new Promise((resolveReady, reject) => {
      rejectReady = reject;
      child.once('error', () => reject(new Error('interruption_subprocess_start')));
      child.once('close', () => reject(new Error('interruption_before_checkpoint')));
      let messages = 0;
      child.on('message', message => {
        if (++messages > 256) { reject(new Error('interruption_ipc_limit')); child.kill('SIGTERM'); return; }
        if (message?.kind === 'spawn') {
          if (!Number.isInteger(message.pid) || message.pid <= 1 || (message.birth !== null && !/^[0-9]+$/.test(message.birth))) { reject(new Error('private_process_identity_invalid')); return; }
          active.set(message.pid, { detached: message.detached === true, birth: message.birth });
        }
        else if (message?.kind === 'closed') active.delete(message.pid);
        else if (message?.kind === 'identity') preparedIdentity = message.identity;
        else if (message?.kind === 'roots') Object.assign(roots, message.roots);
        else if (message?.kind === 'checkpoint') resolveReady(message);
      });
    });
    child.stdout.on('data', chunk => { stdoutBytes += chunk.length; if (stdoutBytes > 8192) { rejectReady(new Error('interruption_stdout_limit')); child.kill('SIGTERM'); } });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 8192) stderr += chunk.toString('utf8');
      else { rejectReady(new Error('interruption_stderr_limit')); child.kill('SIGTERM'); }
    });
    result = await limit(ready, 230000, 'interruption_checkpoint_timeout');
    const build = preparedIdentity?.pinnedBuild;
    const identity = {
      sourceCommit: build?.source?.commit, sourceTree: build?.source?.tree, patchedTree: build?.source?.patchedTree,
      patchSha256: build?.patch?.sha256, fixtureBinarySha256: preparedIdentity?.fixtureBinarySha256,
      nodeBinarySha256: preparedIdentity?.nodeBinarySha256, compilerSha256: build?.compiler?.binarySha256,
      libsslSha256: build?.artifacts?.libsslSha256, libcryptoSha256: build?.artifacts?.libcryptoSha256,
      opensslSha256: build?.artifacts?.opensslSha256, configHeaderSha256: build?.configuration?.configurationHeaderSha256,
      configDataSha256: build?.configuration?.configDataSha256, makefileSha256: build?.configuration?.makefileSha256,
      fixtureSourceSha256: preparedIdentity?.sourceSha256?.fixture, probeSourceSha256: preparedIdentity?.sourceSha256?.probe,
      headerSourceSha256: preparedIdentity?.sourceSha256?.header, helperSha256,
      runnerSha256: sha256(await readFile(RUNNER)), preloadSha256: sha256(PRELOAD), launcherSha256: sha256(await readFile(launcher)),
    };
    requireFact(identity.sourceCommit === '85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c' && identity.sourceTree === '4e48caeae2374ee4982c8e44b6a15cf4753229cb' &&
      typeof identity.patchedTree === 'string' && /^[0-9a-f]{40}$/.test(identity.patchedTree), 'interruption_source_identity_invalid');
    for (const [key, value] of Object.entries(identity)) if (key.endsWith('Sha256')) requireFact(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'interruption_build_identity_invalid');
    requireFact(result.authorized === true && result.sawHandshake === true && result.sawRetryReady === true && result.clientBytes === 0 && result.clientApplicationWrites === 1 && result.relayListening === true && result.tlsSocketLive === true, 'actual_tls_checkpoint_missing');
    const c = result.completed;
    requireFact(c?.event === 'retry-completed' && c.scenario === 'completed-read-retry' && c.call === 2 && c.outcome === 1 && c.retryCall === 0 && c.sameReadArguments === true &&
      Number.isInteger(c.applicationBytesRead) && c.applicationBytesRead > 0 && c.applicationBytesRead <= Math.min(payloadBytes, 16384), 'completed_read_checkpoint_invalid');
    requireFact(Number.isInteger(result.pid) && result.pid > 1 && active.size === 1 && active.has(result.pid) && active.get(result.pid).birth !== null &&
      active.get(result.pid).birth === await birth(result.pid) && alive(result.pid), 'native_process_checkpoint_invalid');
    requireFact([result.serverPort, result.relayPort].every(port => Number.isInteger(port) && port > 0 && port <= 65535) && result.serverPort !== result.relayPort, 'owned_ports_invalid');
    requireFact(typeof roots.openssl === 'string' && dirname(roots.openssl) === BUILD_PARENT && roots.openssl.startsWith(join(BUILD_PARENT, 'continuum-openssl-')) &&
      typeof roots.fixture === 'string' && dirname(roots.fixture) === runs && roots.fixture.startsWith(join(runs, 'x10-c2a-fixture-build-')) &&
      typeof roots.pki === 'string' && dirname(roots.pki) === runs && roots.pki.startsWith(join(runs, 'x10-c2a-pki-')), 'private_resource_ownership');
    requireFact(await exists(join(roots.pki, 'leaf.key')) && await exists(join(roots.fixture, 'openssl-probe-fixture')) && await exists(join(roots.openssl, 'build/libssl.a')), 'actual_private_resources_missing');
    requireFact(child.kill(interruption), 'interruption_signal_failed');
    const exit = await limit(closed, 8000, 'handled_interruption_exit_timeout');
    requireFact(exit.code === (interruption === 'SIGTERM' ? 143 : 130) && exit.signal === null, 'handled_interruption_exit_invalid');
    requireFact(stdoutBytes === 0 && stderrBytes > 0 && stderrBytes <= 8192, 'interruption_output_invalid');
    let report; try { report = JSON.parse(stderr.trim()); } catch { throw new Error('interruption_report_invalid'); }
    requireFact(Object.keys(report).sort().join(',') === 'outcome,reason' && report.outcome === 'fail' && report.reason === 'fixture_interrupted', 'interruption_report_invalid');
    requireFact(!alive(result.pid) && active.size === 0, 'native_child_not_reaped');
    requireFact(!(await exists(roots.pki)) && !(await exists(roots.fixture)) && !(await exists(roots.openssl)) && (await readdir(runs)).length === 0, 'private_resources_survived');
    // The C listener closes immediately after accept. Its accepted TCP tuple
    // may retain kernel state, so native-port rebinding is not a cleanup gate.
    // The relay listener was confirmed live at the signal checkpoint.
    await refusedConnection(result.serverPort); await rebind(result.relayPort);
    requireFact(helperSha256 === sha256(await readFile(fileURLToPath(import.meta.url))), 'interruption_helper_changed');
    return { outcome: 'pass', interruption, checkpoint, exitCode: exit.code, signal: null, identity,
      authenticatedTLS: true, nativeHandshake: true, realReadCompleted: true, applicationBytesRead: c.applicationBytesRead,
      originalReadArguments: true, priorReadRetry: true, retryCleared: true, clientApplicationWrites: 1, echoBytesBeforeSignal: 0,
      nativeChildReaped: true, privatePKIRemoved: true, fixtureBuildRemoved: true, pinnedBuildRemoved: true,
      privateRunDirectoryEmpty: true, listenerPortsRebound: 1, nativeListenerRefused: true, fixedInterruptionFailure: true,
      gracefulTLSClosureClaimed: false, migration: false };
  } finally {
    const errors = [];
    const cleanup = async work => { try { await work(); } catch { errors.push(true); } };
    if (child && child.exitCode === null && child.signalCode === null) {
      await cleanup(async () => {
        child.kill('SIGTERM');
        try { await limit(closed, 4000, 'control_cleanup_timeout'); }
        catch { killOwned(child.pid, true); await limit(closed, 2000, 'control_cleanup_kill_timeout'); }
      });
    }
    // Completed process groups are forgotten. A reused PID is never signaled.
    for (const [pid, identity] of active) await cleanup(async () => {
      if (identity.birth !== null && identity.birth === await birth(pid)) {
        killOwned(pid, identity.detached);
        const deadline = Date.now() + 2000;
        while (identity.birth === await birth(pid)) {
          requireFact(Date.now() < deadline, 'owned_process_cleanup_timeout');
          await new Promise(resolveWait => setTimeout(resolveWait, 20));
        }
      }
      else if (identity.birth === null && alive(pid)) throw new Error('owned_process_identity_unknown');
    });
    // Failed kill/reap must not be hidden by deleting files under live code.
    if (errors.length === 0) {
      for (const path of Object.values(roots)) await cleanup(async () => {
        if (typeof path === 'string' && ((dirname(path) === BUILD_PARENT && path.startsWith(join(BUILD_PARENT, 'continuum-openssl-'))) || dirname(path) === runs)) await rm(path, { recursive: true, force: true });
      });
      await cleanup(() => rm(control, { recursive: true, force: true }));
    }
    if (errors.length) throw new Error('interruption_control_cleanup_failed');
  }
}
