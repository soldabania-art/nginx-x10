#!/usr/bin/env node
// Bounded Linux loopback observation. This does not establish an all-worker fence.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { captureTcpListeners, inspectTcpListeners } from '../control/listeners.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const quote = text => `"${String(text).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
const nativeSources = ['src/os/unix/ngx_process_cycle.c', 'src/os/unix/ngx_process.c', 'src/core/ngx_connection.c', 'src/core/ngx_cycle.c'];

async function until(predicate, label, interrupted, timeout = 6000) {
  const end = performance.now() + timeout;
  let last;
  while (performance.now() < end) {
    if (interrupted()) throw new Error('Handover fixture interrupted');
    try { const result = await predicate(); if (result) return result; }
    catch (error) { last = error; }
    await delay(25);
  }
  throw new Error(`Timed out: ${label}${last ? `: ${last.message}` : ''}`);
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function unusedPort() {
  const server = net.createServer();
  const port = await listen(server);
  await new Promise(resolve => server.close(resolve));
  return port;
}

function trackClient(req, sockets) {
  req.on('socket', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
}

function request(port, sockets) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/revision', agent: false,
      headers: { connection: 'close' } }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; if (Buffer.byteLength(body) > 4096) req.destroy(new Error('Probe too large')); });
      res.once('error', reject);
      res.once('end', () => resolve({ status: res.statusCode, body, revision: res.headers['x-x10-revision'], workerPid: Number(res.headers['x-x10-worker']) }));
    });
    const timer = setTimeout(() => req.destroy(new Error('Absolute probe deadline')), 400);
    trackClient(req, sockets);
    req.once('close', () => clearTimeout(timer));
    req.once('error', reject);
  });
}

function heldRequest(port, sockets) {
  const result = { ended: false, chunks: [], firstReceived: false };
  let firstResolve, firstReject, doneResolve, doneReject;
  result.first = new Promise((resolve, reject) => { firstResolve = resolve; firstReject = reject; });
  result.complete = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });
  result.first.catch(() => {}); result.complete.catch(() => {});
  const fail = error => { firstReject(error); doneReject(error); };
  result.request = http.get({ host: '127.0.0.1', port, path: '/stream', agent: false }, res => {
    result.workerPid = Number(res.headers['x-x10-worker']);
    result.revision = res.headers['x-x10-revision'];
    result.status = res.statusCode;
    res.on('data', chunk => {
      result.chunks.push(chunk);
      if (!result.firstReceived && Buffer.concat(result.chunks).includes(10)) {
        result.firstReceived = true; firstResolve(Buffer.concat(result.chunks).toString('utf8'));
      }
    });
    res.once('error', fail);
    res.once('end', () => { result.ended = true; doneResolve(Buffer.concat(result.chunks).toString('utf8')); });
  });
  const timer = setTimeout(() => result.request.destroy(new Error('Held response absolute deadline')), 25_000);
  trackClient(result.request, sockets);
  result.request.once('close', () => clearTimeout(timer));
  result.request.once('error', fail);
  return result;
}

async function procIdentity(procPid) {
  const dir = `/proc/${procPid}`;
  const [status, stat, executable, pidNamespace, networkNamespace] = await Promise.all([
    readFile(`${dir}/status`, 'utf8'), readFile(`${dir}/stat`, 'utf8'), readlink(`${dir}/exe`),
    readlink(`${dir}/ns/pid`), readlink(`${dir}/ns/net`),
  ]);
  const pids = /^NSpid:\s+([0-9\s]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
  const fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
  const identity = { pid: pids?.at(-1), procPid: Number(procPid), parentProcPid: Number(fields[1]),
    startTicks: fields[19], uid: Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]), executable, pidNamespace, networkNamespace };
  assert(Number.isSafeInteger(identity.pid) && identity.pid > 1 && /^\d+$/.test(identity.startTicks));
  assert(!['Z', 'X'].includes(fields[0]), 'Native process has exited');
  return { identity, state: fields[0] };
}

async function processEntries() {
  const entries = (await readdir('/proc')).filter(value => /^[1-9][0-9]*$/.test(value));
  assert(entries.length <= 10000, 'Bounded /proc entry limit exceeded');
  return entries;
}

async function resolvePid(pid, expected) {
  const results = [];
  const entries = await processEntries();
  for (let index = 0; index < entries.length; index += 32) {
    const batch = await Promise.all(entries.slice(index, index + 32).map(async entry => {
      try {
        const status = await readFile(`/proc/${entry}/status`, 'utf8');
        const pids = /^NSpid:\s+([0-9\s]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
        if (pids?.at(-1) !== pid) return null;
        const found = await procIdentity(entry);
        if (found.identity.pidNamespace !== expected.pidNamespace || found.identity.uid !== expected.uid || found.identity.executable !== expected.executable) return null;
        return found;
      } catch (error) { if (['ENOENT', 'ESRCH', 'EACCES', 'EPERM'].includes(error.code)) return null; throw error; }
    }));
    results.push(...batch.filter(Boolean));
  }
  assert.equal(results.length, 1, 'Local native PID must resolve uniquely in the expected namespace');
  return results[0];
}

async function sameProcess(identity) {
  const current = await procIdentity(identity.procPid);
  assert.deepEqual(current.identity, identity, 'Native process identity changed');
  return current;
}

async function listeningInodes(master, port) {
  await sameProcess(master);
  const text = await readFile(`/proc/${master.procPid}/net/tcp`, 'utf8');
  assert(Buffer.byteLength(text) <= 2 * 1024 * 1024, 'TCP table exceeds fixture bound');
  const endpoint = `0100007F:${port.toString(16).toUpperCase().padStart(4, '0')}`;
  const inodes = text.trim().split('\n').slice(1).map(line => line.trim().split(/\s+/))
    .filter(fields => fields[1] === endpoint && fields[3] === '0A').map(fields => fields[9]);
  assert(inodes.length > 0 && inodes.every(value => /^[1-9][0-9]*$/.test(value)), 'Managed IPv4 LISTEN inode missing');
  await sameProcess(master);
  return [...new Set(inodes)].sort();
}

async function descriptors(identity, inodes) {
  const before = await sameProcess(identity);
  const files = (await readdir(`/proc/${identity.procPid}/fd`)).filter(value => /^\d+$/.test(value));
  assert(files.length <= 4096, 'Native fd inventory exceeds fixture bound');
  const held = new Set();
  for (let index = 0; index < files.length; index += 32) {
    const links = await Promise.all(files.slice(index, index + 32).map(async fd => {
      try { return await readlink(`/proc/${identity.procPid}/fd/${fd}`); }
      catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    }));
    for (const link of links) {
      const inode = /^socket:\[([0-9]+)\]$/.exec(link || '')?.[1];
      if (inodes.includes(inode)) held.add(inode);
    }
  }
  const after = await sameProcess(identity);
  return { identity, stateBefore: before.state, stateAfter: after.state, managedListeningInodes: [...held].sort(), inspectedDescriptors: files.length };
}

function configuration(prefix, port, upstreamPort, revision) {
  const user = process.geteuid?.() === 0 ? `user ${quote(os.userInfo().username)};` : '';
  return `${user}
daemon off;
master_process on;
worker_processes 2;
worker_shutdown_timeout 20s;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log ${quote(path.join(prefix, 'error.log'))} notice;
events { worker_connections 128; }
http {
 access_log off;
 client_body_temp_path ${quote(path.join(prefix, 'body'))};
 proxy_temp_path ${quote(path.join(prefix, 'proxy'))};
 server {
  listen 127.0.0.1:${port};
  server_name localhost;
  add_header X-X10-Worker $pid always;
  add_header X-X10-Revision ${revision} always;
  location = /revision { return 200 "${revision}"; }
  location = /stream {
   proxy_pass http://127.0.0.1:${upstreamPort};
   proxy_buffering off;
   proxy_read_timeout 20s;
  }
 }
}
`;
}

function signalGroup(child, signal) {
  if (!child?.pid) return;
  try { process.kill(-child.pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}

export async function runHandover({ binary }) {
  const evidence = { schemaVersion: 1, suite: 'native-reload-listener-observation', startedAt: new Date().toISOString(),
    success: false, identity: {}, tests: [], skips: [], observations: {}, configurations: [], fixtureErrors: [],
    nativeErrorLogRead: false, unexpectedNativeErrors: [], expectedNativeDiagnostics: [],
    limitations: [
      'Linux IPv4 loopback TCP only; no QUIC, UDP, reuseport, HTTP2, keepalive/pipelining or complete platform matrix.',
      'Observes one exactly identified old worker; process-set churn and unseen respawns are not fenced.',
      'A snapshot of descriptor absence is not all-traffic atomic cutover or a rollback of application effects.',
      'SIGSTOP deliberately delays only a worker owned by this isolated fixture; no production process is targeted.',
      'Local source and binary identities are recorded separately, not signed build attestations.',
    ] };
  let prefix, child, origin, held, release, originPort, port, logTail = '', interrupted = false, stopSignal;
  const sockets = new Set(), clientSockets = new Set();
  const nativeBefore = {}, sourceBefore = {};
  const isInterrupted = () => interrupted;
  const add = (name, details = {}) => evidence.tests.push({ name, status: 'passed', ...details });
  const onInterrupt = signal => {
    interrupted = true; stopSignal = signal;
    // Resume the dedicated native group before requesting termination.
    try { signalGroup(child, 'SIGCONT'); signalGroup(child, 'SIGTERM'); } catch {}
  };
  const onInt = () => onInterrupt('SIGINT'), onTerm = () => onInterrupt('SIGTERM');
  process.on('SIGINT', onInt); process.on('SIGTERM', onTerm);
  const deadline = setTimeout(() => onInterrupt('deadline'), 30_000);
  try {
    assert.equal(process.platform, 'linux', 'Handover fixture requires Linux /proc');
    binary = await realpath(path.resolve(binary));
    nativeBefore.binary = hash(await readFile(binary));
    for (const source of nativeSources) sourceBefore[source] = hash(await readFile(path.join(root, source)));
    const harnessSha256 = hash(await readFile(fileURLToPath(import.meta.url)));
    const observerSha256 = hash(await readFile(path.join(root, 'x10/control/listeners.mjs')));
    const version = await execute(binary, ['-V'], { timeout: 5000, maxBuffer: 256 * 1024 });
    const commit = await execute('git', ['rev-parse', 'HEAD'], { cwd: root, timeout: 5000 });
    evidence.identity = { binary, binarySha256: nativeBefore.binary, versionOutput: `${version.stdout}${version.stderr}`.trim(),
      sourceCheckout: root, checkoutRevision: commit.stdout.trim(), sourceFilesSha256: sourceBefore, harnessSha256, observerSha256,
      node: process.version, platform: process.platform, arch: process.arch };
    prefix = await mkdtemp(path.join(os.tmpdir(), 'nginx-x10-handover-'));
    await chmod(prefix, 0o700);
    await mkdir(path.join(prefix, 'body'), { mode: 0o700 }); await mkdir(path.join(prefix, 'proxy'), { mode: 0o700 });
    origin = http.createServer((req, res) => {
      if (req.url !== '/stream' || release) { res.writeHead(500); res.end(); return; }
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.write('first:old\n');
      release = () => res.end('last:old\n');
    });
    origin.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    origin.on('clientError', error => evidence.fixtureErrors.push(error.message));
    originPort = await listen(origin); port = await unusedPort();
    const config = path.join(prefix, 'nginx.conf');
    const replace = async (revision, invalid = false) => {
      const text = configuration(prefix, port, originPort, revision) + (invalid ? '\nx10_deliberately_invalid;\n' : '');
      await writeFile(`${config}.next`, text, { mode: 0o600 }); await rename(`${config}.next`, config);
      evidence.configurations.push({ revision, invalid, sha256: hash(text), bytes: Buffer.byteLength(text) });
    };
    await replace('revision-a');
    const args = ['-p', `${prefix}/`, '-c', config, '-e', path.join(prefix, 'error.log')];
    await execute(binary, [...args, '-t'], { timeout: 5000, maxBuffer: 256 * 1024 });
    add('native-config-validation');
    if (interrupted) throw new Error('Interrupted before native startup');
    child = spawn(binary, args, { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.once('error', error => { logTail += error.message; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logTail = (logTail + chunk).slice(-16384); });
    const expected = { pidNamespace: await readlink('/proc/self/ns/pid'), networkNamespace: await readlink('/proc/self/ns/net'),
      uid: process.geteuid(), executable: binary };
    const master = (await until(() => resolvePid(child.pid, expected), 'master identity', isInterrupted)).identity;
    assert.equal(master.networkNamespace, expected.networkNamespace);
    evidence.identity.master = master;
    const revision = async desired => until(async () => {
      const response = await request(port, clientSockets);
      return response.status === 200 && response.body === desired && response.revision === desired && Number.isSafeInteger(response.workerPid) && response.workerPid > 1 && response;
    }, `fresh ${desired}`, isInterrupted);
    await revision('revision-a');
    const title = (await readFile(`/proc/${master.procPid}/cmdline`, 'utf8')).split('\0')[0];
    assert(title.startsWith('nginx: master process '));
    const observerMaster = { pid: master.pid, procPid: master.procPid, pidNamespace: master.pidNamespace,
      startTicks: master.startTicks, uid: master.uid, executable: master.executable, commandSha256: hash(title) };
    const observerOptions = { master: observerMaster, port, binary };
    const snapshot = await captureTcpListeners(observerOptions);
    assert.equal(snapshot.scope, 'captured-processes-only');
    assert.equal(snapshot.processes.length, 2, 'Exactly two native workers must be captured');
    assert(snapshot.processes.every(p => p.ownedListenerFds.length > 0));
    evidence.observations.observerCapture = snapshot;
    held = heldRequest(port, clientSockets);
    assert.equal(await held.first, 'first:old\n');
    assert.equal(held.status, 200); assert.equal(held.revision, 'revision-a'); assert.equal(held.ended, false);
    const old = (await resolvePid(held.workerPid, expected)).identity;
    assert.equal(old.parentProcPid, master.procPid);
    assert(snapshot.processes.some(p => p.procPid === old.procPid && p.startTicks === old.startTicks));
    const inodes = await listeningInodes(master, port);
    const initial = await descriptors(old, inodes); assert(initial.managedListeningInodes.length > 0);
    evidence.observations.initial = initial; evidence.observations.listenerInodes = inodes;
    add('held-old-response-and-owned-tcp-listener', { workerPid: old.pid, revision: held.revision, firstChunk: 'first:old\n' });
    await sameProcess(old); process.kill(old.pid, 'SIGSTOP');
    const stopped = await until(async () => { const found = await descriptors(old, inodes); return found.stateBefore === 'T' && found.stateAfter === 'T' && found.managedListeningInodes.length > 0 && found; }, 'old worker stopped with listener', isInterrupted);
    evidence.observations.stoppedBeforeReload = stopped;
    process.stderr.write(`Handover fixture: old worker stopped; master=${master.pid} worker=${old.pid}\n`);
    await replace('revision-b'); await sameProcess(master); process.kill(master.pid, 'SIGHUP');
    const freshB = await revision('revision-b');
    assert.notEqual(freshB.workerPid, old.pid);
    await delay(150);
    const stillStopped = await descriptors(old, inodes);
    assert.equal(stillStopped.stateBefore, 'T'); assert.equal(stillStopped.stateAfter, 'T');
    assert(stillStopped.managedListeningInodes.length > 0); assert.equal(held.ended, false);
    evidence.observations.freshBWhileOldStopped = { freshResponse: freshB, oldWorker: stillStopped };
    const observerPending = await inspectTcpListeners(snapshot, observerOptions);
    assert.equal(observerPending.scope, 'captured-processes-only');
    assert.equal(observerPending.state, 'pending'); assert.equal(observerPending.closed, false);
    assert(observerPending.processes.some(p => p.procPid === old.procPid && p.state === 'owns-listener' && p.ownedListenerFds.length > 0));
    evidence.observations.observerWhileStopped = observerPending;
    add('new-revision-response-does-not-prove-old-listener-closure', { freshRevision: freshB.revision, stoppedWorkerStillOwnsListener: true });
    await sameProcess(old); process.kill(old.pid, 'SIGCONT');
    const closed = await until(async () => { const found = await descriptors(old, inodes); return found.managedListeningInodes.length === 0 && found; }, 'old live worker closes managed listener', isInterrupted);
    assert.equal(held.ended, false); assert.equal(release instanceof Function, true);
    evidence.observations.oldListenerClosedWhileResponseHeld = closed;
    const observerClosed = await until(async () => {
      const value = await inspectTcpListeners(snapshot, observerOptions);
      return value.state === 'closed' && value.closed === true && value;
    }, 'captured process set listener closure', isInterrupted);
    assert(observerClosed.processes.some(p => p.procPid === old.procPid && p.state === 'listener-absent'));
    assert.equal(held.ended, false); await sameProcess(old);
    evidence.observations.observerAfterResume = observerClosed;
    add('old-worker-alive-without-listener-while-response-held');
    await replace('revision-c'); await sameProcess(master); process.kill(master.pid, 'SIGHUP');
    const freshC = await revision('revision-c');
    assert.equal(held.ended, false); await sameProcess(old);
    evidence.observations.secondReload = { freshResponse: freshC, oldResponseStillHeld: true };
    const observerAfterSecond = await inspectTcpListeners(snapshot, observerOptions);
    assert.equal(observerAfterSecond.state, 'closed'); assert.equal(observerAfterSecond.closed, true);
    evidence.observations.observerAfterSecondReload = observerAfterSecond;
    add('second-reload-preserves-first-generation-stream');
    release();
    const complete = await held.complete;
    assert.equal(complete, 'first:old\nlast:old\n');
    add('old-response-completes-exactly-after-listener-closure-and-two-reloads', { bytes: Buffer.byteLength(complete), bodySha256: hash(complete) });
    const beforeInvalid = await readFile(path.join(prefix, 'error.log'), 'utf8');
    await replace('revision-invalid', true); await sameProcess(master); process.kill(master.pid, 'SIGHUP');
    await until(async () => (await readFile(path.join(prefix, 'error.log'), 'utf8')).slice(beforeInvalid.length).includes('unknown directive "x10_deliberately_invalid"'), 'actual native reload rejection', isInterrupted);
    const afterRejected = [];
    for (let i = 0; i < 4; i++) afterRejected.push(await revision('revision-c'));
    evidence.observations.rejectedReload = { actualRejectionLogged: true, responses: afterRejected };
    add('rejected-reload-retains-last-valid-revision', { freshResponses: afterRejected.length });
    await replace('revision-c');
    evidence.success = true;
  } catch (error) { evidence.error = error.stack || error.message; }
  finally {
    const cleanup = { nativeStopped: !child, nativeExitCode: null, nativeSignal: null, mode: null,
      stoppedWorkerResumeRequested: false, fixturesStopped: false, openSockets: null, temporaryRootRemoved: false, errors: [] };
    try { if (child?.pid) { signalGroup(child, 'SIGCONT'); cleanup.stoppedWorkerResumeRequested = true; } } catch (error) { cleanup.errors.push(error.message); }
    held?.request?.destroy();
    try { release?.(); } catch {}
    for (const socket of sockets) socket.destroy();
    for (const socket of clientSockets) socket.destroy();
    if (origin) await new Promise(resolve => origin.close(resolve));
    await delay(20);
    cleanup.fixturesStopped = !origin?.listening && sockets.size === 0 && clientSockets.size === 0;
    cleanup.openSockets = sockets.size + clientSockets.size;
    if (child?.pid) {
      const gone = () => child.exitCode !== null || child.signalCode !== null;
      const wait = async timeout => { const end = performance.now() + timeout; while (!gone() && performance.now() < end) await delay(20); return gone(); };
      try {
        if (!gone()) { cleanup.mode = 'SIGQUIT'; child.kill('SIGQUIT'); }
        if (!await wait(3000)) { cleanup.mode = 'SIGTERM'; signalGroup(child, 'SIGTERM'); }
        if (!await wait(1000)) { cleanup.mode = 'SIGKILL'; signalGroup(child, 'SIGKILL'); }
        await wait(1000); signalGroup(child, 'SIGKILL');
        cleanup.nativeStopped = gone(); cleanup.nativeExitCode = child.exitCode; cleanup.nativeSignal = child.signalCode;
        if (!gone()) cleanup.errors.push('Native master did not exit');
      } catch (error) { cleanup.errors.push(error.message); }
    }
    if (prefix) {
      try {
        const log = await readFile(path.join(prefix, 'error.log'), 'utf8');
        assert(Buffer.byteLength(log) <= 512 * 1024, 'Native error log exceeds fixture bound');
        evidence.nativeErrorLogRead = true; evidence.nativeLogTail = log.slice(-12000);
        for (const line of log.split('\n').filter(line => /\[(?:error|crit|alert|emerg)\]/.test(line))) {
          const rejectedSyntax = line.includes('unknown directive "x10_deliberately_invalid"');
          const containerGroups = process.geteuid?.() === 0 && line.includes(`initgroups(${os.userInfo().username}, 0) failed (1: Operation not permitted)`);
          if (rejectedSyntax || containerGroups) evidence.expectedNativeDiagnostics.push({ kind: rejectedSyntax ? 'deliberate-invalid-reload' : 'restricted-container-initgroups', line });
          else evidence.unexpectedNativeErrors.push(line);
        }
      } catch (error) { cleanup.errors.push(`Native log: ${error.message}`); }
      try { await rm(prefix, { recursive: true, force: true }); cleanup.temporaryRootRemoved = true; } catch (error) { cleanup.errors.push(error.message); }
    }
    try {
      evidence.identity.binaryUnchangedDuringTest = !!binary && hash(await readFile(binary)) === nativeBefore.binary;
      evidence.sourceUnchangedDuringTest = true;
      for (const [source, digest] of Object.entries(sourceBefore)) if (hash(await readFile(path.join(root, source))) !== digest) evidence.sourceUnchangedDuringTest = false;
      evidence.identity.harnessUnchangedDuringTest = hash(await readFile(fileURLToPath(import.meta.url))) === evidence.identity.harnessSha256;
      evidence.identity.observerUnchangedDuringTest = hash(await readFile(path.join(root, 'x10/control/listeners.mjs'))) === evidence.identity.observerSha256;
    } catch (error) { cleanup.errors.push(error.message); }
    evidence.cleanup = cleanup; evidence.childOutputTail = logTail;
    evidence.interrupted = interrupted; if (stopSignal) evidence.stopSignal = stopSignal;
    evidence.success &&= !interrupted && evidence.fixtureErrors.length === 0 && evidence.nativeErrorLogRead && evidence.unexpectedNativeErrors.length === 0 && cleanup.nativeStopped && cleanup.nativeExitCode === 0 &&
      cleanup.nativeSignal === null && cleanup.mode === 'SIGQUIT' && cleanup.fixturesStopped && cleanup.openSockets === 0 &&
      cleanup.temporaryRootRemoved && cleanup.errors.length === 0 && evidence.identity.binaryUnchangedDuringTest &&
      evidence.sourceUnchangedDuringTest && evidence.identity.harnessUnchangedDuringTest && evidence.identity.observerUnchangedDuringTest;
    evidence.finishedAt = new Date().toISOString();
    clearTimeout(deadline);
    process.removeListener('SIGINT', onInt); process.removeListener('SIGTERM', onTerm);
  }
  return evidence;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  let binary = process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'), output;
  try {
    for (let index = 2; index < process.argv.length; index++) {
      const option = process.argv[index];
      if (!['--binary', '--output'].includes(option) || !process.argv[index + 1]) throw new Error(`Unknown or incomplete option ${option}`);
      const value = process.argv[++index]; if (option === '--binary') binary = value; else output = path.resolve(value);
    }
    const result = await runHandover({ binary }); const text = JSON.stringify(result, null, 2) + '\n';
    if (output) await writeFile(output, text, { mode: 0o600 });
    process.stdout.write(text); process.exitCode = result.success ? 0 : 1;
  } catch (error) {
    process.stdout.write(JSON.stringify({ schemaVersion: 1, suite: 'native-reload-listener-observation', success: false, tests: [], skips: [], error: error.message }) + '\n');
    process.exitCode = 1;
  }
}
