#!/usr/bin/env node
// Existing optional native API on explicit isolated loopback TCP or Unix socket.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile);
const digest = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const quote = value => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
const sourceFiles = ['src/core/nginx.c', 'src/os/unix/ngx_control.c', 'src/os/unix/ngx_process.c',
  'src/os/unix/ngx_process_cycle.c', 'src/core/ngx_cycle.c', 'src/os/unix/ngx_control.h', 'src/os/unix/ngx_process.h'];

async function until(predicate, label, cancelled, timeout = 5000) {
  const end = performance.now() + timeout;
  let last;
  while (performance.now() < end) {
    if (cancelled()) throw new Error('Control API fixture interrupted');
    try { const result = await predicate(); if (result) return result; } catch (error) { last = error; }
    await delay(20);
  }
  throw new Error(`Timed out: ${label}${last ? `: ${last.message}` : ''}`);
}

async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port;
}

async function unusedPort() {
  const server = net.createServer(); const port = await listen(server);
  await new Promise(resolve => server.close(resolve)); return port;
}

function track(req, sockets) {
  req.on('socket', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
}

function request(options, sockets) {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...options, agent: false, headers: { connection: 'close' } }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => { bytes += chunk.length; if (bytes > 256 * 1024) req.destroy(new Error('Fixture response exceeds 256 KiB')); else chunks.push(chunk); });
      res.once('error', reject);
      res.once('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    const deadline = setTimeout(() => req.destroy(new Error('Fixture request absolute deadline')), 1200);
    track(req, sockets); req.once('close', () => clearTimeout(deadline)); req.once('error', reject); req.end();
  });
}

function hold(port, sockets) {
  const result = { ended: false, chunks: [] };
  let firstResolve, firstReject, doneResolve, doneReject;
  result.first = new Promise((resolve, reject) => { firstResolve = resolve; firstReject = reject; });
  result.done = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });
  result.first.catch(() => {}); result.done.catch(() => {});
  const failed = error => { firstReject(error); doneReject(error); };
  result.req = http.get({ host: '127.0.0.1', port, path: '/stream', agent: false }, res => {
    result.status = res.statusCode; result.revision = res.headers['x-x10-revision']; result.workerPid = Number(res.headers['x-x10-worker']);
    res.on('data', chunk => {
      result.chunks.push(chunk);
      const body = Buffer.concat(result.chunks);
      if (body.length > 4096) result.req.destroy(new Error('Held body exceeds limit'));
      else if (body.includes(10)) firstResolve(body.toString('utf8'));
    });
    res.once('error', failed); res.once('end', () => { result.ended = true; doneResolve(Buffer.concat(result.chunks).toString('utf8')); });
  });
  const deadline = setTimeout(() => result.req.destroy(new Error('Held response absolute deadline')), 20000);
  track(result.req, sockets); result.req.once('close', () => clearTimeout(deadline)); result.req.once('error', failed);
  return result;
}

async function procIdentity(procPid) {
  const dir = `/proc/${procPid}`;
  const [status, stat, executable, pidNamespace, networkNamespace] = await Promise.all([
    readFile(`${dir}/status`, 'utf8'), readFile(`${dir}/stat`, 'utf8'), readlink(`${dir}/exe`),
    readlink(`${dir}/ns/pid`), readlink(`${dir}/ns/net`),
  ]);
  const pids = /^NSpid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
  const fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
  const value = { procPid: Number(procPid), pid: pids?.at(-1), parentProcPid: Number(fields[1]), startTicks: fields[19],
    uid: Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]), executable, pidNamespace, networkNamespace };
  assert(Number.isSafeInteger(value.pid) && value.pid > 1 && /^[0-9]+$/.test(value.startTicks));
  assert(!['Z', 'X'].includes(fields[0]), 'Native process is not live'); return value;
}

async function resolvePid(pid, selected, parentProcPid) {
  const entries = (await readdir('/proc')).filter(name => /^[1-9][0-9]*$/.test(name));
  assert(entries.length <= 10000, 'Proc inventory exceeds fixture bound'); const found = [];
  for (let index = 0; index < entries.length; index += 32) {
    const values = await Promise.all(entries.slice(index, index + 32).map(async name => {
      try {
        const status = await readFile(`/proc/${name}/status`, 'utf8');
        if (Number(/^NSpid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).at(-1)) !== pid) return null;
        const value = await procIdentity(name);
        if (value.pidNamespace !== selected.pidNamespace || value.networkNamespace !== selected.networkNamespace
          || value.uid !== process.getuid() || value.executable !== selected.binary || value.parentProcPid !== parentProcPid) return null;
        return value;
      } catch (error) { if (['ENOENT', 'ESRCH', 'EACCES', 'EPERM'].includes(error.code)) return null; throw error; }
    }));
    found.push(...values.filter(Boolean));
  }
  assert.equal(found.length, 1, 'Native PID must uniquely map to owned process'); return found[0];
}

async function sameProcess(identity) { assert.deepEqual(await procIdentity(identity.procPid), identity, 'Native process identity changed'); }

async function unixListeners(master) {
  await sameProcess(master);
  const text = await readFile(`/proc/${master.procPid}/net/unix`, 'utf8');
  assert(Buffer.byteLength(text) <= 1024 * 1024, 'Unix table exceeds fixture bound');
  const listeners = text.trim().split('\n').slice(1).map(row => row.trim().split(/\s+/))
    .filter(fields => fields[3] === '00010000').map(fields => ({ inode: fields[6], path: fields.slice(7).join(' ') }));
  const files = await readdir(`/proc/${master.procPid}/fd`); assert(files.length <= 4096, 'Native fd count exceeds bound');
  const owned = new Set();
  for (const fd of files) {
    try { const inode = /^socket:\[(\d+)\]$/.exec(await readlink(`/proc/${master.procPid}/fd/${fd}`))?.[1]; if (inode) owned.add(inode); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  await sameProcess(master); return listeners.filter(item => owned.has(item.inode));
}

async function tcpListeners(master, port) {
  await sameProcess(master);
  const text = await readFile(`/proc/${master.procPid}/net/tcp`, 'utf8');
  assert(Buffer.byteLength(text) <= 1024 * 1024, 'TCP table exceeds fixture bound');
  const endpoint = `0100007F:${port.toString(16).toUpperCase().padStart(4, '0')}`;
  const matches = text.trim().split('\n').slice(1).map(row => row.trim().split(/\s+/))
    .filter(fields => fields[1] === endpoint && fields[3] === '0A').map(fields => fields[9]);
  const files = await readdir(`/proc/${master.procPid}/fd`); assert(files.length <= 4096);
  const owned = new Set();
  for (const fd of files) {
    try { const inode = /^socket:\[(\d+)\]$/.exec(await readlink(`/proc/${master.procPid}/fd/${fd}`))?.[1]; if (inode) owned.add(inode); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  await sameProcess(master); return matches.filter(inode => owned.has(inode));
}

function config(prefix, port, origin, revision, invalid = false) {
  const user = process.geteuid?.() === 0 ? `user ${quote(os.userInfo().username)};` : '';
  return `${user}
daemon off; master_process on; worker_processes 2;
worker_shutdown_timeout 15s;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log ${quote(path.join(prefix, 'error.log'))} notice;
events { worker_connections 128; }
http { access_log off;
 client_body_temp_path ${quote(path.join(prefix, 'body'))};
 proxy_temp_path ${quote(path.join(prefix, 'proxy'))};
 server { listen 127.0.0.1:${port}; server_name localhost;
 add_header X-X10-Worker $pid always;
 add_header X-X10-Revision ${revision} always;
 location = /revision { return 200 "${revision}"; }
 location = /stream { proxy_pass http://127.0.0.1:${origin}; proxy_buffering off; proxy_read_timeout 15s; }
 ${invalid ? 'x10_api_deliberately_invalid on;' : ''}
 }
}
`;
}

function signalGroup(child, signal) {
  if (!child?.pid) return;
  try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

async function stop(child) {
  const gone = () => child.exitCode !== null || child.signalCode !== null;
  const wait = async ms => { const end = performance.now() + ms; while (!gone() && performance.now() < end) await delay(20); return gone(); };
  let mode = 'SIGQUIT';
  if (!gone()) child.kill('SIGQUIT');
  if (!await wait(3000)) { mode = 'SIGTERM'; signalGroup(child, 'SIGTERM'); }
  if (!await wait(1000)) { mode = 'SIGKILL'; signalGroup(child, 'SIGKILL'); }
  await wait(1000); signalGroup(child, 'SIGKILL');
  return { mode, exited: gone(), exitCode: child.exitCode, signal: child.signalCode };
}

export async function runControlApi({ binary, transport = 'tcp', source = root, suite = 'native-control-api-baseline', expectedCases = 9, exercise }) {
  const report = { schemaVersion: 1, suite, startedAt: new Date().toISOString(),
    success: false, tests: [], skips: [], identity: {}, observations: {}, configurations: [], fixtureErrors: [],
    nativeErrorLogRead: false, unexpectedNativeErrors: [], expectedNativeDiagnostics: [], limitations: [
      'Existing opt-in native control API on explicit isolated loopback TCP or private Unix socket; no production service installed.',
      'Processes API exiting is master delivery state, not worker listener-close acknowledgment or complete generation identity.',
      'Reload success precedes fresh-worker readiness; probes and held-stream checks establish only the recorded observations.',
      'Linux/same-UID loopback fixture, not an auth/RBAC, platform, resource-exhaustion or complete protocol matrix.',
      'Configuration dump contains trusted synthetic fixture config only; real config APIs may disclose operator secrets.',
      'Source/binary consistency records are not signed build attestations or performance evidence.',
    ] };
  let prefix, child, origin, held, release, interrupted = false, signal, output = '';
  let beforeBinary, beforeSources = {}, master, socketPath;
  const clientSockets = new Set(), originSockets = new Set(), shutdowns = [];
  const add = (name, details = {}) => { if (interrupted) throw new Error('Control API fixture interrupted'); report.tests.push({ name, status: 'passed', ...details }); };
  const cancelled = () => interrupted;
  const cancel = which => { interrupted = true; signal = which; held?.req.destroy(new Error('Fixture interrupted')); for (const socket of clientSockets) socket.destroy(); };
  const onInt = () => cancel('SIGINT'), onTerm = () => cancel('SIGTERM');
  process.on('SIGINT', onInt); process.on('SIGTERM', onTerm);
  const deadline = setTimeout(() => cancel('deadline'), 30000);
  try {
    assert.equal(process.platform, 'linux', 'Linux fixture required');
    assert(['tcp', 'unix'].includes(transport), 'Transport must be tcp or unix');
    binary = await realpath(binary); source = await realpath(source); beforeBinary = digest(await readFile(binary));
    beforeSources = Object.fromEntries(await Promise.all(sourceFiles.map(async file => [file, digest(await readFile(path.join(source, file)))])));
    const { stderr: version } = await execute(binary, ['-V'], { timeout: 5000, maxBuffer: 128 * 1024 });
    assert(version.includes('--with-control-api'), 'Selected native binary lacks control API');
    const nativeVersion = /nginx version: nginx\/([^\s]+)/.exec(version)?.[1]; assert(nativeVersion);
    report.identity = { binary, sourceCheckout: source, binarySha256: beforeBinary, versionOutput: version, sourceFilesSha256: beforeSources,
      harnessSha256: digest(await readFile(fileURLToPath(import.meta.url))), node: process.version };
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-api-')); await chmod(prefix, 0o700);
    await mkdir(path.join(prefix, 'logs'), { mode: 0o700 }); socketPath = path.join(prefix, 'control.sock');
    const configPath = path.join(prefix, 'nginx.conf'), port = await unusedPort(), controlPort = await unusedPort();
    report.transport = { kind: transport, ...(transport === 'unix' ? { socketPath } : { host: '127.0.0.1', port: controlPort }), automaticFallback: false };
    const controlAddress = transport === 'unix' ? `unix:${socketPath}` : `127.0.0.1:${controlPort}`;
    report.options = { prefix, configPath, controlAddress, workerProcesses: 2, inheritedControlEnvironmentRemoved: true };
    origin = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' }); res.write('first:control-old\n');
      release = () => res.end('last:control-old\n');
    });
    origin.on('connection', socket => { originSockets.add(socket); socket.once('close', () => originSockets.delete(socket)); });
    const originPort = await listen(origin);
    const replace = async (revision, invalid = false) => {
      if (interrupted) throw new Error('Control API fixture interrupted');
      const bytes = config(prefix, port, originPort, revision, invalid), temporary = `${configPath}.next`;
      await writeFile(temporary, bytes, { mode: 0o600 }); await rename(temporary, configPath);
      report.configurations.push({ revision, invalid, sha256: digest(bytes), bytes: Buffer.byteLength(bytes) }); return bytes;
    };
    const initial = await replace('api-a');
    await execute(binary, ['-p', `${prefix}/`, '-c', configPath, '-t'], { timeout: 5000, maxBuffer: 128 * 1024 });
    add('native-profile-and-configuration-validation', { version: nativeVersion });
    const selected = { binary, pidNamespace: await readlink('/proc/self/ns/pid'), networkNamespace: await readlink('/proc/self/ns/net') };
    const selfProcPid = Number(await readlink('/proc/self'));
    const revision = async expected => {
      const response = await request({ host: '127.0.0.1', port, path: '/revision' }, clientSockets);
      assert.equal(response.status, 200); assert.equal(response.body, expected); assert.equal(response.headers['x-x10-revision'], expected);
      return response;
    };
    const start = async enabled => {
      if (interrupted) throw new Error('Control API fixture interrupted');
      const env = { ...process.env }; delete env.NGINX_CTRL;
      child = spawn(binary, ['-p', `${prefix}/`, '-c', configPath, ...(enabled ? ['-l', controlAddress] : [])],
        { detached: true, env, stdio: ['ignore', 'pipe', 'pipe'] });
      child.stdout.on('data', chunk => { output = (output + chunk).slice(-8192); }); child.stderr.on('data', chunk => { output = (output + chunk).slice(-8192); });
      child.once('error', error => report.fixtureErrors.push(error.message));
      await until(async () => {
        if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Native exited early: ${output}`);
        assert.equal(Number((await readFile(path.join(prefix, 'nginx.pid'), 'utf8')).trim()), child.pid);
        master = await resolvePid(child.pid, selected, selfProcPid);
        await revision('api-a'); return true;
      }, 'owned native master and revision', cancelled);
      process.stderr.write(`Control API fixture native started: pid=${master.pid} procPid=${master.procPid} enabled=${enabled}\n`);
    };
    await start(false);
    await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
    const implicit = await unixListeners(master); assert.deepEqual(implicit, []);
    assert.deepEqual(await tcpListeners(master, controlPort), []);
    report.observations.defaultDisabled = { master, ownedUnixListeners: implicit, inheritedControlEnvironmentRemoved: true };
    const firstShutdown = await stop(child); shutdowns.push(firstShutdown); child = null;
    assert.equal(firstShutdown.mode, 'SIGQUIT'); assert.equal(firstShutdown.exitCode, 0); assert.equal(firstShutdown.signal, null);
    add('control-api-is-not-opened-without-explicit-listen-option');
    await start(true); report.identity.master = master;
    const api = async (target, method = 'GET') => {
      if (interrupted) throw new Error('Control API fixture interrupted');
      await sameProcess(master);
      const response = await request({ ...(transport === 'unix' ? { socketPath } : { host: '127.0.0.1', port: controlPort }), path: target, method }, clientSockets);
      assert.equal(response.headers['content-type'], 'application/json');
      assert.equal(Number(response.headers['content-length']), Buffer.byteLength(response.body));
      await sameProcess(master); return { ...response, json: response.body ? JSON.parse(response.body) : null };
    };
    assert.equal((await lstat(prefix)).mode & 0o777, 0o700);
    if (transport === 'unix') {
      const stat = await lstat(socketPath); assert(stat.isSocket()); assert.equal(stat.uid, process.getuid()); assert.equal(stat.mode & 0o777, 0o600);
      const ownedUnix = await unixListeners(master); assert.equal(ownedUnix.length, 1); assert.equal(ownedUnix[0].path, socketPath);
      report.observations.socket = { path: socketPath, mode: '0600', ownerUid: stat.uid, ownedUnixListener: ownedUnix[0] };
    } else {
      await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
      const ownedTcp = await tcpListeners(master, controlPort); assert.equal(ownedTcp.length, 1);
      report.observations.socket = { host: '127.0.0.1', port: controlPort, ownedTcpListener: ownedTcp[0] };
    }
    if (exercise) {
      await exercise({ report, add, api, revision, replace, master, selected, configPath, prefix,
        until: (fn, label, timeout) => until(fn, label, cancelled, timeout),
        hold: () => { held = hold(port, clientSockets); return held; },
        release: () => { assert.equal(typeof release, 'function'); release(); },
        sameProcess, resolveWorker: pid => resolvePid(pid, selected, master.procPid),
        hup: async () => { await sameProcess(master); process.kill(master.pid, 'SIGHUP'); },
        killWorker: async identity => { await sameProcess(identity); assert.equal(identity.parentProcPid, master.procPid); process.kill(identity.pid, 'SIGKILL'); },
      });
    } else {
    const discovery = [];
    for (const [target, expected] of [['/', ['1']], ['/1', ['control', 'nginx']], ['/1/control', ['processes', 'config']]]) {
      const response = await api(target); assert.equal(response.status, 200);
      if (target === '/1/control' && response.json.includes('generations')) assert.deepEqual(response.json, [...expected, 'generations']);
      else assert.deepEqual(response.json, expected);
      discovery.push({ target, value: response.json });
    }
    add('explicit-isolated-control-listener-and-api-discovery', { discovery });
    const info = await api('/1/nginx'); assert.equal(info.status, 200); assert.equal(info.json.version, nativeVersion); assert.equal(typeof info.json.build, 'string');
    const processes = await api('/1/control/processes'); assert.equal(processes.status, 200); assert.equal(processes.json.length, 2);
    const workers = [];
    for (const item of processes.json) {
      assert.equal(item.name, 'worker process'); assert.equal(item.exiting, false); assert(Number.isSafeInteger(item.pid) && item.pid > 1);
      workers.push(await resolvePid(item.pid, selected, master.procPid));
    }
    const dump = await api('/1/control/config'); assert.equal(dump.status, 200); assert.equal(dump.json.length, 1);
    assert.equal(dump.json[0].name, configPath); assert.equal(dump.json[0].content, initial);
    report.observations.initial = { version: info.json, processes: processes.json, workerIdentities: workers, configSha256: digest(dump.json[0].content) };
    add('native-version-process-identities-and-active-configuration');
    const invalidRequests = [];
    for (const [target, method, status] of [['/1/nginx', 'POST', 405], ['/1/control/processes', 'PATCH', 405], ['/1/control/config', 'POST', 405], ['/1/not-present', 'GET', 404]]) {
      const response = await api(target, method); assert.equal(response.status, status); invalidRequests.push({ target, method, status });
    }
    add('unsupported-methods-and-unknown-path-are-rejected', { requests: invalidRequests });
    held = hold(port, clientSockets); assert.equal(await held.first, 'first:control-old\n');
    assert.equal(held.status, 200); assert.equal(held.revision, 'api-a'); assert(workers.some(worker => worker.pid === held.workerPid));
    add('accepted-old-response-is-held-before-control-reload', { workerPid: held.workerPid, revision: held.revision });
    process.stderr.write(`Control API fixture old response held: master=${master.pid} worker=${held.workerPid}\n`);
    const next = await replace('api-b'), reloaded = await api('/1/control/config', 'PATCH');
    assert.equal(reloaded.status, 200); assert(Array.isArray(reloaded.json.logs));
    const fresh = await until(async () => {
      const response = await revision('api-b'); assert(!workers.some(worker => worker.pid === Number(response.headers['x-x10-worker']))); return response;
    }, 'new native worker after control reload', cancelled);
    const during = await until(async () => {
      const response = await api('/1/control/processes'); assert.equal(response.status, 200);
      const old = response.json.find(item => item.pid === held.workerPid); assert.equal(old?.exiting, true);
      assert(response.json.some(item => item.exiting === false && !workers.some(worker => worker.pid === item.pid))); return response.json;
    }, 'master-reported old exiting and new live workers', cancelled);
    assert.equal(held.ended, false); await sameProcess(workers.find(worker => worker.pid === held.workerPid));
    report.observations.reload = { status: reloaded.status, logs: reloaded.json.logs, freshWorkerPid: Number(fresh.headers['x-x10-worker']), processesDuringDrain: during, oldResponseStillHeld: true };
    add('control-patch-reload-starts-new-workers-with-old-response-alive');
    await replace('api-invalid', true);
    const rejected = await api('/1/control/config', 'PATCH'); assert.equal(rejected.status, 422);
    assert(rejected.json.logs.some(line => line.includes('unknown directive "x10_api_deliberately_invalid"')));
    for (let i = 0; i < 4; i++) await revision('api-b');
    const retained = await api('/1/control/config'); assert.equal(retained.status, 200); assert.equal(retained.json[0].content, next);
    assert.equal(held.ended, false);
    report.observations.rejected = { status: rejected.status, logs: rejected.json.logs, retainedConfigSha256: digest(retained.json[0].content), freshRevision: 'api-b', oldResponseStillHeld: true };
    add('invalid-control-reload-retains-active-workers-and-config-dump');
    await replace('api-b'); assert.equal(typeof release, 'function'); release();
    const completed = await held.done; assert.equal(completed, 'first:control-old\nlast:control-old\n');
    add('accepted-old-response-completes-exactly-after-both-reload-attempts', { body: completed });
    }
    report.success = true;
  } catch (error) { report.error = error.stack || error.message; }
  finally {
    held?.req.destroy(); try { release?.(); } catch {}
    for (const socket of clientSockets) socket.destroy(); for (const socket of originSockets) socket.destroy();
    if (origin) await new Promise(resolve => origin.close(resolve));
    if (child) { try { shutdowns.push(await stop(child)); } catch (error) { report.fixtureErrors.push(error.message); } }
    await delay(30);
    const cleanup = { nativeStopped: shutdowns.length > 0 && shutdowns.every(item => item.exited), shutdowns,
      fixturesStopped: !origin?.listening && clientSockets.size === 0 && originSockets.size === 0,
      openSockets: clientSockets.size + originSockets.size, temporaryRootRemoved: false, errors: [] };
    if (prefix) {
      try {
        const log = await readFile(path.join(prefix, 'error.log'), 'utf8'); assert(Buffer.byteLength(log) <= 512 * 1024, 'Native log limit exceeded');
        report.nativeErrorLogRead = true; report.nativeLogTail = log.slice(-12000);
        for (const line of log.split('\n').filter(value => /\[(?:error|crit|alert|emerg)\]/.test(value))) {
          const rejected = line.includes('unknown directive "x10_api_deliberately_invalid"');
          const container = process.geteuid?.() === 0 && line.includes(`initgroups(${os.userInfo().username}, 0) failed (1: Operation not permitted)`);
          const deliberateKill = report.observations.expectedWorkerTermination?.signal === 9
            && new RegExp(`worker process ${report.observations.expectedWorkerTermination.pid} exited on signal 9$`).test(line);
          if (rejected || container || deliberateKill) report.expectedNativeDiagnostics.push({ kind: rejected ? 'deliberate-invalid-reload' : container ? 'restricted-container-initgroups' : 'deliberate-worker-respawn', line });
          else report.unexpectedNativeErrors.push(line);
        }
      } catch (error) { cleanup.errors.push(error.message); }
      try { await rm(prefix, { recursive: true, force: true }); cleanup.temporaryRootRemoved = true; } catch (error) { cleanup.errors.push(error.message); }
    }
    try {
      report.identity.binaryUnchangedDuringTest = !!beforeBinary && digest(await readFile(binary)) === beforeBinary;
      report.sourceUnchangedDuringTest = sourceFiles.length === Object.keys(beforeSources).length;
      for (const file of sourceFiles) if (digest(await readFile(path.join(source, file))) !== beforeSources[file]) report.sourceUnchangedDuringTest = false;
      report.identity.harnessUnchangedDuringTest = digest(await readFile(fileURLToPath(import.meta.url))) === report.identity.harnessSha256;
    } catch (error) { cleanup.errors.push(error.message); }
    report.cleanup = cleanup; report.interrupted = interrupted; if (signal) report.stopSignal = signal; report.childOutputTail = output;
    report.success &&= !interrupted && report.tests.length === expectedCases && report.fixtureErrors.length === 0 && cleanup.nativeStopped &&
      shutdowns.length === 2 && shutdowns.every(item => item.mode === 'SIGQUIT' && item.exitCode === 0 && item.signal === null) &&
      cleanup.fixturesStopped && cleanup.openSockets === 0 && cleanup.temporaryRootRemoved && cleanup.errors.length === 0 &&
      report.nativeErrorLogRead && report.unexpectedNativeErrors.length === 0 && report.identity.binaryUnchangedDuringTest &&
      report.sourceUnchangedDuringTest && report.identity.harnessUnchangedDuringTest;
    report.finishedAt = new Date().toISOString(); clearTimeout(deadline);
    process.removeListener('SIGINT', onInt); process.removeListener('SIGTERM', onTerm);
  }
  return report;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  let binary = process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'), output, transport = 'tcp', source = root;
  try {
    for (let i = 2; i < process.argv.length; i++) {
      const option = process.argv[i]; if (!['--binary', '--output', '--transport', '--source'].includes(option) || !process.argv[i + 1]) throw new Error(`Unknown/incomplete option ${option}`);
      const value = process.argv[++i]; if (option === '--binary') binary = value; else if (option === '--transport') transport = value; else if (option === '--source') source = value; else output = path.resolve(value);
    }
    const result = await runControlApi({ binary, transport, source }); const text = JSON.stringify(result, null, 2) + '\n';
    if (output) await writeFile(output, text, { mode: 0o600 }); process.stdout.write(text); process.exitCode = result.success ? 0 : 1;
  } catch (error) {
    process.stdout.write(JSON.stringify({ schemaVersion: 1, suite: 'native-control-api-baseline', success: false, tests: [], skips: [], error: error.message }) + '\n'); process.exitCode = 1;
  }
}
