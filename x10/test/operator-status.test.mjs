import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, lstat, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { initialize, bind, apply, status, inspectGenerations } from '../control/manager.mjs';
import { generationEndpoint, inspectNativeGenerations, validateGenerations } from '../control/generations.mjs';
import { formatStatus, formatStatusError } from '../control/status-format.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const transport = process.env.X10_STATUS_TRANSPORT || 'tcp';
const execute = promisify(execFile), digest = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const clone = value => structuredClone(value);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function unusedPort() { const server = net.createServer(); const port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function absent(file) {
  try { await lstat(file); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; }
}
async function until(fn) {
  const end = performance.now() + 6000; let last;
  while (performance.now() < end) { try { const value = await fn(); if (value) return value; } catch (error) { last = error; } await delay(25); }
  throw last || new Error('Operator fixture readiness deadline');
}
async function selfBinding() {
  const status = await readFile('/proc/self/status', 'utf8'), stat = await readFile('/proc/self/stat', 'utf8');
  const pids = /^NSpid:\s+([0-9\t ]+)$/m.exec(status)[1].trim().split(/\s+/).map(Number);
  const command = (await readFile('/proc/self/cmdline', 'utf8')).split('\0')[0];
  return { pid: pids.at(-1), procPid: pids[0], uid: process.getuid(), executable: await readlink('/proc/self/exe'),
    startTicks: stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/)[19], pidNamespace: await readlink('/proc/self/ns/pid'), commandSha256: digest(command) };
}
function sample(masterPid = 200) { return { scope: 'master-process', master_pid: masterPid, current_generation: '9007199254740993', available: true,
  reason: '', excluded_detached: 0, processes: [{ name: 'worker process', pid: masterPid + 1, slot: 0,
    generation: '9007199254740993', birth: '18446744073709551615', exiting: false, exited: false }] }; }

test('operator status and explicit bound native generation inspection', { timeout: 45000 }, async t => {
  assert(['tcp', 'unix'].includes(transport), 'X10_STATUS_TRANSPORT must explicitly be tcp or unix');
  const files = ['x10/control/cli.mjs', 'x10/control/manager.mjs', 'x10/control/generations.mjs', 'x10/control/status-format.mjs', 'x10/test/operator-status.test.mjs'];
  const sourceFilesSha256 = Object.fromEntries(await Promise.all(files.map(async f => [f, digest(await readFile(path.join(root, f)))])));
  const report = { schemaVersion: 1, suite: 'native-operator-status', startedAt: new Date().toISOString(), transport,
    binary, binarySha256: digest(await readFile(binary)), sourceFilesSha256, tests: [], passed: false,
    limitations: ['Linux trusted-local-operator diagnostics, not remote authentication or production readiness.',
      'Human status presents existing revision-header observations; it does not add application health or drain checks.',
      'Native generations describe master bookkeeping, not worker readiness or listener closure.',
      'Synthetic reply/schema/HTTP-error controls are distinct from actual native control API runs.'] };
  let prefix, native, backend, fake, state, snapshot, cancelled = false, nativeOutput = '';
  const sockets = new Set();
  const track = server => server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const interrupted = () => { cancelled = true; for (const socket of sockets) socket.destroy(); if (native?.pid) { try { process.kill(-native.pid, 'SIGTERM'); } catch {} } };
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  const check = async (name, fn) => t.test(name, async () => {
    const started = performance.now();
    try { assert.equal(cancelled, false); const detail = await fn(); report.tests.push({ name, passed: true, elapsedMs: Math.round(performance.now() - started), ...(detail ? { detail } : {}) }); }
    catch (error) { report.tests.push({ name, passed: false, error: error.message }); throw error; }
  });
  const cli = async (...args) => {
    try { const run = await execute(process.execPath, [path.join(root, 'x10/control/cli.mjs'), ...args], { timeout: 6000, maxBuffer: 1024 * 1024 }); return { code: 0, ...run }; }
    catch (error) { if (Number.isInteger(error.code)) return { code: error.code, stdout: error.stdout, stderr: error.stderr }; throw error; }
  };
  const stateBytes = async () => Object.fromEntries(await Promise.all(['settings.json', 'state.json', 'history.jsonl'].map(async file => [file, digest(await readFile(path.join(state, file)))])));
  try {
    await check('uint64-identities-retain-values-beyond-javascript-number-precision', () => {
      const value = sample(); assert.equal(validateGenerations(value, 200), value); assert.equal(value.processes[0].birth, '18446744073709551615');
      const exhausted = { ...value, available: false, reason: 'counter_exhausted', current_generation: null,
        processes: value.processes.map(p => ({ ...p, generation: null, birth: null })) };
      assert.equal(validateGenerations(exhausted, 200), exhausted);
      const partial = { ...value, available: false, reason: 'unclassified_process', processes: value.processes.map(p => ({ ...p, generation: null })) };
      assert.equal(validateGenerations(partial, 200), partial);
    });
    const badSchemas = [
      ['numeric counter', d => d.current_generation = 9007199254740992],
      ['leading zero', d => d.processes[0].birth = '01'],
      ['uint64 overflow', d => d.processes[0].birth = '18446744073709551616'],
      ['wrong master PID', d => d.master_pid = 201],
      ['child is master', d => d.processes[0].pid = 200],
      ['duplicate birth', d => d.processes.push({ ...d.processes[0], pid: 202, slot: 1 })],
      ['duplicate slot', d => d.processes.push({ ...d.processes[0], pid: 202, birth: '3' })],
      ['future child generation', d => d.processes[0].generation = '9007199254740994'],
      ['false available null identity', d => d.processes[0].generation = null],
      ['unavailable contradicts reason', d => d.available = false],
      ['exhausted still exposes IDs', d => { d.available = false; d.reason = 'counter_exhausted'; }],
      ['classified generation without birth', d => { d.available = false; d.reason = 'unclassified_process'; d.processes[0].birth = null; }],
      ['nonboolean flags', d => d.processes[0].exiting = 1],
      ['excess processes', d => d.excluded_detached = 1024],
      ['unknown envelope field', d => d.ready = true],
      ['control characters in name', d => d.processes[0].name = 'worker\u001b[31m'],
    ];
    for (const [label, mutate] of badSchemas) await check(`schema-refuses-${label.replaceAll(' ', '-')}`, () => {
      const d = sample(); mutate(d); assert.throws(() => validateGenerations(d, 200), { code: 'generation_schema' });
    });
    await check('endpoint-options-refuse-remote-ambiguous-and-noncanonical-targets', () => {
      for (const value of [{}, { controlAddress: 'localhost:1234' }, { controlAddress: '192.0.2.1:1234' },
        { controlAddress: '127.0.0.1:65536' }, { controlAddress: '127.0.0.1:1/path' }, { controlSocket: 'relative.sock' },
        { controlSocket: '/tmp/a/../b.sock' }, { controlSocket: '/tmp/a.sock', controlAddress: '127.0.0.1:1234' }])
        assert.throws(() => generationEndpoint(value), { code: 'generation_endpoint' });
    });
    await check('human-status-marks-mismatch-pending-and-errors-without-health-claim', () => {
      const formatted = formatStatus({ ok: true, state: '/private/prefix/.x10-control', lastConfirmedRevision: 'a'.repeat(32),
        binding: { pid: 10, procPid: 100 }, runtime: { identityValid: true, observedRevision: 'b'.repeat(32), error: null },
        configUnchanged: false, fragmentMatchesLastConfirmed: true, pending: { stage: 'installed' }, history: { integrity: true, entries: 4 } });
      assert.match(formatted, /MISMATCH/); assert.match(formatted, /PENDING/); assert.match(formatted, /Operator config: CHANGED/);
      assert.match(formatted, /Health and listener drain: not checked/); assert.match(formatted, /recover/); assert.doesNotMatch(formatted, /healthy/i);
      const error = formatStatusError({ code: 'locked', error: '\u001b[31mlock exists' });
      assert.match(error, /exact process exited/); assert.doesNotMatch(error, /\u001b/);
    });
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-status-')); await chmod(prefix, 0o700);
    backend = track(http.createServer((req, res) => { res.writeHead(200); res.end('healthy'); }));
    const healthPort = await listen(backend), port = await unusedPort(), apiPort = transport === 'tcp' ? await unusedPort() : null;
    const controlSocket = path.join(prefix, 'control.sock');
    const endpoint = transport === 'unix' ? { controlSocket } : { controlAddress: `127.0.0.1:${apiPort}` };
    const endpointArgs = transport === 'unix' ? ['--control-socket', controlSocket] : ['--control-address', endpoint.controlAddress];
    const config = path.join(prefix, 'nginx.conf');
    await writeFile(config, `${process.getuid() === 0 ? `user ${os.userInfo().username};` : ''}\ndaemon off; master_process on; worker_processes 1;\npid ${prefix}/nginx.pid;\nerror_log ${prefix}/error.log notice;\nevents { worker_connections 128; }\nhttp { access_log off; client_body_temp_path ${prefix}/body; proxy_temp_path ${prefix}/proxy;\ninclude ${prefix}/managed.conf;\n}\n`, { mode: 0o600 });
    const input = text => ({ serverBody: `location / { return 200 "${text}"; }`, healthURL: `http://127.0.0.1:${healthPort}/healthy` });
    const initial = await initialize({ prefix, binary, port }, input('A')); state = initial.state;
    await check('status-json-compatible-and-human-unbound-is-actionable', async () => {
      const json = await cli('status', '--state', state), human = await cli('status', '--state', state, '--human');
      assert.equal(json.code, 0); const data = JSON.parse(json.stdout); assert.equal(data.ok, true); assert.equal(data.binding, null);
      assert.equal(human.code, 0); assert.match(human.stdout, /Master: unbound/); assert.match(human.stdout, /then run bind/);
      assert.match(human.stdout, /Health and listener drain: not checked/); assert.equal(json.stderr + human.stderr, '');
    });
    native = spawn(binary, ['-p', `${prefix}/`, '-c', config, '-l', transport === 'unix' ? `unix:${controlSocket}` : endpoint.controlAddress], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    native.stdout.on('data', data => nativeOutput = (nativeOutput + data).slice(-8192)); native.stderr.on('data', data => nativeOutput = (nativeOutput + data).slice(-8192));
    await until(async () => { try { return (await bind(state)).ok; } catch (error) { if (native.exitCode !== null || native.signalCode !== null) throw new Error(`Native exited: ${nativeOutput}`); if (error.code === 'already_bound') return true; return false; } });
    await check('actual-native-generation-query-is-bound-to-endpoint-inode-and-local-master-pid', async () => {
      const inspected = await inspectGenerations(state, endpoint); assert.equal(inspected.ok, true);
      const observed = inspected.observation; assert.equal(observed.native.current_generation, '1'); assert.equal(observed.native.available, true);
      assert.equal(observed.native.master_pid, native.pid); assert.equal(observed.masterBinding.pid, native.pid);
      assert.match(observed.endpointIdentity.inode, /^[1-9][0-9]*$/); assert.equal(observed.diagnosticOnly, true);
      report.nativeObservation = observed;
      return { localMasterPid: native.pid, procMasterPid: observed.masterBinding.procPid, transport };
    });
    await check('actual-cli-json-generation-inspection-and-human-bound-status', async () => {
      const result = await cli('inspect-generations', '--state', state, ...endpointArgs); assert.equal(result.code, 0, result.stdout);
      const data = JSON.parse(result.stdout); assert.equal(data.observation.native.master_pid, native.pid);
      const json = await cli('status', '--state', state), human = await cli('status', '--state', state, '--human');
      assert.equal(json.code, human.code); assert.equal(json.code, 0); assert.equal(JSON.parse(json.stdout).runtime.identityValid, true);
      assert.match(human.stdout, /matches last confirmed revision/); assert.match(human.stdout, /Health and listener drain: not checked/);
    });
    await check('generation-inspection-does-not-mutate-controller-journal-or-config', async () => {
      const before = await stateBytes(), configBefore = digest(await readFile(config)); await inspectGenerations(state, endpoint);
      assert.deepEqual(await stateBytes(), before); assert.equal(digest(await readFile(config)), configBefore);
    });
    await check('apply-retains-existing-behavior-and-native-generation-advances', async () => {
      const applied = await apply(state, input('B')); assert.equal(applied.outcome, 'applied');
      const result = await inspectGenerations(state, endpoint); assert.equal(result.observation.native.current_generation, '2');
      assert.equal((await status(state)).lastConfirmedRevision, applied.revision);
    });
    await check('foreign-local-endpoint-is-refused-before-any-http-request', async () => {
      let receipts = 0; fake = track(http.createServer((req, res) => { receipts++; res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(sample(native.pid))); }));
      const fakePort = await listen(fake);
      await assert.rejects(inspectGenerations(state, { controlAddress: `127.0.0.1:${fakePort}` }), { code: 'generation_endpoint' });
      assert.equal(receipts, 0); await new Promise(resolve => fake.close(resolve)); fake = null;
    });
    await check('wrong-native-listener-and-unresolved-transaction-do-not-pass', async () => {
      await assert.rejects(inspectGenerations(state, { controlAddress: `127.0.0.1:${port}` }), { code: 'generation_schema' });
      const confirmed = (await status(state)).lastConfirmedRevision, pendingFile = path.join(state, 'pending.json');
      await writeFile(pendingFile, JSON.stringify({ schemaVersion: 1, previous: confirmed, candidate: confirmed, stage: 'prepared' }), { mode: 0o600 });
      try { await assert.rejects(inspectGenerations(state, endpoint), { code: 'pending' }); }
      finally { await rm(pendingFile); }
    });
    await check('human-option-cannot-turn-apply-into-an-unintended-write', async () => {
      const before = await stateBytes(); const invalid = await cli('apply', '--state', state, '--human');
      assert.equal(invalid.code, 1); assert.equal(JSON.parse(invalid.stdout).ok, false); assert.deepEqual(await stateBytes(), before);
    });
    await check('bounded-http-schema-and-deadline-controls-use-synthetic-owned-replies', async () => {
      // This is a module-boundary fixture using this test process's actual OS
      // lifetime/owned socket. Production CLI additionally requires a native master.
      const self = await selfBinding(); let mode = 'invalid-json', trickle;
      fake = track(http.createServer((req, res) => {
        assert.equal(req.method, 'GET'); assert.equal(req.url, '/1/control/generations');
        if (mode === 'missing-endpoint') { res.writeHead(404); res.end(); return; }
        res.writeHead(200, { 'content-type': 'application/json' });
        if (mode === 'invalid-json') res.end('{invalid');
        if (mode === 'invalid-utf8') res.end(Buffer.from([0xff]));
        if (mode === 'oversized') res.end('x'.repeat(512 * 1024 + 1));
        if (mode === 'trickle') { res.write('{'); trickle = setInterval(() => res.write(' '), 40); res.once('close', () => clearInterval(trickle)); }
        if (mode === 'wrong-master') res.end(JSON.stringify(sample(self.pid + 1)));
        if (mode === 'unclassified') res.end(JSON.stringify({ ...sample(self.pid), available: false, reason: 'unclassified_process',
          processes: sample(self.pid).processes.map(p => ({ ...p, generation: null })) }));
        if (mode === 'endpoint-closed') { res.end(JSON.stringify(sample(self.pid))); fake.close(); }
        if (mode === 'valid') res.end(JSON.stringify(sample(self.pid)));
      }));
      const fakePort = await listen(fake), own = { controlAddress: `127.0.0.1:${fakePort}` };
      try {
        for (mode of ['invalid-json', 'invalid-utf8', 'oversized', 'wrong-master']) await assert.rejects(inspectNativeGenerations(own, self), { code: 'generation_schema' });
        mode = 'missing-endpoint'; await assert.rejects(inspectNativeGenerations(own, self), { code: 'generation_unavailable' });
        mode = 'trickle'; const started = performance.now(); await assert.rejects(inspectNativeGenerations(own, self), { code: 'generation_timeout' });
        assert(performance.now() - started < 3000, 'trickle response cannot extend the absolute request deadline');
        mode = 'unclassified'; const partial = await inspectNativeGenerations(own, self);
        assert.equal(partial.native.available, false); assert.equal(partial.native.processes[0].generation, null);
        mode = 'valid'; assert.equal((await inspectNativeGenerations(own, self)).native.master_pid, self.pid);
        mode = 'endpoint-closed'; await assert.rejects(inspectNativeGenerations(own, self), { code: 'generation_endpoint' });
      } finally { clearInterval(trickle); fake.closeAllConnections(); if (fake.listening) await new Promise(resolve => fake.close(resolve)); fake = null; }
    });
    await check('stopped-master-is-shown-stale-and-generation-query-fails-closed', async () => {
      const exited = once(native, 'exit'); native.kill('SIGQUIT'); await exited;
      const human = await cli('status', '--state', state, '--human'); assert.equal(human.code, 0);
      assert.match(human.stdout, /identity not verified/); assert.match(human.stdout, /Runtime observation error/);
      const query = await cli('inspect-generations', '--state', state, ...endpointArgs); assert.equal(query.code, 1); assert.equal(JSON.parse(query.stdout).ok, false);
    });
    report.passed = report.tests.every(result => result.passed) && !cancelled;
  } finally {
    if (native && native.exitCode === null && native.signalCode === null) {
      native.kill('SIGQUIT'); const end = performance.now() + 3000;
      while (native.exitCode === null && native.signalCode === null && performance.now() < end) await delay(20);
      if (native.exitCode === null && native.signalCode === null) {
        native.kill('SIGKILL'); const killed = performance.now() + 1000;
        while (native.exitCode === null && native.signalCode === null && performance.now() < killed) await delay(20);
      }
    }
    if (native?.pid) { try { process.kill(-native.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
    for (const socket of sockets) socket.destroy();
    for (const server of [fake, backend]) if (server?.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    if (prefix) await rm(prefix, { recursive: true, force: true }); await delay(20);
    report.cleanup = { nativeStopped: !native || native.exitCode !== null || native.signalCode !== null, nativeExitCode: native?.exitCode ?? null,
      nativeSignal: native?.signalCode ?? null, openSockets: sockets.size, temporaryRootRemoved: !prefix || await absent(prefix),
      fixturesStopped: !fake?.listening && !backend?.listening };
    report.binaryUnchangedDuringTest = digest(await readFile(binary)) === report.binarySha256;
    report.sourceUnchangedDuringTest = (await Promise.all(files.map(async f => digest(await readFile(path.join(root, f))) === sourceFilesSha256[f]))).every(Boolean);
    report.passed &&= report.cleanup.nativeStopped && report.cleanup.nativeExitCode === 0 && report.cleanup.nativeSignal === null
      && report.cleanup.openSockets === 0 && report.cleanup.temporaryRootRemoved && report.cleanup.fixturesStopped && report.binaryUnchangedDuringTest && report.sourceUnchangedDuringTest;
    report.finishedAt = new Date().toISOString();
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted);
    if (process.env.X10_OPERATOR_STATUS_EVIDENCE) await writeFile(path.resolve(process.env.X10_OPERATOR_STATUS_EVIDENCE), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    assert.equal(report.passed, true, nativeOutput);
  }
});
