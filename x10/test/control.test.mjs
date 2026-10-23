import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { initialize, bind, apply, revert, recover, status, history } from '../control/manager.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(fn, timeout = 6000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { const result = await fn(); if (result) return result; } catch (error) { last = error; }
    await delay(25);
  }
  throw last || new Error('Fixture readiness timed out');
}
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function unusedPort() { const server = net.createServer(); const port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
function get(port, target = '/') {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: target, agent: false }, res => {
      let body = ''; res.setEncoding('utf8'); res.on('data', chunk => body += chunk);
      res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode, body, revision: res.headers['x-x10-revision'] }));
    });
    req.setTimeout(1000, () => req.destroy(new Error('Fixture request timed out'))); req.on('error', reject);
  });
}
async function stop(child) {
  if (!child) return null;
  const exited = () => child.exitCode !== null || child.signalCode !== null;
  const wait = async n => { const end = Date.now() + n; while (!exited() && Date.now() < end) await delay(20); return exited(); };
  if (!exited()) { child.kill('SIGQUIT'); if (!await wait(3000)) { child.kill('SIGTERM'); if (!await wait(1000)) { child.kill('SIGKILL'); await wait(1000); } } }
  try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  return { exitCode: child.exitCode, signal: child.signalCode };
}

test('native managed fragment transactions and failure boundaries', { timeout: 45000 }, async t => {
  const report = { schemaVersion: 1, suite: 'native-local-control', startedAt: new Date().toISOString(), binary, binarySha256: digest(await readFile(binary)), tests: [], limitations: [
    'Linux/local trusted-operator tool; one managed loopback HTTP server, no remote administration or general nginx.conf editing.',
    'Native -t/reload can have early filesystem/shared-resource side effects; successful sampled probes are not ACID or a proof about every worker.',
    'Same-uid adversarial filesystem mutation and the residual identity-check-to-kill PID-reuse race are outside the security boundary.',
    'Recovery test kills a real CLI during a pending transaction; stale lock removal is an explicit operator step after confirmed process exit.',
  ] };
  let prefix, child, backend, cliChild, childOutput = '';
  const interrupted = () => {
    report.interrupted = true;
    // Native master has its own group. Relay cancellation to that exact group
    // before a supervising test runner escalates termination of this process.
    if (child?.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code === 'ESRCH') child.kill('SIGTERM'); } }
    if (cliChild && cliChild.exitCode === null && cliChild.signalCode === null) cliChild.kill('SIGTERM');
    backend?.closeAllConnections();
  };
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  const check = async (name, fn) => t.test(name, async () => { assert.equal(report.interrupted, undefined, 'fixture was cancelled'); await fn(); report.tests.push({ name, passed: true }); });
  try {
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-control-')); await chmod(prefix, 0o700);
    await mkdir(path.join(prefix, 'logs'), { mode: 0o700 });
    const healthRequests = { healthy: 0, unhealthy: 0 }, healthMethods = [];
    let activeTrickles = 0, healthGate = null;
    backend = http.createServer((req, res) => {
      healthMethods.push(req.method);
      if (req.method !== 'GET') { res.writeHead(405); res.end('method must be GET'); return; }
      if (req.url === '/trickle') {
        activeTrickles++; res.writeHead(200); res.flushHeaders(); res.write('x');
        const timer = setInterval(() => res.write('x'), 50);
        res.once('close', () => { clearInterval(timer); activeTrickles--; });
        return;
      }
      if (req.url === '/gated' && healthGate) {
        healthGate.requests++;
        if (healthGate.released) { res.writeHead(200); res.end('healthy'); }
        else { healthGate.responses.add(res); res.once('close', () => healthGate?.responses.delete(res)); }
        return;
      }
      const healthy = req.url === '/healthy'; healthRequests[healthy ? 'healthy' : 'unhealthy']++;
      res.writeHead(healthy ? 200 : 503, healthy ? { 'cache-control': 'public, max-age=3600' } : {});
      res.end(healthy ? 'healthy' : 'unhealthy');
    });
    const healthPort = await listen(backend), port = await unusedPort();
    const configPath = path.join(prefix, 'nginx.conf'), fragmentPath = path.join(prefix, 'managed.conf');
    const config = `${process.getuid() === 0 ? `user ${os.userInfo().username};` : ''}
daemon off; master_process on; worker_processes 1;
pid ${prefix}/nginx.pid;
error_log ${prefix}/error.log notice;
events { worker_connections 128; }
http { access_log off;
client_body_temp_path ${prefix}/body;
proxy_temp_path ${prefix}/proxy;
proxy_cache_path ${prefix}/cache keys_zone=x10_control_health:1m;
proxy_cache x10_control_health;
proxy_cache_key $request_uri;
proxy_cache_valid 200 1h;
proxy_method POST;
proxy_ignore_client_abort on;
include ${fragmentPath};
}
`;
    await writeFile(configPath, config, { mode: 0o600 });
    const input = text => ({ serverBody: `location / { return 200 "${text}"; }`, healthURL: `http://127.0.0.1:${healthPort}/healthy` });
    const init = await initialize({ prefix, binary, port, gateTimeoutMs: 1000 }, input('A'));
    const state = init.state, initial = init.revision;
    await check('initialization-is-unbound-and-keeps-operator-config', async () => {
      assert.equal((await status(state)).binding, null); assert.equal(await readFile(configPath, 'utf8'), config);
      await assert.rejects(apply(state, input('B')), { code: 'unbound' });
    });
    child = spawn(binary, ['-p', `${prefix}/`, '-c', configPath], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data => childOutput += data.toString()); child.stderr.on('data', data => childOutput += data.toString());
    await waitFor(async () => (await get(port)).body === 'A');
    await check('bind-verifies-native-master-pid-namespace-and-fresh-health', async () => {
      assert.equal((await bind(state)).outcome, 'bound');
      const s = await status(state); assert.equal(s.runtime.identityValid, true); assert.equal(s.runtime.observedRevision, initial);
      assert.ok(s.binding.pid >= 2); assert.ok(s.binding.procPid >= 2); assert.match(s.binding.pidNamespace, /^pid:\[/);
      report.runtimeIdentity = { pidNamespaceMappingVerified: true, masterMode: true };
      assert.ok(healthMethods.length >= 2); assert.ok(healthMethods.every(method => method === 'GET'));
    });
    let applied;
    await check('valid-apply-acknowledges-new-native-revision', async () => {
      applied = await apply(state, input('B')); assert.equal(applied.outcome, 'applied'); assert.notEqual(applied.revision, initial);
      await waitFor(async () => (await get(port)).body === 'B'); assert.equal((await status(state)).runtime.observedRevision, applied.revision);
    });
    await check('invalid-native-config-is-rejected-without-runtime-switch', async () => {
      const before = await readFile(fragmentPath);
      const result = await apply(state, { ...input('unused'), serverBody: 'location / { x10_nonexistent_directive on; }' });
      assert.equal(result.outcome, 'rejected'); assert.deepEqual(await readFile(fragmentPath), before);
      assert.equal((await get(port)).body, 'B'); assert.equal((await status(state)).lastConfirmedRevision, applied.revision);
    });
    await check('health-failure-rolls-back-with-a-fresh-activation-id', async () => {
      assert.ok(healthRequests.healthy >= 2, 'initial health must reach the real cacheable origin more than once');
      const badBefore = healthRequests.unhealthy;
      const result = await apply(state, { ...input('bad'), healthURL: `http://127.0.0.1:${healthPort}/unhealthy` });
      assert.equal(result.outcome, 'rolled_back'); assert.equal(result.ok, false); assert.equal(result.restoredContentFrom, applied.revision);
      assert.notEqual(result.revision, applied.revision); assert.notEqual(result.revision, result.failedRevision);
      await waitFor(async () => (await get(port)).body === 'B'); assert.equal((await status(state)).runtime.observedRevision, result.revision);
      assert.ok(healthRequests.unhealthy > badBefore, 'new health must reach unhealthy origin despite the inherited URI-keyed cache');
      applied = result;
    });
    await check('trickle-health-cannot-hold-lock-past-bounded-gate', async () => {
      const start = Date.now();
      const result = await apply(state, { ...input('trickling'), healthURL: `http://127.0.0.1:${healthPort}/trickle` });
      assert.equal(result.outcome, 'rolled_back'); assert.ok(Date.now() - start < 6000, 'absolute probe deadlines must bound the failed gate and rollback');
      await waitFor(() => activeTrickles === 0, 2000);
      await waitFor(async () => (await get(port)).body === 'B'); assert.equal((await status(state)).pending, null);
      applied = result;
    });
    await check('manual-revert-reuses-content-with-a-new-revision', async () => {
      const result = await revert(state, initial); assert.equal(result.outcome, 'applied'); assert.notEqual(result.revision, initial);
      await waitFor(async () => (await get(port)).body === 'A'); applied = result;
    });
    await check('concurrent-operator-edit-stays-untouched-and-requires-recovery', async () => {
      healthGate = { requests: 0, released: false, responses: new Set() };
      const operation = apply(state, { ...input('candidate-before-conflict'), healthURL: `http://127.0.0.1:${healthPort}/gated` });
      operation.catch(() => {});
      await waitFor(() => healthGate.requests > 0);
      // New native generation is already serving; hold its health response so
      // the operator edit deterministically occurs during acknowledgement.
      const installed = await readFile(fragmentPath), manualFragment = Buffer.concat([installed, Buffer.from('\n# operator edit\n')]);
      const manualConfig = `${config}\n# operator edit during acknowledgement\n`;
      await writeFile(configPath, manualConfig); await writeFile(fragmentPath, manualFragment);
      healthGate.released = true;
      for (const response of healthGate.responses) { response.writeHead(200); response.end('healthy'); }
      await assert.rejects(operation, { code: 'ambiguous' });
      assert.equal(await readFile(configPath, 'utf8'), manualConfig); assert.deepEqual(await readFile(fragmentPath), manualFragment);
      const s = await status(state); assert.equal(s.pending.stage, 'ambiguous'); assert.equal(s.lastConfirmedRevision, applied.revision);
      assert.equal(s.runtime.observedRevision, s.pending.candidate); await waitFor(async () => (await get(port)).body === 'candidate-before-conflict');
      await assert.rejects(apply(state, input('wrong')), { code: 'pending' });
      // Explicit operator reconciliation restores only the known settings and
      // journaled candidate bytes; recover then makes a fresh old-content activation.
      await writeFile(configPath, config); await writeFile(fragmentPath, installed);
      const recovered = await recover(state); assert.equal(recovered.outcome, 'rolled_back'); await waitFor(async () => (await get(port)).body === 'A');
      applied = recovered; healthGate = null;
    });
    await check('exclusive-lock-is-not-auto-deleted', async () => {
      const lockFile = path.join(state, 'lock'); await writeFile(lockFile, '{"pid":9999999}', { mode: 0o600 });
      try { await assert.rejects(apply(state, input('locked')), { code: 'locked' }); assert.equal(await readFile(lockFile, 'utf8'), '{"pid":9999999}'); }
      finally { await rm(lockFile); }
    });
    await check('unsafe-health-urls-and-fragment-escapes-are-rejected', async () => {
      for (const healthURL of ['https://127.0.0.1:443/health', 'http://example.org:80/health', 'http://user:pass@127.0.0.1:80/health', 'http://127.0.0.1:80/health?secret=x', `http://127.0.0.1:${port}/__x10_health`])
        await assert.rejects(apply(state, { ...input('unused'), healthURL }), { code: 'invalid_health_url' });
      for (const serverBody of ['} server { listen 0.0.0.0:80; } server {', 'include /tmp/other.conf;', 'listen 0.0.0.0:80;', '"listen" 127.0.0.2:18442;', "'include' /tmp/other.conf;", 'l\\isten 127.0.0.2:18442;'])
        await assert.rejects(apply(state, { ...input('unused'), serverBody }), { code: 'invalid_candidate' });
      assert.equal((await get(port)).body, 'A');
    });
    await check('operator-config-mutation-refuses-signal', async () => {
      await writeFile(configPath, `${config}\n# manual change\n`);
      try { await assert.rejects(apply(state, input('wrong')), { code: 'operator_config_changed' }); }
      finally { await writeFile(configPath, config); }
      assert.equal((await get(port)).body, 'A');
    });
    await check('managed-fragment-tamper-and-symlink-refuse-signal', async () => {
      const original = await readFile(fragmentPath); await writeFile(fragmentPath, `${original}\n# changed\n`);
      try { await assert.rejects(apply(state, input('wrong')), { code: 'fragment_changed' }); }
      finally { await writeFile(fragmentPath, original); }
      const backup = `${fragmentPath}.backup`; await rename(fragmentPath, backup); await symlink(backup, fragmentPath);
      try { await assert.rejects(apply(state, input('wrong')), { code: 'unsafe_path' }); }
      finally { await rm(fragmentPath); await rename(backup, fragmentPath); }
    });
    await check('wrong-pid-file-refuses-runtime-attachment', async () => {
      const pidFile = path.join(prefix, 'nginx.pid'), bytes = await readFile(pidFile); await writeFile(pidFile, '9999999\n');
      try { await assert.rejects(apply(state, input('wrong')), { code: 'runtime_identity' }); }
      finally { await writeFile(pidFile, bytes); }
      assert.equal((await get(port)).body, 'A');
    });
    await check('revision-and-history-tampering-are-detected', async () => {
      const revisionFile = path.join(state, 'revisions', `${initial}.json`), bytes = await readFile(revisionFile);
      const altered = JSON.parse(bytes); altered.input.serverBody += '\n# changed'; await chmod(revisionFile, 0o600); await writeFile(revisionFile, JSON.stringify(altered));
      try { await assert.rejects(revert(state, initial), { code: 'revision_integrity' }); }
      finally { await writeFile(revisionFile, bytes); await chmod(revisionFile, 0o400); }
      const historyFile = path.join(state, 'history.jsonl'), historyBytes = await readFile(historyFile); await writeFile(historyFile, `${historyBytes}{"sequence":999}\n`);
      try { await assert.rejects(history(state), { code: 'history_integrity' }); }
      finally { await writeFile(historyFile, historyBytes); }
    });
    await check('killed-cli-leaves-pending-and-stale-lock-for-explicit-recovery', async () => {
      const candidateFile = path.join(prefix, 'crash-candidate.json');
      await writeFile(candidateFile, JSON.stringify({ ...input('interrupted'), healthURL: `http://127.0.0.1:${healthPort}/unhealthy` }), { mode: 0o600 });
      cliChild = spawn(process.execPath, [path.join(root, 'x10/control/cli.mjs'), 'apply', '--state', state, '--file', candidateFile], { stdio: ['ignore', 'pipe', 'pipe'] });
      cliChild.stdout.resume(); cliChild.stderr.resume();
      await waitFor(async () => JSON.parse(await readFile(path.join(state, 'pending.json'), 'utf8')).stage === 'reload_requested');
      cliChild.kill('SIGKILL'); await once(cliChild, 'exit');
      assert.equal(cliChild.signalCode, 'SIGKILL');
      await assert.rejects(apply(state, input('wrong')), { code: 'locked' });
      // The test acts as an operator only after confirming that exact CLI exited.
      await rm(path.join(state, 'lock'));
      await assert.rejects(apply(state, input('wrong')), { code: 'pending' });
      const result = await recover(state); assert.equal(result.outcome, 'rolled_back'); assert.notEqual(result.revision, applied.revision);
      await waitFor(async () => (await get(port)).body === 'A'); assert.equal((await status(state)).pending, null);
    });
    await check('history-chain-and-final-config-integrity', async () => {
      const h = await history(state), s = await status(state);
      for (const kind of ['initialized_unbound', 'bound', 'applied', 'rejected', 'rolled_back']) assert.ok(h.records.some(row => row.type === kind));
      assert.equal(h.records.at(-1).hash, s.history.head); assert.equal(s.history.integrity, true);
      assert.equal(s.configUnchanged, true); assert.equal(s.fragmentMatchesLastConfirmed, true); assert.equal(await readFile(configPath, 'utf8'), config);
      report.history = { entries: h.records.length, chainValid: true }; report.operatorConfigUnchanged = true;
    });
    report.passed = report.tests.length === 16 && !report.interrupted;
  } finally {
    if (cliChild && cliChild.exitCode === null && cliChild.signalCode === null) { cliChild.kill('SIGKILL'); await once(cliChild, 'exit'); }
    report.shutdown = await stop(child);
    if (report.shutdown?.exitCode !== 0 || report.shutdown?.signal !== null) report.passed = false;
    if (backend) await new Promise(resolve => backend.close(resolve));
    if (prefix) await rm(prefix, { recursive: true, force: true });
    report.finishedAt = new Date().toISOString();
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted);
    if (process.env.X10_CONTROL_EVIDENCE) await writeFile(path.resolve(process.env.X10_CONTROL_EVIDENCE), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    if (!report.passed) t.diagnostic(childOutput.slice(-4096));
    if (report.tests.length === 16) assert.equal(report.passed, true, 'native process must cleanly exit');
  }
});


// Faults exist only in this child-side fixture. Production controller code has
// no crash environment variable or test-only execution branch. Each pause is
// after the actual filesystem sync resolved; the parent then sends SIGKILL.
const faultWorker = `
import fs from 'node:fs';
import path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';
const [manager, state, operation, inputJSON, type, boundary] = process.argv.slice(1);
const originalOpen = fs.promises.open.bind(fs.promises);
const originalRename = fs.promises.rename.bind(fs.promises);
const originalRm = fs.promises.rm.bind(fs.promises);
let renamed, removedType;
const commit = path.join(state, 'event-commit.json');
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const pause = async actual => {
  process.send({ paused: true, type, boundary: actual });
  setInterval(() => {}, 1000);
  await new Promise(() => {});
};
fs.promises.rename = async (from, to) => { await originalRename(from, to); renamed = to; };
fs.promises.rm = async (file, ...rest) => {
  if (file === commit) removedType = read(commit).record.type;
  return originalRm(file, ...rest);
};
fs.promises.open = async (file, ...rest) => {
  const handle = await originalOpen(file, ...rest), sync = handle.sync.bind(handle);
  handle.sync = async () => {
    await sync();
    if (boundary === 'history' && file === path.join(state, 'history.jsonl')) {
      const records = fs.readFileSync(file, 'utf8').trim().split('\\n').filter(Boolean).map(JSON.parse);
      if (records.at(-1)?.type === type) await pause('history');
    }
    if (file !== state) return;
    if (boundary === 'cleared' && removedType === type && !fs.existsSync(commit)) await pause('cleared');
    if (!fs.existsSync(commit) || read(commit).record.type !== type) return;
    if (boundary === 'intent' && renamed === commit) await pause('intent');
    if (boundary === 'state' && renamed === path.join(state, 'state.json')) await pause('state');
  };
  return handle;
};
syncBuiltinESMExports();
const control = await import(pathToFileURL(manager).href);
const result = operation === 'bind' ? await control.bind(state)
  : operation === 'recover' ? await control.recover(state)
  : await control.apply(state, JSON.parse(inputJSON));
console.log(JSON.stringify(result));
process.exitCode = result.ok ? 0 : 1;
`;

test('native durable event commit reconciliation and crash boundaries', { timeout: 120000 }, async t => {
  const baselineCommit = '29746068bfca299b85062e981df250aa3e12abb8';
  const managerPath = path.join(root, 'x10/control/manager.mjs');
  const baselineSource = (await promisify(execFile)('git', ['show', `${baselineCommit}:x10/control/manager.mjs`], { cwd: root })).stdout;
  const report = { schemaVersion: 1, suite: 'native-control-event-recovery', startedAt: new Date().toISOString(),
    binary, binarySha256: digest(await readFile(binary)), managerSha256: digest(await readFile(managerPath)),
    testSha256: digest(await readFile(fileURLToPath(import.meta.url))),
    baseline: { commit: baselineCommit, managerSha256: digest(baselineSource) }, tests: [], shutdowns: [], passed: false,
    limitations: ['Actual process SIGKILL after synced filesystem boundaries; not a disk/power-loss simulation.',
      'No automatic stale-lock deletion. The exact killed fixture process has exited before test operator lock removal.',
      'Only a valid event-commit intent and exact canonical history/state boundaries can be reconciled; arbitrary old mismatches and partial lines fail closed.',
      'Fresh sampled revision/health and master identity are rechecked; this does not prove atomic all-traffic handover or undo requests.'] };
  let activeChild, activeWorker, backend;
  const interrupted = () => {
    report.interrupted = true;
    if (activeWorker && activeWorker.exitCode === null && activeWorker.signalCode === null) activeWorker.kill('SIGTERM');
    if (activeChild?.pid) { try { process.kill(-activeChild.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
    backend?.closeAllConnections();
  };
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  const check = async (name, fn) => t.test(name, async () => {
    assert.equal(report.interrupted, undefined);
    let prefix, output = '', shutdown;
    try {
      prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-recovery-')); await chmod(prefix, 0o700);
      const health = { healthy: true };
      backend = http.createServer((req, res) => { const good = health.healthy && req.url === '/healthy'; res.writeHead(good ? 200 : 503); res.end(good ? 'healthy' : 'unhealthy'); });
      const healthPort = await listen(backend), port = await unusedPort();
      const configPath = path.join(prefix, 'nginx.conf'), fragmentPath = path.join(prefix, 'managed.conf');
      const config = `${process.getuid() === 0 ? `user ${os.userInfo().username};` : ''}
daemon off; master_process on; worker_processes 1;
pid ${prefix}/nginx.pid;
error_log ${prefix}/error.log notice;
events { worker_connections 128; }
http { access_log off;
include ${fragmentPath};
}
`;
      await writeFile(configPath, config, { mode: 0o600 });
      const input = text => ({ serverBody: `location / { return 200 "${text}"; }`, healthURL: `http://127.0.0.1:${healthPort}/healthy` });
      const init = await initialize({ prefix, binary, port, gateTimeoutMs: 600 }, input('A'));
      const state = init.state;
      activeChild = spawn(binary, ['-p', `${prefix}/`, '-c', configPath], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
      activeChild.stdout.on('data', data => output += data); activeChild.stderr.on('data', data => output += data);
      await waitFor(async () => (await get(port)).body === 'A');
      if (!name.startsWith('bound-')) await bind(state);
      const crash = async (type, boundary, { operation = 'apply', candidate = input('B'), manager = managerPath } = {}) => {
        let paused, childOutput = '';
        activeWorker = spawn(process.execPath, ['--input-type=module', '-e', faultWorker, manager, state, operation, JSON.stringify(candidate), type, boundary], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
        const worker = activeWorker;
        worker.stdout.on('data', chunk => childOutput += chunk); worker.stderr.on('data', chunk => childOutput += chunk);
        worker.on('message', data => { paused = data; });
        await waitFor(() => {
          if (worker.exitCode !== null || worker.signalCode !== null) throw new Error(`Fault worker exited before ${type}/${boundary}: ${childOutput}`);
          return paused;
        });
        assert.deepEqual(paused, { paused: true, type, boundary });
        worker.kill('SIGKILL'); await once(worker, 'exit');
        assert.equal(worker.signalCode, 'SIGKILL'); activeWorker = null;
        await assert.rejects(status(state), { code: 'locked' });
        await rm(path.join(state, 'lock')); // exact killed process is confirmed exited
      };
      const recoverCLI = async () => {
        const result = await promisify(execFile)(process.execPath, [path.join(root, 'x10/control/cli.mjs'), 'recover', '--state', state], { timeout: 6000 });
        assert.equal(result.stderr, ''); return JSON.parse(result.stdout);
      };
      await fn({ prefix, state, init, port, input, crash, health, config, configPath, fragmentPath, recoverCLI });
    } catch (error) { t.diagnostic(output.slice(-4096)); throw error; }
    finally {
      if (activeWorker && activeWorker.exitCode === null && activeWorker.signalCode === null) { activeWorker.kill('SIGKILL'); await once(activeWorker, 'exit'); }
      activeWorker = null;
      shutdown = await stop(activeChild); activeChild = null;
      report.shutdowns.push(shutdown);
      if (backend) { backend.closeAllConnections(); await new Promise(resolve => backend.close(resolve)); backend = null; }
      if (prefix) await rm(prefix, { recursive: true, force: true });
    }
    assert.equal(shutdown?.exitCode, 0); assert.equal(shutdown?.signal, null);
    report.tests.push({ name, passed: true });
  });
  try {
    await check('baseline-terminal-history-state-window-is-reproduced', async ({ prefix, state, input, crash }) => {
      const baselinePath = path.join(prefix, 'baseline-manager.mjs'); await writeFile(baselinePath, baselineSource, { mode: 0o600 });
      await crash('applied', 'history', { manager: baselinePath });
      const baseline = await import(pathToFileURL(baselinePath).href);
      await assert.rejects(baseline.recover(state), { code: 'history_integrity' });
      await assert.rejects(recover(state), { code: 'history_integrity' });
      report.baseline.reproduced = true; report.baseline.outcome = 'history_integrity';
    });
    for (const boundary of ['intent', 'history', 'state', 'cleared']) {
      await check(`applied-${boundary}-recovers-without-duplicate-history`, async ({ state, port, crash }) => {
        await crash('applied', boundary);
        const before = (await readFile(path.join(state, 'history.jsonl'), 'utf8')).split('\n').filter(Boolean).length;
        if (boundary !== 'cleared') await assert.rejects(status(state), { code: 'commit_pending' });
        const result = await recover(state); assert.equal(result.outcome, 'reconciled'); assert.equal(result.recordedOutcome, 'applied');
        const s = await status(state), records = (await history(state)).records;
        assert.equal(records.length, before + (boundary === 'intent' ? 1 : 0));
        assert.equal(records.filter(row => row.type === 'applied').length, 1);
        assert.equal(s.pending, null); assert.equal(s.lastConfirmedRevision, result.revision); assert.equal(s.runtime.observedRevision, result.revision);
        assert.equal((await get(port)).body, 'B');
        assert.deepEqual(await recover(state), { ok: true, outcome: 'nothing_pending' });
      });
    }
    await check('bound-history-reconciliation-retains-verified-master-binding', async ({ state, crash, init }) => {
      await crash('bound', 'history', { operation: 'bind' });
      const result = await recover(state); assert.equal(result.recordedOutcome, 'bound');
      const s = await status(state); assert.equal(s.runtime.identityValid, true); assert.equal(s.lastConfirmedRevision, init.revision);
    });
    await check('apply-started-history-reconciliation-restores-original-content', async ({ state, port, crash }) => {
      await crash('apply_started', 'history');
      const result = await recover(state); assert.equal(result.outcome, 'rolled_back'); assert.equal((await get(port)).body, 'A');
      assert.equal((await status(state)).pending, null);
    });
    await check('rejected-history-reconciliation-does-not-activate-invalid-input', async ({ state, port, input, crash, recoverCLI }) => {
      await crash('rejected', 'history', { candidate: { ...input('unused'), serverBody: 'location / { x10_nonexistent_directive on; }' } });
      const result = await recoverCLI(); assert.equal(result.ok, true); assert.equal(result.outcome, 'reconciled'); assert.equal(result.recordedOutcome, 'rejected'); assert.equal((await get(port)).body, 'A');
      assert.equal((await status(state)).pending, null);
    });
    await check('rolled-back-history-reconciliation-keeps-fresh-restoration', async ({ state, port, input, crash, recoverCLI }) => {
      await crash('rolled_back', 'history', { candidate: { ...input('bad'), healthURL: input('bad').healthURL.replace('/healthy', '/unhealthy') } });
      const result = await recoverCLI(); assert.equal(result.ok, true); assert.equal(result.outcome, 'reconciled'); assert.equal(result.recordedOutcome, 'rolled_back'); assert.equal((await get(port)).body, 'A');
    });
    await check('interrupted-recover-is-idempotent-at-history-boundary', async ({ state, port, crash }) => {
      await crash('applied', 'intent');
      await crash('applied', 'history', { operation: 'recover' });
      const result = await recover(state); assert.equal(result.recordedOutcome, 'applied');
      assert.equal((await history(state)).records.filter(row => row.type === 'applied').length, 1);
      assert.equal((await get(port)).body, 'B');
    });
    await check('reconciliation-refuses-conflicting-operator-bytes', async ({ state, configPath, config, crash }) => {
      await crash('applied', 'history');
      const changed = `${config}\n# operator edit after crash\n`; await writeFile(configPath, changed);
      const historyBytes = await readFile(path.join(state, 'history.jsonl')), stateBytes = await readFile(path.join(state, 'state.json'));
      await assert.rejects(recover(state), { code: 'operator_config_changed' });
      assert.equal(await readFile(configPath, 'utf8'), changed); assert.deepEqual(await readFile(path.join(state, 'history.jsonl')), historyBytes);
      assert.deepEqual(await readFile(path.join(state, 'state.json')), stateBytes);
      await writeFile(configPath, config); assert.equal((await recover(state)).outcome, 'reconciled');
    });
    await check('reconciliation-refuses-stale-binding-and-unhealthy-runtime', async ({ state, health, prefix, crash }) => {
      await crash('applied', 'state');
      const pidFile = path.join(prefix, 'nginx.pid'), original = await readFile(pidFile); await writeFile(pidFile, '9999999\n');
      await assert.rejects(recover(state), { code: 'runtime_identity' }); await writeFile(pidFile, original);
      health.healthy = false; await assert.rejects(recover(state), { code: 'health_gate_failed' });
      health.healthy = true; assert.equal((await recover(state)).outcome, 'reconciled');
    });
    await check('reconciliation-refuses-partial-history-and-invalid-event-transition', async ({ state, crash }) => {
      await crash('applied', 'history');
      const historyFile = path.join(state, 'history.jsonl'), bytes = await readFile(historyFile);
      await writeFile(historyFile, Buffer.concat([bytes, Buffer.from('{"partial":')]));
      await assert.rejects(recover(state), { code: 'history_integrity' }); assert.deepEqual(await readFile(historyFile), Buffer.concat([bytes, Buffer.from('{"partial":')]));
      await writeFile(historyFile, bytes);
      const intentFile = path.join(state, 'event-commit.json'), intentBytes = await readFile(intentFile), intent = JSON.parse(intentBytes);
      intent.after.previousRevision = null; delete intent.sha256; intent.sha256 = digest(JSON.stringify(intent));
      await writeFile(intentFile, JSON.stringify(intent));
      const stateFile = path.join(state, 'state.json'), stateBytes = await readFile(stateFile);
      await assert.rejects(recover(state), { code: 'commit_integrity' });
      assert.deepEqual(await readFile(historyFile), bytes); assert.deepEqual(await readFile(stateFile), stateBytes);
      await writeFile(intentFile, intentBytes); assert.equal((await recover(state)).outcome, 'reconciled');
    });
    await check('before-append-invalid-record-shape-preserves-all-durable-bytes', async ({ state, fragmentPath, crash }) => {
      await crash('applied', 'intent');
      const intentFile = path.join(state, 'event-commit.json'), original = await readFile(intentFile), intent = JSON.parse(original);
      intent.record.at = 123; delete intent.record.hash; intent.record.hash = digest(JSON.stringify(intent.record));
      intent.after.historyHead = intent.record.hash; delete intent.sha256; intent.sha256 = digest(JSON.stringify(intent));
      const altered = JSON.stringify(intent); await writeFile(intentFile, altered);
      const files = [path.join(state, 'state.json'), path.join(state, 'history.jsonl'), fragmentPath];
      const before = await Promise.all(files.map(file => readFile(file)));
      await assert.rejects(recover(state), { code: 'commit_integrity' });
      assert.equal(await readFile(intentFile, 'utf8'), altered);
      for (let i = 0; i < files.length; i++) assert.deepEqual(await readFile(files[i]), before[i]);
      await writeFile(intentFile, original); assert.equal((await recover(state)).outcome, 'reconciled');
    });
    await check('present-falsy-or-array-journals-are-corruption-not-absence', async ({ state, fragmentPath, input }) => {
      const files = [path.join(state, 'state.json'), path.join(state, 'history.jsonl'), fragmentPath];
      const before = await Promise.all(files.map(file => readFile(file)));
      for (const name of ['pending.json', 'event-commit.json']) {
        const file = path.join(state, name), code = name === 'pending.json' ? 'journal_integrity' : 'commit_integrity';
        for (const value of [null, false, 0, '', []]) {
          const bytes = JSON.stringify(value); await writeFile(file, bytes, { mode: 0o600 });
          await assert.rejects(recover(state), { code }); await assert.rejects(status(state), { code });
          await assert.rejects(apply(state, input('must-not-apply')), { code });
          assert.equal(await readFile(file, 'utf8'), bytes);
          for (let i = 0; i < files.length; i++) assert.deepEqual(await readFile(files[i]), before[i]);
          await rm(file);
        }
      }
      assert.equal((await recover(state)).outcome, 'nothing_pending');
    });
    report.passed = report.tests.length === 15 && !report.interrupted;
  } finally {
    report.finishedAt = new Date().toISOString(); process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted);
    if (process.env.X10_CONTROL_RECOVERY_EVIDENCE) await writeFile(path.resolve(process.env.X10_CONTROL_RECOVERY_EVIDENCE), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  }
  assert.equal(report.passed, true);
});
