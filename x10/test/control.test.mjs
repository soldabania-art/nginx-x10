import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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
