import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { chmod, copyFile, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../alpha/runtime.mjs';
import './alpha-runtime.test.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url)), source = path.join(root, 'x10/alpha/cli.mjs');
const manifestFile = path.resolve(process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'));
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const execute = promisify(execFile), delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function unusedPort() { const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
async function absent(file) { return lstat(file).then(() => false, error => { if (error.code === 'ENOENT') return true; throw error; }); }
async function until(fn, timeout = 6500) {
  const end = performance.now() + timeout; let last;
  while (performance.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { last = e; } await delay(25); }
  throw last || new Error('Alpha fixture deadline');
}
async function cli(file, ...args) {
  try { const r = await execute(process.execPath, [file, ...args], { timeout: 12000, maxBuffer: 2 * 1024 * 1024 }); return { code: 0, ...r, json: args.includes('--human') ? null : JSON.parse(r.stdout) }; }
  catch (error) { if (!Number.isInteger(error.code)) throw error; return { code: error.code, stdout: error.stdout, stderr: error.stderr, json: JSON.parse(error.stdout) }; }
}
async function request(port, route = '/') {
  return new Promise((resolve, reject) => { const req = http.get({ host: '127.0.0.1', port, path: route, agent: false }, res => { let body = ''; res.on('data', b => body += b); res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers })); }); req.setTimeout(1500, () => req.destroy(new Error('request timeout'))); req.on('error', reject); });
}
// A sampled reload gate is not an all-request cutover: old workers may overlap.
async function observedBody(port, expected) { await until(async () => (await request(port)).body === expected); }
async function amendRecord(file, mutate) {
  const record = JSON.parse(await readFile(file, 'utf8')), { sha256, ...body } = record; mutate(body);
  await writeFile(file, `${JSON.stringify({ ...body, sha256: digest(JSON.stringify(body)) }, null, 2)}\n`);
}

test('isolated Linux alpha installs, controls native sessions, restarts and removes only owned data', { timeout: 65000 }, async t => {
  const build = JSON.parse(await readFile(manifestFile, 'utf8'));
  assert.equal(build.binary.path, binary, 'Aggregate-selected manifest and binary must be identical');
  assert.equal(build.binary.sha256, digest(await readFile(binary)));
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install'), launcher = path.join(prefix, 'bin/x10');
  const port = await unusedPort(); let healthPort; do { healthPort = await unusedPort(); } while (healthPort === port);
  let runChild, runOutput = '', nativePid, firstSession, firstRevision, secondRevision, cancelled = false;
  const nativeGroups = new Set(), launchers = new Set();
  const emergency = () => { cancelled = true; for (const pid of nativeGroups) { try { process.kill(-pid, 'SIGTERM'); } catch {} } for (const child of launchers) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const check = (name, fn) => t.test(name, async () => { assert.equal(cancelled, false); await fn(); });
  const start = async () => {
    runOutput = ''; runChild = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(runChild);
    runChild.stdout.on('data', b => { runOutput += b; const m = /"(?:pid|candidatePid)": (\d+)/.exec(runOutput); if (m) { nativePid = Number(m[1]); nativeGroups.add(nativePid); } });
    runChild.stderr.on('data', b => runOutput += b);
    await until(() => { if (runChild.exitCode !== null || runChild.signalCode !== null) throw new Error(`run exited: ${runOutput}`); return runOutput.includes('"outcome": "running"'); });
    const result = await cli(launcher, 'info'); assert.equal(result.code, 0, result.stdout); return result.json;
  };
  const stop = async () => {
    const result = await cli(launcher, 'stop'); assert.equal(result.code, 0, result.stdout);
    await until(() => runChild.exitCode !== null || runChild.signalCode !== null); assert.equal(runChild.exitCode, 0, runOutput);
    nativeGroups.delete(nativePid); launchers.delete(runChild); return result.json;
  };
  try {
    await check('reject-existing-prefix-symlink-ancestor-unsafe-port-and-mismatched-build', async () => {
      const existing = await cli(source, 'install', '--prefix', parent, '--manifest', manifestFile, '--binary', binary); assert.equal(existing.json.code, 'already_exists');
      const link = path.join(parent, 'link'); await symlink(parent, link);
      const unsafe = await cli(source, 'install', '--prefix', path.join(link, 'new'), '--manifest', manifestFile, '--binary', binary); assert.equal(unsafe.json.code, 'unsafe_path');
      await rm(link);
      const invalid = await cli(source, 'install', '--prefix', prefix, '--port', '80', '--manifest', manifestFile, '--binary', binary); assert.equal(invalid.json.code, 'invalid_port');
      // A runner-owned copy reaches manifest identity checks on non-root hosts;
      // the system Node executable can be owned by a different user there.
      const wrongBinary = path.join(parent, 'mismatched-nginx'); await copyFile(binary, wrongBinary); await chmod(wrongBinary, 0o500);
      try {
        const mismatch = await cli(source, 'install', '--prefix', prefix, '--manifest', manifestFile, '--binary', wrongBinary);
        assert.equal(mismatch.json.code, 'build_identity'); assert(await absent(prefix));
      } finally { await rm(wrongBinary); }
    });
    await check('manifest-verified-new-private-install-prepares-without-listening', async () => {
      const result = await cli(source, 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--manifest', manifestFile, '--binary', binary);
      assert.equal(result.code, 0, result.stdout); firstSession = result.json.session; firstRevision = result.json.revision;
      assert.equal((await lstat(prefix)).mode & 0o777, 0o700); assert.equal(digest(await readFile(path.join(prefix, 'bin/nginx'))), build.binary.sha256);
      assert.equal(result.json.controlApiEnabled, false); assert.match(result.json.healthNote, /demo self-check/);
      assert.equal((await cli(launcher, 'status')).json.binding, null);
      await assert.rejects(request(port)); await assert.rejects(request(healthPort));
      assert((await readFile(path.join(prefix, 'licenses/NGINX-LICENSE'), 'utf8')).includes('Copyright'));
      assert.equal((await cli(launcher, 'run', '--control-address', '127.0.0.1:9999')).json.code, 'arguments');
    });
    await check('foreground-native-start-explicit-bind-status-and-native-demo-self-check', async () => {
      const info = await start(); assert.equal(info.session, firstSession); assert.equal(info.controlSocket, null);
      assert.equal((await cli(launcher, 'bind')).code, 0);
      const status = await cli(launcher, 'status'); assert.equal(status.json.runtime.identityValid, true); assert.equal(status.json.runtime.observedRevision, firstRevision);
      const human = await cli(launcher, 'status', '--human'); assert.equal(human.code, 0); assert.match(human.stdout, /Health and listener drain: not checked/);
      assert.equal((await request(port)).body, 'NGINX X10 local alpha\n'); assert.equal((await request(healthPort, '/__x10_demo_self_check')).body, 'native demo self-check\n');
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'alpha_live');
      assert.equal((await cli(launcher, 'run')).json.code, 'alpha_live');
      const life = JSON.parse(await readFile(path.join(info.sessionPrefix, 'lifecycle.json'), 'utf8'));
      const cmd = (await readFile(`/proc/${life.runtime.procPid}/cmdline`, 'utf8')).split('\0')[0]; assert(!cmd.includes(' -l '));
      const table = await readFile(`/proc/${life.runtime.procPid}/net/tcp`, 'utf8');
      for (const p of [port, healthPort]) { const key = `0100007F:${p.toString(16).padStart(4, '0').toUpperCase()}`; assert(table.split('\n').some(line => line.includes(key) && /\s0A\s/.test(line)), `IPv4 loopback listener ${p}`); }
    });
    await check('apply-revert-history-recover-and-foreign-pidfile-refusal', async () => {
      const applied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(applied.code, 0, applied.stdout); secondRevision = applied.json.revision;
      await observedBody(port, 'NGINX X10 updated local alpha\n');
      const reverted = await cli(launcher, 'revert', '--revision', firstRevision); assert.equal(reverted.code, 0, reverted.stdout); await observedBody(port, 'NGINX X10 local alpha\n');
      const reapplied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(reapplied.code, 0); secondRevision = reapplied.json.revision;
      await observedBody(port, 'NGINX X10 updated local alpha\n');
      assert.equal((await cli(launcher, 'recover')).code, 0); assert.equal((await cli(launcher, 'history')).json.ok, true);
      const pidFile = path.join(prefix, 'runs', firstSession, 'nginx.pid'), original = await readFile(pidFile);
      try { await writeFile(pidFile, `${process.pid}\n`); assert.equal((await cli(launcher, 'stop')).json.code, 'runtime_identity'); assert.equal((await request(port)).body, 'NGINX X10 updated local alpha\n'); }
      finally { await writeFile(pidFile, original); }
    });
    await check('immutable-tamper-refused-and-library-drift-does-not-block-exact-stop', async () => {
      const file = path.join(prefix, 'licenses/UPSTREAM.txt'), bytes = await readFile(file); await chmod(file, 0o600);
      try { await writeFile(file, 'changed'); assert.equal((await cli(launcher, 'status')).json.code, 'alpha_integrity'); }
      finally { await writeFile(file, bytes); await chmod(file, 0o400); }
      const marker = path.join(prefix, '.alpha-install.json'), original = await readFile(marker);
      // Isolated owned record control: never modify actual host libraries.
      try {
        await amendRecord(marker, value => value.dependencies.files[0].sha256 = '0'.repeat(64));
        assert.equal((await cli(launcher, 'bind')).json.code, 'dependency_changed');
        const stopped = await stop(); assert.equal(stopped.outcome, 'stopped'); assert.equal(stopped.dependencyDrift.length, 1);
      } finally { await writeFile(marker, original); }
      assert.equal((await cli(launcher, 'stop')).json.outcome, 'already_stopped');
      const config = path.join(prefix, 'runs', firstSession, 'nginx.conf'), configBytes = await readFile(config);
      try { await writeFile(config, Buffer.concat([configBytes, Buffer.from('# operator changed config\n')])); for (const command of ['run', 'uninstall']) assert.equal((await cli(launcher, command)).json.code, 'operator_conflict'); }
      finally { await writeFile(config, configBytes); }
      try { await chmod(prefix, 0o775); assert.equal((await cli(launcher, 'uninstall')).json.code, 'unsafe_permissions'); }
      finally { await chmod(prefix, 0o700); }
    });
    await check('restart-creates-fresh-session-keeps-confirmed-response-and-old-history', async () => {
      const priorHistory = await readFile(path.join(prefix, 'runs', firstSession, '.x10-control/history.jsonl'));
      const info = await start(); assert.notEqual(info.session, firstSession); assert.equal((await cli(launcher, 'bind')).code, 0);
      assert.equal((await request(port)).body, 'NGINX X10 updated local alpha\n');
      assert.deepEqual(await readFile(path.join(prefix, 'runs', firstSession, '.x10-control/history.jsonl')), priorHistory);
      const status = (await cli(launcher, 'status')).json; assert.equal(status.runtime.identityValid, true); assert.notEqual(status.lastConfirmedRevision, secondRevision);
      await stop(); await assert.rejects(request(port)); await assert.rejects(request(healthPort));
    });
    await check('uninstall-preserves-extra-and-symlink-data-then-cleans-known-stopped-install', async () => {
      const extra = path.join(prefix, 'operator-notes.txt'); await writeFile(extra, 'preserve me', { mode: 0o600 });
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'operator_data_preserved'); assert.equal(await readFile(extra, 'utf8'), 'preserve me'); await rm(extra);
      const outside = path.join(parent, 'outside.txt'); await writeFile(outside, 'outside', { mode: 0o600 }); await symlink(outside, path.join(prefix, 'operator-link'));
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'unsafe_path'); assert.equal(await readFile(outside, 'utf8'), 'outside'); await rm(path.join(prefix, 'operator-link'));
      const result = await cli(launcher, 'uninstall'); assert.equal(result.code, 0, result.stdout); assert(await absent(prefix)); assert.equal(nativeGroups.size, 0); assert.equal(launchers.size, 0);
      assert.deepEqual((await readdir(parent)).sort(), ['outside.txt']);
    });
    await check('checked-bundle-extracts-and-installs-without-original-build-paths', async () => {
      const archive = path.join(parent, 'alpha.tar.gz'), packed = await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary);
      assert.equal(packed.code, 0, packed.stdout); assert.equal(packed.json.binarySha256, build.binary.sha256);
      const alias = path.join(parent, 'pack-alias'); await symlink(parent, alias);
      assert.equal((await cli(source, 'pack', '--output', path.join(alias, 'must-not-create', 'bad.tar.gz'), '--manifest', manifestFile, '--binary', binary)).json.code, 'unsafe_path');
      assert(await absent(path.join(parent, 'must-not-create'))); await rm(alias);
      assert.equal((await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary)).json.code, 'unsafe_output');
      await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
      const bundle = path.join(parent, 'nginx-x10-alpha'), installer = path.join(bundle, 'install.mjs'), target = path.join(parent, 'bundled-install'), targetLauncher = path.join(target, 'bin/x10');
      const bundled = JSON.parse(await readFile(path.join(bundle, 'bundle.json'), 'utf8'));
      assert.equal(bundled.files['bin/nginx'].sha256, build.binary.sha256); assert(!JSON.stringify(bundled).includes(root.replace(/\/$/, ''))); assert(!JSON.stringify(bundled).includes('/proc/'));
      assert.equal(await absent(path.join(bundle, 'x10/.build')), true); assert.equal(await absent(path.join(bundle, 'runs')), true);
      const code = path.join(bundle, 'x10/control/listeners.mjs'), saved = await readFile(code); await chmod(code, 0o600);
      try { await writeFile(code, 'changed'); assert.equal((await cli(installer, 'install', '--prefix', target)).json.code, 'bundle_identity'); assert(await absent(target)); }
      finally { await writeFile(code, saved); await chmod(code, 0o400); }
      const result = await cli(installer, 'install', '--prefix', target, '--port', String(port), '--health-port', String(healthPort)); assert.equal(result.code, 0, result.stdout);
      let output = '', pid;
      const child = spawn(process.execPath, [targetLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(child);
      child.stdout.on('data', b => { output += b; const match = /"(?:pid|candidatePid)": (\d+)/.exec(output); if (match) { pid = Number(match[1]); nativeGroups.add(pid); } }); child.stderr.on('data', b => output += b);
      await until(() => { if (child.exitCode !== null || child.signalCode !== null) throw new Error(output); return output.includes('"outcome": "running"'); });
      assert.equal((await cli(targetLauncher, 'bind')).code, 0); assert.equal((await request(port)).body, 'NGINX X10 local alpha\n');
      assert.equal((await cli(targetLauncher, 'apply', '--file', path.join(target, 'examples/candidate-b.json'))).code, 0);
      await observedBody(port, 'NGINX X10 updated local alpha\n'); assert.equal((await cli(targetLauncher, 'stop')).code, 0);
      await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0, output); launchers.delete(child); nativeGroups.delete(pid);
      // Interrupt the startup path as soon as a fresh session publishes its native PID.
      let interruptedOutput = '', interruptedPid;
      const interrupted = spawn(process.execPath, [targetLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(interrupted);
      interrupted.stdout.on('data', b => {
        interruptedOutput += b;
        const match = /"candidatePid": (\d+)/.exec(interruptedOutput);
        if (match && !interruptedPid) { interruptedPid = Number(match[1]); nativeGroups.add(interruptedPid); interrupted.kill('SIGTERM'); }
      });
      interrupted.stderr.on('data', b => interruptedOutput += b);
      await until(() => interrupted.exitCode !== null || interrupted.signalCode !== null);
      assert.equal(interrupted.signalCode, null, interruptedOutput); assert.equal(interrupted.exitCode, 1); assert(interruptedPid);
      assert.match(interruptedOutput, /run_cancelled/); assert(!interruptedOutput.includes('"outcome": "running"'));
      assert.equal((await cli(targetLauncher, 'info')).json.stage, 'stopped', interruptedOutput);
      await assert.rejects(request(port)); await assert.rejects(request(healthPort)); nativeGroups.delete(interruptedPid); launchers.delete(interrupted);
      assert.equal((await cli(targetLauncher, 'uninstall')).code, 0); assert(await absent(target));

      // SIGKILL of the master leaves native workers outside graceful completion.
      const fault = path.join(parent, 'faulted-install'), faultLauncher = path.join(fault, 'bin/x10');
      assert.equal((await cli(installer, 'install', '--prefix', fault, '--port', String(port), '--health-port', String(healthPort))).code, 0);
      let faultOutput = '', faultPid;
      const faultRun = spawn(process.execPath, [faultLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(faultRun);
      faultRun.stdout.on('data', b => { faultOutput += b; const match = /"(?:pid|candidatePid)": (\d+)/.exec(faultOutput); if (match) { faultPid = Number(match[1]); nativeGroups.add(faultPid); } }); faultRun.stderr.on('data', b => faultOutput += b);
      await until(() => faultOutput.includes('"outcome": "running"')); assert.equal((await cli(faultLauncher, 'bind')).code, 0);
      process.kill(faultPid, 'SIGKILL'); await until(() => faultRun.exitCode !== null || faultRun.signalCode !== null); assert.equal(faultRun.exitCode, 1);
      assert.equal((await cli(faultLauncher, 'info')).json.stage, 'faulted');
      assert.equal((await request(port)).body, 'NGINX X10 local alpha\n', 'actual orphan worker still serves after master SIGKILL');
      for (const command of ['run', 'stop', 'uninstall']) assert.equal((await cli(faultLauncher, command)).json.code, 'abnormal_exit');
      // Test-owned orphan process group only. Production commands never reap it.
      try { process.kill(-faultPid, 'SIGTERM'); } catch {} await until(async () => { try { await request(port); return false; } catch { return true; } });
      nativeGroups.delete(faultPid); launchers.delete(faultRun);
    });
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    for (const signal of ['SIGQUIT', 'SIGTERM', 'SIGKILL']) {
      for (const pid of nativeGroups) { try { process.kill(-pid, signal); } catch {} }
      for (const child of launchers) if (child.exitCode === null && child.signalCode === null) { try { child.kill(signal === 'SIGQUIT' ? 'SIGTERM' : signal); } catch {} }
      if (nativeGroups.size || launchers.size) await delay(75);
    }
    await rm(parent, { recursive: true, force: true });
  }
});

// G2 opt-in upstream controls. The original demo lifecycle above stays intact.
async function upstreamTransfer(port, route = '/', { method = 'GET', body = null, limit = 9 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => req.destroy(new Error('upstream request deadline')), 5000);
    const req = http.request({ host: '127.0.0.1', port, path: route, method, agent: false,
      headers: body ? { 'Content-Length': body.length, 'Content-Type': 'application/octet-stream' } : {} }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => { bytes += chunk.length; if (bytes > limit) req.destroy(new Error('upstream response limit')); else chunks.push(chunk); });
      res.on('error', reject);
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }); });
    });
    req.setTimeout(1500, () => req.destroy(new Error('upstream request idle timeout')));
    req.once('error', error => { clearTimeout(timer); reject(error); });
    req.end(body);
  });
}
async function upstreamPorts(upstreamPort) {
  let port, healthPort;
  do { port = await unusedPort(); } while (port === upstreamPort);
  do { healthPort = await unusedPort(); } while (healthPort === port || healthPort === upstreamPort);
  return { port, healthPort };
}

test('application upstream port syntax and collisions refuse before creating a prefix', { timeout: 20000 }, async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-port-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install');
  try {
    for (const value of ['0', '80', '65536', '09090', '9090.0', '9e3', ' 9090', '9090;return', '9080', '9081']) {
      const result = await cli(source, 'install', '--prefix', prefix, '--port', '9080', '--health-port', '9081', '--upstream-port', value,
        '--manifest', manifestFile, '--binary', binary);
      assert.equal(result.code, 1); assert.equal(result.json.ok, false); assert.equal(result.json.code, 'invalid_upstream_port');
      assert.equal(await absent(prefix), true, 'invalid optional upstream created installation data');
    }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('extracted bundle proxies an independent app and preserves application readiness across config and sessions', { timeout: 65000 }, async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-')); await chmod(parent, 0o700);
  let ready = false, readinessBody = 'ready\n', appRequests = 0, echoRequests = 0, runChild, output = '', nativePid;
  const groups = new Set(), children = new Set();
  const app = http.createServer((req, res) => {
    appRequests++; res.setHeader('X-App-Marker', 'independent-upstream');
    if (req.url === '/ready' || req.url === '/not-ready') { res.writeHead(ready && req.url === '/ready' ? 200 : 503); res.end(ready ? readinessBody : 'not ready\n'); return; }
    if (req.method === 'POST' && req.url === '/echo') {
      echoRequests++;
      const chunks = []; let bytes = 0;
      req.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) req.destroy(); else chunks.push(chunk); });
      req.on('end', () => { res.writeHead(200); res.end(Buffer.concat(chunks)); }); return;
    }
    res.writeHead(200); res.end('independent application\n');
  });
  app.requestTimeout = 3000; app.headersTimeout = 3000; app.keepAliveTimeout = 500;
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  const upstreamPort = app.address().port, { port, healthPort } = await upstreamPorts(upstreamPort);
  const prefix = path.join(parent, 'installed'), launcher = path.join(prefix, 'bin/x10');
  const emergency = () => { for (const pid of groups) { try { process.kill(-pid, 'SIGTERM'); } catch {} } for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const start = async () => {
    output = ''; runChild = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); children.add(runChild);
    runChild.stdout.on('data', chunk => { output += chunk; const match = /"(?:pid|candidatePid)": (\d+)/.exec(output); if (match) { nativePid = Number(match[1]); groups.add(nativePid); } });
    runChild.stderr.on('data', chunk => output += chunk);
    await until(() => { if (runChild.exitCode !== null || runChild.signalCode !== null) throw new Error(output); return output.includes('"outcome": "running"'); });
    const info = await cli(launcher, 'info'); assert.equal(info.code, 0, info.stdout); return info.json;
  };
  const stop = async () => {
    const result = await cli(launcher, 'stop'); assert.equal(result.code, 0, result.stdout);
    await until(() => runChild.exitCode !== null || runChild.signalCode !== null); assert.equal(runChild.exitCode, 0, output);
    children.delete(runChild); groups.delete(nativePid);
  };
  try {
    const archive = path.join(parent, 'alpha.tar.gz');
    const packed = await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary); assert.equal(packed.code, 0, packed.stdout);
    await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
    const bundle = path.join(parent, 'nginx-x10-alpha'), installer = path.join(bundle, 'install.mjs');
    assert.equal(await absent(path.join(bundle, 'x10/.build')), true);
    const installed = await cli(installer, 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--upstream-port', String(upstreamPort));
    assert.equal(installed.code, 0, installed.stdout); assert.match(installed.json.healthNote, /application readiness/);
    const first = await start();
    assert.equal((await request(healthPort, '/__x10_demo_self_check')).status, 200);
    assert.equal((await request(port, '/__x10_health')).status, 503, 'native demo must not stand in for application readiness');
    const denied = await cli(launcher, 'bind'); assert.equal(denied.code, 1); assert.equal(denied.json.code, 'health_gate_failed');
    assert.equal((await cli(launcher, 'status')).json.binding, null);
    ready = true; readinessBody = 'private-wrong-readiness-body\n';
    assert.equal((await request(port, '/__x10_health')).status, 200);
    const wrongBody = await cli(launcher, 'bind');
    assert.equal(wrongBody.code, 1, 'HTTP 200 with the wrong body must not bind the application');
    assert.equal(wrongBody.json.code, 'health_gate_failed');
    assert.equal(wrongBody.stdout.includes(readinessBody.trim()), false, 'readiness bodies stay out of diagnostics');
    assert.equal((await cli(launcher, 'status')).json.binding, null);
    readinessBody = 'ready\n'; const bound = await cli(launcher, 'bind'); assert.equal(bound.code, 0, bound.stdout);
    const initialRevision = bound.json.revision;
    const response = await upstreamTransfer(port); assert.equal(response.status, 200); assert.equal(response.body.toString(), 'independent application\n'); assert.equal(response.headers['x-app-marker'], 'independent-upstream');
    const payload = Buffer.alloc(65551); for (let i = 0; i < payload.length; i++) payload[i] = (i * 37) & 255;
    const echoed = await upstreamTransfer(port, '/echo', { method: 'POST', body: payload }); assert.equal(echoed.status, 200); assert.deepEqual(echoed.body, payload);
    assert.equal((await request(port, '/__x10_health')).status, 200);
    const applied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(applied.code, 0, applied.stdout);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    assert.equal((await cli(launcher, 'revert', '--revision', initialRevision)).code, 0);
    await until(async () => (await request(port)).headers['x-x10-example'] === undefined);
    assert.equal((await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json'))).code, 0);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    const seed = JSON.parse(await readFile(path.join(prefix, 'examples/candidate-b.json'), 'utf8'));
    assert.equal(seed.healthExpectedStatus, 200); assert.equal(seed.healthExpectedBody, 'ready\n');
    const unhealthy = path.join(parent, 'unhealthy.json'); await writeFile(unhealthy, JSON.stringify({ ...seed, healthURL: `http://127.0.0.1:${upstreamPort}/not-ready` }), { mode: 0o600 });
    const rolled = await cli(launcher, 'apply', '--file', unhealthy); assert.equal(rolled.code, 1); assert.equal(rolled.json.outcome, 'rolled_back'); assert.match(rolled.json.reason, /^No fresh acknowledged healthy revision .*health=503\//);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    const wrongCandidate = path.join(parent, 'wrong-body.json');
    await writeFile(wrongCandidate, JSON.stringify({ ...seed, healthURL: `http://127.0.0.1:${upstreamPort}/wrong-ready-body` }), { mode: 0o600 });
    const bodyRollback = await cli(launcher, 'apply', '--file', wrongCandidate);
    assert.equal(bodyRollback.code, 1); assert.equal(bodyRollback.json.outcome, 'rolled_back');
    assert.equal(bodyRollback.stdout.includes('independent application'), false, 'application response bodies stay out of rollback diagnostics');
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    assert.equal((await cli(launcher, 'recover')).code, 0);
    await stop(); await assert.rejects(request(port));
    const restarted = await start(); assert.notEqual(restarted.session, first.session);
    assert.equal((await cli(launcher, 'bind')).code, 0);
    const afterRestart = await upstreamTransfer(port, '/echo', { method: 'POST', body: payload }); assert.deepEqual(afterRestart.body, payload);
    assert.equal(afterRestart.headers['x-x10-example'], 'application-b'); assert(appRequests > 0); assert.equal(echoRequests, 2, 'POST bodies must not be replayed by gateway operations');
    await stop(); assert.equal((await cli(launcher, 'uninstall')).code, 0); assert.equal(await absent(prefix), true);
    assert.equal(groups.size, 0); assert.equal(children.size, 0);
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    for (const signal of ['SIGQUIT', 'SIGTERM', 'SIGKILL']) { for (const pid of groups) { try { process.kill(-pid, signal); } catch {} } for (const child of children) if (child.exitCode === null && child.signalCode === null) { try { child.kill('SIGTERM'); } catch {} } if (groups.size || children.size) await delay(75); }
    app.closeAllConnections(); await new Promise(resolve => app.close(resolve)); await rm(parent, { recursive: true, force: true });
  }
});

test('shipped loopback upstream example is immutable in extracted installs and serves bounded echo and stream', { timeout: 40000 }, async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-example-')); await chmod(parent, 0o700);
  let child, output = '';
  try {
    const archive = path.join(parent, 'alpha.tar.gz'); assert.equal((await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary)).code, 0);
    await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
    const bundle = path.join(parent, 'nginx-x10-alpha'), prefix = path.join(parent, 'installed'), launcher = path.join(prefix, 'bin/x10');
    const upstreamPort = await unusedPort(), { port, healthPort } = await upstreamPorts(upstreamPort);
    const result = await cli(path.join(bundle, 'install.mjs'), 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--upstream-port', String(upstreamPort)); assert.equal(result.code, 0, result.stdout);
    const example = path.join(prefix, 'lib/alpha/upstream-example.mjs'); assert.equal((await lstat(example)).mode & 0o777, 0o400);
    const bytes = await readFile(example); await chmod(example, 0o600);
    try { await writeFile(example, Buffer.concat([bytes, Buffer.from('\n// changed\n')])); assert.equal((await cli(launcher, 'info')).json.code, 'alpha_integrity'); }
    finally { await writeFile(example, bytes); await chmod(example, 0o400); }
    child = spawn(process.execPath, [example, '--port', String(upstreamPort)], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => output += chunk); child.stderr.on('data', chunk => output += chunk);
    await until(async () => { if (child.exitCode !== null || child.signalCode !== null) throw new Error(output); try { return (await request(upstreamPort, '/ready')).status === 200; } catch { return false; } });
    assert.equal((await request(upstreamPort)).body, 'NGINX X10 upstream example\n');
    const payload = Buffer.from([0, 1, 2, 255, 128, 0, 31]); const echoed = await upstreamTransfer(upstreamPort, '/echo', { method: 'POST', body: payload }); assert.deepEqual(echoed.body, payload);
    const streamed = await upstreamTransfer(upstreamPort, '/stream'); assert.equal(streamed.status, 200); assert.equal(streamed.body.length, 8 * 1024 * 1024); assert.equal(digest(streamed.body), digest(Buffer.alloc(8 * 1024 * 1024, 0x78)));
    child.kill('SIGTERM'); await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0, output);
    assert.equal((await cli(launcher, 'uninstall')).code, 0); assert.equal(await absent(prefix), true);
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await until(() => child.exitCode !== null || child.signalCode !== null, 3000).catch(() => child.kill('SIGKILL')); }
    await rm(parent, { recursive: true, force: true });
  }
});
