import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, writeFile, rm, lstat, symlink } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';

// Explicit loopback HTTPS is additional to the controller's unchanged HTTP
// listener. This suite does not turn its HTTP readiness gate into a TLS probe.
const root = fileURLToPath(new URL('../../', import.meta.url));
const manifest = path.resolve(process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'));
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const execute = promisify(execFile), delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function command(file, args) { return execute(file, args, { timeout: 15000, maxBuffer: 2 * 1024 * 1024 }); }
async function cli(file, ...args) {
  try { const r = await command(process.execPath, [file, ...args]); return { code: 0, json: JSON.parse(r.stdout) }; }
  catch (e) { if (!Number.isInteger(e.code)) throw e; return { code: e.code, json: JSON.parse(e.stdout) }; }
}
async function until(fn, timeout = 8000) {
  const end = performance.now() + timeout; let last;
  while (performance.now() < end) { try { const value = await fn(); if (value) return value; } catch (e) { last = e; } await delay(25); }
  throw last || new Error('Frontend TLS fixture deadline');
}
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function unusedPort() { const server = net.createServer(); const port = await listen(server); await new Promise(r => server.close(r)); return port; }
function transfer(port, route = '/', { secure = false, ca, servername = 'localhost', method = 'GET', body = Buffer.alloc(0), version } = {}) {
  return new Promise((resolve, reject) => {
    const req = (secure ? https : http).request({ host: '127.0.0.1', port, path: route, method, agent: false,
      ...(secure ? { ca, servername, rejectUnauthorized: true, ...(version ? { minVersion: version, maxVersion: version } : {}) } : {}), headers: { 'content-length': body.length } }, res => {
      const chunks = []; let bytes = 0;
      const serial = secure ? res.socket.getPeerCertificate().serialNumber : null;
      const protocol = secure ? res.socket.getProtocol() : null;
      res.on('data', b => { bytes += b.length; if (bytes > 1024 * 1024) res.destroy(new Error('response bound')); else chunks.push(b); });
      res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers, serial, protocol }));
    });
    const timer = setTimeout(() => req.destroy(new Error('absolute request deadline')), 2500);
    req.once('close', () => clearTimeout(timer));
    req.setTimeout(2500, () => req.destroy(new Error('idle request deadline'))); req.on('error', reject); req.end(body);
  });
}
async function certificates(dir) {
  const ca = path.join(dir, 'ca.crt'), caKey = path.join(dir, 'ca.key');
  await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=X10 Frontend Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', caKey, '-out', ca]);
  await writeFile(path.join(dir, 'ext.cnf'), 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  const versions = [];
  for (const name of ['v1', 'v2']) {
    const key = path.join(dir, `${name}.key`), cert = path.join(dir, `${name}.crt`), csr = path.join(dir, `${name}.csr`);
    await command('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=localhost', '-keyout', key, '-out', csr]);
    await command('openssl', ['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-sha256', '-extfile', path.join(dir, 'ext.cnf'), '-out', cert]);
    await chmod(key, 0o600); await chmod(cert, 0o644);
    versions.push({ key, cert, serial: new X509Certificate(await readFile(cert)).serialNumber });
  }
  const wrongCA = path.join(dir, 'wrong-ca.crt'), wrongKey = path.join(dir, 'wrong-ca.key');
  await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=Other Frontend Fixture CA', '-keyout', wrongKey, '-out', wrongCA]);
  for (const file of [caKey, wrongKey]) await chmod(file, 0o600);
  return { ca: await readFile(ca), wrongCA: await readFile(wrongCA), versions };
}

test('installed explicit frontend HTTPS preserves trust and certificate lifecycle boundaries', { timeout: 150000 }, async t => {
  const sourceHash = digest(await readFile(new URL(import.meta.url)));
  const managerHash = digest(await readFile(path.join(root, 'x10/control/manager.mjs')));
  const build = JSON.parse(await readFile(manifest)); assert.equal(build.binary.path, binary); assert.equal(build.binary.sha256, digest(await readFile(binary)));
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-frontend-tls-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install'), launcher = path.join(prefix, 'bin/x10'), sockets = new Set();
  let child, nativePid, nativeIdentity, sessionPrefix, nativeConfirmedStopped = false, spawnError, output = '', app, appPort, gatewayPort, tlsPort, interrupted = false, echoRequests = 0, nativeSessionsStopped = 0;
  const emergency = () => { interrupted = true; if (child?.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const check = async (name, fn) => {
    let failure;
    await t.test(name, async () => { try { assert.equal(interrupted, false); await fn(); } catch (e) { failure = e; throw e; } });
    if (failure) throw failure;
  };
  async function start() {
    output = ''; spawnError = null; nativePid = null; nativeIdentity = null; nativeConfirmedStopped = false;
    child = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.once('error', error => { spawnError = error; });
    const collect = chunk => { output = (output + chunk).slice(-65536); const m = /"(?:pid|candidatePid)": (\d+)/.exec(output); if (m) nativePid = Number(m[1]); };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    await until(() => { if (spawnError) throw spawnError; if (child.exitCode !== null || child.signalCode !== null) throw new Error('installed run exited'); return output.includes('"outcome": "running"'); });
    const info = (await cli(launcher, 'info')).json; sessionPrefix = info.sessionPrefix;
    nativeIdentity = JSON.parse(await readFile(path.join(sessionPrefix, 'lifecycle.json'))).runtime; assert(nativeIdentity);
    assert.equal((await cli(launcher, 'wait-bind', '--timeout-ms', '10000')).code, 0);
  }
  async function stop() {
    assert.equal((await cli(launcher, 'stop')).code, 0); await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0);
    assert.equal(await inspectMaster(path.join(prefix, 'bin/nginx'), sessionPrefix, nativeIdentity, false), null);
    assert.equal((await remainingNativeGroup(path.join(prefix, 'bin/nginx'), nativeIdentity)).length, 0);
    nativeConfirmedStopped = true; nativePid = null; nativeSessionsStopped++;
  }
  try {
    const pki = await certificates(parent), [v1, v2] = pki.versions;
    app = http.createServer((req, res) => {
      if (req.url === '/ready') { res.end('ready\n'); return; }
      if (req.method === 'POST' && req.url === '/echo') {
        echoRequests++; const chunks = []; let bytes = 0;
        req.on('data', b => { bytes += b.length; if (bytes > 256 * 1024) req.destroy(); else chunks.push(b); });
        req.on('end', () => res.end(Buffer.concat(chunks))); return;
      }
      if (req.url === '/stream') { res.write(Buffer.alloc(32768, 37)); res.end(Buffer.alloc(32769, 91)); return; }
      res.end('verified frontend HTTPS proxy\n');
    });
    app.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    app.on('clientError', (_e, socket) => socket.destroy()); app.requestTimeout = 4000; app.headersTimeout = 4000;
    appPort = await listen(app);
    do { gatewayPort = await unusedPort(); } while (gatewayPort === appPort);
    do { tlsPort = await unusedPort(); } while ([gatewayPort, appPort].includes(tlsPort));
    let healthPort; do { healthPort = await unusedPort(); } while ([tlsPort, appPort, gatewayPort].includes(healthPort));
    await check('pack, extract and install the exact candidate with legacy HTTP defaults', async () => {
      const archive = path.join(parent, 'alpha.tar.gz'); assert.equal((await cli(path.join(root, 'x10/alpha/cli.mjs'), 'pack', '--output', archive, '--manifest', manifest, '--binary', binary)).code, 0);
      await command('tar', ['-xzf', archive, '-C', parent]);
      const installer = path.join(parent, 'nginx-x10-alpha/install.mjs');
      assert.equal((await cli(installer, 'install', '--prefix', prefix, '--port', String(gatewayPort), '--health-port', String(healthPort), '--upstream-port', String(appPort))).code, 0);
      assert.equal(digest(await readFile(path.join(prefix, 'lib/control/manager.mjs'))), managerHash);
      assert.equal((await lstat(prefix)).mode & 0o777, 0o700);
    });
    await check('installed startup binds the original HTTP listener before explicit TLS', async () => {
      await start(); assert.equal((await transfer(gatewayPort)).body.toString(), 'verified frontend HTTPS proxy\n');
      await assert.rejects(transfer(tlsPort, '/', { secure: true, ca: pki.ca }));
    });
    const base = { serverBody: `location / { proxy_pass http://127.0.0.1:${appPort}; proxy_http_version 1.1; proxy_next_upstream off; }`,
      healthURL: `http://127.0.0.1:${appPort}/ready`, healthExpectedStatus: 200, healthExpectedBody: 'ready\n' };
    const candidate = version => ({ ...base, https: { port: tlsPort, certificate: version.cert, certificateKey: version.key } });
    async function apply(value, name) { const file = path.join(parent, `${name}.json`); await writeFile(file, JSON.stringify(value), { mode: 0o600 }); return cli(launcher, 'apply', '--file', file); }
    const secure = options => transfer(tlsPort, '/', { secure: true, ca: pki.ca, ...options });
    let goodRevision;
    await check('explicit loopback HTTPS serves an authenticated certificate while HTTP stays available', async () => {
      const result = await apply(candidate(v1), 'tls-v1'); assert.equal(result.code, 0); goodRevision = result.json.revision;
      const response = await until(async () => { const r = await secure(); return r.serial === v1.serial && r; });
      assert.equal(response.status, 200); assert.equal(response.body.toString(), 'verified frontend HTTPS proxy\n');
      assert.equal((await transfer(gatewayPort)).status, 200);
    });
    await check('both declared TLS 1.2 and TLS 1.3 negotiate with strict CA and hostname verification', async () => {
      for (const version of ['TLSv1.2', 'TLSv1.3']) { const r = await secure({ version }); assert.equal(r.status, 200); assert.equal(r.protocol, version); }
    });
    await check('TLS clients reject a wrong CA and hostname rather than disabling verification', async () => {
      await assert.rejects(secure({ ca: pki.wrongCA }), e => ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(e.code));
      await assert.rejects(secure({ servername: 'wrong.invalid' }), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
    });
    await check('frontend HTTPS preserves POST and streamed application bytes without replay', async () => {
      const body = Buffer.alloc(65551); for (let i = 0; i < body.length; i++) body[i] = (i * 37) & 255;
      const echo = await transfer(tlsPort, '/echo', { secure: true, ca: pki.ca, method: 'POST', body }); assert.equal(echo.status, 200); assert.deepEqual(echo.body, body); assert.equal(echoRequests, 1);
      const stream = await transfer(tlsPort, '/stream', { secure: true, ca: pki.ca }); assert.equal(stream.status, 200); assert.deepEqual(stream.body, Buffer.concat([Buffer.alloc(32768, 37), Buffer.alloc(32769, 91)]));
    });
    await check('native certificate and private-key mismatch is rejected before reload', async () => {
      const fragment = digest(await readFile(path.join(sessionPrefix, 'managed.conf')));
      const result = await apply({ ...candidate(v1), https: { ...candidate(v1).https, certificateKey: v2.key } }, 'mismatched-key');
      assert.equal(result.code, 1); assert.equal(result.json.outcome, 'rejected'); assert.match(result.json.reason, /key values mismatch|key.*mismatch/i);
      assert.equal(digest(await readFile(path.join(sessionPrefix, 'managed.conf'))), fragment);
      assert.equal((await cli(launcher, 'status')).json.lastConfirmedRevision, goodRevision);
      assert.equal((await secure()).serial, v1.serial); assert.equal(echoRequests, 1);
    });
    for (const name of ['missing-key', 'world-readable-key', 'symlink-certificate', 'symlink-parent']) {
      await check(`${name} is refused without replacing the known-good TLS revision`, async () => {
        const value = candidate(v1), original = digest(await readFile(path.join(sessionPrefix, 'managed.conf')));
        if (name === 'missing-key') value.https.certificateKey = path.join(parent, 'absent.key');
        if (name === 'world-readable-key') await chmod(v1.key, 0o644);
        if (name === 'symlink-certificate') { const link = path.join(parent, 'cert-link.crt'); await symlink(v1.cert, link); value.https.certificate = link; }
        if (name === 'symlink-parent') { const link = path.join(parent, 'directory-alias'); await symlink(parent, link); value.https.certificate = path.join(link, 'v1.crt'); }
        let result; try { result = await apply(value, name); } finally { if (name === 'world-readable-key') await chmod(v1.key, 0o600); }
        assert.equal(result.code, 1); assert.equal((await cli(launcher, 'status')).json.lastConfirmedRevision, goodRevision);
        assert.equal(digest(await readFile(path.join(sessionPrefix, 'managed.conf'))), original);
        assert.equal((await secure()).serial, v1.serial); assert.equal(echoRequests, 1);
      });
    }
    await check('certificate rotation uses a new versioned pair and explicit revert retains the previous pair', async () => {
      const rotated = await apply(candidate(v2), 'tls-v2'); assert.equal(rotated.code, 0);
      await until(async () => (await secure()).serial === v2.serial);
      const reverted = await cli(launcher, 'revert', '--revision', goodRevision); assert.equal(reverted.code, 0); goodRevision = reverted.json.revision;
      await until(async () => (await secure()).serial === v1.serial); assert.equal(echoRequests, 1);
      assert.equal((await cli(launcher, 'recover')).code, 0);
    });
    await check('verified stop and new installed session preserve the last-confirmed TLS input', async () => {
      await stop(); await assert.rejects(secure()); await start();
      const response = await secure(); assert.equal(response.status, 200); assert.equal(response.serial, v1.serial);
      assert.equal((await transfer(gatewayPort)).status, 200); assert.equal(echoRequests, 1);
    });
    await check('removing the explicit TLS field closes its listener after normal worker drain', async () => {
      const result = await apply(base, 'http-only'); assert.equal(result.code, 0);
      await until(async () => { try { await secure(); return false; } catch (e) { return e.code === 'ECONNREFUSED'; } });
      assert.equal((await transfer(gatewayPort)).status, 200); assert.equal(echoRequests, 1);
    });
    await check('stop and uninstall remove only the owned installation and no native listener remains', async () => {
      await stop(); await assert.rejects(transfer(gatewayPort)); await assert.rejects(secure());
      assert.equal((await cli(launcher, 'uninstall')).code, 0); await assert.rejects(lstat(prefix), { code: 'ENOENT' });
      for (const version of pki.versions) { assert((await lstat(version.cert)).isFile()); assert((await lstat(version.key)).isFile()); }
    });
    assert.equal(digest(await readFile(new URL(import.meta.url))), sourceHash); assert.equal(digest(await readFile(path.join(root, 'x10/control/manager.mjs'))), managerHash);
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    const cleanupErrors = [];
    try {
      if (child?.exitCode === null && child.signalCode === null) { await cli(launcher, 'stop').catch(() => {}); child.kill('SIGTERM'); await until(() => child.exitCode !== null || child.signalCode !== null); }
      if (!nativeConfirmedStopped && nativeIdentity) {
        const selected = path.join(prefix, 'bin/nginx');
        const live = await inspectMaster(selected, sessionPrefix, nativeIdentity, false); if (live) process.kill(live.pid, 'SIGTERM');
        await until(async () => !(await inspectMaster(selected, sessionPrefix, nativeIdentity, false)) && !(await remainingNativeGroup(selected, nativeIdentity)).length);
        nativeConfirmedStopped = true;
      }
      if (nativePid && !nativeConfirmedStopped) throw new Error('Native identity unavailable during cleanup');
    } catch { cleanupErrors.push('owned-native-exit-unconfirmed'); }
    for (const socket of sockets) socket.destroy();
    if (app?.listening) { app.closeAllConnections(); try { await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Origin close deadline')), 3000); app.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); }); }); } catch { cleanupErrors.push('owned-origin-close-unconfirmed'); } }
    try { await until(() => sockets.size === 0, 3000); } catch { cleanupErrors.push('owned-sockets-not-closed'); }
    if (!cleanupErrors.length) await rm(parent, { recursive: true, force: true });
    assert.equal(cleanupErrors.length, 0, 'Frontend TLS cleanup incomplete; private prefix preserved');
    console.log(JSON.stringify({ suite: 'frontend-tls-owned-cleanup', nativeStopped: nativeConfirmedStopped, nativeSessionsStopped, launcherExited: !child || child.exitCode !== null || child.signalCode !== null, openSockets: sockets.size, temporaryRootRemoved: true, applicationPostRequests: echoRequests }));
  }
});
