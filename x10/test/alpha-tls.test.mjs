import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, writeFile, rm, lstat } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';

// This profile authenticates an HTTPS application upstream. The managed listener
// and bounded readiness relay remain HTTP/loopback; neither is frontend TLS.
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
  throw last || new Error('TLS fixture deadline');
}
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function unusedPort() { const server = net.createServer(); const port = await listen(server); await new Promise(r => server.close(r)); return port; }
function transfer(port, route = '/', { secure = false, ca, servername = 'localhost', method = 'GET', body = Buffer.alloc(0) } = {}) {
  return new Promise((resolve, reject) => {
    const req = (secure ? https : http).request({ host: '127.0.0.1', port, path: route, method, agent: false,
      ...(secure ? { ca, servername, rejectUnauthorized: true } : {}), headers: { 'content-length': body.length } }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', b => { bytes += b.length; if (bytes > 1024 * 1024) res.destroy(new Error('response bound')); else chunks.push(b); });
      res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }));
    });
    req.setTimeout(2500, () => req.destroy(new Error('request deadline'))); req.on('error', reject); req.end(body);
  });
}
async function certificates(dir) {
  const ca = path.join(dir, 'ca.crt'), caKey = path.join(dir, 'ca.key'), key = path.join(dir, 'server.key'), cert = path.join(dir, 'server.crt');
  await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=X10 TLS Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', caKey, '-out', ca]);
  await command('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=localhost', '-keyout', key, '-out', path.join(dir, 'server.csr')]);
  await writeFile(path.join(dir, 'ext.cnf'), 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  await command('openssl', ['x509', '-req', '-in', path.join(dir, 'server.csr'), '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-sha256', '-extfile', path.join(dir, 'ext.cnf'), '-out', cert]);
  await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=Other TLS Fixture CA', '-keyout', path.join(dir, 'wrong-ca.key'), '-out', path.join(dir, 'wrong-ca.crt')]);
  for (const file of [caKey, key, path.join(dir, 'wrong-ca.key')]) { await chmod(file, 0o600); assert.equal((await lstat(file)).mode & 0o777, 0o600); }
  return { ca, cert, key, wrongCA: path.join(dir, 'wrong-ca.crt') };
}

test('extracted native alpha authenticates HTTPS upstream and rolls back rejected TLS candidates', { timeout: 100000 }, async t => {
  const sourceHash = digest(await readFile(new URL(import.meta.url)));
  const build = JSON.parse(await readFile(manifest)); assert.equal(build.binary.path, binary); assert.equal(build.binary.sha256, digest(await readFile(binary)));
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-tls-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install'), launcher = path.join(prefix, 'bin/x10'), sockets = new Set();
  let child, nativePid, nativeIdentity, sessionPrefix, nativeConfirmedStopped = false, spawnError, output = '', gatewayPort, app, readiness, appPort, readyPort, interrupted = false, echoRequests = 0, relay502 = 0;
  const emergency = () => { interrupted = true; if (child?.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const track = server => server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const check = async (name, fn) => {
    let failure;
    await t.test(name, async () => { try { assert.equal(interrupted, false); await fn(); } catch (e) { failure = e; throw e; } });
    if (failure) throw failure;
  };
  try {
    const pki = await certificates(parent), ca = await readFile(pki.ca), wrongCA = await readFile(pki.wrongCA);
    app = https.createServer({ key: await readFile(pki.key), cert: await readFile(pki.cert), minVersion: 'TLSv1.2' }, (req, res) => {
      res.setHeader('X-TLS-App', 'authenticated-origin');
      if (req.url === '/ready') { res.end('ready\n'); return; }
      if (req.method === 'POST' && req.url === '/echo') {
        echoRequests++; const chunks = []; let bytes = 0;
        req.on('data', b => { bytes += b.length; if (bytes > 256 * 1024) req.destroy(); else chunks.push(b); });
        req.on('end', () => res.end(Buffer.concat(chunks))); return;
      }
      if (req.url === '/stream') { res.write(Buffer.alloc(32768, 37)); res.end(Buffer.alloc(32769, 91)); return; }
      res.end('verified HTTPS application\n');
    });
    track(app); app.on('tlsClientError', () => {}); app.requestTimeout = 4000; app.headersTimeout = 4000;
    appPort = await listen(app);
    readiness = http.createServer(async (req, res) => {
      if (req.url !== '/tls-probe') { res.end('ready\n'); return; }
      // Probe a regular managed application route, never __x10_health: no cycle.
      try { const result = await transfer(gatewayPort, '/ready'); if (result.status === 502) relay502++; res.writeHead(result.status); res.end(result.body); }
      catch { res.writeHead(503); res.end('not ready\n'); }
    });
    readiness.on('clientError', (_e, socket) => socket.destroy()); track(readiness); readiness.requestTimeout = 4000; readiness.headersTimeout = 4000;
    readyPort = await listen(readiness);
    do { gatewayPort = await unusedPort(); } while ([appPort, readyPort].includes(gatewayPort));
    let healthPort; do { healthPort = await unusedPort(); } while ([appPort, readyPort, gatewayPort].includes(healthPort));
    await check('pack, extract and invoke the extracted installer', async () => {
      const archive = path.join(parent, 'alpha.tar.gz'); assert.equal((await cli(path.join(root, 'x10/alpha/cli.mjs'), 'pack', '--output', archive, '--manifest', manifest, '--binary', binary)).code, 0);
      await command('tar', ['-xzf', archive, '-C', parent]);
      const installer = path.join(parent, 'nginx-x10-alpha/install.mjs');
      assert.equal((await cli(installer, 'install', '--prefix', prefix, '--port', String(gatewayPort), '--health-port', String(healthPort), '--upstream-port', String(readyPort))).code, 0);
      assert.equal((await lstat(prefix)).mode & 0o777, 0o700);
    });
    child = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.once('error', error => { spawnError = error; });
    child.stdout.on('data', chunk => { output = (output + chunk).slice(-65536); const m = /"(?:pid|candidatePid)": (\d+)/.exec(output); if (m) nativePid = Number(m[1]); });
    child.stderr.on('data', chunk => { output = (output + chunk).slice(-65536); });
    await check('installed startup and explicit bounded bind', async () => {
      await until(() => { if (spawnError) throw spawnError; if (child.exitCode !== null || child.signalCode !== null) throw new Error('installed run exited'); return output.includes('"outcome": "running"'); });
      const info = (await cli(launcher, 'info')).json; sessionPrefix = info.sessionPrefix;
      nativeIdentity = JSON.parse(await readFile(path.join(sessionPrefix, 'lifecycle.json'))).runtime; assert(nativeIdentity);
      assert.equal((await cli(launcher, 'wait-bind', '--timeout-ms', '10000')).code, 0);
    });
    const candidate = (trusted = pki.ca, name = 'localhost', target = appPort) => ({
      serverBody: `location / { proxy_pass https://127.0.0.1:${target}; proxy_http_version 1.1; proxy_next_upstream off; proxy_ssl_verify on; proxy_ssl_verify_depth 2; proxy_ssl_trusted_certificate "${trusted}"; proxy_ssl_server_name on; proxy_ssl_name ${name}; }`,
      healthURL: `http://127.0.0.1:${readyPort}/tls-probe`, healthExpectedStatus: 200, healthExpectedBody: 'ready\n'
    });
    async function apply(value, name) { const file = path.join(parent, `${name}.json`); await writeFile(file, JSON.stringify(value), { mode: 0o600 }); return cli(launcher, 'apply', '--file', file); }
    let goodRevision;
    await check('explicit trusted CA and hostname enable the installed native HTTPS proxy', async () => {
      const direct = await transfer(appPort, '/', { secure: true, ca }); assert.equal(direct.status, 200); assert.equal(direct.body.toString(), 'verified HTTPS application\n');
      const result = await apply(candidate(), 'good'); assert.equal(result.code, 0); goodRevision = result.json.revision;
      const response = await until(async () => { const response = await transfer(gatewayPort); return response.body.toString() === 'verified HTTPS application\n' && response; });
      assert.equal(response.headers['x-tls-app'], 'authenticated-origin');
    });
    await check('verified native HTTPS proxy preserves POST bytes and streamed bytes', async () => {
      const payload = Buffer.alloc(65551); for (let i = 0; i < payload.length; i++) payload[i] = (i * 37) & 255;
      const echo = await transfer(gatewayPort, '/echo', { method: 'POST', body: payload }); assert.equal(echo.status, 200); assert.deepEqual(echo.body, payload); assert.equal(echoRequests, 1);
      const streamed = await transfer(gatewayPort, '/stream'); assert.equal(streamed.status, 200); assert.deepEqual(streamed.body, Buffer.concat([Buffer.alloc(32768, 37), Buffer.alloc(32769, 91)]));
    });
    for (const [name, value] of [['wrong-ca', candidate(pki.wrongCA)], ['wrong-hostname', candidate(pki.ca, 'wrong.invalid')], ['plaintext-peer', candidate(pki.ca, 'localhost', readyPort)]]) {
      await check(`${name} refuses native TLS readiness and rolls back to known good`, async () => {
        const before502 = relay502, result = await apply(value, name); assert.equal(result.code, 1); assert.equal(result.json.outcome, 'rolled_back');
        assert.match(result.json.reason, /health=502\//); assert(relay502 > before502, 'actual native TLS proxy refusal must reach the readiness relay');
        assert.equal(result.json.restoredContentFrom, goodRevision);
        await until(async () => (await transfer(gatewayPort)).body.toString() === 'verified HTTPS application\n');
        assert.equal((await cli(launcher, 'status')).json.lastConfirmedRevision, result.json.revision);
        goodRevision = result.json.revision;
        assert.equal(echoRequests, 1, 'readiness and rollback never replay the application POST');
      });
    }
    await check('direct client independently rejects wrong CA and hostname', async () => {
      await assert.rejects(transfer(appPort, '/', { secure: true, ca: wrongCA }), e => ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(e.code));
      await assert.rejects(transfer(appPort, '/', { secure: true, ca, servername: 'wrong.invalid' }), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
    });
    await check('recover preserves verified TLS and stop/uninstall leave no serving fixture', async () => {
      assert.equal((await cli(launcher, 'recover')).code, 0); assert.equal((await transfer(gatewayPort)).status, 200);
      assert.equal((await cli(launcher, 'stop')).code, 0); await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0);
      assert.equal(await inspectMaster(path.join(prefix, 'bin/nginx'), sessionPrefix, nativeIdentity, false), null);
      assert.equal((await remainingNativeGroup(path.join(prefix, 'bin/nginx'), nativeIdentity)).length, 0);
      nativeConfirmedStopped = true; nativePid = null;
      await assert.rejects(transfer(gatewayPort)); assert.equal((await cli(launcher, 'uninstall')).code, 0);
      await assert.rejects(lstat(prefix), { code: 'ENOENT' });
    });
    assert.equal(digest(await readFile(new URL(import.meta.url))), sourceHash);
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    const cleanupErrors = [];
    try {
      if (child?.exitCode === null && child.signalCode === null) {
        await cli(launcher, 'stop').catch(() => {});
        child.kill('SIGTERM');
        await until(() => child.exitCode !== null || child.signalCode !== null);
      }
      if (!nativeConfirmedStopped && nativeIdentity) {
        const selected = path.join(prefix, 'bin/nginx');
        const live = await inspectMaster(selected, sessionPrefix, nativeIdentity, false);
        if (live) process.kill(live.pid, 'SIGTERM');
        await until(async () => !(await inspectMaster(selected, sessionPrefix, nativeIdentity, false)) && !(await remainingNativeGroup(selected, nativeIdentity)).length);
        nativeConfirmedStopped = true;
      }
      if (nativePid && !nativeConfirmedStopped) throw new Error('Native identity unavailable during cleanup');
    } catch { cleanupErrors.push('owned-native-exit-unconfirmed'); }
    for (const socket of sockets) socket.destroy();
    for (const server of [app, readiness]) if (server?.listening) {
      server.closeAllConnections();
      try { await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Origin close deadline')), 3000);
        server.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); });
      }); } catch { cleanupErrors.push('owned-origin-close-unconfirmed'); }
    }
    try { await until(() => sockets.size === 0, 3000); } catch { cleanupErrors.push('owned-sockets-not-closed'); }
    if (!cleanupErrors.length) await rm(parent, { recursive: true, force: true });
    assert.equal(cleanupErrors.length, 0, 'TLS fixture cleanup incomplete; private prefix preserved');
    console.log(JSON.stringify({ suite: 'alpha-tls-owned-cleanup', nativeStopped: nativeConfirmedStopped, launcherExited: !child || child.exitCode !== null || child.signalCode !== null, openSockets: sockets.size, temporaryRootRemoved: true, relay502Observations: relay502, applicationPostRequests: echoRequests }));
  }
});
