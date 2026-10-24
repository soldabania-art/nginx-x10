#!/usr/bin/env node
// Native NGINX baseline only. Node hosts fixtures and assertions, never the proxy.
// Run: X10_NGINX_BINARY=/absolute/path/to/nginx node x10/test/http-baseline.mjs
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const asText = error => error?.message || String(error);

async function command(file, args, options = {}) {
  return execute(file, args, { encoding: 'utf8', timeout: 10_000, maxBuffer: 2 * 1024 * 1024, ...options });
}

async function waitFor(predicate, label, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await predicate();
      if (result) return result;
    } catch (error) { lastError = error; }
    await delay(30);
  }
  throw new Error(`Timed out waiting for ${label}${lastError ? `: ${asText(lastError)}` : ''}`);
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function unusedPort() {
  const reservation = net.createServer();
  const port = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  return port;
}

function request(port, target = '/', { method = 'GET', body, tls, headers = {}, timeoutMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const transport = tls ? https : http;
    const req = transport.request({
      hostname: '127.0.0.1', port, path: target, method, agent: false,
      headers: { ...headers, ...(payload ? { 'content-length': payload.length } : {}) },
      ...(tls || {}),
    }, res => {
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 1024 * 1024) req.destroy(new Error('Fixture response exceeded limit'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Fixture request timed out')));
    req.on('error', reject);
    req.end(payload);
  });
}

function openStream(port, token) {
  const result = { chunks: [], ended: false, response: null, request: null, firstAt: null, firstReady: false, endedAt: null };
  let firstResolve, firstReject, completeResolve, completeReject;
  result.first = new Promise((resolve, reject) => { firstResolve = resolve; firstReject = reject; });
  result.complete = new Promise((resolve, reject) => { completeResolve = resolve; completeReject = reject; });
  // The test intentionally holds completion across reloads; errors must never be unhandled.
  result.first.catch(() => {});
  result.complete.catch(() => {});
  const fail = error => { firstReject(error); completeReject(error); };
  result.request = http.get({ hostname: '127.0.0.1', port, path: `/stream?token=${token}`, agent: false }, res => {
    result.response = res;
    res.on('data', chunk => {
      result.chunks.push(chunk);
      if (result.firstAt === null) result.firstAt = Date.now();
      if (!result.firstReady) {
        // TCP/data-event boundaries need not match application writes.
        const received = Buffer.concat(result.chunks).toString('utf8');
        const lineEnd = received.indexOf('\n');
        if (lineEnd !== -1) {
          result.firstReady = true;
          firstResolve(received.slice(0, lineEnd + 1));
        }
      }
    });
    res.on('error', fail);
    res.on('end', () => {
      result.ended = true;
      result.endedAt = Date.now();
      if (!result.firstReady) firstReject(new Error('Stream ended without a complete first fixture line'));
      completeResolve(Buffer.concat(result.chunks).toString('utf8'));
    });
  });
  result.request.setTimeout(12_000, () => result.request.destroy(new Error('Held stream timed out')));
  result.request.on('error', fail);
  return result;
}

function fixture(id, receipts, gates) {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    const target = new URL(req.url, 'http://fixture.local');
    if (target.pathname === '/stream') {
      const token = target.searchParams.get('token');
      res.writeHead(200, { 'content-type': 'text/plain', 'x-fixture-id': id });
      res.flushHeaders();
      res.write(`first:${id}\n`);
      gates.set(token, { id, release: () => res.end(`last:${id}\n`) });
      res.on('close', () => gates.delete(token));
      return;
    }
    if (req.method === 'POST' && (target.pathname === '/write' || target.pathname === '/write-fail')) {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        receipts.push({ id, path: target.pathname, body: Buffer.concat(chunks).toString('utf8') });
        if (target.pathname === '/write-fail') {
          // A real received write followed by transport failure: replay would be observable.
          req.socket.destroy();
        } else {
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end(`${id}:${Buffer.concat(chunks).toString('utf8')}`);
        }
      });
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain', 'x-fixture-id': id });
    res.end(id);
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return { server, sockets };
}

function nginxQuote(value) {
  return `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
}

function config({ prefix, publicPort, tlsPort, aPort, bPort, routePort, h2 }) {
  // Private loopback test workers retain the invoking UID. User namespaces can
  // expose uid 0 while leaving the packaged default nobody UID unmapped.
  const workerUser = process.geteuid?.() === 0 ? `user ${nginxQuote(os.userInfo().username)};` : '';
  const tlsServer = tlsPort ? `
    server {
      listen 127.0.0.1:${tlsPort} ssl;
      ${h2 ? 'http2 on;' : ''}
      server_name localhost;
      ssl_certificate ${nginxQuote(path.join(prefix, 'certs/server.crt'))};
      ssl_certificate_key ${nginxQuote(path.join(prefix, 'certs/server.key'))};
      ssl_protocols TLSv1.2 TLSv1.3;
      location / { proxy_pass http://balanced; proxy_buffering off; }
    }` : '';
  return `${workerUser}
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 10s;
pid ${nginxQuote(path.join(prefix, 'nginx.pid'))};
error_log ${nginxQuote(path.join(prefix, 'logs/error.log'))} notice;
events { worker_connections 128; }
http {
  access_log off;
  client_body_temp_path ${nginxQuote(path.join(prefix, 'body-temp'))};
  proxy_temp_path ${nginxQuote(path.join(prefix, 'proxy-temp'))};
  proxy_http_version 1.1;
  proxy_set_header Connection "";
  proxy_connect_timeout 2s;
  proxy_read_timeout 10s;
  proxy_send_timeout 2s;
  proxy_next_upstream error timeout invalid_header http_502;
  proxy_next_upstream_tries 2;
  upstream balanced {
    server 127.0.0.1:${aPort} max_fails=0;
    server 127.0.0.1:${bPort} max_fails=0;
  }
  server {
    listen 127.0.0.1:${publicPort};
    server_name localhost;
    location = /ready { return 200 "ready"; }
    location = /route { proxy_pass http://127.0.0.1:${routePort}; }
    location = /stream { proxy_pass http://127.0.0.1:${routePort}; proxy_buffering off; }
    location / { proxy_pass http://balanced; }
  }
  ${tlsServer}
}
`;
}

async function makeCertificates(prefix) {
  const dir = path.join(prefix, 'certs');
  await mkdir(dir, { mode: 0o700 });
  const caKey = path.join(dir, 'ca.key'), caCert = path.join(dir, 'ca.crt');
  const serverKey = path.join(dir, 'server.key'), csr = path.join(dir, 'server.csr');
  const serverCert = path.join(dir, 'server.crt'), extensions = path.join(dir, 'extensions.cnf');
  await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
    '-subj', '/CN=X10 Native Baseline CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', caKey, '-out', caCert]);
  await command('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-subj', '/CN=localhost', '-keyout', serverKey, '-out', csr]);
  await writeFile(extensions, 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  await command('openssl', ['x509', '-req', '-in', csr, '-CA', caCert, '-CAkey', caKey,
    '-CAcreateserial', '-out', serverCert, '-days', '1', '-sha256', '-extfile', extensions]);
  await chmod(caKey, 0o600);
  await chmod(serverKey, 0o600);
  return { ca: await readFile(caCert), caSha256: sha256(await readFile(caCert)), certSha256: sha256(await readFile(serverCert)) };
}

async function h2Request(port, ca) {
  const session = http2.connect(`https://127.0.0.1:${port}`, { ca, servername: 'localhost', rejectUnauthorized: true });
  let timer;
  try {
    const connected = Promise.race([
      once(session, 'connect'),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('HTTP/2 connect timed out')), 3000); }),
    ]);
    await connected;
    clearTimeout(timer);
    assert.equal(session.alpnProtocol, 'h2');
    assert.equal(session.socket.authorized, true);
    const result = await new Promise((resolve, reject) => {
      const stream = session.request({ ':method': 'GET', ':path': '/h2-native' });
      const chunks = [];
      let headers;
      stream.setTimeout(3000, () => stream.destroy(new Error('HTTP/2 response timed out')));
      stream.on('response', value => { headers = value; });
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('error', reject);
      session.once('error', reject);
      stream.on('end', () => resolve({ status: headers?.[':status'], body: Buffer.concat(chunks).toString('utf8'), alpn: session.alpnProtocol }));
      stream.end();
    });
    return result;
  } finally {
    clearTimeout(timer);
    session.destroy();
  }
}

function signalGroup(child, signal) {
  try {
    if (process.platform === 'win32') child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

async function stopChild(child) {
  if (!child?.pid) return { started: false };
  const exited = () => child.exitCode !== null || child.signalCode !== null;
  const wait = async ms => {
    const deadline = Date.now() + ms;
    while (!exited() && Date.now() < deadline) await delay(20);
    return exited();
  };
  let mode = 'already-exited';
  if (!exited()) {
    mode = 'SIGQUIT';
    child.kill('SIGQUIT');
    if (!await wait(3000)) {
      mode = 'SIGTERM';
      signalGroup(child, 'SIGTERM');
      if (!await wait(1000)) {
        mode = 'SIGKILL';
        signalGroup(child, 'SIGKILL');
        await wait(1000);
      }
    }
  }
  // Only the dedicated process group created by this harness is addressed.
  signalGroup(child, 'SIGKILL');
  return { started: true, mode, exitCode: child.exitCode, signal: child.signalCode, exited: exited() };
}

export async function runBaseline({ binary }) {
  const evidence = {
    schemaVersion: 1, suite: 'nginx-x10-native-http-baseline', startedAt: new Date().toISOString(),
    identity: {}, options: {}, tests: [], limitations: [
      'Regression fixtures are not load benchmarks or a performance-superiority claim.',
      'HTTP/2 test covers downstream TLS HTTP/2 to native NGINX with HTTP/1 upstream fixtures; upstream HTTP/2 and multiplexing are untested.',
      'HTTP/3/QUIC, mail, stream, control API, FastCGI/SCGI/uWSGI/memcached and exhaustive platform/module failure paths are untested.',
      'Reload rejection covers invalid syntax, not arbitrary late module initialization or shared-memory side effects.',
      'Checkout identity and binary hash/version/options are recorded separately; this harness does not cryptographically attest the build source.',
    ],
  };
  let prefix, child, held, interrupted = false;
  const fixtures = [], receipts = [], gates = new Map();
  let childOutput = '';
  const add = (name, details = {}) => evidence.tests.push({ name, ...details, status: 'passed' });
  const onInterrupt = () => { interrupted = true; if (child?.pid) signalGroup(child, 'SIGKILL'); process.exitCode = 130; };
  process.once('SIGINT', onInterrupt);
  process.once('SIGTERM', onInterrupt);
  try {
    binary = path.resolve(binary);
    const version = await command(binary, ['-V']);
    const binaryBytes = await readFile(binary);
    const source = {};
    for (const [key, args] of Object.entries({ commit: ['rev-parse', 'HEAD'], tree: ['rev-parse', 'HEAD^{tree}'], branch: ['branch', '--show-current'], trackedChanges: ['status', '--porcelain', '--untracked-files=no'] })) {
      try { source[key] = (await command('git', args, { cwd: repoRoot })).stdout.trim(); }
      catch { source[key] = 'unavailable'; }
    }
    const versionOutput = `${version.stdout}${version.stderr}`.trim();
    const tlsEnabled = versionOutput.includes('--with-http_ssl_module');
    const h2Enabled = versionOutput.includes('--with-http_v2_module');
    evidence.identity = { sourceCheckout: repoRoot, source, binary, binarySha256: sha256(binaryBytes), binarySize: (await stat(binary)).size,
      versionOutput, node: process.version, platform: process.platform, arch: process.arch };
    prefix = await mkdtemp(path.join(os.tmpdir(), 'nginx-x10-native-'));
    await chmod(prefix, 0o700);
    await mkdir(path.join(prefix, 'logs'), { mode: 0o700 });
    await mkdir(path.join(prefix, 'conf'), { mode: 0o700 });
    let certificates;
    if (tlsEnabled) {
      certificates = await makeCertificates(prefix);
      evidence.identity.certificates = { caSha256: certificates.caSha256, serverSha256: certificates.certSha256 };
    }
    for (const id of ['a', 'b']) {
      const item = fixture(id, receipts, gates);
      fixtures.push(item);
      item.port = await listen(item.server);
    }
    const [a, b] = fixtures;
    const publicPort = await unusedPort();
    let tlsPort = tlsEnabled ? await unusedPort() : null;
    while (tlsPort === publicPort) tlsPort = await unusedPort();
    const settings = { prefix, publicPort, tlsPort, aPort: a.port, bPort: b.port, routePort: a.port, h2: h2Enabled };
    const configPath = path.join(prefix, 'conf/nginx.conf');
    const logPath = path.join(prefix, 'logs/error.log');
    const args = ['-p', `${prefix}/`, '-c', configPath, '-e', logPath];
    evidence.options = { bind: '127.0.0.1', prefix, privatePrefixMode: '0700', publicPort, tlsPort, fixturePorts: fixtures.map(item => item.port),
      args, workerProcesses: 1, workerUid: process.geteuid?.() ?? null, workerUserPolicy: 'retain invoking UID in private loopback fixtures', proxyHttpVersion: '1.1', retryNonIdempotent: false, nativeWorkerShutdownTimeoutMs: 10_000, cleanupGraceMs: 3000, tlsVerificationDisabled: false, configurations: [] };
    const replaceConfig = async (text, label) => {
      const candidate = `${configPath}.next`;
      await writeFile(candidate, text, { mode: 0o600 });
      await rename(candidate, configPath);
      evidence.options.configurations.push({ label, sha256: sha256(text), bytes: Buffer.byteLength(text) });
    };
    const initial = config(settings);
    await replaceConfig(initial, 'initial-a');
    await command(binary, [...args, '-t']);
    add('valid-config-native-t');
    const invalidPath = path.join(prefix, 'conf/invalid.conf');
    await writeFile(invalidPath, `${initial}\nx10_invalid_directive;\n`, { mode: 0o600 });
    let invalidResult;
    try { await command(binary, ['-p', `${prefix}/`, '-c', invalidPath, '-e', logPath, '-t']); }
    catch (error) { invalidResult = error; }
    assert(invalidResult && typeof invalidResult.code === 'number' && invalidResult.code !== 0, 'Native -t must reject invalid syntax');
    assert.match(invalidResult.stderr, /unknown directive "x10_invalid_directive"/);
    add('invalid-config-native-t-rejected', { exitCode: invalidResult.code });

    if (interrupted) throw new Error('Baseline interrupted before native server start');
    child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
    child.on('error', error => { childOutput += `${asText(error)}\n`; });
    for (const output of [child.stdout, child.stderr]) output.on('data', chunk => { childOutput = (childOutput + chunk.toString('utf8')).slice(-32_768); });
    await waitFor(async () => {
      if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Native process exited: ${childOutput}`);
      const response = await request(publicPort, '/ready');
      return response.status === 200 && response.body === 'ready';
    }, 'native listener');
    evidence.identity.masterPid = child.pid;
    const counts = { a: 0, b: 0 };
    for (let i = 0; i < 16; i++) {
      const response = await request(publicPort, '/balanced');
      assert.equal(response.status, 200);
      assert(['a', 'b'].includes(response.body));
      counts[response.body]++;
    }
    assert.deepEqual(counts, { a: 8, b: 8 });
    add('http1-round-robin-two-real-upstreams', { requests: 16, receipts: counts });

    const body = `native-write:${randomUUID()}:Привет`;
    const beforeWrite = receipts.length;
    const written = await request(publicPort, '/write', { method: 'POST', body });
    assert.equal(written.status, 200);
    assert.equal(receipts.length, beforeWrite + 1);
    assert.equal(receipts.at(-1).body, body);
    add('post-body-preserved-once', { upstreamReceipts: receipts.length - beforeWrite, bodySha256: sha256(body) });
    const beforeFailure = receipts.length;
    const failedWrite = await request(publicPort, '/write-fail', { method: 'POST', body });
    assert.equal(failedWrite.status, 502);
    await delay(100);
    assert.equal(receipts.length, beforeFailure + 1, 'Transport failure must not replay a received POST on another peer');
    assert.equal(receipts.at(-1).body, body);
    add('post-transport-failure-never-replayed', { httpStatus: failedWrite.status, upstreamReceipts: receipts.length - beforeFailure, receiptPeer: receipts.at(-1).id });

    if (tlsEnabled) {
      const trusted = await request(tlsPort, '/tls-native', { tls: { ca: certificates.ca, servername: 'localhost', rejectUnauthorized: true } });
      assert.equal(trusted.status, 200);
      assert(['a', 'b'].includes(trusted.body));
      await assert.rejects(request(tlsPort, '/', { tls: { servername: 'localhost', rejectUnauthorized: true } }),
        error => ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(error.code));
      await assert.rejects(request(tlsPort, '/', { tls: { ca: certificates.ca, servername: 'wrong.invalid', rejectUnauthorized: true } }),
        error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
      add('tls-trusted-ca-and-hostname-validation', { trustedRequest: 200, untrustedCaRejected: true, wrongHostnameRejected: true });
      if (h2Enabled) {
        const h2 = await h2Request(tlsPort, certificates.ca);
        assert.equal(h2.status, 200);
        assert(['a', 'b'].includes(h2.body));
        add('downstream-http2-over-verified-tls', { httpStatus: h2.status, alpn: h2.alpn });
      } else evidence.tests.push({ name: 'downstream-http2-over-verified-tls', status: 'skipped', reason: 'Binary does not report --with-http_v2_module' });
    } else {
      evidence.tests.push({ name: 'tls-trusted-ca-and-hostname-validation', status: 'skipped', reason: 'Binary does not report --with-http_ssl_module' });
      evidence.tests.push({ name: 'downstream-http2-over-verified-tls', status: 'skipped', reason: 'TLS unavailable in this binary' });
    }

    const token = randomUUID();
    held = openStream(publicPort, token);
    const first = await held.first;
    assert.equal(first, 'first:a\n');
    assert.equal(held.ended, false, 'First chunk must arrive before fixture completion is released');
    assert.equal(gates.get(token)?.id, 'a');
    add('proxy-stream-first-chunk-before-completion', { firstChunk: first.trim(), fixtureCompletionHeld: true });
    assert.equal((await request(publicPort, '/route')).body, 'a');

    const priorLog = await readFile(logPath, 'utf8');
    const next = config({ ...settings, routePort: b.port });
    await replaceConfig(next, 'valid-reload-b');
    await command(binary, [...args, '-t']);
    child.kill('SIGHUP');
    const reloadLog = await waitFor(async () => {
      const delta = (await readFile(logPath, 'utf8')).slice(priorLog.length);
      if (!/reconfiguring/.test(delta) || !/start worker process \d+/.test(delta)) return false;
      const response = await request(publicPort, '/route');
      return response.status === 200 && response.body === 'b' ? delta : false;
    }, 'valid reload new worker and new route');
    assert.equal(held.ended, false);
    const newWorkers = [...reloadLog.matchAll(/start worker process (\d+)/g)].map(match => Number(match[1]));
    assert(newWorkers.length > 0);
    add('valid-reload-new-route-and-live-old-stream', { routeBefore: 'a', routeAfter: 'b', newWorkerPids: newWorkers, oldStreamStillOpen: true });

    const beforeInvalidLog = (await readFile(logPath, 'utf8')).length;
    await replaceConfig(`${next}\nx10_invalid_directive;\n`, 'syntax-invalid-reload');
    child.kill('SIGHUP');
    await waitFor(async () => /unknown directive "x10_invalid_directive"/.test((await readFile(logPath, 'utf8')).slice(beforeInvalidLog)), 'actual master reload rejection log');
    for (let i = 0; i < 4; i++) {
      const stillB = await request(publicPort, '/route');
      assert.equal(stillB.status, 200);
      assert.equal(stillB.body, 'b');
    }
    assert.equal(held.ended, false);
    assert.equal(child.exitCode, null);
    add('syntax-invalid-reload-keeps-serving-route-and-stream', { retainedRoute: 'b', successfulRequests: 4, actualRejectionLogged: true, oldStreamStillOpen: true });
    gates.get(token).release();
    const completed = await held.complete;
    assert.equal(completed, 'first:a\nlast:a\n');
    add('accepted-old-stream-completes-after-both-reloads', { completeBody: completed.trim(), firstBeforeEnd: held.firstAt < held.endedAt });
    // Restore a valid private file before cleanup; no further application reload is requested.
    await replaceConfig(next, 'valid-file-restored-for-cleanup');
    evidence.success = true;
  } catch (error) {
    evidence.success = false;
    evidence.failure = { message: asText(error), stack: error?.stack };
    if (prefix) {
      try { evidence.nativeErrorLogTail = (await readFile(path.join(prefix, 'logs/error.log'), 'utf8')).slice(-16_384); }
      catch { /* early setup failure */ }
    }
    if (childOutput) evidence.childOutputTail = childOutput;
  } finally {
    held?.request?.destroy();
    evidence.cleanup = await stopChild(child);
    for (const item of fixtures) {
      for (const socket of item.sockets) socket.destroy();
      await new Promise(resolve => item.server.close(resolve));
    }
    if (prefix) await rm(prefix, { recursive: true, force: true });
    process.removeListener('SIGINT', onInterrupt);
    process.removeListener('SIGTERM', onInterrupt);
    evidence.finishedAt = new Date().toISOString();
    if (evidence.cleanup.started && !evidence.cleanup.exited) evidence.success = false;
  }
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  let binary = process.env.X10_NGINX_BINARY || path.join(repoRoot, 'objs/nginx');
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--binary' && process.argv[i + 1]) binary = process.argv[++i];
    else if (process.argv[i] === '--help') {
      process.stdout.write('Usage: node x10/test/http-baseline.mjs [--binary /absolute/path/to/nginx]\nEnvironment: X10_NGINX_BINARY\n');
      process.exit(0);
    } else throw new Error(`Unknown or incomplete argument: ${process.argv[i]}`);
  }
  const evidence = await runBaseline({ binary });
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    if (!evidence.success && !process.exitCode) process.exitCode = 1;
}
