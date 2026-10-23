#!/usr/bin/env node
// Real native NGINX feature fixtures. Node supplies loopback origins and assertions.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';

const execute = promisify(execFile);
const repo = fileURLToPath(new URL('../../', import.meta.url));
const digest = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const quote = value => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
const text = value => Buffer.isBuffer(value) ? value.toString('utf8') : String(value);

function bounded(promise, milliseconds, label) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
  })]).finally(() => clearTimeout(timer));
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function reservePort() {
  const server = net.createServer();
  const port = await listen(server);
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function waitFor(predicate, label, timeout = 4000) {
  const deadline = performance.now() + timeout;
  let last;
  while (performance.now() < deadline) {
    try { if (await predicate()) return; } catch (error) { last = error; }
    await delay(20);
  }
  throw new Error(`${label} unavailable${last ? `: ${last.message}` : ''}`);
}

function makeConfig({ prefix, publicPort, untrustedPort, originPort, cacheLock }) {
  const asset = quote(path.join(prefix, 'www/asset.txt'));
  const cache = quote(path.join(prefix, 'cache'));
  const basicFile = quote(path.join(prefix, 'synthetic.htpasswd'));
  // Even -t initializes temp/cache paths using this UID. The invoking root UID
  // can be mapped while the packaged nobody UID is unmapped in a user namespace.
  const user = process.geteuid?.() === 0 ? `user ${quote(os.userInfo().username)};\n` : '';
  return `${user}daemon off;
master_process off;
worker_processes 1;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log ${quote(path.join(prefix, 'logs/error.log'))} notice;
events { worker_connections 256; }
http {
  access_log off;
  default_type text/plain;
  sendfile on;
  gzip_vary on;
  client_body_temp_path ${quote(path.join(prefix, 'body'))};
  proxy_temp_path ${quote(path.join(prefix, 'proxy'))};
  proxy_cache_path ${cache} levels=1:2 keys_zone=features:1m max_size=8m inactive=1m;
  limit_req_zone $http_x_rate_key zone=rate:1m rate=1r/m;
  limit_conn_zone $http_x_limit_key zone=connections:1m;
  map $http_x_role $role { default public; admin privileged; }
  server {
    listen 127.0.0.1:${publicPort};
    server_name localhost;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    location = /ready { return 200 ready; }
    location = /fixture-status { stub_status; allow 127.0.0.1; deny all; }
    location = /asset.txt { alias ${asset}; gzip on; gzip_min_length 1; gzip_types text/plain; }
    location = /pick/exact { return 200 exact; }
    location ^~ /pick/protected { return 200 prefix; }
    location ~ \\.conf$ { return 200 regex; }
    location /pick/ { return 200 fallback; }
    location = /map { return 200 "$role|$arg_id"; }
    location /legacy/ { rewrite ^/legacy/([a-z]+)$ /mapped?value=$1 last; }
    location = /mapped { return 200 "$uri|$arg_value"; }
    location = /protected { auth_basic "X10 synthetic fixture"; auth_basic_user_file ${basicFile}; alias ${asset}; }
    location = /realip { return 200 "$remote_addr|$realip_remote_addr"; }
    location = /rate { limit_req zone=rate; limit_req_status 429; alias ${asset}; }
    location = /hold {
      limit_conn connections 1;
      limit_conn_status 429;
      proxy_pass http://127.0.0.1:${originPort};
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_read_timeout 5s;
    }
    location /cache/ {
      proxy_pass http://127.0.0.1:${originPort};
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_cache features;
      proxy_cache_key "$scheme|$request_method|$host|$request_uri";
      proxy_cache_valid 200 1m;
      proxy_cache_lock ${cacheLock};
      proxy_cache_lock_age 5s;
      proxy_cache_lock_timeout 3s;
      proxy_connect_timeout 1s;
      proxy_read_timeout 5s;
      add_header X-X10-Cache $upstream_cache_status always;
    }
  }
  server {
    listen 127.0.0.1:${untrustedPort};
    server_name localhost;
    set_real_ip_from 192.0.2.0/24;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    location = /realip { return 200 "$remote_addr|$realip_remote_addr"; }
  }
}
`;
}

async function run(binary, { cacheLock }) {
  const evidence = {
    schemaVersion: 1, suite: 'nginx-x10-native-features-baseline', startedAt: new Date().toISOString(),
    identity: {}, options: { bind: '127.0.0.1', masterProcess: false, workerProcesses: 1,
      processMode: 'single native process retaining the invoking UID', fixtureResponseLimitBytes: 1024 * 1024, cacheLock },
    tests: [], fixtureErrors: [], cleanupErrors: [], limitations: [
      'Synthetic loopback regression cases, not load tests or a complete module/platform matrix.',
      'Cache checks cover normal 200 responses, query-string key isolation and one concurrent fill; stale/revalidation, disk failures, Vary/private responses and purge are untested.',
      'Rate limits use isolated nonempty header keys; this does not test multiworker accounting, expiry, dry-run, bursts or distributed clients.',
      'Real-IP checks exercise one trusted loopback hop and a rejected loopback peer, not arbitrary forwarded chains or PROXY protocol.',
      'Single-process mode avoids privilege changes unavailable in some containers; reload/master lifecycle is covered by the separate HTTP baseline.',
      'Binary hash/version and checkout revision are separate identities; source provenance is not cryptographically attested by this harness.',
    ],
  };
  let prefix, nginx, exitResult, interrupted = false;
  let childOutput = '';
  let nativeLog = '';
  let overallTimer;
  const requests = new Set(), sockets = new Set(), gates = new Map(), receipts = new Map();
  let origin;
  const asset = Buffer.from('NGINX X10 native static fixture: range, ETag, HEAD and gzip.\n'.repeat(96));
  const request = (port, target, { method = 'GET', headers = {}, firstLine } = {}) => {
    let readyResolve, readyReject;
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    ready.catch(() => {});
    let sentResolve, sentReject;
    const sent = new Promise((resolve, reject) => { sentResolve = resolve; sentReject = reject; });
    sent.catch(() => {});
    let req;
    const complete = new Promise((resolve, reject) => {
      const fail = error => { sentReject(error); readyReject(error); reject(error); };
      req = http.request({ hostname: '127.0.0.1', port, path: target, method, headers, agent: false }, res => {
        const chunks = [];
        let bytes = 0, first = false;
        res.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 1024 * 1024) return req.destroy(new Error('Fixture response exceeded limit'));
          chunks.push(chunk);
          if (firstLine && !first) {
            const received = Buffer.concat(chunks).toString('utf8');
            if (received.includes('\n')) { first = true; readyResolve(received.slice(0, received.indexOf('\n') + 1)); }
          }
        });
        res.on('error', fail);
        res.on('end', () => {
          if (firstLine && !first) readyReject(new Error('No complete first fixture line'));
          if (!firstLine) readyResolve();
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
        });
      });
      requests.add(req);
      req.once('close', () => requests.delete(req));
      req.once('finish', sentResolve);
      req.on('error', fail);
      req.setTimeout(6000, () => req.destroy(new Error('Fixture request timed out')));
      req.end();
    });
    // Held requests may fail while a different assertion is running.
    complete.catch(() => {});
    complete.sent = sent;
    return firstLine ? { ready, complete, sent, request: req } : complete;
  };
  const check = async (name, fn) => {
    const started = performance.now();
    try {
      if (interrupted) throw new Error('Fixture run interrupted');
      const result = await bounded(Promise.resolve().then(fn), 8000, name);
      evidence.tests.push({ name, status: 'passed', durationMs: +(performance.now() - started).toFixed(2), ...result });
    } catch (error) {
      evidence.tests.push({ name, status: 'failed', durationMs: +(performance.now() - started).toFixed(2), error: error.message });
    }
  };
  const abort = () => {
    interrupted = true;
    for (const req of requests) req.destroy(new Error('Fixture run interrupted'));
    for (const socket of sockets) socket.destroy();
    nginx?.kill('SIGTERM');
  };
  process.once('SIGINT', abort);
  process.once('SIGTERM', abort);
  try {
    binary = path.resolve(binary);
    const version = await execute(binary, ['-V'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024 });
    const versionOutput = `${version.stdout}${version.stderr}`.trim();
    assert(versionOutput.includes('--with-http_realip_module'), 'Real-IP module required by this explicit profile');
    let checkout;
    try { checkout = (await execute('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8', timeout: 3000 })).stdout.trim(); }
    catch { checkout = 'unavailable'; }
    evidence.identity = { binary, binarySha256: digest(await readFile(binary)), versionOutput, checkoutRevision: checkout,
      node: process.version, platform: process.platform, arch: process.arch, invokingUid: process.getuid?.() ?? null };
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-native-features-'));
    await chmod(prefix, 0o700);
    for (const name of ['logs', 'www', 'cache', 'body', 'proxy']) await mkdir(path.join(prefix, name), { mode: 0o700 });
    await writeFile(path.join(prefix, 'www/asset.txt'), asset, { mode: 0o600 });
    const basicPassword = 'fixture-only-password';
    const syntheticHash = createHash('sha1').update(basicPassword).digest('base64');
    await writeFile(path.join(prefix, 'synthetic.htpasswd'), `fixture:{SHA}${syntheticHash}\n`, { mode: 0o600 });
    origin = http.createServer((req, res) => {
      try {
        assert.equal(req.method, 'GET');
        const url = new URL(req.url, 'http://fixture.invalid');
        const count = (receipts.get(req.url) || 0) + 1;
        receipts.set(req.url, count);
        if (url.pathname === '/hold') {
          const id = url.searchParams.get('id');
          assert(id && !gates.has(id), 'unique hold token expected');
          res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
          res.flushHeaders();
          res.write('start\n');
          gates.set(id, () => res.end('end\n'));
          res.once('close', () => gates.delete(id));
        } else if (url.pathname.startsWith('/cache/')) {
          const send = () => {
            res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=60' });
            res.end(`origin:${req.url}:receipt=${count}`);
          };
          if (url.pathname === '/cache/lock') gates.set(req.url, send);
          else send();
        } else throw new Error(`Unexpected fixture path: ${req.url}`);
      } catch (error) {
        evidence.fixtureErrors.push(error.message);
        res.writeHead(500); res.end('fixture error');
      }
    });
    origin.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    origin.on('error', error => evidence.fixtureErrors.push(error.message));
    const originPort = await listen(origin);
    const publicPort = await reservePort();
    let untrustedPort = await reservePort();
    while (untrustedPort === publicPort) untrustedPort = await reservePort();
    const config = makeConfig({ prefix, publicPort, untrustedPort, originPort, cacheLock });
    const configPath = path.join(prefix, 'nginx.conf');
    await writeFile(configPath, config, { mode: 0o600 });
    const args = ['-p', `${prefix}/`, '-c', configPath];
    evidence.options.configurationSha256 = digest(config);
    evidence.options.fixtureAsset = { bytes: asset.length, sha256: digest(asset) };
    await check('native-config-required-modules-and-syntax', async () => {
      await execute(binary, [...args, '-t'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024 });
      return { configured: ['static', 'range', 'not_modified', 'gzip', 'rewrite/map', 'auth_basic', 'realip', 'limit_req', 'limit_conn', 'proxy_cache', 'stub_status'] };
    });
    assert(evidence.tests.at(-1).status === 'passed', 'Native config validation must pass before starting fixtures');
    if (interrupted) throw new Error('Interrupted before native server start');
    nginx = spawn(binary, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    nginx.once('error', error => { exitResult = { error: error.message }; });
    nginx.once('exit', (code, signal) => { exitResult = { code, signal }; });
    nginx.stderr.on('data', chunk => { childOutput = (childOutput + chunk.toString('utf8')).slice(-16_384); });
    overallTimer = setTimeout(abort, 50_000);
    await waitFor(async () => {
      if (exitResult) throw new Error(`Native process exited: ${JSON.stringify(exitResult)} ${childOutput}`);
      const res = await request(publicPort, '/ready');
      return res.status === 200 && text(res.body) === 'ready';
    }, 'native listener');

    let etag;
    await check('static-get-exact-bytes', async () => {
      const res = await request(publicPort, '/asset.txt');
      assert.equal(res.status, 200); assert.deepEqual(res.body, asset);
      assert.equal(Number(res.headers['content-length']), asset.length);
      etag = res.headers.etag; assert(etag);
      return { bytes: res.body.length, sha256: digest(res.body), etagPresent: true };
    });
    await check('static-head-same-length-empty-body', async () => {
      const res = await request(publicPort, '/asset.txt', { method: 'HEAD' });
      assert.equal(res.status, 200); assert.equal(res.body.length, 0);
      assert.equal(Number(res.headers['content-length']), asset.length);
    });
    await check('static-single-byte-range', async () => {
      const res = await request(publicPort, '/asset.txt', { headers: { Range: 'bytes=17-42' } });
      assert.equal(res.status, 206); assert.deepEqual(res.body, asset.subarray(17, 43));
      assert.equal(res.headers['content-range'], `bytes 17-42/${asset.length}`);
    });
    await check('conditional-etag-not-modified', async () => {
      assert(etag, 'ETag from the successful GET is required');
      const res = await request(publicPort, '/asset.txt', { headers: { 'If-None-Match': etag } });
      assert.equal(res.status, 304); assert.equal(res.body.length, 0);
    });
    await check('static-unsatisfiable-range-rejected', async () => {
      const res = await request(publicPort, '/asset.txt', { headers: { Range: `bytes=${asset.length + 1}-` } });
      assert.equal(res.status, 416); assert.equal(res.headers['content-range'], `bytes */${asset.length}`);
    });
    await check('gzip-negotiation-and-decompressed-integrity', async () => {
      const res = await request(publicPort, '/asset.txt', { headers: { 'Accept-Encoding': 'gzip' } });
      assert.equal(res.status, 200); assert.equal(res.headers['content-encoding'], 'gzip');
      assert.match(res.headers.vary, /Accept-Encoding/i); assert.deepEqual(gunzipSync(res.body), asset);
      return { compressedBytes: res.body.length, uncompressedBytes: asset.length };
    });
    await check('route-exact-protected-prefix-regex-and-fallback', async () => {
      const examples = [['/pick/exact', 'exact'], ['/pick/protected.conf', 'prefix'], ['/pick/other.conf', 'regex'], ['/pick/other', 'fallback']];
      for (const [target, expected] of examples) {
        const res = await request(publicPort, target); assert.equal(res.status, 200); assert.equal(text(res.body), expected);
      }
      return { branches: examples.map(([target, result]) => ({ target, result })) };
    });
    await check('map-request-header-and-argument', async () => {
      for (const [role, expected] of [['admin', 'privileged'], ['unknown', 'public']]) {
        const res = await request(publicPort, '/map?id=42', { headers: { 'X-Role': role } });
        assert.equal(res.status, 200); assert.equal(text(res.body), `${expected}|42`);
      }
    });
    await check('rewrite-last-internal-route-and-argument', async () => {
      const res = await request(publicPort, '/legacy/widget');
      assert.equal(res.status, 200); assert.equal(text(res.body), '/mapped|widget');
    });
    await check('basic-auth-missing-and-wrong-credentials-denied', async () => {
      for (const headers of [{}, { Authorization: `Basic ${Buffer.from('fixture:wrong').toString('base64')}` }]) {
        const res = await request(publicPort, '/protected', { headers });
        assert.equal(res.status, 401); assert.match(res.headers['www-authenticate'], /^Basic realm="X10 synthetic fixture"$/);
        assert.notDeepEqual(res.body, asset);
      }
    });
    await check('basic-auth-synthetic-credentials-allowed', async () => {
      const res = await request(publicPort, '/protected', { headers: { Authorization: `Basic ${Buffer.from(`fixture:${basicPassword}`).toString('base64')}` } });
      assert.equal(res.status, 200); assert.deepEqual(res.body, asset);
    });
    await check('realip-trusted-loopback-hop', async () => {
      const res = await request(publicPort, '/realip', { headers: { 'X-Forwarded-For': '203.0.113.9' } });
      assert.equal(res.status, 200); assert.equal(text(res.body), '203.0.113.9|127.0.0.1');
    });
    await check('realip-untrusted-peer-cannot-spoof-address', async () => {
      const res = await request(untrustedPort, '/realip', { headers: { 'X-Forwarded-For': '203.0.113.9' } });
      assert.equal(res.status, 200); assert.equal(text(res.body), '127.0.0.1|127.0.0.1');
    });
    await check('limit-req-rejects-second-request-and-isolates-keys', async () => {
      const key = randomUUID();
      const first = await request(publicPort, '/rate', { headers: { 'X-Rate-Key': key } });
      const second = await request(publicPort, '/rate', { headers: { 'X-Rate-Key': key } });
      const isolated = await request(publicPort, '/rate', { headers: { 'X-Rate-Key': randomUUID() } });
      assert.equal(first.status, 200); assert.equal(second.status, 429); assert.equal(isolated.status, 200);
      assert.deepEqual(first.body, asset); assert.deepEqual(isolated.body, asset);
      return { statuses: [first.status, second.status, isolated.status], rate: '1r/m' };
    });
    await check('limit-conn-live-stream-rejection-and-release', async () => {
      const key = randomUUID(), firstId = randomUUID();
      const held = request(publicPort, `/hold?id=${firstId}`, { headers: { 'X-Limit-Key': key }, firstLine: true });
      assert.equal(await held.ready, 'start\n');
      const deniedPath = `/hold?id=${randomUUID()}`;
      const denied = await request(publicPort, deniedPath, { headers: { 'X-Limit-Key': key } });
      assert.equal(denied.status, 429);
      assert.equal(receipts.get(deniedPath) || 0, 0, 'Rejected request must not reach the origin');
      gates.get(firstId)();
      const completed = await held.complete; assert.equal(completed.status, 200); assert.equal(text(completed.body), 'start\nend\n');
      const nextId = randomUUID();
      const next = request(publicPort, `/hold?id=${nextId}`, { headers: { 'X-Limit-Key': key }, firstLine: true });
      assert.equal(await next.ready, 'start\n'); gates.get(nextId)();
      assert.equal((await next.complete).status, 200);
      assert.equal(receipts.get(`/hold?id=${firstId}`), 1); assert.equal(receipts.get(`/hold?id=${nextId}`), 1);
      return { accepted: 2, rejectedWhileFirstActive: 1, originRequests: 2, rejectedOriginRequests: 0 };
    });
    const token = randomUUID(), keyA = `/cache/item?key=${token}&variant=a`, keyB = `/cache/item?key=${token}&variant=b`;
    let cachedBody;
    await check('proxy-cache-miss-then-hit-one-origin-receipt', async () => {
      const miss = await request(publicPort, keyA); const hit = await request(publicPort, keyA);
      assert.equal(miss.status, 200); assert.equal(hit.status, 200);
      assert.equal(miss.headers['x-x10-cache'], 'MISS'); assert.equal(hit.headers['x-x10-cache'], 'HIT');
      assert.deepEqual(hit.body, miss.body); assert.equal(receipts.get(keyA), 1); cachedBody = miss.body;
      return { cacheStatuses: ['MISS', 'HIT'], originReceipts: receipts.get(keyA) };
    });
    await check('proxy-cache-query-key-isolation', async () => {
      const missB = await request(publicPort, keyB), hitB = await request(publicPort, keyB), hitA = await request(publicPort, keyA);
      assert.equal(missB.status, 200); assert.equal(hitB.status, 200); assert.equal(hitA.status, 200);
      assert.equal(missB.headers['x-x10-cache'], 'MISS'); assert.equal(hitB.headers['x-x10-cache'], 'HIT');
      assert.equal(hitA.headers['x-x10-cache'], 'HIT'); assert.deepEqual(hitB.body, missB.body);
      assert.deepEqual(hitA.body, cachedBody); assert.notDeepEqual(missB.body, cachedBody);
      assert.equal(receipts.get(keyA), 1); assert.equal(receipts.get(keyB), 1);
      return { independentKeys: 2, originReceiptsPerKey: [receipts.get(keyA), receipts.get(keyB)] };
    });
    await check('proxy-cache-lock-concurrent-fill-single-origin', async () => {
      const key = `/cache/lock?key=${randomUUID()}`;
      let completed = 0;
      const submit = () => {
        const result = request(publicPort, key);
        result.then(() => { completed++; }, () => {});
        return result;
      };
      const results = [submit()];
      await waitFor(() => gates.has(key), 'first held cache origin');
      for (let i = 0; i < 5; i++) results.push(submit());
      await Promise.all(results.map(result => result.sent));
      let arrival;
      await waitFor(async () => {
        const status = await request(publicPort, '/fixture-status');
        assert.equal(status.status, 200);
        const counts = text(status.body).match(/Reading: (\d+) Writing: (\d+) Waiting: (\d+)/);
        assert(counts, 'Native stub_status response must contain connection states');
        arrival = { reading: Number(counts[1]), writing: Number(counts[2]), waiting: Number(counts[3]) };
        // Six native requests must be inside HTTP processing, plus the current
        // status request. Client write completion alone is insufficient proof.
        return arrival.writing >= results.length + 1 && arrival.reading === 0 && arrival.waiting === 0;
      }, 'six native cache requests inside HTTP processing');
      assert.equal(completed, 0); assert.equal(receipts.get(key), 1);
      gates.get(key)(); gates.delete(key);
      const responses = await Promise.all(results);
      for (const res of responses) { assert.equal(res.status, 200); assert.deepEqual(res.body, responses[0].body); }
      assert.equal(responses.filter(res => res.headers['x-x10-cache'] === 'MISS').length, 1);
      assert.equal(responses.filter(res => res.headers['x-x10-cache'] === 'HIT').length, 5);
      assert.equal(receipts.get(key), 1);
      return { concurrentClients: responses.length, requestsSubmittedBeforeGateRelease: true, nativeArrivalBarrier: arrival,
        originReceipts: receipts.get(key), cacheStatuses: responses.map(res => res.headers['x-x10-cache']) };
    });
    assert.deepEqual(evidence.fixtureErrors, []);
    assert(!exitResult, 'Native process must remain alive through all fixtures');
  } catch (error) {
    evidence.failure = { message: error.message };
  } finally {
    clearTimeout(overallTimer);
    for (const req of requests) req.destroy();
    for (const socket of sockets) socket.destroy();
    let signal = null;
    if (nginx?.pid && !exitResult) {
      signal = 'SIGQUIT'; nginx.kill(signal);
      const until = performance.now() + 3000;
      while (!exitResult && performance.now() < until) await delay(20);
      if (!exitResult) {
        signal = 'SIGTERM'; nginx.kill(signal);
        const termUntil = performance.now() + 1000;
        while (!exitResult && performance.now() < termUntil) await delay(20);
      }
      if (!exitResult) {
        signal = 'SIGKILL'; nginx.kill(signal);
        try { await bounded(once(nginx, 'exit'), 1000, 'native forced exit'); }
        catch (error) { evidence.cleanupErrors.push(error.message); }
      }
    }
    evidence.cleanup = { signal, process: exitResult || null, exited: Boolean(exitResult) };
    if (origin?.listening) {
      try { await bounded(new Promise(resolve => origin.close(resolve)), 1000, 'origin close'); }
      catch (error) { evidence.cleanupErrors.push(error.message); }
    }
    if (prefix) {
      try { nativeLog = await readFile(path.join(prefix, 'logs/error.log'), 'utf8'); evidence.nativeErrorLogTail = nativeLog.slice(-8192); } catch {}
      try { await rm(prefix, { recursive: true, force: true }); } catch (error) { evidence.cleanupErrors.push(error.message); }
    }
    evidence.unexpectedNativeErrors = nativeLog.split('\n').filter(line => /\[(?:alert|emerg|crit)\]/i.test(line));
    try { evidence.identity.binaryUnchangedDuringTest = digest(await readFile(binary)) === evidence.identity.binarySha256; }
    catch (error) { evidence.identity.binaryUnchangedDuringTest = false; evidence.cleanupErrors.push(`Final binary identity: ${error.message}`); }
    if (childOutput) evidence.childOutputTail = childOutput;
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
    evidence.finishedAt = new Date().toISOString();
    evidence.summary = { passed: evidence.tests.filter(test => test.status === 'passed').length,
      failed: evidence.tests.filter(test => test.status === 'failed').length, skipped: 0 };
    evidence.success = !interrupted && !evidence.failure && !evidence.summary.failed && evidence.tests.length === 19 &&
      evidence.fixtureErrors.length === 0 && evidence.cleanupErrors.length === 0 && evidence.unexpectedNativeErrors.length === 0 &&
      evidence.identity.binaryUnchangedDuringTest === true && evidence.cleanup.signal === 'SIGQUIT' && exitResult?.code === 0;
  }
  return evidence;
}

let binary = process.env.X10_NGINX_BINARY || path.join(repo, 'x10/.build/objs/nginx');
let cacheLock = 'on';
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--binary' && process.argv[i + 1]) binary = process.argv[++i];
  else if (process.argv[i] === '--cache-lock' && process.argv[i + 1]) cacheLock = process.argv[++i];
  else if (process.argv[i] === '--help') {
    process.stdout.write('Usage: node x10/test/features-baseline.mjs [--binary /path/to/nginx] [--cache-lock on|off]\nEnvironment: X10_NGINX_BINARY\nDefault cache lock is on; off is an oracle negative control expected to fail the concurrent-fill case.\n');
    process.exit(0);
  } else throw new Error(`Unknown or incomplete argument: ${process.argv[i]}`);
}
if (!['on', 'off'].includes(cacheLock)) throw new Error('--cache-lock must be on or off');
const result = await run(binary, { cacheLock });
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.success) process.exitCode = 1;
