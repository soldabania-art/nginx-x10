#!/usr/bin/env node
// Native protocol adapters; Node supplies strict loopback wire fixtures only.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const quote = value => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
const adapters = ['fastcgi', 'scgi', 'uwsgi'];
const sourcePaths = adapters.map(name => `src/http/modules/ngx_http_${name}_module.c`);
const longValue = 'long-metadata-'.repeat(14);
const wireLimit = 256 * 1024;
const binaryBody = Buffer.alloc(70 * 1024 + 7);
for (let i = 0; i < binaryBody.length; i++) binaryBody[i] = i % 256;
const chunkedBody = binaryBody.subarray(0, 4099);
const getBody = Buffer.from([0x58, 0x31, 0x30, 0, 0xff, 0x0d, 0x0a, 0x80]);

async function bounded(promise, ms, label) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms); })]); }
  finally { clearTimeout(timer); }
}
async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}
async function unusedPort() {
  const s = net.createServer(); const port = await listen(s);
  await new Promise(resolve => s.close(resolve)); return port;
}
async function waitFor(predicate, label) {
  const until = performance.now() + 4000;
  while (performance.now() < until) { try { if (await predicate()) return; } catch {} await delay(20); }
  throw new Error(`${label} unavailable`);
}
async function sourceIdentity() {
  const files = [...sourcePaths, 'x10/test/adapters-baseline.mjs'];
  return Object.fromEntries(await Promise.all(files.map(async name => [name, sha(await readFile(path.join(root, name)))])));
}
function pairs(parts) {
  const result = {};
  for (const [name, value] of parts) {
    assert(name && !Object.hasOwn(result, name), `duplicate or empty fixture parameter ${name}`);
    result[name] = value;
  }
  return result;
}
function fastcgiParams(bytes) {
  let at = 0;
  const fields = [], widths = [];
  const length = () => {
    assert(at < bytes.length, 'FastCGI parameter length available');
    if (!(bytes[at] & 0x80)) { widths.push(1); return bytes[at++]; }
    assert(at + 4 <= bytes.length, 'complete four-byte FastCGI length');
    const value = bytes.readUInt32BE(at) & 0x7fffffff; at += 4; widths.push(4); return value;
  };
  while (at < bytes.length) {
    const keyLength = length(), valueLength = length();
    assert(at + keyLength + valueLength <= bytes.length, 'FastCGI parameter inside declared PARAMS data');
    const key = bytes.subarray(at, at + keyLength).toString(); at += keyLength;
    const value = bytes.subarray(at, at + valueLength).toString(); at += valueLength;
    fields.push([key, value]);
  }
  return { params: pairs(fields), parameterLengthWidths: [...new Set(widths)] };
}
function fastcgiParser() {
  let pending = Buffer.alloc(0), began = false, paramsEnded = false, stdinEnded = false;
  const params = [], body = [], records = [];
  return bytes => {
    assert(!stdinEnded, 'one FastCGI request per nonpersistent fixture connection');
    pending = Buffer.concat([pending, bytes]);
    while (pending.length >= 8) {
      const version = pending[0], type = pending[1], requestId = pending.readUInt16BE(2);
      const length = pending.readUInt16BE(4), padding = pending[6];
      assert.equal(version, 1); assert.equal(requestId, 1); assert.equal(pending[7], 0);
      if (pending.length < 8 + length + padding) return;
      const data = Buffer.from(pending.subarray(8, 8 + length));
      assert(pending.subarray(8 + length, 8 + length + padding).every(byte => byte === 0), 'native request padding is zeroed');
      records.push({ type, length, padding });
      pending = pending.subarray(8 + length + padding);
      if (type === 1) {
        assert(!began && records.length === 1); assert.equal(data.length, 8);
        assert.equal(data.readUInt16BE(0), 1, 'RESPONDER role'); assert.equal(data[2], 0, 'keep_conn disabled');
        assert(data.subarray(3).every(byte => byte === 0)); began = true;
      } else if (type === 4) {
        assert(began && !paramsEnded && !body.length);
        if (length === 0) paramsEnded = true; else params.push(data);
      } else if (type === 5) {
        assert(began && paramsEnded);
        if (length === 0) stdinEnded = true; else body.push(data);
      } else throw new Error(`unexpected FastCGI request record type ${type}`);
      if (stdinEnded) {
        assert.equal(pending.length, 0, 'no trailing bytes after terminal STDIN');
        return { ...fastcgiParams(Buffer.concat(params)), body: Buffer.concat(body), framing: { records, paramsEnded, stdinEnded } };
      }
    }
  };
}
function simpleParser(adapter) {
  let pending = Buffer.alloc(0), parsed, offset;
  return bytes => {
    pending = Buffer.concat([pending, bytes]);
    if (!parsed) {
      const fields = [];
      if (adapter === 'scgi') {
        const colon = pending.indexOf(0x3a);
        if (colon < 0) { assert(pending.length <= 8, 'bounded netstring prefix'); return; }
        const digits = pending.subarray(0, colon).toString();
        assert(/^[1-9][0-9]{0,5}$/.test(digits), 'canonical SCGI netstring size');
        const length = Number(digits); assert(length < wireLimit);
        if (pending.length < colon + 1 + length + 1) return;
        assert.equal(pending[colon + 1 + length], 0x2c, 'SCGI netstring comma');
        const payload = pending.subarray(colon + 1, colon + 1 + length);
        assert.equal(payload.at(-1), 0, 'SCGI final value NUL');
        const tokens = payload.toString().split('\0'); tokens.pop(); assert.equal(tokens.length % 2, 0);
        for (let i = 0; i < tokens.length; i += 2) fields.push([tokens[i], tokens[i + 1]]);
        assert.equal(fields[0][0], 'CONTENT_LENGTH', 'SCGI first parameter');
        offset = colon + 1 + length + 1;
        parsed = { params: pairs(fields), framing: { netstringBytes: length, firstParameter: fields[0][0] } };
        assert.equal(parsed.params.SCGI, '1');
      } else {
        if (pending.length < 4) return;
        assert.equal(pending[0], 0); assert.equal(pending[3], 0);
        const length = pending.readUInt16LE(1);
        if (pending.length < 4 + length) return;
        let at = 4;
        while (at < 4 + length) {
          assert(at + 2 <= 4 + length); const keyLength = pending.readUInt16LE(at); at += 2;
          assert(at + keyLength + 2 <= 4 + length); const key = pending.subarray(at, at + keyLength).toString(); at += keyLength;
          const valueLength = pending.readUInt16LE(at); at += 2;
          assert(at + valueLength <= 4 + length); const value = pending.subarray(at, at + valueLength).toString(); at += valueLength;
          fields.push([key, value]);
        }
        assert.equal(at, 4 + length); offset = at;
        parsed = { params: pairs(fields), framing: { modifier1: pending[0], modifier2: pending[3], packetBytes: length } };
      }
      assert(/^[0-9]*$/.test(parsed.params.CONTENT_LENGTH), 'decimal CONTENT_LENGTH');
    }
    const length = Number(parsed.params.CONTENT_LENGTH || 0); assert(length < wireLimit);
    if (pending.length < offset + length) return;
    assert.equal(pending.length, offset + length, 'no bytes beyond declared request body');
    return { ...parsed, body: Buffer.from(pending.subarray(offset)) };
  };
}
function record(type, bytes, padding = 0) {
  assert(bytes.length <= 65535);
  const h = Buffer.from([1, type, 0, 1, 0, 0, padding, 0]); h.writeUInt16BE(bytes.length, 4);
  return Buffer.concat([h, bytes, Buffer.alloc(padding, 0x5a)]);
}
function response(adapter, header, body, complete = true) {
  const data = Buffer.concat([Buffer.from(header), body]);
  if (adapter !== 'fastcgi') return data;
  const records = [record(6, data.subarray(0, 13), 3)];
  for (let at = 13; at < data.length; at += 32768) records.push(record(6, data.subarray(at, at + 32768), 5));
  if (complete) records.push(record(6, Buffer.alloc(0)), record(3, Buffer.alloc(8)));
  return Buffer.concat(records);
}
function config(prefix, port, origins) {
  const user = process.geteuid?.() === 0 ? `user ${quote(os.userInfo().username)};\n` : '';
  const locations = adapters.map(adapter => `location /${adapter}/ {
      ${adapter}_pass 127.0.0.1:${origins[adapter]};
      ${adapter}_param REQUEST_METHOD $request_method;
      ${adapter}_param REQUEST_URI $request_uri;
      ${adapter}_param QUERY_STRING $query_string;
      ${adapter}_param CONTENT_TYPE $content_type;
      ${adapter === 'scgi' ? 'scgi_param SCGI 1;' : `${adapter}_param CONTENT_LENGTH $content_length;`}
      ${adapter}_param FIXTURE_TOKEN wire-only;
      ${adapter}_request_buffering on;
      ${adapter}_buffering off;
      ${adapter}_next_upstream off;
      ${adapter}_connect_timeout 300ms;
      ${adapter}_read_timeout 300ms;
      ${adapter}_send_timeout 1s;
      ${adapter}_temp_path ${quote(path.join(prefix, adapter))};
    }`).join('\n');
  return `${user}daemon off;
master_process off;
worker_processes 1;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log ${quote(path.join(prefix, 'logs/error.log'))} notice;
events { worker_connections 128; }
http {
  access_log off;
  client_body_buffer_size 1k;
  client_max_body_size 256k;
  client_body_temp_path ${quote(path.join(prefix, 'body'))};
  server {
    listen 127.0.0.1:${port};
    server_name fixture.test;
    location = /ready { return 200 ready; }
    ${locations}
  }
}
`;
}

async function run(selectedBinary) {
  const result = { schemaVersion: 1, suite: 'native-protocol-adapters', startedAt: new Date().toISOString(),
    identity: {}, tests: [], skips: [], fixtureErrors: [], cleanup: { errors: [] },
    options: { bind: '127.0.0.1', masterProcess: false, requestBuffering: true, responseBuffering: false,
      readTimeoutMs: 300, maximumWireBytes: wireLimit },
    limitations: [
      'Synthetic loopback FastCGI RESPONDER, SCGI and uWSGI fixtures; no real application runtime, keepalive pool, TLS, cache, retry or multiplexing coverage.',
      'Request buffering is explicitly on and response buffering off. Chunked client input is decoded by native NGINX before adapter framing; this does not test unbuffered request backpressure.',
      'Source hashes identify local adapter translation units and this harness; binary identity is separate and does not attest that those files built the executable.',
      'Baseline and candidate are expected to agree. These are compatibility checks, not newly fixed adapter defects or performance improvements.',
    ] };
  let binary, initialSources, prefix, nginx, exitResult, nativeLog = '', interrupted = false;
  const servers = [], sockets = new Set(), requests = new Set(), writeTimers = new Set(), receipts = new Map();
  let childOutput = '';
  const stop = () => {
    interrupted = true;
    for (const req of requests) req.destroy(new Error('Fixture interrupted'));
    for (const socket of sockets) socket.destroy();
    nginx?.kill('SIGTERM');
  };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const timer = setTimeout(stop, 60_000);
  const check = async (name, fn) => {
    const at = performance.now();
    try {
      assert(!interrupted, 'run not interrupted');
      const details = await bounded(Promise.resolve().then(fn), 5000, name);
      result.tests.push({ name, status: 'passed', durationMs: +(performance.now() - at).toFixed(2), ...details });
    } catch (error) { result.tests.push({ name, status: 'failed', durationMs: +(performance.now() - at).toFixed(2), error: error.message }); }
  };
  const request = (port, target, { body, chunked = false } = {}) => new Promise((resolve, reject) => {
    const chunks = []; let status, headers, settled = false;
    const finish = (complete, error) => {
      if (settled) return; settled = true;
      resolve({ status, headers, body: Buffer.concat(chunks), complete, ...(error ? { error: error.message } : {}) });
    };
    const req = http.request({ host: '127.0.0.1', port, path: target, method: body ? 'POST' : 'GET', agent: false,
      headers: { Host: 'fixture.test', 'X-Long': longValue, 'X-Join': ['first', 'second'],
        ...(body ? { 'Content-Type': 'application/octet-stream', ...(chunked ? {} : { 'Content-Length': body.length }) } : {}) } }, res => {
      status = res.statusCode; headers = res.headers;
      res.on('data', bytes => { chunks.push(bytes); if (Buffer.concat(chunks).length > wireLimit) req.destroy(new Error('HTTP fixture response exceeds limit')); });
      res.on('end', () => finish(res.complete));
      res.on('aborted', () => finish(false, new Error('Response aborted')));
      res.on('error', error => finish(false, error));
    });
    requests.add(req); req.once('close', () => requests.delete(req));
    req.setTimeout(2500, () => req.destroy(new Error('HTTP fixture request timeout')));
    req.on('error', error => { if (status) finish(false, error); else reject(error); });
    if (chunked) { for (let at = 0; at < body.length; at += 137) req.write(body.subarray(at, at + 137)); req.end(); }
    else req.end(body);
  });
  const validateReceipt = (adapter, mode, body = Buffer.alloc(0)) => {
    const key = `/${adapter}/${mode}?id=${adapter}&value=a%2Fb`;
    const list = receipts.get(key); assert.equal(list?.length, 1, 'one parsed upstream request, with no retry');
    const receipt = list[0];
    assert.equal(receipt.params.REQUEST_METHOD, body.length ? 'POST' : 'GET');
    assert.equal(receipt.params.REQUEST_URI, key); assert.equal(receipt.params.QUERY_STRING, `id=${adapter}&value=a%2Fb`);
    assert.equal(receipt.params.FIXTURE_TOKEN, 'wire-only'); assert.equal(receipt.params.HTTP_HOST, 'fixture.test');
    assert.equal(receipt.params.HTTP_X_LONG, longValue); assert.equal(receipt.params.HTTP_X_JOIN, 'first, second');
    assert.equal(Number(receipt.params.CONTENT_LENGTH || 0), body.length);
    if (body.length) assert.equal(receipt.params.CONTENT_TYPE, 'application/octet-stream');
    assert.deepEqual(receipt.body, body);
    if (adapter === 'fastcgi') {
      assert(receipt.framing.paramsEnded && receipt.framing.stdinEnded);
      assert(receipt.parameterLengthWidths.includes(4), 'long metadata uses four-byte FastCGI parameter encoding');
      if (body.length > 65535) assert(receipt.framing.records.filter(r => r.type === 5 && r.length).length >= 3, 'large body crosses native STDIN records');
    }
    return { requestBytes: body.length, requestBodySha256: sha(receipt.body), upstreamReceipts: list.length, framing: receipt.framing };
  };
  try {
    binary = await realpath(path.resolve(selectedBinary)); initialSources = await sourceIdentity();
    const version = await execute(binary, ['-V'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024 });
    result.identity = { binary, binarySha256: sha(await readFile(binary)), versionOutput: `${version.stdout}${version.stderr}`.trim(),
      checkoutRevision: (await execute('git', ['rev-parse', 'HEAD'], { cwd: root, timeout: 3000 })).stdout.trim(),
      sourceFiles: initialSources, node: process.version, platform: process.platform, arch: process.arch };
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-native-adapters-')); await chmod(prefix, 0o700);
    for (const dir of ['logs', 'body', ...adapters]) await mkdir(path.join(prefix, dir), { mode: 0o700 });
    const origins = {};
    for (const adapter of adapters) {
      const server = net.createServer(socket => {
        sockets.add(socket); socket.once('close', () => sockets.delete(socket));
        socket.on('error', error => { if (!['ECONNRESET', 'EPIPE'].includes(error.code) && !interrupted) result.fixtureErrors.push(`${adapter} socket: ${error.message}`); });
        socket.setTimeout(2500, () => socket.destroy());
        const parse = adapter === 'fastcgi' ? fastcgiParser() : simpleParser(adapter);
        let handled = false, bytes = 0;
        socket.on('data', chunk => {
          if (handled) { result.fixtureErrors.push(`${adapter}: unexpected bytes after complete request`); socket.destroy(); return; }
          try {
            bytes += chunk.length; assert(bytes <= wireLimit, 'bounded adapter request');
            const receipt = parse(chunk); if (!receipt) return; handled = true;
            const key = receipt.params.REQUEST_URI; const list = receipts.get(key) || []; list.push(receipt); receipts.set(key, list);
            const mode = key?.split('?')[0].split('/').at(-1);
            if (mode === 'timeout') return;
            if (mode === 'invalid') { socket.end(response(adapter, 'Bad\0Header: rejected\r\n\r\n', Buffer.from('invalid'))); return; }
            if (mode === 'truncated-header') {
              socket.end(adapter === 'fastcgi' ? Buffer.concat([Buffer.from([1, 6, 0, 1, 3, 0, 0, 0]), Buffer.from('Sta')]) : Buffer.from('Status: 200 OK\r\nX-Incomplete: value'));
              return;
            }
            if (mode === 'truncated-body') {
              socket.end(response(adapter, 'Status: 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 20\r\nX-Adapter: '+adapter+'\r\n\r\n', Buffer.from('short'), false)); return;
            }
            assert(['get', 'binary', 'chunked'].includes(mode), `known fixture mode ${mode}`);
            const output = mode === 'get' ? getBody : receipt.body;
            const line = mode === 'get' && adapter !== 'fastcgi' ? 'HTTP/1.1 201 Created\r\n' : 'Status: 201 Created\r\n';
            const wire = response(adapter, `${line}Content-Type: application/octet-stream\r\nContent-Length: ${output.length}\r\nX-Adapter: ${adapter}\r\n\r\n`, output);
            let at = 0;
            const send = () => {
              if (socket.destroyed) return;
              const end = at < 7 ? Math.min(at + 2, wire.length) : at < 40 ? Math.min(at + 11, wire.length) : wire.length;
              if (end === wire.length) { socket.end(wire.subarray(at)); return; }
              socket.write(wire.subarray(at, end)); at = end;
              const t = setTimeout(() => { writeTimers.delete(t); send(); }, 3); writeTimers.add(t);
            };
            send();
          } catch (error) { result.fixtureErrors.push(`${adapter} parser/fixture: ${error.message}`); socket.destroy(); }
        });
      });
      servers.push(server); origins[adapter] = await listen(server);
    }
    const port = await unusedPort(); await writeFile(path.join(prefix, 'nginx.conf'), config(prefix, port, origins), { mode: 0o600 });
    await execute(binary, ['-t', '-p', `${prefix}/`, '-c', 'nginx.conf'], { encoding: 'utf8', timeout: 5000 });
    nginx = spawn(binary, ['-p', `${prefix}/`, '-c', 'nginx.conf'], { stdio: ['ignore', 'pipe', 'pipe'] });
    nginx.on('error', error => { result.fixtureErrors.push(`native spawn: ${error.message}`); });
    nginx.stdout.on('data', bytes => { childOutput = (childOutput + bytes).slice(-8192); });
    nginx.stderr.on('data', bytes => { childOutput = (childOutput + bytes).slice(-8192); });
    nginx.on('exit', (code, signal) => { exitResult = { code, signal }; });
    await waitFor(async () => (await request(port, '/ready')).status === 200, 'native readiness');
    for (const adapter of adapters) {
      const target = mode => `/${adapter}/${mode}?id=${adapter}&value=a%2Fb`;
      for (const [mode, body, chunked] of [['get', undefined, false], ['binary', binaryBody, false], ['chunked', chunkedBody, true]]) {
        await check(`${adapter}-${mode}-wire-metadata-and-exact-response`, async () => {
          const res = await request(port, target(mode), { body, chunked });
          const details = validateReceipt(adapter, mode, body); assert.equal(res.status, 201); assert.equal(res.complete, true);
          assert.equal(res.headers['x-adapter'], adapter); assert.equal(res.headers['content-type'], 'application/octet-stream');
          const expected = mode === 'get' ? getBody : body;
          assert.equal(Number(res.headers['content-length']), expected.length); assert.deepEqual(res.body, expected);
          return { ...details, responseStatus: res.status, responseBytes: res.body.length, responseBodySha256: sha(res.body), responseComplete: true };
        });
      }
      for (const mode of ['invalid', 'truncated-header', 'truncated-body', 'timeout']) {
        await check(`${adapter}-${mode}-upstream-failure`, async () => {
          const started = performance.now(); const res = await request(port, target(mode));
          const details = validateReceipt(adapter, mode); const elapsedMs = performance.now() - started;
          assert(elapsedMs < 2000, 'native failure has a bounded response');
          if (mode === 'truncated-body') {
            assert.equal(res.status, 200); assert.equal(res.complete, false);
            assert.equal(Number(res.headers['content-length']), 20); assert.deepEqual(res.body, Buffer.from('short'));
          } else {
            assert.equal(res.status, mode === 'timeout' ? 504 : 502); assert.equal(res.complete, true);
            assert(!res.headers['x-adapter']); assert.match(res.body.toString(), new RegExp(`${res.status} (Bad Gateway|Gateway Time-out)`));
          }
          return { ...details, responseStatus: res.status, responseComplete: res.complete, responseBytes: res.body.length, failureElapsedMs: +elapsedMs.toFixed(2) };
        });
      }
    }
    assert.deepEqual(result.fixtureErrors, []); assert(!exitResult, 'native stays alive through malformed origins');
  } catch (error) { result.failure = { message: error.message }; }
  finally {
    clearTimeout(timer); for (const t of writeTimers) clearTimeout(t); writeTimers.clear();
    for (const req of requests) req.destroy(); for (const socket of sockets) socket.destroy();
    let signal = null;
    if (nginx?.pid && !exitResult) {
      for (const [nextSignal, timeout] of [['SIGQUIT', 2000], ['SIGTERM', 1000], ['SIGKILL', 1000]]) {
        if (exitResult) break; signal = nextSignal; nginx.kill(signal);
        const until = performance.now() + timeout; while (!exitResult && performance.now() < until) await delay(20);
      }
    }
    for (const server of servers) {
      if (server.listening) try { await bounded(new Promise(resolve => server.close(resolve)), 1000, 'adapter close'); }
      catch (error) { result.cleanup.errors.push(error.message); }
    }
    await delay(0);
    if (prefix) {
      try {
        nativeLog = await readFile(path.join(prefix, 'logs/error.log'), 'utf8');
        result.nativeErrorLogTail = nativeLog.slice(-12000); result.nativeLogRead = true;
      } catch (error) {
        result.nativeLogRead = false;
        if (nginx?.pid) result.cleanup.errors.push(`Native error log unavailable: ${error.message}`);
      }
      try { await rm(prefix, { recursive: true, force: true }); } catch (error) { result.cleanup.errors.push(error.message); }
    }
    result.cleanup = { ...result.cleanup, nativeStopped: Boolean(exitResult), nativeExit: exitResult || null, signal,
      fixturesStopped: servers.every(server => !server.listening), openSockets: sockets.size, temporaryRootRemoved: true };
    if (prefix) try { await stat(prefix); result.cleanup.temporaryRootRemoved = false; }
    catch (error) { if (error.code !== 'ENOENT') { result.cleanup.temporaryRootRemoved = false; result.cleanup.errors.push(error.message); } }
    try { result.identity.binaryUnchangedDuringTest = sha(await readFile(binary)) === result.identity.binarySha256; }
    catch { result.identity.binaryUnchangedDuringTest = false; }
    try { result.sourceUnchangedDuringTest = JSON.stringify(initialSources) === JSON.stringify(await sourceIdentity()); }
    catch { result.sourceUnchangedDuringTest = false; }
    result.unexpectedNativeErrors = nativeLog.split('\n').filter(line => /\[(?:alert|emerg|crit)\]/i.test(line));
    result.expectedFailureDiagnostics = nativeLog.split('\n').filter(line => /upstream sent invalid header|upstream prematurely closed|upstream timed out/.test(line));
    if (childOutput) result.childOutputTail = childOutput;
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    result.summary = { passed: result.tests.filter(t => t.status === 'passed').length, failed: result.tests.filter(t => t.status === 'failed').length, skipped: 0 };
    result.finishedAt = new Date().toISOString();
    result.success = !interrupted && !result.failure && result.tests.length === 21 && result.summary.failed === 0 &&
      result.fixtureErrors.length === 0 && result.nativeLogRead === true && result.unexpectedNativeErrors.length === 0 && result.sourceUnchangedDuringTest &&
      result.identity.binaryUnchangedDuringTest && result.cleanup.nativeStopped && result.cleanup.nativeExit?.code === 0 &&
      result.cleanup.signal === 'SIGQUIT' && result.cleanup.fixturesStopped && result.cleanup.openSockets === 0 &&
      result.cleanup.temporaryRootRemoved && result.cleanup.errors.length === 0;
  }
  return result;
}

let binary = process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'), output;
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--binary' && process.argv[i + 1]) binary = process.argv[++i];
  else if (process.argv[i] === '--output' && process.argv[i + 1]) output = process.argv[++i];
  else if (process.argv[i] === '--help') {
    process.stdout.write('Usage: node x10/test/adapters-baseline.mjs [--binary /path/to/nginx] [--output FILE]\nEnvironment: X10_NGINX_BINARY\n'); process.exit(0);
  } else throw new Error(`Unknown or incomplete argument: ${process.argv[i]}`);
}
const result = await run(binary);
if (output) {
  try { await writeFile(path.resolve(output), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 }); }
  catch (error) { result.success = false; result.outputError = error.message; }
}
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.success) process.exitCode = 1;
