// Private HTTPS origin and candidate-bound HTTP readiness relay for loopback tests.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createServicePKI } from './tls-fixture.mjs';

export const ORIGIN_FIXTURE_ERROR_CODES = Object.freeze(['origin_fixture_invalid',
  'origin_fixture_failed', 'origin_cleanup_unconfirmed', 'origin_query_failed',
  'origin_query_timeout', 'origin_query_limit', 'origin_response_invalid']);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const validPort = p => Number.isInteger(p) && p >= 1024 && p <= 65535;
const validTag = t => typeof t === 'string' && /^[a-f0-9]{32}$/.test(t);
function values(value, keys) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('origin_fixture_invalid');
  const out = Object.create(null);
  for (const k of Reflect.ownKeys(value)) { const d = Object.getOwnPropertyDescriptor(value, k);
    if (typeof k !== 'string' || !keys.includes(k) || !d || !Object.hasOwn(d, 'value')) fail('origin_fixture_invalid');
    out[k] = d.value;
  }
  return out;
}
async function privateDirectory(parent) {
  if (typeof parent !== 'string' || !path.isAbsolute(parent) || !/^[A-Za-z0-9_./-]+$/.test(parent)
      || path.normalize(parent) !== parent) fail('origin_fixture_invalid');
  const s = await lstat(parent);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700
      || await realpath(parent) !== parent) fail('origin_fixture_invalid');
}
async function secretFile(file) {
  const h = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await h.stat();
    if (!s.isFile() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o600
        || s.nlink !== 1 || s.size < 1 || s.size > 65536 || await realpath(file) !== file) fail('origin_fixture_invalid');
    const data = Buffer.alloc(s.size + 1); let used = 0;
    while (used < data.length) { const r = await h.read(data, used, data.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    const after = await h.stat();
    if (used !== s.size || after.size !== s.size || after.ino !== s.ino || after.dev !== s.dev
        || after.mtimeMs !== s.mtimeMs || after.ctimeMs !== s.ctimeMs) { data.fill(0); fail('origin_fixture_invalid'); }
    return data.subarray(0, used);
  } finally { await h.close(); }
}

// Fixture correlation only: a matching immutable input tag cannot confer authority.
export function routeOriginReadiness(result, expectedTag) {
  if (!validTag(expectedTag) || !result || !Buffer.isBuffer(result.body) || result.body.length > 4096
      || !Number.isInteger(result.status) || result.status < 100 || result.status > 599
      || result.tag !== expectedTag) return { status: 503, body: Buffer.from('route not ready\n') };
  return { status: result.status, body: Buffer.from(result.body) };
}

export function queryOriginReadiness(port, pending = new Set()) {
  if (!validPort(port) || !(pending instanceof Set)) fail('origin_fixture_invalid');
  return new Promise((resolve, reject) => {
    let req, result, failure, settled = false;
    const remember = code => { if (!failure) failure = code; };
    const finish = () => { if (settled) return; settled = true; clearTimeout(timer); pending.delete(req);
      if (failure || !result) reject(Object.assign(new Error(failure || 'origin_query_failed'), { code: failure || 'origin_query_failed' })); else resolve(result); };
    const timer = setTimeout(() => { if (settled) return; remember('origin_query_timeout'); req?.destroy(); }, 1000);
    try {
      req = http.request({ host: '127.0.0.1', port, path: '/ready', method: 'GET', agent: false,
        headers: { connection: 'close' } }, res => {
        res.once('error', () => { if (settled) return; remember('origin_query_failed'); req.destroy(); });
        if (settled) { res.destroy(); return; }
        let tags = 0, tag;
        for (let i = 0; i < res.rawHeaders.length; i += 2) if (res.rawHeaders[i].toLowerCase() === 'x-x10-tls-probe') { tags++; tag = res.rawHeaders[i + 1]; }
        if (!Number.isInteger(res.statusCode) || res.statusCode < 100 || res.statusCode > 599
            || tags !== 1 || !validTag(tag)) remember('origin_response_invalid');
        if (failure) { res.destroy(); req.destroy(); return; }
        const chunks = []; let size = 0;
        res.on('data', b => { if (settled) return; size += b.length;
          if (size > 4096) { remember('origin_query_limit'); res.destroy(); req.destroy(); } else chunks.push(b); });
        res.once('end', () => { if (settled) return;
          if (!res.complete) remember('origin_response_invalid');
          if (!failure) result = { status: res.statusCode, tag, body: Buffer.concat(chunks) }; });
      });
      pending.add(req); req.setTimeout(1000, () => { if (settled) return; remember('origin_query_timeout'); req.destroy(); });
      req.once('error', () => { if (!settled) remember('origin_query_failed'); });
      req.once('close', finish); req.end();
    } catch { remember('origin_query_failed'); req?.destroy(); if (!req) finish(); }
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = error => { if (settled) return; settled = true; clearTimeout(timer); server.removeListener('error', onError);
      if (error) reject(Object.assign(new Error('origin_fixture_failed'), { code: 'origin_fixture_failed' })); else resolve(server.address().port); };
    const onError = () => done(true), timer = setTimeout(() => done(true), 2500);
    server.once('error', onError); server.listen(0, '127.0.0.1', () => done(false));
  });
}
export function originPortClosed(port) {
  if (!validPort(port)) return Promise.resolve(false);
  return new Promise(resolve => {
    let settled = false, refused = false;
    const finish = value => { if (settled) return; settled = true; clearTimeout(timer); resolve(value); };
    const socket = net.connect({ host: '127.0.0.1', port }), timer = setTimeout(() => { socket.destroy(); finish(false); }, 1000);
    socket.once('connect', () => socket.destroy());
    socket.once('error', e => { refused = e.code === 'ECONNREFUSED'; socket.destroy(); });
    socket.once('close', () => finish(refused));
  });
}
async function closeServer(server, sockets) {
  if (!server) return true;
  return new Promise(resolve => {
    let settled = false;
    const done = value => { if (settled) return; settled = true; clearTimeout(timer); resolve(value); };
    const timer = setTimeout(() => done(false), 2500);
    for (const socket of sockets) socket.destroy();
    try { server.close(error => done(!error || error.code === 'ERR_SERVER_NOT_RUNNING')); } catch { done(false); }
  });
}

export async function createOriginFixture(parent, options) {
  let v;
  try { v = values(options, ['gatewayPort', 'body', 'stream']); await privateDirectory(parent); }
  catch { fail('origin_fixture_invalid'); }
  const { gatewayPort, body = Buffer.from('service-fixture\n'), stream = Buffer.alloc(65537, 0x62) } = v;
  if (!validPort(gatewayPort) || !Buffer.isBuffer(body) || body.length < 1 || body.length > 4096
      || !Buffer.isBuffer(stream) || stream.length < 1 || stream.length > 1024 * 1024) fail('origin_fixture_invalid');
  const responseBody = Buffer.from(body), responseStream = Buffer.from(stream), originSockets = new Set(), relaySockets = new Set(), pending = new Set();
  let origin, relay, port, readyPort, closing = false, echoRequests = 0, relay502 = 0, pki, drain = null;
  const byTag = new Map();
  // One private capability per fixture. Its expiry only aborts; it never sends
  // the remainder or grants completed-stream evidence.
  function abortDrain() {
    if (!drain || drain.aborted || drain.closed || drain.completed) return false;
    drain.aborted = true; drain.held = false; clearTimeout(drain.timer);
    if (drain.response) drain.response.destroy();
    return true;
  }
  function expireDrain() {
    if (drain && !drain.released && !drain.completed && performance.now() >= drain.deadline) abortDrain();
  }
  const track = (server, sockets) => { server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    server.on('clientError', (_error, socket) => socket.destroy()); server.requestTimeout = 4000; server.headersTimeout = 4000; };
  async function close() {
    closing = true; abortDrain(); for (const request of pending) request.destroy();
    const [originClosed, relayClosed] = await Promise.all([closeServer(origin, originSockets), closeServer(relay, relaySockets)]);
    const [originPortClosedProof, relayPortClosedProof] = await Promise.all([port ? originPortClosed(port) : true, readyPort ? originPortClosed(readyPort) : true]);
    const end = performance.now() + 2500;
    while ((pending.size || originSockets.size || relaySockets.size || (drain?.response && !drain.closed)) && performance.now() < end) await new Promise(resolve => setTimeout(resolve, 10));
    if (!originClosed || !relayClosed || !originPortClosedProof || !relayPortClosedProof
        || pending.size || originSockets.size || relaySockets.size || (drain?.response && !drain.closed)) fail('origin_cleanup_unconfirmed');
    return { originClosed, relayClosed, originPortClosed: originPortClosedProof, relayPortClosed: relayPortClosedProof };
  }
  try {
    pki = await createServicePKI(parent);
    let key, certificate;
    try {
      key = await secretFile(pki.certificateKey); certificate = await secretFile(pki.certificate);
      origin = https.createServer({ key, cert: certificate, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' }, (req, res) => {
        res.on('error', () => res.destroy()); if (closing) { req.destroy(); return; }
        res.setHeader('X-TLS-App', 'authenticated-origin'); res.setHeader('X-X10-TLS-Probe', 'untrusted-origin-marker');
        if (req.url?.startsWith('/slow-stream/')) {
          expireDrain();
          if (req.method !== 'GET' || !drain || req.url !== drain.path || drain.requested || drain.aborted || drain.closed) {
            res.writeHead(404); res.end('not found\n'); return;
          }
          drain.requested = true; drain.response = res;
          res.once('finish', () => { if (drain.released && !drain.aborted && !closing) drain.completed = true; });
          res.once('close', () => { drain.closed = true; drain.held = false; clearTimeout(drain.timer);
            if (!drain.completed) drain.aborted = true; });
          res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': 65537,
            'X-Accel-Buffering': 'no' });
          res.flushHeaders(); res.write(Buffer.alloc(4096, 0x62)); drain.held = true; return;
        }
        if (req.method === 'GET' && req.url === '/ready') { res.end('ready\n'); return; }
        if (req.method === 'POST' && req.url === '/echo') {
          echoRequests++; const chunks = []; let size = 0;
          req.on('error', () => res.destroy()); req.on('data', b => { size += b.length; if (size > 256 * 1024) req.destroy(); else chunks.push(b); });
          req.once('end', () => { if (!closing && req.complete && !req.destroyed) res.end(Buffer.concat(chunks)); }); return;
        }
        if (req.method === 'GET' && req.url === '/stream') { const half = Math.floor(responseStream.length / 2); res.write(responseStream.subarray(0, half)); res.end(responseStream.subarray(half)); return; }
        if (req.method === 'GET' && req.url === '/') { res.end(responseBody); return; }
        res.writeHead(404); res.end('not found\n');
      });
    } finally { key?.fill(0); certificate?.fill(0); }
    origin.on('tlsClientError', () => {}); track(origin, originSockets); port = await listen(origin);
    relay = http.createServer(async (req, res) => {
      res.on('error', () => res.destroy()); if (closing) { req.destroy(); return; }
      if (req.method === 'GET' && ['/', '/ready'].includes(req.url)) { res.end('ready\n'); return; }
      const match = req.method === 'GET' && /^\/tls-probe\/([a-f0-9]{32})$/.exec(req.url);
      if (!match || !byTag.has(match[1])) { res.writeHead(503); res.end('route not ready\n'); return; }
      try {
        const observed = await queryOriginReadiness(gatewayPort, pending);
        if (closing || res.destroyed) { res.destroy(); return; }
        const result = routeOriginReadiness(observed, match[1]);
        if (result.status === 502) { relay502++; byTag.set(match[1], (byTag.get(match[1]) || 0) + 1); }
        res.writeHead(result.status); res.end(result.body);
      } catch { if (!closing && !res.destroyed) { res.writeHead(503); res.end('not ready\n'); } else res.destroy(); }
    });
    track(relay, relaySockets); readyPort = await listen(relay);
    return { port, readyPort, ...pki,
      prepareDrain(...args) {
        if (args.length || closing || drain) fail('origin_fixture_invalid');
        drain = { path: `/slow-stream/${randomBytes(16).toString('hex')}`, response: null,
          requested: false, held: false, released: false, completed: false, aborted: false, closed: false,
          deadline: performance.now() + 8000 };
        drain.timer = setTimeout(abortDrain, 8000);
        return Object.freeze({ path: drain.path, prefixBytes: 4096, totalBytes: 65537,
          snapshot: () => { expireDrain(); return { held: drain.held && !drain.response?.destroyed && !drain.response?.writableEnded,
            requested: drain.requested, released: drain.released, completed: drain.completed,
            aborted: drain.aborted, closed: drain.closed }; },
          release() {
            expireDrain();
            if (closing || !drain.requested || !drain.held || drain.released || drain.aborted || drain.closed
                || !drain.response || drain.response.destroyed || drain.response.writableEnded) fail('origin_fixture_invalid');
            drain.released = true; drain.held = false; clearTimeout(drain.timer);
            drain.response.end(Buffer.alloc(65537 - 4096, 0x62)); return true;
          }, async abort() {
            abortDrain();
            if (!drain.response || drain.closed) return true;
            return new Promise(resolve => {
              let settled = false;
              const done = value => { if (settled) return; settled = true; clearTimeout(timer);
                drain.response.removeListener('close', closed); resolve(value); };
              const closed = () => done(drain.closed === true);
              const timer = setTimeout(() => done(false), 1000);
              drain.response.once('close', closed);
            });
          } });
      },
      candidate(input) {
        const { tag, trust = 'good', name = 'localhost', target = 'https' } = values(input, ['tag', 'trust', 'name', 'target']);
      if (closing || !validTag(tag) || !['good', 'wrong'].includes(trust) || !['localhost', 'wrong.invalid'].includes(name)
            || !['https', 'plaintext'].includes(target) || byTag.has(tag) || byTag.size >= 128) fail('origin_fixture_invalid');
        byTag.set(tag, 0);
        const trusted = path.join(pki.directory, trust === 'good' ? 'ca.crt' : 'wrong-ca.crt');
        return { serverBody: `location / { proxy_pass https://127.0.0.1:${target === 'https' ? port : readyPort}; proxy_http_version 1.1; proxy_next_upstream off; proxy_ssl_verify on; proxy_ssl_verify_depth 2; proxy_ssl_trusted_certificate "${trusted}"; proxy_ssl_server_name on; proxy_ssl_name ${name}; proxy_hide_header X-X10-TLS-Probe; add_header X-X10-TLS-Probe "${tag}" always; }`,
          healthURL: `http://127.0.0.1:${readyPort}/tls-probe/${tag}`, healthExpectedStatus: 200, healthExpectedBody: 'ready\n' };
      },
      counts: () => ({ echoRequests, relay502 }), count502: tag => { if (!validTag(tag)) fail('origin_fixture_invalid'); return byTag.get(tag) || 0; }, close };
  } catch {
    try { await close(); } catch { fail('origin_cleanup_unconfirmed'); }
    fail('origin_fixture_failed');
  }
}
