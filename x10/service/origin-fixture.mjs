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
  'origin_query_timeout', 'origin_query_limit', 'origin_response_invalid',
  'origin_challenge_invalid', 'origin_challenge_failed', 'origin_challenge_timeout', 'origin_challenge_identity']);
export const ADMISSION_DIAGNOSTIC_STAGES = Object.freeze(['open', 'relay_admission',
  'relay_readiness', 'native_headers', 'native_body', 'native_pair', 'transport', 'lifetime']);
export const ADMISSION_DIAGNOSTIC_REASONS = Object.freeze(['invalid_arguments', 'expired',
  'replay_or_route', 'ready_status', 'ready_tag', 'ready_body', 'ready_query', 'native_status',
  'duplicate_header', 'native_headers', 'relay_headers', 'content_length', 'prefix_mismatch',
  'prefix_overflow', 'prefix_repeated', 'early_eof', 'pair_not_live', 'response_error',
  'response_aborted', 'response_closed', 'request_error', 'request_closed', 'socket_closed', 'aborted', 'closing']);
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
  let origin, relay, port, readyPort, closing = false, echoRequests = 0, relay502 = 0, pki, drain = null, readinessHold = null, nativeChallenge = null;
  const byTag = new Map(), readinessQueried = new Set();
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
  function readinessHoldClosed() {
    if (readinessHold && readinessHold.aborted && !readinessHold.responses.size && !readinessHold.pending.size) readinessHold.closed = true;
    return readinessHold?.closed === true;
  }
  function abortReadinessHold() {
    if (!readinessHold) return;
    readinessHold.aborted = true; clearTimeout(readinessHold.timer); abortNativeChallenge();
    for (const response of readinessHold.responses) response.destroy();
    for (const request of readinessHold.pending) request.destroy();
    readinessHoldClosed();
  }
  function expireReadinessHold() {
    if (readinessHold && performance.now() >= readinessHold.deadline) abortReadinessHold();
  }
  function nativeClosed() {
    const c = nativeChallenge;
    if (!c) return true;
    c.closed = c.aborted && (!c.started || (c.requestClosed && (!c.socket || c.socketClosed)))
      && (!c.relayResponse || c.relayClosed) && c.pending.size === 0;
    return c.closed;
  }
  function rememberAdmission(stage, reason) {
    const c = nativeChallenge;
    if (c && !c.accepted && !c.firstRefusal) c.firstRefusal = Object.freeze({ stage, reason });
  }
  function admissionDiagnostics() {
    if (arguments.length) fail('origin_challenge_invalid');
    const c = nativeChallenge, now = performance.now();
    const deadlineExpired = Boolean(c?.started && Number.isFinite(c.absoluteDeadline)
      && now >= c.absoluteDeadline);
    // Display is observational: unlike the live authority snapshot, it never
    // expires, aborts or resurrects a request and never grants admission.
    const currentPairLive = Boolean(c?.started && !closing && !c.aborted && !c.closed
      && !readinessHold.aborted && now < readinessHold.deadline && !deadlineExpired
      && c.validated === 1 && c.prefixMatched
      && c.headersMatched && c.request && !c.requestClosed && !c.request.destroyed
      && c.socket && !c.socketClosed && !c.socket.destroyed && c.response
      && !c.response.complete && !c.response.destroyed && c.relayResponse && !c.relayClosed
      && !c.relayResponse.destroyed && !c.relayResponse.writableEnded
      && c.relayResponse.socket && !c.relayResponse.socket.destroyed);
    return Object.freeze({ schema: 1, started: c?.started === true, admitted: c?.admitted === true,
      accepted: c?.accepted === true, firstRefusal: c?.firstRefusal || null,
      nativeStatusClass: c?.nativeStatusClass || 0, relayReadyStatusClass: c?.relayReadyStatusClass || 0,
      nativeHeaderPairMatched: c?.nativeHeaderPairMatched === true,
      relayHeaderPairMatched: c?.relayHeaderPairMatched === true,
      contentLengthMatched: c?.contentLengthMatched === true, prefixMatched: c?.prefixMatched === true,
      currentPairLive, deadlineExpired, prefixChunks: c?.prefixChunks || 0 });
  }
  function abortNativeChallenge(code = 'origin_challenge_failed', stage = 'transport', reason = 'aborted') {
    const c = nativeChallenge; if (!c) return;
    if (c.started) rememberAdmission(stage, reason);
    c.aborted = true; if (!c.failure) c.failure = code;
    clearTimeout(c.openTimer);
    c.response?.destroy(); c.request?.destroy(); c.socket?.destroy(); c.relayResponse?.destroy();
    for (const request of c.pending) request.destroy();
    c.rejectOpen?.(Object.assign(new Error(c.failure), { code: c.failure }));
    nativeClosed();
  }
  function expireNativeChallenge() {
    if (nativeChallenge?.started && Number.isFinite(nativeChallenge.absoluteDeadline)
        && performance.now() >= nativeChallenge.absoluteDeadline) abortNativeChallenge('origin_challenge_timeout', 'lifetime', 'expired');
  }
  function nativeSnapshot() {
    expireReadinessHold(); expireNativeChallenge(); nativeClosed();
    const c = nativeChallenge;
    const requestOpen = Boolean(c?.started && c.request && !c.requestClosed && !c.request.destroyed);
    const socketOpen = Boolean(c?.socket && !c.socketClosed && !c.socket.destroyed);
    const incomplete = Boolean(c?.response && !c.response.complete && !c.response.destroyed && requestOpen);
    const relayOpen = Boolean(c?.relayResponse && !c.relayClosed && !c.relayResponse.destroyed
      && !c.relayResponse.writableEnded && c.relayResponse.socket && !c.relayResponse.socket.destroyed);
    const bound = Boolean(c && !closing && !c.aborted && !c.closed && !readinessHold.aborted
      && c.validated === 1 && c.prefixMatched && c.headersMatched && requestOpen && socketOpen && incomplete && relayOpen);
    return { held: bound, requested: c?.started === true, candidateReadyObserved: c?.validated === 1,
      nativeProbeChecks: c?.validated || 0, heldResponses: relayOpen ? 1 : 0,
      aborted: c?.aborted === true, closed: c?.closed === true, released: false,
      nativeRouteObserved: bound, ownedRequestObserved: bound, relayResponseMatched: bound,
      currentRequestOpen: requestOpen, responseIncomplete: incomplete, relayResponseOpen: relayOpen,
      socketOpen, pairMatched: bound };
  }
  async function closeNativeChallenge() {
    abortNativeChallenge(); const end = performance.now() + 1000;
    while (!nativeClosed() && performance.now() < end) await new Promise(resolve => setTimeout(resolve, 10));
    return nativeClosed();
  }
  function challengeLocation(tag) {
    const nonce = randomBytes(16).toString('hex'), route = `/__x10-native-challenge/${nonce}`;
    nativeChallenge = { tag, nonce, route, relayRoute: `/native-challenge/${tag}/${nonce}`,
      prefix: Buffer.from(`x10-native-challenge:${tag}:${nonce}\n`), pending: new Set(),
      started: false, admitted: false, accepted: false, firstRefusal: null, nativeStatusClass: 0,
      relayReadyStatusClass: 0, nativeHeaderPairMatched: false, relayHeaderPairMatched: false,
      contentLengthMatched: false, prefixChunks: 0,
      validated: 0, request: null, response: null, socket: null,
      requestClosed: false, socketClosed: false, relayResponse: null, relayClosed: false,
      prefixMatched: false, headersMatched: false, aborted: false, closed: false, failure: null };
    return `location = ${route} { proxy_pass http://127.0.0.1:${readyPort}${nativeChallenge.relayRoute}; proxy_http_version 1.1; proxy_method GET; proxy_pass_request_body off; proxy_pass_request_headers off; proxy_set_header Host $proxy_host; proxy_set_header Connection close; proxy_set_header Content-Length ""; proxy_cache off; proxy_store off; proxy_buffering off; proxy_ignore_client_abort off; proxy_connect_timeout 1s; proxy_send_timeout 1s; proxy_read_timeout 1s; proxy_next_upstream off; proxy_intercept_errors off; proxy_hide_header X-X10-Native-Challenge; proxy_hide_header X-X10-Native-Candidate; add_header X-X10-Native-Challenge "${nonce}" always; add_header X-X10-Native-Candidate "${tag}" always; }`;
  }
  async function openNativeChallenge(absoluteDeadline) {
    const c = nativeChallenge, now = performance.now(); expireReadinessHold();
    if (arguments.length !== 1 || !c || c.started || closing || c.aborted || readinessHold.aborted
        || !Number.isFinite(absoluteDeadline) || absoluteDeadline <= now || absoluteDeadline > now + 1000
        || absoluteDeadline > readinessHold.deadline || gatewayPort === readyPort || gatewayPort === port) {
      if (c && !c.started) rememberAdmission('open', 'invalid_arguments');
      fail('origin_challenge_invalid');
    }
    c.started = true; c.absoluteDeadline = absoluteDeadline;
    const handle = Object.freeze({
      snapshot() { if (arguments.length) fail('origin_challenge_invalid'); return nativeSnapshot(); },
      async abort() { if (arguments.length) fail('origin_challenge_invalid'); return closeNativeChallenge(); }
    });
    let resolveOpen;
    const opened = new Promise((resolve, reject) => { resolveOpen = resolve; c.rejectOpen = reject; });
    // The rejected promise is consumed immediately; late network events never
    // rearm the one-use capability or create an unhandled promise rejection.
    opened.catch(() => {});
    c.openTimer = setTimeout(() => abortNativeChallenge('origin_challenge_timeout', 'lifetime', 'expired'), Math.max(1, absoluteDeadline - performance.now()));
    try {
      c.request = http.request({ host: '127.0.0.1', port: gatewayPort, path: c.route,
        method: 'GET', agent: false, maxHeaderSize: 4096, headers: { connection: 'close' } }, response => {
        c.response = response;
        response.once('error', () => abortNativeChallenge('origin_challenge_failed', 'transport', 'response_error'));
        response.once('aborted', () => abortNativeChallenge('origin_challenge_failed',
          c.headersMatched && !c.prefixMatched ? 'native_body' : 'transport',
          c.headersMatched && !c.prefixMatched ? 'early_eof' : 'response_aborted'));
        response.once('close', () => { if (!c.aborted) abortNativeChallenge('origin_challenge_failed', 'transport', 'response_closed'); });
        expireReadinessHold();
        if (c.aborted || closing || performance.now() >= absoluteDeadline) { abortNativeChallenge('origin_challenge_timeout', 'lifetime', 'expired'); return; }
        c.nativeStatusClass = Number.isInteger(response.statusCode) && response.statusCode >= 100 && response.statusCode <= 599
          ? Math.floor(response.statusCode / 100) : 0;
        const expected = { 'x-x10-native-challenge': c.nonce, 'x-x10-native-candidate': c.tag,
          'x-x10-relay-challenge': c.nonce, 'x-x10-relay-candidate': c.tag };
        const found = Object.create(null), duplicates = new Set();
        for (let i = 0; i < response.rawHeaders.length; i += 2) {
          const name = response.rawHeaders[i].toLowerCase();
          if (Object.hasOwn(expected, name)) {
            if (Object.hasOwn(found, name)) duplicates.add(name);
            found[name] = response.rawHeaders[i + 1];
          }
        }
        c.nativeHeaderPairMatched = ['x-x10-native-challenge', 'x-x10-native-candidate']
          .every(k => !duplicates.has(k) && found[k] === expected[k]);
        c.relayHeaderPairMatched = ['x-x10-relay-challenge', 'x-x10-relay-candidate']
          .every(k => !duplicates.has(k) && found[k] === expected[k]);
        c.contentLengthMatched = response.headers['content-length'] === String(c.prefix.length + 1);
        if (duplicates.size) { abortNativeChallenge('origin_challenge_identity', 'native_headers', 'duplicate_header'); return; }
        if (response.statusCode !== 200) { abortNativeChallenge('origin_challenge_identity', 'native_headers', 'native_status'); return; }
        if (!c.contentLengthMatched) { abortNativeChallenge('origin_challenge_identity', 'native_headers', 'content_length'); return; }
        if (!c.nativeHeaderPairMatched) { abortNativeChallenge('origin_challenge_identity', 'native_headers', 'native_headers'); return; }
        if (!c.relayHeaderPairMatched) { abortNativeChallenge('origin_challenge_identity', 'native_headers', 'relay_headers'); return; }
        c.headersMatched = true; let received = 0;
        response.on('data', b => {
          expireReadinessHold(); expireNativeChallenge();
          if (c.aborted || closing) return;
          c.prefixChunks = Math.min(4096, c.prefixChunks + 1);
          if (c.prefixMatched) { abortNativeChallenge('origin_challenge_identity', 'native_body', 'prefix_repeated'); return; }
          if (!Buffer.isBuffer(b) || received + b.length > c.prefix.length) {
            abortNativeChallenge('origin_challenge_identity', 'native_body', 'prefix_overflow'); return;
          }
          if (!b.equals(c.prefix.subarray(received, received + b.length))) {
            abortNativeChallenge('origin_challenge_identity', 'native_body', 'prefix_mismatch'); return;
          }
          received += b.length;
          if (received === c.prefix.length) {
            c.prefixMatched = true; response.pause();
            if (performance.now() >= absoluteDeadline) { abortNativeChallenge('origin_challenge_identity', 'lifetime', 'expired'); return; }
            if (nativeSnapshot().held !== true) { abortNativeChallenge('origin_challenge_identity', 'native_pair', 'pair_not_live'); return; }
            c.accepted = true; c.rejectOpen = null; resolveOpen(handle);
          }
        });
        response.once('end', () => abortNativeChallenge('origin_challenge_identity', 'native_body', 'early_eof'));
      });
      c.request.once('socket', socket => { c.socket = socket; socket.once('close', () => { c.socketClosed = true;
        abortNativeChallenge('origin_challenge_failed', 'transport', 'socket_closed'); nativeClosed(); });
        expireNativeChallenge(); if (c.aborted) socket.destroy(); });
      c.request.once('error', () => abortNativeChallenge('origin_challenge_failed', 'transport', 'request_error'));
      c.request.once('close', () => { c.requestClosed = true;
        if (!c.aborted) abortNativeChallenge('origin_challenge_failed', 'transport', 'request_closed'); nativeClosed(); });
      c.request.end();
    } catch { abortNativeChallenge('origin_challenge_failed', 'transport', 'request_error'); }
    try { return await opened; }
    catch (error) { await closeNativeChallenge(); throw error; }
  }
  const track = (server, sockets) => { server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    server.on('clientError', (_error, socket) => socket.destroy()); server.requestTimeout = 4000; server.headersTimeout = 4000; };
  async function close() {
    closing = true; abortDrain(); abortReadinessHold(); for (const request of pending) request.destroy();
    const nativeClosedProof = await closeNativeChallenge();
    const [originClosed, relayClosed] = await Promise.all([closeServer(origin, originSockets), closeServer(relay, relaySockets)]);
    const [originPortClosedProof, relayPortClosedProof] = await Promise.all([port ? originPortClosed(port) : true, readyPort ? originPortClosed(readyPort) : true]);
    const end = performance.now() + 2500;
    while ((pending.size || originSockets.size || relaySockets.size || (drain?.response && !drain.closed)
        || (readinessHold && (readinessHold.responses.size || readinessHold.pending.size))) && performance.now() < end) await new Promise(resolve => setTimeout(resolve, 10));
    readinessHoldClosed();
    if (!nativeClosedProof || !originClosed || !relayClosed || !originPortClosedProof || !relayPortClosedProof
        || pending.size || originSockets.size || relaySockets.size || (drain?.response && !drain.closed)
        || (readinessHold && !readinessHold.closed)) fail('origin_cleanup_unconfirmed');
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
      if (req.url?.startsWith('/native-challenge/')) {
        expireReadinessHold(); expireNativeChallenge(); const c = nativeChallenge;
        if (req.method !== 'GET' || !c || req.url !== c.relayRoute || !c.started || c.admitted || c.aborted || closing) {
          if (c?.started && req.url === c.relayRoute) rememberAdmission('relay_admission', 'replay_or_route');
          res.writeHead(503); res.end('challenge refused\n'); return;
        }
        c.admitted = true; c.relayResponse = res;
        res.once('close', () => { c.relayClosed = true;
          if (!c.aborted) abortNativeChallenge('origin_challenge_failed', 'transport', 'response_closed'); nativeClosed(); });
        try {
          const observed = await queryOriginReadiness(gatewayPort, c.pending); expireReadinessHold(); expireNativeChallenge();
          const result = routeOriginReadiness(observed, c.tag);
          c.relayReadyStatusClass = Math.floor(observed.status / 100);
          if (c.aborted || closing || res.destroyed || result.status !== 200 || !result.body.equals(Buffer.from('ready\n'))) {
            const reason = c.aborted ? 'aborted' : closing ? 'closing' : res.destroyed ? 'response_closed'
              : observed.tag !== c.tag ? 'ready_tag' : observed.status !== 200 ? 'ready_status' : 'ready_body';
            abortNativeChallenge('origin_challenge_identity', 'relay_readiness', reason); return;
          }
          c.validated = 1;
          res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': c.prefix.length + 1,
            'X-X10-Relay-Challenge': c.nonce, 'X-X10-Relay-Candidate': c.tag });
          res.flushHeaders(); res.write(c.prefix); return;
        } catch { abortNativeChallenge('origin_challenge_failed', 'relay_readiness', 'ready_query'); return; }
      }
      const match = req.method === 'GET' && /^\/tls-probe\/([a-f0-9]{32})$/.exec(req.url);
      if (!match || !byTag.has(match[1])) { res.writeHead(503); res.end('route not ready\n'); return; }
      expireReadinessHold();
      const heldCandidate = readinessHold && match[1] === readinessHold.tag;
      if (heldCandidate && (readinessHold.aborted || readinessHold.admitted >= 8)) { res.writeHead(503); res.end('route not ready\n'); return; }
      readinessQueried.add(match[1]);
      if (heldCandidate) {
        readinessHold.admitted++; readinessHold.responses.add(res);
        res.once('close', () => { readinessHold.responses.delete(res); readinessHold.held.delete(res); readinessHoldClosed(); });
      }
      try {
        const observed = await queryOriginReadiness(gatewayPort, heldCandidate ? readinessHold.pending : pending);
        expireReadinessHold();
        if (closing || res.destroyed || (heldCandidate && readinessHold.aborted)) { res.destroy(); return; }
        const result = routeOriginReadiness(observed, match[1]);
        if (result.status === 502) { relay502++; byTag.set(match[1], (byTag.get(match[1]) || 0) + 1); }
        if (heldCandidate) {
          if (result.status === 200 && result.body.equals(Buffer.from('ready\n'))) {
            readinessHold.validated++; readinessHold.held.add(res); return;
          }
          res.writeHead(503); res.end('route not ready\n'); return;
        }
        res.writeHead(result.status); res.end(result.body);
      } catch { if (!closing && !res.destroyed && !(heldCandidate && readinessHold.aborted)) { res.writeHead(503); res.end('not ready\n'); } else res.destroy(); }
    });
    track(relay, relaySockets); readyPort = await listen(relay);
    return { port, readyPort, ...pki,
      prepareReadinessHold(tag, ...args) {
        if (args.length || closing || readinessHold || !validTag(tag) || !byTag.has(tag) || readinessQueried.has(tag)) fail('origin_fixture_invalid');
        readinessHold = { tag, admitted: 0, validated: 0, aborted: false, closed: false,
          deadline: performance.now() + 8000, responses: new Set(), held: new Set(), pending: new Set() };
        readinessHold.timer = setTimeout(abortReadinessHold, 8000);
        const nativeLocation = challengeLocation(tag);
        return Object.freeze({ nativeLocation, openNativeChallenge, admissionDiagnostics,
          snapshot() {
            expireReadinessHold(); readinessHoldClosed();
            const active = [...readinessHold.held].filter(response => !response.destroyed && !response.writableEnded).length;
            return { held: !closing && !readinessHold.aborted && active > 0, requested: readinessHold.admitted > 0,
              candidateReadyObserved: readinessHold.validated > 0, nativeProbeChecks: readinessHold.validated,
              heldResponses: active, aborted: readinessHold.aborted, closed: readinessHold.closed, released: false };
          },
          release() { expireReadinessHold(); fail('origin_fixture_invalid'); },
          async abort() {
            abortReadinessHold();
            const end = performance.now() + 1000;
            while ((!readinessHoldClosed() || !nativeClosed()) && performance.now() < end) await new Promise(resolve => setTimeout(resolve, 10));
            return readinessHoldClosed() && nativeClosed();
          },
        });
      },
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
