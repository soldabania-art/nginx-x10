// Bounded owned HTTPS response hold for the ephemeral drain acceptance fixture.
// No CLI, logging, persistent state or manager/native authority.
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { performance } from 'node:perf_hooks';

export const SLOW_CLIENT_ERROR_CODES = Object.freeze(['slow_client_invalid', 'slow_client_failed',
  'slow_client_timeout', 'slow_client_cancelled', 'slow_client_state', 'slow_client_identity',
  'slow_client_protocol', 'slow_client_response', 'slow_client_payload', 'slow_client_overflow',
  'slow_client_early_end', 'slow_client_close_unknown', 'slow_client_ca_refused', 'slow_client_hostname_refused']);
const error = code => Object.assign(new Error(code), { code });
const caCodes = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT']);
function input(port, route, options) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535
      || typeof route !== 'string' || !/^\/slow-stream\/[a-f0-9]{32}$/.test(route)
      || !options || typeof options !== 'object'
      || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) throw error('slow_client_invalid');
  const keys = ['ca', 'expectedCertificate', 'servername', 'version', 'expectedBody', 'prefixBytes', 'signal', 'timeoutMs'];
  const o = Object.create(null);
  for (const k of Reflect.ownKeys(options)) {
    const d = Object.getOwnPropertyDescriptor(options, k);
    if (typeof k !== 'string' || !keys.includes(k) || !d || !Object.hasOwn(d, 'value')) throw error('slow_client_invalid');
    o[k] = d.value;
  }
  const { ca, expectedCertificate, expectedBody, prefixBytes = 4096,
    servername = 'localhost', version = 'TLSv1.3', signal, timeoutMs = 8000 } = o;
  if (!Buffer.isBuffer(ca) || ca.length < 1 || ca.length > 65536
      || !Buffer.isBuffer(expectedCertificate) || expectedCertificate.length < 1 || expectedCertificate.length > 65536
      || !Buffer.isBuffer(expectedBody) || expectedBody.length < 2 || expectedBody.length > 1024 * 1024
      || !Number.isInteger(prefixBytes) || prefixBytes < 1 || prefixBytes >= expectedBody.length
      || !['localhost', 'wrong.invalid'].includes(servername) || version !== 'TLSv1.3'
      || !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 8000
      || (signal !== undefined && !(signal instanceof AbortSignal))) throw error('slow_client_invalid');
  try { if (!new X509Certificate(ca).ca || new X509Certificate(expectedCertificate).ca) throw error('slow_client_invalid'); }
  catch { throw error('slow_client_invalid'); }
  return { ca: Buffer.from(ca), expectedCertificate: Buffer.from(expectedCertificate),
    expectedBody: Buffer.from(expectedBody), prefixBytes, servername, version, signal, timeoutMs };
}
export async function createPausedTLSClient(port, route, options) {
  const v = input(port, route, options);
  if (v.signal?.aborted) throw error('slow_client_cancelled');
  let req, res, socket, count = 0, held = false, resumed = false, ended = false;
  let tlsVerified = false, failure, terminal = false, reqClosed = false, socketClosed = false;
  let closeTimer, overallTimer, readyResolve, readyReject, doneResolve, doneReject;
  const chunks = [], deadline = performance.now() + v.timeoutMs;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const done = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });
  // A post-hold error may precede the caller's resume/cancel decision.
  done.catch(() => {});
  function expired() {
    if (!terminal && performance.now() >= deadline) { fail('slow_client_timeout'); return true; }
    return false;
  }
  function finish() {
    if (terminal || !reqClosed || (socket && !socketClosed)) return;
    if (!failure && performance.now() >= deadline) failure = 'slow_client_timeout';
    if (!failure && (!resumed || !ended || !tlsVerified || count !== v.expectedBody.length)) failure = 'slow_client_early_end';
    terminal = true; clearTimeout(overallTimer); clearTimeout(closeTimer);
    v.signal?.removeEventListener('abort', abort);
    if (failure) { const e = error(failure); readyReject(e); doneReject(e); }
    else doneResolve({ ok: true, complete: true, certificateMatched: true, protocol: 'TLSv1.3', body: Buffer.concat(chunks) });
  }
  function fail(code) {
    if (terminal) return;
    if (!failure) failure = code;
    res?.destroy(); req?.destroy(); socket?.destroy();
    if (!req) { reqClosed = true; finish(); return; }
    if (!closeTimer) closeTimer = setTimeout(() => {
      if (terminal) return;
      terminal = true; clearTimeout(overallTimer); v.signal?.removeEventListener('abort', abort);
      failure = 'slow_client_close_unknown'; const e = error(failure); readyReject(e); doneReject(e);
    }, 1000);
    finish();
  }
  function abort() { fail('slow_client_cancelled'); }
  const handle = Object.freeze({
    snapshot() {
      if (arguments.length !== 0) throw error('slow_client_invalid');
      expired(); return { paused: held && !resumed && !failure && !terminal && res?.isPaused() === true,
        complete: terminal && !failure, failed: Boolean(failure), tlsVerified,
        requestClosed: reqClosed, responseIncomplete: Boolean(res && !res.complete && !ended && !failure && !reqClosed && !res.destroyed) };
    },
    async resume() {
      if (arguments.length !== 0) throw error('slow_client_invalid');
      expired();
      if (!held || resumed || failure || terminal) throw error('slow_client_state');
      resumed = true; res.resume(); return done;
    },
    async cancel() {
      if (arguments.length !== 0) throw error('slow_client_invalid');
      expired();
      if (!terminal) fail('slow_client_cancelled');
      try { await done; } catch { /* Refusal is expected; physical close is separate. */ }
      return reqClosed && (!socket || socketClosed) && failure !== 'slow_client_close_unknown';
    }
  });
  overallTimer = setTimeout(() => fail('slow_client_timeout'), v.timeoutMs);
  v.signal?.addEventListener('abort', abort, { once: true });
  try {
    req = https.request({ host: '127.0.0.1', port, path: route, method: 'GET', agent: false,
      ca: v.ca, servername: v.servername, rejectUnauthorized: true,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', headers: { connection: 'close' } }, response => {
      res = response;
      res.once('error', () => fail('slow_client_failed'));
      res.once('aborted', () => fail('slow_client_early_end'));
      if (expired() || terminal || failure) { res.destroy(); return; }
      const peer = res.socket?.getPeerCertificate();
      if (res.socket?.authorized !== true || !Buffer.isBuffer(peer?.raw)
          || !peer.raw.equals(v.expectedCertificate)) { fail('slow_client_identity'); return; }
      if (res.socket.getProtocol() !== 'TLSv1.3') { fail('slow_client_protocol'); return; }
      if (res.statusCode !== 200) { fail('slow_client_response'); return; }
      tlsVerified = true;
      res.on('data', b => {
        if (expired() || terminal || failure) return;
        if (held && !resumed) { fail('slow_client_state'); return; }
        if (!Buffer.isBuffer(b) || b.length === 0) { fail('slow_client_payload'); return; }
        if (count + b.length > v.expectedBody.length) { fail('slow_client_overflow'); return; }
        if (!b.equals(v.expectedBody.subarray(count, count + b.length))) { fail('slow_client_payload'); return; }
        count += b.length; chunks.push(Buffer.from(b));
        if (!held && count >= v.prefixBytes) {
          if (count !== v.prefixBytes || count === v.expectedBody.length) { fail('slow_client_early_end'); return; }
          held = true; res.pause(); readyResolve(handle);
        }
      });
      res.once('end', () => {
        if (expired() || terminal || failure) return;
        if (!held || !resumed || !res.complete || count !== v.expectedBody.length) { fail('slow_client_early_end'); return; }
        ended = true; finish();
      });
      res.once('close', () => { if (!terminal && !failure && !ended) fail('slow_client_early_end'); });
    });
    req.once('socket', s => {
      socket = s; s.once('close', () => { socketClosed = true; finish(); });
      if (failure || terminal) s.destroy();
    });
    req.once('error', e => fail(e?.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ? 'slow_client_hostname_refused'
      : caCodes.has(e?.code) ? 'slow_client_ca_refused' : 'slow_client_failed'));
    req.once('close', () => { reqClosed = true; finish(); });
    req.setTimeout(v.timeoutMs, () => fail('slow_client_timeout')); req.end();
  } catch { fail('slow_client_failed'); }
  return ready;
}
