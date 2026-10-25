import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createServicePKI } from './tls-fixture.mjs';
import { createPausedTLSClient, SLOW_CLIENT_ERROR_CODES } from './slow-client.mjs';
const route = '/slow-stream/' + 'a'.repeat(32), expected = Buffer.alloc(65537, 0x62);
let parent, pki, key, cert;
before(async () => {
  parent = await mkdtemp(path.join(os.tmpdir(), 'x10-slow-client-')); await chmod(parent, 0o700);
  pki = await createServicePKI(parent); key = await readFile(pki.certificateKey); cert = await readFile(pki.certificate);
});
after(async () => { key?.fill(0); if (parent) await rm(parent, { recursive: true }); });
const opts = extra => ({ ca: pki.ca, expectedCertificate: pki.expectedCertificate,
  servername: 'localhost', version: 'TLSv1.3', expectedBody: expected, prefixBytes: 4096, ...extra });
async function fixture(fn, config = {}) {
  const sockets = new Set(); let response, requests = 0;
  const server = https.createServer({ key, cert, minVersion: config.tls12 ? 'TLSv1.2' : 'TLSv1.3',
    maxVersion: config.tls12 ? 'TLSv1.2' : 'TLSv1.3' }, (req, res) => {
    requests++; response = res;
    res.on('error', () => {});
    if (config.noData) return;
    res.writeHead(config.status || 200, { 'content-length': config.length ?? expected.length });
    if (config.earlyFull) { res.end(expected); return; }
    if (config.earlyShort) { res.end(expected.subarray(0, 100)); return; }
    if (config.badPrefix) { res.write(Buffer.alloc(4096, 0x61)); return; }
    if (config.splitPrefix) { res.write(expected.subarray(0, 1024)); setImmediate(() => { if (!res.destroyed) res.write(expected.subarray(1024, 4096)); }); }
    else res.write(expected.subarray(0, 4096));
  });
  server.on('tlsClientError', () => {});
  server.on('connection', s => { sockets.add(s); s.once('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    await fn({ port: server.address().port,
      release(body = expected.subarray(4096)) { assert(response); response.end(body); },
      truncate() { assert(response); response.destroy(); }, get requests() { return requests; } });
  } finally {
    const closed = [...sockets].map(s => new Promise(resolve => { s.once('close', resolve); s.destroy(); }));
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('owned_server_close_timeout')), 1500);
      server.close(e => { clearTimeout(timer); e ? reject(e) : resolve(); });
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('owned_socket_close_timeout')), 1500);
      Promise.all(closed).then(() => { clearTimeout(timer); resolve(); }, reject);
    });
    assert.equal(sockets.size, 0);
  }
}
test('error allowlist contains only distinct fixed nonsecret names', () => {
  assert(Object.isFrozen(SLOW_CLIENT_ERROR_CODES)); assert.equal(new Set(SLOW_CLIENT_ERROR_CODES).size, SLOW_CLIENT_ERROR_CODES.length);
  assert(SLOW_CLIENT_ERROR_CODES.every(x => /^slow_client_[a-z_]+$/.test(x)));
});
for (const splitPrefix of [false, true]) test(`real TLS verifies exact prefix, pauses and completes only after explicit resume (${splitPrefix})`, async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts());
    assert.deepEqual(h.snapshot(), { paused: true, complete: false, failed: false, tlsVerified: true, requestClosed: false, responseIncomplete: true });
    assert.equal(f.requests, 1); f.release();
    // The origin can finish while the receiving response remains held.
    assert.equal(h.snapshot().complete, false);
    const r = await h.resume(); assert.deepEqual(r, { ok: true, complete: true, certificateMatched: true, protocol: 'TLSv1.3', body: expected });
    assert.deepEqual(h.snapshot(), { paused: false, complete: true, failed: false, tlsVerified: true, requestClosed: true, responseIncomplete: false });
    assert.equal(await h.cancel(), true); assert.equal(f.requests, 1);
  }, { splitPrefix });
});
test('expected body, CA and leaf are copied before caller mutation', async () => {
  await fixture(async f => {
    const o = opts({ expectedBody: Buffer.from(expected), ca: Buffer.from(pki.ca), expectedCertificate: Buffer.from(pki.expectedCertificate) });
    const promise = createPausedTLSClient(f.port, route, o); o.expectedBody.fill(1); o.ca.fill(1); o.expectedCertificate.fill(1);
    const h = await promise; f.release(); assert.deepEqual((await h.resume()).body, expected);
  });
});
for (const [name, config, code] of [
  ['wrong status', { status: 503 }, 'slow_client_response'],
  ['bad prefix', { badPrefix: true }, 'slow_client_payload'],
  ['early full response', { earlyFull: true }, 'slow_client_early_end'],
  ['early short response', { earlyShort: true }, 'slow_client_early_end'],
  ['no response', { noData: true }, 'slow_client_timeout'],
]) test(`refuses ${name} without a held success`, async () => {
  await fixture(async f => { await assert.rejects(createPausedTLSClient(f.port, route, opts({ timeoutMs: 150 })), { code }); }, config);
});
test('wrong CA and hostname cannot acquire a held client', async () => {
  await fixture(async f => {
    await assert.rejects(createPausedTLSClient(f.port, route, opts({ ca: pki.wrongCA })), { code: 'slow_client_ca_refused' });
    await assert.rejects(createPausedTLSClient(f.port, route, opts({ servername: 'wrong.invalid' })), { code: 'slow_client_hostname_refused' });
    assert.equal(f.requests, 0);
  });
});
test('different expected leaf cannot borrow a valid TLS authorization', async () => {
  await fixture(async f => {
    const leaf = Buffer.from(pki.expectedCertificate); leaf[leaf.length - 1] ^= 1;
    await assert.rejects(createPausedTLSClient(f.port, route, opts({ expectedCertificate: leaf })), { code: 'slow_client_identity' });
  });
});
test('TLS1.2-only peer cannot acquire TLS1.3 hold', async () => {
  await fixture(async f => { await assert.rejects(createPausedTLSClient(f.port, route, opts()), { code: 'slow_client_failed' }); }, { tls12: true });
});
test('paused cancellation awaits physical closure and cannot resume late', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts()); assert.equal(await h.cancel(), true);
    assert.equal(h.snapshot().failed, true); assert.equal(h.snapshot().complete, false);
    await assert.rejects(h.resume(), { code: 'slow_client_state' }); f.release();
    assert.equal(await h.cancel(), true); assert.equal(h.snapshot().complete, false);
  });
});
test('abort while paused closes own request and permanently revokes completion', async () => {
  await fixture(async f => {
    const a = new AbortController(), h = await createPausedTLSClient(f.port, route, opts({ signal: a.signal }));
    a.abort(); assert.equal(await h.cancel(), true); await assert.rejects(h.resume(), { code: 'slow_client_state' });
    assert.equal(h.snapshot().complete, false);
  });
});
test('overall timeout includes held duration and late response cannot revive it', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts({ timeoutMs: 100 }));
    await new Promise(r => setTimeout(r, 150)); assert.equal(h.snapshot().failed, true);
    f.release(); await assert.rejects(h.resume(), { code: 'slow_client_state' }); assert.equal(await h.cancel(), true);
  });
});
test('already aborted signal refuses before any request', async () => {
  await fixture(async f => {
    const a = new AbortController(); a.abort();
    await assert.rejects(createPausedTLSClient(f.port, route, opts({ signal: a.signal })), { code: 'slow_client_cancelled' }); assert.equal(f.requests, 0);
  });
});
test('resume is one shot and successful payload still requires actual end and socket close', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts()), completion = h.resume();
    await assert.rejects(h.resume(), { code: 'slow_client_state' }); assert.equal(h.snapshot().complete, false);
    f.release(); await completion; await assert.rejects(h.resume(), { code: 'slow_client_state' });
  });
});
test('cancellation of a resumed pending read rejects its existing completion', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts()), completion = h.resume();
    const rejected = assert.rejects(completion, { code: 'slow_client_cancelled' });
    assert.equal(await h.cancel(), true); await rejected; f.release(); assert.equal(h.snapshot().complete, false);
  });
});
for (const [name, body, config, code] of [
  ['corrupt remainder', Buffer.alloc(65537 - 4096, 0x61), {}, 'slow_client_payload'],
  ['truncated remainder', Buffer.alloc(20, 0x62), {}, 'slow_client_early_end'],
  ['overflow remainder', Buffer.alloc(65537 - 4096 + 1, 0x62), { length: 65538 }, 'slow_client_overflow'],
]) test(`resumed client refuses ${name}`, async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts()), completion = h.resume();
    const rejected = assert.rejects(completion, { code }); f.release(body); await rejected; assert.equal(await h.cancel(), true);
  }, config);
});
test('peer destruction during resumed read refuses early EOF', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts()), completion = h.resume();
    const rejected = assert.rejects(completion, e => ['slow_client_early_end', 'slow_client_failed'].includes(e.code));
    f.truncate(); await rejected; assert.equal(await h.cancel(), true);
  });
});
test('unrelated absent loopback port is a failure rather than a TLS refusal proof', async () => {
  const s = net.createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const port = s.address().port;
  await new Promise(r => s.close(r)); await assert.rejects(createPausedTLSClient(port, route, opts()), { code: 'slow_client_failed' });
});
test('unknown options, accessors and malformed inputs refuse before network authority', async () => {
  let reads = 0; const o = opts(); Object.defineProperty(o, 'servername', { get() { reads++; return 'localhost'; } });
  await assert.rejects(createPausedTLSClient(4444, route, o), { code: 'slow_client_invalid' }); assert.equal(reads, 0);
  for (const extra of [{ rejectUnauthorized: false }, { version: 'TLSv1.2' }, { prefixBytes: 65537 }, { prefixBytes: 0 },
    { expectedBody: Buffer.alloc(1048577) }, { timeoutMs: 8001 }, { timeoutMs: '50' }, { ca: Buffer.from('invalid') }, { signal: {} }])
    await assert.rejects(createPausedTLSClient(4444, route, opts(extra)), { code: 'slow_client_invalid' });
  for (const bad of ['/', '/slow-stream', '/slow-stream/' + 'A'.repeat(32), route + '?x', route + '\n'])
    await assert.rejects(createPausedTLSClient(4444, bad, opts()), { code: 'slow_client_invalid' });
  for (const port of [0, 80, 65536, '4444', NaN]) await assert.rejects(createPausedTLSClient(port, route, opts()), { code: 'slow_client_invalid' });
});

test('expired hold cannot resume when the timer callback was delayed by the event loop', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts({ timeoutMs: 100 }));
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 130);
    // No timer callback has run since the synchronous pause, so the action
    // itself must consult the monotonic deadline and revoke continuation.
    await assert.rejects(h.resume(), { code: 'slow_client_state' });
    assert.equal(h.snapshot().failed, true); assert.equal(h.snapshot().complete, false);
    assert.equal(await h.cancel(), true); f.release();
  });
});
test('snapshot revokes an expired hold before a delayed timer callback', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts({ timeoutMs: 100 }));
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 130);
    const s = h.snapshot(); assert.equal(s.paused, false); assert.equal(s.failed, true); assert.equal(s.complete, false);
    assert.equal(await h.cancel(), true);
  });
});
test('capability methods refuse extra arguments without changing a valid hold', async () => {
  await fixture(async f => {
    const h = await createPausedTLSClient(f.port, route, opts());
    assert.throws(() => h.snapshot('unexpected'), { code: 'slow_client_invalid' });
    await assert.rejects(h.resume('unexpected'), { code: 'slow_client_invalid' });
    await assert.rejects(h.cancel('unexpected'), { code: 'slow_client_invalid' });
    assert.equal(h.snapshot().paused, true); f.release(); assert.deepEqual((await h.resume()).body, expected);
  });
});
