import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, lstat, readFile, readdir, rm, realpath } from 'node:fs/promises';
import { once, EventEmitter } from 'node:events';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createServicePKI, probeServiceTLS, expectServiceTLSRefusal, TLS_FIXTURE_ERROR_CODES } from './tls-fixture.mjs';

let parent, pki, server, port, posts = 0;
const sockets = new Set(), body = Buffer.from('service-fixture\n');
const options = extra => ({ ca: pki.ca, expectedCertificate: pki.expectedCertificate, ...extra });
before(async () => {
  parent = await mkdtemp(path.join(os.tmpdir(), 'x10-service-pki-')); await chmod(parent, 0o700);
  pki = await createServicePKI(parent);
  const key = await readFile(pki.certificateKey), cert = await readFile(pki.certificate);
  try {
    server = https.createServer({ key, cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' }, (req, res) => {
      if (req.url === '/echo') { posts++; const chunks = []; let size = 0;
        req.on('data', b => { size += b.length; if (size > 256 * 1024) req.destroy(); else chunks.push(b); });
        req.once('end', () => res.end(Buffer.concat(chunks))); return; }
      if (req.url === '/stream') { res.write(Buffer.alloc(32768, 0x62)); res.end(Buffer.alloc(32769, 0x62)); return; }
      res.end(body);
    });
  } finally { key.fill(0); }
  server.on('tlsClientError', () => {}); server.on('connection', s => { sockets.add(s); s.once('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); port = server.address().port;
});
after(async () => {
  for (const s of sockets) s.destroy();
  if (server?.listening) await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('owned TLS close timeout')), 3000);
    server.close(e => { clearTimeout(timer); e ? reject(e) : resolve(); });
  });
  assert.equal(sockets.size, 0);
  if (parent) await rm(parent, { recursive: true });
});

test('private PKI publishes only four assets without signing keys or staging leftovers', async () => {
  assert.equal(await realpath(pki.directory), pki.directory);
  assert.deepEqual((await readdir(pki.directory)).sort(), ['ca.crt', 'server.crt', 'server.key', 'wrong-ca.crt']);
  assert.equal((await lstat(pki.directory)).mode & 0o7777, 0o700);
  for (const name of await readdir(pki.directory)) {
    const s = await lstat(path.join(pki.directory, name));
    assert.equal(s.uid, process.getuid()); assert.equal(s.mode & 0o7777, 0o600); assert.equal(s.nlink, 1);
  }
  assert(new X509Certificate(await readFile(pki.certificate)).raw.equals(pki.expectedCertificate));
});
test('PKI collision preserves the existing assets and refuses overwrite', async () => {
  const before = await lstat(pki.certificateKey);
  await assert.rejects(createServicePKI(parent), { code: 'pki_collision' });
  const after = await lstat(pki.certificateKey);
  assert.equal(before.ino, after.ino); assert.equal(before.size, after.size); assert.equal(before.mtimeMs, after.mtimeMs);
});
test('unsafe parent arguments refuse before tool invocation', async () => {
  for (const p of ['relative', '/', parent + '/..', parent + '/missing', parent + '\n'])
    await assert.rejects(createServicePKI(p));
});
for (const version of ['TLSv1.2', 'TLSv1.3']) {
  test(`strict ${version} probe authenticates CA, hostname, exact leaf and body`, async () => {
    const r = await probeServiceTLS(port, '/', options({ version }));
    assert.equal(r.status, 200); assert.deepEqual(r.body, body);
    assert.equal(r.protocol, version); assert.equal(r.certificateMatched, true);
    assert.deepEqual(Object.keys(r).sort(), ['body', 'certificateMatched', 'protocol', 'status']);
  });
}
test('strict probe preserves exact POST and streamed bytes without replay', async () => {
  const payload = Buffer.alloc(65551); for (let i = 0; i < payload.length; i++) payload[i] = (i * 37) & 255;
  const echo = await probeServiceTLS(port, '/echo', options({ method: 'POST', body: payload, version: 'TLSv1.3' }));
  assert.equal(echo.status, 200); assert.deepEqual(echo.body, payload); assert.equal(posts, 1);
  const stream = await probeServiceTLS(port, '/stream', options({ version: 'TLSv1.3' }));
  assert.equal(stream.status, 200); assert.deepEqual(stream.body, Buffer.alloc(65537, 0x62)); assert.equal(posts, 1);
});
test('wrong CA and hostname count only specific TLS authorization refusals', async () => {
  assert.deepEqual(await expectServiceTLSRefusal(port, options({ ca: pki.wrongCA })), { ok: true, code: 'tls_ca_refused' });
  assert.deepEqual(await expectServiceTLSRefusal(port, options({ servername: 'wrong.invalid' })), { ok: true, code: 'tls_hostname_refused' });
  assert.equal(posts, 1);
});
test('successful trust cannot be relabeled as a negative control', async () => {
  await assert.rejects(expectServiceTLSRefusal(port, options()), { code: 'tls_refusal_missing' });
});
test('different expected leaf cannot borrow an otherwise valid certificate', async () => {
  const altered = Buffer.from(pki.expectedCertificate); altered[altered.length - 1] ^= 1;
  assert.equal(new X509Certificate(altered).ca, false);
  await assert.rejects(probeServiceTLS(port, '/', options({ expectedCertificate: altered })), { code: 'tls_probe_identity' });
});
test('an unrelated refused port is not a passing bad-CA control', async () => {
  const reserve = net.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const absentPort = reserve.address().port; await new Promise(r => reserve.close(r));
  await assert.rejects(expectServiceTLSRefusal(absentPort, options({ ca: pki.wrongCA })), { code: 'tls_refusal_unexpected' });
});
test('unknown options and accessors cannot override TLS verification', async () => {
  await assert.rejects(probeServiceTLS(port, '/', options({ rejectUnauthorized: false })), { code: 'tls_probe_invalid' });
  let calls = 0; const v = options(); Object.defineProperty(v, 'servername', { get() { calls++; return 'localhost'; } });
  await assert.rejects(probeServiceTLS(port, '/', v), { code: 'tls_probe_invalid' }); assert.equal(calls, 0);
  for (const extra of [{ version: 'TLSv1' }, { body: Buffer.alloc(262145), method: 'POST' }, { ca: Buffer.from('invalid') }])
    await assert.rejects(probeServiceTLS(port, '/', options(extra)), { code: 'tls_probe_invalid' });
});
test('failure enum is fixed and contains no raw TLS or path messages', () => {
  assert(Object.isFrozen(TLS_FIXTURE_ERROR_CODES)); assert.equal(new Set(TLS_FIXTURE_ERROR_CODES).size, TLS_FIXTURE_ERROR_CODES.length);
  assert(TLS_FIXTURE_ERROR_CODES.every(c => /^(?:tls_|pki_)[a-z_]+$/.test(c)));
});

function fakeRequest(t, onEnd) {
  let responseCallback, destroyed = false, closeCount = 0;
  const req = new EventEmitter();
  req.setTimeout = (ms, fn) => { assert.equal(ms, 2500); req.timeout = fn; };
  req.destroy = () => { destroyed = true; closeCount++; req.emit('close'); };
  req.end = () => onEnd(req, () => responseCallback);
  t.mock.method(https, 'request', (_options, callback) => { responseCallback = callback; return req; });
  return { req, callback: () => responseCallback, counts: () => ({ destroyed, closeCount }), response() {
    const res = new EventEmitter(); res.socket = { authorized: true, getProtocol: () => 'TLSv1.3', getPeerCertificate: () => ({ raw: pki.expectedCertificate }) };
    res.statusCode = 200; res.complete = true; res.destroy = () => {}; return res;
  } };
}
test('timeout closes the owned request and a later valid response cannot regain success', async t => {
  const f = fakeRequest(t, () => {}), promise = probeServiceTLS(port, '/', options());
  const refused = assert.rejects(promise, { code: 'tls_probe_timeout' });
  f.req.timeout(); await refused;
  assert.equal(f.counts().destroyed, true);
  const late = f.response(); f.callback()(late);
  // A response arriving after close has no remaining promise authority.
  late.emit('data', body); late.emit('end'); f.req.emit('close'); f.req.timeout();
  assert.equal(f.counts().closeCount, 1);
});
test('close without a complete response cannot later become a successful observation', async t => {
  let callback; const f = fakeRequest(t, (_req, get) => { callback = get(); });
  const promise = probeServiceTLS(port, '/', options()); const refused = assert.rejects(promise, { code: 'tls_probe_failed' });
  f.req.emit('close'); await refused;
  const late = f.response(); callback(late); late.emit('data', body); late.emit('end'); f.req.emit('close');
});
test('response overflow destroys the owned request and cannot count as trust refusal', async t => {
  let callback; const f = fakeRequest(t, (_req, get) => { callback = get(); });
  const promise = probeServiceTLS(port, '/', options()); const refused = assert.rejects(promise, { code: 'tls_probe_output_limit' });
  const res = f.response(); callback(res); res.emit('data', Buffer.alloc(1024 * 1024 + 1)); await refused;
  assert.equal(f.counts().destroyed, true);
});

test('partial PKI command failure preserves unknown staged files rather than deleting them', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'x10-pki-failure-')); await chmod(root, 0o700);
  try {
    const source = await readFile(new URL('./tls-fixture.mjs', import.meta.url), 'utf8');
    const code = source.slice(source.indexOf('export async function createServicePKI(parent) {'), source.indexOf('\nfunction requestInput(')).replace('export ', '');
    const fail = value => { throw Object.assign(new Error(value), { code: value }); };
    const directory = async file => { const s = await lstat(file);
      assert.equal(s.isDirectory(), true); assert.equal(s.uid, process.getuid()); assert.equal(s.mode & 0o7777, 0o700);
      assert.equal(await realpath(file), file); return { dev: s.dev, ino: s.ino, uid: s.uid }; };
    const dependencies = { process, path, constants, directory, tool: async () => {}, mkdir: fs.mkdir, open: fs.open,
      openssl: async (_args, cwd) => { await fs.writeFile(path.join(cwd, 'unknown-fixture-file'), 'fixed synthetic fixture data', { mode: 0o600, flag: 'wx' }); fail('pki_failed'); },
      fail, allowed: new Set(TLS_FIXTURE_ERROR_CODES) };
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const create = await new AsyncFunction(...Object.keys(dependencies), code + '\nreturn createServicePKI;')(...Object.values(dependencies));
    await assert.rejects(create(root), { code: 'pki_failed' });
    assert.equal((await fs.readFile(path.join(root, 'pki/staging/unknown-fixture-file'), 'utf8')), 'fixed synthetic fixture data');
    assert.equal((await lstat(path.join(root, 'pki'))).mode & 0o7777, 0o700);
    assert.equal((await lstat(path.join(root, 'pki/staging'))).mode & 0o7777, 0o700);
  } finally { await rm(root, { recursive: true }); }
});
