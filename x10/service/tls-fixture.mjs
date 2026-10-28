// Private, ephemeral test PKI and strict loopback TLS probes. No CLI or logging.
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { chmod, link, lstat, mkdir, open, readdir, realpath, rmdir, unlink } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import https from 'node:https';
import path from 'node:path';

export const TLS_FIXTURE_ERROR_CODES = Object.freeze(['tls_fixture_invalid', 'pki_tool_unavailable',
  'pki_collision', 'pki_failed', 'pki_cleanup_unconfirmed', 'tls_probe_invalid', 'tls_probe_failed',
  'tls_probe_timeout', 'tls_probe_output_limit', 'tls_probe_identity', 'tls_probe_protocol',
  'tls_probe_response_invalid', 'tls_ca_refused', 'tls_hostname_refused',
  'tls_refusal_missing', 'tls_refusal_unexpected']);
const TOOL = '/usr/bin/openssl', MAX_CERT = 65536, MAX_RESPONSE = 1024 * 1024;
const allowed = new Set(TLS_FIXTURE_ERROR_CODES);
const caErrors = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT']);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const id = s => ({ dev: s.dev, ino: s.ino, uid: s.uid });
const same = (a, b) => a && b && a.dev === b.dev && a.ino === b.ino && a.uid === b.uid;
async function directory(value, expected) {
  const s = await lstat(value);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700
      || await realpath(value) !== value || (expected && !same(expected, id(s)))) fail('tls_fixture_invalid');
  return id(s);
}
async function tool() {
  for (const p of ['/', '/usr', '/usr/bin']) {
    const s = await lstat(p);
    if (!s.isDirectory() || s.uid !== 0 || (s.mode & 0o7022) !== 0 || await realpath(p) !== p) fail('pki_tool_unavailable');
  }
  const s = await lstat(TOOL);
  if (!s.isFile() || s.uid !== 0 || (s.mode & 0o7022) !== 0 || !(s.mode & 0o111)
      || await realpath(TOOL) !== TOOL) fail('pki_tool_unavailable');
}
async function regular(file, max, read = true, links = 1) {
  if (await realpath(file) !== file) fail('pki_failed');
  const h = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await h.stat();
    if (!s.isFile() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o600
        || s.nlink !== links || s.size < 1 || s.size > max) fail('pki_failed');
    if (!read) return null;
    const buffer = Buffer.alloc(s.size + 1); let used = 0;
    while (used < buffer.length) { const part = await h.read(buffer, used, buffer.length - used, null);
      if (!part.bytesRead) break; used += part.bytesRead; }
    const after = await h.stat();
    if (used !== s.size || after.size !== s.size || after.mtimeMs !== s.mtimeMs
        || after.ctimeMs !== s.ctimeMs || !same(id(s), id(after))) fail('pki_failed');
    return buffer.subarray(0, used);
  } finally { await h.close(); }
}
function openssl(args, cwd) {
  return new Promise((resolve, reject) => execFile(TOOL, args, { cwd, timeout: 15000,
    maxBuffer: 65536, killSignal: 'SIGKILL', encoding: 'buffer',
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' } },
  (error, stdout, stderr) => {
    stdout?.fill(0); stderr?.fill(0);
    if (error) reject(Object.assign(new Error('pki_failed'), { code: 'pki_failed' })); else resolve();
  }));
}

// Final files are linked without overwrites out of a new private staging area.
// On partial/unknown failure preserve the private directory for caller cleanup;
// there is no claim of atomic publication of the entire set or same-UID fencing.
export async function createServicePKI(parent) {
  try {
    if (process.platform !== 'linux' || typeof process.getuid !== 'function'
        || typeof parent !== 'string' || parent.length > 1024 || !/^\/[A-Za-z0-9_./+-]+$/.test(parent)
        || path.posix.normalize(parent) !== parent || parent === '/') fail('tls_fixture_invalid');
    const parentId = await directory(parent); await tool();
    const pki = path.join(parent, 'pki');
    try { await mkdir(pki, { mode: 0o700 }); } catch (e) { if (e.code === 'EEXIST') fail('pki_collision'); throw e; }
    const pkiId = await directory(pki), stage = path.join(pki, 'staging');
    await mkdir(stage, { mode: 0o700 }); const stageId = await directory(stage);
    const extension = path.join(stage, 'extensions.cnf');
    const ext = await open(extension, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await ext.writeFile('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'); await ext.sync(); } finally { await ext.close(); }
    const call = async args => { await directory(parent, parentId); await directory(pki, pkiId); await directory(stage, stageId); await tool(); await openssl(args, stage); };
    await call(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=X10 Service Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', 'ca.key', '-out', 'ca.crt']);
    await call(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.csr']);
    await call(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-set_serial', '2', '-days', '1', '-sha256', '-extfile', 'extensions.cnf', '-out', 'server.crt']);
    await call(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=Other Service Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', 'wrong-ca.key', '-out', 'wrong-ca.crt']);
    const names = ['ca.key', 'ca.crt', 'server.key', 'server.csr', 'server.crt', 'extensions.cnf', 'wrong-ca.key', 'wrong-ca.crt'];
    if (JSON.stringify((await readdir(stage)).sort()) !== JSON.stringify([...names].sort())) fail('pki_cleanup_unconfirmed');
    for (const name of names) { const file = path.join(stage, name), s = await lstat(file);
      if (!s.isFile() || s.uid !== process.getuid() || s.nlink !== 1 || await realpath(file) !== file) fail('pki_failed');
      await chmod(file, 0o600); await regular(file, MAX_CERT, false); }
    const ca = await regular(path.join(stage, 'ca.crt'), MAX_CERT), cert = await regular(path.join(stage, 'server.crt'), MAX_CERT);
    const wrongCA = await regular(path.join(stage, 'wrong-ca.crt'), MAX_CERT);
    const issuer = new X509Certificate(ca), leaf = new X509Certificate(cert), wrong = new X509Certificate(wrongCA);
    if (!issuer.ca || !wrong.ca || leaf.ca || leaf.checkHost('localhost') !== 'localhost'
        || !leaf.verify(issuer.publicKey) || leaf.verify(wrong.publicKey)) fail('pki_failed');
    for (const name of ['ca.crt', 'server.crt', 'server.key', 'wrong-ca.crt']) await link(path.join(stage, name), path.join(pki, name));
    await directory(stage, stageId);
    if (JSON.stringify((await readdir(stage)).sort()) !== JSON.stringify([...names].sort())) fail('pki_cleanup_unconfirmed');
    for (const name of names) { await regular(path.join(stage, name), MAX_CERT, false, ['ca.crt', 'server.crt', 'server.key', 'wrong-ca.crt'].includes(name) ? 2 : 1); await unlink(path.join(stage, name)); }
    await rmdir(stage); await directory(parent, parentId); await directory(pki, pkiId);
    const final = ['ca.crt', 'server.crt', 'server.key', 'wrong-ca.crt'];
    if (JSON.stringify((await readdir(pki)).sort()) !== JSON.stringify([...final].sort())) fail('pki_cleanup_unconfirmed');
    for (const name of final) await regular(path.join(pki, name), MAX_CERT, false);
    return { directory: pki, ca, wrongCA, certificate: path.join(pki, 'server.crt'),
      certificateKey: path.join(pki, 'server.key'), expectedCertificate: Buffer.from(leaf.raw) };
  } catch (error) {
    const d = error && Object.getOwnPropertyDescriptor(error, 'code');
    fail(d && Object.hasOwn(d, 'value') && allowed.has(d.value) ? d.value : 'pki_failed');
  }
}

function requestInput(port, route, value) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !['/', '/echo', '/stream'].includes(route)
      || !value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('tls_probe_invalid');
  const names = ['ca', 'expectedCertificate', 'servername', 'version', 'method', 'body'], copy = Object.create(null);
  for (const key of Reflect.ownKeys(value)) { const d = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !names.includes(key) || !d || !Object.hasOwn(d, 'value')) fail('tls_probe_invalid'); copy[key] = d.value; }
  const { ca, expectedCertificate, servername = 'localhost', version, method = 'GET', body = Buffer.alloc(0) } = copy;
  if (!Buffer.isBuffer(ca) || ca.length < 1 || ca.length > MAX_CERT || !Buffer.isBuffer(expectedCertificate)
      || expectedCertificate.length < 1 || expectedCertificate.length > MAX_CERT
      || !['localhost', 'wrong.invalid'].includes(servername) || (version !== undefined && !['TLSv1.2', 'TLSv1.3'].includes(version))
      || !['GET', 'POST'].includes(method) || !Buffer.isBuffer(body) || body.length > 256 * 1024
      || (method === 'POST' ? route !== '/echo' : body.length !== 0)) fail('tls_probe_invalid');
  try { if (!new X509Certificate(ca).ca || new X509Certificate(expectedCertificate).ca) fail('tls_probe_invalid'); }
  catch { fail('tls_probe_invalid'); }
  return { ca: Buffer.from(ca), expectedCertificate: Buffer.from(expectedCertificate), servername,
    version, method, body: Buffer.from(body) };
}
const classify = e => e?.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ? 'tls_hostname_refused'
  : caErrors.has(e?.code) ? 'tls_ca_refused' : 'tls_probe_failed';

export async function probeServiceTLS(port, route = '/', options = {}) {
  let v;
  try { v = requestInput(port, route, options); } catch { fail('tls_probe_invalid'); }
  return new Promise((resolve, reject) => {
    let req, result, failure, settled = false;
    const remember = code => { if (!failure) failure = code; };
    const finish = () => { if (settled) return; settled = true; clearTimeout(timer);
      if (failure || !result) reject(Object.assign(new Error(failure || 'tls_probe_failed'), { code: failure || 'tls_probe_failed' })); else resolve(result); };
    const timer = setTimeout(() => { if (settled) return; remember('tls_probe_timeout'); req?.destroy(); }, 2500);
    try {
      req = https.request({ host: '127.0.0.1', port, path: route, method: v.method, agent: false,
        ca: v.ca, servername: v.servername, rejectUnauthorized: true,
        minVersion: v.version || 'TLSv1.2', maxVersion: v.version || 'TLSv1.3',
        headers: { 'content-length': v.body.length, connection: 'close' } }, res => {
        res.once('error', () => { if (settled) return; remember('tls_probe_failed'); req.destroy(); });
        if (settled) { res.destroy(); return; }
        const socket = res.socket, protocol = socket.getProtocol(), peer = socket.getPeerCertificate();
        if (socket.authorized !== true || !Buffer.isBuffer(peer?.raw) || !peer.raw.equals(v.expectedCertificate)) remember('tls_probe_identity');
        if (!['TLSv1.2', 'TLSv1.3'].includes(protocol) || (v.version && protocol !== v.version)) remember('tls_probe_protocol');
        if (!Number.isInteger(res.statusCode) || res.statusCode < 100 || res.statusCode > 599) remember('tls_probe_response_invalid');
        if (failure) { res.destroy(); req.destroy(); return; }
        const chunks = []; let size = 0;
        res.on('data', b => { if (settled) return; size += b.length; if (size > MAX_RESPONSE) { remember('tls_probe_output_limit'); res.destroy(); req.destroy(); } else chunks.push(b); });
        res.once('end', () => { if (settled) return; if (!res.complete) remember('tls_probe_response_invalid');
          if (!failure) result = { status: res.statusCode, body: Buffer.concat(chunks), protocol, certificateMatched: true }; });
      });
      req.setTimeout(2500, () => { if (settled) return; remember('tls_probe_timeout'); req.destroy(); });
      req.once('error', e => { if (!settled) remember(classify(e)); });
      req.once('close', finish); req.end(v.body);
    } catch { remember('tls_probe_failed'); req?.destroy(); if (!req) finish(); }
  });
}

export async function expectServiceTLSRefusal(port, options) {
  let v;
  try { v = requestInput(port, '/', options); } catch { fail('tls_probe_invalid'); }
  const expected = v.servername === 'wrong.invalid' ? 'tls_hostname_refused' : 'tls_ca_refused';
  try { await probeServiceTLS(port, '/', v); }
  catch (error) {
    if (error?.code === expected) return { ok: true, code: expected };
    fail('tls_refusal_unexpected');
  }
  fail('tls_refusal_missing');
}
