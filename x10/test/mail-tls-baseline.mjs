#!/usr/bin/env node
// Native mail TLS compatibility: synthetic loopback clients, auth and backends.
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const root = fileURLToPath(new URL('../../', import.meta.url));
const args = process.argv.slice(2);
let binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--binary' && args[i + 1]) binary = path.resolve(args[++i]);
  else throw new Error('Usage: node x10/test/mail-tls-baseline.mjs [--binary FILE]');
}
const execute = promisify(execFile);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const timeoutMs = 3000;
const protocols = ['smtp', 'imap', 'pop3'];
const login = 'tls-fixture-user', password = 'synthetic-pass';
const plain = Buffer.from(`\0${login}\0${password}`).toString('base64');
const sockets = new Set(), fixtures = [], fixtureErrors = [], authCalls = [], tests = [];
const backendConnections = { smtp: 0, imap: 0, pop3: 0 };
const backendHandshakes = { smtp: 0, imap: 0, pop3: 0 };
const sourceFiles = ['src/mail/ngx_mail_handler.c', 'src/mail/ngx_mail_ssl_module.c',
  ...protocols.map(protocol => `src/mail/ngx_mail_${protocol}_handler.c`),
  'src/mail/ngx_mail_auth_http_module.c', 'src/mail/ngx_mail_proxy_module.c'];
let prefix, nginx, nginxExit, nginxStopped = true, nginxResult, nginxLog = '', interrupted;
let stopping = false;
const commandChildren = new Set();

function bounded(promise, ms, label) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
  })]).finally(() => clearTimeout(timer));
}
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function track(socket) {
  sockets.add(socket);
  socket.on('error', () => {});
  socket.once('close', () => sockets.delete(socket));
  return socket;
}

class Peer {
  constructor(socket) {
    this.socket = track(socket);
    this.buffer = Buffer.alloc(0);
    this.failure = null;
    this.closed = false;
    this.wake = null;
    this.listeners = {
      data: chunk => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        if (this.buffer.length > 64 * 1024) {
          this.failure = new Error('Protocol response exceeded 64 KiB');
          socket.destroy();
        }
        this.wake?.();
      },
      error: error => { this.failure = error; this.wake?.(); },
      close: () => { this.closed = true; this.wake?.(); },
    };
    for (const [event, listener] of Object.entries(this.listeners)) socket.on(event, listener);
  }
  async line() {
    const read = async () => {
      for (;;) {
        const end = this.buffer.indexOf('\r\n');
        if (end >= 0) {
          const line = this.buffer.subarray(0, end + 2).toString('utf8');
          this.buffer = this.buffer.subarray(end + 2);
          return line;
        }
        if (this.failure) throw this.failure;
        if (this.closed) throw new Error('Connection closed before protocol line');
        await new Promise(resolve => { this.wake = resolve; });
      }
    };
    try { return await bounded(read(), timeoutMs, 'Protocol line'); }
    finally { this.wake = null; }
  }
  detach() {
    assert.equal(this.buffer.length, 0, 'Unexpected bytes before TLS upgrade');
    assert.equal(this.wake, null, 'No pending plaintext read at TLS upgrade');
    for (const [event, listener] of Object.entries(this.listeners)) this.socket.off(event, listener);
    return this.socket;
  }
  send(value) { this.socket.write(value); }
  close() { this.socket.destroy(); }
}

async function ready(socket, event, label) {
  return bounded(new Promise((resolve, reject) => {
    const success = () => { socket.off('error', failure); resolve(); };
    const failure = error => { socket.off(event, success); reject(error); };
    socket.once(event, success);
    socket.once('error', failure);
  }), timeoutMs, label);
}

async function connect(port) {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  const peer = new Peer(socket);
  try { await ready(socket, 'connect', 'Loopback connect'); return peer; }
  catch (error) { peer.close(); throw error; }
}

async function secure({ port, peer, ca, servername = 'localhost' }) {
  const socket = tls.connect({ ...(peer ? { socket: peer.detach() } : { host: '127.0.0.1', port }),
    ca, servername, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
  const secured = new Peer(socket);
  try {
    await ready(socket, 'secureConnect', 'Verified TLS handshake');
    assert.equal(socket.authorized, true);
    assert.match(socket.getProtocol(), /^TLSv1\.[23]$/);
    return secured;
  } catch (error) { secured.close(); throw error; }
}

async function listen(server) {
  fixtures.push(server);
  await new Promise((resolve, reject) => {
    const failure = error => { server.off('listening', success); reject(error); };
    const success = () => { server.off('error', failure); resolve(); };
    server.once('error', failure); server.once('listening', success);
    server.listen(0, '127.0.0.1');
  });
  server.on('error', error => fixtureErrors.push(error.message));
  return server.address().port;
}

async function unusedPort(reserved) {
  for (;;) {
    const server = net.createServer();
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const port = server.address().port;
    await new Promise(resolve => server.close(resolve));
    if (!reserved.has(port)) { reserved.add(port); return port; }
  }
}

async function smtp(peer, code) {
  const lines = [];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line();
    assert.match(line, new RegExp(`^${code}[ -]`));
    lines.push(line);
    if (line.startsWith(`${code} `)) return lines.join('');
  }
  throw new Error('SMTP response exceeded 40 lines');
}

async function imap(peer, tag, status = 'OK') {
  const lines = [];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line(); lines.push(line);
    if (line.startsWith(`${tag} `)) {
      assert.match(line, new RegExp(`^${tag} ${status}(?: |\r\n)`));
      return lines.join('');
    }
  }
  throw new Error('IMAP response exceeded 40 lines');
}

async function pop3(peer) {
  const first = await peer.line(); assert.match(first, /^\+OK(?: |\r\n)/);
  const lines = [first];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line(); lines.push(line);
    if (line === '.\r\n') return lines.join('');
  }
  throw new Error('POP3 response exceeded 40 lines');
}

async function greeting(peer, protocol) {
  if (protocol === 'smtp') await smtp(peer, 220);
  else assert.match(await peer.line(), protocol === 'imap' ? /^\* OK / : /^\+OK /);
}

async function capabilities(peer, protocol, tag, hello = 'post-upgrade.test') {
  if (protocol === 'smtp') { peer.send(`EHLO ${hello}\r\n`); return smtp(peer, 250); }
  if (protocol === 'imap') { peer.send(`${tag} CAPABILITY\r\n`); return imap(peer, tag); }
  peer.send('CAPA\r\n'); return pop3(peer);
}

function assertCapabilities(value, protocol, encrypted) {
  if (protocol === 'smtp') {
    assert.match(value, /PIPELINING/);
    if (encrypted) { assert.doesNotMatch(value, /STARTTLS/); assert.match(value, /AUTH.*PLAIN/); }
    else { assert.match(value, /STARTTLS/); assert.doesNotMatch(value, /AUTH/); }
  } else if (protocol === 'imap') {
    assert.match(value, /IMAP4rev1/);
    if (encrypted) { assert.doesNotMatch(value, /STARTTLS|LOGINDISABLED/); assert.match(value, /AUTH=PLAIN/); }
    else { assert.match(value, /STARTTLS LOGINDISABLED/); assert.doesNotMatch(value, /AUTH=PLAIN/); }
  } else if (encrypted) { assert.doesNotMatch(value, /STLS/); assert.match(value, /\r\nUSER\r\n/); }
  else { assert.match(value, /\r\nSTLS\r\n/); assert.doesNotMatch(value, /\r\nUSER\r\n|SASL/); }
}

async function refusePlainAuthentication(peer, protocol) {
  const before = authCalls.length;
  if (protocol === 'smtp') { peer.send(`AUTH PLAIN ${plain}\r\n`); await smtp(peer, 500); }
  else if (protocol === 'imap') { peer.send(`a1 LOGIN ${login} ${password}\r\n`); await imap(peer, 'a1', 'BAD'); }
  else { peer.send(`USER ${login}\r\n`); assert.match(await peer.line(), /^-ERR /); }
  assert.equal(authCalls.length, before, 'Plaintext authentication must not reach auth_http');
}

async function startTLS(peer, protocol, pipeline = false) {
  const command = protocol === 'smtp' ? 'STARTTLS\r\n' : protocol === 'imap' ? 'a2 STARTTLS\r\n' : 'STLS\r\n';
  // Both commands are one plaintext write. The second must be discarded rather
  // than reinterpreted as an encrypted-session authentication command.
  const extra = protocol === 'smtp' ? `AUTH PLAIN ${plain}\r\n`
    : protocol === 'imap' ? `discard LOGIN ${login} ${password}\r\n` : `USER stale-user\r\n`;
  peer.send(command + (pipeline ? extra : ''));
  if (protocol === 'smtp') await smtp(peer, 220);
  else if (protocol === 'imap') await imap(peer, 'a2');
  else assert.match(await peer.line(), /^\+OK(?: |\r\n)/);
}

async function refuseSecondUpgrade(peer, protocol) {
  if (protocol === 'smtp') { peer.send('STARTTLS\r\n'); await smtp(peer, 500); }
  else if (protocol === 'imap') { peer.send('a3 STARTTLS\r\n'); await imap(peer, 'a3', 'BAD'); }
  else { peer.send('STLS\r\n'); assert.match(await peer.line(), /^-ERR /); }
}

async function authenticateAndTunnel(peer, protocol) {
  if (protocol === 'smtp') {
    peer.send(`AUTH PLAIN ${plain}\r\n`); await smtp(peer, 235);
    peer.send('NOOP\r\n'); assert.equal(await peer.line(), '250 2.0.0 tls-fixture noop\r\n');
    peer.send('QUIT\r\n'); assert.equal(await peer.line(), '221 2.0.0 tls-fixture bye\r\n');
  } else if (protocol === 'imap') {
    peer.send(`a4 LOGIN ${login} ${password}\r\n`); assert.equal(await peer.line(), 'a4 OK tls-fixture authenticated\r\n');
    peer.send('a5 NOOP\r\n'); assert.equal(await peer.line(), 'a5 OK tls-fixture noop\r\n');
    peer.send('a6 LOGOUT\r\n'); assert.match(await imap(peer, 'a6'), /tls-fixture logout/);
  } else {
    peer.send(`USER ${login}\r\n`); assert.match(await peer.line(), /^\+OK(?: |\r\n)/);
    peer.send(`PASS ${password}\r\n`); assert.equal(await peer.line(), '+OK tls-fixture authenticated\r\n');
    peer.send('STAT\r\n'); assert.equal(await peer.line(), '+OK 0 0\r\n');
    peer.send('QUIT\r\n'); assert.equal(await peer.line(), '+OK tls-fixture bye\r\n');
  }
}

function backend(protocol) {
  return net.createServer(socket => {
    backendConnections[protocol]++;
    const peer = new Peer(socket);
    socket.setTimeout(8000, () => socket.destroy());
    const handle = async () => {
      if (protocol === 'smtp') {
        peer.send('220 tls-fixture ESMTP ready\r\n');
        assert.equal(await peer.line(), 'EHLO mail-tls.test\r\n');
        peer.send('250-tls-fixture\r\n250 AUTH PLAIN\r\n');
        const next = await peer.line();
        if (next === `AUTH PLAIN ${plain}\r\n`) peer.send('235 2.7.0 tls-fixture accepted\r\n');
        else {
          assert.equal(next, 'MAIL FROM:<fresh@example.test>\r\n');
          peer.send('250 2.1.0 fresh sender\r\n');
          assert.equal(await peer.line(), 'RCPT TO:<fresh-recipient@example.test>\r\n');
          peer.send('250 2.1.5 fresh recipient\r\n');
        }
        backendHandshakes[protocol]++;
        assert.equal(await peer.line(), 'NOOP\r\n'); peer.send('250 2.0.0 tls-fixture noop\r\n');
        assert.equal(await peer.line(), 'QUIT\r\n'); peer.socket.end('221 2.0.0 tls-fixture bye\r\n');
      } else if (protocol === 'imap') {
        peer.send('* OK tls-fixture ready\r\n');
        assert.equal(await peer.line(), `a4 LOGIN {${login.length}}\r\n`);
        peer.send('+ username\r\n'); assert.equal(await peer.line(), `${login} {${password.length}}\r\n`);
        peer.send('+ password\r\n'); assert.equal(await peer.line(), `${password}\r\n`);
        backendHandshakes[protocol]++;
        peer.send('a4 OK tls-fixture authenticated\r\n');
        assert.equal(await peer.line(), 'a5 NOOP\r\n'); peer.send('a5 OK tls-fixture noop\r\n');
        assert.equal(await peer.line(), 'a6 LOGOUT\r\n'); peer.socket.end('* BYE tls-fixture bye\r\na6 OK tls-fixture logout\r\n');
      } else {
        peer.send('+OK tls-fixture ready\r\n');
        assert.equal(await peer.line(), `USER ${login}\r\n`); peer.send('+OK user\r\n');
        assert.equal(await peer.line(), `PASS ${password}\r\n`); backendHandshakes[protocol]++;
        peer.send('+OK tls-fixture authenticated\r\n');
        assert.equal(await peer.line(), 'STAT\r\n'); peer.send('+OK 0 0\r\n');
        assert.equal(await peer.line(), 'QUIT\r\n'); peer.socket.end('+OK tls-fixture bye\r\n');
      }
    };
    handle().catch(error => { if (!stopping) fixtureErrors.push(`${protocol} backend: ${error.message}`); peer.close(); });
  });
}

async function command(file, argv) {
  if (interrupted) throw new Error(`Interrupted by ${interrupted}`);
  const promise = execute(file, argv, { encoding: 'utf8', timeout: 10_000, maxBuffer: 512 * 1024 });
  commandChildren.add(promise.child);
  try { return await promise; }
  finally { commandChildren.delete(promise.child); }
}

async function certificates() {
  const dir = path.join(prefix, 'certs'); await mkdir(dir, { mode: 0o700 });
  const file = name => path.join(dir, name);
  for (const name of ['ca', 'untrusted']) {
    await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
      '-subj', `/CN=X10 Mail ${name}`, '-addext', 'basicConstraints=critical,CA:TRUE',
      '-keyout', file(`${name}.key`), '-out', file(`${name}.crt`)]);
    await chmod(file(`${name}.key`), 0o600);
  }
  await command('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-subj', '/CN=localhost', '-keyout', file('server.key'), '-out', file('server.csr')]);
  await writeFile(file('extensions.cnf'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  await command('openssl', ['x509', '-req', '-in', file('server.csr'), '-CA', file('ca.crt'), '-CAkey', file('ca.key'),
    '-CAcreateserial', '-out', file('server.crt'), '-days', '1', '-sha256', '-extfile', file('extensions.cnf')]);
  await chmod(file('server.key'), 0o600);
  return { ca: await readFile(file('ca.crt')), untrusted: await readFile(file('untrusted.crt')),
    certSha256: sha256(await readFile(file('server.crt'))), key: file('server.key'), certificate: file('server.crt') };
}

async function check(name, action) {
  if (interrupted) throw new Error(`Interrupted by ${interrupted}`);
  const start = Date.now();
  try { tests.push({ name, passed: true, ...(await action()), elapsedMs: Date.now() - start }); }
  catch (error) { tests.push({ name, passed: false, error: error.message, elapsedMs: Date.now() - start }); }
}

const quote = value => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
const identity = { sourceFilesSha256: {} };
let version;
async function main() {
  binary = await realpath(binary);
  identity.binary = binary;
  identity.binarySha256 = sha256(await readFile(binary));
  identity.harnessSha256 = sha256(await readFile(fileURLToPath(import.meta.url)));
  for (const file of sourceFiles) identity.sourceFilesSha256[file] = sha256(await readFile(path.join(root, file)));
  version = (await command(binary, ['-V'])).stderr.trim();
  identity.versionOutput = version;
  assert.match(version, /--with-mail(?: |$)/); assert.match(version, /--with-mail_ssl_module(?: |$)/);
  prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-mail-tls-')); await chmod(prefix, 0o700);
  await mkdir(path.join(prefix, 'logs'), { mode: 0o700 });
  const certs = await certificates();
  identity.certificates = { caSha256: sha256(certs.ca), untrustedCaSha256: sha256(certs.untrusted), serverSha256: certs.certSha256 };
  const upstreams = {};
  for (const protocol of protocols) upstreams[protocol] = await listen(backend(protocol));
  const auth = http.createServer((req, res) => {
    try {
      const protocol = req.headers['auth-protocol'];
      assert.ok(protocols.includes(protocol)); assert.equal(req.url, '/auth'); assert.equal(req.method, 'GET');
      const method = req.headers['auth-method'];
      if (method === 'none') {
        assert.equal(protocol, 'smtp');
        assert.equal(req.headers['auth-smtp-from'], 'MAIL FROM:<fresh@example.test>');
        assert.equal(req.headers['auth-smtp-to'], 'RCPT TO:<fresh-recipient@example.test>');
        assert.ok(Object.hasOwn(req.headers, 'auth-smtp-helo'), 'Auth-NONE must provide the actual HELO field');
        assert.equal(req.headers['auth-smtp-helo'], '');
      } else {
        assert.equal(method, 'plain'); assert.equal(req.headers['auth-user'], login);
        assert.equal(req.headers['auth-pass'], password);
      }
      assert.equal(req.headers['auth-ssl'], 'on');
      assert.match(req.headers['auth-ssl-protocol'], /^TLSv1\.[23]$/); assert.ok(req.headers['auth-ssl-cipher']);
      authCalls.push({ protocol, method, ssl: req.headers['auth-ssl'], tlsProtocol: req.headers['auth-ssl-protocol'],
        ...(method === 'none' ? { helo: req.headers['auth-smtp-helo'], from: req.headers['auth-smtp-from'], to: req.headers['auth-smtp-to'] } : {}) });
      res.writeHead(200, { 'Auth-Status': 'OK', 'Auth-Server': '127.0.0.1', 'Auth-Port': String(upstreams[protocol]),
        'Content-Length': '0', Connection: 'close' }); res.end();
    } catch (error) { fixtureErrors.push(`auth_http: ${error.message}`); res.writeHead(500, { Connection: 'close' }); res.end(); }
  });
  auth.on('connection', track);
  const authPort = await listen(auth);
  const ports = {}, reserved = new Set(Object.values(upstreams).concat(authPort));
  for (const protocol of protocols) {
    ports[protocol] = { upgrade: await unusedPort(reserved), implicit: await unusedPort(reserved) };
  }
  const smtpResetPort = await unusedPort(reserved);
  const authMethods = { smtp: 'smtp_auth plain login; smtp_capabilities PIPELINING;',
    imap: 'imap_auth plain; imap_capabilities IMAP4rev1;', pop3: 'pop3_auth plain; pop3_capabilities USER;' };
  const config = `${process.geteuid?.() === 0 ? `user ${quote(os.userInfo().username)};` : ''}
daemon off;
master_process off;
worker_processes 1;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log stderr info;
events { worker_connections 128; }
mail {
 server_name mail-tls.test;
 auth_http http://127.0.0.1:${authPort}/auth;
 auth_http_timeout 2s;
 timeout 5s;
 resolver off;
 proxy_timeout 5s;
 xclient off;
 proxy_smtp_auth on;
 ssl_certificate ${quote(certs.certificate)};
 ssl_certificate_key ${quote(certs.key)};
 ssl_protocols TLSv1.2 TLSv1.3;
 ${protocols.map(protocol => `server { listen 127.0.0.1:${ports[protocol].upgrade}; protocol ${protocol}; starttls only; ${authMethods[protocol]} }
 server { listen 127.0.0.1:${ports[protocol].implicit} ssl; protocol ${protocol}; ${authMethods[protocol]} }`).join('\n')}
 server { listen 127.0.0.1:${smtpResetPort}; protocol smtp; starttls on; smtp_auth none; smtp_capabilities PIPELINING; }
}
`;
  const configPath = path.join(prefix, 'nginx.conf'); await writeFile(configPath, config, { mode: 0o600 });
  await check('config.native_validation', async () => {
    await command(binary, ['-p', `${prefix}/`, '-c', configPath, '-t']);
    return { configSha256: sha256(config), mailListeners: 7 };
  });
  assert.equal(tests.at(-1).passed, true, 'Native config validation must pass');
  nginx = spawn(binary, ['-p', `${prefix}/`, '-c', configPath], { stdio: ['ignore', 'ignore', 'pipe'] });
  nginxStopped = false;
  nginx.stderr.on('data', chunk => { nginxLog = (nginxLog + chunk).slice(-128 * 1024); });
  nginxExit = new Promise(resolve => {
    nginx.once('error', error => { nginxStopped = true; fixtureErrors.push(error.message); resolve(); });
    nginx.once('exit', (code, signal) => { nginxStopped = true; nginxResult = { code, signal }; resolve(); });
  });
  const deadline = Date.now() + 4000;
  for (;;) {
    if (nginxStopped) throw new Error(`Native startup failed: ${nginxLog}`);
    let peer;
    try { peer = await connect(ports.smtp.upgrade); await greeting(peer, 'smtp'); break; }
    catch (error) { if (Date.now() >= deadline) throw error; await delay(30); }
    finally { peer?.close(); }
  }

  for (const protocol of protocols) {
    await check(`${protocol}.required_upgrade_policy_capability_pipeline_and_tunnel`, async () => {
      let peer = await connect(ports[protocol].upgrade);
      try {
        await greeting(peer, protocol);
        assertCapabilities(await capabilities(peer, protocol, 'p0', 'pre-upgrade.test'), protocol, false);
        await refusePlainAuthentication(peer, protocol);
        const before = authCalls.length;
        await startTLS(peer, protocol, true);
        peer = await secure({ peer, ca: certs.ca });
        const tlsProtocol = peer.socket.getProtocol();
        assertCapabilities(await capabilities(peer, protocol, 'p1'), protocol, true);
        assert.equal(authCalls.length, before, 'Pipelined plaintext must not authenticate after upgrade');
        await refuseSecondUpgrade(peer, protocol);
        await authenticateAndTunnel(peer, protocol);
        assert.equal(authCalls.length, before + 1);
        return { verifiedPeer: true, tlsProtocol, plaintextAuthRefused: true, pipelinedPlaintextDiscarded: true,
          postUpgradeCapabilitiesChecked: true, secondUpgradeRefused: true, nativeAuthenticatedTunnel: true };
      } finally { peer.close(); }
    });
    await check(`${protocol}.implicit_tls_verified_auth_and_tunnel`, async () => {
      const peer = await secure({ port: ports[protocol].implicit, ca: certs.ca });
      try {
        await greeting(peer, protocol);
        assertCapabilities(await capabilities(peer, protocol, 'i1', 'implicit.test'), protocol, true);
        await authenticateAndTunnel(peer, protocol);
        return { verifiedPeer: true, tlsProtocol: peer.socket.getProtocol(), nativeAuthenticatedTunnel: true };
      } finally { peer.close(); }
    });
    await check(`${protocol}.upgrade_wrong_ca_rejected`, async () => {
      const peer = await connect(ports[protocol].upgrade);
      try {
        await greeting(peer, protocol); await startTLS(peer, protocol);
        let failure;
        try { (await secure({ peer, ca: certs.untrusted })).close(); } catch (error) { failure = error; }
        assert.ok(failure, 'Untrusted certificate must fail');
        assert.ok(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(failure.code),
          `Expected certificate trust error, got ${failure.code}: ${failure.message}`);
        return { expectedCertificateError: failure.code, rejectUnauthorized: true };
      } finally { peer.close(); }
    });
    await check(`${protocol}.implicit_wrong_hostname_rejected`, async () => {
      let failure;
      try { (await secure({ port: ports[protocol].implicit, ca: certs.ca, servername: 'wrong-hostname.test' })).close(); }
      catch (error) { failure = error; }
      assert.ok(failure, 'Wrong hostname must fail'); assert.equal(failure.code, 'ERR_TLS_CERT_ALTNAME_INVALID');
      return { expectedCertificateError: failure.code, rejectUnauthorized: true };
    });
  }

  await check('smtp.starttls_discards_pre_upgrade_helo_and_mail_state', async () => {
    let peer = await connect(smtpResetPort);
    try {
      await greeting(peer, 'smtp'); await capabilities(peer, 'smtp', 'unused', 'must-be-discarded.test');
      peer.send('MAIL FROM:<stale@example.test>\r\n'); await smtp(peer, 250);
      await startTLS(peer, 'smtp'); peer = await secure({ peer, ca: certs.ca });
      const before = authCalls.length;
      // AUTH PLAIN omits Auth-SMTP-Helo entirely. This auth-NONE transaction
      // observes the actual HELO header and rejects the stale MAIL state.
      peer.send('RCPT TO:<stale-recipient@example.test>\r\n'); await smtp(peer, 503);
      assert.equal(authCalls.length, before);
      peer.send('MAIL FROM:<fresh@example.test>\r\n'); await smtp(peer, 250);
      peer.send('RCPT TO:<fresh-recipient@example.test>\r\n');
      assert.equal(await peer.line(), '250 2.1.5 fresh recipient\r\n');
      peer.send('NOOP\r\n'); assert.equal(await peer.line(), '250 2.0.0 tls-fixture noop\r\n');
      peer.send('QUIT\r\n'); assert.equal(await peer.line(), '221 2.0.0 tls-fixture bye\r\n');
      assert.equal(authCalls.length, before + 1);
      assert.equal(authCalls.at(-1).helo, '');
      assert.equal(authCalls.at(-1).method, 'none');
      return { authHttpHelo: '', authHttpHeloHeaderPresent: true, preUpgradeHeloDiscarded: true, staleMailStateRejected: true };
    } finally { peer.close(); }
  });
  await check('fixtures.tls_auth_metadata_and_backend_counts', async () => {
    assert.equal(authCalls.length, 7);
    for (const protocol of protocols) {
      const count = protocol === 'smtp' ? 3 : 2;
      assert.equal(authCalls.filter(call => call.protocol === protocol).length, count);
      assert.equal(backendConnections[protocol], count); assert.equal(backendHandshakes[protocol], count);
    }
    assert.equal(authCalls.filter(call => call.method === 'plain').length, 6);
    assert.equal(authCalls.filter(call => call.method === 'none' && call.helo === '').length, 1);
    assert.deepEqual(fixtureErrors, []); assert.equal(nginxStopped, false);
    return { authRequests: authCalls.length, allAuthRequestsEncrypted: authCalls.every(call => call.ssl === 'on'),
      backendConnections: { ...backendConnections }, backendHandshakes: { ...backendHandshakes } };
  });
}

async function cleanup() {
  stopping = true;
  const errors = [];
  for (const child of commandChildren) child.kill('SIGKILL');
  for (const socket of sockets) socket.destroy();
  if (nginx && !nginxStopped) {
    for (const [signal, ms] of [['SIGQUIT', 1500], ['SIGTERM', 800], ['SIGKILL', 800]]) {
      if (nginxStopped) break;
      nginx.kill(signal); await bounded(nginxExit, ms, `Native ${signal}`).catch(() => {});
    }
  }
  if (!nginxStopped) errors.push('Native child did not stop');
  for (const server of fixtures.reverse()) {
    if (!server.listening) continue;
    try { await bounded(new Promise((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); }), 1500, 'Fixture shutdown'); }
    catch (error) { errors.push(error.message); }
  }
  const deadline = Date.now() + 1000;
  while (sockets.size && Date.now() < deadline) await delay(10);
  if (sockets.size) errors.push(`${sockets.size} sockets remained open`);
  let temporaryRootRemoved = !prefix;
  if (prefix) {
    try { await rm(prefix, { recursive: true, force: true }); temporaryRootRemoved = true; }
    catch (error) { errors.push(error.message); }
  }
  return { nativeStopped: nginxStopped, fixturesStopped: fixtures.every(server => !server.listening),
    openSockets: sockets.size, temporaryRootRemoved, commandChildren: commandChildren.size, errors, nativeExit: nginxResult ?? null };
}

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  interrupted ||= signal;
  for (const socket of sockets) socket.destroy();
  for (const child of commandChildren) child.kill('SIGTERM');
  if (nginx && !nginxStopped) nginx.kill('SIGTERM');
});

let setupError;
try { await main(); } catch (error) { setupError = error.message; }
const cleanupResult = await cleanup();
let sourceUnchangedDuringTest = true, binaryUnchangedDuringTest = true;
try {
  binaryUnchangedDuringTest = identity.binarySha256 === sha256(await readFile(binary));
  for (const file of sourceFiles) {
    if (identity.sourceFilesSha256[file] !== sha256(await readFile(path.join(root, file)))) sourceUnchangedDuringTest = false;
  }
} catch (error) { sourceUnchangedDuringTest = false; setupError ||= error.message; }
identity.binaryUnchangedDuringTest = binaryUnchangedDuringTest;
identity.sourceUnchangedDuringTest = sourceUnchangedDuringTest;
const unexpectedNginxErrors = nginxLog.split('\n').filter(line => /\[(?:emerg|alert|crit|error)\]/.test(line));
const expectedHandshakeDiagnostics = nginxLog.split('\n').filter(line => /SSL_do_handshake\(\) failed|peer closed connection in SSL handshake/.test(line));
const passed = !setupError && !interrupted && tests.length === 15 && tests.every(test => test.passed)
  && !fixtureErrors.length && !cleanupResult.errors.length && !unexpectedNginxErrors.length
  && cleanupResult.nativeStopped && cleanupResult.fixturesStopped && cleanupResult.openSockets === 0
  && cleanupResult.temporaryRootRemoved && cleanupResult.commandChildren === 0
  && cleanupResult.nativeExit?.code === 0 && cleanupResult.nativeExit?.signal === null
  && sourceUnchangedDuringTest && binaryUnchangedDuringTest;
console.log(JSON.stringify({ schemaVersion: 1, suite: 'native-mail-tls-baseline', passed, binary, version, versionOutput: version, identity,
  scope: 'Synthetic loopback native SMTP/IMAP/POP3 TLS and STARTTLS/STLS compatibility; clients verify server certificates.',
  processMode: 'master_process off; one native process retaining the invoking UID',
  limits: ['Not a complete TLS library, protocol-version or client matrix', 'No client-certificate authentication or TLS resumption coverage',
    'No real mailbox, external identity provider, delivery, upstream TLS or production-readiness claim',
    'Pipelined plaintext test covers a single coalesced write, not every TCP fragmentation pattern'],
  tests, skips: [], authCalls, backendConnections, backendHandshakes, fixtureErrors,
  sourceUnchangedDuringTest, binaryUnchangedDuringTest, cleanup: cleanupResult,
  unexpectedNginxErrors, expectedHandshakeDiagnosticCount: expectedHandshakeDiagnostics.length,
  ...(setupError ? { setupError } : {}), ...(interrupted ? { interrupted } : {}), ...(!passed ? { nginxLog } : {}) }, null, 2));
process.exitCode = passed ? 0 : 1;
