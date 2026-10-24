#!/usr/bin/env node
// Native stream/mail baseline: only synthetic loopback fixtures, Node built-ins.
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const defaultBinary = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../.build/objs/nginx');
const binary = path.resolve(process.env.X10_NGINX_BINARY || defaultBinary);
const timeoutMs = 2500;
const user = 'allow-user';
const password = 'synthetic-pass';
const rejection = 'fixture rejected';
const plain = Buffer.from(`\0${user}\0${password}`).toString('base64');
const sockets = new Set();
const fixtures = [];
const fixtureErrors = [];
const authCalls = [];
const backendHandshakes = { smtp: 0, imap: 0, pop3: 0 };
const backendConnections = { smtp: 0, imap: 0, pop3: 0 };
const tests = [];
let prefix;
let nginx;
let nginxExit;
let nginxExited = false;
let nginxExitResult = null;
let shutdownSignal = null;
let nginxLog = '';

function track(socket) {
  sockets.add(socket);
  socket.on('error', () => {});
  socket.once('close', () => sockets.delete(socket));
  return socket;
}

function bounded(promise, milliseconds, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

async function listen(server) {
  fixtures.push(server);
  await new Promise((resolve, reject) => {
    const error = (err) => { server.off('listening', ready); reject(err); };
    const ready = () => { server.off('error', error); resolve(); };
    server.once('error', error);
    server.once('listening', ready);
    if (server instanceof net.Server) server.listen(0, '127.0.0.1');
    else server.bind(0, '127.0.0.1');
  });
  server.on('error', (err) => fixtureErrors.push(err.message));
  return server.address().port;
}

async function reservePort(udp = false) {
  const server = udp ? dgram.createSocket('udp4') : net.createServer();
  const port = await listen(server);
  await new Promise((resolve) => server.close(resolve));
  fixtures.splice(fixtures.indexOf(server), 1);
  return port;
}

class Peer {
  constructor(socket) {
    this.socket = track(socket);
    this.buffer = Buffer.alloc(0);
    this.ended = false;
    this.failure = null;
    this.wake = null;
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > 64 * 1024) {
        this.failure = new Error('peer response exceeded 64 KiB');
        socket.destroy();
      }
      this.wake?.();
    });
    socket.on('error', (err) => { this.failure = err; this.wake?.(); });
    socket.on('close', () => { this.ended = true; this.wake?.(); });
  }
  async take(find, label) {
    const read = async () => {
      for (;;) {
        const length = find(this.buffer);
        if (length !== null) {
          const value = this.buffer.subarray(0, length);
          this.buffer = this.buffer.subarray(length);
          return value;
        }
        if (this.failure) throw this.failure;
        if (this.ended) throw new Error(`connection closed before ${label}`);
        await new Promise((resolve) => { this.wake = resolve; });
      }
    };
    try { return await bounded(read(), timeoutMs, label); }
    finally { this.wake = null; }
  }
  async line() {
    return (await this.take((b) => {
      const end = b.indexOf('\r\n');
      return end < 0 ? null : end + 2;
    }, 'protocol line')).toString('utf8');
  }
  bytes(length) { return this.take((b) => b.length >= length ? length : null, 'exact payload'); }
  send(value) { this.socket.write(value); }
  close() { this.socket.destroy(); }
}

async function connect(port) {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  const peer = new Peer(socket);
  try {
    await bounded(new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    }), timeoutMs, 'loopback connect');
    return peer;
  } catch (err) { peer.close(); throw err; }
}

async function session(port, action) {
  const peer = await connect(port);
  try { return await action(peer); }
  finally { peer.close(); }
}

async function smtpReply(peer, code) {
  const lines = [];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line();
    assert.match(line, new RegExp(`^${code}[ -]`));
    lines.push(line);
    if (line.startsWith(`${code} `)) return lines.join('');
  }
  throw new Error('SMTP multiline reply exceeded 40 lines');
}

async function imapReply(peer, tag, status = 'OK') {
  const lines = [];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line();
    lines.push(line);
    if (line.startsWith(`${tag} `)) {
      assert.match(line, new RegExp(`^${tag} ${status} `));
      return lines.join('');
    }
  }
  throw new Error('IMAP reply exceeded 40 lines');
}

async function pop3Multiline(peer) {
  const first = await peer.line();
  assert.match(first, /^\+OK /);
  const lines = [first];
  for (let i = 0; i < 40; i++) {
    const line = await peer.line();
    lines.push(line);
    if (line === '.\r\n') return lines.join('');
  }
  throw new Error('POP3 multiline reply exceeded 40 lines');
}

async function check(name, fn) {
  const start = performance.now();
  try {
    const evidence = await fn();
    tests.push({ name, passed: true, durationMs: +(performance.now() - start).toFixed(2), ...evidence });
  } catch (err) {
    tests.push({ name, passed: false, durationMs: +(performance.now() - start).toFixed(2), error: err.message });
  }
}

function backend(protocol, handler) {
  return net.createServer((socket) => {
    backendConnections[protocol]++;
    const peer = new Peer(socket);
    socket.setTimeout(8000, () => socket.destroy());
    handler(peer).catch((err) => {
      fixtureErrors.push(`${protocol} fixture: ${err.message}`);
      peer.close();
    });
  });
}

async function runCommand(args) {
  const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk) => { output = (output + chunk).slice(-65536); });
  child.stderr.on('data', (chunk) => { output = (output + chunk).slice(-65536); });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  try {
    const result = await bounded(done, 5000, 'nginx command');
    assert.equal(result.code, 0, output || `nginx exited ${result.code}/${result.signal}`);
    return output.trim();
  } catch (err) {
    child.kill('SIGKILL');
    await bounded(done.catch(() => {}), 1000, 'command cleanup').catch(() => {});
    throw err;
  }
}

function quote(value) { return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`; }

async function cleanup() {
  const errors = [];
  for (const socket of sockets) socket.destroy();
  if (nginx && !nginxExited) {
    for (const [signal, milliseconds] of [['SIGQUIT', 1800], ['SIGTERM', 800], ['SIGKILL', 800]]) {
      if (nginxExited) break;
      shutdownSignal = signal;
      nginx.kill(signal);
      await bounded(nginxExit, milliseconds, `nginx ${signal}`).catch(() => {});
    }
    if (!nginxExited) errors.push('nginx child did not exit after SIGKILL');
  }
  for (const fixture of fixtures.reverse()) {
    try {
      await bounded(new Promise((resolve, reject) => {
        try { fixture.close(resolve); } catch (err) { reject(err); }
      }), 1500, 'fixture close');
    } catch (err) { errors.push(err.message); }
  }
  if (prefix) await rm(prefix, { recursive: true, force: true }).catch((err) => errors.push(err.message));
  return errors;
}

async function main() {
  const version = await runCommand(['-v']);
  const tcpFixture = net.createServer((socket) => {
    track(socket);
    socket.on('data', (chunk) => socket.write(chunk));
  });
  const tcpUpstream = await listen(tcpFixture);
  const udpFixture = dgram.createSocket('udp4');
  udpFixture.on('message', (message, remote) => udpFixture.send(message, remote.port, remote.address));
  const udpUpstream = await listen(udpFixture);
  const smtpUpstream = await listen(backend('smtp', async (peer) => {
    peer.send('220 smtp-fixture ESMTP ready\r\n');
    assert.equal(await peer.line(), 'EHLO baseline.test\r\n');
    peer.send('250-smtp-fixture\r\n250 AUTH PLAIN\r\n');
    assert.equal(await peer.line(), `AUTH PLAIN ${plain}\r\n`);
    backendHandshakes.smtp++;
    peer.send('235 2.7.0 fixture accepted\r\n');
    assert.equal(await peer.line(), 'NOOP\r\n');
    peer.send('250 2.0.0 fixture noop\r\n');
    assert.equal(await peer.line(), 'QUIT\r\n');
    peer.socket.end('221 2.0.0 fixture bye\r\n');
  }));
  const imapUpstream = await listen(backend('imap', async (peer) => {
    peer.send('* OK imap-fixture ready\r\n');
    assert.equal(await peer.line(), `a2 LOGIN {${user.length}}\r\n`);
    peer.send('+ fixture username\r\n');
    assert.equal(await peer.line(), `${user} {${password.length}}\r\n`);
    peer.send('+ fixture password\r\n');
    assert.equal(await peer.line(), `${password}\r\n`);
    backendHandshakes.imap++;
    peer.send('a2 OK fixture authenticated\r\n');
    assert.equal(await peer.line(), 'a3 NOOP\r\n');
    peer.send('a3 OK fixture noop\r\n');
    assert.equal(await peer.line(), 'a4 LOGOUT\r\n');
    peer.socket.end('* BYE fixture bye\r\na4 OK fixture logout\r\n');
  }));
  const pop3Upstream = await listen(backend('pop3', async (peer) => {
    peer.send('+OK pop3-fixture ready\r\n');
    assert.equal(await peer.line(), `USER ${user}\r\n`);
    peer.send('+OK fixture user\r\n');
    assert.equal(await peer.line(), `PASS ${password}\r\n`);
    backendHandshakes.pop3++;
    peer.send('+OK fixture authenticated\r\n');
    assert.equal(await peer.line(), 'STAT\r\n');
    peer.send('+OK 0 0\r\n');
    assert.equal(await peer.line(), 'QUIT\r\n');
    peer.socket.end('+OK fixture bye\r\n');
  }));
  const upstreams = { smtp: smtpUpstream, imap: imapUpstream, pop3: pop3Upstream };
  const auth = http.createServer((req, res) => {
    try {
      const protocol = req.headers['auth-protocol'];
      const login = req.headers['auth-user'];
      assert.equal(req.url, '/auth');
      assert.equal(req.method, 'GET');
      assert.ok(Object.hasOwn(upstreams, protocol), 'unexpected auth protocol');
      assert.equal(req.headers['auth-method'], 'plain');
      assert.ok(login === user || login === 'deny-user', 'unexpected synthetic user');
      assert.equal(req.headers['auth-pass'], password);
      authCalls.push({ protocol, decision: login === user ? 'allow' : 'deny' });
      const headers = login === user
        ? { 'Auth-Status': 'OK', 'Auth-Server': '127.0.0.1', 'Auth-Port': String(upstreams[protocol]) }
        : { 'Auth-Status': rejection, 'Auth-Error-Code': '535 5.7.8' };
      res.writeHead(200, { ...headers, Connection: 'close', 'Content-Length': '0' });
      res.end();
    } catch (err) {
      fixtureErrors.push(`auth fixture: ${err.message}`);
      res.writeHead(500, { Connection: 'close' }); res.end();
    }
  });
  auth.on('connection', track);
  const authPort = await listen(auth);
  const ports = {};
  for (const name of ['tcp', 'smtp', 'imap', 'pop3']) ports[name] = await reservePort();
  ports.udp = await reservePort(true);
  prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-stream-mail-'));
  await chmod(prefix, 0o755);
  await mkdir(path.join(prefix, 'logs'), { mode: 0o755 });
  // The current-user single process also works in root containers without CAP_SETGID.
  const userDirective = process.getuid?.() === 0 ? `user ${quote(os.userInfo().username)};` : '';
  const config = `${userDirective}
daemon off;
master_process off;
worker_processes 1;
pid ${quote(path.join(prefix, 'nginx.pid'))};
error_log stderr notice;
events { worker_connections 128; }
stream {
  server { listen 127.0.0.1:${ports.tcp}; proxy_pass 127.0.0.1:${tcpUpstream}; proxy_connect_timeout 1s; proxy_timeout 3s; }
  server { listen 127.0.0.1:${ports.udp} udp; proxy_pass 127.0.0.1:${udpUpstream}; proxy_requests 1; proxy_responses 1; proxy_timeout 2s; }
}
mail {
  server_name baseline.test;
  auth_http http://127.0.0.1:${authPort}/auth;
  auth_http_timeout 2s;
  timeout 5s;
  resolver off;
  proxy_timeout 5s;
  xclient off;
  proxy_smtp_auth on;
  server { listen 127.0.0.1:${ports.smtp}; protocol smtp; smtp_auth plain login; smtp_capabilities PIPELINING; }
  server { listen 127.0.0.1:${ports.imap}; protocol imap; imap_auth plain; imap_capabilities IMAP4rev1; }
  server { listen 127.0.0.1:${ports.pop3}; protocol pop3; pop3_auth plain; pop3_capabilities USER; }
}
`;
  const configPath = path.join(prefix, 'nginx.conf');
  await writeFile(configPath, config, { mode: 0o644 });
  await runCommand(['-p', `${prefix}/`, '-c', configPath, '-t']);
  nginx = spawn(binary, ['-p', `${prefix}/`, '-c', configPath], { stdio: ['ignore', 'ignore', 'pipe'] });
  nginx.stderr.on('data', (chunk) => { nginxLog = (nginxLog + chunk).slice(-65536); });
  nginxExit = new Promise((resolve) => {
    nginx.once('error', (err) => { nginxExited = true; fixtureErrors.push(err.message); resolve(); });
    nginx.once('exit', (code, signal) => { nginxExited = true; nginxExitResult = { code, signal }; resolve(nginxExitResult); });
  });
  const deadline = performance.now() + 4000;
  for (;;) {
    if (nginxExited) throw new Error(`nginx exited during startup: ${nginxLog}`);
    try { (await connect(ports.tcp)).close(); break; }
    catch (err) {
      if (performance.now() >= deadline) throw new Error(`nginx listener unavailable: ${err.message}; ${nginxLog}`);
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }

  await check('stream.tcp.exact_binary_payload', async () => {
    const payload = Buffer.concat([Buffer.from([0, 255, 13, 10, 128]), Buffer.from('x10 synthetic TCP payload\0')]);
    await session(ports.tcp, async (peer) => {
      peer.send(payload.subarray(0, 7)); peer.send(payload.subarray(7));
      assert.deepEqual(await peer.bytes(payload.length), payload);
      assert.equal(peer.buffer.length, 0);
    });
    return { payloadBytes: payload.length };
  });
  await check('stream.udp.exact_binary_datagram', async () => {
    const socket = dgram.createSocket('udp4');
    const payload = Buffer.from([0, 255, 128, 13, 10, 88, 49, 48]);
    try {
      const response = new Promise((resolve, reject) => {
        socket.once('error', reject);
        socket.once('message', (message, remote) => resolve({ message, remote }));
      });
      socket.send(payload, ports.udp, '127.0.0.1');
      const { message, remote } = await bounded(response, timeoutMs, 'UDP echo');
      assert.deepEqual(message, payload);
      assert.equal(remote.address, '127.0.0.1'); assert.equal(remote.port, ports.udp);
    } finally { await new Promise((resolve) => socket.close(resolve)); }
    return { payloadBytes: payload.length };
  });
  await check('mail.smtp.greeting_capability_quit', () => session(ports.smtp, async (peer) => {
    assert.match(await smtpReply(peer, 220), /baseline\.test/);
    peer.send('EHLO client.test\r\n');
    const capabilities = await smtpReply(peer, 250);
    assert.match(capabilities, /PIPELINING/); assert.match(capabilities, /AUTH.*PLAIN/);
    peer.send('QUIT\r\n'); await smtpReply(peer, 221);
  }));
  await check('mail.imap.greeting_capability_logout', () => session(ports.imap, async (peer) => {
    assert.match(await peer.line(), /^\* OK /);
    peer.send('a1 CAPABILITY\r\n');
    const capabilities = await imapReply(peer, 'a1');
    assert.match(capabilities, /IMAP4rev1/); assert.match(capabilities, /AUTH=PLAIN/);
    peer.send('a2 LOGOUT\r\n');
    assert.match(await imapReply(peer, 'a2'), /^\* BYE(?: |\r\n)/);
  }));
  await check('mail.pop3.greeting_capability_quit', () => session(ports.pop3, async (peer) => {
    assert.match(await peer.line(), /^\+OK /);
    peer.send('CAPA\r\n'); assert.match(await pop3Multiline(peer), /\r\nUSER\r\n/);
    peer.send('QUIT\r\n'); assert.match(await peer.line(), /^\+OK(?: |\r\n)/);
  }));
  for (const protocol of ['smtp', 'imap', 'pop3']) {
    await check(`mail.${protocol}.auth_http_denial`, () => session(ports[protocol], async (peer) => {
      const before = backendConnections[protocol];
      await peer.line();
      if (protocol === 'smtp') {
        peer.send('EHLO client.test\r\n'); await smtpReply(peer, 250);
        peer.send(`AUTH PLAIN ${Buffer.from(`\0deny-user\0${password}`).toString('base64')}\r\n`);
        assert.equal(await peer.line(), `535 5.7.8 ${rejection}\r\n`);
      } else if (protocol === 'imap') {
        peer.send(`a2 LOGIN deny-user ${password}\r\n`);
        assert.equal(await peer.line(), `a2 NO ${rejection}\r\n`);
      } else {
        peer.send('USER deny-user\r\n'); assert.match(await peer.line(), /^\+OK/);
        peer.send(`PASS ${password}\r\n`);
        assert.equal(await peer.line(), `-ERR ${rejection}\r\n`);
      }
      assert.equal(backendConnections[protocol], before, 'denied auth must not connect to a backend');
    }));
  }
  await check('mail.smtp.auth_proxy_success_and_tunnel', () => session(ports.smtp, async (peer) => {
    await smtpReply(peer, 220);
    peer.send('EHLO client.test\r\n'); await smtpReply(peer, 250);
    peer.send(`AUTH PLAIN ${plain}\r\n`); await smtpReply(peer, 235);
    peer.send('NOOP\r\n'); assert.equal(await peer.line(), '250 2.0.0 fixture noop\r\n');
    peer.send('QUIT\r\n'); assert.equal(await peer.line(), '221 2.0.0 fixture bye\r\n');
  }));
  await check('mail.imap.auth_proxy_literal_handshake_and_tunnel', () => session(ports.imap, async (peer) => {
    await peer.line(); peer.send(`a2 LOGIN ${user} ${password}\r\n`);
    assert.equal(await peer.line(), 'a2 OK fixture authenticated\r\n');
    peer.send('a3 NOOP\r\n'); assert.equal(await peer.line(), 'a3 OK fixture noop\r\n');
    peer.send('a4 LOGOUT\r\n'); assert.match(await imapReply(peer, 'a4'), /fixture logout/);
  }));
  await check('mail.pop3.auth_proxy_success_and_tunnel', () => session(ports.pop3, async (peer) => {
    await peer.line(); peer.send(`USER ${user}\r\n`); assert.match(await peer.line(), /^\+OK/);
    peer.send(`PASS ${password}\r\n`); assert.equal(await peer.line(), '+OK fixture authenticated\r\n');
    peer.send('STAT\r\n'); assert.equal(await peer.line(), '+OK 0 0\r\n');
    peer.send('QUIT\r\n'); assert.equal(await peer.line(), '+OK fixture bye\r\n');
  }));
  await check('fixtures.expected_auth_and_backend_counts', async () => {
    for (const protocol of ['smtp', 'imap', 'pop3']) {
      for (const decision of ['allow', 'deny']) {
        assert.equal(authCalls.filter((call) => call.protocol === protocol && call.decision === decision).length, 1);
      }
      assert.equal(backendHandshakes[protocol], 1);
      assert.equal(backendConnections[protocol], 1);
    }
    assert.deepEqual(fixtureErrors, []);
    assert.equal(nginxExited, false, 'nginx must remain alive through all cases');
    return { authRequests: authCalls.length, backendConnections: { ...backendConnections }, backendHandshakes: { ...backendHandshakes } };
  });
  return version;
}

let version = null;
let setupError = null;
try { version = await main(); }
catch (err) { setupError = err.message; }
const cleanupErrors = await cleanup();
const unexpectedNginxErrors = nginxLog.split('\n').filter((line) => /\[(?:emerg|alert|crit|error)\]/.test(line));
const passed = !setupError && tests.length === 12 && tests.every((test) => test.passed)
  && fixtureErrors.length === 0 && cleanupErrors.length === 0 && unexpectedNginxErrors.length === 0;
console.log(JSON.stringify({
  suite: 'native-stream-mail-baseline', passed, binary, version,
  processMode: 'master_process off; single native process under the current uid',
  masterProcess: false,
  scope: 'Existing native NGINX stream/mail behavior with synthetic loopback fixtures; no performance or production-readiness claim.',
  limits: ['No mail TLS/STARTTLS coverage', 'No external identity provider or real accounts', 'No exhaustive protocol, failure, platform or load coverage'],
  tests, authCalls, backendConnections, backendHandshakes, fixtureErrors, cleanupErrors,
  unexpectedNginxErrors, shutdown: { requestedSignal: shutdownSignal, result: nginxExitResult },
  ...(setupError ? { setupError } : {}),
  ...(!passed ? { nginxLog } : {}),
}, null, 2));
process.exitCode = passed ? 0 : 1;
