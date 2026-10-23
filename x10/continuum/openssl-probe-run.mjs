// C2a read-only OpenSSL metadata fixture. No exporter, importer or migration.
// Two recording-relay TCP legs are explicit and never called a handover.
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, chmod, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { createServer, createConnection } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyHandshakeCapture } from './handshake-oracle.mjs';
import { buildOpenSSL } from './openssl-build.mjs';

const SOURCE = fileURLToPath(new URL('./openssl-probe-fixture.c', import.meta.url));
const PEER_SOURCE = fileURLToPath(new URL('./openssl-peer-client.c', import.meta.url));
const PROBE_SOURCE = fileURLToPath(new URL('./openssl-probe.c', import.meta.url));
const PATCH = fileURLToPath(new URL('./openssl-probe.patch', import.meta.url));
const DEADLINE_MS = 12000;
const CAPTURE_LIMIT = 262144;
const SCENARIOS = ['quiescent', 'partial-header', 'partial-body', 'unread-plaintext', 'empty-read-retry', 'write-backpressure', 'queued-key-update', 'completed-key-update',
  'completed-read-retry', 'unrelated-write-read-retry', 'peer-key-update-pending', 'peer-key-update-completed', 'completed-write-retry'];
const SECRET_LABELS = Object.freeze({
  CLIENT_HANDSHAKE_TRAFFIC_SECRET: 'clientHandshake', SERVER_HANDSHAKE_TRAFFIC_SECRET: 'serverHandshake',
  CLIENT_TRAFFIC_SECRET_0: 'clientApplication', SERVER_TRAFFIC_SECRET_0: 'serverApplication',
});
// Preserve only fixed builder stage names. Arbitrary codes/messages may contain
// private paths or command output and remain a generic dependency failure.
const BUILD_ERROR_CODES = new Set([
  'C2A_BUILD_artifact_invalid', 'C2A_BUILD_tool_unavailable', 'C2A_BUILD_aborted',
  'C2A_BUILD_deadline', 'C2A_BUILD_output_limit', 'C2A_BUILD_unsupported_platform',
  'C2A_BUILD_patch_invalid', 'C2A_BUILD_source_init', 'C2A_BUILD_source_fetch',
  'C2A_BUILD_source_checkout', 'C2A_BUILD_source_identity', 'C2A_BUILD_source_dirty',
  'C2A_BUILD_source_epoch', 'C2A_BUILD_patch_check', 'C2A_BUILD_patch_apply',
  'C2A_BUILD_patch_identity', 'C2A_BUILD_compiler_identity', 'C2A_BUILD_configure',
  'C2A_BUILD_configuration_identity', 'C2A_BUILD_compile', 'C2A_BUILD_binary_identity',
  'C2A_BUILD_provider_identity', 'C2A_BUILD_cleanup', 'C2A_BUILD_identity_unavailable',
  'C2A_BUILD_source_changed', 'C2A_BUILD_patch_changed', 'C2A_BUILD_artifact_changed',
  'C2A_BUILD_unavailable',
]);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const assertFixture = (condition, code) => { if (!condition) throw new ProbeFixtureError(code); };
let nodeBinaryHash;

export class ProbeFixtureError extends Error {
  constructor(code) { super(code); this.name = 'ProbeFixtureError'; this.code = code; }
}
function bounded(promise, code, milliseconds = DEADLINE_MS, signal) {
  let timer;
  let onAbort;
  const interruption = signal ? new Promise((_, reject) => {
    onAbort = () => reject(signal.reason ?? new ProbeFixtureError('fixture_interrupted'));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  }) : new Promise(() => {});
  return Promise.race([promise, interruption, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ProbeFixtureError(code)), milliseconds);
  })]).finally(() => { clearTimeout(timer); if (onAbort) signal.removeEventListener('abort', onAbort); });
}
function trackedSpawn(command, args, children, signal, privatePipe = false) {
  signal.throwIfAborted();
  const child = spawn(command, args, { stdio: privatePipe ? ['pipe', 'pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe'], signal, killSignal: 'SIGTERM',
    env: { ...process.env, OPENSSL_CONF: '/dev/null' } });
  children.add(child);
  child.on('error', () => {});
  const closed = new Promise(resolve => {
    child.once('close', (code, signal) => { children.delete(child); resolve({ code, signal }); });
    // AbortError may arrive while the child is still alive. Only actual close
    // releases ownership and resolves the reaping promise.
  });
  return { child, closed };
}
async function command(commandName, args, children, signal) {
  const process = trackedSpawn(commandName, args, children, signal);
  process.child.stdin.end();
  let output = Buffer.alloc(0);
  let errorBytes = 0;
  let overflow = false;
  process.child.stdout.on('data', chunk => {
    if (output.length + chunk.length > 32768) { overflow = true; process.child.kill('SIGKILL'); }
    else output = Buffer.concat([output, chunk]);
  });
  process.child.stderr.on('data', chunk => {
    errorBytes += chunk.length;
    if (errorBytes > 32768) { overflow = true; process.child.kill('SIGKILL'); }
  });
  const exit = await bounded(process.closed, 'tool_timeout', DEADLINE_MS, signal);
  assertFixture(exit.code === 0 && exit.signal === null && !overflow, 'tool_failed');
  return output;
}
function nativeChannel(binary, args, children, signal, privateSecrets) {
  const process = trackedSpawn(binary, args, children, signal, privateSecrets !== undefined);
  const messages = [];
  const waiters = new Set();
  let pending = '';
  let outputBytes = 0;
  let stderrBytes = 0;
  let failure = false;
  let closed;
  const wake = () => { for (const callback of waiters) callback(); };
  process.child.stdout.on('data', chunk => {
    outputBytes += chunk.length;
    if (outputBytes > 65536) { failure = true; process.child.kill('SIGKILL'); wake(); return; }
    pending += chunk.toString('utf8');
    while (pending.includes('\n')) {
      const end = pending.indexOf('\n');
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      try {
        const value = JSON.parse(line);
        if (!value || typeof value !== 'object' || typeof value.event !== 'string' || messages.length >= 32) throw new Error();
        messages.push(value);
      } catch { failure = true; process.child.kill('SIGKILL'); }
    }
    wake();
  });
  process.child.stderr.on('data', chunk => {
    stderrBytes += chunk.length;
    if (stderrBytes > 16384) { failure = true; process.child.kill('SIGKILL'); }
  });
  const keylog = privateSecrets ? privateKeylog(process.child.stdio[3], privateSecrets, () => { failure = true; process.child.kill('SIGKILL'); wake(); }) : undefined;
  process.closed.then(value => { closed = value; if (pending.length) failure = true; wake(); });
  const wait = (event, predicate = () => true) => bounded(new Promise((resolve, reject) => {
    const callback = () => {
      if (failure) { waiters.delete(callback); reject(new ProbeFixtureError('native_output_invalid')); return; }
      const message = messages.find(item => item.event === event && predicate(item));
      if (message) { waiters.delete(callback); resolve(message); }
      else if (closed) { waiters.delete(callback); reject(new ProbeFixtureError('native_early_exit')); }
    };
    waiters.add(callback); callback();
  }), 'native_event_timeout', DEADLINE_MS, signal);
  return { ...process, messages, wait, keylog, validOutput: () => !failure && pending.length === 0 && (!keylog || keylog.valid()) };
}
// Only the peer fixture inherits fd 3. NSS material stays in bounded buffers,
// never enters the JSON channel or files, and is scrubbed during final cleanup.
function privateKeylog(stream, secrets, fail) {
  let pending = Buffer.alloc(0), random, bytes = 0, invalid = false, ended = false;
  const hex = buffer => {
    assertFixture(buffer.length === 64, 'keylog_invalid');
    const output = Buffer.alloc(32);
    const nibble = value => value >= 48 && value <= 57 ? value - 48 : value >= 65 && value <= 70 ? value - 55 : value >= 97 && value <= 102 ? value - 87 : -1;
    try {
      for (let i = 0; i < output.length; i++) {
        const high = nibble(buffer[i * 2]), low = nibble(buffer[i * 2 + 1]);
        assertFixture(high >= 0 && low >= 0, 'keylog_invalid'); output[i] = high * 16 + low;
      }
      return output;
    } catch (error) { output.fill(0); throw error; }
  };
  const line = buffer => {
    assertFixture(buffer.length > 0 && buffer.length <= 512, 'keylog_invalid');
    const a = buffer.indexOf(32), b = buffer.indexOf(32, a + 1);
    assertFixture(a > 0 && b === a + 65 && buffer.length === b + 65, 'keylog_invalid');
    const label = buffer.subarray(0, a).toString('ascii');
    assertFixture(/^[A-Z0-9_]{1,64}$/.test(label), 'keylog_invalid');
    let binding, value;
    try {
      binding = hex(buffer.subarray(a + 1, b)); value = hex(buffer.subarray(b + 1));
      if (random) assertFixture(random.equals(binding), 'keylog_binding');
      else { random = binding; binding = undefined; }
      if (Object.hasOwn(SECRET_LABELS, label)) {
        const name = SECRET_LABELS[label];
        if (secrets[name]) assertFixture(secrets[name].equals(value), 'keylog_binding');
        else { secrets[name] = value; value = undefined; }
      }
    } finally { binding?.fill(0); value?.fill(0); }
  };
  stream.on('data', chunk => {
    try {
      bytes += chunk.length;
      assertFixture(bytes <= 16384 && pending.length + chunk.length <= 16384, 'keylog_limit');
      const combined = Buffer.concat([pending, chunk]); pending.fill(0); pending = combined;
      let end;
      while ((end = pending.indexOf(10)) !== -1) {
        const current = pending.subarray(0, end);
        try { line(current); } finally { current.fill(0); }
        const rest = Buffer.from(pending.subarray(end + 1)); pending.fill(0); pending = rest;
      }
      assertFixture(pending.length <= 512, 'keylog_limit');
    } catch { invalid = true; fail(); }
    finally { chunk.fill(0); }
  });
  stream.on('error', () => { invalid = true; fail(); });
  stream.on('end', () => { ended = true; if (pending.length) { invalid = true; fail(); } });
  return { random: () => random,
    valid: () => !invalid && ended && pending.length === 0 && Object.values(SECRET_LABELS).every(name => secrets[name]?.length === 32),
    clear() { pending.fill(0); random?.fill(0); } };
}

async function makeCertificates(directory, children, signal, openssl) {
  const path = name => join(directory, name);
  await command(openssl, ['req', '-config', '/dev/null', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-sha256', '-days', '1', '-subj', '/CN=Continuum-C2a-Test-CA', '-keyout', path('ca.key'), '-out', path('ca.crt'),
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], children, signal);
  await command(openssl, ['req', '-config', '/dev/null', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-sha256', '-subj', '/CN=continuum.test', '-keyout', path('leaf.key'), '-out', path('leaf.csr')], children, signal);
  signal.throwIfAborted();
  await writeFile(path('leaf.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:continuum.test\n', { mode: 0o600 });
  await command(openssl, ['x509', '-req', '-in', path('leaf.csr'), '-CA', path('ca.crt'), '-CAkey', path('ca.key'),
    '-set_serial', '0x1001', '-days', '1', '-sha256', '-extfile', path('leaf.ext'), '-out', path('leaf.crt')], children, signal);
  await Promise.all([chmod(path('ca.key'), 0o600), chmod(path('leaf.key'), 0o600)]);
  return { cert: path('leaf.crt'), key: path('leaf.key'), caPath: path('ca.crt'), ca: await readFile(path('ca.crt')) };
}

function scope(milliseconds) {
  const controller = new AbortController();
  const interrupt = name => {
    const error = new ProbeFixtureError('fixture_interrupted');
    error.exitCode = name === 'SIGTERM' ? 143 : 130;
    controller.abort(error);
  };
  const term = () => interrupt('SIGTERM');
  const int = () => interrupt('SIGINT');
  process.on('SIGTERM', term); process.on('SIGINT', int);
  const timer = setTimeout(() => controller.abort(new ProbeFixtureError('fixture_deadline')), milliseconds);
  return { signal: controller.signal, close() { clearTimeout(timer); process.removeListener('SIGTERM', term); process.removeListener('SIGINT', int); } };
}
async function reap(children) {
  const work = [];
  for (const child of children) {
    work.push(bounded(new Promise(resolve => child.once('close', resolve)), 'cleanup_process_timeout', 2000));
    child.kill('SIGKILL');
  }
  await Promise.all(work);
}

let harness;
let preparing;
let running = false;
const sourceFiles = { fixture: SOURCE, peerClient: PEER_SOURCE, probe: PROBE_SOURCE,
  header: fileURLToPath(new URL('./openssl-probe.h', import.meta.url)), patch: PATCH };
const sourceHashes = async () => Object.fromEntries(await Promise.all(Object.entries(sourceFiles).map(async ([name, path]) => [name, sha256(await readFile(path))])));

/** One pinned build per process. Returned value contains public identity only. */
export async function prepareProbeHarness() {
  if (harness) { await verifyHarness(); return structuredClone(harness.identity); }
  if (preparing) return preparing;
  preparing = (async () => {
    const owned = scope(1200000);
    const children = new Set();
    let build;
    let directory;
    try {
      build = await buildOpenSSL({ signal: owned.signal });
      directory = await mkdtemp(join(tmpdir(), 'x10-c2a-fixture-build-'));
      await chmod(directory, 0o700);
      const hashes = await sourceHashes();
      const binary = join(directory, 'openssl-probe-fixture');
      const paths = build.privatePaths;
      const include = [paths.includeDir, paths.sourceIncludeDir, paths.sourceDir, paths.buildDir];
      await command(paths.compiler ?? 'cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
        ...include.flatMap(path => ['-I', path]), '-o', binary, SOURCE, PROBE_SOURCE,
        paths.libssl, paths.libcrypto, '-pthread', '-ldl'], children, owned.signal);
      await chmod(binary, 0o700);
      const peerBinary = join(directory, 'openssl-peer-client');
      await command(paths.compiler ?? 'cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        ...include.flatMap(path => ['-I', path]), '-o', peerBinary, PEER_SOURCE,
        paths.libssl, paths.libcrypto, '-pthread', '-ldl'], children, owned.signal);
      await chmod(peerBinary, 0o700);
      assertFixture(JSON.stringify(await sourceHashes()) === JSON.stringify(hashes), 'probe_source_changed_during_compile');
      nodeBinaryHash ??= readFile(process.execPath).then(sha256);
      const binaryHash = sha256(await readFile(binary));
      const peerBinaryHash = sha256(await readFile(peerBinary));
      const identity = { schemaVersion: 1, pinnedBuild: build.identity, sourceSha256: hashes,
        fixtureBinarySha256: binaryHash, peerClientBinarySha256: peerBinaryHash, nodeBinarySha256: await nodeBinaryHash,
        nodeVersion: process.version, nodeOpenSSLVersion: process.versions.openssl };
      harness = { build, directory, binary, binaryHash, peerBinary, peerBinaryHash, hashes, identity };
      return structuredClone(identity);
    } catch (error) {
      try { await reap(children); } finally {
        if (directory) await rm(directory, { recursive: true, force: true });
        await build?.cleanup();
      }
      if (owned.signal.aborted) throw owned.signal.reason;
      const code = error instanceof ProbeFixtureError || BUILD_ERROR_CODES.has(error?.code)
        ? error.code : 'probe_build_failed';
      throw new ProbeFixtureError(code);
    } finally { owned.close(); preparing = undefined; }
  })();
  return preparing;
}
async function verifyHarness(signal) {
  assertFixture(harness !== undefined, 'probe_build_not_prepared');
  await bounded(harness.build.verifyIdentity({ signal }), 'build_identity_timeout', 30000, signal);
  assertFixture(JSON.stringify(await sourceHashes()) === JSON.stringify(harness.hashes) &&
    sha256(await readFile(harness.binary)) === harness.binaryHash &&
    sha256(await readFile(harness.peerBinary)) === harness.peerBinaryHash, 'probe_identity_changed');
}
export async function cleanupProbeHarness() {
  assertFixture(!running && !preparing, 'probe_harness_busy');
  if (!harness) return;
  const previous = harness; harness = undefined;
  try { await rm(previous.directory, { recursive: true, force: true }); }
  finally { await previous.build.cleanup(); }
}

function relayTo(port, sockets, signal) {
  const capture = { clientToServer: [], serverToClient: [] };
  const observed = { clientFin: false, serverFin: false, frontClosed: false, backClosed: false, frontConnections: 0, backConnections: 0 };
  const watchers = new Set();
  let backend;
  let failure;
  let captureBytes = 0;
  let gate;
  const wake = () => { for (const callback of watchers) callback(); };
  const server = createServer({ allowHalfOpen: true }, front => {
    sockets.add(front);
    observed.frontConnections++;
    if (observed.frontConnections !== 1) { failure = true; front.destroy(); wake(); return; }
    backend = createConnection({ host: '127.0.0.1', port, allowHalfOpen: true, signal });
    const back = backend;
    sockets.add(back);
    back.once('connect', () => { observed.backConnections++; });
    const record = (direction, chunk) => {
      captureBytes += chunk.length;
      if (captureBytes > CAPTURE_LIMIT) throw new ProbeFixtureError('capture_limit');
      capture[direction].push(Buffer.from(chunk));
    };
    front.on('data', chunk => {
      try {
        record('clientToServer', chunk);
        if (!gate) back.write(chunk);
        else {
          const count = Math.min(chunk.length, gate.prefix - gate.forwarded);
          gate.withheld += chunk.length - count;
          if (count) {
            gate.forwarded += count;
            back.write(chunk.subarray(0, count), error => {
              if (error) failure = true;
              else if (gate.forwarded === gate.prefix) gate.delivered = true;
              wake();
            });
          }
        }
      } catch { failure = true; front.destroy(); back.destroy(); }
      wake();
    });
    back.on('data', chunk => { try { record('serverToClient', chunk); front.write(chunk); } catch { failure = true; front.destroy(); back.destroy(); } wake(); });
    front.on('end', () => { observed.clientFin = true; back.end(); wake(); });
    back.on('end', () => { observed.serverFin = true; front.end(); wake(); });
    front.on('close', bad => { observed.frontClosed = true; failure ||= bad; wake(); });
    back.on('close', bad => { observed.backClosed = true; failure ||= bad; wake(); });
    front.on('error', () => { failure = true; back.destroy(); wake(); });
    back.on('error', () => { failure = true; front.destroy(); wake(); });
  });
  server.on('error', () => { failure = true; wake(); });
  const wait = predicate => bounded(new Promise((resolve, reject) => {
    const callback = () => {
      if (failure) { watchers.delete(callback); reject(new ProbeFixtureError('relay_failed')); }
      else if (predicate()) { watchers.delete(callback); resolve(); }
    };
    watchers.add(callback); callback();
  }), 'relay_timeout', DEADLINE_MS, signal);
  return { server, capture, observed,
    prefix(count) { assertFixture(!gate && count > 0, 'prefix_gate_invalid'); gate = { prefix: count, forwarded: 0, withheld: 0, delivered: false }; },
    waitPrefix: () => wait(() => gate?.delivered === true),
    pauseServerReads() { assertFixture(backend !== undefined, 'relay_backend_missing'); backend.pause(); },
    serverReadsPaused: () => backend?.isPaused() === true,
    resumeServerReads() { assertFixture(backend?.isPaused(), 'relay_backend_not_paused'); backend.resume(); },
    waitClosed: () => wait(() => observed.frontClosed && observed.backClosed),
  };
}
function independentClient(port, ca, payload, sockets, secrets, signal) {
  const socket = tlsConnect({ host: '127.0.0.1', port, servername: 'continuum.test', ca, rejectUnauthorized: true,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ciphers: 'TLS_AES_128_GCM_SHA256', ALPNProtocols: ['continuum-c1'], signal });
  sockets.add(socket);
  let clientRandom;
  let negotiated;
  let received = Buffer.alloc(0);
  let failure;
  let endAfterEcho = false;
  let ended = false;
  let closed = false;
  let applicationWrites = 0;
  const observers = new Set();
  const wake = () => { for (const callback of observers) callback(); };
  socket.on('keylog', line => {
    try {
      assertFixture(line.length <= 512, 'keylog_invalid');
      const fields = line.toString('ascii').trim().split(' ');
      if (!Object.hasOwn(SECRET_LABELS, fields[0])) return;
      assertFixture(fields.length === 3 && /^[0-9a-fA-F]{64}$/.test(fields[1]) && /^[0-9a-fA-F]{64}$/.test(fields[2]), 'keylog_invalid');
      const random = Buffer.from(fields[1], 'hex');
      if (clientRandom) assertFixture(clientRandom.equals(random), 'keylog_binding'); else clientRandom = random;
      const name = SECRET_LABELS[fields[0]];
      const value = Buffer.from(fields[2], 'hex');
      if (secrets[name]) { assertFixture(secrets[name].equals(value), 'keylog_binding'); value.fill(0); }
      else secrets[name] = value;
    } catch { failure = new ProbeFixtureError('keylog_invalid'); socket.destroy(); wake(); }
  });
  socket.on('secureConnect', () => {
    negotiated = { protocol: socket.getProtocol(), cipher: socket.getCipher()?.standardName,
      alpn: socket.alpnProtocol, authorized: socket.authorized };
    if (!negotiated.authorized || negotiated.protocol !== 'TLSv1.3' || negotiated.cipher !== 'TLS_AES_128_GCM_SHA256' ||
      negotiated.alpn !== 'continuum-c1' || socket.isSessionReused()) { failure = new ProbeFixtureError('client_profile'); socket.destroy(); }
    wake();
  });
  socket.on('data', chunk => {
    if (received.length + chunk.length > payload.length) { failure = new ProbeFixtureError('unexpected_plaintext'); socket.destroy(); }
    else {
      received = Buffer.concat([received, chunk]);
      if (received.length === payload.length && !received.equals(payload)) { failure = new ProbeFixtureError('plaintext_mismatch'); socket.destroy(); }
      else if (endAfterEcho && received.length === payload.length) socket.end();
    }
    wake();
  });
  socket.on('error', () => { failure ??= new ProbeFixtureError('client_transport'); wake(); });
  socket.on('end', () => { ended = true; wake(); });
  socket.on('close', () => { closed = true; wake(); });
  const wait = predicate => bounded(new Promise((resolve, reject) => {
    const callback = () => {
      if (failure) { observers.delete(callback); reject(failure); }
      else if (predicate()) { observers.delete(callback); resolve(); }
      else if (closed) { observers.delete(callback); reject(new ProbeFixtureError('client_early_close')); }
    };
    observers.add(callback); callback();
  }), 'client_timeout', DEADLINE_MS, signal);
  return { socket, secure: () => wait(() => negotiated !== undefined),
    write() { applicationWrites++; socket.write(payload, error => { if (error) { failure = new ProbeFixtureError('client_write'); wake(); } }); },
    endOnEcho() { endAfterEcho = true; if (received.equals(payload)) socket.end(); }, finish: () => wait(() => closed && ended && received.equals(payload)),
    receivedPayload: () => wait(() => received.equals(payload)), receivedBytes: () => received.length,
    applicationWrites: () => applicationWrites,
    negotiated: () => negotiated, random: () => clientRandom,
  };
}

async function stepNative(channel, signal) {
  await bounded(new Promise((resolve, reject) => channel.child.stdin.write('STEP\n', error =>
    error ? reject(new ProbeFixtureError('native_step')) : resolve())), 'native_step', DEADLINE_MS, signal);
}
function peerClient(port, cert, scenario, payloadBytes, challenge, children, secrets, signal) {
  const channel = nativeChannel(harness.peerBinary, ['--port', String(port), '--ca', cert.caPath,
    '--scenario', scenario, '--bytes', String(payloadBytes), '--challenge', challenge.toString('hex')], children, signal, secrets);
  let negotiated;
  return { channel, random: () => channel.keylog.random(), negotiated: () => negotiated,
    async secure() {
      const message = await channel.wait('handshake');
      assertFixture(message.version === 'TLSv1.3' && message.cipher === 'TLS_AES_128_GCM_SHA256' &&
        message.alpn === 'continuum-c1' && message.resumed === false && message.authorized === true &&
        message.opensslVersion === 'OpenSSL 3.0.13 30 Jan 2024' && message.opensslHeadersVersion === message.opensslVersion,
      'peer_client_profile');
      negotiated = { protocol: message.version, cipher: message.cipher, alpn: message.alpn, authorized: true };
      await channel.wait('ready', item => item.scenario === scenario);
    },
    async send() {
      await stepNative(channel, signal);
      const sent = await channel.wait('sent');
      assertFixture(Object.keys(sent).sort().join(',') === 'applicationBytesWritten,event,keyUpdateRequested,scenario' &&
        sent.scenario === scenario && sent.applicationBytesWritten === payloadBytes && sent.keyUpdateRequested === true,
      'peer_client_sent');
    },
    async finish() {
      const done = await channel.wait('done');
      const graceful = scenario === 'peer-key-update-completed';
      assertFixture(Object.keys(done).sort().join(',') === 'applicationBytesRead,applicationBytesWritten,event,graceful,scenario' &&
        done.scenario === scenario && done.graceful === graceful && done.applicationBytesWritten === payloadBytes &&
        done.applicationBytesRead === (graceful ? payloadBytes : 0), 'peer_client_done');
      if (graceful) {
        const shutdown = await channel.wait('shutdown');
        assertFixture(shutdown.clean === true && shutdown.shutdownBits === 3, 'peer_client_shutdown');
      }
      const exit = await bounded(channel.closed, 'peer_client_exit', DEADLINE_MS, signal);
      assertFixture(exit.code === 0 && exit.signal === null && channel.validOutput(), 'peer_client_failed');
    },
    clear() { channel.keylog.clear(); },
  };
}
function checkedPeerReceived(message, scenario, payloadBytes) {
  const keys = ['event', 'scenario', 'call', 'outcome', 'retryCall', 'applicationBytesRead', 'sslPending',
    'keyUpdate', 'readGeneration', 'writeGeneration', 'mutationSerial'];
  assertFixture(message?.event === 'peer-update-received' && message.scenario === scenario &&
    Object.keys(message).sort().join(',') === keys.sort().join(',') && message.call === 2 && message.outcome === 1 &&
    message.retryCall === 0 && message.applicationBytesRead === payloadBytes && message.sslPending === 0 &&
    message.keyUpdate === 0 && message.readGeneration === '1' && message.writeGeneration === '0' &&
    message.mutationSerial === '3', 'peer_update_received');
  return structuredClone(message);
}

const decimalFields = ['reasons', 'readGeneration', 'writeGeneration', 'mutationSerial', 'ledgerCallSerial'];
const sequenceFields = ['readNextSequence', 'writeNextSequence'];
const booleanFields = ['allowed', 'sslHasPending', 'monitorKnown'];
const numericFields = ['sslPending', 'packetLength', 'rbufLeft', 'rbufOffset', 'rbufLength', 'unreadRecordBytes', 'unreadControlBytes',
  'wbufLeft', 'wbufOffset', 'wbufLength', 'wnum', 'staleWpendTot', 'staleWpendRet', 'readRecordSlots', 'writeBufferSlots',
  'rstate', 'rwstate', 'flowState', 'handshakeState', 'inInit', 'inHandshake', 'encReadState', 'encWriteState', 'keyUpdate',
  'alertDispatch', 'shutdown', 'handshakeFragmentLength', 'initNum', 'ledgerLastCall', 'ledgerRetryCall', 'ledgerLastOutcome'];
function checkedProbe(message, scenario) {
  const keys = ['event', 'scenario', 'sample', ...decimalFields, ...sequenceFields, ...booleanFields, ...numericFields];
  assertFixture(message?.event === 'probe' && message.scenario === scenario &&
    (scenario === 'completed-write-retry' ? [1, 2, 3, 4] : [1, 2]).includes(message.sample) &&
    Object.keys(message).sort().join(',') === keys.sort().join(','), 'probe_schema');
  for (const field of decimalFields) assertFixture(typeof message[field] === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(message[field]) && BigInt(message[field]) <= 0xffffffffffffffffn, 'probe_counter');
  for (const field of sequenceFields) assertFixture(typeof message[field] === 'string' && /^[0-9a-f]{16}$/.test(message[field]), 'probe_sequence');
  for (const field of booleanFields) assertFixture(typeof message[field] === 'boolean', 'probe_boolean');
  for (const field of numericFields) assertFixture(Number.isSafeInteger(message[field]) && message[field] >= -1 && message[field] <= 8388608, 'probe_number');
  assertFixture(message.monitorKnown && (message.allowed ? message.reasons === '0' : BigInt(message.reasons) !== 0n), 'probe_monitor_or_reasons');
  return structuredClone(message);
}
function checkRefusal(probe, scenario) {
  assertFixture(!probe.allowed, 'unsafe_probe_allowed');
  const reasons = BigInt(probe.reasons);
  if (scenario.startsWith('partial-')) assertFixture(probe.sslPending === 0 && (probe.packetLength > 0 || probe.rbufLeft > 0) &&
    (reasons & (1n << 7n)) !== 0n && probe.ledgerLastOutcome === 2 && probe.ledgerRetryCall === 2, 'partial_state_not_observed');
  else if (scenario === 'unread-plaintext') assertFixture(probe.sslPending > 0 && probe.unreadRecordBytes > 0 && (reasons & (1n << 8n)) !== 0n, 'unread_state_not_observed');
  else if (scenario === 'empty-read-retry') assertFixture(probe.sslPending === 0 && probe.packetLength === 0 && (reasons & (1n << 4n)) !== 0n && probe.ledgerRetryCall === 2 && probe.ledgerLastOutcome === 2, 'empty_retry_not_observed');
  else if (scenario === 'write-backpressure' || scenario === 'completed-write-retry') assertFixture(probe.wbufLeft > 0 && probe.ledgerRetryCall === 3 && probe.ledgerLastOutcome === 3 && (reasons & ((1n << 9n) | (1n << 10n))) !== 0n, 'write_pressure_not_observed');
  else if (scenario === 'queued-key-update') assertFixture(probe.keyUpdate === 0 && (reasons & ((1n << 12n) | (1n << 15n))) !== 0n, 'queued_key_update_not_observed');
  else if (scenario === 'unrelated-write-read-retry') assertFixture(probe.reasons === '16' &&
    probe.sslPending === 0 && probe.sslHasPending === false && probe.ledgerRetryCall === 2 &&
    probe.ledgerLastCall === 3 && probe.ledgerLastOutcome === 1, 'unrelated_write_cleared_read_retry');
}

function checkedRetryEvent(message, event, scenario, payloadBytes) {
  const completed = event === 'retry-completed';
  const keys = ['event', 'scenario', 'call', 'outcome', 'retryCall', 'applicationBytesRead', 'sslPending',
    ...(completed ? ['sameReadArguments'] : [])];
  assertFixture(message?.event === event && message.scenario === scenario &&
    Object.keys(message).sort().join(',') === keys.sort().join(','), 'retry_event_schema');
  assertFixture(message.call === 2 && message.outcome === (completed ? 1 : 2) &&
    message.retryCall === (completed ? 0 : 2), 'retry_event_ledger');
  assertFixture(Number.isSafeInteger(message.sslPending) && message.sslPending >= 0 &&
    message.sslPending <= 65536, 'retry_event_pending');
  assertFixture(Number.isSafeInteger(message.applicationBytesRead) && (completed
    ? message.applicationBytesRead >= 1 && message.applicationBytesRead <= Math.min(payloadBytes, 16384) && message.sameReadArguments === true
    : message.applicationBytesRead === 0 && message.sslPending === 0), 'retry_event_transition');
  return structuredClone(message);
}

function checkedWriteRetryEvent(message, event, payloadBytes) {
  const completed = event === 'write-retry-completed';
  const keys = ['event', 'scenario', 'call', 'outcome', 'retryCall', 'applicationBytesRead',
    'writeLength', 'sameWriteArguments', ...(completed ? ['applicationBytesWritten'] : [])];
  assertFixture(message?.event === event && message.scenario === 'completed-write-retry' &&
    Object.keys(message).sort().join(',') === keys.sort().join(','), 'write_retry_event_schema');
  assertFixture(message.call === 3 && message.outcome === (completed ? 1 : 3) &&
    message.retryCall === (completed ? 0 : 3) && message.applicationBytesRead === payloadBytes &&
    (!completed || message.applicationBytesWritten === payloadBytes) && message.writeLength === payloadBytes &&
    message.sameWriteArguments === true, 'write_retry_event_transition');
  return structuredClone(message);
}

function checkedImmutablePair(first, second) {
  const normalized = value => { const copy = { ...value }; delete copy.sample; return copy; };
  assertFixture(second.sample === first.sample + 1 &&
    JSON.stringify(normalized(first)) === JSON.stringify(normalized(second)), 'stable_probe_changed_or_wrong_gate');
}

/** Observe only; controlled refusal cases intentionally terminate the fixture
 * without claiming clean TLS shutdown, state export, migration or ownership. */
export async function runProbeScenario({ scenario = 'quiescent', payloadBytes = scenario === 'completed-write-retry' ? 65536 : 257, fragmentPrefix } = {}) {
  assertFixture(SCENARIOS.includes(scenario) && Number.isInteger(payloadBytes) && payloadBytes >= 2 && payloadBytes <= 65536, 'scenario_options');
  if (scenario === 'completed-write-retry') assertFixture(payloadBytes === 65536, 'write_retry_payload_size');
  const prefix = fragmentPrefix ?? (scenario === 'partial-header' ? 3 : 13);
  if (scenario.startsWith('partial-')) assertFixture(Number.isInteger(prefix) &&
    (scenario === 'partial-header' ? prefix >= 1 && prefix <= 4 : prefix >= 6 && prefix < Math.min(payloadBytes, 16384) + 22), 'fragment_prefix');
  assertFixture(!running, 'concurrent_probe_fixture');
  assertFixture(!process.execArgv.some(value => value.startsWith('--tls-keylog')) && !(process.env.NODE_OPTIONS ?? '').includes('--tls-keylog'), 'external_keylog_option');
  running = true;
  const peerScenario = scenario.startsWith('peer-key-update-');
  const peerCompleted = scenario === 'peer-key-update-completed';
  const retryCompleted = scenario === 'completed-read-retry';
  const retryUnrelatedWrite = scenario === 'unrelated-write-read-retry';
  const retryScenario = retryCompleted || retryUnrelatedWrite;
  const writeRetryCompleted = scenario === 'completed-write-retry';
  const allowed = scenario === 'quiescent' || retryCompleted || writeRetryCompleted;
  const graceful = allowed || scenario === 'completed-key-update' || peerCompleted;
  const owned = scope(25000);
  const children = new Set();
  const sockets = new Set();
  const secrets = {};
  let directory;
  let relay;
  let client;
  try {
    await verifyHarness(owned.signal);
    directory = await mkdtemp(join(tmpdir(), 'x10-c2a-pki-'));
    owned.signal.throwIfAborted();
    await chmod(directory, 0o700);
    assertFixture(((await stat(directory)).mode & 0o077) === 0, 'private_directory_permissions');
    const cert = await makeCertificates(directory, children, owned.signal, harness.build.privatePaths.openssl);
    const challenge = randomBytes(16);
    const payload = Buffer.from(Array.from({ length: payloadBytes }, (_, i) => ((i * 29 + 7) & 255) ^ challenge[i % 16]));
    const native = nativeChannel(harness.binary, ['--cert', cert.cert, '--key', cert.key, '--scenario', scenario,
      '--bytes', String(payloadBytes), '--challenge', challenge.toString('hex')], children, owned.signal);
    const listening = await native.wait('listening');
    assertFixture(Number.isInteger(listening.port) && listening.port >= 1 && listening.port <= 65535, 'native_port');
    relay = relayTo(listening.port, sockets, owned.signal);
    await bounded(new Promise((resolve, reject) => { relay.server.once('error', reject); relay.server.listen({ port: 0, host: '127.0.0.1', signal: owned.signal }, resolve); }), 'relay_listen', DEADLINE_MS, owned.signal);
    client = peerScenario
      ? peerClient(relay.server.address().port, cert, scenario, payloadBytes, challenge, children, secrets, owned.signal)
      : independentClient(relay.server.address().port, cert.ca, payload, sockets, secrets, owned.signal);
    await client.secure();
    await native.wait('ready', message => message.scenario === scenario);
    if (peerScenario) { await client.send(); }
    else if (scenario.startsWith('partial-')) {
      relay.prefix(prefix); client.write(); await relay.waitPrefix();
    } else if (writeRetryCompleted) {
      client.socket.pause(); relay.pauseServerReads(); client.write();
    } else if ((graceful && !retryCompleted) || scenario === 'unread-plaintext') {
      if (graceful) client.endOnEcho();
      client.write();
    } else if (scenario === 'write-backpressure') {
      client.socket.pause(); relay.pauseServerReads();
    }
    await bounded(new Promise((resolve, reject) => native.child.stdin.write('STEP\n', error => error ? reject(new ProbeFixtureError('native_step')) : resolve())), 'native_step', DEADLINE_MS, owned.signal);
    const peerReceived = peerScenario ? checkedPeerReceived(await native.wait('peer-update-received'), scenario, payloadBytes) : undefined;
    let retryLifecycle;
    if (retryScenario) {
      const ready = checkedRetryEvent(await native.wait('retry-ready'), 'retry-ready', scenario, payloadBytes);
      assertFixture(client.applicationWrites() === 0, 'application_sent_before_read_retry');
      retryLifecycle = { ready, completed: null, clientApplicationWritesBeforeRetry: 0 };
      if (retryCompleted) {
        client.endOnEcho(); client.write();
        const completed = checkedRetryEvent(await native.wait('retry-completed'), 'retry-completed', scenario, payloadBytes);
        assertFixture(client.receivedBytes() === 0 && client.applicationWrites() === 1, 'echo_before_retry_completion');
        retryLifecycle.completed = completed;
        await bounded(new Promise((resolve, reject) => native.child.stdin.write('STEP\n', error => error ? reject(new ProbeFixtureError('native_step')) : resolve())), 'native_step', DEADLINE_MS, owned.signal);
      }
    }
    let writeRetryLifecycle;
    if (writeRetryCompleted) {
      const ready = checkedWriteRetryEvent(await native.wait('write-retry-ready'), 'write-retry-ready', payloadBytes);
      assertFixture(client.socket.isPaused() && relay.serverReadsPaused() && client.applicationWrites() === 1 && client.receivedBytes() === 0,
        'write_retry_readers_not_paused');
      const refused = checkedProbe(await native.wait('probe', message => message.sample === 1), scenario);
      const repeatedRefused = checkedProbe(await native.wait('probe', message => message.sample === 2), scenario);
      checkRefusal(refused, scenario); checkRefusal(repeatedRefused, scenario);
      checkedImmutablePair(refused, repeatedRefused);
      client.socket.resume(); relay.resumeServerReads();
      assertFixture(!client.socket.isPaused() && !relay.serverReadsPaused(), 'write_retry_readers_not_resumed');
      await stepNative(native, owned.signal);
      const completed = checkedWriteRetryEvent(await native.wait('write-retry-completed'), 'write-retry-completed', payloadBytes);
      // A successful retry can emit its buffered prefix before the JSON event.
      // The client sends the application payload once and never resends it.
      assertFixture(client.applicationWrites() === 1, 'write_retry_duplicate_application_write');
      writeRetryLifecycle = { ready, refused, repeatedRefused, completed,
        immutableRefusedProbes: true, bothReadersResumedBeforeRetry: true, clientApplicationWrites: 1 };
    }
    const firstSample = writeRetryCompleted ? 3 : 1;
    const first = checkedProbe(await native.wait('probe', message => message.sample === firstSample), scenario);
    let immutableRepeatedProbe = false;
    if (graceful || peerScenario) {
      const second = checkedProbe(await native.wait('probe', message => message.sample === firstSample + 1), scenario);
      assertFixture(first.allowed === allowed, 'stable_probe_changed_or_wrong_gate');
      checkedImmutablePair(first, second);
      if (writeRetryCompleted) {
        assertFixture(first.reasons === '0' && first.ledgerRetryCall === 0 && first.ledgerLastCall === 3 &&
          first.ledgerLastOutcome === 1 && first.wbufLeft === 0 && first.wnum === 0, 'completed_write_retry_not_cleared');
        client.endOnEcho();
      }
      if (scenario === 'completed-key-update') assertFixture(first.reasons === '64' &&
        first.readGeneration === '0' && first.writeGeneration === '1' && first.mutationSerial === '3' && first.keyUpdate === -1, 'completed_key_update_not_observed');
      if (peerScenario) {
        assertFixture(first.allowed === false && first.readGeneration === '1' && first.writeGeneration === (peerCompleted ? '1' : '0') &&
          first.mutationSerial === (peerCompleted ? '4' : '3') && first.keyUpdate === (peerCompleted ? -1 : 0) &&
          first.reasons === (peerCompleted ? '64' : '32832') && first.ledgerRetryCall === 0, 'peer_key_update_not_observed');
      }
      immutableRepeatedProbe = true;
    } else checkRefusal(first, scenario);
    if (retryScenario) {
      if (retryCompleted) assertFixture(first.ledgerRetryCall === 0 && first.ledgerLastCall === 3 &&
        first.ledgerLastOutcome === 1, 'completed_retry_not_cleared');
      else {
        assertFixture(client.applicationWrites() === 0, 'unrelated_retry_client_write');
        await client.receivedPayload();
        await bounded(new Promise((resolve, reject) => native.child.stdin.write('STEP\n', error => error ? reject(new ProbeFixtureError('native_step')) : resolve())), 'native_step', DEADLINE_MS, owned.signal);
      }
    }
    if (peerScenario && !peerCompleted) { await stepNative(native, owned.signal); await stepNative(client.channel, owned.signal); }
    const done = await native.wait('done');
    const exit = await bounded(native.closed, 'native_exit', DEADLINE_MS, owned.signal);
    assertFixture(exit.code === 0 && exit.signal === null && native.validOutput() && done.scenario === scenario && done.observed === true && done.allowed === allowed && done.graceful === graceful, 'native_scenario_failed');
    if (writeRetryCompleted) {
      const events = native.messages;
      const expected = ['ready', 'write-retry-ready', 'probe', 'probe', 'write-retry-completed', 'probe', 'probe', 'shutdown', 'done'];
      assertFixture(events.filter(message => expected.includes(message.event)).map(message => message.event).join(',') === expected.join(',') &&
        events.filter(message => message.event === 'probe').map(message => message.sample).join(',') === '1,2,3,4' &&
        done.applicationBytesRead === payloadBytes && done.applicationBytesWritten === payloadBytes && done.pressureBytesCompleted === 0,
      'write_retry_event_order_or_counts');
    }
    if (retryScenario) {
      const events = native.messages.map(message => message.event);
      assertFixture(events.filter(event => event === 'retry-ready').length === 1 &&
        events.filter(event => event === 'retry-completed').length === (retryCompleted ? 1 : 0), 'retry_event_count');
      const readyAt = events.indexOf('retry-ready');
      const completedAt = events.indexOf('retry-completed');
      const probeAt = events.indexOf('probe');
      assertFixture(events.indexOf('ready') < readyAt && readyAt < probeAt && probeAt < events.indexOf('done') &&
        (!retryCompleted || readyAt < completedAt && completedAt < probeAt), 'retry_event_order');
    }
    if (peerScenario) {
      const events = native.messages.map(message => message.event);
      assertFixture(events.filter(event => event === 'peer-update-received').length === 1 &&
        events.indexOf('ready') < events.indexOf('peer-update-received') &&
        events.indexOf('peer-update-received') < events.indexOf('probe') && events.indexOf('probe') < events.indexOf('done'), 'peer_event_order');
      if (!peerCompleted) await client.finish();
    }
    let wire;
    if (graceful) {
      await client.finish(); await relay.waitClosed();
      wire = verifyHandshakeCapture({ ...relay.capture, secrets, clientRandom: client.random(),
        expected: { clientApplication: payload, serverApplication: payload }, negotiated: client.negotiated(),
        clientFin: relay.observed.clientFin, serverFin: relay.observed.serverFin, expectedServerKeyUpdates: scenario === 'completed-key-update' || peerCompleted ? 1 : 0,
        expectedClientKeyUpdates: peerCompleted ? 1 : 0 });
      if (peerCompleted) assertFixture(wire.directions.client.beforeCloseNotify.epoch === 1 &&
        wire.directions.server.beforeCloseNotify.epoch === 1 &&
        BigInt(`0x${first.readNextSequence}`) === BigInt(wire.directions.client.beforeCloseNotify.nextSequence) &&
        BigInt(`0x${first.writeNextSequence}`) === BigInt(wire.directions.server.beforeCloseNotify.nextSequence), 'peer_wire_probe_sequence_mismatch');
      else assertFixture(first.readGeneration === '0' && first.writeGeneration === (scenario === 'completed-key-update' ? '1' : '0') &&
        BigInt(`0x${first.readNextSequence}`) === BigInt(wire.directions.client.applicationRecords) &&
        BigInt(`0x${first.writeNextSequence}`) === BigInt(wire.directions.server.applicationRecords), 'wire_probe_sequence_mismatch');
    }
    assertFixture(relay.observed.frontConnections === 1 && relay.observed.backConnections === 1, 'connection_count');
    return { schemaVersion: 1, recordKind: 'research-openssl-read-only-probe-result', outcome: 'pass', scenario,
      negotiated: client.negotiated(), probe: first, immutableRepeatedProbe, wire: wire ?? null,
      topology: 'two-leg-recording-relay-not-migration', clientConnections: 1, serverConnections: 1,
      fragmentPrefix: scenario.startsWith('partial-') ? prefix : null, fixtureGracefulShutdown: done.graceful,
      ...(retryLifecycle ? { retryLifecycle } : {}), ...(peerReceived ? { peerReceived } : {}),
      ...(writeRetryLifecycle ? { writeRetryLifecycle } : {}),
      identity: structuredClone(harness.identity), semanticExportImport: false, migration: false, nativeNginxIntegration: false };
  } catch (error) {
    if (owned.signal.aborted) throw owned.signal.reason;
    if (error instanceof ProbeFixtureError || error?.name === 'HandshakeOracleError') throw error;
    throw new ProbeFixtureError('probe_fixture_failed');
  } finally {
    for (const socket of sockets) socket.destroy();
    try { if (relay?.server.listening) { relay.server.close(); relay.server.unref(); } }
    finally {
      try { await reap(children); }
      finally {
        try { for (const value of Object.values(secrets)) value.fill(0); client?.random()?.fill(0); client?.clear?.(); if (directory) await rm(directory, { recursive: true, force: true }); }
        finally { running = false; owned.close(); }
      }
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const all = process.argv[2] === '--all';
  const work = async () => {
    try {
      await prepareProbeHarness();
      const observations = [];
      for (const scenario of all ? SCENARIOS : [process.argv[2] ?? 'quiescent']) observations.push(await runProbeScenario({ scenario }));
      console.log(JSON.stringify({ schemaVersion: 1, outcome: 'pass', observations }));
    } finally { await cleanupProbeHarness(); }
  };
  work().catch(error => {
    console.error(JSON.stringify({ outcome: 'fail', reason: error instanceof ProbeFixtureError ? error.code : 'probe_dependency_failed' }));
    process.exitCode = [130, 143].includes(error?.exitCode) ? error.exitCode : 1;
  });
}
