// C1 research fixture: authenticated Node TLS client -> recording relay ->
// native OpenSSL server. Two TCP legs are intentional; this is NOT migration.
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, chmod, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { createServer, createConnection } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyHandshakeCapture } from './handshake-oracle.mjs';

const SOURCE = fileURLToPath(new URL('./handshake-server.c', import.meta.url));
const DEADLINE_MS = 12000;
const CAPTURE_LIMIT = 262144;
const SCENARIOS = ['valid', 'unknown-ca', 'wrong-hostname', 'tls12-only', 'cipher-mismatch', 'alpn-mismatch'];
const SECRET_LABELS = Object.freeze({
  CLIENT_HANDSHAKE_TRAFFIC_SECRET: 'clientHandshake', SERVER_HANDSHAKE_TRAFFIC_SECRET: 'serverHandshake',
  CLIENT_TRAFFIC_SECRET_0: 'clientApplication', SERVER_TRAFFIC_SECRET_0: 'serverApplication',
});
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const assertFixture = (condition, code) => { if (!condition) throw new HandshakeFixtureError(code); };
let nodeBinaryHash;

export class HandshakeFixtureError extends Error {
  constructor(code) { super(code); this.name = 'HandshakeFixtureError'; this.code = code; }
}
function bounded(promise, code, milliseconds = DEADLINE_MS, signal) {
  let timer;
  let onAbort;
  const interruption = signal ? new Promise((_, reject) => {
    onAbort = () => reject(signal.reason ?? new HandshakeFixtureError('fixture_interrupted'));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  }) : new Promise(() => {});
  return Promise.race([promise, interruption, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new HandshakeFixtureError(code)), milliseconds);
  })]).finally(() => { clearTimeout(timer); if (onAbort) signal.removeEventListener('abort', onAbort); });
}
function trackedSpawn(command, args, children, signal) {
  signal.throwIfAborted();
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], signal, killSignal: 'SIGTERM' });
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
function nativeChannel(binary, args, children, signal) {
  const process = trackedSpawn(binary, args, children, signal);
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
    if (outputBytes > 16384) { failure = true; process.child.kill('SIGKILL'); wake(); return; }
    pending += chunk.toString('utf8');
    while (pending.includes('\n')) {
      const end = pending.indexOf('\n');
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      try {
        const value = JSON.parse(line);
        if (!value || typeof value !== 'object' || typeof value.event !== 'string' || messages.length >= 16) throw new Error();
        messages.push(value);
      } catch { failure = true; process.child.kill('SIGKILL'); }
    }
    wake();
  });
  process.child.stderr.on('data', chunk => {
    stderrBytes += chunk.length;
    if (stderrBytes > 16384) { failure = true; process.child.kill('SIGKILL'); }
  });
  process.closed.then(value => { closed = value; if (pending.length) failure = true; wake(); });
  const wait = event => bounded(new Promise((resolve, reject) => {
    const callback = () => {
      if (failure) { waiters.delete(callback); reject(new HandshakeFixtureError('native_output_invalid')); return; }
      const message = messages.find(item => item.event === event);
      if (message) { waiters.delete(callback); resolve(message); }
      else if (closed) { waiters.delete(callback); reject(new HandshakeFixtureError('native_early_exit')); }
    };
    waiters.add(callback); callback();
  }), 'native_event_timeout', DEADLINE_MS, signal);
  return { ...process, messages, wait, validOutput: () => !failure && pending.length === 0 };
}
async function makeCertificates(directory, children, signal) {
  const path = name => join(directory, name);
  await command('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-sha256', '-days', '1', '-subj', '/CN=Continuum-C1-Test-CA', '-keyout', path('ca.key'), '-out', path('ca.crt'),
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], children, signal);
  await command('openssl', ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-sha256', '-subj', '/CN=continuum.test', '-keyout', path('leaf.key'), '-out', path('leaf.csr')], children, signal);
  signal.throwIfAborted();
  await writeFile(path('leaf.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:continuum.test\n', { mode: 0o600 });
  await command('openssl', ['x509', '-req', '-in', path('leaf.csr'), '-CA', path('ca.crt'), '-CAkey', path('ca.key'),
    '-set_serial', '0x1001', '-days', '1', '-sha256', '-extfile', path('leaf.ext'), '-out', path('leaf.crt')], children, signal);
  await Promise.all([chmod(path('ca.key'), 0o600), chmod(path('leaf.key'), 0o600)]);
  return { cert: path('leaf.crt'), key: path('leaf.key'), ca: await readFile(path('ca.crt')) };
}
function createRelay(port, sockets, signal) {
  const capture = { clientToServer: [], serverToClient: [] };
  const observed = { clientFin: false, serverFin: false, frontClosed: false, backClosed: false, frontConnections: 0, backConnections: 0 };
  const waiters = new Set();
  let failed = false;
  let captureBytes = 0;
  const wake = () => { for (const callback of waiters) callback(); };
  const server = createServer({ allowHalfOpen: true }, front => {
    sockets.add(front);
    observed.frontConnections++;
    if (observed.frontConnections !== 1) { failed = true; front.destroy(); wake(); return; }
    const back = createConnection({ host: '127.0.0.1', port, allowHalfOpen: true, signal });
    sockets.add(back);
    back.once('connect', () => { observed.backConnections++; });
    const record = (direction, chunk) => {
      captureBytes += chunk.length;
      if (captureBytes > CAPTURE_LIMIT) { failed = true; front.destroy(); back.destroy(); wake(); }
      else capture[direction].push(Buffer.from(chunk));
    };
    front.on('data', chunk => record('clientToServer', chunk));
    back.on('data', chunk => record('serverToClient', chunk));
    front.on('end', () => { observed.clientFin = true; wake(); });
    back.on('end', () => { observed.serverFin = true; wake(); });
    front.on('close', hadError => { observed.frontClosed = true; failed ||= hadError; wake(); });
    back.on('close', hadError => { observed.backClosed = true; failed ||= hadError; wake(); });
    front.on('error', () => { failed = true; back.destroy(); wake(); });
    back.on('error', () => { failed = true; front.destroy(); wake(); });
    front.pipe(back); back.pipe(front);
  });
  server.on('error', () => { failed = true; wake(); });
  const waitClosed = () => bounded(new Promise((resolve, reject) => {
    const callback = () => {
      if (failed) { waiters.delete(callback); reject(new HandshakeFixtureError('relay_transport_failed')); }
      else if (observed.frontClosed && observed.backClosed) { waiters.delete(callback); resolve(); }
    };
    waiters.add(callback); callback();
  }), 'relay_close_timeout', DEADLINE_MS, signal);
  return { server, capture, observed, waitClosed };
}
function runClient(options, payload, sockets, secrets, scenario, signal) {
  signal.throwIfAborted();
  const socket = tlsConnect({ ...options, signal });
  sockets.add(socket);
  const observed = { secureConnect: false, resumed: null, applicationBytesWritten: 0, applicationBytesRead: 0, ended: false, closed: false, errorCode: null };
  let clientRandom;
  let failed;
  let negotiated;
  let received = Buffer.alloc(0);
  socket.on('keylog', line => {
    try {
      assertFixture(line.length <= 512, 'keylog_invalid');
      const parts = line.toString('ascii').trim().split(' ');
      if (!Object.hasOwn(SECRET_LABELS, parts[0])) return;
      assertFixture(parts.length === 3 && /^[0-9a-fA-F]{64}$/.test(parts[1]) && /^[0-9a-fA-F]{64}$/.test(parts[2]), 'keylog_invalid');
      const random = Buffer.from(parts[1], 'hex');
      if (clientRandom) assertFixture(clientRandom.equals(random), 'keylog_random_mismatch');
      else clientRandom = random;
      const name = SECRET_LABELS[parts[0]];
      const secret = Buffer.from(parts[2], 'hex');
      if (secrets[name]) { assertFixture(secrets[name].equals(secret), 'keylog_secret_mismatch'); secret.fill(0); }
      else secrets[name] = secret;
    } catch { failed = new HandshakeFixtureError('keylog_invalid'); socket.destroy(); }
  });
  socket.on('secureConnect', () => {
    try {
      observed.secureConnect = true;
      negotiated = { protocol: socket.getProtocol(), cipher: socket.getCipher()?.standardName,
        alpn: socket.alpnProtocol, authorized: socket.authorized };
      observed.resumed = socket.isSessionReused();
      assertFixture(negotiated.authorized === true && negotiated.protocol === 'TLSv1.3' &&
        negotiated.cipher === 'TLS_AES_128_GCM_SHA256' && negotiated.alpn === 'continuum-c1' &&
        observed.resumed === false, 'negotiated_profile_invalid');
      assertFixture(scenario === 'valid', 'negative_handshake_accepted');
      observed.applicationBytesWritten += payload.length;
      socket.write(payload, error => { if (error) { failed ??= new HandshakeFixtureError('client_write_failed'); socket.destroy(); } });
    } catch (error) { failed = error instanceof HandshakeFixtureError ? error : new HandshakeFixtureError('client_profile_failed'); socket.destroy(); }
  });
  socket.on('data', chunk => {
    if (failed) return;
    if (received.length + chunk.length > payload.length) { failed = new HandshakeFixtureError('application_overflow'); socket.destroy(); return; }
    received = Buffer.concat([received, chunk]);
    observed.applicationBytesRead = received.length;
    if (received.length === payload.length) {
      if (!received.equals(payload)) { failed = new HandshakeFixtureError('application_mismatch'); socket.destroy(); }
      else socket.end();
    }
  });
  socket.on('end', () => { observed.ended = true; });
  socket.on('error', error => { observed.errorCode = typeof error.code === 'string' ? error.code : 'UNKNOWN_TLS_ERROR'; });
  const completed = bounded(new Promise(resolve => socket.once('close', hadError => {
    observed.closed = true;
    if (scenario === 'valid' && (hadError || observed.errorCode || !observed.ended)) failed ??= new HandshakeFixtureError('client_terminal_failed');
    resolve();
  })), 'client_close_timeout', DEADLINE_MS, signal);
  return { socket, observed, completed, negotiated: () => negotiated, failure: () => failed, random: () => clientRandom,
    exactBytes: () => received.equals(payload) };
}
function expectedDenial(scenario, code) {
  const allowed = {
    'unknown-ca': ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT'],
    'wrong-hostname': ['ERR_TLS_CERT_ALTNAME_INVALID'],
    'tls12-only': ['ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'ERR_SSL_UNSUPPORTED_PROTOCOL'],
    'cipher-mismatch': ['ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE', 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE', 'ERR_SSL_NO_SHARED_CIPHER'],
    'alpn-mismatch': ['ERR_SSL_TLSV1_ALERT_NO_APPLICATION_PROTOCOL'],
  };
  return allowed[scenario]?.includes(code) === true;
}

/** Run one finite real handshake. Real traffic keys/wire bytes never leave this
 * function; callers receive public metadata and sanitized oracle counts only. */
export async function runHandshake({ scenario = 'valid', keyUpdate = false, payloadBytes = 257 } = {}) {
  assertFixture(SCENARIOS.includes(scenario) && typeof keyUpdate === 'boolean' && Number.isInteger(payloadBytes) && payloadBytes >= 1 && payloadBytes <= 65536, 'fixture_options_invalid');
  // Reject Node's explicit disk-keylog switches before creating any TLS session.
  // This is not protection against a compromised runtime or external tracing.
  assertFixture(!process.execArgv.some(argument => argument.startsWith('--tls-keylog')) &&
    !(process.env.NODE_OPTIONS ?? '').includes('--tls-keylog'), 'external_keylog_option');
  const children = new Set();
  const sockets = new Set();
  const secrets = {};
  const controller = new AbortController();
  const signal = controller.signal;
  const interrupt = name => {
    const error = new HandshakeFixtureError('fixture_interrupted');
    error.exitCode = name === 'SIGTERM' ? 143 : 130;
    controller.abort(error);
  };
  const onTerm = () => interrupt('SIGTERM');
  const onInt = () => interrupt('SIGINT');
  // Installed before mkdtemp, PKI subprocesses, listeners or other effects.
  process.on('SIGTERM', onTerm);
  process.on('SIGINT', onInt);
  const deadline = setTimeout(() => controller.abort(new HandshakeFixtureError('fixture_deadline')), 25000);
  let directory;
  let relay;
  let client;
  try {
    directory = await mkdtemp(join(tmpdir(), 'x10-continuum-c1-'));
    signal.throwIfAborted();
    await chmod(directory, 0o700);
    assertFixture(((await stat(directory)).mode & 0o077) === 0, 'temporary_directory_permissions');
    const certificates = await makeCertificates(directory, children, signal);
    const binary = join(directory, 'handshake-server');
    const sourceBytes = await readFile(SOURCE);
    await command('cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-o', binary, SOURCE, '-lssl', '-lcrypto'], children, signal);
    assertFixture(sha256(await readFile(SOURCE)) === sha256(sourceBytes), 'source_changed_during_build');
    await chmod(binary, 0o700);
    const versions = (await command('openssl', ['version'], children, signal)).toString('ascii').trim();
    assertFixture(/^[A-Za-z0-9 ._():+-]{1,160}$/.test(versions), 'openssl_identity_invalid');
    nodeBinaryHash ??= readFile(process.execPath).then(sha256);
    const identity = { serverSourceSha256: sha256(sourceBytes), serverBinarySha256: sha256(await readFile(binary)),
      nodeBinarySha256: await nodeBinaryHash, nodeVersion: process.version, nodeOpenSSLVersion: process.versions.openssl, systemOpenSSLVersion: versions };
    const challenge = randomBytes(16);
    const payload = Buffer.from(Array.from({ length: payloadBytes }, (_, i) => ((i * 29 + 7) & 255) ^ challenge[i % 16]));
    const args = ['--cert', certificates.cert, '--key', certificates.key, '--bytes', String(payloadBytes), '--challenge', challenge.toString('hex')];
    if (keyUpdate) args.push('--key-update');
    const native = nativeChannel(binary, args, children, signal);
    const ready = await native.wait('listening');
    assertFixture(Number.isInteger(ready.port) && ready.port >= 1 && ready.port <= 65535, 'native_port_invalid');
    relay = createRelay(ready.port, sockets, signal);
    await bounded(new Promise((resolve, reject) => {
      relay.server.once('error', reject);
      relay.server.listen({ port: 0, host: '127.0.0.1', signal }, resolve);
    }), 'relay_listen_timeout', DEADLINE_MS, signal);
    const options = {
      host: '127.0.0.1', port: relay.server.address().port,
      servername: scenario === 'wrong-hostname' ? 'wrong.continuum.test' : 'continuum.test',
      rejectUnauthorized: true, minVersion: scenario === 'tls12-only' ? 'TLSv1.2' : 'TLSv1.3',
      maxVersion: scenario === 'tls12-only' ? 'TLSv1.2' : 'TLSv1.3',
      ciphers: scenario === 'cipher-mismatch' ? 'TLS_AES_256_GCM_SHA384' :
        scenario === 'tls12-only' ? 'ECDHE-ECDSA-AES128-GCM-SHA256' : 'TLS_AES_128_GCM_SHA256',
      ALPNProtocols: [scenario === 'alpn-mismatch' ? 'wrong-c1' : 'continuum-c1'],
      ...(scenario === 'unknown-ca' ? {} : { ca: certificates.ca }),
    };
    client = runClient(options, payload, sockets, secrets, scenario, signal);
    await client.completed;
    if (client.failure()) throw client.failure();
    const exit = await bounded(native.closed, 'native_close_timeout', DEADLINE_MS, signal);
    assertFixture(native.validOutput(), 'native_output_invalid');
    if (scenario !== 'valid') {
      assertFixture(!client.observed.secureConnect && client.observed.applicationBytesWritten === 0 &&
        client.observed.applicationBytesRead === 0, 'negative_not_rejected_before_application');
      const safeErrorCode = /^[A-Z0-9_\/]{1,80}$/.test(client.observed.errorCode ?? '') ? client.observed.errorCode : 'UNKNOWN';
      assertFixture(expectedDenial(scenario, client.observed.errorCode), `negative_tls_error_unrecognized:${safeErrorCode}`);
      const nativeErrors = native.messages.filter(message => message.event === 'error');
      const mismatch = ['tls12-only', 'cipher-mismatch', 'alpn-mismatch'].includes(scenario);
      assertFixture(exit.code === 1 && exit.signal === null && nativeErrors.length === 1 &&
        (mismatch ? nativeErrors[0].code === 'handshake' && !native.messages.some(message => message.event === 'handshake') :
          ['handshake', 'application_read'].includes(nativeErrors[0].code)) &&
        !native.messages.some(message => ['quiesce', 'shutdown'].includes(message.event)), 'native_negative_application_reached');
      return { schemaVersion: 1, recordKind: 'research-handshake-fixture-result', outcome: 'rejected', scenario,
        rejectedBeforeApplication: true, clientApplicationBytesWritten: 0, clientApplicationBytesRead: 0,
        tlsErrorCode: client.observed.errorCode, nativeErrorCode: nativeErrors[0].code,
        nativeExitedNormally: true, identity, migrationImplemented: false, nativeNginxIntegration: false };
    }
    assertFixture(exit.code === 0 && exit.signal === null, 'native_failed');
    const handshake = await native.wait('handshake');
    const quiesce = await native.wait('quiesce');
    const shutdown = await native.wait('shutdown');
    assertFixture(handshake.version === 'TLSv1.3' && handshake.cipher === 'TLS_AES_128_GCM_SHA256' && handshake.alpn === 'continuum-c1' && handshake.resumed === false, 'native_profile_invalid');
    assertFixture(/^[A-Za-z0-9 ._():+-]{1,160}$/.test(handshake.opensslVersion) &&
      /^[A-Za-z0-9 ._():+-]{1,160}$/.test(handshake.opensslHeadersVersion) &&
      Number.isSafeInteger(handshake.opensslVersionNumber) && handshake.opensslVersionNumber > 0, 'native_backend_identity_invalid');
    identity.serverRuntimeOpenSSLVersion = handshake.opensslVersion;
    identity.serverRuntimeOpenSSLVersionNumber = handshake.opensslVersionNumber;
    identity.serverOpenSSLHeadersVersion = handshake.opensslHeadersVersion;
    assertFixture(quiesce.applicationBytesRead === payloadBytes && quiesce.applicationBytesWritten === payloadBytes && shutdown.clean === true, 'native_application_or_shutdown_invalid');
    await relay.waitClosed();
    assertFixture(client.exactBytes() && relay.observed.frontConnections === 1 && relay.observed.backConnections === 1, 'connection_or_application_invalid');
    assertFixture(Object.values(SECRET_LABELS).every(label => Buffer.isBuffer(secrets[label]) && secrets[label].length === 32), 'handshake_secrets_missing');
    const oracle = verifyHandshakeCapture({ ...relay.capture, secrets, clientRandom: client.random(),
      expected: { clientApplication: payload, serverApplication: payload }, negotiated: client.negotiated(),
      clientFin: relay.observed.clientFin, serverFin: relay.observed.serverFin, expectedServerKeyUpdates: keyUpdate ? 1 : 0 });
    return { schemaVersion: 1, recordKind: 'research-handshake-fixture-result', outcome: 'pass', scenario,
      negotiated: client.negotiated(), resumed: client.observed.resumed, applicationBytesEachDirection: payloadBytes,
      freshChallenge: true, clientConnections: relay.observed.frontConnections, serverConnections: relay.observed.backConnections,
      topology: 'two-leg-recording-relay-not-migration', oracle, identity,
      migrationImplemented: false, openSSLStateExportImport: false, nativeNginxIntegration: false,
      independentFinishedMacVerification: false };
  } catch (error) {
    if (signal.aborted) throw signal.reason;
    if (error instanceof HandshakeFixtureError || (error?.name === 'HandshakeOracleError' && typeof error.code === 'string')) throw error;
    throw new HandshakeFixtureError('handshake_fixture_failed');
  } finally {
    // Close listeners before awaiting any process cleanup that might reject.
    for (const socket of sockets) socket.destroy();
    try {
      if (relay?.server.listening) { relay.server.close(); relay.server.unref(); }
    } finally {
      try {
        const cleanup = [];
        for (const child of children) {
          cleanup.push(bounded(new Promise(resolve => child.once('close', resolve)), 'cleanup_process_timeout', 2000));
          child.kill('SIGKILL');
        }
        await Promise.all(cleanup);
      } finally {
        // Secret wiping and private-file removal run even if reaping fails.
        try {
          for (const secret of Object.values(secrets)) secret.fill(0);
          client?.random()?.fill(0);
          if (directory) await rm(directory, { recursive: true, force: true });
        } finally {
          clearTimeout(deadline);
          process.removeListener('SIGTERM', onTerm);
          process.removeListener('SIGINT', onInt);
        }
      }
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runHandshake().then(result => console.log(JSON.stringify(result))).catch(error => {
    console.error(JSON.stringify({ outcome: 'fail', reason: error instanceof HandshakeFixtureError ? error.code : 'handshake_oracle_failed' }));
    process.exitCode = error instanceof HandshakeFixtureError && [130, 143].includes(error.exitCode) ? error.exitCode : 1;
  });
}
