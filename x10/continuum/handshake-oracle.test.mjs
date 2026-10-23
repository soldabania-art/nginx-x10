import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHmac } from 'node:crypto';
import { verifyHandshakeCapture, HandshakeOracleError, MAX_CAPTURE_BYTES, MAX_CAPTURE_CHUNKS, MAX_CAPTURE_RECORDS } from './handshake-oracle.mjs';

// Public, deliberately synthetic framing units. These are NOT real handshakes,
// certificates or Finished MACs. The separate C/OpenSSL + Node TLS runner owns
// actual handshake/PKI interoperability. No real keylog data is stored here.
// Independent AES/HKDF writer: no import from record.mjs or oracle internals.
const secret = n => Buffer.alloc(32, n);
function label(key, name, n) {
  const l = Buffer.from(`tls13 ${name}`), info = Buffer.concat([Buffer.from([0, n, l.length]), l, Buffer.from([0, 1])]);
  return createHmac('sha256', key).update(info).digest().subarray(0, n);
}
function encrypted(key, sequence, content, type = 23) {
  const nonce = Buffer.from(label(key, 'iv', 12));
  for (let i = 0; i < 8; i++) nonce[11 - i] ^= Number((sequence >> BigInt(8 * i)) & 255n);
  const plain = Buffer.concat([content, Buffer.from([type])]), size = plain.length + 16;
  const header = Buffer.from([23, 3, 3, size >> 8, size & 255]);
  const aes = createCipheriv('aes-128-gcm', label(key, 'key', 16), nonce); aes.setAAD(header);
  return Buffer.concat([header, aes.update(plain), aes.final(), aes.getAuthTag()]);
}
const vector16 = b => Buffer.concat([Buffer.from([b.length >> 8, b.length & 255]), b]);
const vector8 = b => Buffer.concat([Buffer.from([b.length]), b]);
const handshake = (type, body) => Buffer.concat([Buffer.from([type, body.length >> 16, (body.length >> 8) & 255, body.length & 255]), body]);
const extension = (type, data) => Buffer.concat([Buffer.from([type >> 8, type & 255]), vector16(data)]);
const alpn = () => vector16(vector8(Buffer.from('continuum-c1')));
function plainHandshake(message, client = false) {
  return Buffer.concat([Buffer.from([22, 3, client ? 1 : 3, message.length >> 8, message.length & 255]), message]);
}
const CCS = Buffer.from('140303000101', 'hex');
function fixture({ update = false, handshakeSplit = false, length = 257 } = {}) {
  const secrets = { clientHandshake: secret(0x11), serverHandshake: secret(0x22), clientApplication: secret(0x33), serverApplication: secret(0x44) };
  const random = secret(0x55), sid = Buffer.from('01020304', 'hex');
  const clientHello = Buffer.concat([Buffer.from([3, 3]), random, vector8(sid), vector16(Buffer.from([0x13, 1])), Buffer.from([1, 0]),
    vector16(Buffer.concat([extension(43, Buffer.from([2, 3, 4])), extension(16, alpn())]))]);
  const serverHello = Buffer.concat([Buffer.from([3, 3]), secret(0x66), vector8(sid), Buffer.from([0x13, 1, 0]), vector16(extension(43, Buffer.from([3, 4])))]);
  const ee = handshake(8, vector16(extension(16, alpn())));
  const flight = Buffer.concat([ee, handshake(11, Buffer.from('synthetic certificate framing')), handshake(15, Buffer.from('synthetic certificate verify framing')), handshake(20, secret(0x77))]);
  const client = [plainHandshake(handshake(1, clientHello), true), Buffer.from(CCS), encrypted(secrets.clientHandshake, 0n, handshake(20, secret(0x88)), 22)];
  const server = [plainHandshake(handshake(2, serverHello)), Buffer.from(CCS)];
  if (handshakeSplit) {
    const cuts = [1, 7, flight.length - 9, flight.length]; let begin = 0, sequence = 0n;
    for (const end of cuts) { server.push(encrypted(secrets.serverHandshake, sequence++, flight.subarray(begin, end), 22)); begin = end; }
  } else server.push(encrypted(secrets.serverHandshake, 0n, flight, 22));
  const payload = Buffer.from(Array.from({ length }, (_, i) => (i * 29 + 7) & 255));
  client.push(encrypted(secrets.clientApplication, 0n, payload), encrypted(secrets.clientApplication, 1n, Buffer.from([1, 0]), 21));
  let serverSecret = secrets.serverApplication;
  if (update) { server.push(encrypted(serverSecret, 0n, Buffer.from([24, 0, 0, 1, 0]), 22)); serverSecret = label(serverSecret, 'traffic upd', 32); }
  server.push(encrypted(serverSecret, 0n, payload), encrypted(serverSecret, 1n, Buffer.from([1, 0]), 21));
  const input = { clientToServer: client, serverToClient: server, clientRandom: random, secrets,
    expected: { clientApplication: Buffer.from(payload), serverApplication: Buffer.from(payload) },
    negotiated: { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', alpn: 'continuum-c1', authorized: true },
    clientFin: true, serverFin: true, expectedServerKeyUpdates: update ? 1 : 0 };
  return { input, client, server, clientHello, serverHello, flight, payload, serverSecret };
}
function requestedFixture() {
  const f = fixture(), { secrets } = f.input;
  const clientSecret = label(secrets.clientApplication, 'traffic upd', 32);
  const serverSecret = label(secrets.serverApplication, 'traffic upd', 32);
  // Deliberately different segmentation before/after each update distinguishes
  // lifetime application-record totals from the next sequence in the new epoch.
  f.client.splice(3, 2,
    encrypted(secrets.clientApplication, 0n, f.payload.subarray(0, 3)),
    encrypted(secrets.clientApplication, 1n, f.payload.subarray(3, 11)),
    encrypted(secrets.clientApplication, 2n, Buffer.from([24, 0, 0, 1, 1]), 22),
    encrypted(clientSecret, 0n, f.payload.subarray(11)),
    encrypted(clientSecret, 1n, Buffer.from([1, 0]), 21));
  f.server.splice(3, 2,
    encrypted(secrets.serverApplication, 0n, f.payload.subarray(0, 7)),
    encrypted(secrets.serverApplication, 1n, Buffer.from([24, 0, 0, 1, 0]), 22),
    encrypted(serverSecret, 0n, f.payload.subarray(7, 19)),
    encrypted(serverSecret, 1n, f.payload.subarray(19)),
    encrypted(serverSecret, 2n, Buffer.from([1, 0]), 21));
  f.input.expectedClientKeyUpdates = 1; f.input.expectedServerKeyUpdates = 1;
  return { ...f, clientSecret, serverSecret };
}
function rejected(input, expectedCode) {
  assert.throws(() => verifyHandshakeCapture(input), error => error instanceof HandshakeOracleError
    && error.message === 'TLS capture rejected' && /^oracle_[a-z_]+$/.test(error.code)
    && (!expectedCode || error.code === expectedCode));
}
function chunks(wire, steps) {
  const output = []; let at = 0, n = 0;
  while (at < wire.length) { const end = Math.min(wire.length, at + steps[n++ % steps.length]); output.push(wire.subarray(at, end)); at = end; }
  return output;
}

test('complete synthetic framing is independently assembled across TCP chunk schedules', () => {
  for (const steps of [[1], [2, 3, 5, 13], [127, 1, 4096]]) {
    const { input } = fixture({ handshakeSplit: true });
    input.clientToServer = chunks(Buffer.concat(input.clientToServer), steps);
    input.serverToClient = chunks(Buffer.concat(input.serverToClient), steps.toReversed());
    const result = verifyHandshakeCapture(input);
    assert.equal(result.passed, true); assert.equal(result.independentFinishedMacVerification, false);
    assert.equal(result.fullHandshakeVerifier, false); assert.equal(result.migration, false);
    assert.deepEqual(result.directions.client, { captureRecords: 5, preApplicationRecords: 3, helloRecords: 1,
      compatibilityCCSRecords: 1, encryptedHandshakeRecords: 1, applicationRecords: 1, applicationBytes: 257, keyUpdates: 0,
      beforeCloseNotify: { epoch: 0, nextSequence: 1 }, finalEpoch: 0, finalNextSequence: 2, closeNotify: true, trailingBytes: 0 });
    assert.equal(result.directions.server.encryptedHandshakeRecords, 4);
    assert.equal(result.directions.server.preApplicationRecords, 6);
    assert.equal(result.directions.server.closeNotify, true);
    for (const s of Object.values(input.secrets)) assert.equal(JSON.stringify(result).includes(s.toString('hex')), false);
  }
});

test('captured input bytes and secrets remain caller-owned and unchanged', () => {
  const { input } = fixture(), before = JSON.stringify(input);
  verifyHandshakeCapture(input); assert.equal(JSON.stringify(input), before);
});

test('missing or corrupt first application record is rejected without boundary search', () => {
  const missing = fixture(); missing.client.splice(3, 1); rejected(missing.input, 'oracle_authentication');
  const corrupt = fixture(); corrupt.client[3][corrupt.client[3].length - 1] ^= 1; rejected(corrupt.input, 'oracle_authentication');
  const gap = fixture(); gap.client[3] = encrypted(gap.input.secrets.clientApplication, 1n, gap.payload); rejected(gap.input, 'oracle_authentication');
  const wrongEpoch = fixture(); wrongEpoch.client[3] = encrypted(label(wrongEpoch.input.secrets.clientApplication, 'traffic upd', 32), 0n, wrongEpoch.payload);
  rejected(wrongEpoch.input, 'oracle_authentication');
});

test('valid later application records cannot hide an earlier corrupt or omitted record', () => {
  const { input, client, payload } = fixture();
  client[3][client[3].length - 2] ^= 1;
  client.splice(4, 0, encrypted(input.secrets.clientApplication, 0n, payload));
  rejected(input, 'oracle_authentication');
  const omitted = fixture(); omitted.client[3] = encrypted(omitted.input.secrets.clientApplication, 1n, omitted.payload);
  omitted.client.splice(4, 0, encrypted(omitted.input.secrets.clientApplication, 0n, omitted.payload));
  rejected(omitted.input, 'oracle_authentication');
});

test('late ciphertext, empty application, control record and incomplete tails cannot follow close_notify', () => {
  for (const tail of [Buffer.from([23]), Buffer.from([23, 3, 3, 0]), Buffer.from([23, 3, 3, 0, 20, 1]), Buffer.from('garbage')]) {
    const f = fixture(); f.server.push(tail); rejected(f.input);
  }
  for (const type of [23, 22, 21]) {
    const f = fixture(); f.server.push(encrypted(f.input.secrets.serverApplication, 2n, Buffer.alloc(0), type)); rejected(f.input, 'oracle_trailing');
  }
  const corrupt = fixture(), tail = encrypted(corrupt.input.secrets.serverApplication, 2n, Buffer.from('late'));
  tail[tail.length - 1] ^= 1; corrupt.server.push(tail); rejected(corrupt.input, 'oracle_trailing');
});

test('FIN alone, missing close_notify and non-close alerts never satisfy closure', () => {
  for (const key of ['clientFin', 'serverFin']) { const f = fixture(); f.input[key] = false; rejected(f.input, 'oracle_terminal'); }
  for (const key of ['client', 'server']) { const f = fixture(); f[key].pop(); rejected(f.input, 'oracle_close_notify'); }
  const f = fixture(); f.client[4] = encrypted(f.input.secrets.clientApplication, 1n, Buffer.from([2, 0]), 21); rejected(f.input, 'oracle_close_notify');
});

test('exact concatenated application data allows segmentation but no prefix-only success', () => {
  const f = fixture(); f.client.splice(3, 2,
    encrypted(f.input.secrets.clientApplication, 0n, f.payload.subarray(0, 1)),
    encrypted(f.input.secrets.clientApplication, 1n, f.payload.subarray(1)),
    encrypted(f.input.secrets.clientApplication, 2n, Buffer.from([1, 0]), 21));
  assert.equal(verifyHandshakeCapture(f.input).directions.client.applicationRecords, 2);
  const short = fixture(); short.client[3] = encrypted(short.input.secrets.clientApplication, 0n, short.payload.subarray(0, -1)); rejected(short.input, 'oracle_close_notify');
  const extra = fixture(); extra.client[3] = encrypted(extra.input.secrets.clientApplication, 0n, Buffer.concat([extra.payload, Buffer.from([0])])); rejected(extra.input, 'oracle_application');
  const changed = fixture(); changed.payload[7] ^= 1; changed.client[3] = encrypted(changed.input.secrets.clientApplication, 0n, changed.payload); rejected(changed.input, 'oracle_application');
});

test('direction keys, duplicate sequence and record reordering fail authentication', () => {
  const f = fixture(); [f.input.secrets.clientApplication, f.input.secrets.serverApplication] = [f.input.secrets.serverApplication, f.input.secrets.clientApplication]; rejected(f.input, 'oracle_authentication');
  const duplicate = fixture(); duplicate.client.splice(4, 0, Buffer.from(duplicate.client[3])); rejected(duplicate.input, 'oracle_authentication');
  const swapped = fixture(); [swapped.server[3], swapped.server[4]] = [swapped.server[4], swapped.server[3]]; rejected(swapped.input, 'oracle_authentication');
});

test('optional server KeyUpdate authenticates old epoch then resets only that direction', () => {
  const f = fixture({ update: true }), result = verifyHandshakeCapture(f.input);
  assert.equal(result.directions.server.keyUpdates, 1); assert.equal(result.directions.client.keyUpdates, 0);
  assert.deepEqual(result.directions.client.beforeCloseNotify, { epoch: 0, nextSequence: 1 });
  assert.deepEqual(result.directions.server.beforeCloseNotify, { epoch: 1, nextSequence: 1 });
  const wrongSequence = fixture({ update: true }); wrongSequence.server[4] = encrypted(wrongSequence.serverSecret, 1n, wrongSequence.payload); rejected(wrongSequence.input, 'oracle_authentication');
  const wrongSecret = fixture({ update: true }); wrongSecret.server[4] = encrypted(wrongSecret.input.secrets.serverApplication, 0n, wrongSecret.payload); rejected(wrongSecret.input, 'oracle_authentication');
  const requested = fixture({ update: true }); requested.server[3] = encrypted(requested.input.secrets.serverApplication, 0n, Buffer.from([24, 0, 0, 1, 1]), 22); rejected(requested.input, 'oracle_key_update');
  const unannounced = fixture({ update: true }); unannounced.input.expectedServerKeyUpdates = 0; rejected(unannounced.input, 'oracle_key_update');
  const missing = fixture(); missing.input.expectedServerKeyUpdates = 1; rejected(missing.input, 'oracle_key_update');
  const clientUpdate = fixture(); clientUpdate.client[3] = encrypted(clientUpdate.input.secrets.clientApplication, 0n, Buffer.from([24, 0, 0, 1, 0]), 22); rejected(clientUpdate.input, 'oracle_key_update');
});

test('requested client KeyUpdate remains unsupported unless explicitly selected', () => {
  for (const explicitZero of [false, true]) {
    const f = requestedFixture();
    if (explicitZero) f.input.expectedClientKeyUpdates = 0;
    else delete f.input.expectedClientKeyUpdates;
    rejected(f.input, 'oracle_key_update');
  }
  for (const invalid of [-1, 2, null, true, 1n, NaN, '1']) {
    const f = requestedFixture(); f.input.expectedClientKeyUpdates = invalid; rejected(f.input, 'oracle_input');
  }
  const mismatch = requestedFixture(); mismatch.input.expectedServerKeyUpdates = 0; rejected(mismatch.input, 'oracle_input');
});

test('requested client KeyUpdate and server response authenticate independent epochs and exact data', () => {
  for (const steps of [[1], [3, 17, 4096]]) {
    const f = requestedFixture(), before = JSON.stringify(f.input);
    f.input.clientToServer = chunks(Buffer.concat(f.client), steps);
    f.input.serverToClient = chunks(Buffer.concat(f.server), steps.toReversed());
    const result = verifyHandshakeCapture(f.input);
    for (const name of ['client', 'server']) {
      const d = result.directions[name];
      assert.equal(d.keyUpdates, 1); assert.equal(d.applicationRecords, 3);
      assert.equal(d.applicationBytes, f.payload.length); assert.equal(d.finalEpoch, 1);
      assert.equal(d.closeNotify, true); assert.equal(d.trailingBytes, 0);
    }
    assert.deepEqual(result.directions.client.beforeCloseNotify, { epoch: 1, nextSequence: 1 });
    assert.deepEqual(result.directions.server.beforeCloseNotify, { epoch: 1, nextSequence: 2 });
    assert.equal(result.directions.client.finalNextSequence, 2);
    assert.equal(result.directions.server.finalNextSequence, 3);
    // compare the original arrays too: oracle never owns or wipes caller bytes.
    f.input.clientToServer = f.client; f.input.serverToClient = f.server;
    assert.equal(JSON.stringify(f.input), before);
  }
});

test('requested profile rejects missing response, wrong request byte and extra updates', () => {
  const missingClient = fixture({ update: true }); missingClient.input.expectedClientKeyUpdates = 1;
  rejected(missingClient.input, 'oracle_key_update');
  const missingServer = requestedFixture(), { serverApplication } = missingServer.input.secrets;
  // A complete authenticated old-epoch server stream cannot discharge a
  // request merely by delivering the exact expected payload and close_notify.
  missingServer.server.splice(3, missingServer.server.length - 3,
    encrypted(serverApplication, 0n, missingServer.payload), encrypted(serverApplication, 1n, Buffer.from([1, 0]), 21));
  rejected(missingServer.input, 'oracle_key_update');
  for (const request of [0, 2, 255]) {
    const f = requestedFixture(); f.client[5] = encrypted(f.input.secrets.clientApplication, 2n, Buffer.from([24, 0, 0, 1, request]), 22);
    rejected(f.input, 'oracle_key_update');
  }
  const recursive = requestedFixture(); recursive.server[4] = encrypted(recursive.input.secrets.serverApplication, 1n, Buffer.from([24, 0, 0, 1, 1]), 22);
  rejected(recursive.input, 'oracle_key_update');
  const extra = requestedFixture(); extra.client.splice(7, 0, encrypted(extra.clientSecret, 1n, Buffer.from([24, 0, 0, 1, 1]), 22));
  rejected(extra.input, 'oracle_key_update');
});

test('requested profile rejects premature keys, retained old keys and sequences in either direction', () => {
  for (const name of ['client', 'server']) {
    const updateIndex = name === 'client' ? 5 : 4, oldSequence = name === 'client' ? 2n : 1n;
    const request = name === 'client' ? 1 : 0, offset = name === 'client' ? 11 : 7, end = name === 'client' ? 257 : 19;
    const premature = requestedFixture();
    premature[name][updateIndex] = encrypted(premature[`${name}Secret`], oldSequence, Buffer.from([24, 0, 0, 1, request]), 22);
    rejected(premature.input, 'oracle_authentication');
    const wrongKey = requestedFixture();
    wrongKey[name][updateIndex + 1] = encrypted(wrongKey.input.secrets[`${name}Application`], 0n, wrongKey.payload.subarray(offset, end));
    rejected(wrongKey.input, 'oracle_authentication');
    for (const sequence of [1n, oldSequence + 1n]) {
      const wrongSequence = requestedFixture();
      wrongSequence[name][updateIndex + 1] = encrypted(wrongSequence[`${name}Secret`], sequence, wrongSequence.payload.subarray(offset, end));
      rejected(wrongSequence.input, 'oracle_authentication');
    }
    const skipped = requestedFixture(); skipped[name].splice(updateIndex, 1); rejected(skipped.input, 'oracle_authentication');
    const corruptClose = requestedFixture(); corruptClose[name].at(-1)[5] ^= 1; rejected(corruptClose.input, 'oracle_authentication');
  }
});

test('requested profile requires application data after both updates and exact new-epoch closure', () => {
  for (const name of ['client', 'server']) {
    const f = requestedFixture(), initial = f.input.secrets[`${name}Application`];
    f[name].splice(3, f[name].length - 3,
      encrypted(initial, 0n, f.payload),
      encrypted(initial, 1n, Buffer.from([24, 0, 0, 1, name === 'client' ? 1 : 0]), 22),
      encrypted(f[`${name}Secret`], 0n, Buffer.from([1, 0]), 21));
    rejected(f.input, 'oracle_key_update');
    const missingClose = requestedFixture(); missingClose[name].pop(); rejected(missingClose.input, 'oracle_close_notify');
    const trailing = requestedFixture(); trailing[name].push(encrypted(trailing[`${name}Secret`], name === 'client' ? 2n : 3n, Buffer.from('late')));
    rejected(trailing.input, 'oracle_trailing');
  }
  const changed = requestedFixture(), wrong = Buffer.from(changed.payload.subarray(11)); wrong[0] ^= 1;
  changed.client[6] = encrypted(changed.clientSecret, 0n, wrong); rejected(changed.input, 'oracle_application');
  const short = requestedFixture(); short.client[6] = encrypted(short.clientSecret, 0n, short.payload.subarray(11, -1));
  rejected(short.input, 'oracle_close_notify');
  const noFin = requestedFixture(); noFin.input.serverFin = false; rejected(noFin.input, 'oracle_terminal');
});

test('wire Hello version, cipher, session identity, client random and encrypted ALPN are checked', () => {
  for (const mutate of [f => f.input.clientRandom[0] ^= 1, f => f.serverHello[39] ^= 1,
    f => { f.serverHello[0] = 3; f.serverHello[1] = 1; }, f => f.serverHello[38] = 2,
    f => f.serverHello.set(Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex'), 2)]) {
    const f = fixture(); mutate(f); f.server[0] = plainHandshake(handshake(2, f.serverHello)); rejected(f.input, 'oracle_profile');
  }
  const badAlpn = fixture(); badAlpn.flight[badAlpn.flight.indexOf(Buffer.from('continuum-c1'))] ^= 1;
  badAlpn.server[2] = encrypted(badAlpn.input.secrets.serverHandshake, 0n, badAlpn.flight, 22); rejected(badAlpn.input, 'oracle_profile');
  const wrongCipher = fixture(); wrongCipher.serverHello[39] = 0x13; wrongCipher.serverHello[40] = 2;
  wrongCipher.server[0] = plainHandshake(handshake(2, wrongCipher.serverHello)); rejected(wrongCipher.input, 'oracle_profile');
});

test('Finished structural boundary, handshake framing and compatibility CCS fail closed', () => {
  const short = fixture(); short.client[2] = encrypted(short.input.secrets.clientHandshake, 0n, handshake(20, Buffer.alloc(31)), 22); rejected(short.input, 'oracle_handshake');
  const trailing = fixture(); trailing.client[2] = encrypted(trailing.input.secrets.clientHandshake, 0n, Buffer.concat([handshake(20, secret(1)), handshake(20, secret(2))]), 22); rejected(trailing.input, 'oracle_handshake');
  const wrongType = fixture(); wrongType.client[2] = encrypted(wrongType.input.secrets.clientHandshake, 0n, handshake(20, secret(1)), 23); rejected(wrongType.input, 'oracle_handshake');
  const missing = fixture(); missing.client.splice(2, 1); rejected(missing.input, 'oracle_authentication');
  const duplicateCcs = fixture(); duplicateCcs.client.splice(2, 0, Buffer.from(CCS)); rejected(duplicateCcs.input, 'oracle_profile');
  const lateCcs = fixture(); lateCcs.client.splice(3, 0, Buffer.from(CCS)); rejected(lateCcs.input, 'oracle_record');
});

test('metadata cannot override wire profile or missing TLS authorization', () => {
  for (const change of [{ protocol: 'TLSv1.2' }, { cipher: 'TLS_AES_256_GCM_SHA384' }, { alpn: 'http/1.1' }, { authorized: false }]) {
    const f = fixture(); Object.assign(f.input.negotiated, change); rejected(f.input, 'oracle_profile');
  }
  const f = fixture(); f.input.negotiated = { ...f.input.negotiated, banner: 'TLSv1.3' }; rejected(f.input, 'oracle_input');
});

test('input and budget failures expose only fixed safe errors', () => {
  const mutations = [f => f.input.clientToServer = Buffer.alloc(MAX_CAPTURE_BYTES + 1),
    f => f.input.clientToServer = Array.from({ length: MAX_CAPTURE_CHUNKS + 1 }, () => Buffer.alloc(0)),
    f => f.input.clientToServer = Array.from({ length: MAX_CAPTURE_RECORDS + 1 }, () => Buffer.from(CCS)),
    f => f.input.secrets.clientApplication = Buffer.alloc(31), f => f.input.expected.clientApplication = Buffer.alloc(0),
    f => f.input.expectedServerKeyUpdates = 2, f => f.input.extra = 'never echoed'];
  for (const mutate of mutations) { const f = fixture(); mutate(f); rejected(f.input); }
  const f = fixture(); let invoked = false;
  Object.defineProperty(f.input.negotiated, 'authorized', { enumerable: true, get() { invoked = true; return true; } });
  rejected(f.input, 'oracle_input'); assert.equal(invoked, false);
});
