import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHmac } from 'node:crypto';
import {
  MAX_SEQUENCE, MAX_EPOCH, MAX_RECORDS_PER_KEY, MAX_CONTENT_BYTES, MAX_RECORD_BYTES,
  hkdfExpandLabel, deriveTrafficKeys, nonceFor, recordLength, sealRecord, openRecord,
  advanceSequence, updateTrafficState, encodeKeyUpdate, parseKeyUpdate,
} from './record.mjs';

// PUBLIC TEST VECTORS, never deployment keys. Exact provenance:
// RFC 8448, January 2019, Section 3 "Simple 1-RTT Handshake":
// https://www.rfc-editor.org/rfc/rfc8448.txt
// client/server "c ap traffic"/"s ap traffic", application key/IV derivations,
// and the final 50-octet application_data / 2-octet alert records on pp. 15–16.
// Client application sequence = 0; server application sequence = 1 because its
// preceding NewSessionTicket used application sequence 0. Client alert uses 1,
// server alert uses 2. Expected wires are literal RFC bytes, not local outputs.
const hex = s => Buffer.from(s.replaceAll(/\s/g, ''), 'hex');
const CLIENT_SECRET = hex('9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5');
const SERVER_SECRET = hex('a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643');
const CLIENT_KEY = hex('17422dda596ed5d9acd890e3c63f5051');
const CLIENT_IV = hex('5b78923dee08579033e523d9');
const SERVER_KEY = hex('9f02283b6c9c07efc26bb9f2ac92e356');
const SERVER_IV = hex('cf782b88dd83549aadf1e984');
const PAYLOAD = Buffer.from(Array.from({ length: 50 }, (_, i) => i));
const CLIENT_WIRE = hex(`1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b
  9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4`);
const SERVER_WIRE = hex(`17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e3
  0efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d`);
const CLIENT_ALERT = hex('1703030013c9872760655666b74d7ff1153efd6db6d0b0e3');
const SERVER_ALERT = hex('1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9');
const direction = (secret = CLIENT_SECRET, sequence = 0n, epoch = 0n) => ({ trafficSecret: Buffer.from(secret), epoch, sequence });

// Independent reference construction using public key/IV values and the Node
// OpenSSL AES API. It does not call any record.mjs derivation/framing helpers.
function referenceRecord(key, iv, sequence, content, contentType = 23, padding = 0) {
  const nonce = Buffer.from(iv);
  for (let i = 0; i < 8; i++) nonce[11 - i] ^= Number((sequence >> BigInt(i * 8)) & 255n);
  const inner = Buffer.concat([content, Buffer.from([contentType]), Buffer.alloc(padding)]);
  const length = inner.length + 16;
  const header = Buffer.from([23, 3, 3, length >> 8, length & 255]);
  const cipher = createCipheriv('aes-128-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  return Buffer.concat([header, cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
}
function expandOnly(prk, info, length) {
  let block = Buffer.alloc(0), output = Buffer.alloc(0);
  for (let n = 1; output.length < length; n++) {
    block = createHmac('sha256', prk).update(Buffer.concat([block, info, Buffer.from([n])])).digest();
    output = Buffer.concat([output, block]);
  }
  return output.subarray(0, length);
}
function referenceLabel(secret, label, context, length) {
  const l = Buffer.from(`tls13 ${label}`), size = Buffer.alloc(2); size.writeUInt16BE(length);
  return expandOnly(secret, Buffer.concat([size, Buffer.from([l.length]), l, Buffer.from([context.length]), context]), length);
}
const code = expected => error => error?.code === expected;

test('RFC 8448 public traffic-secret, key and IV known answers', () => {
  const masterPrk = hex('18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919');
  const transcriptHash = hex('9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13');
  assert.deepEqual(hkdfExpandLabel(masterPrk, 'c ap traffic', transcriptHash, 32), CLIENT_SECRET);
  assert.deepEqual(hkdfExpandLabel(masterPrk, 's ap traffic', transcriptHash, 32), SERVER_SECRET);
  assert.deepEqual(deriveTrafficKeys(CLIENT_SECRET), { key: CLIENT_KEY, iv: CLIENT_IV });
  assert.deepEqual(deriveTrafficKeys(SERVER_SECRET), { key: SERVER_KEY, iv: SERVER_IV });
});

test('independent HKDF expansion oracle matches RFC 5869 A.1 before multi-block label comparison', () => {
  // https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
  const prk = hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  assert.deepEqual(createHmac('sha256', hex('000102030405060708090a0b0c')).update(Buffer.alloc(22, 11)).digest(), prk);
  assert.deepEqual(expandOnly(prk, hex('f0f1f2f3f4f5f6f7f8f9'), 42),
    hex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'));
  assert.deepEqual(hkdfExpandLabel(prk, 'continuum test', hex('010203'), 96), referenceLabel(prk, 'continuum test', hex('010203'), 96));
});

test('RFC 8448 client application record seals and opens exact external wire bytes', () => {
  assert.equal(CLIENT_WIRE.length, 72);
  assert.deepEqual(sealRecord(direction(), PAYLOAD), CLIENT_WIRE);
  assert.deepEqual(openRecord(direction(), CLIENT_WIRE), { content: PAYLOAD, contentType: 23, padding: 0 });
  assert.deepEqual(referenceRecord(CLIENT_KEY, CLIENT_IV, 0n, PAYLOAD), CLIENT_WIRE);
});

test('RFC 8448 server sequence-one and following alerts retain independent direction counters', () => {
  assert.deepEqual(sealRecord(direction(SERVER_SECRET, 1n), PAYLOAD), SERVER_WIRE);
  assert.deepEqual(openRecord(direction(SERVER_SECRET, 1n), SERVER_WIRE).content, PAYLOAD);
  assert.deepEqual(sealRecord(direction(CLIENT_SECRET, 1n), hex('0100'), { contentType: 21 }), CLIENT_ALERT);
  assert.deepEqual(sealRecord(direction(SERVER_SECRET, 2n), hex('0100'), { contentType: 21 }), SERVER_ALERT);
  assert.equal(openRecord(direction(SERVER_SECRET, 2n), SERVER_ALERT).contentType, 21);
  assert.throws(() => openRecord(direction(SERVER_SECRET, 0n), SERVER_WIRE), code('bad_record_mac'));
});

test('bad tag, ciphertext, authenticated length, sequence and next-epoch secret reject before plaintext', () => {
  const tag = Buffer.from(CLIENT_WIRE); tag[tag.length - 1] ^= 1;
  const data = Buffer.from(CLIENT_WIRE); data[5] ^= 1;
  const aad = Buffer.concat([CLIENT_WIRE, Buffer.from([0])]); aad.writeUInt16BE(aad.length - 5, 3);
  for (const wire of [tag, data, aad]) assert.throws(() => openRecord(direction(), wire), code('bad_record_mac'));
  assert.throws(() => openRecord(direction(CLIENT_SECRET, 1n), CLIENT_WIRE), code('bad_record_mac'));
  assert.throws(() => openRecord(updateTrafficState(direction()), CLIENT_WIRE), code('bad_record_mac'));
  assert.throws(() => openRecord(direction(SERVER_SECRET), CLIENT_WIRE), code('bad_record_mac'));
  // RFC wire AAD contains no epoch field. Epoch-only relabeling is NOT an AEAD
  // security boundary; trusted continuation ownership must bind that metadata.
  assert.deepEqual(openRecord(direction(CLIENT_SECRET, 0n, 1n), CLIENT_WIRE).content, PAYLOAD);
});

test('record operations do not mutate or implicitly advance supplied state or input bytes', () => {
  const s = direction(), before = Buffer.from(s.trafficSecret), wire = Buffer.from(CLIENT_WIRE), content = Buffer.from(PAYLOAD);
  sealRecord(s, content); openRecord(s, wire);
  const bad = Buffer.from(wire); bad[bad.length - 1] ^= 1; assert.throws(() => openRecord(s, bad));
  assert.deepEqual(s.trafficSecret, before); assert.deepEqual(content, PAYLOAD); assert.deepEqual(wire, CLIENT_WIRE);
  assert.equal(s.sequence, 0n); assert.equal(s.epoch, 0n);
  const next = advanceSequence(s); assert.equal(next.sequence, 1n); next.trafficSecret[0] ^= 1;
  assert.deepEqual(s.trafficSecret, before);
});

test('nonces use a full big-endian uint64 and per-key usage or counter exhaustion fails closed', () => {
  assert.deepEqual(nonceFor(CLIENT_IV, 0n), CLIENT_IV);
  assert.deepEqual(nonceFor(CLIENT_IV, MAX_SEQUENCE), hex('5b78923d11f7a86fcc1adc26'));
  assert.throws(() => advanceSequence(direction(CLIENT_SECRET, MAX_SEQUENCE)), code('sequence_exhausted'));
  assert.throws(() => updateTrafficState(direction(CLIENT_SECRET, 0n, MAX_EPOCH)), code('epoch_exhausted'));
  assert.throws(() => sealRecord(direction(CLIENT_SECRET, MAX_RECORDS_PER_KEY), PAYLOAD), code('key_usage_limit'));
  assert.throws(() => openRecord(direction(CLIENT_SECRET, MAX_RECORDS_PER_KEY), CLIENT_WIRE), code('key_usage_limit'));
  for (const n of [-1n, MAX_SEQUENCE + 1n, 0, '0']) assert.throws(() => nonceFor(CLIENT_IV, n), code('invalid_counter'));
});

test('strict header, exact one-record framing and inner-padding boundaries', () => {
  assert.equal(recordLength(CLIENT_WIRE.subarray(0, 5)), CLIENT_WIRE.length);
  assert.throws(() => recordLength(CLIENT_WIRE.subarray(0, 4)), code('invalid_bytes'));
  for (const p of [0, 1, 2]) { const b = Buffer.from(CLIENT_WIRE.subarray(0, 5)); b[p] ^= 1; assert.throws(() => recordLength(b), code('invalid_record_header')); }
  for (const length of [0, 16, 16402, 65535]) { const h = hex('1703030000'); h.writeUInt16BE(length, 3); assert.throws(() => recordLength(h), code('record_overflow')); }
  assert.throws(() => openRecord(direction(), CLIENT_WIRE.subarray(0, -1)), code('invalid_record_length'));
  assert.throws(() => openRecord(direction(), Buffer.concat([CLIENT_WIRE, CLIENT_WIRE])), code('invalid_record_length'));
  const content = hex('610000'), padded = referenceRecord(CLIENT_KEY, CLIENT_IV, 0n, content, 23, 19);
  assert.deepEqual(openRecord(direction(), padded), { content, contentType: 23, padding: 19 });
  assert.equal(sealRecord(direction(), Buffer.alloc(MAX_CONTENT_BYTES)).length, MAX_RECORD_BYTES);
  assert.throws(() => sealRecord(direction(), Buffer.alloc(MAX_CONTENT_BYTES), { padding: 1 }), code('record_overflow'));
  assert.equal(openRecord(direction(), sealRecord(direction(), Buffer.alloc(0))).content.length, 0);
  assert.throws(() => openRecord(direction(), referenceRecord(CLIENT_KEY, CLIENT_IV, 0n, Buffer.alloc(0), 0)), code('unexpected_message'));
});

test('KeyUpdate is protected with old keys before installing next directional epoch and sequence zero', () => {
  const old = direction(CLIENT_SECRET, 7n), message = hex('1800000100');
  assert.deepEqual(encodeKeyUpdate(false), message); assert.deepEqual(parseKeyUpdate(message), { requestUpdate: false });
  assert.deepEqual(encodeKeyUpdate(true), hex('1800000101'));
  for (const bad of [hex('1800000102'), hex('1900000100'), hex('1800010100')]) assert.throws(() => parseKeyUpdate(bad), code('invalid_key_update'));
  assert.throws(() => parseKeyUpdate(message.subarray(0, 4)), code('invalid_bytes'));
  const ku = referenceRecord(CLIENT_KEY, CLIENT_IV, 7n, message, 22);
  assert.deepEqual(sealRecord(old, message, { contentType: 22 }), ku);
  assert.deepEqual(parseKeyUpdate(openRecord(old, ku).content), { requestUpdate: false });
  const next = updateTrafficState(old), expectedSecret = referenceLabel(CLIENT_SECRET, 'traffic upd', Buffer.alloc(0), 32);
  assert.deepEqual(next.trafficSecret, expectedSecret); assert.equal(next.epoch, 1n); assert.equal(next.sequence, 0n);
  assert.throws(() => openRecord(next, ku), code('bad_record_mac'));
  const key = referenceLabel(expectedSecret, 'key', Buffer.alloc(0), 16), iv = referenceLabel(expectedSecret, 'iv', Buffer.alloc(0), 12);
  const post = referenceRecord(key, iv, 0n, Buffer.from('after update'));
  assert.equal(openRecord(next, post).content.toString(), 'after update');
  assert.throws(() => openRecord(advanceSequence(old), post), code('bad_record_mac'));
  assert.equal(old.sequence, 7n); assert.equal(old.epoch, 0n); assert.deepEqual(old.trafficSecret, CLIENT_SECRET);
});

test('bidirectional non-idle IR preserves partial ciphertext, partially sent wire and plaintext offsets', async () => {
  const { validateContinuationIR, parseContinuationIR } = await import('./state.mjs');
  const incomingContent = Buffer.from('incoming second record\0with bytes');
  const incoming = referenceRecord(CLIENT_KEY, CLIENT_IV, 1n, incomingContent);
  const make = cut => ({
    schema: 'ContinuationIRv0', version: 0, protocol: 'TLS1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', connectionId: '11'.repeat(16),
    ownership: { source: 'source', target: 'target', epoch: '1', nextEpoch: '2', transferNonce: '22'.repeat(32) },
    read: { trafficSecretHex: CLIENT_SECRET.toString('hex'), epoch: '0', sequence: '1' },
    write: { trafficSecretHex: SERVER_SECRET.toString('hex'), epoch: '0', sequence: '2' },
    pending: { readCipher: { hex: incoming.subarray(0, cut).toString('hex'), offset: 0 },
      writeCipher: { hex: SERVER_WIRE.toString('hex'), offset: 19, epoch: '0', sequence: '1' },
      readPlain: { hex: PAYLOAD.toString('hex'), offset: 13 }, writePlain: { hex: Buffer.from('queued outbound tail').toString('hex'), offset: 4 } },
  });
  for (const cut of [1, 4, 5, 13, incoming.length - 1]) {
    const original = validateContinuationIR(make(cut)), restored = parseContinuationIR(Buffer.from(JSON.stringify(original)));
    assert.deepEqual(restored, original);
    const read = direction(hex(restored.read.trafficSecretHex), BigInt(restored.read.sequence), BigInt(restored.read.epoch));
    const write = direction(hex(restored.write.trafficSecretHex), BigInt(restored.write.sequence), BigInt(restored.write.epoch));
    const prefix = hex(restored.pending.readCipher.hex);
    assert.throws(() => openRecord(read, prefix));
    // External fixture assembly, NOT a production stream-parser implementation.
    const complete = Buffer.concat([prefix, incoming.subarray(cut)]);
    assert.equal(complete.length, recordLength(complete.subarray(0, 5)));
    assert.deepEqual(openRecord(read, complete).content, incomingContent);
    assert.deepEqual(hex(restored.pending.readPlain.hex).subarray(restored.pending.readPlain.offset), PAYLOAD.subarray(13));
    const pending = restored.pending.writeCipher, wire = hex(pending.hex);
    assert.deepEqual(Buffer.concat([SERVER_WIRE.subarray(0, pending.offset), wire.subarray(pending.offset)]), SERVER_WIRE);
    const content = hex(restored.pending.writePlain.hex).subarray(restored.pending.writePlain.offset);
    assert.deepEqual(sealRecord(write, content), referenceRecord(SERVER_KEY, SERVER_IV, 2n, content));
    assert.equal(write.sequence, 2n); assert.equal(read.sequence, 1n);
    const tampered = structuredClone(restored); tampered.pending.writeCipher.hex = `${pending.hex.slice(0, -2)}00`;
    assert.throws(() => validateContinuationIR(tampered));
    const wrongEpoch = structuredClone(restored); wrongEpoch.pending.writeCipher.epoch = '1';
    assert.throws(() => validateContinuationIR(wrongEpoch));
    const wrongSequence = structuredClone(restored); wrongSequence.pending.writeCipher.sequence = '0';
    assert.throws(() => validateContinuationIR(wrongSequence));
  }
});

test('partial KeyUpdate survives IR restore and changes only receiving keys after old-key authentication', async () => {
  const { validateContinuationIR, parseContinuationIR } = await import('./state.mjs');
  const message = hex('1800000100'), wire = referenceRecord(CLIENT_KEY, CLIENT_IV, 7n, message, 22);
  const ir = {
    schema: 'ContinuationIRv0', version: 0, protocol: 'TLS1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', connectionId: '33'.repeat(16),
    ownership: { source: 'source', target: 'target', epoch: '4', nextEpoch: '5', transferNonce: '44'.repeat(32) },
    read: { trafficSecretHex: CLIENT_SECRET.toString('hex'), epoch: '0', sequence: '7' },
    write: { trafficSecretHex: SERVER_SECRET.toString('hex'), epoch: '0', sequence: '2' },
    pending: { readCipher: { hex: wire.subarray(0, 13).toString('hex'), offset: 0 },
      writeCipher: { hex: SERVER_WIRE.toString('hex'), offset: 11, epoch: '0', sequence: '1' },
      readPlain: { hex: PAYLOAD.toString('hex'), offset: 13 }, writePlain: { hex: '61626364', offset: 1 } },
  };
  const restored = parseContinuationIR(Buffer.from(JSON.stringify(validateContinuationIR(ir))));
  const oldRead = direction(hex(restored.read.trafficSecretHex), 7n), untouchedWrite = structuredClone(restored.write);
  const complete = Buffer.concat([hex(restored.pending.readCipher.hex), wire.subarray(13)]);
  const authenticated = openRecord(oldRead, complete); assert.equal(authenticated.contentType, 22);
  assert.deepEqual(parseKeyUpdate(authenticated.content), { requestUpdate: false });
  const nextRead = updateTrafficState(oldRead); assert.equal(nextRead.epoch, 1n); assert.equal(nextRead.sequence, 0n);
  assert.deepEqual(restored.write, untouchedWrite);
  // Relabeling a partially sent old-key record as new-key output is refused.
  const invalid = structuredClone(restored); invalid.write = { trafficSecretHex: nextRead.trafficSecret.toString('hex'), epoch: '1', sequence: '0' };
  assert.throws(() => validateContinuationIR(invalid));
});
