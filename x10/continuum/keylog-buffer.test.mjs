// Clearly synthetic NSS data only; no real handshake secrets or traffic.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { parseKeylogBuffer } from './keylog-buffer.mjs';

const frame = (label = 'CLIENT_TRAFFIC_SECRET_0', random = '01'.repeat(32), secret = 'aB'.repeat(32), ending = '\n') =>
  Buffer.from(`${label} ${random} ${secret}${ending}`, 'ascii');
const allZero = value => value.every(byte => byte === 0);

export function checkSyntheticKeylogBuffers() {
  let accepted = 0, refused = 0, trackedFailedAllocations = 0;
  for (const label of ['CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0', 'EXPORTER_SECRET', 'X', 'X'.repeat(64)]) {
    for (const ending of ['', '\n']) {
      const input = frame(label, 'eF'.repeat(32), '09'.repeat(32), ending);
      const result = parseKeylogBuffer(input);
      assert.equal(result.label, label);
      assert.equal(allZero(input), true);
      assert.equal(Buffer.isBuffer(result.random), true);
      assert.equal(Buffer.isBuffer(result.secret), true);
      assert.equal(result.random.length, 32);
      assert.equal(result.secret.length, 32);
      assert.equal(result.random.every(byte => byte === 0xef), true);
      assert.equal(result.secret.every(byte => byte === 0x09), true);
      assert.notEqual(result.random.buffer, input.buffer);
      assert.notEqual(result.secret.buffer, input.buffer);
      result.random.fill(0); result.secret.fill(0); accepted++;
    }
  }
  const values = [
    Buffer.alloc(0), frame(''), frame('client_traffic_secret_0'), frame('X'.repeat(65)),
    frame('CLIENT\tSECRET'), frame('CLIENT-SECRET'), frame('CLIENT SECRET'),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(31)),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(33)),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(31) + '0g'),
    frame('CLIENT_TRAFFIC_SECRET_0', '0g' + '00'.repeat(31)),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(31)),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(33)),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(31) + 'fg'),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'gf' + 'ff'.repeat(31)),
    frame('UNKNOWN', '00'.repeat(32), 'ff'.repeat(31) + 'fg'),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(32), '\r\n'),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(32), '\n\n'),
    frame('CLIENT_TRAFFIC_SECRET_0', '00'.repeat(32), 'ff'.repeat(32), ' '),
    Buffer.concat([Buffer.from(' '), frame()]),
    Buffer.from(frame().toString('ascii').replace(' ', '  '), 'ascii'),
    Buffer.from(frame().toString('ascii').replace(' ', '\t'), 'ascii'),
    Buffer.concat([frame(), Buffer.from('EXTRA')]), Buffer.alloc(513, 0x61),
  ];
  for (const offset of [0, 5, 35, 90, 150]) {
    const input = frame(); input[Math.min(offset, input.length - 2)] = 0x80; values.push(input);
  }
  for (const input of values) {
    assert.throws(() => parseKeylogBuffer(input), error => error?.code === 'keylog_invalid');
    assert.equal(allZero(input), true); refused++;
  }
  // Observe only synthetic temporary allocations. Failure after at least one
  // successful decode must scrub every allocated decoded buffer before throw.
  const alloc = Buffer.alloc;
  const allocations = [];
  const bad = frame('CLIENT_TRAFFIC_SECRET_0', '11'.repeat(32), '22'.repeat(31) + '2z');
  try {
    Buffer.alloc = function(size, ...args) { const b = Reflect.apply(alloc, Buffer, [size, ...args]); if (size === 32) allocations.push(b); return b; };
    assert.throws(() => parseKeylogBuffer(bad), error => error?.code === 'keylog_invalid');
  } finally { Buffer.alloc = alloc; }
  assert.equal(allZero(bad), true);
  for (const value of allocations) { assert.equal(allZero(value), true); trackedFailedAllocations++; }
  assert.ok(trackedFailedAllocations >= 1);
  refused++;
  // No source buffer exists for these wrong-type inputs. Do not invoke getters.
  for (const value of [undefined, null, '', 1, {}, new Uint8Array(5)]) {
    assert.throws(() => parseKeylogBuffer(value), error => error?.code === 'keylog_invalid'); refused++;
  }
  return Object.freeze({ passed: true, accepted, refused, trackedFailedAllocations,
    inputWipeVerified: true, decodedFailureWipeVerified: true, actualTLS: false,
    syntheticDataOnly: true, wholeProcessWipeClaimed: false, migration: false });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  test('synthetic NSS line buffers are bounded, parsed without secret strings and scrubbed', () => {
    assert.equal(checkSyntheticKeylogBuffers().passed, true);
  });
}
