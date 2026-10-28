import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { HandoverModel, createHandover, transitionHandover, canWrite, handoverDigest,
  validateContinuationIR, parseContinuationIR, validateHandoverState, MAX_SERIALIZED_BYTES, U64_MAX, MAX_RECORDS_PER_KEY } from './state.mjs';

// Public synthetic fixture, generated independently by the record worker from
// 32 repeated 0x44 bytes, sequence4, application content and two padding bytes.
// No live connection keys, plaintext or state is read or printed by this suite.
const PENDING_WIRE = '170303002dde547e107fe4dd22ab5bc7d3e3080eea9473079ca0a0c2e94fe635a77346505bd91bdbd61634a4c2fe8fc371bf';
const clone = value => structuredClone(value);
function example() {
  return { schema: 'ContinuationIRv0', version: 0, protocol: 'TLS1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', connectionId: '11'.repeat(16),
    ownership: { source: 'source', target: 'target', epoch: '1', nextEpoch: '2', transferNonce: '22'.repeat(32) },
    read: { trafficSecretHex: '33'.repeat(32), epoch: '0', sequence: '3' }, write: { trafficSecretHex: '44'.repeat(32), epoch: '0', sequence: '5' },
    pending: { readCipher: { hex: PENDING_WIRE.slice(0, 26), offset: 0 }, writeCipher: { hex: PENDING_WIRE, offset: 11, epoch: '0', sequence: '4' },
      readPlain: { hex: Buffer.from('delivered-prefix and remaining input').toString('hex'), offset: 3 },
      writePlain: { hex: Buffer.from('consumed-prefix and queued output').toString('hex'), offset: 4 } } };
}
function event(state, type, changes = {}) {
  return { type, connectionId: state.connectionId, transferNonce: state.transferNonce, epoch: type === 'retire' ? state.nextEpoch : state.epoch,
    actor: type === 'prepared' ? state.target : state.source, irSha256: state.irSha256, ...changes };
}
function retire(model, input) {
  let state = createHandover(input, { model }); for (const phase of ['prepared', 'commit', 'retire']) state = transitionHandover(state, event(state, phase)); return state;
}
function rejected(fn, code) { assert.throws(fn, error => error.message === 'Continuation model rejected input' && (!code || error.code === code)); }

test('nonidle IR preserves independent directions and pending offsets in detached immutable JSON', () => {
  const input = example(), checked = validateContinuationIR(input), parsed = parseContinuationIR(Buffer.from(JSON.stringify(input)));
  assert.equal(parsed.write.sequence, '5'); assert.equal(parsed.read.sequence, '3'); assert.equal(parsed.pending.writeCipher.offset, 11);
  assert.equal(parsed.pending.readCipher.hex.length, 26); assert.equal(parsed.pending.readPlain.offset, 3); assert.equal(parsed.pending.writePlain.offset, 4);
  assert.equal(handoverDigest(checked), handoverDigest(parsed)); assert(Object.isFrozen(parsed.pending.writeCipher)); assert(Object.isFrozen(parsed.ownership));
  input.read.sequence = '9'; assert.equal(checked.read.sequence, '3');
  assert.throws(() => { checked.write.sequence = '0'; }, TypeError);
  const reordered = Object.fromEntries(Object.entries(example()).reverse()); assert.equal(handoverDigest(reordered), handoverDigest(parsed));
});

test('unsupported identity/profile/schema and hidden executable fields fail closed without echoing input', () => {
  const mutations = [v => v.schema = 'v1', v => v.version = 1, v => v.protocol = 'TLS1.2', v => v.cipherSuite = 'TLS_AES_256_GCM_SHA384',
    v => v.connectionId = 'bad', v => v.ownership.source = v.ownership.target, v => v.ownership.target = 'remote/owner',
    v => v.ownership.nextEpoch = '9', v => v.ownership.transferNonce = 'a'.repeat(63), v => v.extra = 'secret-canary',
    v => v.read.extra = 1, v => v.pending.readPlain.extra = 1, v => delete v.pending.writePlain,
    v => v.read.trafficSecretHex = 'ab'.repeat(31), v => v.read.trafficSecretHex = 'AB'.repeat(32)];
  for (const mutate of mutations) { const value = example(); mutate(value); rejected(() => validateContinuationIR(value)); }
  let invoked = false; const value = example(); Object.defineProperty(value.read, 'sequence', { enumerable: true, get() { invoked = true; return '0'; } });
  rejected(() => validateContinuationIR(value), 'ir_schema'); assert.equal(invoked, false);
  rejected(() => validateContinuationIR(new Date()), 'ir_schema');
});

test('U64 counters retain exact wide values and reject alternate numeric spellings and overflow', () => {
  for (const bad of [0, 1, 1n, '-1', '+1', '00', '01', ' 1', '1.0', '1e0', '18446744073709551616', '', null]) {
    const value = example(); value.read.sequence = bad; rejected(() => validateContinuationIR(value), 'ir_counter');
  }
  const wide = example(); wide.read.sequence = (MAX_RECORDS_PER_KEY - 1n).toString(); wide.read.epoch = '9007199254740993';
  assert.equal(validateContinuationIR(wide).read.epoch, '9007199254740993');
  const full = example(); full.ownership.epoch = U64_MAX.toString(); full.ownership.nextEpoch = '0'; rejected(() => validateContinuationIR(full), 'ir_ownership');
});

test('import refuses exhausted per-key sequences before any ownership grant', () => {
  for (const name of ['read', 'write']) for (const sequence of [MAX_RECORDS_PER_KEY, MAX_RECORDS_PER_KEY + 1n, U64_MAX]) {
    const input = example(); input[name].sequence = sequence.toString();
    rejected(() => validateContinuationIR(input), 'ir_key_usage');
    rejected(() => parseContinuationIR(JSON.stringify(input)), 'ir_key_usage');
    rejected(() => createHandover(input), 'ir_key_usage');
  }
});

test('pending offsets and partial-record boundaries cannot silently discard, duplicate or overrun data', () => {
  const mutations = [v => v.pending.readCipher.offset = 1, v => v.pending.readCipher.hex = PENDING_WIRE,
    v => v.pending.readCipher.hex = '160303002d', v => v.pending.readCipher.hex = '170303ffff', v => v.pending.readCipher.hex = '1703030001',
    v => v.pending.readPlain.offset = v.pending.readPlain.hex.length / 2, v => v.pending.writePlain.offset = -1,
    v => v.pending.writePlain.offset = 0.5, v => v.pending.readPlain.hex = 'ab'.repeat(16385),
    v => v.pending.writeCipher.offset = PENDING_WIRE.length / 2, v => v.pending.writeCipher.offset = -0,
    v => v.pending.writeCipher.hex = PENDING_WIRE.slice(0, -2), v => v.pending.readPlain = { hex: '', offset: 1 },
    v => v.pending.writePlain.hex = 'a'];
  for (const mutate of mutations) { const value = example(); mutate(value); rejected(() => validateContinuationIR(value)); }
  for (const prefix of ['', '17', '1703', '170303', '17030300']) { const value = example(); value.pending.readCipher.hex = prefix; assert.equal(validateContinuationIR(value).pending.readCipher.hex, prefix); }
  const idle = example(); idle.pending = { readCipher: { hex: '', offset: 0 }, writeCipher: null, readPlain: { hex: '', offset: 0 }, writePlain: { hex: '', offset: 0 } };
  assert.equal(validateContinuationIR(idle).pending.writeCipher, null);
});

test('already-encrypted pending output binds exact secret, sequence, epoch and authenticated bytes', () => {
  const mutations = [v => v.write.sequence = '6', v => v.pending.writeCipher.epoch = '1', v => v.write.trafficSecretHex = '55'.repeat(32),
    v => { v.pending.writeCipher.sequence = '3'; v.write.sequence = '4'; },
    v => v.pending.writeCipher.hex = PENDING_WIRE.slice(0, -2) + '00'];
  for (const mutate of mutations) { const value = example(); mutate(value); rejected(() => validateContinuationIR(value)); }
});

test('bounded parser rejects duplicate decoded keys, invalid UTF8, containers and trailing input', () => {
  const encoded = JSON.stringify(example());
  for (const text of [encoded + '{}', encoded.slice(0, -1), encoded.replace('"version":0', '"version":0,"version":0'),
    encoded.replace('"version":0', '"version":0,"\\u0076ersion":0'), '[]', '{}', 'null', '{"a":{"b":{"c":{"d":{"e":{"f":{"g":0}}}}}}}',
    encoded.replace('"version":0', '"version":0.0'), '\ufeff' + encoded]) rejected(() => parseContinuationIR(text));
  rejected(() => parseContinuationIR(Buffer.from([0xff, 0xfe])), 'ir_json');
  rejected(() => parseContinuationIR(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(encoded)])), 'ir_json');
  rejected(() => parseContinuationIR(' '.repeat(MAX_SERIALIZED_BYTES + 1)), 'ir_input_limit');
  rejected(() => parseContinuationIR(Buffer.alloc(MAX_SERIALIZED_BYTES + 1)), 'ir_input_limit');
});

test('offer-prepared-commit-retire grants exactly one modeled writer and consumes transition tokens', () => {
  const model = new HandoverModel(), first = createHandover(example(), { model });
  assert.equal(first.phase, 'offer'); assert.equal(canWrite(first, 'source'), false); assert.equal(canWrite(first, 'target'), false);
  rejected(() => transitionHandover(first, event(first, 'commit')), 'handover_phase');
  const prepared = transitionHandover(first, event(first, 'prepared')); assert.equal(prepared.activeOwner, 'source');
  rejected(() => transitionHandover(first, event(first, 'prepared')), 'handover_stale');
  const committed = transitionHandover(prepared, event(prepared, 'commit'));
  assert.equal(canWrite(committed, 'source'), false); assert.equal(canWrite(committed, 'target'), true);
  rejected(() => transitionHandover(prepared, event(prepared, 'commit')), 'handover_stale');
  rejected(() => transitionHandover(committed, event(committed, 'commit')), 'handover_phase');
  const retired = transitionHandover(committed, event(committed, 'retire')); assert.equal(canWrite(retired, 'source'), false); assert.equal(canWrite(retired, 'target'), true);
  rejected(() => transitionHandover(retired, event(retired, 'retire')), 'handover_phase');
  rejected(() => transitionHandover({ ...retired }, event(retired, 'retire')), 'handover_stale');
  rejected(() => createHandover(example(), { model }), 'handover_replay');
  rejected(() => validateHandoverState({ ...retired, writer: 'source' }), 'handover_ownership');
});

test('prepared acknowledgment cannot substitute changed sequence, TLS epoch, ownership or transfer identity', () => {
  const offered = createHandover(example());
  for (const changed of [{ actor: 'source' }, { epoch: '2' }, { transferNonce: '77'.repeat(32) }, { connectionId: '88'.repeat(16) }]) rejected(() => transitionHandover(offered, event(offered, 'prepared', changed)));
  for (const mutate of [v => v.read.sequence = '4', v => v.read.epoch = '1', v => v.ownership.target = 'another-target']) {
    const altered = example(); mutate(altered); rejected(() => transitionHandover(offered, event(offered, 'prepared', { irSha256: handoverDigest(altered) })), 'handover_binding');
  }
  const prepared = transitionHandover(offered, event(offered, 'prepared')); assert.equal(prepared.phase, 'prepared');
});

test('new handovers retain coordinator owner epochs and reject TLS rollback despite a fresh nonce', () => {
  const model = new HandoverModel(); retire(model, example());
  const next = example(); next.ownership = { source: 'target', target: 'third', epoch: '2', nextEpoch: '3', transferNonce: '66'.repeat(32) };
  for (const mutate of [v => v.read.sequence = '2', v => v.read.epoch = '1', v => v.read.epoch = '17', v => v.read.trafficSecretHex = '55'.repeat(32),
    v => { v.ownership.epoch = '1'; v.ownership.nextEpoch = '2'; }]) {
    const bad = clone(next); mutate(bad);
    rejected(() => createHandover(bad, { model }));
  }
  const updated = clone(next); updated.read.epoch = '1'; updated.read.sequence = '0';
  const label = Buffer.from('tls13 traffic upd'), info = Buffer.concat([Buffer.from([0, 32, label.length]), label, Buffer.from([0, 1])]);
  updated.read.trafficSecretHex = createHmac('sha256', Buffer.from(next.read.trafficSecretHex, 'hex')).update(info).digest('hex');
  const accepted = createHandover(updated, { model }); assert.equal(accepted.epoch, '2'); assert.equal(accepted.phase, 'offer');
});
