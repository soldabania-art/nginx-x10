// Synthetic metadata controls only. No SSL objects, secrets or TLS I/O.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { checkCapsulePreflight } from './capsule-preflight.mjs';

const PIN = '85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c';
const CAP = 1n << 24n;
const copy = value => structuredClone(value);
export function syntheticPreflightRequest() {
  return {
    schemaVersion: 1,
    sourceIdentity: { sourceCommit: PIN, probeSha256: '1'.repeat(64), fixtureBinarySha256: '2'.repeat(64) },
    probe: {
      event: 'probe', scenario: 'quiescent', sample: 1, allowed: true, reasons: '0', monitorKnown: true,
      readGeneration: '0', writeGeneration: '0', mutationSerial: '2',
      readNextSequence: '0000000000000001', writeNextSequence: '0000000000000001',
      sslPending: 0, sslHasPending: false, packetLength: 0,
      rbufLeft: 0, rbufOffset: 27, rbufLength: 16712,
      unreadRecordBytes: 0, unreadControlBytes: 0,
      wbufLeft: 0, wbufOffset: 27, wbufLength: 16584, wnum: 0,
      staleWpendTot: 5, staleWpendRet: 5, readRecordSlots: 1, writeBufferSlots: 1,
      rstate: 240, rwstate: 1, flowState: 4, handshakeState: 1,
      inInit: 0, inHandshake: 0, encReadState: 0, encWriteState: 0,
      keyUpdate: -1, alertDispatch: 0, shutdown: 0, handshakeFragmentLength: 0, initNum: 0,
      ledgerLastCall: 3, ledgerRetryCall: 0, ledgerLastOutcome: 1, ledgerCallSerial: '3',
    },
    budget: {
      read: { applicationRecords: '4', handoverRecords: '1', closureRecords: '1' },
      write: { applicationRecords: '4', handoverRecords: '1', closureRecords: '1' },
    },
  };
}

export function checkSyntheticCapsulePreflight() {
  let accepted = 0, refused = 0, immutable = 0;
  const check = (request, eligible, expected = copy(request.sourceIdentity)) => {
    const before = JSON.stringify(request);
    const beforeExpected = JSON.stringify(expected);
    const result = checkCapsulePreflight(request, expected);
    assert.equal(result.eligibleForInventoryReview, eligible);
    assert.equal(result.semanticExportImport, false);
    assert.equal(result.migration, false);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(JSON.stringify(request), before);
    assert.equal(JSON.stringify(expected), beforeExpected);
    immutable += 1;
    if (eligible) {
      accepted += 1;
      for (const direction of ['read', 'write']) {
        const next = BigInt('0x' + request.probe[direction + 'NextSequence']);
        const planned = Object.values(request.budget[direction]).reduce((s, n) => s + BigInt(n), 0n);
        const budget = result.recordBudget[direction];
        assert.equal(BigInt(budget.availableRecords), CAP - next);
        assert.equal(BigInt(budget.plannedRecords), planned);
        assert.equal(BigInt(budget.remainingRecords), CAP - next - planned);
        assert.equal(Object.isFrozen(budget), true);
      }
      assert.equal(Object.isFrozen(result.recordBudget), true);
    } else {
      refused += 1;
      assert.equal(typeof result.code, 'string');
      assert.equal(Object.hasOwn(result, 'recordBudget'), false);
      assert.equal(JSON.stringify(result).includes('private-sensitive-sentinel'), false);
    }
    return result;
  };
  check(syntheticPreflightRequest(), true);
  // Independent BigInt oracle: each direction and both directions at once,
  // exact exhaustion accepted, one-record deficit refused, uint64 extremes.
  const sequences = [0n, 1n, 255n, 65535n, CAP - 3n, CAP - 2n, CAP - 1n, CAP,
    1n << 32n, (1n << 64n) - 1n];
  for (const direction of ['read', 'write']) {
    for (const next of sequences) {
      for (const app of [0n, 1n, 2n, CAP - 1n, CAP]) {
        const request = syntheticPreflightRequest();
        request.probe[direction + 'NextSequence'] = next.toString(16).padStart(16, '0');
        request.budget[direction] = { applicationRecords: String(app), handoverRecords: '0', closureRecords: '1' };
        check(request, next < CAP && app + 1n <= CAP - next);
      }
    }
  }
  const both = syntheticPreflightRequest();
  both.probe.readNextSequence = both.probe.writeNextSequence = (CAP - 1n).toString(16).padStart(16, '0');
  both.budget.read = both.budget.write = { applicationRecords: '0', handoverRecords: '0', closureRecords: '1' };
  check(both, true);

  const mutations = [
    r => { r.schemaVersion = 2; }, r => { r.extra = 'private-sensitive-sentinel'; },
    r => { delete r.probe; }, r => { r.sourceIdentity.sourceCommit = '0'.repeat(40); },
    r => { r.sourceIdentity.probeSha256 = '3'.repeat(64); },
    r => { r.sourceIdentity.fixtureBinarySha256 = '3'.repeat(64); },
    r => { r.sourceIdentity.extra = 'private-sensitive-sentinel'; },
    r => { r.probe.extra = 'private-sensitive-sentinel'; },
    r => { r.probe.allowed = false; }, r => { r.probe.reasons = '16'; },
    r => { r.probe.monitorKnown = false; }, r => { r.probe.readGeneration = '1'; },
    r => { r.probe.writeGeneration = '1'; }, r => { r.probe.mutationSerial = '3'; },
    r => { r.probe.sslHasPending = true; }, r => { r.probe.ledgerRetryCall = 2; },
    r => { r.probe.ledgerLastOutcome = 4; }, r => { r.probe.ledgerLastCall = 5; },
    r => { r.probe.readNextSequence = '000000000000000A'; },
    r => { r.probe.writeNextSequence = '000000000000000'; },
    r => { r.probe.ledgerCallSerial = '0'; }, r => { r.probe.ledgerCallSerial = '01'; },
    r => { r.probe.sample = Number.MAX_SAFE_INTEGER + 1; },
    r => { r.budget.extra = {}; }, r => { r.budget.read.extra = '1'; },
    r => { r.budget.read.closureRecords = '0'; }, r => { r.budget.write.closureRecords = '0'; },
    ...['-1', '+1', '01', '1.0', '1e0', '', ' ', '16777217', '18446744073709551615', 1, 1n, null].map(value =>
      r => { r.budget.read.applicationRecords = value; }),
    ...['packetLength', 'rbufLeft', 'unreadRecordBytes', 'unreadControlBytes', 'wbufLeft', 'wnum',
      'inInit', 'inHandshake', 'alertDispatch', 'shutdown', 'handshakeFragmentLength', 'initNum', 'sslPending'].map(key =>
      r => { r.probe[key] = 1; }),
  ];
  for (const mutate of mutations) {
    const request = syntheticPreflightRequest();
    const expected = copy(request.sourceIdentity);
    mutate(request);
    // JSON cannot encode BigInt; evaluate it through the descriptor-only path.
    if (typeof request.budget.read.applicationRecords === 'bigint') {
      const result = checkCapsulePreflight(request, expected);
      assert.equal(result.eligibleForInventoryReview, false); refused += 1;
    } else check(request, false, expected);
  }
  let getters = 0;
  for (const location of ['request', 'probe', 'budget', 'direction', 'identity', 'expected']) {
    const request = syntheticPreflightRequest();
    let expected = copy(request.sourceIdentity);
    const object = { request, probe: request.probe, budget: request.budget, direction: request.budget.read,
      identity: request.sourceIdentity, expected }[location];
    const key = Object.keys(object)[0];
    Object.defineProperty(object, key, { enumerable: true, get() { getters += 1; throw new Error('private-sensitive-sentinel'); } });
    const result = checkCapsulePreflight(request, expected);
    assert.equal(result.eligibleForInventoryReview, false); refused += 1;
  }
  assert.equal(getters, 0);
  let traps = 0;
  for (const location of ['request', 'probe', 'budget', 'direction', 'identity', 'expected']) {
    let request = syntheticPreflightRequest();
    let expected = copy(request.sourceIdentity);
    const object = { request, probe: request.probe, budget: request.budget, direction: request.budget.read,
      identity: request.sourceIdentity, expected }[location];
    const proxy = new Proxy(object, {
      ownKeys() { traps += 1; throw new Error('private-sensitive-sentinel'); },
      getPrototypeOf() { traps += 1; throw new Error('private-sensitive-sentinel'); },
      get() { traps += 1; throw new Error('private-sensitive-sentinel'); },
    });
    if (location === 'request') request = proxy;
    if (location === 'probe') request.probe = proxy;
    if (location === 'budget') request.budget = proxy;
    if (location === 'direction') request.budget.read = proxy;
    if (location === 'identity') request.sourceIdentity = proxy;
    if (location === 'expected') expected = proxy;
    const result = checkCapsulePreflight(request, expected);
    assert.equal(result.eligibleForInventoryReview, false); refused += 1;
  }
  assert.equal(traps, 0);
  for (const key of [Symbol('unexpected'), 'nonenumerable']) {
    const request = syntheticPreflightRequest();
    Object.defineProperty(request.probe, key, { value: 'private-sensitive-sentinel', enumerable: false });
    const result = checkCapsulePreflight(request, copy(request.sourceIdentity));
    assert.equal(result.eligibleForInventoryReview, false); refused += 1;
  }
  for (const location of ['request', 'probe', 'budget', 'direction', 'identity', 'expected']) {
    let request = syntheticPreflightRequest();
    let expected = copy(request.sourceIdentity);
    const object = { request, probe: request.probe, budget: request.budget, direction: request.budget.read,
      identity: request.sourceIdentity, expected }[location];
    Object.setPrototypeOf(object, { inherited: 'private-sensitive-sentinel' });
    const result = checkCapsulePreflight(request, expected);
    assert.equal(result.eligibleForInventoryReview, false); refused += 1;
  }
  return Object.freeze({ scope: 'synthetic-metadata-preflight-only', passed: true,
    accepted, refused, immutableInputs: immutable, getterInvocations: getters, proxyTrapInvocations: traps,
    actualTLS: false, semanticExportImport: false, migration: false });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  test('synthetic capsule metadata and directional future record budget preflight', () => {
    const result = checkSyntheticCapsulePreflight();
    assert.equal(result.passed, true);
    assert.ok(result.accepted > 10 && result.refused > 100);
  });
}
