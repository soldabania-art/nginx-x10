// Synthetic public metadata controls. No SSL objects or secret material.
import assert from 'node:assert/strict';
import { checkCapsulePreflight, checkHeldCapturePreflight } from './capsule-preflight.mjs';
import { syntheticPreflightRequest } from './capsule-preflight.test.mjs';

export function syntheticHeldCaptureRequest() {
  const value = syntheticPreflightRequest();
  value.probe.scenario = 'quiescent-live-hold';
  value.repeatedProbe = { ...value.probe, sample: 2 };
  value.hold = { nonce: 'a'.repeat(32), callSerial: value.probe.ledgerCallSerial,
    sourceHeld: true, historical: false };
  return value;
}

export function checkSyntheticHeldCapturePreflight() {
  let accepted = 0, refused = 0, getters = 0, traps = 0;
  const check = (request, eligible, expected = structuredClone(request.sourceIdentity),
    current = { nonce: 'a'.repeat(32), callSerial: '3' }) => {
    const before = JSON.stringify(request);
    const result = checkHeldCapturePreflight(request, expected, current);
    assert.equal(result.eligibleForInventoryReview, eligible);
    assert.equal(result.semanticExportImport, false);
    assert.equal(result.migration, false);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(JSON.stringify(request), before);
    if (eligible) {
      accepted++;
      for (const direction of ['read', 'write']) {
        const planned = Object.values(request.budget[direction]).reduce((a, b) => a + BigInt(b), 0n);
        const next = BigInt('0x' + request.probe[direction + 'NextSequence']);
        assert.equal(BigInt(result.recordBudget[direction].remainingRecords), (1n << 24n) - next - planned);
      }
    } else { refused++; assert.equal(Object.hasOwn(result, 'recordBudget'), false); }
  };
  check(syntheticHeldCaptureRequest(), true);
  const held = syntheticHeldCaptureRequest();
  const legacy = { schemaVersion: 1, sourceIdentity: held.sourceIdentity, probe: held.probe, budget: held.budget };
  assert.equal(checkCapsulePreflight(legacy, held.sourceIdentity).code, 'unsupported_profile');
  refused++;
  for (const direction of ['read', 'write']) for (const next of [0n, 1n, 255n, (1n << 24n) - 2n, (1n << 24n) - 1n]) {
    for (const extra of [-1n, 0n, 1n]) {
      const value = syntheticHeldCaptureRequest();
      value.probe[direction + 'NextSequence'] = value.repeatedProbe[direction + 'NextSequence'] = next.toString(16).padStart(16, '0');
      const available = (1n << 24n) - next;
      value.budget[direction] = { applicationRecords: (available - 1n + extra).toString(), handoverRecords: '0', closureRecords: '1' };
      check(value, available - 1n + extra >= 0n && extra <= 0n);
    }
  }
  const mutations = [
    r => { r.hold.nonce = 'b'.repeat(32); }, r => { r.hold.callSerial = '4'; },
    r => { r.hold.sourceHeld = false; }, r => { r.hold.historical = true; },
    r => { r.hold.extra = true; }, r => { r.hold.nonce = 'A'.repeat(32); },
    r => { r.hold.callSerial = '03'; }, r => { r.hold.callSerial = '18446744073709551616'; },
    r => { r.probe.scenario = 'quiescent'; }, r => { r.repeatedProbe.scenario = 'quiescent'; },
    r => { r.probe.sample = 3; }, r => { r.repeatedProbe.sample = 1; },
    r => { r.repeatedProbe.ledgerCallSerial = '4'; }, r => { r.repeatedProbe.wbufOffset++; },
    r => { r.repeatedProbe.writeNextSequence = '0000000000000002'; },
    r => { r.probe.readGeneration = r.repeatedProbe.readGeneration = '1'; },
    r => { r.probe.ledgerRetryCall = r.repeatedProbe.ledgerRetryCall = 2; },
    r => { r.probe.unreadControlBytes = r.repeatedProbe.unreadControlBytes = 1; },
    r => { r.probe.shutdown = r.repeatedProbe.shutdown = 1; },
    r => { r.budget.read.closureRecords = '0'; }, r => { r.budget.write.applicationRecords = '16777216'; },
    r => { r.sourceIdentity.probeSha256 = '3'.repeat(64); },
    r => { r.sourceIdentity.fixtureBinarySha256 = '4'.repeat(64); },
    r => { r.extra = 'sentinel'; }, r => { delete r.repeatedProbe; },
  ];
  for (const mutate of mutations) { const r = syntheticHeldCaptureRequest(); const expected = structuredClone(r.sourceIdentity); mutate(r); check(r, false, expected); }
  for (const current of [{nonce:'b'.repeat(32),callSerial:'3'}, {nonce:'a'.repeat(32),callSerial:'4'},
    {nonce:'a'.repeat(32),callSerial:'0'}, {nonce:'a'.repeat(32),callSerial:'3',extra:true}]) check(syntheticHeldCaptureRequest(), false, undefined, current);
  for (const place of ['request', 'hold', 'probe', 'repeatedProbe', 'budget', 'direction', 'identity', 'expected', 'current']) {
    const r = syntheticHeldCaptureRequest(); let expected = structuredClone(r.sourceIdentity), current = { nonce:'a'.repeat(32),callSerial:'3' };
    const objects = { request:r, hold:r.hold, probe:r.probe, repeatedProbe:r.repeatedProbe, budget:r.budget, direction:r.budget.read, identity:r.sourceIdentity, expected, current };
    const object = objects[place];
    const key = Object.keys(object)[0];
    Object.defineProperty(object, key, { enumerable:true, get() { getters++; throw Error('getter'); } });
    const result = checkHeldCapturePreflight(r, expected, current);
    assert.equal(result.eligibleForInventoryReview, false); refused++;
  }
  for (const place of ['request', 'hold', 'probe', 'repeatedProbe', 'budget', 'direction', 'identity', 'expected', 'current']) {
    let r = syntheticHeldCaptureRequest(), expected = structuredClone(r.sourceIdentity), current = {nonce:'a'.repeat(32),callSerial:'3'};
    const proxy = new Proxy({}, { ownKeys() { traps++; throw Error('trap'); }, getPrototypeOf() { traps++; throw Error('trap'); }, get() { traps++; throw Error('trap'); } });
    if (place === 'request') r = proxy; else if (place === 'expected') expected = proxy; else if (place === 'current') current = proxy;
    else if (place === 'direction') r.budget.read = proxy; else if (place === 'identity') r.sourceIdentity = proxy; else r[place] = proxy;
    assert.equal(checkHeldCapturePreflight(r, expected, current).eligibleForInventoryReview, false); refused++;
  }
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  assert.equal(checkHeldCapturePreflight(revoked.proxy, {}, {}).eligibleForInventoryReview, false); refused++;
  assert.equal(getters, 0); assert.equal(traps, 0);
  return Object.freeze({ passed:true, accepted, refused, getterInvocations:getters, proxyTrapInvocations:traps,
    actualTLS:false, sourceProtection:false, semanticExportImport:false, migration:false });
}
