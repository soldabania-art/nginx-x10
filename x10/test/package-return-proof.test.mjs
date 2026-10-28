import test from 'node:test';
import assert from 'node:assert/strict';
import { checkOperatorReturnProof, canActivateOperatorPackage } from './package-return-proof.mjs';

// Synthetic proof consistency/phase-gate controls only. This file does not run
// a package, invoke a native process, signal anything or activate a service.
const hash = character => character.repeat(64);
const stop = () => ({ stage: 'stopped', runtimeIdentityVerified: true, masterAbsent: true,
  processGroupAbsent: true, launcherExited: true, launcherExitCode: 0, launcherSignal: null,
  portsClosed: true, operatorLockAbsent: true, pendingAbsent: true });
const phases = ['a_started', 'a_served', 'a_stopped', 'b_staged', 'b_started',
  'b_readiness_refused', 'b_served', 'b_stopped', 'a2_restored',
  'a2_started', 'a2_served', 'a2_stopped', 'cleanup'];
const oldPackage = () => ({ runtimePayloadSha256: hash('a'), operatorPayloadSha256: hash('b'), nativeBinarySha256: hash('c') });
const newPackage = () => ({ runtimePayloadSha256: hash('d'), operatorPayloadSha256: hash('e'), nativeBinarySha256: hash('c') });
function syntheticProof() {
  return { schemaVersion: 1, kind: 'nginx-x10-operator-package-return-proof',
    packages: { a: oldPackage(), b: newPackage(), a2: oldPackage() },
    inputs: { pSha256: hash('1'), qSha256: hash('2'), a2RestoredSha256: hash('2') },
    phases: [...phases],
    legs: ['a', 'b', 'a2'].map((name, index) => ({ name,
      identityOrdinals: { installation: index + 1, session: index + 1, revision: index + 1, binding: index + 1 },
      inputSha256: hash(index === 0 ? '1' : '2'), initialBindingAbsent: true, readinessAccepted: true,
      bindingMatchesOwnedRuntime: true, getExact: true, postExact: true, streamExact: true,
      postEffectsBefore: index, postEffectsAfter: index + 1, stop: stop() })),
    staging: { commandExercised: true, sourcePreserved: true, initialBindingAbsent: true,
      initialInputSha256: hash('1'), runtimePayloadChanged: true, operatorPayloadChanged: true, nativeBinaryChanged: false },
    controls: { bWrongReadinessRefused: true, bBindingAbsentAfterRefusal: true,
      retainedAAllFilesPreserved: true, retainedABackupPreserved: true,
      forwardStartedAfterConfirmedStop: true, returnStartedAfterConfirmedStop: true, oldAInstallerRestoredQ: true },
    cleanup: { known: true, ownedProcessesAbsent: true, ownedLaunchersAbsent: true,
      ownedListenersClosed: true, ownedInstallationsRemoved: 3, historicalBundleRemoved: true, backupFilesRemoved: true },
    limits: { consistencyOnly: true, nativeBinaryUpgradeAccepted: false, liveConnectionPreserved: false,
      applicationSideEffectsReversed: false, managedServiceAccepted: false, productionAccepted: false } };
}
const refused = proof => {
  const result = checkOperatorReturnProof(proof);
  assert.deepEqual(result, { ok: false, code: 'operator_return_proof_invalid', compatibilityAccepted: false,
    packageReturnAccepted: false, serviceAccepted: false, productionAccepted: false });
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE|\/synthetic\//);
};
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }

test('operator return proof accepts a bounded synthetic A(P)-B(Q)-oldA2(Q) observation without accepting a release', () => {
  const value = syntheticProof(), before = structuredClone(value), result = checkOperatorReturnProof(freeze(value));
  assert.deepEqual(result, { ok: true, code: 'operator_return_proof_valid', compatibilityAccepted: false,
    packageReturnAccepted: false, serviceAccepted: false, productionAccepted: false });
  assert.deepEqual(value, before);
});
test('operator return proof permits own-data null-prototype records without invoking conversions', () => {
  const value = syntheticProof(); value.packages = Object.assign(Object.create(null), value.packages);
  value.legs[0].identityOrdinals = Object.assign(Object.create(null), value.legs[0].identityOrdinals);
  assert.equal(checkOperatorReturnProof(value).ok, true);
});
for (const [label, mutate] of [
  ['runtime package identity unchanged', p => { p.packages.b.runtimePayloadSha256 = p.packages.a.runtimePayloadSha256; }],
  ['operator package identity unchanged', p => { p.packages.b.operatorPayloadSha256 = p.packages.a.operatorPayloadSha256; }],
  ['return runtime is new package rather than old A', p => { p.packages.a2.runtimePayloadSha256 = p.packages.b.runtimePayloadSha256; }],
  ['return operator is new package rather than old A', p => { p.packages.a2.operatorPayloadSha256 = p.packages.b.operatorPayloadSha256; }],
  ['native binary changed at forward leg', p => { p.packages.b.nativeBinarySha256 = hash('f'); }],
  ['native binary changed at return leg', p => { p.packages.a2.nativeBinarySha256 = hash('f'); }],
  ['inputs never changed', p => { p.inputs.qSha256 = p.inputs.pSha256; p.inputs.a2RestoredSha256 = p.inputs.pSha256; }],
  ['old A did not restore Q', p => { p.inputs.a2RestoredSha256 = p.inputs.pSha256; }],
  ['B served P instead of Q', p => { p.legs[1].inputSha256 = p.inputs.pSha256; }],
  ['return served retained P instead of Q', p => { p.legs[2].inputSha256 = p.inputs.pSha256; }],
  ['stage initial input is not preserved P', p => { p.staging.initialInputSha256 = p.inputs.qSha256; }],
  ['wrong kind', p => { p.kind = 'service-or-live-migration'; }],
  ['coerced schema', p => { p.schemaVersion = '1'; }],
  ['unknown schema', p => { p.schemaVersion = 2; }],
]) test(`operator return proof refuses ${label}`, () => { const p = syntheticProof(); mutate(p); refused(p); });
for (const label of ['a', 'b', 'a2']) for (const key of ['runtimePayloadSha256', 'operatorPayloadSha256', 'nativeBinarySha256'])
  test(`operator return proof refuses missing ${label} ${key}`, () => { const p = syntheticProof(); delete p.packages[label][key]; refused(p); });
for (const value of ['a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'a'.repeat(64) + '\n', 'a'.repeat(64) + '\r', '', 1, null, { toString: () => hash('a') }])
  test(`operator return proof refuses noncanonical hash ${typeof value}:${String(value).length}`, () => { const p = syntheticProof(); p.packages.a.runtimePayloadSha256 = value; refused(p); });
for (const key of ['pSha256', 'qSha256', 'a2RestoredSha256']) test(`operator return proof refuses malformed ${key}`, () => { const p = syntheticProof(); p.inputs[key] += '\n'; refused(p); });
for (let index = 0; index < phases.length; index++) test(`operator return proof refuses missing transition ${phases[index]}`, () => { const p = syntheticProof(); p.phases.splice(index, 1); refused(p); });
for (const [label, mutate] of [
  ['B started before A stopped', p => { [p.phases[2], p.phases[4]] = [p.phases[4], p.phases[2]]; }],
  ['A2 started before B stopped', p => { [p.phases[7], p.phases[9]] = [p.phases[9], p.phases[7]]; }],
  ['duplicate start transition', p => { p.phases[3] = 'a_started'; }],
  ['duplicate return transition', p => { p.phases[8] = 'b_staged'; }],
  ['appended transition', p => { p.phases.push('cleanup'); }],
  ['phase array hole', p => { delete p.phases[4]; }],
  ['extra array field', p => { p.phases.private = 'SYNTHETIC_PRIVATE'; }],
]) test(`operator return proof refuses ${label}`, () => { const p = syntheticProof(); mutate(p); refused(p); });
for (const index of [0, 1, 2]) for (const key of ['installation', 'session', 'revision', 'binding'])
  test(`operator return proof refuses reused ${key} identity on leg${index}`, () => { const p = syntheticProof(); p.legs[index].identityOrdinals[key] = index === 0 ? 2 : 1; refused(p); });
for (const value of [0, -0, -1, 1.5, 4, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '2', true, null])
  test(`operator return proof refuses noncanonical identity ordinal ${String(value)}`, () => { const p = syntheticProof(); p.legs[1].identityOrdinals.binding = value; refused(p); });
for (const [label, mutate] of [
  ['leg missing', p => { p.legs.pop(); }],
  ['leg order swapped', p => { [p.legs[0], p.legs[1]] = [p.legs[1], p.legs[0]]; }],
  ['duplicated leg', p => { p.legs[2] = structuredClone(p.legs[1]); }],
  ['unrecognized leg name', p => { p.legs[1].name = 'fixture-green'; }],
]) test(`operator return proof refuses ${label}`, () => { const p = syntheticProof(); mutate(p); refused(p); });
for (const index of [0, 1, 2]) for (const key of ['initialBindingAbsent', 'readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact', 'streamExact'])
  test(`operator return proof refuses missing/false ${key} on leg${index}`, () => { const p = syntheticProof(); p.legs[index][key] = false; refused(p); });
for (const [label, mutate] of [
  ['POST replay on B', p => { p.legs[1].postEffectsAfter = 3; }],
  ['POST silently omitted on A2', p => { p.legs[2].postEffectsAfter = 2; }],
  ['POST counter reset before B', p => { p.legs[1].postEffectsBefore = 0; }],
  ['all POST counters self-reported one', p => { for (const leg of p.legs) { leg.postEffectsBefore = 0; leg.postEffectsAfter = 1; } }],
  ['negative POST counter', p => { p.legs[0].postEffectsBefore = -1; }],
  ['coerced POST count', p => { p.legs[1].postEffectsAfter = '2'; }],
  ['fractional POST count', p => { p.legs[1].postEffectsAfter = 2.5; }],
  ['negative-zero POST counter', p => { p.legs[0].postEffectsBefore = -0; }],
]) test(`operator return proof refuses ${label}`, () => { const p = syntheticProof(); mutate(p); refused(p); });
for (const index of [0, 1, 2]) for (const key of ['runtimeIdentityVerified', 'masterAbsent', 'processGroupAbsent', 'launcherExited', 'portsClosed', 'operatorLockAbsent', 'pendingAbsent'])
  test(`operator return proof refuses unconfirmed stop ${key} on leg${index}`, () => { const p = syntheticProof(); p.legs[index].stop[key] = false; refused(p); });
for (const [key, value] of [['stage', 'faulted'], ['launcherExitCode', 1], ['launcherExitCode', null], ['launcherSignal', 'SIGTERM']])
  test(`operator return proof refuses abnormal stop ${key}:${String(value)}`, () => { const p = syntheticProof(); p.legs[1].stop[key] = value; refused(p); });
for (const key of Object.keys(syntheticProof().staging)) test(`operator return proof refuses missing staging ${key}`, () => { const p = syntheticProof(); delete p.staging[key]; refused(p); });
for (const key of Object.keys(syntheticProof().controls)) test(`operator return proof refuses absent required control ${key}`, () => { const p = syntheticProof(); p.controls[key] = false; refused(p); });
for (const key of Object.keys(syntheticProof().cleanup)) test(`operator return proof refuses unknown cleanup ${key}`, () => { const p = syntheticProof(); p.cleanup[key] = null; refused(p); });
for (const key of Object.keys(syntheticProof().limits)) test(`operator return proof refuses an unsupported acceptance claim ${key}`, () => { const p = syntheticProof(); p.limits[key] = !p.limits[key]; refused(p); });
for (const path of [[], ['packages'], ['packages', 'a'], ['inputs'], ['legs', 1], ['legs', 1, 'identityOrdinals'], ['legs', 1, 'stop'], ['staging'], ['controls'], ['cleanup'], ['limits']])
  test(`operator return proof refuses extra data on ${path.join('.') || 'root'}`, () => {
    const p = syntheticProof(); let selected = p; for (const key of path) selected = selected[key]; selected.private = 'SYNTHETIC_PRIVATE /synthetic/path'; refused(p);
  });
for (const value of [null, undefined, true, 1, [], 'PASS']) test(`operator return proof refuses nonrecord ${String(value)}`, () => refused(value));
test('operator return proof rejects accessor data without reading getters or toJSON', () => {
  const p = syntheticProof(); let reads = 0;
  Object.defineProperty(p.packages.a, 'runtimePayloadSha256', { enumerable: true, get() { reads++; throw new Error('SYNTHETIC_PRIVATE'); } });
  refused(p); assert.equal(reads, 0);
  const q = syntheticProof(); q.toJSON = () => { reads++; throw new Error('SYNTHETIC_PRIVATE'); }; refused(q); assert.equal(reads, 0);
});
test('operator return proof rejects inherited records, symbol fields and array accessors', () => {
  const p = syntheticProof(); p.controls = Object.create(p.controls); refused(p);
  const q = syntheticProof(); q.inputs[Symbol('private')] = 'SYNTHETIC_PRIVATE'; refused(q);
  const r = syntheticProof(); let reads = 0; Object.defineProperty(r.legs, '1', { enumerable: true, get() { reads++; return syntheticProof().legs[1]; } }); refused(r); assert.equal(reads, 0);
});
test('operator return proof fails closed for revoked proxies without exposing exceptions', () => {
  const { proxy, revoke } = Proxy.revocable(syntheticProof(), {}); revoke(); refused(proxy);
});

test('operator activation phase gate accepts only a fully confirmed finite clean-stop observation', () => {
  assert.equal(canActivateOperatorPackage(freeze(stop())), true);
});
for (const key of Object.keys(stop())) test(`operator activation phase gate blocks missing ${key} before a replacement can start`, () => {
  const value = stop(); delete value[key]; assert.equal(canActivateOperatorPackage(value), false);
});
for (const [key, value] of [['stage', 'running'], ['stage', 'faulted'], ['runtimeIdentityVerified', false], ['masterAbsent', false],
  ['processGroupAbsent', false], ['launcherExited', false], ['launcherExitCode', 1], ['launcherExitCode', null], ['launcherExitCode', -0],
  ['launcherSignal', 'SIGKILL'], ['portsClosed', false], ['operatorLockAbsent', false], ['pendingAbsent', false]])
  test(`operator activation phase gate blocks unknown/abnormal ${key}:${String(value)}`, () => { const record = stop(); record[key] = value; assert.equal(canActivateOperatorPackage(record), false); });
test('operator activation phase gate refuses unknown fields and never evaluates a claimed stop getter', () => {
  const value = stop(); value.authority = 'SYNTHETIC_PRIVATE'; assert.equal(canActivateOperatorPackage(value), false);
  const accessor = stop(); let reads = 0; Object.defineProperty(accessor, 'portsClosed', { enumerable: true, get() { reads++; return true; } });
  assert.equal(canActivateOperatorPackage(accessor), false); assert.equal(reads, 0);
});
