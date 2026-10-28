import test from 'node:test';
import assert from 'node:assert/strict';
import { MANAGED_OPERATOR_FALLBACK_PROOF_KIND, MANAGED_OPERATOR_FALLBACK_PHASES,
  MAX_MANAGED_OPERATOR_FALLBACK_REPORT_BYTES, checkManagedOperatorFallbackProof,
  checkManagedOperatorFallbackReport, checkManagedOperatorFallbackFailureReport,
  MANAGED_OPERATOR_FALLBACK_FAILURE_CODES, MANAGED_OPERATOR_FALLBACK_FAILURE_PHASES,
  MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES } from './operator-package-fallback-proof.mjs';
import { checkManagedOperatorReturnProof, checkManagedOperatorReturnReport,
  checkManagedOperatorReturnFailureReport } from './operator-package-return-proof.mjs';

// Synthetic finite facts only: no manager, process, network or native fixture.
const positive = {
  "schemaVersion": 1,
  "kind": "nginx-x10-managed-operator-package-fallback-proof",
  "packages": {
    "a": {
      "runtimePayloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "operatorPayloadSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "nativeBinarySha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "b": {
      "runtimePayloadSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "operatorPayloadSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "nativeBinarySha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "aFallback": {
      "runtimePayloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "operatorPayloadSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "nativeBinarySha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  },
  "inputs": {
    "pSha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "bStagedSha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "aFallbackSha256": "1111111111111111111111111111111111111111111111111111111111111111"
  },
  "phases": [
    "a_started",
    "a_served",
    "a_stopped",
    "b_staged",
    "b_start_requested",
    "b_failed",
    "b_retired",
    "a_retention_verified",
    "a_prepared",
    "a_reactivated",
    "a_fallback_served",
    "a_fallback_stopped",
    "cleanup"
  ],
  "legs": [
    {
      "name": "a",
      "identityOrdinals": {
        "installation": 1,
        "unit": 1,
        "session": 1,
        "revision": 1,
        "binding": 1,
        "invocation": 1
      },
      "inputSha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "initialBindingAbsent": true,
      "readinessAccepted": true,
      "bindingMatchesOwnedRuntime": true,
      "getExact": true,
      "postExact": true,
      "streamExact": true,
      "postEffectsBefore": 0,
      "postEffectsAfter": 1
    },
    {
      "name": "a_fallback",
      "identityOrdinals": {
        "installation": 1,
        "unit": 3,
        "session": 3,
        "revision": 3,
        "binding": 2,
        "invocation": 3
      },
      "inputSha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "initialBindingAbsent": true,
      "readinessAccepted": true,
      "bindingMatchesOwnedRuntime": true,
      "getExact": true,
      "postExact": true,
      "streamExact": true,
      "postEffectsBefore": 1,
      "postEffectsAfter": 2
    }
  ],
  "failedB": {
    "identityOrdinals": {
      "installation": 2,
      "unit": 2,
      "session": 2,
      "revision": 2,
      "invocation": 2
    },
    "readinessHeld": true,
    "activatingLauncherCaptured": true,
    "nativeCaptured": true,
    "invocationCaptured": true,
    "hookCaptured": true,
    "wrongBodyObserved": true,
    "managerRefused": true,
    "hookExitObserved": true,
    "bindingAbsent": true,
    "noPOSTEffects": true,
    "failedSessionStopped": true,
    "launcherExited": true,
    "nativeGroupsAbsent": true,
    "listeningPortsClosed": true,
    "controlSocketAbsent": true,
    "operatorLocksAbsent": true,
    "managerResetConfirmed": true,
    "runtimeLinkAbsent": true,
    "unitNotFound": true
  },
  "transitions": {
    "beforeB": {
      "unitInactive": true,
      "invocationRetired": true,
      "launcherExited": true,
      "masterAbsent": true,
      "nativeGroupsAbsent": true,
      "portsClosed": true,
      "controlSocketAbsent": true,
      "operatorLocksAbsent": true,
      "pendingAbsent": true,
      "runtimeLinkAbsent": true,
      "unitNotFound": true
    },
    "afterFallback": {
      "unitInactive": true,
      "invocationRetired": true,
      "launcherExited": true,
      "masterAbsent": true,
      "nativeGroupsAbsent": true,
      "portsClosed": true,
      "controlSocketAbsent": true,
      "operatorLocksAbsent": true,
      "pendingAbsent": true,
      "runtimeLinkAbsent": true,
      "unitNotFound": true
    }
  },
  "preparation": {
    "freshSession": true,
    "freshRevision": true,
    "nullInitialBinding": true,
    "inputPPreserved": true,
    "registryTwoSessions": true,
    "oldSessionPreservedStopped": true,
    "oneFreshHistoryEntry": true
  },
  "retention": {
    "retainedAAllFilesPreservedThroughBFailure": true,
    "retainedABackupPreserved": true,
    "keptAPrefixReused": true,
    "keptAInstallationPreserved": true,
    "oldAExplicitlyPrepared": true,
    "oldAInputPreserved": true
  },
  "counts": {
    "units": 3,
    "installations": 2,
    "successfulInvocations": 2,
    "failedAttempts": 1,
    "restarts": 0,
    "journalChecks": 2,
    "trafficGets": 2,
    "posts": 2,
    "streams": 2
  },
  "cleanup": {
    "known": true,
    "ownedProcessesAbsent": true,
    "ownedLaunchersAbsent": true,
    "ownedListenersClosed": true,
    "ownedUnitsRemoved": 3,
    "ownedInstallationsRemoved": 2,
    "historicalBundleRemoved": true,
    "backupFilesRemoved": true
  },
  "limits": {
    "consistencyOnly": true,
    "nativeBinaryUpgradeAccepted": false,
    "liveConnectionPreserved": false,
    "applicationSideEffectsReversed": false,
    "productionAccepted": false,
    "automaticMigrationAccepted": false,
    "allTrafficFenceAccepted": false,
    "automaticFallbackAccepted": false
  }
};
const fixture = () => structuredClone(positive);
const at = (value, keys) => keys.reduce((current, key) => current[key], value);
function set(value, keys, replacement) { at(value, keys.slice(0, -1))[keys.at(-1)] = replacement; }
function collect(value, path = [], output = []) {
  output.push({ path, value });
  if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) collect(item, [...path, key], output);
  return output;
}
const result = ok => ({ ok, code: ok ? 'managed_operator_fallback_proof_valid' : 'managed_operator_fallback_proof_invalid',
  compatibilityAccepted: false, managedPackageFallbackAccepted: false, serviceAccepted: false, productionAccepted: false });
const report = proof => ({ schemaVersion: 1, kind: 'nginx-x10-managed-operator-fallback-report', ok: true,
  code: 'managed_operator_fallback_verified', phase: 'complete', proof, primaryFailure: null,
  cleanupFailures: [], cleanupFailureCount: 0, cleanupFailuresTruncated: false,
  serviceAccepted: false, productionAccepted: false, subprocessOutputsPublished: false });
const failed = () => ({ ...report(null), ok: false, code: 'failed_start_unconfirmed',
  phase: 'b_failed', primaryFailure: 'failed_start_unconfirmed' });
test('finite synthetic fallback facts grant no product acceptance', () => {
  assert.equal(MANAGED_OPERATOR_FALLBACK_PROOF_KIND, positive.kind);
  assert.deepEqual(MANAGED_OPERATOR_FALLBACK_PHASES, positive.phases);
  assert.equal(Object.isFrozen(MANAGED_OPERATOR_FALLBACK_PHASES), true);
  assert.deepEqual(checkManagedOperatorFallbackProof(fixture()), result(true));
  assert.deepEqual(checkManagedOperatorFallbackReport(report(fixture())), result(true));
  assert(Buffer.byteLength(JSON.stringify(report(fixture()))) < MAX_MANAGED_OPERATOR_FALLBACK_REPORT_BYTES);
});
for (const item of collect(positive).filter(item => !item.value || typeof item.value !== 'object'))
  test('required fallback fact refuses mutation ' + item.path.join('.'), () => {
    const value = fixture(), replacement = typeof item.value === 'boolean' ? !item.value
      : typeof item.value === 'number' ? item.value + 1 : item.value === null ? true : 'invalid';
    set(value, item.path, replacement); assert.deepEqual(checkManagedOperatorFallbackProof(value), result(false));
  });
for (const item of collect(positive).filter(item => item.value && typeof item.value === 'object')) {
  const label = item.path.join('.') || 'root';
  for (const mutation of ['unknown', 'symbol', 'prototype', 'accessor', 'nonenumerable', 'missing'])
    test('fallback container refuses ' + mutation + ' at ' + label, () => {
      const value = fixture(), selected = at(value, item.path), key = Object.keys(selected)[0];
      let getterCalls = 0;
      if (mutation === 'unknown') selected.unexpected = true;
      if (mutation === 'symbol') selected[Symbol('unexpected')] = true;
      if (mutation === 'prototype') Object.setPrototypeOf(selected, Object.create(null));
      if (mutation === 'accessor') Object.defineProperty(selected, key, { enumerable: true, configurable: true,
        get() { getterCalls++; throw new Error('must not execute'); } });
      if (mutation === 'nonenumerable') Object.defineProperty(selected, key, { enumerable: false });
      if (mutation === 'missing') delete selected[key];
      assert.deepEqual(checkManagedOperatorFallbackProof(value), result(false)); assert.equal(getterCalls, 0);
    });
}
for (const key of ['phases', 'legs']) for (const mutation of ['hole', 'extra', 'missing', 'reordered'])
  test('observed fallback array refuses ' + mutation + ' ' + key, () => {
    const value = fixture(), selected = value[key];
    if (mutation === 'hole') delete selected[0];
    if (mutation === 'extra') selected.push(selected[0]);
    if (mutation === 'missing') selected.pop();
    if (mutation === 'reordered') selected.reverse();
    assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
  });
for (const invalid of [NaN, Infinity, -Infinity, -0, -1, 1.5, Number.MAX_SAFE_INTEGER, '2', null, true])
  test('finite fallback counters refuse ' + String(invalid) + (Object.is(invalid, -0) ? ' negative zero' : ''), () => {
    const value = fixture(); value.counts.successfulInvocations = invalid;
    assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
  });
for (const invalid of ['a'.repeat(63), 'A'.repeat(64), 'a'.repeat(64) + '\n', 'a'.repeat(65), '', null, 42, new String('a'.repeat(64))])
  test('fallback hash framing refuses ' + String(invalid).slice(0, 68), () => {
    const value = fixture(); value.packages.a.runtimePayloadSha256 = invalid;
    assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
  });
for (const name of ['a', 'b', 'aFallback']) for (const key of ['runtimePayloadSha256', 'operatorPayloadSha256', 'nativeBinarySha256'])
  test('package relational identity is independently checked ' + name + '.' + key, () => {
    const value = fixture(); value.packages[name][key] = 'f'.repeat(64);
    // A newly distinct B payload is allowed; changing one of its payload hashes
    // alone does not violate the declaration. Equaling A is the counterexample.
    if (name === 'b' && key !== 'nativeBinarySha256') value.packages.b[key] = value.packages.a[key];
    assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
  });
for (const key of ['pSha256', 'bStagedSha256', 'aFallbackSha256'])
  test('the same retained P must survive every package leg ' + key, () => {
    const value = fixture(); value.inputs[key] = '2'.repeat(64);
    assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
  });
test('a reinstalled A cannot impersonate kept A under a new unit', () => {
  const value = fixture(); value.legs[1].identityOrdinals.installation = 3;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('failed B cannot gain a binding ordinal', () => {
  const value = fixture(); value.failedB.identityOrdinals.binding = 2;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('failed B is not counted as a successful traffic leg or manager restart', () => {
  const value = fixture(); value.counts.successfulInvocations = 3; value.counts.failedAttempts = 0; value.counts.restarts = 1;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('final cleanup cannot substitute for B retirement before fallback preparation', () => {
  const value = fixture(); value.failedB.runtimeLinkAbsent = false;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('new installation preparation cannot substitute for same-prefix two-session registry', () => {
  const value = fixture(); value.preparation.registryTwoSessions = false;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('all-file A preservation applies through failed B before intentional reactivation', () => {
  const value = fixture(); value.retention.retainedAAllFilesPreservedThroughBFailure = false;
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('normal managed return counters and phase sequence are not fallback evidence', () => {
  const value = fixture(); value.counts = { units: 3, invocations: 4, restarts: 1, journalChecks: 5,
    trafficGets: 4, posts: 4, streams: 4, bInitialPGetChecks: 1 };
  assert.equal(checkManagedOperatorFallbackProof(value).ok, false);
});
test('fallback proof and reports never satisfy normal managed return admission', () => {
  assert.equal(checkManagedOperatorReturnProof(fixture()).ok, false);
  assert.equal(checkManagedOperatorReturnReport(report(fixture())).ok, false);
  assert.equal(checkManagedOperatorReturnFailureReport(failed()).validFailureReport, false);
  const normalKind = report(fixture()); normalKind.kind = 'nginx-x10-managed-operator-return-report'; normalKind.schemaVersion = 2;
  normalKind.code = 'managed_operator_return_verified';
  assert.equal(checkManagedOperatorFallbackReport(normalKind).ok, false);
  assert.equal(checkManagedOperatorReturnReport(normalKind).ok, false);
});
test('null-prototype finite fallback facts are accepted', () => {
  const value = fixture();
  for (const { value: selected } of collect(value)) if (selected && typeof selected === 'object' && !Array.isArray(selected)) Object.setPrototypeOf(selected, null);
  assert.equal(checkManagedOperatorFallbackProof(value).ok, true);
});
test('deeply frozen finite fallback facts remain accepted', () => {
  const value = fixture();
  for (const { value: selected } of collect(value).reverse()) if (selected && typeof selected === 'object') Object.freeze(selected);
  assert.equal(checkManagedOperatorFallbackProof(value).ok, true);
});
for (const key of Object.keys(report(positive))) if (key !== 'proof')
  test('successful fallback report refuses changed ' + key, () => {
    const value = report(fixture()); value[key] = key === 'cleanupFailures' ? ['unconfirmed']
      : typeof value[key] === 'boolean' ? !value[key] : typeof value[key] === 'number' ? value[key] + 1 : 'invalid';
    assert.equal(checkManagedOperatorFallbackReport(value).ok, false);
  });
for (const mutation of ['extra', 'missing', 'getter', 'prototype', 'symbol', 'cleanupHole'])
  test('success fallback report refuses structural ' + mutation, () => {
    const value = report(fixture()); let calls = 0;
    if (mutation === 'extra') value.accepted = true;
    if (mutation === 'missing') delete value.ok;
    if (mutation === 'getter') Object.defineProperty(value, 'proof', { enumerable: true, get() { calls++; throw new Error('must not execute'); } });
    if (mutation === 'prototype') Object.setPrototypeOf(value, { inherited: true });
    if (mutation === 'symbol') value[Symbol('unexpected')] = true;
    if (mutation === 'cleanupHole') value.cleanupFailures.length = 1;
    assert.equal(checkManagedOperatorFallbackReport(value).ok, false); assert.equal(calls, 0);
  });
for (const value of [null, undefined, true, 1, 'complete', [], Object.create({}), () => {}])
  test('unsupported fallback root refuses ' + String(value), () => {
    assert.deepEqual(checkManagedOperatorFallbackProof(value), result(false));
    assert.deepEqual(checkManagedOperatorFallbackReport(value), result(false));
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, false);
  });
for (const code of MANAGED_OPERATOR_FALLBACK_FAILURE_CODES.filter(code => code !== 'cleanup_unconfirmed'))
  test('closed fallback refusal preserves primary code ' + code, () => {
    const value = failed(); value.code = code; value.primaryFailure = code;
    const checked = checkManagedOperatorFallbackFailureReport(value);
    assert.equal(checked.validFailureReport, true); assert.equal(checked.ok, false);
    for (const key of ['compatibilityAccepted', 'managedPackageFallbackAccepted', 'serviceAccepted', 'productionAccepted']) assert.equal(checked[key], false);
    assert.equal(checkManagedOperatorFallbackReport(value).ok, false);
  });
for (const phase of MANAGED_OPERATOR_FALLBACK_FAILURE_PHASES)
  test('bounded adverse fallback report preserves closed phase ' + phase, () => {
    const value = failed(); value.phase = phase;
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, true);
  });
test('cleanup refusal retains original failed-start code and finite cleanup counts', () => {
  const value = failed(); value.code = 'cleanup_unconfirmed';
  value.cleanupFailures = ['owned_unit_cleanup_unconfirmed', 'owned_origin_cleanup_unconfirmed']; value.cleanupFailureCount = 2;
  assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, true);
  const before = structuredClone(value); checkManagedOperatorFallbackFailureReport(value); assert.deepEqual(value, before);
  value.cleanupFailures = Array(8).fill('owned_unit_cleanup_unconfirmed'); value.cleanupFailureCount = 9; value.cleanupFailuresTruncated = true;
  assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, true);
});
for (const [name, mutate] of [
  ['arbitrary exception', value => value.code = '/private/operator/raw failure'],
  ['arbitrary phase', value => value.phase = 'unknown-private-path'],
  ['partial proof', value => value.proof = fixture()],
  ['success ok', value => value.ok = true],
  ['success code', value => value.code = 'managed_operator_fallback_verified'],
  ['service acceptance', value => value.serviceAccepted = true],
  ['production acceptance', value => value.productionAccepted = true],
  ['raw subprocess publication', value => value.subprocessOutputsPublished = true],
  ['cleanup code without cleanup failure', value => value.code = 'cleanup_unconfirmed'],
  ['unknown cleanup text', value => { value.code = 'cleanup_unconfirmed'; value.cleanupFailureCount = 1; value.cleanupFailures = ['/private/runtime/log']; }],
  ['cleanup count nonfinite', value => value.cleanupFailureCount = Infinity],
  ['cleanup count negative zero', value => value.cleanupFailureCount = -0],
  ['cleanup count unsafe', value => value.cleanupFailureCount = Number.MAX_SAFE_INTEGER],
  ['cleanup count above bound', value => value.cleanupFailureCount = 65],
  ['cleanup truncation without entries', value => value.cleanupFailuresTruncated = true],
  ['cleanup hole', value => value.cleanupFailures.length = 1],
  ['cleanup extra key', value => value.cleanupFailures.extra = true],
  ['unknown top key', value => value.stdout = 'private output'],
  ['custom prototype', value => Object.setPrototypeOf(value, { inherited: true })],
  ['original cause missing', value => delete value.primaryFailure],
  ['original cause unknown', value => value.primaryFailure = 'unknown_failure'],
  ['original cause raw', value => value.primaryFailure = '/private/operator/raw cause'],
  ['original cause null', value => value.primaryFailure = null],
  ['original cause boxed', value => value.primaryFailure = new String('failed_start_unconfirmed')],
  ['original cause replaced by final disposition', value => value.primaryFailure = 'cleanup_unconfirmed'],
  ['original cause nonenumerable', value => Object.defineProperty(value, 'primaryFailure', { enumerable: false })],
  ['original cause mismatches report', value => value.primaryFailure = 'file_refused'],
]) test('malformed fallback failure report refuses ' + name, () => {
  const value = failed(); mutate(value); const checked = checkManagedOperatorFallbackFailureReport(value);
  assert.equal(checked.validFailureReport, false); assert.equal(checked.ok, false);
});
for (const key of ['proof', 'primaryFailure', 'cleanupFailures'])
  test('fallback failure never evaluates accessor ' + key, () => {
    const value = failed(); let calls = 0;
    Object.defineProperty(value, key, { enumerable: true, get() { calls++; throw new Error('must not execute'); } });
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, false); assert.equal(calls, 0);
  });
test('report bound refusal preserves original closed cause without granting success', () => {
  for (const primary of ['failed_start_unconfirmed', 'report_bound']) {
    const value = failed(); value.code = 'report_bound'; value.primaryFailure = primary;
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, true);
    assert.equal(checkManagedOperatorFallbackReport(value).ok, false);
  }
});
test('failure inventories are frozen and cannot promote cleanup to original cause', () => {
  for (const inventory of [MANAGED_OPERATOR_FALLBACK_FAILURE_CODES, MANAGED_OPERATOR_FALLBACK_FAILURE_PHASES,
    MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES]) assert.equal(Object.isFrozen(inventory), true);
  assert.equal(MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES.includes('cleanup_unconfirmed'), false);
  assert.equal(MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES.includes('report_bound'), true);
});

for (const phase of ['apply_q', 'restart_b', 'stop_b', 'restore_a2', 'start_a2', 'stop_a2'])
  test('normal-only phase is not a fallback failure ' + phase, () => {
    const value = failed(); value.phase = phase;
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, false);
  });
for (const code of ['initial_b_unconfirmed', 'unit_restart', 'restart_identity', 'restore_refused', 'managed_operator_fallback_refused'])
  test('unreachable normal-only label is not a fallback cause ' + code, () => {
    const value = failed(); value.code = code; value.primaryFailure = code;
    assert.equal(checkManagedOperatorFallbackFailureReport(value).validFailureReport, false);
  });
