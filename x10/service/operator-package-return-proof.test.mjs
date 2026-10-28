import test from 'node:test';
import assert from 'node:assert/strict';
import { MANAGED_OPERATOR_RETURN_PROOF_KIND, MANAGED_OPERATOR_RETURN_PHASES,
  MAX_MANAGED_OPERATOR_RETURN_REPORT_BYTES, checkManagedOperatorReturnProof,
  checkManagedOperatorReturnReport, checkManagedOperatorReturnFailureReport,
  MANAGED_OPERATOR_RETURN_FAILURE_CODES, MANAGED_OPERATOR_RETURN_FAILURE_PHASES,
  MANAGED_OPERATOR_RETURN_PRIMARY_FAILURE_CODES } from './operator-package-return-proof.mjs';

// Synthetic finite facts only. No process, manager, socket or native code runs.
const positive = {
  "schemaVersion": 1,
  "kind": "nginx-x10-managed-operator-package-return-proof",
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
    "a2": {
      "runtimePayloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "operatorPayloadSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "nativeBinarySha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  },
  "inputs": {
    "pSha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "qSha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "a2RestoredSha256": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "phases": [
    "a_started",
    "a_served",
    "a_stopped",
    "b_staged",
    "b_started",
    "b_initial_p_observed",
    "b_q_applied",
    "b_served",
    "b_restart_started",
    "b_restarted_served",
    "b_stopped",
    "a2_restored",
    "a2_started",
    "a2_served",
    "a2_stopped",
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
      "name": "b",
      "identityOrdinals": {
        "installation": 2,
        "unit": 2,
        "session": 2,
        "revision": 2,
        "binding": 2,
        "invocation": 2
      },
      "inputSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "initialBindingAbsent": true,
      "readinessAccepted": true,
      "bindingMatchesOwnedRuntime": true,
      "getExact": true,
      "postExact": true,
      "streamExact": true,
      "postEffectsBefore": 1,
      "postEffectsAfter": 2
    },
    {
      "name": "b_restart",
      "identityOrdinals": {
        "installation": 2,
        "unit": 2,
        "session": 3,
        "revision": 3,
        "binding": 3,
        "invocation": 3
      },
      "inputSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "initialBindingAbsent": null,
      "readinessAccepted": true,
      "bindingMatchesOwnedRuntime": true,
      "getExact": true,
      "postExact": true,
      "streamExact": true,
      "postEffectsBefore": 2,
      "postEffectsAfter": 3
    },
    {
      "name": "a2",
      "identityOrdinals": {
        "installation": 3,
        "unit": 3,
        "session": 4,
        "revision": 4,
        "binding": 4,
        "invocation": 4
      },
      "inputSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "initialBindingAbsent": true,
      "readinessAccepted": true,
      "bindingMatchesOwnedRuntime": true,
      "getExact": true,
      "postExact": true,
      "streamExact": true,
      "postEffectsBefore": 3,
      "postEffectsAfter": 4
    }
  ],
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
    "beforeA2": {
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
  "restart": {
    "commandExercised": true,
    "oldLauncherExited": true,
    "oldMasterAbsent": true,
    "oldNativeGroupsAbsent": true,
    "oldInvocationRetired": true,
    "freshSession": true,
    "freshBinding": true,
    "freshInvocation": true,
    "sameUnit": true,
    "samePackage": true,
    "inputPreserved": true,
    "unitActive": true
  },
  "retention": {
    "retainedAAllFilesPreserved": true,
    "retainedABackupPreserved": true,
    "oldAInstallerRestoredQ": true,
    "bInitialPObservedBeforeQ": true
  },
  "counts": {
    "units": 3,
    "invocations": 4,
    "restarts": 1,
    "journalChecks": 5,
    "trafficGets": 4,
    "posts": 4,
    "streams": 4,
    "bInitialPGetChecks": 1
  },
  "cleanup": {
    "known": true,
    "ownedProcessesAbsent": true,
    "ownedLaunchersAbsent": true,
    "ownedListenersClosed": true,
    "ownedUnitsRemoved": 3,
    "ownedInstallationsRemoved": 3,
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
    "restartPreparedBindingObserved": false
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
const result = ok => ({ ok, code: ok ? 'managed_operator_return_proof_valid' : 'managed_operator_return_proof_invalid',
  compatibilityAccepted: false, managedPackageReturnAccepted: false, serviceAccepted: false, productionAccepted: false });
const report = proof => ({ schemaVersion: 2, kind: 'nginx-x10-managed-operator-return-report', ok: true,
  code: 'managed_operator_return_verified', phase: 'complete', proof, primaryFailure: null, cleanupFailures: [], cleanupFailureCount: 0,
  cleanupFailuresTruncated: false, serviceAccepted: false, productionAccepted: false, subprocessOutputsPublished: false });
test('finite positive managed return facts grant no acceptance', () => {
  assert.equal(MANAGED_OPERATOR_RETURN_PROOF_KIND, positive.kind);
  assert.deepEqual(MANAGED_OPERATOR_RETURN_PHASES, positive.phases);
  assert.equal(Object.isFrozen(MANAGED_OPERATOR_RETURN_PHASES), true);
  assert.deepEqual(checkManagedOperatorReturnProof(fixture()), result(true));
  assert.deepEqual(checkManagedOperatorReturnReport(report(fixture())), result(true));
  assert(Buffer.byteLength(JSON.stringify(report(fixture()))) < MAX_MANAGED_OPERATOR_RETURN_REPORT_BYTES);
});
for (const item of collect(positive).filter(item => !item.value || typeof item.value !== 'object'))
  test('required finite field refuses mutation ' + item.path.join('.'), () => {
    const value = fixture(), replacement = typeof item.value === 'boolean' ? !item.value
      : typeof item.value === 'number' ? item.value + 1 : item.value === null ? true : 'invalid';
    set(value, item.path, replacement); assert.deepEqual(checkManagedOperatorReturnProof(value), result(false));
  });
for (const item of collect(positive).filter(item => item.value && typeof item.value === 'object')) {
  const label = item.path.join('.') || 'root';
  for (const mutation of ['unknown', 'symbol', 'prototype', 'accessor', 'nonenumerable'])
    test('strict container refuses ' + mutation + ' at ' + label, () => {
      const value = fixture(), selected = at(value, item.path);
      let getterCalls = 0;
      if (mutation === 'unknown') selected.unexpected = true;
      if (mutation === 'symbol') selected[Symbol('unexpected')] = true;
      if (mutation === 'prototype') Object.setPrototypeOf(selected, Object.create(null));
      if (mutation === 'accessor') {
        const key = Object.keys(selected)[0];
        Object.defineProperty(selected, key, { enumerable: true, configurable: true, get() { getterCalls++; throw new Error('must not execute'); } });
      }
      if (mutation === 'nonenumerable') Object.defineProperty(selected, Object.keys(selected)[0], { enumerable: false });
      assert.deepEqual(checkManagedOperatorReturnProof(value), result(false)); assert.equal(getterCalls, 0);
    });
}
for (const initial of [true, false, undefined, 'unobserved', 0])
  test('manager restart preparation must remain explicit null, refuses ' + String(initial), () => {
    const value = fixture(); value.legs[2].initialBindingAbsent = initial;
    assert.equal(checkManagedOperatorReturnProof(value).ok, false);
  });
for (const path of [['phases'], ['legs']]) for (const mutation of ['hole', 'extra', 'missing', 'reordered'])
  test('strict observed array refuses ' + mutation + ' ' + path[0], () => {
    const value = fixture(), selected = at(value, path);
    if (mutation === 'hole') delete selected[0];
    if (mutation === 'extra') selected.push(selected[0]);
    if (mutation === 'missing') selected.pop();
    if (mutation === 'reordered') selected.reverse();
    assert.equal(checkManagedOperatorReturnProof(value).ok, false);
  });
for (const invalid of [NaN, Infinity, -Infinity, -0, -1, 1.5, Number.MAX_SAFE_INTEGER, '4', null, true])
  test('finite exact counters reject ' + String(invalid) + (Object.is(invalid, -0) ? ' negative zero' : ''), () => {
    const value = fixture(); value.counts.invocations = invalid;
    assert.equal(checkManagedOperatorReturnProof(value).ok, false);
  });
for (const invalid of ['a'.repeat(63), 'A'.repeat(64), 'a'.repeat(64) + '\n', 'a'.repeat(65), '', null, 42, new String('a'.repeat(64))])
  test('hash framing refuses ' + String(invalid).slice(0, 68), () => {
    const value = fixture(); value.packages.a.runtimePayloadSha256 = invalid;
    assert.equal(checkManagedOperatorReturnProof(value).ok, false);
  });
test('four unique sessions cannot replace required shared B unit and installation', () => {
  const value = fixture(); value.legs[2].identityOrdinals.unit = 3; value.legs[2].identityOrdinals.installation = 3;
  assert.equal(checkManagedOperatorReturnProof(value).ok, false);
});
test('final unit cleanup cannot substitute for retiring old runtime links before activation', () => {
  const value = fixture(); value.transitions.beforeB.runtimeLinkAbsent = false;
  assert.equal(checkManagedOperatorReturnProof(value).ok, false);
});
test('Q from B must be restored into old A2 rather than rewinding P', () => {
  const value = fixture(); value.inputs.a2RestoredSha256 = value.inputs.pSha256;
  assert.equal(checkManagedOperatorReturnProof(value).ok, false);
});
test('null-prototype JSON-like fact records are accepted', () => {
  const value = fixture();
  for (const { value: selected } of collect(value)) if (selected && typeof selected === 'object' && !Array.isArray(selected)) Object.setPrototypeOf(selected, null);
  assert.equal(checkManagedOperatorReturnProof(value).ok, true);
});
test('frozen own-data facts remain accepted', () => {
  const value = fixture(); for (const { value: selected } of collect(value).reverse()) if (selected && typeof selected === 'object') Object.freeze(selected);
  assert.equal(checkManagedOperatorReturnProof(value).ok, true);
});
for (const key of Object.keys(report(positive))) if (key !== 'proof')
  test('successful report refuses changed ' + key, () => {
    const value = report(fixture()); value[key] = key === 'cleanupFailures' ? ['unconfirmed']
      : typeof value[key] === 'boolean' ? !value[key] : typeof value[key] === 'number' ? value[key] + 1 : 'invalid';
    assert.equal(checkManagedOperatorReturnReport(value).ok, false);
  });
for (const mutation of ['extra', 'missing', 'getter', 'prototype', 'symbol', 'cleanupHole'])
  test('report rejects structural ' + mutation, () => {
    const value = report(fixture()); let calls = 0;
    if (mutation === 'extra') value.accepted = true;
    if (mutation === 'missing') delete value.ok;
    if (mutation === 'getter') Object.defineProperty(value, 'proof', { enumerable: true, get() { calls++; throw new Error('must not execute'); } });
    if (mutation === 'prototype') Object.setPrototypeOf(value, { inherited: true });
    if (mutation === 'symbol') value[Symbol('unexpected')] = true;
    if (mutation === 'cleanupHole') value.cleanupFailures.length = 1;
    assert.equal(checkManagedOperatorReturnReport(value).ok, false); assert.equal(calls, 0);
  });
for (const value of [null, undefined, true, 1, 'complete', [], Object.create({}), () => {}])
  test('unsupported root type ' + String(value), () => {
    assert.deepEqual(checkManagedOperatorReturnProof(value), result(false));
    assert.deepEqual(checkManagedOperatorReturnReport(value), result(false));
  });

const failed = () => ({ ...report(null), ok: false, code: 'usage_refused', phase: 'arguments', primaryFailure: 'usage_refused' });
for (const code of MANAGED_OPERATOR_RETURN_FAILURE_CODES.filter(code => code !== 'cleanup_unconfirmed'))
  test('bounded adverse report preserves known code without success ' + code, () => {
    const value = failed(); value.code = code; value.primaryFailure = code;
    const checked = checkManagedOperatorReturnFailureReport(value);
    assert.equal(checked.validFailureReport, true); assert.equal(checked.ok, false);
    for (const key of ['compatibilityAccepted', 'managedPackageReturnAccepted', 'serviceAccepted', 'productionAccepted']) assert.equal(checked[key], false);
    assert.equal(checkManagedOperatorReturnReport(value).ok, false);
  });
for (const phase of MANAGED_OPERATOR_RETURN_FAILURE_PHASES)
  test('bounded adverse report keeps closed phase ' + phase, () => {
    const value = failed(); value.phase = phase;
    assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, true);
  });
test('adverse cleanup codes remain finite and do not grant cleanup success', () => {
  const value = failed(); value.code = 'cleanup_unconfirmed';
  value.cleanupFailures = ['owned_unit_cleanup_unconfirmed', 'owned_origin_cleanup_unconfirmed']; value.cleanupFailureCount = 2;
  assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, true);
  value.cleanupFailures = Array(8).fill('owned_unit_cleanup_unconfirmed'); value.cleanupFailureCount = 9; value.cleanupFailuresTruncated = true;
  assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, true);
});
for (const [name, mutate] of [
  ['arbitrary error text', value => value.code = '/private/prefix/exception'],
  ['arbitrary phase', value => value.phase = 'unknown-private-path'],
  ['partial proof', value => value.proof = fixture()],
  ['success ok', value => value.ok = true],
  ['success code', value => value.code = 'managed_operator_return_verified'],
  ['service accepted', value => value.serviceAccepted = true],
  ['production accepted', value => value.productionAccepted = true],
  ['raw output published', value => value.subprocessOutputsPublished = true],
  ['unmatched cleanup reason', value => value.code = 'cleanup_unconfirmed'],
  ['unknown cleanup text', value => { value.code = 'cleanup_unconfirmed'; value.cleanupFailureCount = 1; value.cleanupFailures = ['/private/runtime/log']; }],
  ['cleanup count nonfinite', value => value.cleanupFailureCount = Infinity],
  ['cleanup count negative zero', value => value.cleanupFailureCount = -0],
  ['cleanup count unsafe', value => value.cleanupFailureCount = Number.MAX_SAFE_INTEGER],
  ['cleanup truncation false count', value => value.cleanupFailuresTruncated = true],
  ['cleanup array hole', value => value.cleanupFailures.length = 1],
  ['cleanup extra field', value => value.cleanupFailures.extra = true],
  ['unknown top field', value => value.stdout = 'must not publish'],
  ['unknown prototype', value => Object.setPrototypeOf(value, { inherited: true })],
]) test('malformed adverse report refuses ' + name, () => {
  const value = failed(); mutate(value); const checked = checkManagedOperatorReturnFailureReport(value);
  assert.equal(checked.validFailureReport, false); assert.equal(checked.ok, false);
});
test('adverse report accessors never execute', () => {
  const value = failed(); let calls = 0;
  Object.defineProperty(value, 'proof', { enumerable: true, get() { calls++; throw new Error('must not execute'); } });
  assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, false); assert.equal(calls, 0);
});

test('schema2 success requires thirteen exact fields and null primaryFailure', () => {
  const value = report(fixture()); assert.equal(Object.keys(value).length, 13);
  assert.equal(checkManagedOperatorReturnReport(value).ok, true);
  value.primaryFailure = 'file_refused'; assert.equal(checkManagedOperatorReturnReport(value).ok, false);
});
test('cleanup disposition preserves the original closed primary failure', () => {
  const value = failed(); value.primaryFailure = 'file_refused'; value.code = 'cleanup_unconfirmed';
  value.cleanupFailures = ['owned_unit_cleanup_unconfirmed']; value.cleanupFailureCount = 1;
  const before = structuredClone(value); const checked = checkManagedOperatorReturnFailureReport(value);
  assert.equal(checked.validFailureReport, true); assert.equal(checked.ok, false); assert.deepEqual(value, before);
});
for (const mutation of ['missing', 'inherited', 'getter', 'unknown', 'raw', 'null', 'boxed', 'final_cleanup', 'nonenumerable'])
  test('closed original primary refuses ' + mutation, () => {
    const value = failed(); let getterCalls = 0;
    if (mutation === 'missing') delete value.primaryFailure;
    if (mutation === 'inherited') { delete value.primaryFailure; Object.setPrototypeOf(value, { primaryFailure: 'usage_refused' }); }
    if (mutation === 'getter') Object.defineProperty(value, 'primaryFailure', { enumerable: true, get() { getterCalls++; throw new Error('must not execute'); } });
    if (mutation === 'unknown') value.primaryFailure = 'unknown_failure';
    if (mutation === 'raw') value.primaryFailure = '/private/operator/prefix/raw error';
    if (mutation === 'null') value.primaryFailure = null;
    if (mutation === 'boxed') value.primaryFailure = new String('usage_refused');
    if (mutation === 'final_cleanup') value.primaryFailure = 'cleanup_unconfirmed';
    if (mutation === 'nonenumerable') Object.defineProperty(value, 'primaryFailure', { enumerable: false });
    const checked = checkManagedOperatorReturnFailureReport(value);
    assert.equal(checked.validFailureReport, false); assert.equal(checked.ok, false); assert.equal(getterCalls, 0);
  });
test('success never reads a primaryFailure getter', () => {
  const value = report(fixture()); let getterCalls = 0;
  Object.defineProperty(value, 'primaryFailure', { enumerable: true, get() { getterCalls++; throw new Error('must not execute'); } });
  assert.equal(checkManagedOperatorReturnReport(value).ok, false); assert.equal(getterCalls, 0);
});
for (const code of ['usage_refused', 'report_bound'])
  test('normal refusal cannot silently replace primary with ' + code, () => {
    const value = failed(); value.code = 'file_refused'; value.primaryFailure = code;
    assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, false);
  });
test('report_bound retains an earlier closed cause or names its own bounded failure', () => {
  for (const primary of ['file_refused', 'report_bound']) {
    const value = failed(); value.code = 'report_bound'; value.primaryFailure = primary;
    assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, true);
  }
  const value = failed(); value.code = 'report_bound'; value.primaryFailure = 'file_refused';
  value.cleanupFailures = ['owned_unit_cleanup_unconfirmed']; value.cleanupFailureCount = 1;
  assert.equal(checkManagedOperatorReturnFailureReport(value).validFailureReport, true);
});
test('an original schema1 c2 adverse report cannot satisfy schema2 or new cleanup admission', () => {
  const original = { schemaVersion: 1, kind: 'nginx-x10-managed-operator-return-report', ok: false,
    code: 'cleanup_unconfirmed', phase: 'install_a', proof: null,
    cleanupFailures: ['owned_unit_cleanup_unconfirmed'], cleanupFailureCount: 1, cleanupFailuresTruncated: false,
    serviceAccepted: false, productionAccepted: false, subprocessOutputsPublished: false };
  assert.equal(checkManagedOperatorReturnReport(original).ok, false);
  assert.equal(checkManagedOperatorReturnFailureReport(original).validFailureReport, false);
  const oldSuccess = report(fixture()); oldSuccess.schemaVersion = 1; delete oldSuccess.primaryFailure;
  assert.equal(checkManagedOperatorReturnReport(oldSuccess).ok, false);
});
test('primary-code inventory excludes only the final cleanup disposition', () => {
  assert.equal(Object.isFrozen(MANAGED_OPERATOR_RETURN_PRIMARY_FAILURE_CODES), true);
  assert.equal(MANAGED_OPERATOR_RETURN_PRIMARY_FAILURE_CODES.includes('cleanup_unconfirmed'), false);
  assert.equal(MANAGED_OPERATOR_RETURN_PRIMARY_FAILURE_CODES.includes('report_bound'), true);
});
