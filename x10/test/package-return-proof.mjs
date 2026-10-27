// A finite consistency checker for separately observed fixture facts. It does
// not execute an operator action, authenticate observations, grant authority or
// accept a release. Real native/service behavior remains a hosted evidence gate.
export const OPERATOR_RETURN_PROOF_KIND = 'nginx-x10-operator-package-return-proof';
export const OPERATOR_RETURN_PHASES = Object.freeze([
  'a_started', 'a_served', 'a_stopped', 'b_staged', 'b_started',
  'b_readiness_refused', 'b_served', 'b_stopped', 'a2_restored',
  'a2_started', 'a2_served', 'a2_stopped', 'cleanup',
]);
const STOP_KEYS = ['stage', 'runtimeIdentityVerified', 'masterAbsent', 'processGroupAbsent',
  'launcherExited', 'launcherExitCode', 'launcherSignal', 'portsClosed', 'operatorLockAbsent', 'pendingAbsent'];
const PACKAGE_KEYS = ['runtimePayloadSha256', 'operatorPayloadSha256', 'nativeBinarySha256'];
const LEG_KEYS = ['name', 'identityOrdinals', 'inputSha256', 'initialBindingAbsent',
  'readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact', 'streamExact',
  'postEffectsBefore', 'postEffectsAfter', 'stop'];
const IDENTITY_KEYS = ['installation', 'session', 'revision', 'binding'];
const CONTROL_KEYS = ['bWrongReadinessRefused', 'bBindingAbsentAfterRefusal', 'retainedAAllFilesPreserved',
  'retainedABackupPreserved', 'forwardStartedAfterConfirmedStop', 'returnStartedAfterConfirmedStop', 'oldAInstallerRestoredQ'];
const TOP_KEYS = ['schemaVersion', 'kind', 'packages', 'inputs', 'phases', 'legs', 'staging', 'controls', 'cleanup', 'limits'];
const own = (value, key) => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) throw new Error('invalid');
  return descriptor.value;
};
function fields(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error('invalid');
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) throw new Error('invalid');
  return Object.fromEntries(keys.map(key => [key, own(value, key)]));
}
function array(value, length) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertyDescriptor(value, 'length')?.value !== length) throw new Error('invalid');
  const actual = Reflect.ownKeys(value), names = Array.from({ length }, (_, i) => String(i));
  if (actual.length !== length + 1 || actual.some(key => key !== 'length' && !names.includes(key))) throw new Error('invalid');
  return names.map(key => own(value, key));
}
const hash = value => typeof value === 'string' && value.length === 64 && !/[^a-f0-9]/.test(value);
const integer = (value, expected) => Number.isSafeInteger(value) && !Object.is(value, -0) && value === expected;
const requireFact = condition => { if (!condition) throw new Error('invalid'); };
function stopped(value) {
  const record = fields(value, STOP_KEYS);
  requireFact(record.stage === 'stopped' && integer(record.launcherExitCode, 0) && record.launcherSignal === null);
  for (const key of STOP_KEYS.filter(key => !['stage', 'launcherExitCode', 'launcherSignal'].includes(key))) requireFact(record[key] === true);
}

// Call this on a FRESH, actual stop observation before starting the next owned
// package. The return value is a finite fact check, not a process/OS fence or a
// promise that the observation remains current after it returns.
export function canActivateOperatorPackage(stopObservation) {
  try { stopped(stopObservation); return true; } catch { return false; }
}
function result(ok) {
  return { ok, code: ok ? 'operator_return_proof_valid' : 'operator_return_proof_invalid',
    compatibilityAccepted: false, packageReturnAccepted: false, serviceAccepted: false, productionAccepted: false };
}
export function checkOperatorReturnProof(value) {
  try {
    const proof = fields(value, TOP_KEYS);
    requireFact(proof.schemaVersion === 1 && proof.kind === OPERATOR_RETURN_PROOF_KIND);
    const packageValues = fields(proof.packages, ['a', 'b', 'a2']), packages = {};
    for (const label of ['a', 'b', 'a2']) {
      packages[label] = fields(packageValues[label], PACKAGE_KEYS);
      for (const key of PACKAGE_KEYS) requireFact(hash(packages[label][key]));
    }
    for (const key of ['runtimePayloadSha256', 'operatorPayloadSha256'])
      requireFact(packages.a[key] === packages.a2[key] && packages.a[key] !== packages.b[key]);
    requireFact(packages.a.nativeBinarySha256 === packages.b.nativeBinarySha256
      && packages.a.nativeBinarySha256 === packages.a2.nativeBinarySha256);
    const inputs = fields(proof.inputs, ['pSha256', 'qSha256', 'a2RestoredSha256']);
    for (const key of Object.keys(inputs)) requireFact(hash(inputs[key]));
    requireFact(inputs.pSha256 !== inputs.qSha256 && inputs.qSha256 === inputs.a2RestoredSha256);
    const phases = array(proof.phases, OPERATOR_RETURN_PHASES.length);
    requireFact(phases.every((phase, index) => phase === OPERATOR_RETURN_PHASES[index]));
    const legs = array(proof.legs, 3);
    for (const [index, value] of legs.entries()) {
      const leg = fields(value, LEG_KEYS), identities = fields(leg.identityOrdinals, IDENTITY_KEYS);
      requireFact(leg.name === ['a', 'b', 'a2'][index]);
      // The observer assigns these finite ordinals by privately comparing the
      // actual identities in one map per identity kind. They expose equality,
      // not raw PIDs, paths, session identifiers or binding metadata.
      for (const key of IDENTITY_KEYS) requireFact(integer(identities[key], index + 1));
      requireFact(leg.inputSha256 === (index === 0 ? inputs.pSha256 : inputs.qSha256));
      for (const key of ['initialBindingAbsent', 'readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact', 'streamExact']) requireFact(leg[key] === true);
      requireFact(integer(leg.postEffectsBefore, index) && integer(leg.postEffectsAfter, index + 1));
      stopped(leg.stop);
    }
    const staging = fields(proof.staging, ['commandExercised', 'sourcePreserved', 'initialBindingAbsent',
      'initialInputSha256', 'runtimePayloadChanged', 'operatorPayloadChanged', 'nativeBinaryChanged']);
    for (const key of ['commandExercised', 'sourcePreserved', 'initialBindingAbsent', 'runtimePayloadChanged', 'operatorPayloadChanged']) requireFact(staging[key] === true);
    requireFact(staging.initialInputSha256 === inputs.pSha256 && staging.nativeBinaryChanged === false);
    const controls = fields(proof.controls, CONTROL_KEYS);
    for (const key of CONTROL_KEYS) requireFact(controls[key] === true);
    const cleanup = fields(proof.cleanup, ['known', 'ownedProcessesAbsent', 'ownedLaunchersAbsent',
      'ownedListenersClosed', 'ownedInstallationsRemoved', 'historicalBundleRemoved', 'backupFilesRemoved']);
    for (const key of ['known', 'ownedProcessesAbsent', 'ownedLaunchersAbsent', 'ownedListenersClosed', 'historicalBundleRemoved', 'backupFilesRemoved']) requireFact(cleanup[key] === true);
    requireFact(integer(cleanup.ownedInstallationsRemoved, 3));
    const limits = fields(proof.limits, ['consistencyOnly', 'nativeBinaryUpgradeAccepted', 'liveConnectionPreserved',
      'applicationSideEffectsReversed', 'managedServiceAccepted', 'productionAccepted']);
    requireFact(limits.consistencyOnly === true);
    for (const key of ['nativeBinaryUpgradeAccepted', 'liveConnectionPreserved', 'applicationSideEffectsReversed', 'managedServiceAccepted', 'productionAccepted']) requireFact(limits[key] === false);
    return result(true);
  } catch { return result(false); }
}
