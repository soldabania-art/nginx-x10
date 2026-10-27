// Finite consistency checks for independently collected managed-service facts.
// These functions perform no I/O and grant no execution or release authority.
export const MANAGED_OPERATOR_RETURN_PROOF_KIND = 'nginx-x10-managed-operator-package-return-proof';
export const MAX_MANAGED_OPERATOR_RETURN_REPORT_BYTES = 12288;
export const MANAGED_OPERATOR_RETURN_PHASES = Object.freeze([
  'a_started', 'a_served', 'a_stopped', 'b_staged', 'b_started',
  'b_initial_p_observed', 'b_q_applied', 'b_served', 'b_restart_started',
  'b_restarted_served', 'b_stopped', 'a2_restored', 'a2_started',
  'a2_served', 'a2_stopped', 'cleanup',
]);
const PACKAGE_KEYS = ['runtimePayloadSha256', 'operatorPayloadSha256', 'nativeBinarySha256'];
const PROOF_KEYS = ['schemaVersion', 'kind', 'packages', 'inputs', 'phases', 'legs',
  'transitions', 'restart', 'retention', 'counts', 'cleanup', 'limits'];
const LEG_KEYS = ['name', 'identityOrdinals', 'inputSha256', 'initialBindingAbsent',
  'readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact',
  'streamExact', 'postEffectsBefore', 'postEffectsAfter'];
const IDENTITY_KEYS = ['installation', 'unit', 'session', 'revision', 'binding', 'invocation'];
const STOP_KEYS = ['unitInactive', 'invocationRetired', 'launcherExited', 'masterAbsent',
  'nativeGroupsAbsent', 'portsClosed', 'controlSocketAbsent', 'operatorLocksAbsent', 'pendingAbsent',
  'runtimeLinkAbsent', 'unitNotFound'];
const RESTART_KEYS = ['commandExercised', 'oldLauncherExited', 'oldMasterAbsent',
  'oldNativeGroupsAbsent', 'oldInvocationRetired', 'freshSession', 'freshBinding',
  'freshInvocation', 'sameUnit', 'samePackage', 'inputPreserved', 'unitActive'];
const RETENTION_KEYS = ['retainedAAllFilesPreserved', 'retainedABackupPreserved',
  'oldAInstallerRestoredQ', 'bInitialPObservedBeforeQ'];
const COUNTS = Object.freeze({ units: 3, invocations: 4, restarts: 1, journalChecks: 5,
  trafficGets: 4, posts: 4, streams: 4, bInitialPGetChecks: 1 });
const CLEANUP_KEYS = ['known', 'ownedProcessesAbsent', 'ownedLaunchersAbsent',
  'ownedListenersClosed', 'ownedUnitsRemoved', 'ownedInstallationsRemoved',
  'historicalBundleRemoved', 'backupFilesRemoved'];
const LIMIT_KEYS = ['consistencyOnly', 'nativeBinaryUpgradeAccepted', 'liveConnectionPreserved',
  'applicationSideEffectsReversed', 'productionAccepted', 'automaticMigrationAccepted',
  'allTrafficFenceAccepted', 'restartPreparedBindingObserved'];
const REPORT_KEYS = ['schemaVersion', 'kind', 'ok', 'code', 'phase', 'proof',
  'cleanupFailures', 'cleanupFailureCount', 'cleanupFailuresTruncated',
  'serviceAccepted', 'productionAccepted', 'subprocessOutputsPublished'];
const invalid = () => { throw new Error('invalid'); };
function own(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
  return descriptor.value;
}
function fields(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) invalid();
  return Object.fromEntries(keys.map(key => [key, own(value, key)]));
}
function array(value, length) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertyDescriptor(value, 'length')?.value !== length) invalid();
  const actual = Reflect.ownKeys(value), indices = Array.from({ length }, (_, index) => String(index));
  if (actual.length !== length + 1 || actual.some(key => key !== 'length' && !indices.includes(key))) invalid();
  return indices.map(key => own(value, key));
}
const requireFact = condition => { if (!condition) invalid(); };
const hash = value => typeof value === 'string' && value.length === 64 && !/[^a-f0-9]/.test(value);
const integer = (value, expected) => Number.isSafeInteger(value) && !Object.is(value, -0) && value === expected;
const allTrue = (value, keys) => { const record = fields(value, keys); for (const key of keys) requireFact(record[key] === true); };
function proofValid(value) {
  const proof = fields(value, PROOF_KEYS);
  requireFact(proof.schemaVersion === 1 && proof.kind === MANAGED_OPERATOR_RETURN_PROOF_KIND);
  const selected = fields(proof.packages, ['a', 'b', 'a2']), packages = {};
  for (const name of ['a', 'b', 'a2']) {
    packages[name] = fields(selected[name], PACKAGE_KEYS);
    for (const key of PACKAGE_KEYS) requireFact(hash(packages[name][key]));
  }
  for (const key of ['runtimePayloadSha256', 'operatorPayloadSha256'])
    requireFact(packages.a[key] === packages.a2[key] && packages.a[key] !== packages.b[key]);
  requireFact(packages.a.nativeBinarySha256 === packages.b.nativeBinarySha256
    && packages.a.nativeBinarySha256 === packages.a2.nativeBinarySha256);
  const inputs = fields(proof.inputs, ['pSha256', 'qSha256', 'a2RestoredSha256']);
  for (const key of Object.keys(inputs)) requireFact(hash(inputs[key]));
  requireFact(inputs.pSha256 !== inputs.qSha256 && inputs.qSha256 === inputs.a2RestoredSha256);
  const phases = array(proof.phases, MANAGED_OPERATOR_RETURN_PHASES.length);
  requireFact(phases.every((phase, index) => phase === MANAGED_OPERATOR_RETURN_PHASES[index]));
  const legs = array(proof.legs, 4);
  for (const [index, value] of legs.entries()) {
    const leg = fields(value, LEG_KEYS), identities = fields(leg.identityOrdinals, IDENTITY_KEYS);
    requireFact(leg.name === ['a', 'b', 'b_restart', 'a2'][index]);
    for (const key of IDENTITY_KEYS) requireFact(integer(identities[key],
      ['installation', 'unit'].includes(key) ? [1, 2, 2, 3][index] : index + 1));
    requireFact(leg.inputSha256 === (index === 0 ? inputs.pSha256 : inputs.qSha256));
    // An active manager restart can bind before the observer regains control.
    // null records that intermediate absence was UNOBSERVED; neither true nor
    // false is supported there. The other three preparations were observed.
    requireFact(leg.initialBindingAbsent === (index === 2 ? null : true));
    for (const key of ['readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact', 'streamExact'])
      requireFact(leg[key] === true);
    requireFact(integer(leg.postEffectsBefore, index) && integer(leg.postEffectsAfter, index + 1));
  }
  const transitions = fields(proof.transitions, ['beforeB', 'beforeA2']);
  allTrue(transitions.beforeB, STOP_KEYS); allTrue(transitions.beforeA2, STOP_KEYS);
  allTrue(proof.restart, RESTART_KEYS); allTrue(proof.retention, RETENTION_KEYS);
  const counts = fields(proof.counts, Object.keys(COUNTS));
  for (const [key, value] of Object.entries(COUNTS)) requireFact(integer(counts[key], value));
  const cleanup = fields(proof.cleanup, CLEANUP_KEYS);
  for (const key of CLEANUP_KEYS) requireFact(['ownedUnitsRemoved', 'ownedInstallationsRemoved'].includes(key)
    ? integer(cleanup[key], 3) : cleanup[key] === true);
  const limits = fields(proof.limits, LIMIT_KEYS);
  requireFact(limits.consistencyOnly === true);
  for (const key of LIMIT_KEYS.filter(key => key !== 'consistencyOnly')) requireFact(limits[key] === false);
}
function result(ok) {
  return { ok, code: ok ? 'managed_operator_return_proof_valid' : 'managed_operator_return_proof_invalid',
    compatibilityAccepted: false, managedPackageReturnAccepted: false,
    serviceAccepted: false, productionAccepted: false };
}
export function checkManagedOperatorReturnProof(value) {
  try { proofValid(value); return result(true); } catch { return result(false); }
}
export function checkManagedOperatorReturnReport(value) {
  try {
    const report = fields(value, REPORT_KEYS);
    requireFact(report.schemaVersion === 1 && report.kind === 'nginx-x10-managed-operator-return-report'
      && report.ok === true && report.code === 'managed_operator_return_verified' && report.phase === 'complete');
    proofValid(report.proof); array(report.cleanupFailures, 0);
    requireFact(integer(report.cleanupFailureCount, 0) && report.cleanupFailuresTruncated === false
      && report.serviceAccepted === false && report.productionAccepted === false && report.subprocessOutputsPublished === false);
    // All strings/counts have fixed schema bounds. The transport consumer must
    // additionally enforce MAX_MANAGED_OPERATOR_RETURN_REPORT_BYTES on RAW bytes.
    return result(true);
  } catch { return result(false); }
}

// These closed producer labels permit retaining finite adverse reports without
// publishing runtime logs, arbitrary exception text, paths or partial proofs.
export const MANAGED_OPERATOR_RETURN_FAILURE_PHASES = Object.freeze([
  'arguments', 'preflight', 'archive',
  'historical', 'application', 'install_a',
  'start_a', 'stop_a', 'stage_b',
  'start_b', 'apply_q', 'restart_b',
  'stop_b', 'restore_a2', 'start_a2',
  'stop_a2', 'cleanup', 'complete',
]);
export const MANAGED_OPERATOR_RETURN_FAILURE_CODES = Object.freeze([
  'usage_refused', 'input_refused', 'file_refused',
  'historical_cli_refused', 'dependency_source_refused', 'manager_unavailable',
  'archive_refused', 'session_identity', 'controller_state',
  'preparation_refused', 'unit_directory', 'unit_authority',
  'manager_query', 'unit_cgroup', 'launcher_identity',
  'unit_not_active', 'invocation_changed', 'native_identity',
  'binding_identity', 'journal_unconfirmed', 'unit_stop',
  'unit_retirement', 'unit_collision', 'unit_link',
  'unit_start', 'input_mismatch', 'traffic_unconfirmed',
  'traffic_identity_changed', 'apply_refused', 'backup_refused',
  'source_preservation', 'backup_preservation', 'transition_refused',
  'stage_refused', 'package_identity', 'initial_b_unconfirmed',
  'unit_restart', 'restart_identity', 'restore_refused',
  'final_observation', 'uninstall_unconfirmed', 'snapshot_refused',
  'origin_cleanup', 'proof_refused', 'cancelled',
  'observation_timeout', 'installed_command_failed', 'installed_response_invalid',
  'managed_operator_return_refused', 'cleanup_unconfirmed', 'report_bound',
]);

export function checkManagedOperatorReturnFailureReport(value) {
  let validFailureReport = false;
  try {
    const report = fields(value, REPORT_KEYS);
    requireFact(report.schemaVersion === 1 && report.kind === 'nginx-x10-managed-operator-return-report'
      && report.ok === false && MANAGED_OPERATOR_RETURN_FAILURE_CODES.includes(report.code)
      && MANAGED_OPERATOR_RETURN_FAILURE_PHASES.includes(report.phase) && report.proof === null
      && report.serviceAccepted === false && report.productionAccepted === false && report.subprocessOutputsPublished === false);
    requireFact(Number.isSafeInteger(report.cleanupFailureCount) && !Object.is(report.cleanupFailureCount, -0)
      && report.cleanupFailureCount >= 0 && report.cleanupFailureCount <= 64
      && typeof report.cleanupFailuresTruncated === 'boolean');
    const length = Object.getOwnPropertyDescriptor(report.cleanupFailures, 'length')?.value;
    requireFact(Number.isSafeInteger(length) && length >= 0 && length <= 8);
    const failures = array(report.cleanupFailures, length);
    for (const code of failures) requireFact(['owned_unit_cleanup_unconfirmed', 'owned_origin_cleanup_unconfirmed'].includes(code));
    requireFact(report.cleanupFailuresTruncated
      ? length === 8 && report.cleanupFailureCount > 8
      : report.cleanupFailureCount === length);
    requireFact(report.cleanupFailureCount === 0 ? report.code !== 'cleanup_unconfirmed' : report.code === 'cleanup_unconfirmed');
    validFailureReport = true;
  } catch { /* Unknown or malformed observations never become public authority. */ }
  // Valid adverse data must NEVER resemble successful child admission.
  return { ok: false, validFailureReport,
    code: validFailureReport ? 'managed_operator_return_failure_report_valid' : 'managed_operator_return_failure_report_invalid',
    compatibilityAccepted: false, managedPackageReturnAccepted: false, serviceAccepted: false, productionAccepted: false };
}
