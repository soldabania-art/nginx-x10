// Finite consistency checks for a separately collected unhealthy-package fallback.
// No I/O, service authority, cleanup authority or product acceptance is granted.
export const MANAGED_OPERATOR_FALLBACK_PROOF_KIND = 'nginx-x10-managed-operator-package-fallback-proof';
export const MAX_MANAGED_OPERATOR_FALLBACK_REPORT_BYTES = 12288;
export const MANAGED_OPERATOR_FALLBACK_PHASES = Object.freeze([
  'a_started', 'a_served', 'a_stopped', 'b_staged', 'b_start_requested',
  'b_failed', 'b_retired', 'a_retention_verified', 'a_prepared', 'a_reactivated',
  'a_fallback_served', 'a_fallback_stopped', 'cleanup',
]);
const PACKAGE_KEYS = ['runtimePayloadSha256', 'operatorPayloadSha256', 'nativeBinarySha256'];
const PROOF_KEYS = ['schemaVersion', 'kind', 'packages', 'inputs', 'phases', 'legs',
  'failedB', 'transitions', 'preparation', 'retention', 'counts', 'cleanup', 'limits'];
const LEG_KEYS = ['name', 'identityOrdinals', 'inputSha256', 'initialBindingAbsent',
  'readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact',
  'streamExact', 'postEffectsBefore', 'postEffectsAfter'];
const IDENTITY_KEYS = ['installation', 'unit', 'session', 'revision', 'binding', 'invocation'];
const FAILED_IDENTITY_KEYS = ['installation', 'unit', 'session', 'revision', 'invocation'];
const STOP_KEYS = ['unitInactive', 'invocationRetired', 'launcherExited', 'masterAbsent',
  'nativeGroupsAbsent', 'portsClosed', 'controlSocketAbsent', 'operatorLocksAbsent', 'pendingAbsent',
  'runtimeLinkAbsent', 'unitNotFound'];
const FAILURE_FACT_KEYS = ['readinessHeld', 'activatingLauncherCaptured', 'nativeCaptured',
  'invocationCaptured', 'hookCaptured', 'wrongBodyObserved', 'managerRefused',
  'hookExitObserved', 'bindingAbsent', 'noPOSTEffects', 'failedSessionStopped',
  'launcherExited', 'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent',
  'operatorLocksAbsent', 'managerResetConfirmed', 'runtimeLinkAbsent', 'unitNotFound'];
const PREPARATION_KEYS = ['freshSession', 'freshRevision', 'nullInitialBinding',
  'inputPPreserved', 'registryTwoSessions', 'oldSessionPreservedStopped', 'oneFreshHistoryEntry'];
const RETENTION_KEYS = ['retainedAAllFilesPreservedThroughBFailure', 'retainedABackupPreserved',
  'keptAPrefixReused', 'keptAInstallationPreserved', 'oldAExplicitlyPrepared', 'oldAInputPreserved'];
const COUNTS = Object.freeze({ units: 3, installations: 2, successfulInvocations: 2,
  failedAttempts: 1, restarts: 0, journalChecks: 2, trafficGets: 2, posts: 2, streams: 2 });
const CLEANUP_KEYS = ['known', 'ownedProcessesAbsent', 'ownedLaunchersAbsent',
  'ownedListenersClosed', 'ownedUnitsRemoved', 'ownedInstallationsRemoved',
  'historicalBundleRemoved', 'backupFilesRemoved'];
const LIMIT_KEYS = ['consistencyOnly', 'nativeBinaryUpgradeAccepted', 'liveConnectionPreserved',
  'applicationSideEffectsReversed', 'productionAccepted', 'automaticMigrationAccepted',
  'allTrafficFenceAccepted', 'automaticFallbackAccepted'];
const REPORT_KEYS = ['schemaVersion', 'kind', 'ok', 'code', 'phase', 'proof', 'primaryFailure',
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
  requireFact(proof.schemaVersion === 1 && proof.kind === MANAGED_OPERATOR_FALLBACK_PROOF_KIND);
  const selected = fields(proof.packages, ['a', 'b', 'aFallback']), packages = {};
  for (const name of ['a', 'b', 'aFallback']) {
    packages[name] = fields(selected[name], PACKAGE_KEYS);
    for (const key of PACKAGE_KEYS) requireFact(hash(packages[name][key]));
  }
  for (const key of ['runtimePayloadSha256', 'operatorPayloadSha256'])
    requireFact(packages.a[key] === packages.aFallback[key] && packages.a[key] !== packages.b[key]);
  requireFact(packages.a.nativeBinarySha256 === packages.b.nativeBinarySha256
    && packages.a.nativeBinarySha256 === packages.aFallback.nativeBinarySha256);
  const inputs = fields(proof.inputs, ['pSha256', 'bStagedSha256', 'aFallbackSha256']);
  for (const key of Object.keys(inputs)) requireFact(hash(inputs[key]));
  requireFact(inputs.pSha256 === inputs.bStagedSha256 && inputs.pSha256 === inputs.aFallbackSha256);
  const phases = array(proof.phases, MANAGED_OPERATOR_FALLBACK_PHASES.length);
  requireFact(phases.every((phase, index) => phase === MANAGED_OPERATOR_FALLBACK_PHASES[index]));
  const legs = array(proof.legs, 2);
  for (const [index, value] of legs.entries()) {
    const leg = fields(value, LEG_KEYS), identities = fields(leg.identityOrdinals, IDENTITY_KEYS);
    requireFact(leg.name === ['a', 'a_fallback'][index]);
    for (const key of IDENTITY_KEYS) requireFact(integer(identities[key], index === 0 ? 1
      : key === 'installation' ? 1 : key === 'binding' ? 2 : 3));
    requireFact(leg.inputSha256 === inputs.pSha256 && leg.initialBindingAbsent === true);
    for (const key of ['readinessAccepted', 'bindingMatchesOwnedRuntime', 'getExact', 'postExact', 'streamExact'])
      requireFact(leg[key] === true);
    requireFact(integer(leg.postEffectsBefore, index) && integer(leg.postEffectsAfter, index + 1));
  }
  const failed = fields(proof.failedB, ['identityOrdinals', ...FAILURE_FACT_KEYS]);
  const failedIdentities = fields(failed.identityOrdinals, FAILED_IDENTITY_KEYS);
  for (const key of FAILED_IDENTITY_KEYS) requireFact(integer(failedIdentities[key], 2));
  for (const key of FAILURE_FACT_KEYS) requireFact(failed[key] === true);
  const transitions = fields(proof.transitions, ['beforeB', 'afterFallback']);
  allTrue(transitions.beforeB, STOP_KEYS); allTrue(transitions.afterFallback, STOP_KEYS);
  allTrue(proof.preparation, PREPARATION_KEYS); allTrue(proof.retention, RETENTION_KEYS);
  const counts = fields(proof.counts, Object.keys(COUNTS));
  for (const [key, value] of Object.entries(COUNTS)) requireFact(integer(counts[key], value));
  const cleanup = fields(proof.cleanup, CLEANUP_KEYS);
  for (const key of CLEANUP_KEYS) requireFact(key === 'ownedUnitsRemoved' ? integer(cleanup[key], 3)
    : key === 'ownedInstallationsRemoved' ? integer(cleanup[key], 2) : cleanup[key] === true);
  const limits = fields(proof.limits, LIMIT_KEYS);
  requireFact(limits.consistencyOnly === true);
  for (const key of LIMIT_KEYS.filter(key => key !== 'consistencyOnly')) requireFact(limits[key] === false);
}
function result(ok) {
  return { ok, code: ok ? 'managed_operator_fallback_proof_valid' : 'managed_operator_fallback_proof_invalid',
    compatibilityAccepted: false, managedPackageFallbackAccepted: false,
    serviceAccepted: false, productionAccepted: false };
}
export function checkManagedOperatorFallbackProof(value) {
  try { proofValid(value); return result(true); } catch { return result(false); }
}
export function checkManagedOperatorFallbackReport(value) {
  try {
    const report = fields(value, REPORT_KEYS);
    requireFact(report.schemaVersion === 1 && report.kind === 'nginx-x10-managed-operator-fallback-report'
      && report.ok === true && report.code === 'managed_operator_fallback_verified' && report.phase === 'complete'
      && report.primaryFailure === null);
    proofValid(report.proof); array(report.cleanupFailures, 0);
    requireFact(integer(report.cleanupFailureCount, 0) && report.cleanupFailuresTruncated === false
      && report.serviceAccepted === false && report.productionAccepted === false && report.subprocessOutputsPublished === false);
    // Raw-byte admission additionally enforces the exported bound before parsing.
    return result(true);
  } catch { return result(false); }
}

// These closed producer labels permit retaining finite adverse reports without
// publishing runtime logs, arbitrary exception text, paths or partial proofs.
export const MANAGED_OPERATOR_FALLBACK_FAILURE_PHASES = Object.freeze([
  'arguments', 'preflight', 'archive',
  'historical', 'application', 'install_a',
  'start_a', 'stop_a', 'stage_b',
  'start_b', 'b_failed', 'a_retention', 'prepare_a',
  'start_a_fallback', 'stop_a_fallback', 'cleanup', 'complete',
]);
export const MANAGED_OPERATOR_FALLBACK_FAILURE_CODES = Object.freeze([
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
  'stage_refused', 'package_identity',
  'final_observation', 'uninstall_unconfirmed', 'snapshot_refused',
  'origin_cleanup', 'proof_refused', 'cancelled',
  'observation_timeout', 'installed_command_failed', 'installed_response_invalid',
  'cleanup_unconfirmed', 'report_bound',
  'failed_start_refused', 'failed_start_unconfirmed', 'reactivation_refused', 'fallback_refused',
]);

// cleanup_unconfirmed is a final cleanup disposition, never an original cause.
export const MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES = Object.freeze(
  MANAGED_OPERATOR_FALLBACK_FAILURE_CODES.filter(code => code !== 'cleanup_unconfirmed'));

export function checkManagedOperatorFallbackFailureReport(value) {
  let validFailureReport = false;
  try {
    const report = fields(value, REPORT_KEYS);
    requireFact(report.schemaVersion === 1 && report.kind === 'nginx-x10-managed-operator-fallback-report'
      && report.ok === false && MANAGED_OPERATOR_FALLBACK_FAILURE_CODES.includes(report.code)
      && MANAGED_OPERATOR_FALLBACK_PRIMARY_FAILURE_CODES.includes(report.primaryFailure)
      && MANAGED_OPERATOR_FALLBACK_FAILURE_PHASES.includes(report.phase) && report.proof === null
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
    if (report.code === 'report_bound') {
      // A final bound failure retains the original cause if one exists; when
      // there was no earlier refusal, report_bound is itself the cause.
      requireFact(report.primaryFailure !== 'cleanup_unconfirmed');
    } else {
      requireFact(report.primaryFailure !== 'report_bound');
      requireFact(report.cleanupFailureCount > 0
        ? report.code === 'cleanup_unconfirmed'
        : report.code === report.primaryFailure && report.code !== 'cleanup_unconfirmed');
    }
    validFailureReport = true;
  } catch { /* Unknown or malformed observations never become public authority. */ }
  // Valid adverse data must NEVER resemble successful child admission.
  return { ok: false, validFailureReport,
    code: validFailureReport ? 'managed_operator_fallback_failure_report_valid' : 'managed_operator_fallback_failure_report_invalid',
    compatibilityAccepted: false, managedPackageFallbackAccepted: false, serviceAccepted: false, productionAccepted: false };
}
