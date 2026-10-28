#!/usr/bin/env node
// Actual ephemeral user-service verification. Never enables a persistent unit.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { chmod, lstat, mkdtemp, mkdir, open, readFile, readlink, realpath, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { preflight } from './preflight.mjs';
import { verifyAlphaArchive, MAX_ARCHIVE_BYTES } from '../release/verify-alpha-archive.mjs';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';
import { observeOwnedJournal, JOURNAL_RESULT_CODES } from './journal-check.mjs';
import { createOriginFixture, ORIGIN_FIXTURE_ERROR_CODES, ADMISSION_DIAGNOSTIC_STAGES, ADMISSION_DIAGNOSTIC_REASONS } from './origin-fixture.mjs';
import { startOwnedOperator, INTERRUPTED_OPERATOR_ERROR_CODES } from './interrupted-operator.mjs';
import { createPausedTLSClient, SLOW_CLIENT_ERROR_CODES } from './slow-client.mjs';
import { createServicePKI, probeServiceTLS, expectServiceTLSRefusal, TLS_FIXTURE_ERROR_CODES } from './tls-fixture.mjs';

const execute = promisify(execFile), TOOL = '/usr/bin/systemctl';
const HEX = /^[a-f0-9]{64}$/, TOKEN = /^[a-f0-9]{32}$/;
const KEYS = ['LoadState', 'ActiveState', 'SubState', 'Result', 'FragmentPath', 'MainPID', 'ControlGroup'];
const ERROR_CODES = new Set(["restored_http_unconfirmed", "archive_extract_failed", "archive_refused", "binding_unconfirmed", "cancelled", "installed_command_failed", "installed_response_invalid", "lifecycle_identity", "linux_required", "local_manager_prerequisites_unavailable", "manager_query_failed", "manager_response_invalid", "manager_unavailable", "native_cleanup_unknown", "native_identity", "nonroot_required", "observation_timeout", "proxy_body_mismatch", "query_invalid", "query_output_limit", "query_timeout", "recipe_diagnostic_failed", "installed_recipe_invalid", "service_resources_live", "session_identity", "session_reused", "stream_mismatch", "uid_mismatch", "uninstall_incomplete", "unit_cgroup_identity", "unit_collision", "unit_directory_identity", "unit_file_identity", "unit_fragment_identity", "unit_launcher_identity", "unit_link_failed", "unit_link_identity", "unit_name_invalid", "unit_not_active", "unit_not_stopped", "unit_query_failed", "unit_reload_failed", "unit_removal_unconfirmed", "unit_response_invalid", "unit_start_failed", "unit_stop_unconfirmed", "upload_mismatch", "usage_invalid", "unit_invocation_invalid", "unit_invocation_changed", "unit_restart_failed", "restart_identity", "restart_retirement_unconfirmed", "journal_unconfirmed", ...JOURNAL_RESULT_CODES, ...TLS_FIXTURE_ERROR_CODES, ...ORIGIN_FIXTURE_ERROR_CODES, "upstream_tls_unconfirmed", "upstream_tls_session", "upstream_tls_rollback_unconfirmed", "upstream_tls_candidate_unconfirmed", "upstream_tls_replay", "downstream_tls_unconfirmed", "downstream_tls_session", "downstream_tls_body_mismatch", "downstream_tls_upload_mismatch", "downstream_tls_stream_mismatch", "downstream_tls_ca_unconfirmed", "downstream_tls_hostname_unconfirmed", "failed_start_unconfirmed", "controlled_drain_unconfirmed", "operator_interruption_unconfirmed", ...SLOW_CLIENT_ERROR_CODES, ...INTERRUPTED_OPERATOR_ERROR_CODES]);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const reject = code => { throw Object.assign(new Error(code), { code }); };
export const LIMITATIONS = Object.freeze({ scope: 'ephemeral-user-service-basic-lifecycle',
  automaticReadinessAccepted: false, failedStartAccepted: false, slowDrainAccepted: false,
  orphanRecoveryAccepted: false, tlsServiceAccepted: false, permanentDistributionAccepted: false,
  serviceAccepted: false, productionAccepted: false });
export function parseArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--archive' || argv[2] !== '--sha256'
      || typeof argv[1] !== 'string' || argv[1].length > 4096 || typeof argv[3] !== 'string' || !/^[A-Za-z0-9_./+-]+\.tar\.gz$/.test(argv[1]) || argv[1].startsWith('-')
      || argv[1].split('/').includes('..') || path.posix.normalize(argv[1]) !== argv[1] || !HEX.test(argv[3] || '')) reject('usage_invalid');
  return { archive: path.resolve(argv[1]), sha256: argv[3] };
}
export function fixtureUnitName(token) {
  if (typeof token !== 'string' || !TOKEN.test(token)) reject('unit_name_invalid');
  return `x10-lifecycle-${token}.service`;
}
export function parseUnitProperties(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16384 || !text.endsWith('\n') || /[^\x20-\x7e\n]/.test(text)) reject('unit_response_invalid');
  const rows = text.slice(0, -1).split('\n'), result = Object.create(null);
  if (rows.length !== KEYS.length) reject('unit_response_invalid');
  for (const row of rows) {
    const i = row.indexOf('='), key = row.slice(0, i);
    if (i < 1 || !KEYS.includes(key) || Object.hasOwn(result, key)) reject('unit_response_invalid');
    result[key] = row.slice(i + 1);
  }
  if (!KEYS.every(k => Object.hasOwn(result, k)) || !['loaded', 'not-found'].includes(result.LoadState)
      || !['active', 'activating', 'inactive', 'deactivating', 'failed'].includes(result.ActiveState)
      || !/^[a-z][a-z-]{0,63}$/.test(result.SubState) || !/^(?:[a-z][a-z-]{0,63})?$/.test(result.Result)
      || !/^(?:0|[1-9][0-9]{0,9})$/.test(result.MainPID) || Number(result.MainPID) > 2147483647
      || (result.FragmentPath !== '' && (!/^\/[A-Za-z0-9_./+-]+$/.test(result.FragmentPath) || path.posix.normalize(result.FragmentPath) !== result.FragmentPath))
      || (result.ControlGroup !== '' && !/^\/[A-Za-z0-9_./@+-]+$/.test(result.ControlGroup))) reject('unit_response_invalid');
  return result;
}
// A parsed invocation is a private correlation value, never unit authority.
export function parseInvocationProperty(text) {
  if (typeof text !== 'string' || !/^InvocationID=[a-f0-9]{32}\n$/.test(text)) reject('unit_invocation_invalid');
  const value = text.slice(13, -1);
  if (value === '0'.repeat(32)) reject('unit_invocation_invalid');
  return value;
}
export function managerEnvironment(uid) {
  if (!Number.isSafeInteger(uid) || uid < 1 || uid > 4294967294) reject('nonroot_required');
  const runtime = `/run/user/${uid}`;
  return { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', XDG_RUNTIME_DIR: runtime,
    DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtime}/bus` };
}
// These facts are diagnostic only. The unchanged inspector remains mandatory.
export function assessNodePrerequisites(value) {
  const names = ['regular', 'canonical', 'ownerAllowed', 'mode', 'recordedPathMatches', 'recordedVersion'];
  try {
    if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) reject('recipe_diagnostic_failed');
    const keys = Reflect.ownKeys(value);
    if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) reject('recipe_diagnostic_failed');
    const fields = Object.create(null);
    for (const name of names) {
      const d = Object.getOwnPropertyDescriptor(value, name);
      if (!d || !Object.hasOwn(d, 'value')) reject('recipe_diagnostic_failed'); fields[name] = d.value;
    }
    if (!['regular', 'canonical', 'ownerAllowed', 'recordedPathMatches'].every(k => typeof fields[k] === 'boolean')
        || !Number.isInteger(fields.mode) || fields.mode < 0 || fields.mode > 0o7777
        || typeof fields.recordedVersion !== 'string' || fields.recordedVersion.length > 128) reject('recipe_diagnostic_failed');
    return { selectedNodeRegular: fields.regular, selectedNodeCanonical: fields.canonical,
      selectedNodeOwnerExecutable: (fields.mode & 0o100) !== 0,
      selectedNodeModeAllowed: (fields.mode & 0o7022) === 0,
      selectedNodeOwnerAllowed: fields.ownerAllowed, recordedNodePathMatches: fields.recordedPathMatches,
      recordedNodeVersionSupported: /^v(?:2[2-9]|[3-9][0-9])\.[0-9]+\.[0-9]+$/.test(fields.recordedVersion) };
  } catch { reject('recipe_diagnostic_failed'); }
}
// The managed-service profile consumes a recipe emitted by the verified
// installation. This validates the complete fixed profile; it never substitutes
// checkout generator output when the installed command is absent or refuses.
export function assessInstalledServiceRecipe(value, prefix, nodeExecutable) {
  const refuse = () => reject('installed_recipe_invalid');
  try {
    const validPath = item => typeof item === 'string' && item.length <= 1024
      && /^\/[A-Za-z0-9_./+-]+$/.test(item) && path.posix.normalize(item) === item
      && item !== '/' && !item.endsWith('/');
    if (!validPath(prefix) || !validPath(nodeExecutable) || path.posix.dirname(prefix) === '/'
        || prefix.length + 13 > 107 || !value || typeof value !== 'object'
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse();
    const names = ['ok', 'unit', 'scope', 'readinessAutomated', 'startupHealthAccepted', 'serviceAccepted',
      'productionAccepted', 'outcome', 'activationPerformed'];
    const keys = Reflect.ownKeys(value), fields = Object.create(null);
    if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) refuse();
    for (const key of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) refuse();
      fields[key] = descriptor.value;
    }
    if (fields.ok !== true || fields.scope !== 'systemd-user-recipe-only' || fields.readinessAutomated !== true
        || fields.startupHealthAccepted !== false || fields.serviceAccepted !== false || fields.productionAccepted !== false
        || fields.outcome !== 'service_unit_generated' || fields.activationPerformed !== false
        || typeof fields.unit !== 'string' || Buffer.byteLength(fields.unit) > 8192 || /[^\x20-\x7e\n]/.test(fields.unit)) refuse();
    const command = `${nodeExecutable} ${prefix}/bin/x10`;
    const requiredLines = [
      '# X10 systemd --user recipe only; no activation performed.',
      '# ExecStartPre prepares the guarded session before run and wait-bind can race.',
      '# ExecStartPost waits for installed guarded bind; full startup health is not accepted.',
      '# readinessAutomated:true startupHealthAccepted:false serviceAccepted:false',
      '# The explicit pinned-node installed launcher waits within the start timeout.',
      '[Unit]', 'Description=NGINX X10 private operator service', '',
      '[Service]', 'Type=exec', `WorkingDirectory=${prefix}`,
      `ExecStartPre=${command} prepare-run`,
      `ExecStart=${command} run --control-socket ${prefix}/control.sock`,
      `ExecStartPost=${command} wait-bind --timeout-ms 10000`, `ExecStop=${command} stop`,
      'Restart=no', 'KillMode=process', 'KillSignal=SIGTERM', 'SendSIGKILL=no',
      'TimeoutStartSec=30s', 'TimeoutStopSec=30s', 'UMask=0077',
      'UnsetEnvironment=NODE_OPTIONS NODE_PATH NGINX_CTRL',
      'StandardOutput=journal', 'StandardError=journal', '', '[Install]', 'WantedBy=default.target', '',
    ];
    const lines = fields.unit.split('\n');
    if (lines.length !== requiredLines.length || lines.some((line, index) => line !== requiredLines[index])) refuse();
    // Return the installed payload bytes, never requiredLines or a source recipe.
    return fields.unit;
  } catch { refuse(); }
}
export function assessInstalledServiceRecipeCommand(record, prefix, nodeExecutable) {
  try {
    if (!record || typeof record !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(record))) reject('installed_recipe_invalid');
    const names = ['ok', 'exitCode', 'stdout', 'stderr', 'termination'], keys = Reflect.ownKeys(record), fields = Object.create(null);
    if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) reject('installed_recipe_invalid');
    for (const key of names) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) reject('installed_recipe_invalid'); fields[key] = descriptor.value;
    }
    if (fields.ok !== true || fields.exitCode !== 0 || fields.termination !== 'none' || fields.stderr !== ''
        || typeof fields.stdout !== 'string' || Buffer.byteLength(fields.stdout) > 16384) reject('installed_recipe_invalid');
    return assessInstalledServiceRecipe(JSON.parse(fields.stdout), prefix, nodeExecutable);
  } catch { reject('installed_recipe_invalid'); }
}
export function classifyLifecycleError(error, phase) {
  try {
    const message = error && Object.getOwnPropertyDescriptor(error, 'message');
    if (phase === 'recipe_inspection' && error instanceof Error && Object.getPrototypeOf(error) === Error.prototype
        && message && Object.hasOwn(message, 'value') && message.value === 'service_recipe_invalid') return 'recipe_inspection_refused';
    const code = error && Object.getOwnPropertyDescriptor(error, 'code');
    return code && Object.hasOwn(code, 'value') && typeof code.value === 'string' && ERROR_CODES.has(code.value)
      ? code.value : 'lifecycle_failed';
  } catch { return 'lifecycle_failed'; }
}
export async function observeNodePrerequisites(prefix, nodeExecutable) {
  let handle;
  try {
    if (typeof prefix !== 'string' || typeof nodeExecutable !== 'string' || !/^\/[A-Za-z0-9_./+-]+$/.test(prefix)
        || !/^\/[A-Za-z0-9_./+-]+$/.test(nodeExecutable) || prefix.length > 4096 || nodeExecutable.length > 4096
        || path.posix.normalize(prefix) !== prefix || path.posix.normalize(nodeExecutable) !== nodeExecutable) reject('recipe_diagnostic_failed');
    const directory = await lstat(prefix);
    if (!directory.isDirectory() || directory.uid !== process.getuid() || (directory.mode & 0o7777) !== 0o700 || await realpath(prefix) !== prefix) reject('recipe_diagnostic_failed');
    handle = await open(`${prefix}/.alpha-install.json`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o7077) !== 0 || st.size < 1 || st.size > 2 * 1024 * 1024) reject('recipe_diagnostic_failed');
    const bytes = Buffer.alloc(st.size + 1); let used = 0;
    while (used < bytes.length) { const r = await handle.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    const after = await handle.stat();
    if (used !== st.size || after.size !== st.size || after.mtimeMs !== st.mtimeMs || after.ctimeMs !== st.ctimeMs) reject('recipe_diagnostic_failed');
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used))), { sha256, ...record } = parsed;
    if (!HEX.test(sha256 || '') || digest(JSON.stringify(record)) !== sha256 || record.schemaVersion !== 2
        || record.kind !== 'nginx-x10-local-alpha' || record.prefix !== prefix || !record.nodeRuntime) reject('recipe_diagnostic_failed');
    const node = await lstat(nodeExecutable);
    return assessNodePrerequisites({ regular: node.isFile(), canonical: await realpath(nodeExecutable) === nodeExecutable,
      ownerAllowed: node.uid === 0 || node.uid === process.getuid(), mode: node.mode & 0o7777,
      recordedPathMatches: record.nodeRuntime.executable === nodeExecutable, recordedVersion: record.nodeRuntime.version });
  } catch { reject('recipe_diagnostic_failed'); }
  finally { if (handle) { try { await handle.close(); } catch { reject('recipe_diagnostic_failed'); } } }
}
// Diagnostic collectors have no I/O or lifecycle authority.
export const DIAGNOSTIC_PHASES = Object.freeze(['arguments', 'preflight', 'archive', 'install', 'recipe_inspection', 'unit_preparation', 'link', 'failed_start', 'first_start', 'restore_http', 'tls_apply', 'origin_negative', 'first_stop', 'second_start', 'second_stop', 'manager_restart', 'operator_interruption', 'controlled_drain', 'third_stop', 'journal', 'uninstall', 'complete', 'unknown']);
export const START_SUBPHASES = Object.freeze(['not_started', 'not_applicable', 'cancel_check', 'before_properties', 'request_start', 'request_restart', 'old_retirement', 'invocation_identity', 'journal_read', 'downstream_tls', 'upstream_tls', 'origin_negative', 'after_properties', 'launcher_identity', 'native_inventory', 'wait_bind', 'native_observation', 'session_freshness', 'binding_status', 'proxy_body', 'upload', 'stream', 'final_cancel_check', 'complete', 'unknown']);
export const CLEANUP_STAGES = Object.freeze(['unit_cleanup', 'link_readback', 'inert_uninstall', 'app_close', 'operator_close', 'operator_recovery', 'drain_close', 'origin_close', 'temporary_root', 'final_assertion', 'unknown']);
const pickEnum = (value, list, fallback = 'unknown') => typeof value === 'string' && list.includes(value) ? value : fallback;
function ownData(record, key) {
  try { const d = record && Object.getOwnPropertyDescriptor(record, key); return d && Object.hasOwn(d, 'value') ? d.value : undefined; }
  catch { return undefined; }
}
export function classifySystemError(error) {
  try {
    if (!(error instanceof Error)) return 'unknown';
    const code = ownData(error, 'code');
    if (code === 'EACCES' || code === 'EPERM') return 'permission_denied';
    if (code === 'ENOENT') return 'not_found';
    if (code === 'ESRCH') return 'process_missing';
    return 'unknown';
  } catch { return 'unknown'; }
}
export function createFailureDiagnostics() {
  let primary = null, cleanupCount = 0, truncated = false; const cleanup = [];
  return Object.freeze({
    primary(error, phase, subphase) {
      if (primary) return;
      const safePhase = pickEnum(phase, DIAGNOSTIC_PHASES);
      primary = { phase: safePhase, subphase: ['first_start', 'second_start', 'manager_restart'].includes(safePhase)
        ? pickEnum(subphase, START_SUBPHASES) : 'not_applicable', code: classifyLifecycleError(error, safePhase), systemErrorClass: classifySystemError(error) };
    },
    cleanup(error, stage) {
      if (cleanupCount < 32) cleanupCount++; else truncated = true;
      const classified = classifyLifecycleError(error, 'cleanup');
      const item = { stage: pickEnum(stage, CLEANUP_STAGES), code: classified === 'lifecycle_failed' ? 'cleanup_unconfirmed' : classified };
      if (cleanup.length < 8) cleanup.push(item); else truncated = true;
    },
    snapshot() { return { primaryFailure: primary ? { ...primary } : null, cleanupFailures: cleanup.map(x => ({ ...x })),
      cleanupFailureCount: cleanupCount, cleanupFailuresTruncated: truncated }; },
  });
}
export function classifyCommandTermination(error) {
  const code = ownData(error, 'code'), killed = ownData(error, 'killed'), signal = ownData(error, 'signal');
  if (code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return 'output_limit';
  if (killed === true) return 'timeout_or_killed';
  if (typeof signal === 'string' && signal.length > 0) return 'signal';
  if (typeof code === 'string' && ['ENOENT', 'EACCES', 'EPERM', 'ENOTDIR', 'EISDIR', 'ENOEXEC'].includes(code)) return 'unavailable';
  if (Number.isInteger(code) && code > 0 && code <= 255) return 'exit_nonzero';
  return 'unknown';
}
export function summarizeManagerOutcome(record) {
  const ok = ownData(record, 'ok'), exitCode = ownData(record, 'exitCode'), stderr = ownData(record, 'stderr');
  const exitCodeClass = exitCode === 0 ? 'zero' : Number.isInteger(exitCode) && exitCode >= 1 && exitCode <= 255 ? 'nonzero' : 'unknown';
  return { outcome: ok === true && exitCodeClass === 'zero' ? 'succeeded'
    : ok === false && exitCodeClass === 'nonzero' ? 'exited_nonzero' : 'unresolved',
    exitCodeClass, termination: pickEnum(ownData(record, 'termination'), ['none', 'output_limit', 'timeout_or_killed', 'signal', 'unavailable', 'exit_nonzero']),
    stderrPresent: typeof stderr === 'string' && stderr.length > 0 };
}
export function summarizeUnitProperties(record) {
  const load = ownData(record, 'LoadState'), active = ownData(record, 'ActiveState'), sub = ownData(record, 'SubState'), result = ownData(record, 'Result');
  const pid = ownData(record, 'MainPID'), group = ownData(record, 'ControlGroup'), fragment = ownData(record, 'FragmentPath');
  return { loadState: pickEnum(load, ['loaded', 'not-found']),
    activeState: pickEnum(active, ['active', 'activating', 'inactive', 'deactivating', 'failed']),
    subState: pickEnum(sub, ['dead', 'running', 'start', 'start-pre', 'start-post', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'failed', 'auto-restart', 'reload', 'reload-signal', 'reload-notify']),
    result: result === '' ? 'empty' : pickEnum(result, ['success', 'exit-code', 'signal', 'core-dump', 'timeout', 'watchdog', 'start-limit-hit', 'resources', 'protocol', 'oom-kill', 'exec-condition']),
    mainPIDPresent: typeof pid === 'string' && /^[1-9][0-9]{0,9}$/.test(pid) && !pid.includes('\n') && Number(pid) <= 2147483647,
    controlGroupPresent: typeof group === 'string' && group.length > 0, fragmentPathPresent: typeof fragment === 'string' && fragment.length > 0 };
}
export function createStartDiagnostics() {
  let attempts = 0, completed = 0, step = 'not_started', count = 0, truncated = false; const observations = [];
  return Object.freeze({
    begin() { if (attempts < 2) attempts++; step = 'cancel_check'; },
    step(value) { step = pickEnum(value, START_SUBPHASES); },
    observe(kind, record) {
      if (!['properties_command', 'properties_state', 'start_command'].includes(kind)) return;
      if (count < 32) count++; else truncated = true;
      const state = kind === 'properties_state' ? summarizeUnitProperties(record) : summarizeManagerOutcome(record);
      const item = { attempt: attempts, step, kind, ...state };
      if (observations.length < 8) observations.push(item); else truncated = true;
    },
    complete() { if (completed < 2) completed++; step = 'complete'; },
    snapshot() { return { attempts, completedAttempts: completed, lastStep: step, observationCount: count,
      observationsTruncated: truncated, observations: observations.map(x => ({ ...x })) }; },
  });
}
// Compare strings from the parsed response only. Never resolve or read a
// manager-supplied path; these observations cannot admit a unit or clean it up.
export function summarizeUnitFragmentIdentity(record, knownPaths, precedingLinkCheck) {
  const fragment = ownData(record, 'FragmentPath'), unit = ownData(knownPaths, 'unitFile'), link = ownData(knownPaths, 'runtimeLink');
  const validPath = value => typeof value === 'string' && value.length <= 4096
    && /^\/[A-Za-z0-9_./+-]+$/.test(value) && !value.includes('\n') && path.posix.normalize(value) === value;
  let fragmentPathMatch = 'unknown';
  if (fragment === '') fragmentPathMatch = 'empty';
  else if (validPath(fragment) && validPath(unit) && validPath(link) && unit !== link) {
    fragmentPathMatch = fragment === unit ? 'unit_file' : fragment === link ? 'runtime_link' : 'other';
  }
  return { loadState: pickEnum(ownData(record, 'LoadState'), ['loaded', 'not-found']), fragmentPathMatch,
    precedingLinkTargetMatchesUnit: ownData(precedingLinkCheck, 'targetMatchesUnit') === true ? 'verified' : 'unknown',
    precedingUnitOwnedModeHash: ownData(precedingLinkCheck, 'unitOwnedModeHash') === true ? 'verified' : 'unknown',
    canonicalIdentity: 'not_measured' };
}
// This checks only the parsed spelling and the two already known paths.
// Ownership, mode, bytes and runtime parents still require linkAuthority.
export async function verifyKnownUnitFragmentPaths(record, knownPaths) {
  try {
    if (!record || typeof record !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(record))
        || !knownPaths || typeof knownPaths !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(knownPaths))) reject('unit_fragment_identity');
  } catch { reject('unit_fragment_identity'); }
  const load = ownData(record, 'LoadState'), fragment = ownData(record, 'FragmentPath');
  const unit = ownData(knownPaths, 'unitFile'), link = ownData(knownPaths, 'runtimeLink');
  const validPath = value => typeof value === 'string' && value.length <= 4096
    && /^\/[A-Za-z0-9_./+-]+$/.test(value) && !value.includes('\n') && path.posix.normalize(value) === value;
  if (load !== 'loaded' || !validPath(fragment) || !validPath(unit) || !validPath(link) || unit === link
      || (fragment !== unit && fragment !== link)) reject('unit_fragment_identity');
  if (fragment === link) {
    try {
      if (await realpath(unit) !== unit || await realpath(link) !== unit) reject('unit_fragment_identity');
    } catch { reject('unit_fragment_identity'); }
  }
  return true;
}
export function createFragmentIdentityDiagnostics() {
  let count = 0, truncated = false; const observations = [];
  return Object.freeze({
    observe(record, knownPaths, precedingLinkCheck, phase, subphase, inCleanup) {
      if (count < 32) count++; else truncated = true;
      const safePhase = pickEnum(phase, DIAGNOSTIC_PHASES);
      const item = { phase: safePhase, subphase: inCleanup === true ? 'not_applicable'
        : ['first_start', 'second_start', 'manager_restart'].includes(safePhase) ? pickEnum(subphase, START_SUBPHASES) : 'not_applicable',
        context: inCleanup === true ? 'cleanup' : 'lifecycle',
        ...summarizeUnitFragmentIdentity(record, knownPaths, precedingLinkCheck) };
      if (observations.length < 8) observations.push(item); else truncated = true;
    },
    snapshot() { return { observationCount: count, observationsTruncated: truncated, observations: observations.map(x => ({ ...x })) }; },
  });
}
// ExecStartPost diagnostics are bounded observations, never lifecycle authority.
// Raw execution identity stays inside this collector and is never returned.
export function createHookStatusDiagnostics() {
  let count = 0, truncated = false; const observations = [], before = new Map(), seen = new Set();
  const unknown = result => ({ diagnosticResult: result, state: 'unknown', codeClass: 'unknown', exitStatus: null, signalClass: 'unknown' });
  function parse(text, expected) {
    const node = ownData(expected, 'nodeExecutable'), launcher = ownData(expected, 'launcher');
    const simple = value => typeof value === 'string' && value.length <= 4096 && /^\/[A-Za-z0-9_./+-]+$/.test(value)
      && !value.includes('\n') && path.posix.normalize(value) === value;
    if (!simple(node) || !simple(launcher) || typeof text !== 'string' || Buffer.byteLength(text) > 16384
        || /[^\x20-\x7e\n]/.test(text)) return { safe: unknown('parse_refused'), identity: null };
    const match = /^ExecStartPost=\{ path=([^;{}\n]{1,4096}) ; argv\[\]=([^;{}\n]{1,8192}) ; ignore_errors=no ; start_time=\[([^\]\n]{1,128})\] ; stop_time=\[([^\]\n]{1,128})\] ; pid=(0|[1-9][0-9]{0,9}) ; code=([a-z]+|\(null\)|n\/a) ; status=(-?(?:0|[1-9][0-9]{0,9}))(?:\/([A-Z][A-Z0-9+-]{0,15}))? \}\n$/.exec(text);
    if (!match || match[0] !== text || match[1] !== node || match[2] !== `${node} ${launcher} wait-bind --timeout-ms 10000`) return { safe: unknown('parse_refused'), identity: null };
    const [, , , startTime, stopTime, pid, code, status, signal] = match;
    const timestamp = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})? (?:[A-Z]{1,8}|[+-][0-9]{4})$/;
    if (!timestamp.test(startTime) || !timestamp.test(stopTime) || Number(pid) < 2 || Number(pid) > 2147483647) return { safe: unknown('unresolved_record'), identity: null };
    const identity = { pid, startTime };
    if (code === 'exited' && !signal && /^(?:0|[1-9][0-9]{0,2})$/.test(status) && Number(status) <= 255)
      return { safe: { diagnosticResult: 'observed', state: 'completed', codeClass: 'exited', exitStatus: Number(status), signalClass: 'none' }, identity };
    if (['killed', 'dumped'].includes(code) && signal && /^[1-9][0-9]?$/.test(status) && Number(status) <= 64)
      return { safe: { diagnosticResult: 'observed', state: 'completed', codeClass: 'signal', exitStatus: null, signalClass: code }, identity };
    return { safe: unknown('unresolved_record'), identity: null };
  }
  function add(attempt, stage, parsed) {
    if (![1, 2].includes(attempt) || !['before_start', 'failed_start'].includes(stage)) { truncated = true; return; }
    if (count >= 4) { truncated = true; return; } count++;
    const key = `${attempt}:${stage}`;
    if (seen.has(key)) { before.delete(attempt); parsed = { safe: unknown('parse_refused'), identity: null }; }
    seen.add(key);
    let changed = 'unknown';
    if (stage === 'before_start') { if (!before.has(attempt)) before.set(attempt, parsed.identity); }
    else { const prior = before.get(attempt); if (prior && parsed.identity) changed = prior.pid !== parsed.identity.pid || prior.startTime !== parsed.identity.startTime; }
    observations.push({ attempt, stage, ...parsed.safe, recordChangedSincePreStart: changed });
  }
  return Object.freeze({
    observe(attempt, stage, text, expected) { let parsed; try { parsed = parse(text, expected); } catch { parsed = { safe: unknown('parse_refused'), identity: null }; } add(attempt, stage, parsed); },
    unavailable(attempt, stage, result) { add(attempt, stage, { safe: unknown(pickEnum(result, ['unavailable', 'query_refused', 'parse_refused', 'cancelled'], 'unavailable')), identity: null }); },
    snapshot() { return { observationCount: count, observationsTruncated: truncated, observations: observations.map(item => ({ ...item })) }; },
  });
}
// These strict expected-failure assessments never accept a timeout or signal.
// Runtime authority still requires the caller's fresh owned-unit/session checks.
export function parseFailedStartIdentity(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 256 || !text.endsWith('\n')) reject('failed_start_unconfirmed');
  const rows = text.slice(0, -1).split('\n'), value = Object.create(null);
  if (rows.length !== 2) reject('failed_start_unconfirmed');
  for (const row of rows) {
    const match = /^(InvocationID|ControlPID)=([a-f0-9]+)$/.exec(row);
    if (!match || Object.hasOwn(value, match[1])) reject('failed_start_unconfirmed');
    value[match[1]] = match[2];
  }
  if (!TOKEN.test(value.InvocationID || '') || /^0+$/.test(value.InvocationID)
      || !/^[1-9][0-9]{0,9}$/.test(value.ControlPID || '') || Number(value.ControlPID) < 2
      || Number(value.ControlPID) > 2147483647) reject('failed_start_unconfirmed');
  return { invocation: value.InvocationID, hookPID: Number(value.ControlPID) };
}
export function assessFailedReadinessStart(record, properties, text, expected) {
  const get = ownData;
  if (get(record, 'ok') !== false || get(record, 'exitCode') !== 1 || get(record, 'termination') !== 'exit_nonzero'
      || typeof get(record, 'stdout') !== 'string' || typeof get(record, 'stderr') !== 'string'
      || Buffer.byteLength(get(record, 'stdout')) + Buffer.byteLength(get(record, 'stderr')) > 256 * 1024
      || get(properties, 'LoadState') !== 'loaded' || get(properties, 'ActiveState') !== 'failed'
      || get(properties, 'SubState') !== 'failed' || get(properties, 'Result') !== 'exit-code'
      || get(properties, 'MainPID') !== '0') reject('failed_start_unconfirmed');
  const node = get(expected, 'nodeExecutable'), launcher = get(expected, 'launcher'), pid = get(expected, 'hookPID');
  const simple = value => typeof value === 'string' && value.length <= 4096
    && /^\/[A-Za-z0-9_./+-]+$/.test(value) && path.posix.normalize(value) === value;
  if (!simple(node) || !simple(launcher) || !Number.isInteger(pid) || pid < 2 || pid > 2147483647
      || typeof text !== 'string' || Buffer.byteLength(text) > 16384 || /[^\x20-\x7e\n]/.test(text)) reject('failed_start_unconfirmed');
  const match = /^ExecStartPost=\{ path=([^;{}\n]{1,4096}) ; argv\[\]=([^;{}\n]{1,8192}) ; ignore_errors=no ; start_time=\[([^\]\n]{1,128})\] ; stop_time=\[([^\]\n]{1,128})\] ; pid=([1-9][0-9]{0,9}) ; code=exited ; status=1(?:\/FAILURE)? \}\n$/.exec(text);
  const time = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})? (?:[A-Z]{1,8}|[+-][0-9]{4})$/;
  if (!match || match[0] !== text || match[1] !== node
      || match[2] !== `${node} ${launcher} wait-bind --timeout-ms 10000`
      || !time.test(match[3]) || !time.test(match[4]) || Number(match[5]) !== pid) reject('failed_start_unconfirmed');
  return true;
}

// Restored HTTP preparation is a data consistency check, never service authority.
// The caller separately verifies stopped source ownership and the live new unit.
export function assessRestoredHTTPPreparation(source, backup, restored) {
  const refuse = () => reject('restored_http_unconfirmed');
  try {
    const plain = value => value && typeof value === 'object'
      && [Object.prototype, null].includes(Object.getPrototypeOf(value));
    const fields = (value, names, exact = false) => {
      if (!plain(value) || (exact && (Reflect.ownKeys(value).length !== names.length
          || Reflect.ownKeys(value).some(key => !names.includes(key))))) refuse();
      const out = Object.create(null);
      for (const name of names) {
        const descriptor = Object.getOwnPropertyDescriptor(value, name);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) refuse();
        out[name] = descriptor.value;
      }
      return out;
    };
    const inputData = input => {
      const names = ['serverBody', 'healthURL'];
      if (Object.hasOwn(input || {}, 'healthExpectedStatus')) names.push('healthExpectedStatus', 'healthExpectedBody');
      const data = fields(input, names, true);
      if (typeof data.serverBody !== 'string' || Buffer.byteLength(data.serverBody) > 1024 * 1024
          || typeof data.healthURL !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/[A-Za-z0-9/_.~%-]*$/.test(data.healthURL)
          || (names.length === 4 && (!Number.isInteger(data.healthExpectedStatus) || data.healthExpectedStatus < 200
            || data.healthExpectedStatus > 299 || typeof data.healthExpectedBody !== 'string'
            || Buffer.byteLength(data.healthExpectedBody) > 4096))) refuse();
      return input;
    };
    const before = fields(source, ['installationId', 'session', 'revision', 'input', 'inputSha256', 'port', 'healthPort'], true);
    inputData(before.input);
    if (![before.installationId, before.session, before.revision].every(value => typeof value === 'string' && TOKEN.test(value))
        || ![before.port, before.healthPort].every(value => Number.isInteger(value) && value >= 1024 && value <= 65535)
        || before.port === before.healthPort || typeof before.inputSha256 !== 'string' || !HEX.test(before.inputSha256)
        || digest(JSON.stringify(before.input)) !== before.inputSha256 || Object.hasOwn(before.input, 'https')) refuse();
    const saved = fields(backup, ['schemaVersion', 'kind', 'source', 'port', 'healthPort', 'input', 'inputSha256', 'sha256'], true);
    inputData(saved.input);
    const ids = fields(saved.source, ['installationId', 'session', 'revision'], true);
    if (![ids.installationId, ids.session, ids.revision].every(value => typeof value === 'string' && TOKEN.test(value))) refuse();
    const { sha256, ...body } = saved;
    if (saved.schemaVersion !== 1 || saved.kind !== 'nginx-x10-declarative-backup' || typeof sha256 !== 'string' || !HEX.test(sha256)
        || digest(JSON.stringify(body)) !== sha256 || saved.port !== before.port || saved.healthPort !== before.healthPort
        || ids.installationId !== before.installationId || ids.session !== before.session || ids.revision !== before.revision
        || saved.inputSha256 !== before.inputSha256 || JSON.stringify(saved.input) !== JSON.stringify(before.input)) refuse();
    const value = fields(restored, ['prefix', 'manifest', 'registry', 'lifecycle', 'revision', 'status', 'history'], true);
    if (typeof value.prefix !== 'string' || !/^\/[A-Za-z0-9_./+-]+$/.test(value.prefix)
        || path.posix.normalize(value.prefix) !== value.prefix || value.prefix === '/') refuse();
    const manifest = fields(value.manifest, ['installationId', 'prefix', 'port', 'healthPort']);
    const registry = fields(value.registry, ['installationId', 'current', 'sessions']);
    const life = fields(value.lifecycle, ['installationId', 'session', 'prefix', 'stage', 'runtime', 'controlSocket']);
    const revision = fields(value.revision, ['id', 'parent', 'sourceRevision', 'input', 'inputSha256']);
    inputData(revision.input);
    const status = fields(value.status, ['binding', 'pending', 'lastConfirmedRevision', 'configUnchanged', 'fragmentMatchesLastConfirmed', 'history']);
    const history = fields(value.history, ['records']);
    if (typeof manifest.installationId !== 'string' || !TOKEN.test(manifest.installationId) || manifest.installationId === before.installationId
        || manifest.prefix !== value.prefix || manifest.port !== before.port || manifest.healthPort !== before.healthPort
        || registry.installationId !== manifest.installationId || typeof registry.current !== 'string' || !TOKEN.test(registry.current) || registry.current === before.session
        || !Array.isArray(registry.sessions) || registry.sessions.length !== 1 || registry.sessions[0] !== registry.current
        || life.installationId !== manifest.installationId || life.session !== registry.current
        || life.prefix !== `${value.prefix}/runs/${registry.current}` || life.stage !== 'prepared' || life.runtime !== null || life.controlSocket !== null
        || typeof revision.id !== 'string' || !TOKEN.test(revision.id) || revision.id === before.revision || revision.parent !== null || revision.sourceRevision !== null
        || revision.inputSha256 !== before.inputSha256 || JSON.stringify(revision.input) !== JSON.stringify(before.input)
        || status.binding !== null || status.pending !== null || status.lastConfirmedRevision !== revision.id
        || status.configUnchanged !== true || status.fragmentMatchesLastConfirmed !== true || ownData(status.history, 'entries') !== 1 || ownData(status.history, 'integrity') !== true
        || !Array.isArray(history.records) || history.records.length !== 1 || ownData(history.records[0], 'type') !== 'initialized_unbound'
        || ownData(history.records[0], 'sequence') !== 1 || ownData(history.records[0], 'previousHash') !== null
        || ownData(ownData(history.records[0], 'details'), 'revision') !== revision.id) refuse();
    return { freshInstallation: true, freshSession: true, freshRevision: true, exactInputRestored: true,
      portsPreserved: true, bindingInitiallyAbsent: true, freshHistory: true };
  } catch { refuse(); }
}
// End restored HTTP preparation assessment.

// Narrow held-response/paused-client control, not a backpressure or soak proof.
export function assessControlledDrainHold(client, originState, stopSettled) {
  if (stopSettled !== false || ownData(client, 'paused') !== true || ownData(client, 'complete') !== false
      || ownData(client, 'failed') !== false || ownData(client, 'tlsVerified') !== true
      || ownData(client, 'requestClosed') !== false || ownData(client, 'responseIncomplete') !== true
      || ownData(originState, 'requested') !== true || ownData(originState, 'held') !== true
      || ownData(originState, 'released') !== false || ownData(originState, 'completed') !== false
      || ownData(originState, 'aborted') !== false || ownData(originState, 'closed') !== false) reject('controlled_drain_unconfirmed');
  return true;
}
export function assessControlledDrainResult(result) {
  if (ownData(result, 'ok') !== true || ownData(result, 'complete') !== true
      || ownData(result, 'certificateMatched') !== true || ownData(result, 'protocol') !== 'TLSv1.3'
      || !Buffer.isBuffer(ownData(result, 'body')) || !ownData(result, 'body').equals(Buffer.alloc(65537, 0x62))) reject('controlled_drain_unconfirmed');
  return true;
}

export function assessInterruptedRecovery(record, previousRevision, failedRevision) {
  if (ownData(record, 'ok') !== false || ownData(record, 'exitCode') !== 1
      || ownData(record, 'termination') !== 'exit_nonzero' || ownData(record, 'stderr') !== ''
      || typeof ownData(record, 'stdout') !== 'string' || Buffer.byteLength(ownData(record, 'stdout')) > 256 * 1024
      || !TOKEN.test(previousRevision || '') || !TOKEN.test(failedRevision || '') || previousRevision === failedRevision) reject('operator_interruption_unconfirmed');
  let value; try { value = JSON.parse(ownData(record, 'stdout')); } catch { reject('operator_interruption_unconfirmed'); }
  if (ownData(value, 'ok') !== false || ownData(value, 'outcome') !== 'rolled_back'
      || ownData(value, 'reason') !== 'explicit_recovery' || ownData(value, 'failedRevision') !== failedRevision
      || ownData(value, 'restoredContentFrom') !== previousRevision || !TOKEN.test(ownData(value, 'revision') || '')
      || value.revision === previousRevision || value.revision === failedRevision) reject('operator_interruption_unconfirmed');
  return { revision: value.revision };
}
export function assessInterruptedProbeHold(value) {
  if (ownData(value, 'held') !== true || ownData(value, 'requested') !== true || ownData(value, 'candidateReadyObserved') !== true
      || ownData(value, 'aborted') !== false || ownData(value, 'closed') !== false || ownData(value, 'released') !== false
      || !Number.isInteger(ownData(value, 'nativeProbeChecks')) || value.nativeProbeChecks < 1 || value.nativeProbeChecks > 8
      || !Number.isInteger(ownData(value, 'heldResponses')) || value.heldResponses < 1 || value.heldResponses > 8) reject('operator_interruption_unconfirmed');
  return true;
}
// A historical relay observation alone never grants current challenge authority.
export function assessOwnedNativeChallenge(value) {
  assessInterruptedProbeHold(value);
  for (const key of ['nativeRouteObserved', 'ownedRequestObserved', 'relayResponseMatched',
    'currentRequestOpen', 'responseIncomplete', 'relayResponseOpen', 'socketOpen', 'pairMatched']) {
    if (ownData(value, key) !== true) reject('operator_interruption_unconfirmed');
  }
  return true;
}
// Only this exact finite data schema may cross the diagnostic publication boundary.
// It cannot grant capture, signal, retirement or recovery authority.
export function sanitizeNativeChallengeAdmission(value) {
  const booleans = ['started', 'admitted', 'accepted', 'nativeHeaderPairMatched', 'relayHeaderPairMatched',
    'contentLengthMatched', 'prefixMatched', 'currentPairLive', 'deadlineExpired'];
  const keys = ['schema', ...booleans, 'firstRefusal', 'nativeStatusClass', 'relayReadyStatusClass', 'prefixChunks'];
  const record = (input, names) => {
    if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) return null;
    const actual = Reflect.ownKeys(input);
    if (actual.length !== names.length || actual.some(key => typeof key !== 'string' || !names.includes(key))) return null;
    const result = Object.create(null);
    for (const key of names) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
  };
  try {
    const data = record(value, keys);
    if (!data || data.schema !== 1 || booleans.some(key => typeof data[key] !== 'boolean')
        || !['nativeStatusClass', 'relayReadyStatusClass'].every(key => Number.isInteger(data[key]) && data[key] >= 0 && data[key] <= 5)
        || !Number.isInteger(data.prefixChunks) || data.prefixChunks < 0 || data.prefixChunks > 4096) return null;
    if (data.firstRefusal !== null) {
      const refusal = record(data.firstRefusal, ['stage', 'reason']);
      if (!refusal || !ADMISSION_DIAGNOSTIC_STAGES.includes(refusal.stage) || !ADMISSION_DIAGNOSTIC_REASONS.includes(refusal.reason)) return null;
      data.firstRefusal = { stage: refusal.stage, reason: refusal.reason };
    }
    return { ...data };
  } catch { return null; }
}
// Diagnostics record the actual authority decision; later cleanup cannot replace
// the first refusal. They never grant a signal, lock or recovery capability.
const OPERATOR_HOLD_STAGES = Object.freeze(['harness_capture', 'harness_terminate', 'capture_final', 'terminate_capture', 'terminate_final', 'unknown']);
const OPERATOR_HOLD_REASONS = Object.freeze(['current', 'deadline_expired', 'live_probe_gap', 'candidate_unobserved', 'aborted', 'closed', 'budget_unarmed', 'cancelled', 'invalid']);
export function classifyOperatorHoldDecision(value, deadline, now) {
  try { assessInterruptedProbeHold(value); }
  catch {
    if (ownData(value, 'aborted') === true) return 'aborted';
    if (ownData(value, 'closed') === true) return 'closed';
    if (ownData(value, 'requested') === true && ownData(value, 'candidateReadyObserved') === true
        && ownData(value, 'held') === false && ownData(value, 'heldResponses') === 0
        && ownData(value, 'released') === false && ownData(value, 'aborted') === false && ownData(value, 'closed') === false) return 'live_probe_gap';
    if (ownData(value, 'requested') === false || ownData(value, 'candidateReadyObserved') === false) return 'candidate_unobserved';
    return 'invalid';
  }
  if (!Number.isFinite(now) || !Number.isFinite(deadline)) return 'invalid';
  if (deadline <= 0) return 'budget_unarmed';
  return now >= deadline ? 'deadline_expired' : 'current';
}
export function createOperatorHoldDiagnostics() {
  let count = 0, truncated = false, firstRefusal = null; const records = [];
  return Object.freeze({
    observe(stage, reason, now, deadline, value) {
      const age = Number.isFinite(now) && Number.isFinite(deadline) && deadline > 0 ? Math.max(0, Math.min(10000, Math.floor(now - (deadline - 1000)))) : null;
      const bounded = key => { const n = ownData(value, key); return Number.isInteger(n) && n >= 0 && n <= 8 ? n : null; };
      const entry = { stage: OPERATOR_HOLD_STAGES.includes(stage) ? stage : 'unknown',
        reason: OPERATOR_HOLD_REASONS.includes(reason) ? reason : 'invalid', ageMs: age,
        deadlineExpired: Number.isFinite(now) && Number.isFinite(deadline) && deadline > 0 && now >= deadline,
        nativeProbeChecks: bounded('nativeProbeChecks'), heldResponses: bounded('heldResponses') };
      if (count < 64) count++; else truncated = true;
      if (entry.reason !== 'current' && !firstRefusal) firstRefusal = { ...entry };
      if (records.length === 8) { records.shift(); truncated = true; }
      records.push(entry);
    },
    snapshot() { return { observationCount: count, observationsTruncated: truncated,
      firstRefusal: firstRefusal ? { ...firstRefusal } : null, observations: records.map(record => ({ ...record })) }; },
  });
}
// Only exact known private fixture paths reach this reader. Raw state stays local.
async function interruptionFile(file, parse = true) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o7077) !== 0 || st.nlink !== 1
        || st.size < 1 || st.size > 2 * 1024 * 1024 || await realpath(file) !== file) reject('operator_interruption_unconfirmed');
    const bytes = Buffer.alloc(st.size + 1); let used = 0;
    while (used < bytes.length) { const read = await handle.read(bytes, used, bytes.length - used, null); if (!read.bytesRead) break; used += read.bytesRead; }
    const after = await handle.stat();
    if (used !== st.size || after.size !== st.size || after.dev !== st.dev || after.ino !== st.ino
        || after.mtimeMs !== st.mtimeMs || after.ctimeMs !== st.ctimeMs) reject('operator_interruption_unconfirmed');
    const data = bytes.subarray(0, used), value = parse ? JSON.parse(data.toString('utf8')) : null;
    return { bytes: data, sha256: digest(data), value };
  } finally { await handle.close(); }
}

async function archiveBytes(file) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat(); if (!stat.isFile() || stat.size < 1 || stat.size > MAX_ARCHIVE_BYTES) reject('archive_refused');
    const bytes = Buffer.alloc(stat.size + 1); let used = 0;
    while (used < bytes.length) { const r = await handle.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    const after = await handle.stat();
    if (used !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) reject('archive_refused');
    return bytes.subarray(0, used);
  } finally { await handle.close(); }
}
async function absent(file) { try { await lstat(file); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; } }
async function until(fn, budget = 10000) {
  const end = performance.now() + budget;
  while (performance.now() < end) { if (await fn()) return; await pause(40); }
  reject('observation_timeout');
}
async function command(file, args, env, timeout = 15000) {
  try { const r = await execute(file, args, { cwd: '/', env, timeout, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
    return { ok: true, exitCode: 0, stdout: r.stdout, stderr: r.stderr, termination: 'none' }; }
  catch (e) { return { ok: false, exitCode: Number.isInteger(e.code) ? e.code : null, stdout: typeof e.stdout === 'string' ? e.stdout : '', stderr: typeof e.stderr === 'string' ? e.stderr : '', termination: classifyCommandTermination(e) }; }
}
async function cli(node, launcher, args, env) {
  const r = await command(node, [launcher, ...args], env);
  if (!r.ok) reject('installed_command_failed');
  let value; try { value = JSON.parse(r.stdout); } catch { reject('installed_response_invalid'); }
  if (!value || value.ok !== true) reject('installed_command_failed');
  return value;
}
// Only a known installed apply's explicit rollback is an expected failure.
// Raw reason/stdout, revision IDs and candidate tags stay private to this run.
export function assessRejectedOriginApply(record, previousRevision) {
  if (!record || record.ok !== false || record.exitCode !== 1 || record.termination !== 'exit_nonzero'
      || record.stderr !== '' || typeof record.stdout !== 'string' || record.stdout.length > 256 * 1024
      || !TOKEN.test(previousRevision || '')) reject('upstream_tls_rollback_unconfirmed');
  let value; try { value = JSON.parse(record.stdout); } catch { reject('upstream_tls_rollback_unconfirmed'); }
  if (!value || value.ok !== false || value.outcome !== 'rolled_back' || !TOKEN.test(value.revision || '')
      || !TOKEN.test(value.failedRevision || '') || value.restoredContentFrom !== previousRevision
      || value.revision === previousRevision || value.revision === value.failedRevision
      || value.failedRevision === previousRevision) reject('upstream_tls_rollback_unconfirmed');
  return { revision: value.revision, restoredContentFrom: value.restoredContentFrom };
}
async function listen(server) {
  await new Promise((resolve, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', () => { server.removeListener('error', fail); resolve(); }); });
  return server.address().port;
}
async function unusedPort() { const s = net.createServer(); const n = await listen(s); await new Promise(resolve => s.close(resolve)); return n; }
async function closedPort(port) {
  return new Promise(resolve => { const socket = net.connect({ host: '127.0.0.1', port }); let done = false;
    const finish = value => { if (done) return; done = true; socket.destroy(); resolve(value); };
    socket.once('connect', () => finish(false)); socket.once('error', e => finish(e.code === 'ECONNREFUSED'));
    socket.setTimeout(1000, () => finish(false)); });
}
async function request(port, route = '/', body = Buffer.alloc(0)) {
  return new Promise((resolve, fail) => {
    const req = http.request({ host: '127.0.0.1', port, path: route, method: body.length ? 'POST' : 'GET', agent: false,
      headers: { 'content-length': body.length } }, res => { const chunks = []; let size = 0;
      res.on('data', b => { size += b.length; if (size > 1024 * 1024) res.destroy(new Error('bound')); else chunks.push(b); });
      res.once('error', fail); res.once('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) })); });
    const timer = setTimeout(() => req.destroy(new Error('deadline')), 2500); req.once('close', () => clearTimeout(timer));
    req.setTimeout(2500, () => req.destroy(new Error('idle'))); req.once('error', fail); req.end(body);
  });
}

export async function main(argv = process.argv.slice(2)) {
  const report = { ok: false, code: 'not_started', phase: 'arguments', ...LIMITATIONS,
    actualNonrootManagerObserved: false, actualUnitStarted: false, explicitReadinessPasses: 0,
    tlsBackupAccepted: false, packageUpgradeRollbackAccepted: false, restoredHTTPChecks: 0,
    restoredHTTPProof: { stoppedConfirmedSource: false, privateBackupCreated: false, sourceUnitRemoved: false, freshUnit: false,
      freshInstallation: false, freshSession: false, freshRevision: false, exactInputRestored: false, portsPreserved: false,
      bindingInitiallyAbsent: false, freshHistory: false, restoredHTTPServed: false, restoredHTTPRestarted: false,
      noPostReplay: false, sourceRecordsPreserved: false, backupPreserved: false, archivePreserved: false, sourceInstallationRemoved: false },
    nativeSessionsStarted: 0, nativeSessionsStopped: 0, proxyBodyChecks: 0, uploadChecks: 0, streamChecks: 0,
    operatorNativeChallengeAdmission: null,
    operatorNativeChallengeChecks: 0, operatorNativeChallengeProof: { nativeRouteObserved: false, ownedRequestObserved: false, relayResponseMatched: false, candidateBindingMatched: false, authorityReobservedBeforeSignal: false, ownedChallengeClosed: false },
    operatorInterruptionContainment: { attempted: false, operatorAbsent: false, holdClosed: false, snapshotRevalidated: false, locksRetired: false, recoveryVerified: false, completed: false, disposition: 'not_needed' },
    operatorInterruptionChecks: 0, operatorInterruptionProof: { candidateProbeHeld: false, pendingReloadObserved: false, lastConfirmedPreserved: false, sameServiceObserved: false, ownedOperatorTerminated: false, staleLocksPreserved: false, lockedRecoveryRefused: false, exactLockRemovalConfirmed: false, explicitRollbackObserved: false, pendingCleared: false, restoredContentVerified: false, noPostReplay: false, sameServiceAfterRecovery: false, repeatedRecoveryIdempotent: false },
    controlledSlowDrainChecks: 0, controlledSlowDrainProof: { clientPaused: false, originResponseHeld: false, sameSessionObserved: false, managerStopPending: false, nativeGroupLiveDuringStop: false, unitDeactivatingObserved: false, incompleteResponseObserved: false, payloadCompleted: false, tlsVerified: false, managerStopCompleted: false, launcherExited: false, nativeGroupsAbsent: false, listeningPortsClosed: false, controlSocketAbsent: false },
    failedStartChecks: 0, failedStartProof: { unhealthyReadinessObserved: false, managerRefused: false, hookExitObserved: false, bindingAbsent: false, launcherExited: false, nativeGroupsAbsent: false, listeningPortsClosed: false, controlSocketAbsent: false, failedSessionStopped: false, managerResetConfirmed: false, healthyRestartFresh: false },
    managerRestartCommands: 0, completedManagerRestarts: 0,
    restartProof: { oldLauncherExited: false, oldNativeGroupsAbsent: false, freshSession: false, freshInvocation: false },
    journalChecks: 0, journalRecordsObserved: 0, journalRunningMarkers: 0,
    downstreamTLSActivated: false, downstreamTLSSessionChecks: 0, downstreamTLSBodyChecks: 0,
    downstreamTLSUploadChecks: 0, downstreamTLSStreamChecks: 0, downstreamTLS12Checks: 0, downstreamTLS13Checks: 0,
    downstreamTLSCertificateChecks: 0, downstreamTLSWrongCARefusals: 0, downstreamTLSWrongNameRefusals: 0,
    upstreamTLSActivated: false, upstreamTLSSessionChecks: 0, upstreamTLSBodyChecks: 0,
    upstreamTLSUploadChecks: 0, upstreamTLSStreamChecks: 0, upstreamTLSDirectChecks: 0,
    upstreamTLSWrongCARefusals: 0, upstreamTLSWrongNameRefusals: 0, upstreamTLSPlaintextRefusals: 0,
    upstreamTLSRollbackChecks: 0, upstreamTLSCandidate502Checks: 0, upstreamTLSNoPostReplayChecks: 0,
    bundleSchemaVersion: null, installSchemaVersion: null, installedRecipeGenerated: false,
    readinessAutomated: false, runtimeUnitLinked: false, runtimeUnitRemoved: false, unitEnabled: false, subprocessOutputsPublished: false,
    cleanup: { managerStopped: false, launcherExited: false, nativeGroupsAbsent: false,
      listeningPortsClosed: false, controlSocketAbsent: false, downstreamTLSPortClosed: false, runtimeLinkAbsent: false,
      upstreamTLSPortClosed: false, readinessRelayPortClosed: false, upstreamTLSOriginClosed: false, readinessRelayClosed: false,
      appSocketsRemaining: 0, installationRemoved: false, temporaryRootRemoved: false } };
  let input, parent, prefix, node, launcher, unitFile, runtimeLink, unitName, env, app, appPort, gatewayPort, healthPort, tlsPort, tlsFixture, origin, goodOriginRevision;
  let originCreationRequested = false, originCleanupSafe = true, retainedHTTPSource = null, appEchoRequests = 0;
  let failedStartup = null, readinessBlocked = true, readinessCaptureDone = false, readinessRefusals = 0;
  const heldReadiness = new Set();
  const originSessions = new Set();
  const tlsSessions = new Set();
  let linked = false, installed = false, safeToRemove = false, cancelled = false, startRequested = false, lastSession = null, inCleanup = false;
  const sessions = [], launcherIdentities = [], sockets = new Set();
  const failures = createFailureDiagnostics(), start = createStartDiagnostics(), fragments = createFragmentIdentityDiagnostics(), hooks = createHookStatusDiagnostics(), operatorHoldDiagnostics = createOperatorHoldDiagnostics();
  const cancel = () => { cancelled = true; };
  const checkCancelled = () => { if (cancelled) reject('cancelled'); };
  const systemctl = (args, timeout = 10000) => command(TOOL, ['--user', '--no-pager', '--no-ask-password', ...args], env, timeout);
  async function runtimeParents() {
    for (const directory of [`${env.XDG_RUNTIME_DIR}/systemd`, `${env.XDG_RUNTIME_DIR}/systemd/user`]) {
      if (await absent(directory)) continue;
      const st = await lstat(directory);
      if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o7022) !== 0 || await realpath(directory) !== directory) reject('unit_directory_identity');
    }
  }
  async function linkAuthority() {
    await runtimeParents();
    const st = await lstat(runtimeLink);
    if (!st.isSymbolicLink() || st.uid !== process.getuid() || await readlink(runtimeLink) !== unitFile) reject('unit_link_identity');
    const actual = await lstat(unitFile);
    if (!actual.isFile() || actual.uid !== process.getuid() || (actual.mode & 0o7777) !== 0o600
        || digest(await readFile(unitFile)) !== report.unitSha256) reject('unit_file_identity');
    return { targetMatchesUnit: true, unitOwnedModeHash: true };
  }
  async function properties(observe = true) {
    const r = await systemctl(['show', unitName, ...KEYS.map(k => `--property=${k}`)], 2500);
    if (observe && !inCleanup && ['first_start', 'second_start', 'manager_restart'].includes(report.phase)) start.observe('properties_command', r);
    if (![0, 1].includes(r.exitCode)) reject('unit_query_failed');
    const parsed = parseUnitProperties(r.stdout);
    if (observe && !inCleanup && ['first_start', 'second_start', 'manager_restart'].includes(report.phase)) start.observe('properties_state', parsed);
    if (parsed.LoadState === 'loaded' && (!r.ok || r.stderr)) reject('unit_query_failed');
    if (parsed.LoadState === 'not-found' && (parsed.MainPID !== '0' || parsed.FragmentPath !== '' || parsed.ControlGroup !== '' || parsed.ActiveState !== 'inactive')) reject('unit_response_invalid');
    return parsed;
  }
  async function ownedProperties(observe = true) {
    const precedingLinkCheck = await linkAuthority(); const p = await properties(observe);
    if (observe) fragments.observe(p, { unitFile, runtimeLink }, precedingLinkCheck, report.phase, start.snapshot().lastStep, inCleanup);
    await verifyKnownUnitFragmentPaths(p, { unitFile, runtimeLink });
    await linkAuthority();
    if (p.ControlGroup !== '' && !p.ControlGroup.startsWith(`/user.slice/user-${process.getuid()}.slice/user@${process.getuid()}.service/`)) reject('unit_cgroup_identity');
    if (p.ControlGroup !== '' && !p.ControlGroup.endsWith(`/${unitName}`)) reject('unit_cgroup_identity');
    return p;
  }
  async function observeStartPost(stage) {
    let attempt;
    try {
      attempt = start.snapshot().attempts;
      if (cancelled) { hooks.unavailable(attempt, stage, 'cancelled'); return; }
      await ownedProperties(false);
      if (cancelled) { hooks.unavailable(attempt, stage, 'cancelled'); return; }
      const result = await systemctl(['show', unitName, '--property=ExecStartPost'], 2500);
      await ownedProperties(false);
      if (cancelled) { hooks.unavailable(attempt, stage, 'cancelled'); return; }
      if (!result.ok || result.exitCode !== 0 || result.stderr !== '') hooks.unavailable(attempt, stage, 'query_refused');
      else hooks.observe(attempt, stage, result.stdout, { nodeExecutable: node, launcher });
    } catch {
      try { hooks.unavailable(attempt, stage, 'unavailable'); } catch { /* Diagnostics never acquire lifecycle authority. */ }
    }
  }
  async function launcherIdentity(p) {
    const pid = Number(p.MainPID);
    if (pid < 2 || !p.ControlGroup) reject('unit_launcher_identity');
    const base = `/proc/${pid}`;
    const [status, stat, executable, cmdline, pidNamespace, networkNamespace, cgroup] = await Promise.all([
      readFile(`${base}/status`, 'utf8'), readFile(`${base}/stat`, 'utf8'), readlink(`${base}/exe`), readFile(`${base}/cmdline`),
      readlink(`${base}/ns/pid`), readlink(`${base}/ns/net`), readFile(`${base}/cgroup`, 'utf8')]);
    const args = cmdline.toString('utf8').split('\0'); if (args.at(-1) === '') args.pop();
    if (Buffer.byteLength(status) + Buffer.byteLength(stat) + cmdline.length + Buffer.byteLength(cgroup) > 128 * 1024) reject('unit_launcher_identity');
    const expected = [node, launcher, 'run', '--control-socket', `${prefix}/control.sock`];
    const fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
    if (Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]) !== process.getuid() || executable !== node
        || JSON.stringify(args) !== JSON.stringify(expected) || ['Z', 'X'].includes(fields[0]) || !/^[0-9]+$/.test(fields[19])
        || pidNamespace !== await readlink('/proc/self/ns/pid') || networkNamespace !== await readlink('/proc/self/ns/net')
        || !cgroup.split('\n').includes(`0::${p.ControlGroup}`)) reject('unit_launcher_identity');
    return { pid, startTicks: fields[19], pidNamespace, networkNamespace };
  }
  async function exitedLauncher(identity) {
    if (!identity) return true;
    // A reused PID is unresolved: absence alone accepts the recorded launcher exit.
    return absent(`/proc/${identity.pid}`);
  }
  async function nativeStopped(session) {
    return await inspectMaster(`${prefix}/bin/nginx`, session.prefix, session.identity, false) === null
      && (await remainingNativeGroup(`${prefix}/bin/nginx`, session.identity)).length === 0;
  }
  async function checkedRecord(file) {
    const st = await lstat(file);
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0 || st.size > 2 * 1024 * 1024) reject('lifecycle_identity');
    const parsed = JSON.parse(await readFile(file, 'utf8')), { sha256, ...value } = parsed;
    if (sha256 !== digest(JSON.stringify(value))) reject('lifecycle_identity'); return value;
  }
  async function inventorySessions() {
    const manifest = await checkedRecord(`${prefix}/.alpha-install.json`), registry = await checkedRecord(`${prefix}/.alpha-registry.json`);
    if (manifest.prefix !== prefix || registry.installationId !== manifest.installationId || !Array.isArray(registry.sessions)
        || registry.sessions.length < 1 || registry.sessions.length > 256 || new Set(registry.sessions).size !== registry.sessions.length
        || !registry.sessions.includes(registry.current)) reject('lifecycle_identity');
    for (const id of registry.sessions) {
      if (!/^[a-f0-9]{32}$/.test(id)) reject('lifecycle_identity');
      const sessionPrefix = `${prefix}/runs/${id}`, life = await checkedRecord(`${sessionPrefix}/lifecycle.json`);
      if (life.installationId !== manifest.installationId || life.session !== id || life.prefix !== sessionPrefix) reject('lifecycle_identity');
      if (life.runtime) {
        if (!sessions.some(s => s.id === id)) sessions.push({ id, prefix: sessionPrefix, identity: life.runtime });
        else if (JSON.stringify(sessions.find(s => s.id === id).identity) !== JSON.stringify(life.runtime)) reject('lifecycle_identity');
      } else if (startRequested || life.stage !== 'prepared') reject('native_cleanup_unknown');
    }
  }
  async function observeNative() {
    const info = await cli(node, launcher, ['info'], env);
    if (info.stage !== 'running' || !/^[a-f0-9]{32}$/.test(info.session || '') || info.sessionPrefix !== `${prefix}/runs/${info.session}`) reject('session_identity');
    const life = JSON.parse(await readFile(`${info.sessionPrefix}/lifecycle.json`, 'utf8'));
    const { sha256, ...value } = life;
    if (sha256 !== digest(JSON.stringify(value)) || value.session !== info.session || value.stage !== 'running' || !value.runtime) reject('lifecycle_identity');
    const identity = await inspectMaster(`${prefix}/bin/nginx`, info.sessionPrefix, value.runtime);
    if (!identity) reject('native_identity');
    const s = { id: info.session, prefix: info.sessionPrefix, identity };
    const old = sessions.find(v => v.id === s.id); if (old) { if (JSON.stringify(old.identity) !== JSON.stringify(identity)) reject('native_identity'); } else sessions.push(s);
    report.nativeSessionsStarted++;
    return s;
  }
  // These are confirmations of the current attempt, not historical stop counts.
  function resetServiceCleanupEvidence() {
    report.cleanup.managerStopped = false; report.cleanup.launcherExited = false; report.cleanup.nativeGroupsAbsent = false;
    report.cleanup.listeningPortsClosed = false; report.cleanup.controlSocketAbsent = false;
    report.cleanup.downstreamTLSPortClosed = false;
  }
  async function stopOwned() {
    resetServiceCleanupEvidence();
    try { await inventorySessions(); } catch (e) { if (e.code !== 'native_cleanup_unknown') throw e; }
    const p = await ownedProperties();
    if (Number(p.MainPID) > 0) {
      const identity = await launcherIdentity(p); if (!launcherIdentities.some(i => i.pid === identity.pid && i.startTicks === identity.startTicks)) launcherIdentities.push(identity);
      // Normal stop belongs to the manager: its unchanged ExecStop runs the
      // installed guarded stop. A second concurrent CLI could race that lock.
    }
    const r = await systemctl(['stop', unitName], 35000);
    const after = await ownedProperties();
    await inventorySessions();
    if (!r.ok || after.ActiveState !== 'inactive' || Number(after.MainPID) !== 0 || after.Result !== 'success') reject('unit_stop_unconfirmed');
    await until(async () => { for (const identity of launcherIdentities) if (!await exitedLauncher(identity)) return false;
      for (const s of sessions) if (!await nativeStopped(s)) return false; return true; });
    if (!await absent(`${prefix}/control.sock`) || !await closedPort(gatewayPort) || !await closedPort(healthPort)) reject('service_resources_live');
    if (typeof tlsPort === 'number') {
      if (!await closedPort(tlsPort)) reject('service_resources_live');
      report.cleanup.downstreamTLSPortClosed = true;
    }
    report.cleanup.managerStopped = true; report.cleanup.launcherExited = true; report.cleanup.nativeGroupsAbsent = true;
    report.cleanup.listeningPortsClosed = true; report.cleanup.controlSocketAbsent = true;
  }
  async function verifyFailedReadinessStart() {
    resetServiceCleanupEvidence(); checkCancelled();
    const before = await ownedProperties(false);
    if (before.ActiveState !== 'inactive' || before.MainPID !== '0') reject('unit_not_stopped');
    const prior = await systemctl(['show', unitName, '--all', '--property=InvocationID'], 2500);
    if (!prior.ok || prior.stderr !== '' || prior.stdout !== 'InvocationID=\n') reject('failed_start_unconfirmed');
    checkCancelled();
    startRequested = true;
    // This single bounded command is always awaited, even if capture is refused.
    const pendingStart = systemctl(['start', unitName], 15000);
    let started, captured;
    try {
      await until(async () => { checkCancelled(); return heldReadiness.size > 0; }, 4000);
      const active = await ownedProperties(false);
      if (active.ActiveState !== 'activating' || active.SubState !== 'start-post' || active.Result !== 'success') reject('failed_start_unconfirmed');
      const launcherCapture = await launcherIdentity(active);
      const query = await systemctl(['show', unitName, '--property=InvocationID', '--property=ControlPID'], 2500);
      if (!query.ok || query.stderr !== '') reject('failed_start_unconfirmed');
      const identity = parseFailedStartIdentity(query.stdout);
      const manifest = await checkedRecord(`${prefix}/.alpha-install.json`);
      const registry = await checkedRecord(`${prefix}/.alpha-registry.json`);
      if (registry.installationId !== manifest.installationId || registry.sessions.length !== 1
          || registry.current !== registry.sessions[0] || !TOKEN.test(registry.current)) reject('failed_start_unconfirmed');
      const sessionPrefix = `${prefix}/runs/${registry.current}`, life = await checkedRecord(`${sessionPrefix}/lifecycle.json`);
      if (life.installationId !== manifest.installationId || life.session !== registry.current || life.prefix !== sessionPrefix
          || life.stage !== 'running' || !life.runtime) reject('failed_start_unconfirmed');
      const native = await inspectMaster(`${prefix}/bin/nginx`, sessionPrefix, life.runtime);
      if (!native) reject('failed_start_unconfirmed');
      const again = await ownedProperties(false), same = await launcherIdentity(again);
      if (again.ActiveState !== 'activating' || again.SubState !== 'start-post' || !sameLauncher(launcherCapture, same)) reject('failed_start_unconfirmed');
      captured = { id: registry.current, prefix: sessionPrefix, identity: native, launcher: launcherCapture, ...identity };
      // Keep this failed session in the full cleanup inventory, without counting
      // it as one of the three successful native/readiness/I/O sessions.
      sessions.push({ id: captured.id, prefix: captured.prefix, identity: native }); launcherIdentities.push(launcherCapture);
      readinessCaptureDone = true;
      for (const response of heldReadiness) {
        if (!response.destroyed && !response.writableEnded) { response.once('finish', () => { if (!response.destroyed) readinessRefusals++; }); response.writeHead(503); response.end('not-ready\n'); }
      }
      heldReadiness.clear();
      started = await pendingStart;
    } finally {
      // A capture failure grants no startup acceptance, but releases only our
      // own held health responses and observes completion of the one command.
      for (const response of heldReadiness) { if (!response.destroyed && !response.writableEnded) { response.writeHead(503); response.end('not-ready\n'); } }
      heldReadiness.clear();
      if (!started) await pendingStart;
    }
    checkCancelled();
    if (!captured || readinessRefusals < 1) reject('failed_start_unconfirmed');
    const failed = await ownedProperties(false);
    const invocation = await systemctl(['show', unitName, '--property=InvocationID'], 2500);
    const hook = await systemctl(['show', unitName, '--property=ExecStartPost'], 2500);
    if (!invocation.ok || invocation.stderr !== '' || parseInvocationProperty(invocation.stdout) !== captured.invocation
        || !hook.ok || hook.stderr !== '') reject('failed_start_unconfirmed');
    assessFailedReadinessStart(started, failed, hook.stdout, { nodeExecutable: node, launcher, hookPID: captured.hookPID });
    const after = await ownedProperties(false), repeated = await systemctl(['show', unitName, '--property=InvocationID'], 2500);
    if (!repeated.ok || repeated.stderr !== '' || parseInvocationProperty(repeated.stdout) !== captured.invocation) reject('failed_start_unconfirmed');
    assessFailedReadinessStart(started, after, hook.stdout, { nodeExecutable: node, launcher, hookPID: captured.hookPID });
    report.failedStartProof.unhealthyReadinessObserved = true; report.failedStartProof.managerRefused = true; report.failedStartProof.hookExitObserved = true;
    await until(async () => { checkCancelled();
      const life = await checkedRecord(`${captured.prefix}/lifecycle.json`);
      return life.session === captured.id && life.stage === 'stopped' && life.lastExit?.code === 0 && life.lastExit?.signal === null
        && JSON.stringify(life.runtime) === JSON.stringify(captured.identity) && await exitedLauncher(captured.launcher) && await nativeStopped(captured);
    });
    report.failedStartProof.failedSessionStopped = true; report.failedStartProof.launcherExited = true; report.failedStartProof.nativeGroupsAbsent = true;
    const info = await cli(node, launcher, ['info'], env), status = await cli(node, launcher, ['status'], env);
    if (info.session !== captured.id || info.sessionPrefix !== captured.prefix || info.stage !== 'stopped'
        || !Object.hasOwn(status, 'binding') || status.binding !== null || status.pending !== null) reject('failed_start_unconfirmed');
    report.failedStartProof.bindingAbsent = true;
    if (!await closedPort(gatewayPort) || !await closedPort(healthPort) || !await absent(`${prefix}/control.sock`)) reject('service_resources_live');
    report.failedStartProof.listeningPortsClosed = true; report.failedStartProof.controlSocketAbsent = true;
    checkCancelled();
    // Reset only this hash/owner/link-verified failed unit, after observing every
    // captured process and service resource absent. This is never a broad reset.
    const still = await ownedProperties(false);
    if (still.ActiveState !== 'failed' || still.MainPID !== '0' || still.Result !== 'exit-code') reject('failed_start_unconfirmed');
    if (!await exitedLauncher(captured.launcher) || !await nativeStopped(captured)) reject('failed_start_unconfirmed');
    checkCancelled();
    const reset = await systemctl(['reset-failed', unitName], 2500); checkCancelled();
    const resetState = await ownedProperties(false);
    if (!reset.ok || reset.stderr !== '' || resetState.ActiveState !== 'inactive' || resetState.SubState !== 'dead'
        || resetState.MainPID !== '0' || resetState.Result !== 'success') reject('failed_start_unconfirmed');
    checkCancelled();
    report.failedStartProof.managerResetConfirmed = true; failedStartup = captured; readinessBlocked = false;
  }
  async function startAndServe() {
    resetServiceCleanupEvidence();
    start.begin();
    checkCancelled();
    start.step('before_properties');
    const before = await ownedProperties(); if (before.ActiveState !== 'inactive' || Number(before.MainPID) !== 0) reject('unit_not_stopped');
    await observeStartPost('before_start');
    const fresh = await ownedProperties(false); if (fresh.ActiveState !== 'inactive' || Number(fresh.MainPID) !== 0) reject('unit_not_stopped');
    checkCancelled();
    start.step('request_start');
    startRequested = true;
    const started = await systemctl(['start', unitName], 15000);
    start.observe('start_command', started);
    // Any timeout is diagnosed in finally; no second start is attempted blindly.
    if (!started.ok) { await observeStartPost('failed_start'); reject('unit_start_failed'); }
    start.step('after_properties');
    const active = await ownedProperties(); if (active.ActiveState !== 'active' || active.SubState !== 'running') reject('unit_not_active');
    const servedSession = await observeActiveAndServe(active);
    if (failedStartup && report.failedStartChecks === 0) {
      const invocation = await ownedInvocation();
      if (servedSession.id === failedStartup.id || invocation.id === failedStartup.invocation
          || sameLauncher(invocation.launcher, failedStartup.launcher)) reject('failed_start_unconfirmed');
      report.failedStartProof.healthyRestartFresh = true; report.failedStartChecks++;
    }
    start.complete();
  }
  async function observeActiveAndServe(active) {
    start.step('launcher_identity');
    launcherIdentities.push(await launcherIdentity(active)); report.actualUnitStarted = true;
    start.step('binding_status');
    const startupStatus = await cli(node, launcher, ['status'], env); if (!startupStatus.binding || startupStatus.runtime?.identityValid !== true) reject('binding_unconfirmed');
    start.step('native_inventory');
    await until(async () => { try { await inventorySessions(); const current = await cli(node, launcher, ['info'], env); return current.stage === 'running' && current.session !== failedStartup?.id && sessions.some(s => s.id === current.session); } catch (e) { if (e.code === 'native_cleanup_unknown') return false; throw e; } });
    start.step('native_observation');
    const s = await observeNative();
    start.step('session_freshness');
    if (lastSession === s.id) reject('session_reused');
    lastSession = s.id;
    start.step('binding_status');
    const status = await cli(node, launcher, ['status'], env); if (!status.binding || status.runtime?.identityValid !== true) reject('binding_unconfirmed');
    report.explicitReadinessPasses++;
    start.step('proxy_body');
    const served = await request(gatewayPort); if (served.status !== 200 || served.body.toString() !== 'service-fixture\n') reject('proxy_body_mismatch'); report.proxyBodyChecks++;
    start.step('upload');
    const upload = Buffer.alloc(65551, 0x61), echo = await request(gatewayPort, '/echo', upload);
    if (echo.status !== 200 || !echo.body.equals(upload)) reject('upload_mismatch'); report.uploadChecks++;
    start.step('stream');
    const stream = await request(gatewayPort, '/stream'); if (stream.status !== 200 || !stream.body.equals(Buffer.alloc(65537, 0x62))) reject('stream_mismatch'); report.streamChecks++;
    start.step('final_cancel_check');
    checkCancelled();
    if (report.downstreamTLSActivated === true) await verifyDownstreamTLS();
    if (report.upstreamTLSActivated === true) await verifyUpstreamTLS();
    return s;
  }
  function sameLauncher(a, b) {
    return Boolean(a && b && a.pid === b.pid && a.startTicks === b.startTicks
      && a.pidNamespace === b.pidNamespace && a.networkNamespace === b.networkNamespace);
  }
  async function ownedInvocation() {
    start.step('invocation_identity');
    checkCancelled();
    const before = await ownedProperties(false);
    if (before.ActiveState !== 'active' || before.SubState !== 'running' || before.Result !== 'success') reject('unit_not_active');
    const identity = await launcherIdentity(before);
    if (!launcherIdentities.some(v => sameLauncher(v, identity))) reject('unit_launcher_identity');
    checkCancelled();
    const query = await systemctl(['show', unitName, '--property=InvocationID'], 2500);
    const after = await ownedProperties(false);
    const afterIdentity = await launcherIdentity(after);
    if (after.ActiveState !== 'active' || after.SubState !== 'running' || after.Result !== 'success'
        || !sameLauncher(identity, afterIdentity)) reject('unit_invocation_changed');
    checkCancelled();
    if (!query.ok || query.exitCode !== 0 || query.stderr !== '') reject('unit_invocation_invalid');
    return { id: parseInvocationProperty(query.stdout), launcher: identity };
  }
  async function verifyJournalForInvocation(expected) {
    const before = await ownedInvocation();
    if (before.id !== expected.id || !sameLauncher(before.launcher, expected.launcher)) reject('unit_invocation_changed');
    checkCancelled();
    start.step('journal_read');
    const observed = await observeOwnedJournal({ unitName, uid: process.getuid(), invocationId: expected.id });
    const after = await ownedInvocation();
    if (after.id !== expected.id || !sameLauncher(after.launcher, expected.launcher)) reject('unit_invocation_changed');
    checkCancelled();
    start.step('journal_read');
    if (observed && observed.ok === false && typeof observed.code === 'string'
        && JOURNAL_RESULT_CODES.includes(observed.code)) reject(observed.code);
    if (!observed || observed.ok !== true || observed.code !== 'owned_journal_observed'
        || observed.journalReadabilityObserved !== true || !Number.isInteger(observed.queryAttempts)
        || observed.queryAttempts < 1 || observed.queryAttempts > 3
        || !Number.isInteger(observed.recordsObserved) || observed.recordsObserved < 1 || observed.recordsObserved > 128
        || !Number.isInteger(observed.runningMarkers) || observed.runningMarkers < 1
        || observed.runningMarkers > observed.recordsObserved) reject('journal_unconfirmed');
    report.journalChecks++;
    report.journalRecordsObserved += observed.recordsObserved;
    report.journalRunningMarkers += observed.runningMarkers;
  }
  async function restartAndServe() {
    // Prior stop confirmations cannot describe this new mutating attempt.
    resetServiceCleanupEvidence();
    checkCancelled();
    const oldSession = sessions.find(s => s.id === lastSession);
    if (!oldSession || !await inspectMaster(`${prefix}/bin/nginx`, oldSession.prefix, oldSession.identity)) reject('restart_identity');
    const oldInvocation = await ownedInvocation();
    await verifyJournalForInvocation(oldInvocation);
    // Confirm the captured session is still current, then repeat the native
    // and owned-unit checks after these journal and installed-CLI awaits.
    const current = await cli(node, launcher, ['info'], env);
    if (current.stage !== 'running' || current.session !== oldSession.id || current.sessionPrefix !== oldSession.prefix) reject('restart_identity');
    if (!await inspectMaster(`${prefix}/bin/nginx`, oldSession.prefix, oldSession.identity)) reject('restart_identity');
    const fresh = await ownedProperties(false);
    const freshLauncher = await launcherIdentity(fresh);
    if (fresh.ActiveState !== 'active' || fresh.SubState !== 'running' || fresh.Result !== 'success'
        || !sameLauncher(oldInvocation.launcher, freshLauncher)) reject('restart_identity');
    checkCancelled();
    start.step('request_restart');
    report.managerRestartCommands++;
    const restarted = await systemctl(['restart', unitName], 35000);
    if (!restarted.ok) reject('unit_restart_failed');
    checkCancelled();
    start.step('old_retirement');
    await until(async () => { checkCancelled(); return await exitedLauncher(oldInvocation.launcher) && await nativeStopped(oldSession); });
    checkCancelled();
    report.restartProof.oldLauncherExited = true;
    report.restartProof.oldNativeGroupsAbsent = true;
    report.nativeSessionsStopped++;
    checkCancelled();
    start.step('after_properties');
    const active = await ownedProperties(false);
    if (active.ActiveState !== 'active' || active.SubState !== 'running' || active.Result !== 'success') reject('unit_not_active');
    const newLauncher = await launcherIdentity(active);
    if (sameLauncher(oldInvocation.launcher, newLauncher)) reject('restart_identity');
    const newSession = await observeActiveAndServe(active);
    if (newSession.id === oldSession.id) reject('session_reused');
    report.restartProof.freshSession = true;
    const newInvocation = await ownedInvocation();
    if (newInvocation.id === oldInvocation.id || !sameLauncher(newLauncher, newInvocation.launcher)) reject('unit_invocation_changed');
    report.restartProof.freshInvocation = true;
    await verifyJournalForInvocation(newInvocation);
    checkCancelled();
    report.completedManagerRestarts++;
    start.step('complete');
  }
  async function activateDownstreamTLS() {
    // Applying a listener is a new attempt, including failures before activation.
    resetServiceCleanupEvidence();
    checkCancelled();
    tlsFixture = await createServicePKI(parent);
    checkCancelled();
    do { tlsPort = await unusedPort(); } while ([appPort, gatewayPort, healthPort].includes(tlsPort));
    checkCancelled();
    const inputFile = `${parent}/downstream-tls-input.json`;
    const originParent = `${parent}/origin`;
    await mkdir(originParent, { mode: 0o700 });
    checkCancelled(); originCreationRequested = true; originCleanupSafe = false;
    origin = await createOriginFixture(originParent, { gatewayPort, body: Buffer.from('service-fixture\n'), stream: Buffer.alloc(65537, 0x62) });
    checkCancelled();
    if (!origin || [appPort, gatewayPort, healthPort, tlsPort].includes(origin.port)
        || [appPort, gatewayPort, healthPort, tlsPort, origin.port].includes(origin.readyPort)) reject('upstream_tls_unconfirmed');
    const direct = await probeServiceTLS(origin.port, '/', { ca: origin.ca, expectedCertificate: origin.expectedCertificate,
      servername: 'localhost', version: 'TLSv1.3' });
    checkCancelled();
    if (direct.status !== 200 || direct.certificateMatched !== true || direct.protocol !== 'TLSv1.3'
        || !Buffer.isBuffer(direct.body) || direct.body.toString() !== 'service-fixture\n') reject('upstream_tls_unconfirmed');
    report.upstreamTLSDirectChecks++;
    const input = origin.candidate({ tag: randomBytes(16).toString('hex') });
    input.https = { port: tlsPort, certificate: tlsFixture.certificate, certificateKey: tlsFixture.certificateKey };
    const file = await open(inputFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await file.writeFile(JSON.stringify(input)); await file.sync(); } finally { await file.close(); }
    const current = await cli(node, launcher, ['info'], env);
    const known = sessions.find(s => s.id === lastSession);
    if (!known || current.stage !== 'running' || current.session !== known.id || current.sessionPrefix !== known.prefix
        || !await inspectMaster(`${prefix}/bin/nginx`, known.prefix, known.identity)) reject('downstream_tls_session');
    const before = await ownedInvocation();
    checkCancelled();
    const applied = await cli(node, launcher, ['apply', '--file', inputFile], env);
    if (applied.outcome !== 'applied' || !TOKEN.test(applied.revision || '')) reject('downstream_tls_unconfirmed');
    goodOriginRevision = applied.revision;
    const after = await ownedInvocation();
    if (before.id !== after.id || !sameLauncher(before.launcher, after.launcher)) reject('unit_invocation_changed');
    checkCancelled();
    report.downstreamTLSActivated = true; report.upstreamTLSActivated = true;
    await verifyDownstreamTLS();
    await verifyUpstreamTLS();
    await verifyOriginRefusals();
  }
  async function verifyDownstreamTLS() {
    start.step('downstream_tls');
    checkCancelled();
    if (!report.downstreamTLSActivated || !tlsFixture || !Number.isInteger(tlsPort)) reject('downstream_tls_unconfirmed');
    const current = await cli(node, launcher, ['info'], env);
    const known = sessions.find(s => s.id === lastSession);
    if (!known || current.stage !== 'running' || current.session !== known.id || current.sessionPrefix !== known.prefix
        || tlsSessions.has(known.id) || tlsSessions.size >= 3) reject('downstream_tls_session');
    const before = await ownedInvocation();
    async function checkedProbe(route, version, body = Buffer.alloc(0)) {
      start.step('downstream_tls');
      checkCancelled();
      const response = await probeServiceTLS(tlsPort, route, { ca: tlsFixture.ca, expectedCertificate: tlsFixture.expectedCertificate,
        servername: 'localhost', version, method: body.length ? 'POST' : 'GET', body });
      checkCancelled();
      if (!response || response.status !== 200 || !Buffer.isBuffer(response.body) || response.protocol !== version
          || response.certificateMatched !== true) reject('downstream_tls_unconfirmed');
      report.downstreamTLSCertificateChecks++;
      return response;
    }
    for (const version of ['TLSv1.2', 'TLSv1.3']) {
      const response = await checkedProbe('/', version);
      if (response.body.toString() !== 'service-fixture\n') reject('downstream_tls_body_mismatch');
      report.downstreamTLSBodyChecks++;
      if (version === 'TLSv1.2') report.downstreamTLS12Checks++; else report.downstreamTLS13Checks++;
    }
    const upload = Buffer.alloc(65551, 0x61), echo = await checkedProbe('/echo', 'TLSv1.3', upload);
    if (!echo.body.equals(upload)) reject('downstream_tls_upload_mismatch'); report.downstreamTLSUploadChecks++;
    const stream = await checkedProbe('/stream', 'TLSv1.3');
    if (!stream.body.equals(Buffer.alloc(65537, 0x62))) reject('downstream_tls_stream_mismatch'); report.downstreamTLSStreamChecks++;
    checkCancelled();
    const wrongCA = await expectServiceTLSRefusal(tlsPort, { ca: tlsFixture.wrongCA,
      expectedCertificate: tlsFixture.expectedCertificate, servername: 'localhost' });
    checkCancelled();
    if (!wrongCA || wrongCA.ok !== true || wrongCA.code !== 'tls_ca_refused') reject('downstream_tls_ca_unconfirmed');
    report.downstreamTLSWrongCARefusals++;
    checkCancelled();
    const wrongName = await expectServiceTLSRefusal(tlsPort, { ca: tlsFixture.ca,
      expectedCertificate: tlsFixture.expectedCertificate, servername: 'wrong.invalid' });
    checkCancelled();
    if (!wrongName || wrongName.ok !== true || wrongName.code !== 'tls_hostname_refused') reject('downstream_tls_hostname_unconfirmed');
    report.downstreamTLSWrongNameRefusals++;
    const afterInfo = await cli(node, launcher, ['info'], env);
    if (afterInfo.stage !== 'running' || afterInfo.session !== known.id || afterInfo.sessionPrefix !== known.prefix
        || !await inspectMaster(`${prefix}/bin/nginx`, known.prefix, known.identity)) reject('downstream_tls_session');
    const after = await ownedInvocation();
    if (before.id !== after.id || !sameLauncher(before.launcher, after.launcher)) reject('unit_invocation_changed');
    checkCancelled();
    tlsSessions.add(known.id); report.downstreamTLSSessionChecks++;
  }
  async function verifyUpstreamTLS() {
    start.step('upstream_tls'); checkCancelled();
    if (!report.upstreamTLSActivated || !origin) reject('upstream_tls_unconfirmed');
    const known = sessions.find(s => s.id === lastSession);
    if (!known || originSessions.has(known.id) || originSessions.size >= 3) reject('upstream_tls_session');
    const before = await currentOriginAuthority(known);
    const body = await request(gatewayPort); checkCancelled();
    if (body.status !== 200 || body.body.toString() !== 'service-fixture\n') reject('upstream_tls_unconfirmed');
    report.upstreamTLSBodyChecks++;
    const upload = Buffer.alloc(65551, 0x61), echo = await request(gatewayPort, '/echo', upload); checkCancelled();
    if (echo.status !== 200 || !echo.body.equals(upload)) reject('upstream_tls_unconfirmed');
    report.upstreamTLSUploadChecks++;
    const stream = await request(gatewayPort, '/stream'); checkCancelled();
    if (stream.status !== 200 || !stream.body.equals(Buffer.alloc(65537, 0x62))) reject('upstream_tls_unconfirmed');
    report.upstreamTLSStreamChecks++;
    const after = await currentOriginAuthority(known);
    if (before.id !== after.id || !sameLauncher(before.launcher, after.launcher)) reject('unit_invocation_changed');
    checkCancelled(); originSessions.add(known.id); report.upstreamTLSSessionChecks++;
  }
  async function currentOriginAuthority(known) {
    checkCancelled();
    const info = await cli(node, launcher, ['info'], env);
    if (!known || info.stage !== 'running' || info.session !== known.id || info.sessionPrefix !== known.prefix
        || !await inspectMaster(`${prefix}/bin/nginx`, known.prefix, known.identity)) reject('upstream_tls_session');
    return ownedInvocation();
  }
  async function verifyOriginRefusals() {
    report.phase = 'origin_negative'; start.step('origin_negative');
    const known = sessions.find(s => s.id === lastSession);
    for (const [kind, changed, counter] of [
      ['wrong-ca', { trust: 'wrong' }, 'upstreamTLSWrongCARefusals'],
      ['wrong-name', { name: 'wrong.invalid' }, 'upstreamTLSWrongNameRefusals'],
      ['plaintext', { target: 'plaintext' }, 'upstreamTLSPlaintextRefusals']]) {
      resetServiceCleanupEvidence(); checkCancelled();
      const direct = await probeServiceTLS(origin.port, '/', { ca: origin.ca, expectedCertificate: origin.expectedCertificate,
        servername: 'localhost', version: 'TLSv1.3' });
      checkCancelled();
      if (direct.status !== 200 || !Buffer.isBuffer(direct.body) || direct.body.toString() !== 'service-fixture\n'
          || direct.certificateMatched !== true || direct.protocol !== 'TLSv1.3') reject('upstream_tls_unconfirmed');
      const tag = randomBytes(16).toString('hex'), input = origin.candidate({ tag, ...changed });
      input.https = { port: tlsPort, certificate: tlsFixture.certificate, certificateKey: tlsFixture.certificateKey };
      const inputFile = `${parent}/origin-${kind}.json`;
      const file = await open(inputFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await file.writeFile(JSON.stringify(input)); await file.sync(); } finally { await file.close(); }
      const before502 = origin.count502(tag), beforePosts = origin.counts().echoRequests;
      const before = await currentOriginAuthority(known);
      checkCancelled();
      const result = await command(node, [launcher, 'apply', '--file', inputFile], env);
      checkCancelled();
      const rollback = assessRejectedOriginApply(result, goodOriginRevision);
      const after = await currentOriginAuthority(known);
      if (before.id !== after.id || !sameLauncher(before.launcher, after.launcher)) reject('unit_invocation_changed');
      checkCancelled();
      if (!Number.isInteger(before502) || before502 !== 0 || !Number.isInteger(origin.count502(tag))
          || origin.count502(tag) <= before502) reject('upstream_tls_candidate_unconfirmed');
      const status = await cli(node, launcher, ['status'], env); checkCancelled();
      if (status.lastConfirmedRevision !== rollback.revision || !status.binding || status.runtime?.identityValid !== true) reject('upstream_tls_rollback_unconfirmed');
      const restored = await request(gatewayPort); checkCancelled();
      if (restored.status !== 200 || restored.body.toString() !== 'service-fixture\n') reject('upstream_tls_rollback_unconfirmed');
      const secure = await probeServiceTLS(tlsPort, '/', { ca: tlsFixture.ca, expectedCertificate: tlsFixture.expectedCertificate,
        servername: 'localhost', version: 'TLSv1.3' }); checkCancelled();
      if (secure.status !== 200 || secure.certificateMatched !== true || secure.protocol !== 'TLSv1.3'
          || !Buffer.isBuffer(secure.body) || secure.body.toString() !== 'service-fixture\n') reject('upstream_tls_rollback_unconfirmed');
      if (!Number.isInteger(beforePosts) || origin.counts().echoRequests !== beforePosts) reject('upstream_tls_replay');
      const final = await currentOriginAuthority(known);
      if (before.id !== final.id || !sameLauncher(before.launcher, final.launcher)) reject('unit_invocation_changed');
      checkCancelled();
      goodOriginRevision = rollback.revision;
      report[counter]++; report.upstreamTLSRollbackChecks++; report.upstreamTLSCandidate502Checks++; report.upstreamTLSNoPostReplayChecks++;
    }
  }
  async function verifyOperatorInterruption() {
    checkCancelled();
    if (!origin || !tlsFixture || !report.upstreamTLSActivated || !report.downstreamTLSActivated) reject('operator_interruption_unconfirmed');
    const known = sessions.find(session => session.id === lastSession);
    if (!known) reject('operator_interruption_unconfirmed');
    const before = await currentOriginAuthority(known), initialStatus = await cli(node, launcher, ['status'], env);
    checkCancelled();
    if (!TOKEN.test(initialStatus.lastConfirmedRevision || '') || !initialStatus.binding || initialStatus.pending !== null
        || initialStatus.runtime?.identityValid !== true || initialStatus.configUnchanged !== true
        || initialStatus.fragmentMatchesLastConfirmed !== true || initialStatus.history?.integrity !== true) reject('operator_interruption_unconfirmed');
    const statePath = `${known.prefix}/.x10-control`, previousRevision = initialStatus.lastConfirmedRevision;
    const originalState = await interruptionFile(`${statePath}/state.json`), originalHistory = await interruptionFile(`${statePath}/history.jsonl`, false);
    const previous = await interruptionFile(`${statePath}/revisions/${previousRevision}.json`);
    const { recordSha256: oldRecordHash, ...oldRevision } = previous.value;
    if (oldRecordHash !== digest(JSON.stringify(oldRevision)) || previous.value.id !== previousRevision
        || previous.value.inputSha256 !== digest(JSON.stringify(previous.value.input))) reject('operator_interruption_unconfirmed');
    if (originalState.value.activeRevision !== previousRevision || JSON.stringify(originalState.value.binding) !== JSON.stringify(initialStatus.binding)) reject('operator_interruption_unconfirmed');
    const tag = randomBytes(16).toString('hex'), input = origin.candidate({ tag });
    input.https = { port: tlsPort, certificate: tlsFixture.certificate, certificateKey: tlsFixture.certificateKey };
    const inputFile = `${parent}/interrupted-input.json`;
    let held, ownedChallenge, operator, snapshot, heldDeadline = 0, primary = null, normalRetirementAttempted = false;
    let cleanupCapturePhase = 'unarmed';
    const beforePosts = origin.counts().echoRequests;
    async function sameServiceNoCLI() {
      const p = await ownedProperties(false); checkCancelled();
      if (p.ActiveState !== 'active' || p.SubState !== 'running' || p.Result !== 'success'
          || !sameLauncher(await launcherIdentity(p), before.launcher)) reject('unit_launcher_identity');
      const query = await systemctl(['show', unitName, '--property=InvocationID'], 2500); checkCancelled();
      if (!query.ok || query.stderr !== '' || parseInvocationProperty(query.stdout) !== before.id
          || !await inspectMaster(`${prefix}/bin/nginx`, known.prefix, known.identity)) reject('unit_invocation_changed');
      const registry = await checkedRecord(`${prefix}/.alpha-registry.json`), life = await checkedRecord(`${known.prefix}/lifecycle.json`);
      if (registry.current !== known.id || life.session !== known.id || life.stage !== 'running'
          || JSON.stringify(life.runtime) !== JSON.stringify(known.identity)) reject('operator_interruption_unconfirmed');
      checkCancelled();
    }
    async function capturePending() {
      const pending = await interruptionFile(`${statePath}/pending.json`), state = await interruptionFile(`${statePath}/state.json`);
      if (pending.value.schemaVersion !== 1 || pending.value.stage !== 'reload_requested' || pending.value.previous !== previousRevision
          || !TOKEN.test(pending.value.candidate || '') || pending.value.candidate === previousRevision
          || state.value.activeRevision !== previousRevision || JSON.stringify(state.value.binding) !== JSON.stringify(originalState.value.binding)
          || JSON.stringify({ ...state.value, historyHead: originalState.value.historyHead }) !== JSON.stringify(originalState.value)
          || !await absent(`${statePath}/event-commit.json`)) reject('operator_interruption_unconfirmed');
      const candidate = await interruptionFile(`${statePath}/revisions/${pending.value.candidate}.json`);
      const { recordSha256, ...revision } = candidate.value;
      const fragment = await interruptionFile(`${known.prefix}/managed.conf`, false), history = await interruptionFile(`${statePath}/history.jsonl`, false);
      if (recordSha256 !== digest(JSON.stringify(revision)) || candidate.value.id !== pending.value.candidate
          || candidate.value.parent !== previousRevision || candidate.value.sourceRevision !== null
          || candidate.value.inputSha256 !== digest(JSON.stringify(input)) || JSON.stringify(candidate.value.input) !== JSON.stringify(input)
          || candidate.value.fragmentSha256 !== fragment.sha256 || !history.bytes.subarray(0, originalHistory.bytes.length).equals(originalHistory.bytes)) reject('operator_interruption_unconfirmed');
      const appended = history.bytes.subarray(originalHistory.bytes.length).toString('utf8');
      if (!appended.endsWith('\n') || appended.split('\n').length !== 2) reject('operator_interruption_unconfirmed');
      const event = JSON.parse(appended), { hash, ...eventBody } = event;
      if (event.sequence !== originalHistory.bytes.toString('utf8').split('\n').length
          || event.type !== 'apply_started' || event.details?.revision !== candidate.value.id || event.details?.previous !== previousRevision
          || event.previousHash !== originalState.value.historyHead || hash !== digest(JSON.stringify(eventBody)) || state.value.historyHead !== hash) reject('operator_interruption_unconfirmed');
      return { pending, state, candidate, fragment, history, failedRevision: candidate.value.id };
    }
    async function unchangedPending(expected) {
      const actual = await capturePending();
      for (const key of ['pending', 'state', 'candidate', 'fragment', 'history']) if (actual[key].sha256 !== expected[key].sha256) reject('operator_interruption_unconfirmed');
      return actual;
    }
    const isHeld = (stage = 'harness_capture') => {
      let value, reason;
      try { checkCancelled(); }
      catch (error) { operatorHoldDiagnostics.observe(stage, 'cancelled', performance.now(), heldDeadline, null); throw error; }
      let now;
      try {
        if (stage === 'capture_final') {
          // This one-shot legacy observation permits cleanup ownership capture
          // only while the helper is checking the exact original process/locks.
          // It is never acceptance authority for either termination callback.
          const permitted = cleanupCapturePhase === 'pending';
          cleanupCapturePhase = 'consumed';
          value = permitted ? held?.snapshot() : null; now = performance.now();
          reason = permitted ? classifyOperatorHoldDecision(value, heldDeadline, now) : 'invalid';
        } else {
          value = ownedChallenge?.snapshot(); now = performance.now(); reason = classifyOperatorHoldDecision(value, heldDeadline, now);
          if (!['harness_capture', 'harness_terminate', 'terminate_capture', 'terminate_final'].includes(stage)) reason = 'invalid';
          if (reason === 'current') { try { assessOwnedNativeChallenge(value); } catch { reason = 'invalid'; } }
        }
      }
      catch (error) { operatorHoldDiagnostics.observe(stage, 'invalid', performance.now(), heldDeadline, null); throw error; }
      operatorHoldDiagnostics.observe(stage, reason, now, heldDeadline, value);
      if (stage === 'terminate_final' && reason === 'current') report.operatorNativeChallengeProof.authorityReobservedBeforeSignal = true;
      return reason === 'current';
    };
    try {
      held = origin.prepareReadinessHold(tag); checkCancelled();
      if (!held || typeof held.nativeLocation !== 'string' || Buffer.byteLength(held.nativeLocation) < 1
          || Buffer.byteLength(held.nativeLocation) > 8192) reject('operator_interruption_unconfirmed');
      input.serverBody += `\n${held.nativeLocation}`;
      const file = await open(inputFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await file.writeFile(JSON.stringify(input)); await file.sync(); } finally { await file.close(); }
      checkCancelled();
      operator = await startOwnedOperator({ node, launcher, prefix, sessionPrefix: known.prefix, inputFile, env, isHeld, checkCancelled });
      checkCancelled();
      await until(async () => { checkCancelled(); const value = held.snapshot();
        if (value.held !== true || value.candidateReadyObserved !== true) return false;
        if (!heldDeadline) heldDeadline = performance.now() + 1000;
        return true;
      }, 2000);
      checkCancelled();
      if (performance.now() >= heldDeadline) reject('operator_interruption_unconfirmed');
      // Capture the exact process/locks and pending state before opening a
      // challenge that may refuse admission. This is cleanup ownership only.
      let captured;
      cleanupCapturePhase = 'pending';
      try { captured = await operator.captureLocks(); }
      finally { cleanupCapturePhase = 'closed'; }
      checkCancelled();
      if (!captured || captured.ok !== true || captured.alphaCaptured !== true || captured.controllerCaptured !== true || captured.pendingCaptured !== true) reject('operator_interruption_unconfirmed');
      snapshot = await capturePending(); await sameServiceNoCLI();
      await unchangedPending(snapshot); checkCancelled();
      if (performance.now() >= heldDeadline) reject('operator_interruption_unconfirmed');
      // This request traverses the new candidate-only native location. Its
      // deadline is the original first-controller-hold deadline, never renewed.
      ownedChallenge = await held.openNativeChallenge(heldDeadline); checkCancelled();
      if (!isHeld()) reject('operator_interruption_unconfirmed');
      const challenge = ownedChallenge.snapshot(); assessOwnedNativeChallenge(challenge);
      report.operatorNativeChallengeProof.nativeRouteObserved = true; report.operatorNativeChallengeProof.ownedRequestObserved = true;
      report.operatorNativeChallengeProof.relayResponseMatched = true;
      // Admission may await native I/O: revalidate every original mutable
      // state and current service identity again before acceptance proceeds.
      await unchangedPending(snapshot); await sameServiceNoCLI(); checkCancelled();
      if (!isHeld('harness_terminate')) reject('operator_interruption_unconfirmed');
      report.operatorInterruptionProof.candidateProbeHeld = true; report.operatorInterruptionProof.pendingReloadObserved = true;
      report.operatorInterruptionProof.lastConfirmedPreserved = true; report.operatorInterruptionProof.sameServiceObserved = true;
      report.operatorNativeChallengeProof.candidateBindingMatched = true;
      const terminated = await operator.terminate(); checkCancelled();
      if (!terminated || terminated.ok !== true || terminated.wrapperExited !== true || terminated.controllerExited !== true || terminated.groupAbsent !== true) reject('operator_interruption_unconfirmed');
      report.operatorInterruptionProof.ownedOperatorTerminated = true;
      if (await held.abort() !== true) reject('operator_interruption_unconfirmed'); checkCancelled();
      await unchangedPending(snapshot); await sameServiceNoCLI(); checkCancelled();
      const blocked = await command(node, [launcher, 'recover'], env); checkCancelled();
      let blockedValue; try { blockedValue = JSON.parse(blocked.stdout); } catch { reject('operator_interruption_unconfirmed'); }
      if (blocked.ok !== false || blocked.exitCode !== 1 || blocked.termination !== 'exit_nonzero' || blocked.stderr !== ''
          || blockedValue.ok !== false || blockedValue.code !== 'alpha_locked') reject('operator_interruption_unconfirmed');
      await unchangedPending(snapshot); checkCancelled();
      report.operatorInterruptionProof.staleLocksPreserved = true; report.operatorInterruptionProof.lockedRecoveryRefused = true;
      normalRetirementAttempted = true;
      const retired = await operator.removeCapturedLocks(); checkCancelled();
      if (!retired || retired.ok !== true || retired.alphaRemoved !== true || retired.controllerRemoved !== true) reject('operator_interruption_unconfirmed');
      report.operatorInterruptionProof.exactLockRemovalConfirmed = true;
      await unchangedPending(snapshot); await sameServiceNoCLI(); checkCancelled();
      const recovered = await command(node, [launcher, 'recover'], env); checkCancelled();
      const recovery = assessInterruptedRecovery(recovered, previousRevision, snapshot.failedRevision);
      report.operatorInterruptionProof.explicitRollbackObserved = true;
      const restored = await interruptionFile(`${statePath}/revisions/${recovery.revision}.json`), { recordSha256, ...revision } = restored.value;
      const recoveredStatus = await cli(node, launcher, ['status'], env); checkCancelled();
      if (recordSha256 !== digest(JSON.stringify(revision)) || restored.value.id !== recovery.revision
          || restored.value.parent !== previousRevision || restored.value.sourceRevision !== previousRevision
          || restored.value.inputSha256 !== previous.value.inputSha256 || JSON.stringify(restored.value.input) !== JSON.stringify(previous.value.input)
          || !await absent(`${statePath}/pending.json`) || recoveredStatus.pending !== null || recoveredStatus.lastConfirmedRevision !== recovery.revision
          || JSON.stringify(recoveredStatus.binding) !== JSON.stringify(originalState.value.binding) || recoveredStatus.runtime?.identityValid !== true
          || recoveredStatus.configUnchanged !== true || recoveredStatus.fragmentMatchesLastConfirmed !== true || recoveredStatus.history?.integrity !== true) reject('operator_interruption_unconfirmed');
      report.operatorInterruptionProof.pendingCleared = true;
      const body = await request(gatewayPort); checkCancelled();
      const secure = await probeServiceTLS(tlsPort, '/', { ca: tlsFixture.ca, expectedCertificate: tlsFixture.expectedCertificate, servername: 'localhost', version: 'TLSv1.3' }); checkCancelled();
      if (body.status !== 200 || body.body.toString() !== 'service-fixture\n' || secure.status !== 200 || secure.certificateMatched !== true
          || secure.protocol !== 'TLSv1.3' || !Buffer.isBuffer(secure.body) || secure.body.toString() !== 'service-fixture\n') reject('operator_interruption_unconfirmed');
      report.operatorInterruptionProof.restoredContentVerified = true;
      if (!Number.isInteger(beforePosts) || origin.counts().echoRequests !== beforePosts) reject('upstream_tls_replay');
      report.operatorInterruptionProof.noPostReplay = true;
      const final = await currentOriginAuthority(known); checkCancelled();
      if (final.id !== before.id || !sameLauncher(final.launcher, before.launcher)) reject('unit_invocation_changed');
      report.operatorInterruptionProof.sameServiceAfterRecovery = true;
      const confirmedState = await interruptionFile(`${statePath}/state.json`), confirmedHistory = await interruptionFile(`${statePath}/history.jsonl`, false);
      checkCancelled();
      const repeated = await cli(node, launcher, ['recover'], env); checkCancelled();
      if (repeated.outcome !== 'nothing_pending' || !await absent(`${statePath}/pending.json`)
          || (await interruptionFile(`${statePath}/state.json`)).sha256 !== confirmedState.sha256
          || (await interruptionFile(`${statePath}/history.jsonl`, false)).sha256 !== confirmedHistory.sha256) reject('operator_interruption_unconfirmed');
      await sameServiceNoCLI(); checkCancelled();
      report.operatorInterruptionProof.repeatedRecoveryIdempotent = true;
      goodOriginRevision = recovery.revision;
    } catch (error) { primary = error; }
    finally {
      let operatorAbsent = false, holdClosed = false, ownedChallengeClosed = false;
      try {
        if (ownedChallenge) {
          if (await ownedChallenge.abort() !== true) reject('operator_interruption_unconfirmed');
          ownedChallengeClosed = true; report.operatorNativeChallengeProof.ownedChallengeClosed = true;
        }
      } catch (error) { failures.cleanup(error, 'operator_close'); if (!primary) primary = error; }
      try { if (operator) { if (await operator.close() !== true) reject('operator_interruption_unconfirmed'); operatorAbsent = true; } } catch (error) { failures.cleanup(error, 'operator_close'); if (!primary) primary = error; }
      try { if (held) { if (await held.abort() !== true) reject('operator_interruption_unconfirmed'); holdClosed = !ownedChallenge || ownedChallengeClosed; } } catch (error) { failures.cleanup(error, 'operator_close'); if (!primary) primary = error; }
      if (primary && operator && snapshot && !normalRetirementAttempted) {
        const containment = report.operatorInterruptionContainment;
        containment.attempted = true; containment.operatorAbsent = operatorAbsent; containment.holdClosed = holdClosed;
        containment.disposition = 'refused';
        try {
          if (!operatorAbsent || !holdClosed) reject('operator_interruption_unconfirmed');
          checkCancelled(); await unchangedPending(snapshot); await sameServiceNoCLI(); checkCancelled();
          containment.snapshotRevalidated = true;
          const retired = await operator.retireCapturedLocksAfterFailure(); checkCancelled();
          if (!retired || retired.ok !== true || retired.alphaRemoved !== true || retired.controllerRemoved !== true || retired.pendingPreserved !== true) reject('operator_interruption_unconfirmed');
          containment.locksRetired = true;
          await unchangedPending(snapshot); await sameServiceNoCLI(); checkCancelled();
          // This permit is synchronous after every awaited state/runtime check.
          // It retains the original capture deadline and cancellation policy.
          if (operator.assertCleanupAuthority() !== true) reject('operator_interruption_unconfirmed');
          const recovered = await command(node, [launcher, 'recover'], env); checkCancelled();
          const result = assessInterruptedRecovery(recovered, previousRevision, snapshot.failedRevision);
          const status = await cli(node, launcher, ['status'], env); checkCancelled();
          const restored = await interruptionFile(`${statePath}/revisions/${result.revision}.json`), { recordSha256, ...revision } = restored.value;
          if (recordSha256 !== digest(JSON.stringify(revision)) || restored.value.id !== result.revision
              || restored.value.parent !== previousRevision || restored.value.sourceRevision !== previousRevision
              || restored.value.inputSha256 !== previous.value.inputSha256 || JSON.stringify(restored.value.input) !== JSON.stringify(previous.value.input)
              || !await absent(`${statePath}/pending.json`) || status.pending !== null || status.lastConfirmedRevision !== result.revision
              || JSON.stringify(status.binding) !== JSON.stringify(originalState.value.binding) || status.runtime?.identityValid !== true
              || status.configUnchanged !== true || status.fragmentMatchesLastConfirmed !== true || status.history?.integrity !== true) reject('operator_interruption_unconfirmed');
          const body = await request(gatewayPort); checkCancelled();
          const secure = await probeServiceTLS(tlsPort, '/', { ca: tlsFixture.ca, expectedCertificate: tlsFixture.expectedCertificate, servername: 'localhost', version: 'TLSv1.3' }); checkCancelled();
          if (body.status !== 200 || body.body.toString() !== 'service-fixture\n' || secure.status !== 200 || secure.certificateMatched !== true
              || secure.protocol !== 'TLSv1.3' || !Buffer.isBuffer(secure.body) || secure.body.toString() !== 'service-fixture\n'
              || !Number.isInteger(beforePosts) || origin.counts().echoRequests !== beforePosts) reject('operator_interruption_unconfirmed');
          await sameServiceNoCLI(); checkCancelled();
          const beforeRepeatState = await interruptionFile(`${statePath}/state.json`), beforeRepeatHistory = await interruptionFile(`${statePath}/history.jsonl`, false);
          checkCancelled(); if (operator.assertCleanupAuthority() !== true) reject('operator_interruption_unconfirmed');
          const repeated = await cli(node, launcher, ['recover'], env); checkCancelled();
          if (repeated.outcome !== 'nothing_pending' || !await absent(`${statePath}/pending.json`)
              || (await interruptionFile(`${statePath}/state.json`)).sha256 !== beforeRepeatState.sha256
              || (await interruptionFile(`${statePath}/history.jsonl`, false)).sha256 !== beforeRepeatHistory.sha256) reject('operator_interruption_unconfirmed');
          await sameServiceNoCLI(); checkCancelled();
          containment.recoveryVerified = true; containment.completed = true; containment.disposition = 'contained';
          // Acceptance proofs/counter and primary are intentionally unchanged.
        } catch (error) { failures.cleanup(error, 'operator_recovery'); }
      } else if (primary) report.operatorInterruptionContainment.disposition = normalRetirementAttempted ? 'retirement_already_started' : 'no_snapshot';
      try { report.operatorNativeChallengeAdmission = sanitizeNativeChallengeAdmission(held?.admissionDiagnostics()); }
      catch { report.operatorNativeChallengeAdmission = null; }
    }
    if (primary) throw primary;
    checkCancelled();
    if (Object.values(report.operatorInterruptionProof).some(value => value !== true)
        || Object.values(report.operatorNativeChallengeProof).some(value => value !== true)) reject('operator_interruption_unconfirmed');
    report.operatorNativeChallengeChecks++; report.operatorInterruptionChecks++;
  }
  async function verifyControlledSlowDrain() {
    checkCancelled();
    if (!origin || !tlsFixture || !report.upstreamTLSActivated || !report.downstreamTLSActivated) reject('controlled_drain_unconfirmed');
    const known = sessions.find(session => session.id === lastSession);
    if (!known) reject('controlled_drain_unconfirmed');
    const before = await currentOriginAuthority(known); checkCancelled();
    let held, client, stopping, stopSettled = false, primary = null;
    try {
      held = origin.prepareDrain();
      if (!held || typeof held.path !== 'string' || !/^\/slow-stream\/[a-f0-9]{32}$/.test(held.path)
          || held.prefixBytes !== 4096 || held.totalBytes !== 65537) reject('controlled_drain_unconfirmed');
      checkCancelled();
      client = await createPausedTLSClient(tlsPort, held.path, { ca: tlsFixture.ca,
        expectedCertificate: tlsFixture.expectedCertificate, servername: 'localhost', version: 'TLSv1.3',
        expectedBody: Buffer.alloc(65537, 0x62), prefixBytes: 4096 });
      checkCancelled();
      assessControlledDrainHold(client.snapshot(), held.snapshot(), stopSettled);
      const fresh = await currentOriginAuthority(known); checkCancelled();
      if (fresh.id !== before.id || !sameLauncher(fresh.launcher, before.launcher)) reject('unit_invocation_changed');
      assessControlledDrainHold(client.snapshot(), held.snapshot(), stopSettled);
      report.controlledSlowDrainProof.clientPaused = true; report.controlledSlowDrainProof.originResponseHeld = true;
      report.controlledSlowDrainProof.sameSessionObserved = true;
      checkCancelled();
      // Exactly one normal owned manager-stop task. Both fulfillment and rejection
      // are observed immediately; finally always awaits its terminal outcome.
      stopping = stopOwned().then(() => { stopSettled = true; return { ok: true }; }, error => { stopSettled = true; return { ok: false, error }; });
      const end = performance.now() + 1000;
      await until(async () => {
        checkCancelled(); assessControlledDrainHold(client.snapshot(), held.snapshot(), stopSettled);
        const p = await ownedProperties(false); checkCancelled();
        if (performance.now() >= end) reject('controlled_drain_unconfirmed');
        if (p.ActiveState === 'active') return false;
        if (p.ActiveState !== 'deactivating' || p.MainPID !== String(before.launcher.pid)) reject('controlled_drain_unconfirmed');
        const identity = await launcherIdentity(p); checkCancelled();
        if (!sameLauncher(identity, before.launcher)) reject('unit_launcher_identity');
        const query = await systemctl(['show', unitName, '--property=InvocationID'], 2500); checkCancelled();
        if (!query.ok || query.stderr !== '' || parseInvocationProperty(query.stdout) !== before.id) reject('unit_invocation_changed');
        if ((await remainingNativeGroup(`${prefix}/bin/nginx`, known.identity)).length < 1) reject('controlled_drain_unconfirmed');
        checkCancelled();
        const after = await ownedProperties(false); checkCancelled();
        if (after.ActiveState !== 'deactivating' || after.MainPID !== String(before.launcher.pid)
            || !sameLauncher(await launcherIdentity(after), before.launcher)) reject('unit_launcher_identity');
        if ((await remainingNativeGroup(`${prefix}/bin/nginx`, known.identity)).length < 1) reject('controlled_drain_unconfirmed');
        checkCancelled(); assessControlledDrainHold(client.snapshot(), held.snapshot(), stopSettled);
        if (performance.now() >= end) reject('controlled_drain_unconfirmed');
        return true;
      }, 1000);
      checkCancelled(); assessControlledDrainHold(client.snapshot(), held.snapshot(), stopSettled);
      report.controlledSlowDrainProof.managerStopPending = true; report.controlledSlowDrainProof.nativeGroupLiveDuringStop = true;
      report.controlledSlowDrainProof.unitDeactivatingObserved = true; report.controlledSlowDrainProof.incompleteResponseObserved = true;
      checkCancelled();
      if (performance.now() >= end) reject('controlled_drain_unconfirmed');
      if (held.release() !== true) reject('controlled_drain_unconfirmed');
      const completed = await client.resume(); checkCancelled(); assessControlledDrainResult(completed);
      report.controlledSlowDrainProof.payloadCompleted = true; report.controlledSlowDrainProof.tlsVerified = true;
      const stopped = await stopping; checkCancelled();
      if (!stopped.ok) throw stopped.error;
      if (!await exitedLauncher(before.launcher) || !await nativeStopped(known)) reject('controlled_drain_unconfirmed');
      checkCancelled();
      if (!report.cleanup.managerStopped || !report.cleanup.launcherExited || !report.cleanup.nativeGroupsAbsent
          || !report.cleanup.listeningPortsClosed || !report.cleanup.controlSocketAbsent || !report.cleanup.downstreamTLSPortClosed
          || !await absent(`${prefix}/control.sock`) || !await closedPort(gatewayPort) || !await closedPort(healthPort)
          || !await closedPort(tlsPort)) reject('controlled_drain_unconfirmed');
      checkCancelled();
      report.controlledSlowDrainProof.managerStopCompleted = true; report.controlledSlowDrainProof.launcherExited = true;
      report.controlledSlowDrainProof.nativeGroupsAbsent = true; report.controlledSlowDrainProof.listeningPortsClosed = true;
      report.controlledSlowDrainProof.controlSocketAbsent = true;
    } catch (error) { primary = error; }
    finally {
      // Cancel only the captured request/response handles. No new unit stop or
      // direct signal is issued here; preserve the first failure and await all tasks.
      try { if (held && await held.abort() !== true) reject('controlled_drain_unconfirmed'); } catch (error) { failures.cleanup(error, 'drain_close'); if (!primary) primary = error; }
      try { if (client && await client.cancel() !== true) reject('controlled_drain_unconfirmed'); } catch (error) { failures.cleanup(error, 'drain_close'); if (!primary) primary = error; }
      if (stopping) { const stopped = await stopping; if (!stopped.ok) { failures.cleanup(stopped.error, 'drain_close'); if (!primary) primary = stopped.error; } }
    }
    if (primary) throw primary;
    checkCancelled();
    if (Object.values(report.controlledSlowDrainProof).some(value => value !== true)) reject('controlled_drain_unconfirmed');
    report.controlledSlowDrainChecks++;
  }
  async function prepareOwnedRuntimeUnit() {
    checkCancelled();
    report.nodePrerequisites = await observeNodePrerequisites(prefix, node);
    const recipeCommand = await command(node, [launcher, 'service-unit', '--auto-readiness'], env); checkCancelled();
    const unit = assessInstalledServiceRecipeCommand(recipeCommand, prefix, node);
    report.installSchemaVersion = 2; report.installedRecipeGenerated = true;
    unitName = fixtureUnitName(randomBytes(16).toString('hex')); unitFile = `${parent}/${unitName}`;
    runtimeLink = `${env.XDG_RUNTIME_DIR}/systemd/user/${unitName}`;
    await runtimeParents();
    if (!await absent(runtimeLink)) reject('unit_collision');
    const prior = await properties(); if (prior.LoadState !== 'not-found' || prior.ActiveState !== 'inactive' || prior.MainPID !== '0' || prior.FragmentPath !== '') reject('unit_collision');
    report.unitSha256 = digest(unit); report.readinessAutomated = true;
    const handle = await open(unitFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(unit); await handle.sync(); } finally { await handle.close(); }
    checkCancelled();
    const linkResult = await systemctl(['--runtime', 'link', unitFile]);
    linked = !await absent(runtimeLink);
    if (!linkResult.ok) reject('unit_link_failed'); await linkAuthority(); linked = true; report.runtimeUnitLinked = true;
  }
  // This retires only the current, freshly checked unit after every captured
  // launcher/native group and listener is absent. Never reinterpret old sessions
  // using a new prefix: inventory is reset only after this complete retirement.
  async function retireStoppedRuntimeUnit() {
    const before = await ownedProperties(false);
    if (before.ActiveState !== 'inactive' || before.MainPID !== '0' || before.Result !== 'success') reject('unit_stop_unconfirmed');
    for (const identity of launcherIdentities) if (!await exitedLauncher(identity)) reject('native_cleanup_unknown');
    for (const session of sessions) if (!await nativeStopped(session)) reject('native_cleanup_unknown');
    if (!await closedPort(gatewayPort) || !await closedPort(healthPort) || !await absent(`${prefix}/control.sock`)) reject('service_resources_live');
    await linkAuthority(); checkCancelled(); await rm(runtimeLink);
    report.cleanup.runtimeLinkAbsent = await absent(runtimeLink);
    const reload = await systemctl(['daemon-reload']); if (!reload.ok) reject('unit_reload_failed');
    const after = await properties();
    if (after.LoadState !== 'not-found' || after.ActiveState !== 'inactive' || after.MainPID !== '0') reject('unit_removal_unconfirmed');
    linked = false; report.runtimeUnitRemoved = true;
    checkCancelled();
  }
  // Restored managed HTTP acceptance.
  async function restoreConfirmedHTTPService() {
    checkCancelled();
    const beforeEchoes = appEchoRequests;
    await stopOwned(); report.nativeSessionsStopped++; checkCancelled();
    if (appEchoRequests !== beforeEchoes) reject('restored_http_unconfirmed');
    const sourceManifest = await checkedRecord(`${prefix}/.alpha-install.json`);
    const sourceRegistry = await checkedRecord(`${prefix}/.alpha-registry.json`);
    if (typeof sourceRegistry.current !== 'string' || !TOKEN.test(sourceRegistry.current)) reject('restored_http_unconfirmed');
    const currentPrefix = `${prefix}/runs/${sourceRegistry.current}`;
    const life = await checkedRecord(`${currentPrefix}/lifecycle.json`);
    const status = await cli(node, launcher, ['status'], env);
    if (life.stage !== 'stopped' || life.session !== lastSession || sourceRegistry.current !== lastSession
        || life.installationId !== sourceManifest.installationId || status.pending !== null
        || status.configUnchanged !== true || status.fragmentMatchesLastConfirmed !== true || status.history?.integrity !== true
        || !TOKEN.test(status.lastConfirmedRevision || '')) reject('restored_http_unconfirmed');
    const revisionPath = `${currentPrefix}/.x10-control/revisions/${status.lastConfirmedRevision}.json`;
    const revisionRecord = await interruptionFile(revisionPath), revision = revisionRecord.value;
    const { recordSha256, ...revisionBody } = revision;
    if (recordSha256 !== digest(JSON.stringify(revisionBody)) || revision.id !== status.lastConfirmedRevision
        || revision.inputSha256 !== digest(JSON.stringify(revision.input))) reject('restored_http_unconfirmed');
    const source = { installationId: sourceManifest.installationId, session: sourceRegistry.current, revision: revision.id,
      input: revision.input, inputSha256: revision.inputSha256, port: sourceManifest.port, healthPort: sourceManifest.healthPort };
    const files = [`${prefix}/.alpha-install.json`, `${prefix}/.alpha-registry.json`, `${currentPrefix}/lifecycle.json`,
      `${currentPrefix}/.x10-control/state.json`, `${currentPrefix}/.x10-control/history.jsonl`, revisionPath];
    const records = await Promise.all(files.map(file => interruptionFile(file, false)));
    const backupFile = `${parent}/confirmed-http-backup.json`;
    retainedHTTPSource = { prefix, launcher, files, records, backupFile, backupBytes: null, expectedAppEchoRequests: beforeEchoes + 2, removed: false };
    report.restoredHTTPProof.stoppedConfirmedSource = true;
    checkCancelled();
    const backedUp = await cli(node, launcher, ['backup', '--output', backupFile], env);
    const backupRecord = await interruptionFile(backupFile), backup = backupRecord.value;
    if (backedUp.outcome !== 'declarative_backup_created' || backedUp.nativeStarted !== false
        || backedUp.serviceAccepted !== false || backedUp.productionAccepted !== false
        || backedUp.sha256 !== digest(backupRecord.bytes) || ((await lstat(backupFile)).mode & 0o7777) !== 0o600) reject('restored_http_unconfirmed');
    retainedHTTPSource.backupBytes = backupRecord.bytes; report.restoredHTTPProof.privateBackupCreated = true; checkCancelled();
    const oldUnit = unitName;
    await retireStoppedRuntimeUnit(); report.restoredHTTPProof.sourceUnitRemoved = true; checkCancelled();
    // No remaining source launcher/group/unit can be mistaken for this new one.
    sessions.length = 0; launcherIdentities.length = 0; startRequested = false; failedStartup = null;
    runtimeLink = undefined; unitFile = undefined; unitName = undefined; installed = false;
    prefix = `${parent}/restored-http`; launcher = `${prefix}/bin/x10`;
    checkCancelled();
    const restored = await cli(node, `${parent}/nginx-x10-alpha/install.mjs`, ['install', '--prefix', prefix, '--restore', backupFile], env);
    installed = true; checkCancelled();
    if (typeof restored.session !== 'string' || !TOKEN.test(restored.session) || typeof restored.revision !== 'string' || !TOKEN.test(restored.revision)
        || restored.declarativeRestored !== true || ['nativeStarted', 'readinessChecked', 'serviceAccepted', 'productionAccepted'].some(key => restored[key] !== false)) reject('restored_http_unconfirmed');
    const manifest = await checkedRecord(`${prefix}/.alpha-install.json`), registry = await checkedRecord(`${prefix}/.alpha-registry.json`);
    if (typeof registry.current !== 'string' || !TOKEN.test(registry.current)) reject('restored_http_unconfirmed');
    const sessionPrefix = `${prefix}/runs/${registry.current}`;
    const restoredLife = await checkedRecord(`${sessionPrefix}/lifecycle.json`);
    const restoredRevision = (await interruptionFile(`${sessionPrefix}/.x10-control/revisions/${restored.revision}.json`)).value;
    const { recordSha256: restoredHash, ...restoredBody } = restoredRevision;
    if (restoredHash !== digest(JSON.stringify(restoredBody))) reject('restored_http_unconfirmed');
    const prepared = await cli(node, launcher, ['status'], env), history = await cli(node, launcher, ['history'], env);
    const preparation = assessRestoredHTTPPreparation(source, backup, { prefix, manifest, registry, lifecycle: restoredLife,
      revision: restoredRevision, status: prepared, history });
    if (restored.session !== registry.current || restored.revision !== prepared.lastConfirmedRevision
        || !await closedPort(gatewayPort) || !await closedPort(healthPort) || appEchoRequests !== beforeEchoes) reject('restored_http_unconfirmed');
    Object.assign(report.restoredHTTPProof, preparation);
    report.runtimeUnitRemoved = false; report.cleanup.runtimeLinkAbsent = false;
    await prepareOwnedRuntimeUnit();
    if (unitName === oldUnit) reject('restored_http_unconfirmed'); report.restoredHTTPProof.freshUnit = true;
    report.phase = 'first_start'; await startAndServe(); await verifyJournalForInvocation(await ownedInvocation());
    if (lastSession !== restored.session || appEchoRequests !== beforeEchoes + 1) reject('restored_http_unconfirmed');
    const served = await cli(node, launcher, ['status'], env);
    const running = sessions.find(session => session.id === lastSession);
    if (!running || served.lastConfirmedRevision !== restored.revision || served.runtime?.observedRevision !== restored.revision
        || served.runtime?.identityValid !== true || !served.binding || served.pending !== null) reject('restored_http_unconfirmed');
    report.restoredHTTPProof.restoredHTTPServed = true;
    report.phase = 'manager_restart'; await restartAndServe();
    if (appEchoRequests !== beforeEchoes + 2 || lastSession === restored.session) reject('restored_http_unconfirmed');
    const restarted = await cli(node, launcher, ['status'], env);
    if (typeof restarted.lastConfirmedRevision !== 'string' || !TOKEN.test(restarted.lastConfirmedRevision)) reject('restored_http_unconfirmed');
    const restartedRevision = (await interruptionFile(`${prefix}/runs/${lastSession}/.x10-control/revisions/${restarted.lastConfirmedRevision}.json`)).value;
    const { recordSha256: restartedHash, ...restartedBody } = restartedRevision;
    if (restartedHash !== digest(JSON.stringify(restartedBody)) || JSON.stringify(restartedRevision.input) !== JSON.stringify(source.input) || restartedRevision.inputSha256 !== source.inputSha256
        || restarted.runtime?.identityValid !== true || !restarted.binding || restarted.pending !== null) reject('restored_http_unconfirmed');
    report.restoredHTTPProof.restoredHTTPRestarted = true;
  }
  async function verifyRetainedHTTPSource() {
    if (!retainedHTTPSource || !retainedHTTPSource.backupBytes || retainedHTTPSource.removed
        || appEchoRequests !== retainedHTTPSource.expectedAppEchoRequests) reject('restored_http_unconfirmed');
    for (let index = 0; index < retainedHTTPSource.files.length; index++) {
      const current = await interruptionFile(retainedHTTPSource.files[index], false);
      if (!current.bytes.equals(retainedHTTPSource.records[index].bytes)) reject('restored_http_unconfirmed');
    }
    if (!(await interruptionFile(retainedHTTPSource.backupFile, false)).bytes.equals(retainedHTTPSource.backupBytes)
        || digest(await archiveBytes(input.archive)) !== input.sha256) reject('restored_http_unconfirmed');
    report.restoredHTTPProof.sourceRecordsPreserved = true;
    report.restoredHTTPProof.backupPreserved = true; report.restoredHTTPProof.archivePreserved = true;
  }
  // End restored managed HTTP acceptance.
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  try {
    input = parseArguments(argv); report.phase = 'preflight';
    const prerequisite = await preflight();
    if (!prerequisite.ok || prerequisite.managerAvailable !== true) reject(prerequisite.code || 'manager_unavailable');
    report.actualNonrootManagerObserved = true; env = managerEnvironment(process.getuid());
    report.phase = 'archive'; const capturedArchive = await archiveBytes(input.archive), verified = verifyAlphaArchive(capturedArchive, input.sha256);
    if (!verified.valid || verified.schemaVersion !== 2) reject('archive_refused');
    report.bundleSchemaVersion = verified.schemaVersion;
    report.archiveSha256 = verified.archiveSha256; report.binarySha256 = verified.binarySha256; report.sourceCommit = verified.sourceCommit;
    checkCancelled(); parent = await mkdtemp(path.join(os.tmpdir(), 'x10-service-')); await chmod(parent, 0o700);
    prefix = `${parent}/install`; node = await realpath(process.execPath); launcher = `${prefix}/bin/x10`;
    const archiveCopy = `${parent}/verified.tar.gz`, archiveHandle = await open(archiveCopy, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await archiveHandle.writeFile(capturedArchive); await archiveHandle.sync(); } finally { await archiveHandle.close(); }
    const unpack = await command('/usr/bin/tar', ['-xzf', archiveCopy, '-C', parent], env);
    if (!unpack.ok) reject('archive_extract_failed');
    app = http.createServer((req, res) => {
      if (req.url === '/ready') {
        if (readinessBlocked && readinessCaptureDone) { res.once('finish', () => { if (!res.destroyed) readinessRefusals++; }); res.writeHead(503); res.end('not-ready\n'); }
        else if (readinessBlocked) { if (heldReadiness.size >= 8) { req.destroy(); return; } heldReadiness.add(res); res.once('close', () => heldReadiness.delete(res)); }
        else res.end('ready\n'); return;
      }
      if (req.url === '/stream') { res.write(Buffer.alloc(32768, 0x62)); res.end(Buffer.alloc(32769, 0x62)); return; }
      if (req.url === '/echo') { const chunks = []; let size = 0; req.on('data', b => { size += b.length; if (size > 1024 * 1024) req.destroy(); else chunks.push(b); }); req.on('end', () => { if (req.method === 'POST') appEchoRequests++; res.end(Buffer.concat(chunks)); }); return; }
      res.end('service-fixture\n');
    });
    app.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    appPort = await listen(app); gatewayPort = await unusedPort(); do { healthPort = await unusedPort(); } while (healthPort === gatewayPort || healthPort === appPort);
    report.phase = 'install';
    await cli(node, `${parent}/nginx-x10-alpha/install.mjs`, ['install', '--prefix', prefix, '--port', String(gatewayPort), '--health-port', String(healthPort), '--upstream-port', String(appPort)], env); installed = true;
    report.phase = 'recipe_inspection';
    report.nodePrerequisites = await observeNodePrerequisites(prefix, node);
    const recipeCommand = await command(node, [launcher, 'service-unit', '--auto-readiness'], env); checkCancelled();
    const unit = assessInstalledServiceRecipeCommand(recipeCommand, prefix, node);
    report.installSchemaVersion = 2; report.installedRecipeGenerated = true;
    report.phase = 'unit_preparation';
    const token = randomBytes(16).toString('hex'); unitName = fixtureUnitName(token); unitFile = `${parent}/${unitName}`;
    runtimeLink = `${env.XDG_RUNTIME_DIR}/systemd/user/${unitName}`;
    await runtimeParents();
    if (!await absent(runtimeLink)) reject('unit_collision');
    const prior = await properties(); if (prior.LoadState !== 'not-found' || prior.ActiveState !== 'inactive' || prior.MainPID !== '0' || prior.FragmentPath !== '') reject('unit_collision');
    report.unitSha256 = digest(unit); report.readinessAutomated = true;
    const handle = await open(unitFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(unit); await handle.sync(); } finally { await handle.close(); }
    report.phase = 'link';
    const linkResult = await systemctl(['--runtime', 'link', unitFile]);
    linked = !await absent(runtimeLink);
    if (!linkResult.ok) reject('unit_link_failed'); await linkAuthority(); linked = true; report.runtimeUnitLinked = true;
    report.phase = 'failed_start'; await verifyFailedReadinessStart();
    report.phase = 'first_start'; await startAndServe(); await verifyJournalForInvocation(await ownedInvocation());
    report.phase = 'restore_http'; await restoreConfirmedHTTPService();
    report.phase = 'tls_apply'; await activateDownstreamTLS();
    report.phase = 'first_stop'; await stopOwned(); report.nativeSessionsStopped++;
    report.phase = 'second_start'; await startAndServe();
    report.phase = 'manager_restart'; await restartAndServe();
    report.phase = 'operator_interruption'; await verifyOperatorInterruption();
    report.phase = 'controlled_drain'; await verifyControlledSlowDrain(); report.nativeSessionsStopped++;
    if (report.operatorInterruptionChecks !== 1 || report.operatorNativeChallengeChecks !== 1) reject('operator_interruption_unconfirmed');
    if (report.controlledSlowDrainChecks !== 1) reject('controlled_drain_unconfirmed');
    if (report.failedStartChecks !== 1 || Object.values(report.failedStartProof).some(value => value !== true)) reject('failed_start_unconfirmed');
    if (report.downstreamTLSSessionChecks !== 3) reject('downstream_tls_unconfirmed');
    if (report.upstreamTLSSessionChecks !== 3 || report.upstreamTLSRollbackChecks !== 3) reject('upstream_tls_unconfirmed');
    report.phase = 'uninstall'; await cli(node, launcher, ['uninstall'], env); installed = false;
    if (!await absent(prefix)) reject('uninstall_incomplete'); report.cleanup.installationRemoved = true;
    report.phase = 'restore_http'; await verifyRetainedHTTPSource();
    await cli(node, retainedHTTPSource.launcher, ['uninstall'], env);
    if (!await absent(retainedHTTPSource.prefix)) reject('uninstall_incomplete');
    retainedHTTPSource.removed = true; report.restoredHTTPProof.sourceInstallationRemoved = true;
    if (appEchoRequests !== retainedHTTPSource.expectedAppEchoRequests) reject('restored_http_unconfirmed');
    report.restoredHTTPProof.noPostReplay = true;
    if (Object.values(report.restoredHTTPProof).some(value => value !== true)) reject('restored_http_unconfirmed');
    report.restoredHTTPChecks++; checkCancelled();
    report.ok = true; report.code = 'basic_lifecycle_verified'; report.phase = 'complete';
  } catch (error) {
    failures.primary(error, report.phase, start.snapshot().lastStep);
    report.ok = false; report.code = classifyLifecycleError(error, report.phase);
  } finally {
    inCleanup = true;
    // No direct signal, force kill, disable-all, enable, linger or account mutation.
    if (linked) {
      try {
        await linkAuthority();
        if (installed) await stopOwned();
        else { const p = await ownedProperties(); if (p.ActiveState !== 'inactive' || p.MainPID !== '0') reject('unit_stop_unconfirmed'); }
        await linkAuthority(); await rm(runtimeLink); report.cleanup.runtimeLinkAbsent = await absent(runtimeLink);
        const reload = await systemctl(['daemon-reload']); if (!reload.ok) reject('unit_reload_failed');
        const p = await properties(); if (p.LoadState !== 'not-found' || p.ActiveState !== 'inactive' || p.MainPID !== '0') reject('unit_removal_unconfirmed');
        report.runtimeUnitRemoved = true;
      } catch (error) { failures.cleanup(error, 'unit_cleanup'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    } else if (runtimeLink) {
      // Ambiguous link completion is never blindly repeated or removed.
      try { if (!await absent(runtimeLink)) { failures.cleanup(null, 'link_readback'); report.ok = false; report.code = 'cleanup_unconfirmed'; } else report.cleanup.runtimeLinkAbsent = true; } catch (error) { failures.cleanup(error, 'link_readback'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    }
    if (installed && !linked && !startRequested) {
      try {
        if (runtimeLink && !await absent(runtimeLink)) reject('unit_link_identity');
        await cli(node, launcher, ['uninstall'], env); installed = false;
        report.cleanup.installationRemoved = await absent(prefix);
      } catch (error) { failures.cleanup(error, 'inert_uninstall'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    }
    if (app) {
      let closed = false, closeError;
      try { for (const socket of sockets) socket.destroy();
        closed = await new Promise(resolve => { const timer = setTimeout(() => resolve(false), 2000); app.close(error => { clearTimeout(timer); resolve(!error); }); }); await pause(20);
      } catch (error) { closeError = error; }
      if (!closed) { failures.cleanup(closeError, 'app_close'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    }
    if (origin) {
      report.cleanup.upstreamTLSPortClosed = false; report.cleanup.readinessRelayPortClosed = false;
      report.cleanup.upstreamTLSOriginClosed = false; report.cleanup.readinessRelayClosed = false;
      originCleanupSafe = false;
      try {
        const closed = await origin.close();
        if (!closed || closed.originClosed !== true || closed.relayClosed !== true
            || closed.originPortClosed !== true || closed.relayPortClosed !== true
            || !await closedPort(origin.port) || !await closedPort(origin.readyPort)) reject('service_resources_live');
        report.cleanup.upstreamTLSPortClosed = true; report.cleanup.readinessRelayPortClosed = true;
        report.cleanup.upstreamTLSOriginClosed = true; report.cleanup.readinessRelayClosed = true;
        originCleanupSafe = true;
      } catch (error) { failures.cleanup(error, 'origin_close'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    } else if (originCreationRequested) {
      failures.cleanup(null, 'origin_close'); report.ok = false; report.code = 'cleanup_unconfirmed';
    }
    report.cleanup.appSocketsRemaining = sockets.size;
    safeToRemove = Boolean(parent && !installed && (!retainedHTTPSource || retainedHTTPSource.removed) && (!linked || report.runtimeUnitRemoved) && sockets.size === 0 && originCleanupSafe);
    if (safeToRemove) { try { await rm(parent, { recursive: true, force: true }); report.cleanup.temporaryRootRemoved = await absent(parent); } catch (error) { failures.cleanup(error, 'temporary_root'); report.ok = false; report.code = 'cleanup_unconfirmed'; } }
    if (report.ok && (!report.cleanup.temporaryRootRemoved || !report.runtimeUnitRemoved || !report.cleanup.downstreamTLSPortClosed || !report.cleanup.upstreamTLSPortClosed || !report.cleanup.readinessRelayPortClosed
        || !report.cleanup.upstreamTLSOriginClosed || !report.cleanup.readinessRelayClosed || sockets.size)) { failures.cleanup(null, 'final_assertion'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  }
  return { ...report, ...failures.snapshot(), operatorHoldDiagnostics: operatorHoldDiagnostics.snapshot(), startDiagnostics: start.snapshot(), fragmentIdentityDiagnostics: fragments.snapshot(), hookStatusDiagnostics: hooks.snapshot() };
}
let invoked = false;
try { invoked = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* Import has no mutation authority. */ }
if (invoked) { const result = await main(); process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.ok ? 0 : 1; }
