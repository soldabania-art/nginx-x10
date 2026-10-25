#!/usr/bin/env node
// Actual ephemeral user-service verification. Never enables a persistent unit.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { chmod, lstat, mkdtemp, open, readFile, readlink, realpath, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { preflight } from './preflight.mjs';
import { inspectInstallation, renderUserUnit } from './user-unit.mjs';
import { verifyAlphaArchive, MAX_ARCHIVE_BYTES } from '../release/verify-alpha-archive.mjs';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';

const execute = promisify(execFile), TOOL = '/usr/bin/systemctl';
const HEX = /^[a-f0-9]{64}$/, TOKEN = /^[a-f0-9]{32}$/;
const KEYS = ['LoadState', 'ActiveState', 'SubState', 'Result', 'FragmentPath', 'MainPID', 'ControlGroup'];
const ERROR_CODES = new Set(["archive_extract_failed", "archive_refused", "binding_unconfirmed", "cancelled", "installed_command_failed", "installed_response_invalid", "lifecycle_identity", "linux_required", "local_manager_prerequisites_unavailable", "manager_query_failed", "manager_response_invalid", "manager_unavailable", "native_cleanup_unknown", "native_identity", "nonroot_required", "observation_timeout", "proxy_body_mismatch", "query_invalid", "query_output_limit", "query_timeout", "recipe_diagnostic_failed", "service_resources_live", "session_identity", "session_reused", "stream_mismatch", "uid_mismatch", "uninstall_incomplete", "unit_cgroup_identity", "unit_collision", "unit_directory_identity", "unit_file_identity", "unit_fragment_identity", "unit_launcher_identity", "unit_link_failed", "unit_link_identity", "unit_name_invalid", "unit_not_active", "unit_not_stopped", "unit_query_failed", "unit_reload_failed", "unit_removal_unconfirmed", "unit_response_invalid", "unit_start_failed", "unit_stop_unconfirmed", "upload_mismatch", "usage_invalid"]);
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
    if (!HEX.test(sha256 || '') || digest(JSON.stringify(record)) !== sha256 || record.schemaVersion !== 1
        || record.kind !== 'nginx-x10-local-alpha' || record.prefix !== prefix || !record.nodeRuntime) reject('recipe_diagnostic_failed');
    const node = await lstat(nodeExecutable);
    return assessNodePrerequisites({ regular: node.isFile(), canonical: await realpath(nodeExecutable) === nodeExecutable,
      ownerAllowed: node.uid === 0 || node.uid === process.getuid(), mode: node.mode & 0o7777,
      recordedPathMatches: record.nodeRuntime.executable === nodeExecutable, recordedVersion: record.nodeRuntime.version });
  } catch { reject('recipe_diagnostic_failed'); }
  finally { if (handle) { try { await handle.close(); } catch { reject('recipe_diagnostic_failed'); } } }
}
// Diagnostic collectors have no I/O or lifecycle authority.
export const DIAGNOSTIC_PHASES = Object.freeze(['arguments', 'preflight', 'archive', 'install', 'recipe_inspection', 'unit_preparation', 'link', 'first_start', 'first_stop', 'second_start', 'second_stop', 'uninstall', 'complete', 'unknown']);
export const START_SUBPHASES = Object.freeze(['not_started', 'not_applicable', 'cancel_check', 'before_properties', 'request_start', 'after_properties', 'launcher_identity', 'native_inventory', 'wait_bind', 'native_observation', 'session_freshness', 'binding_status', 'proxy_body', 'upload', 'stream', 'final_cancel_check', 'complete', 'unknown']);
export const CLEANUP_STAGES = Object.freeze(['unit_cleanup', 'link_readback', 'inert_uninstall', 'app_close', 'temporary_root', 'final_assertion', 'unknown']);
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
      primary = { phase: safePhase, subphase: ['first_start', 'second_start'].includes(safePhase)
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
        : ['first_start', 'second_start'].includes(safePhase) ? pickEnum(subphase, START_SUBPHASES) : 'not_applicable',
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
    nativeSessionsStarted: 0, nativeSessionsStopped: 0, proxyBodyChecks: 0, uploadChecks: 0, streamChecks: 0,
    readinessAutomated: false, runtimeUnitLinked: false, runtimeUnitRemoved: false, unitEnabled: false, subprocessOutputsPublished: false,
    cleanup: { managerStopped: false, launcherExited: false, nativeGroupsAbsent: false,
      listeningPortsClosed: false, controlSocketAbsent: false, runtimeLinkAbsent: false,
      appSocketsRemaining: 0, installationRemoved: false, temporaryRootRemoved: false } };
  let input, parent, prefix, node, launcher, unitFile, runtimeLink, unitName, env, app, appPort, gatewayPort, healthPort;
  let linked = false, installed = false, safeToRemove = false, cancelled = false, startRequested = false, lastSession = null, inCleanup = false;
  const sessions = [], launcherIdentities = [], sockets = new Set();
  const failures = createFailureDiagnostics(), start = createStartDiagnostics(), fragments = createFragmentIdentityDiagnostics(), hooks = createHookStatusDiagnostics();
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
    if (observe && !inCleanup && ['first_start', 'second_start'].includes(report.phase)) start.observe('properties_command', r);
    if (![0, 1].includes(r.exitCode)) reject('unit_query_failed');
    const parsed = parseUnitProperties(r.stdout);
    if (observe && !inCleanup && ['first_start', 'second_start'].includes(report.phase)) start.observe('properties_state', parsed);
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
    report.cleanup.managerStopped = true; report.cleanup.launcherExited = true; report.cleanup.nativeGroupsAbsent = true;
    report.cleanup.listeningPortsClosed = true; report.cleanup.controlSocketAbsent = true;
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
    start.step('launcher_identity');
    launcherIdentities.push(await launcherIdentity(active)); report.actualUnitStarted = true;
    start.step('binding_status');
    const startupStatus = await cli(node, launcher, ['status'], env); if (!startupStatus.binding || startupStatus.runtime?.identityValid !== true) reject('binding_unconfirmed');
    start.step('native_inventory');
    await until(async () => { try { await inventorySessions(); return sessions.length > report.nativeSessionsStopped; } catch (e) { if (e.code === 'native_cleanup_unknown') return false; throw e; } });
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
    start.complete();
  }
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  try {
    input = parseArguments(argv); report.phase = 'preflight';
    const prerequisite = await preflight();
    if (!prerequisite.ok || prerequisite.managerAvailable !== true) reject(prerequisite.code || 'manager_unavailable');
    report.actualNonrootManagerObserved = true; env = managerEnvironment(process.getuid());
    report.phase = 'archive'; const capturedArchive = await archiveBytes(input.archive), verified = verifyAlphaArchive(capturedArchive, input.sha256);
    if (!verified.valid) reject('archive_refused');
    report.archiveSha256 = verified.archiveSha256; report.binarySha256 = verified.binarySha256; report.sourceCommit = verified.sourceCommit;
    checkCancelled(); parent = await mkdtemp(path.join(os.tmpdir(), 'x10-service-')); await chmod(parent, 0o700);
    prefix = `${parent}/install`; node = await realpath(process.execPath); launcher = `${prefix}/bin/x10`;
    const archiveCopy = `${parent}/verified.tar.gz`, archiveHandle = await open(archiveCopy, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await archiveHandle.writeFile(capturedArchive); await archiveHandle.sync(); } finally { await archiveHandle.close(); }
    const unpack = await command('/usr/bin/tar', ['-xzf', archiveCopy, '-C', parent], env);
    if (!unpack.ok) reject('archive_extract_failed');
    app = http.createServer((req, res) => {
      if (req.url === '/ready') { res.end('ready\n'); return; }
      if (req.url === '/stream') { res.write(Buffer.alloc(32768, 0x62)); res.end(Buffer.alloc(32769, 0x62)); return; }
      if (req.url === '/echo') { const chunks = []; let size = 0; req.on('data', b => { size += b.length; if (size > 1024 * 1024) req.destroy(); else chunks.push(b); }); req.on('end', () => res.end(Buffer.concat(chunks))); return; }
      res.end('service-fixture\n');
    });
    app.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    appPort = await listen(app); gatewayPort = await unusedPort(); do { healthPort = await unusedPort(); } while (healthPort === gatewayPort || healthPort === appPort);
    report.phase = 'install';
    await cli(node, `${parent}/nginx-x10-alpha/install.mjs`, ['install', '--prefix', prefix, '--port', String(gatewayPort), '--health-port', String(healthPort), '--upstream-port', String(appPort)], env); installed = true;
    report.phase = 'recipe_inspection';
    report.nodePrerequisites = await observeNodePrerequisites(prefix, node);
    await inspectInstallation({ prefix, nodeExecutable: node });
    report.phase = 'unit_preparation';
    const token = randomBytes(16).toString('hex'); unitName = fixtureUnitName(token); unitFile = `${parent}/${unitName}`;
    runtimeLink = `${env.XDG_RUNTIME_DIR}/systemd/user/${unitName}`;
    await runtimeParents();
    if (!await absent(runtimeLink)) reject('unit_collision');
    const prior = await properties(); if (prior.LoadState !== 'not-found' || prior.ActiveState !== 'inactive' || prior.MainPID !== '0' || prior.FragmentPath !== '') reject('unit_collision');
    const unit = renderUserUnit({ prefix, nodeExecutable: node, autoReadiness: true }); report.unitSha256 = digest(unit); report.readinessAutomated = true;
    const handle = await open(unitFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(unit); await handle.sync(); } finally { await handle.close(); }
    report.phase = 'link';
    const linkResult = await systemctl(['--runtime', 'link', unitFile]);
    linked = !await absent(runtimeLink);
    if (!linkResult.ok) reject('unit_link_failed'); await linkAuthority(); linked = true; report.runtimeUnitLinked = true;
    report.phase = 'first_start'; await startAndServe();
    report.phase = 'first_stop'; await stopOwned(); report.nativeSessionsStopped++;
    report.phase = 'second_start'; await startAndServe();
    report.phase = 'second_stop'; await stopOwned(); report.nativeSessionsStopped++;
    report.phase = 'uninstall'; await cli(node, launcher, ['uninstall'], env); installed = false;
    if (!await absent(prefix)) reject('uninstall_incomplete'); report.cleanup.installationRemoved = true;
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
    report.cleanup.appSocketsRemaining = sockets.size;
    safeToRemove = Boolean(parent && !installed && (!linked || report.runtimeUnitRemoved) && sockets.size === 0);
    if (safeToRemove) { try { await rm(parent, { recursive: true, force: true }); report.cleanup.temporaryRootRemoved = await absent(parent); } catch (error) { failures.cleanup(error, 'temporary_root'); report.ok = false; report.code = 'cleanup_unconfirmed'; } }
    if (report.ok && (!report.cleanup.temporaryRootRemoved || !report.runtimeUnitRemoved || sockets.size)) { failures.cleanup(null, 'final_assertion'); report.ok = false; report.code = 'cleanup_unconfirmed'; }
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  }
  return { ...report, ...failures.snapshot(), startDiagnostics: start.snapshot(), fragmentIdentityDiagnostics: fragments.snapshot(), hookStatusDiagnostics: hooks.snapshot() };
}
let invoked = false;
try { invoked = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* Import has no mutation authority. */ }
if (invoked) { const result = await main(); process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.ok ? 0 : 1; }
