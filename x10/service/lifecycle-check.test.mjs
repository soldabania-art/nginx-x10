import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, mkdir, writeFile, readFile, chmod, symlink, link, rm, realpath, lstat, readlink } from 'node:fs/promises';
import { digest } from '../alpha/runtime.mjs';
import { parseArguments, classifyOperatorHoldDecision, createOperatorHoldDiagnostics, assessInterruptedRecovery, assessInterruptedProbeHold, assessControlledDrainHold, assessControlledDrainResult, parseFailedStartIdentity, assessFailedReadinessStart, assessRejectedOriginApply, fixtureUnitName, parseUnitProperties, parseInvocationProperty, managerEnvironment, LIMITATIONS, assessNodePrerequisites, classifyLifecycleError, createFailureDiagnostics, createStartDiagnostics, summarizeManagerOutcome, summarizeUnitProperties, classifyCommandTermination, classifySystemError, DIAGNOSTIC_PHASES, START_SUBPHASES, CLEANUP_STAGES, summarizeUnitFragmentIdentity, createFragmentIdentityDiagnostics, verifyKnownUnitFragmentPaths, createHookStatusDiagnostics } from './lifecycle-check.mjs';
import { JOURNAL_RESULT_CODES } from './journal-check.mjs';
const run = promisify(execFile), script = fileURLToPath(new URL('./lifecycle-check.mjs', import.meta.url));
const hash = 'a'.repeat(64), token = 'b'.repeat(32);
const transcript = (changes = {}) => Object.entries({ LoadState: 'loaded', ActiveState: 'active', SubState: 'running', Result: 'success',
  FragmentPath: '/tmp/x10-example/x10-lifecycle-test.service', MainPID: '1234',
  ControlGroup: '/user.slice/user-1000.slice/user@1000.service/app.slice/x10-lifecycle-test.service', ...changes }).map(([k, v]) => `${k}=${v}\n`).join('');

test('exact archive CLI accepts absolute and canonical relative paths without adding options', () => {
  assert.deepEqual(parseArguments(['--archive', '/tmp/example.tar.gz', '--sha256', hash]), { archive: '/tmp/example.tar.gz', sha256: hash });
  assert.deepEqual(parseArguments(['--archive', 'x10/.build/example.tar.gz', '--sha256', hash]), { archive: path.resolve('x10/.build/example.tar.gz'), sha256: hash });
});
for (const [name, argv] of Object.entries({ empty: [], reordered: ['--sha256', hash, '--archive', '/tmp/a.tar.gz'],
  extra: ['--archive', '/tmp/a.tar.gz', '--sha256', hash, '--enable'], upperhash: ['--archive', '/tmp/a.tar.gz', '--sha256', hash.toUpperCase()],
  short: ['--archive', '/tmp/a.tar.gz', '--sha256', 'aa'], spaces: ['--archive', '/tmp/a b.tar.gz', '--sha256', hash],
  traversal: ['--archive', '../a.tar.gz', '--sha256', hash], alias: ['--archive', '/tmp/../a.tar.gz', '--sha256', hash],
  extension: ['--archive', '/tmp/a.zip', '--sha256', hash], shell: ['--archive', '/tmp/$(id).tar.gz', '--sha256', hash],
  newline: ['--archive', '/tmp/a\n.tar.gz', '--sha256', hash], percent: ['--archive', '/tmp/a%20.tar.gz', '--sha256', hash] })) {
  test(`CLI refuses ${name}`, () => assert.throws(() => parseArguments(argv), { code: 'usage_invalid' }));
}
test('CLI hash requires a primitive string without coercion', () => {
  for (const value of [Buffer.from(hash), { toString: () => hash }]) assert.throws(() => parseArguments(['--archive', 'a.tar.gz', '--sha256', value]), { code: 'usage_invalid' });
});
test('unit name is a fixed namespace with bounded lowercase random token', () => assert.equal(fixtureUnitName(token), `x10-lifecycle-${token}.service`));
for (const value of ['', 'a'.repeat(31), 'a'.repeat(33), 'A'.repeat(32), '../a', 'x.service', token + '\n']) {
  test(`unit token refusal ${JSON.stringify(value)}`, () => assert.throws(() => fixtureUnitName(value), { code: 'unit_name_invalid' }));
}
test('manager environment always selects fixed current-UID local bus and no inherited variables', () => {
  assert.deepEqual(managerEnvironment(1000), { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', XDG_RUNTIME_DIR: '/run/user/1000', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' });
});
for (const value of [0, -1, 1.5, '1000', NaN, Infinity, 4294967295]) {
  test(`manager UID refusal ${String(value)}`, () => assert.throws(() => managerEnvironment(value), { code: 'nonroot_required' }));
}
test('pure unit transcript parsing does not imply manager or service authority', () => {
  const p = parseUnitProperties(transcript()); assert.equal(p.MainPID, '1234'); assert.equal(Object.getPrototypeOf(p), null);
  for (const key of ['serviceAccepted', 'productionAccepted', 'automaticReadinessAccepted', 'failedStartAccepted', 'slowDrainAccepted', 'orphanRecoveryAccepted', 'tlsServiceAccepted']) assert.equal(LIMITATIONS[key], false);
  assert.equal(Object.isFrozen(LIMITATIONS), true);
});
test('inactive not-found transcript permits absent service properties only as parsed data', () => {
  const p = parseUnitProperties(transcript({ LoadState: 'not-found', ActiveState: 'inactive', SubState: 'dead', Result: '', FragmentPath: '', MainPID: '0', ControlGroup: '' }));
  assert.equal(p.LoadState, 'not-found');
});
for (const [name, value] of Object.entries({ noLF: transcript().slice(0, -1), duplicate: transcript() + 'MainPID=2\n',
  missing: transcript().replace('Result=success\n', ''), unknown: transcript().replace('Result=success\n', 'Other=success\n'),
  crlf: transcript().replaceAll('\n', '\r\n'), nonascii: transcript({ Result: 'succès' }), huge: 'x'.repeat(16385) + '\n',
  pidLeading: transcript({ MainPID: '0123' }), pidNegative: transcript({ MainPID: '-1' }), pidOverflow: transcript({ MainPID: '2147483648' }),
  fragmentAlias: transcript({ FragmentPath: '/tmp/../unit.service' }), fragmentRelative: transcript({ FragmentPath: 'unit.service' }),
  groupForeignSyntax: transcript({ ControlGroup: 'remote:user' }), stateUnknown: transcript({ ActiveState: 'whatever' }), loadUnknown: transcript({ LoadState: 'masked' }) })) {
  test(`unit parser refuses ${name}`, () => assert.throws(() => parseUnitProperties(value), { code: 'unit_response_invalid' }));
}
test('actual CLI usage refusal is fixed JSON and never activates service', async () => {
  await assert.rejects(run(process.execPath, [script, '--bad'], { timeout: 5000, maxBuffer: 16384 }), e => {
    assert.equal(e.code, 1); assert.equal(e.stderr, ''); const r = JSON.parse(e.stdout);
    assert.equal(r.code, 'usage_invalid'); assert.equal(r.phase, 'arguments'); assert.equal(r.actualUnitStarted, false);
    assert.equal(r.runtimeUnitLinked, false); assert.equal(r.serviceAccepted, false);
    assert.deepEqual(r.primaryFailure, { phase: 'arguments', subphase: 'not_applicable', code: 'usage_invalid', systemErrorClass: 'unknown' }); assert.deepEqual(r.cleanupFailures, []); return true;
  });
});
test('actual root CLI refuses before archive read or mutation; nonroot observation is not synthesized', async t => {
  if (process.getuid?.() !== 0) { t.skip('actual root refusal only; real nonroot lifecycle is a separate required CI command'); return; }
  await assert.rejects(run(process.execPath, [script, '--archive', '/absent/safe.tar.gz', '--sha256', hash], { timeout: 5000, maxBuffer: 16384 }), e => {
    assert.equal(e.code, 1); assert.equal(e.stderr, ''); const r = JSON.parse(e.stdout);
    assert.equal(r.code, 'nonroot_required'); assert.equal(r.phase, 'preflight'); assert.equal(r.actualNonrootManagerObserved, false);
    assert.equal(r.actualUnitStarted, false); assert.equal(r.runtimeUnitLinked, false); assert.equal(r.nativeSessionsStarted, 0);
    assert.equal(r.cleanup.temporaryRootRemoved, false); assert.equal(r.serviceAccepted, false);
    assert.deepEqual(r.primaryFailure, { phase: 'preflight', subphase: 'not_applicable', code: 'nonroot_required', systemErrorClass: 'unknown' }); assert.equal(r.startDiagnostics.attempts, 0); return true;
  });
});

const nodeFacts = { regular: true, canonical: true, ownerAllowed: true, mode: 0o755, recordedPathMatches: true, recordedVersion: 'v22.23.3' };
test('node prerequisite assessment emits only seven booleans and never service authority', () => {
  const r = assessNodePrerequisites(nodeFacts);
  assert.equal(Object.keys(r).length, 7); assert(Object.values(r).every(v => v === true));
  assert.equal(Object.hasOwn(r, 'serviceAccepted'), false); assert.equal(Object.hasOwn(r, 'uid'), false); assert.equal(Object.hasOwn(r, 'mode'), false);
});
test('unsafe Node metadata stays diagnostic false without granting authority', () => {
  const r = assessNodePrerequisites({ ...nodeFacts, regular: false, canonical: false, ownerAllowed: false, mode: 0o666, recordedPathMatches: false, recordedVersion: 'v21.9.0' });
  assert(Object.values(r).every(v => v === false)); assert.equal(LIMITATIONS.serviceAccepted, false);
});
for (const [name, value] of Object.entries({ boolCoercion: { ...nodeFacts, ownerAllowed: 1 }, modeString: { ...nodeFacts, mode: '0755' }, modeNegative: { ...nodeFacts, mode: -1 }, modeHuge: { ...nodeFacts, mode: 0o10000 }, modeFraction: { ...nodeFacts, mode: 1.5 }, versionBuffer: { ...nodeFacts, recordedVersion: Buffer.from('v22.23.3') }, versionObject: { ...nodeFacts, recordedVersion: { toString: () => 'v22.23.3' } }, versionHuge: { ...nodeFacts, recordedVersion: 'x'.repeat(129) }, extraUID: { ...nodeFacts, uid: 0 }, extraPath: { ...nodeFacts, executable: '/private/path' }, missing: { regular: true }, array: [], foreignPrototype: Object.assign(Object.create({}), nodeFacts) })) {
  test(`node diagnostic refuses ${name}`, () => assert.throws(() => assessNodePrerequisites(value), { code: 'recipe_diagnostic_failed' }));
}
test('node prerequisite getters are refused without evaluation', () => {
  let called = false; const value = { ...nodeFacts }; Object.defineProperty(value, 'ownerAllowed', { get() { called = true; return true; } });
  assert.throws(() => assessNodePrerequisites(value), { code: 'recipe_diagnostic_failed' }); assert.equal(called, false);
});
test('exact recipe refusal receives a fixed code only at recipe inspection', () => {
  const e = new Error('service_recipe_invalid');
  assert.equal(classifyLifecycleError(e, 'recipe_inspection'), 'recipe_inspection_refused');
  assert.equal(classifyLifecycleError(e, 'install'), 'lifecycle_failed');
  assert.equal(classifyLifecycleError(new TypeError('service_recipe_invalid'), 'recipe_inspection'), 'lifecycle_failed');
  assert.equal(classifyLifecycleError({ message: 'service_recipe_invalid' }, 'recipe_inspection'), 'lifecycle_failed');
});
test('arbitrary messages and accessor codes never reach diagnostics', () => {
  assert.equal(classifyLifecycleError(new Error('/private/path uid=999 pid=999'), 'recipe_inspection'), 'lifecycle_failed');
  assert.equal(classifyLifecycleError(Object.assign(new Error('private'), { code: 'private_runtime_secret_abc' }), 'recipe_inspection'), 'lifecycle_failed');
  assert.equal(classifyLifecycleError(Object.assign(new Error('private'), { code: 'EACCES' }), 'recipe_inspection'), 'lifecycle_failed');
  let called = false; const e = new Error('private'); Object.defineProperty(e, 'code', { get() { called = true; return 'private'; } });
  assert.equal(classifyLifecycleError(e, 'recipe_inspection'), 'lifecycle_failed'); assert.equal(called, false);
  assert.equal(classifyLifecycleError(Object.assign(new Error('private'), { code: 'unit_query_failed' }), 'unit_preparation'), 'unit_query_failed');
});

test('primary refusal survives multiple independent cleanup failures with unchanged final refusal', () => {
  const primary = Object.assign(new Error('private path and pid'), { code: 'unit_launcher_identity' });
  const old = { ok: false, phase: 'first_start', code: classifyLifecycleError(primary, 'first_start') };
  old.code = 'cleanup_unconfirmed';
  assert.equal(old.code, 'cleanup_unconfirmed'); assert.equal(Object.hasOwn(old, 'primaryFailure'), false);
  const d = createFailureDiagnostics(); d.primary(primary, 'first_start', 'launcher_identity');
  d.cleanup(Object.assign(new Error('private'), { code: 'native_cleanup_unknown' }), 'unit_cleanup');
  d.cleanup(new Error('private'), 'app_close'); d.primary(new Error('later'), 'uninstall', 'complete');
  const result = { ...old, ...d.snapshot() };
  assert.equal(result.ok, false); assert.equal(result.code, 'cleanup_unconfirmed');
  assert.deepEqual(result.primaryFailure, { phase: 'first_start', subphase: 'launcher_identity', code: 'unit_launcher_identity', systemErrorClass: 'unknown' });
  assert.deepEqual(result.cleanupFailures, [{ stage: 'unit_cleanup', code: 'native_cleanup_unknown' }, { stage: 'app_close', code: 'cleanup_unconfirmed' }]);
});
test('cleanup-only failure never invents a primary service refusal', () => {
  const d = createFailureDiagnostics(); d.cleanup(new Error('private'), 'final_assertion');
  assert.equal(d.snapshot().primaryFailure, null); assert.equal(d.snapshot().cleanupFailureCount, 1);
});
test('later stop and uninstall failures cannot inherit a previous start subphase', () => {
  for (const phase of ['preflight', 'first_stop', 'second_stop', 'uninstall', 'complete']) {
    const d = createFailureDiagnostics(); d.primary(new Error('private'), phase, 'launcher_identity');
    assert.equal(d.snapshot().primaryFailure.subphase, 'not_applicable');
  }
});
test('diagnostic snapshots are defensive and cleanup counts are bounded explicitly', () => {
  const d = createFailureDiagnostics(); d.primary(new Error('private'), 'second_start', 'wait_bind');
  for (let i = 0; i < 40; i++) d.cleanup(new Error('private'), 'app_close');
  const snapshot = d.snapshot(); snapshot.primaryFailure.code = 'tampered'; snapshot.cleanupFailures[0].stage = 'tampered'; snapshot.cleanupFailures.push({ secret: true });
  const actual = d.snapshot(); assert.equal(actual.primaryFailure.code, 'lifecycle_failed'); assert.equal(actual.cleanupFailures.length, 8);
  assert.equal(actual.cleanupFailures[0].stage, 'app_close'); assert.equal(actual.cleanupFailureCount, 32); assert.equal(actual.cleanupFailuresTruncated, true);
});
test('hostile errors and phase objects never leak through failure diagnostics', () => {
  let called = false; const error = new Error('private-host-path-pid');
  Object.defineProperty(error, 'code', { get() { called = true; return 'private_runtime_secret'; } });
  const phase = { toString() { called = true; return 'private_runtime_secret'; } };
  const d = createFailureDiagnostics(); d.primary(error, phase, phase); d.cleanup(new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('private'); } }), phase);
  const text = JSON.stringify(d.snapshot()); assert.equal(called, false); assert.equal(text.includes('private'), false);
  assert.equal(d.snapshot().primaryFailure.phase, 'unknown'); assert.equal(d.snapshot().primaryFailure.subphase, 'not_applicable');
});
test('fixed unit observation whitelist hides paths, PIDs and unknown states', () => {
  const r = summarizeUnitProperties({ LoadState: 'loaded', ActiveState: 'active', SubState: 'private-secret', Result: 'private-secret', MainPID: '1234', ControlGroup: '/private/uid', FragmentPath: '/private/file' });
  assert.equal(r.loadState, 'loaded'); assert.equal(r.activeState, 'active'); assert.equal(r.subState, 'unknown'); assert.equal(r.result, 'unknown');
  assert.equal(r.mainPIDPresent, true); assert.equal(r.controlGroupPresent, true); assert.equal(r.fragmentPathPresent, true);
  const text = JSON.stringify(r); assert.equal(text.includes('private'), false); assert.equal(text.includes('1234'), false);
});
test('unit and manager summary functions never evaluate metadata getters', () => {
  let called = false; const r = {};
  for (const k of ['LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID', 'ControlGroup', 'FragmentPath', 'ok', 'exitCode', 'stderr', 'termination']) Object.defineProperty(r, k, { get() { called = true; return 'private'; } });
  assert.equal(summarizeUnitProperties(r).activeState, 'unknown'); assert.equal(summarizeManagerOutcome(r).outcome, 'unresolved'); assert.equal(called, false);
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('private'); } });
  assert.equal(JSON.stringify(summarizeUnitProperties(proxy)).includes('private'), false); assert.equal(summarizeManagerOutcome(proxy).outcome, 'unresolved');
});
test('manager outcomes distinguish success, nonzero and unresolved without raw exit codes', () => {
  assert.equal(summarizeManagerOutcome({ ok: true, exitCode: 0, stderr: '', termination: 'none' }).outcome, 'succeeded');
  const r = summarizeManagerOutcome({ ok: false, exitCode: 7, stderr: '/private/path pid=123', termination: 'exit_nonzero' });
  assert.equal(r.outcome, 'exited_nonzero'); assert.equal(r.exitCodeClass, 'nonzero'); assert.equal(r.stderrPresent, true); assert.equal(Object.hasOwn(r, 'exitCode'), false);
  assert.equal(summarizeManagerOutcome({ ok: true, exitCode: '0', stderr: '', termination: 'private' }).outcome, 'unresolved');
  assert.equal(summarizeManagerOutcome({ ok: false, exitCode: null, stderr: '', termination: 'timeout_or_killed' }).termination, 'timeout_or_killed');
});
for (const [name, input, expected] of [
  ['output bound', { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true }, 'output_limit'],
  ['timeout or killed', { code: null, killed: true, signal: 'SIGKILL' }, 'timeout_or_killed'],
  ['signal', { code: null, killed: false, signal: 'SIGTERM' }, 'signal'],
  ['unavailable', { code: 'EACCES' }, 'unavailable'],
  ['nonzero', { code: 1 }, 'exit_nonzero'],
  ['unknown', { code: 'private_runtime_secret' }, 'unknown']]) {
  test(`command termination diagnostic: ${name}`, () => assert.equal(classifyCommandTermination(input), expected));
}
test('start diagnostics have bounded defensive observations and explicit truncation', () => {
  const d = createStartDiagnostics(); d.begin(); d.step('before_properties');
  for (let i = 0; i < 40; i++) d.observe('properties_state', { LoadState: 'loaded', ActiveState: 'inactive', SubState: 'dead', Result: 'success', MainPID: '0', FragmentPath: '/private', ControlGroup: '' });
  d.step('complete'); d.complete(); const first = d.snapshot(); first.observations[0].activeState = 'tampered';
  const actual = d.snapshot(); assert.equal(actual.attempts, 1); assert.equal(actual.completedAttempts, 1); assert.equal(actual.observations.length, 8);
  assert.equal(actual.observationCount, 32); assert.equal(actual.observationsTruncated, true); assert.equal(actual.observations[0].activeState, 'inactive');
  assert.equal(JSON.stringify(actual).includes('/private'), false);
});
test('diagnostic enum contracts are immutable and do not grant manager authority', () => {
  for (const list of [DIAGNOSTIC_PHASES, START_SUBPHASES, CLEANUP_STAGES]) assert.equal(Object.isFrozen(list), true);
  assert.equal(LIMITATIONS.serviceAccepted, false); assert.equal(LIMITATIONS.productionAccepted, false);
});

test('unit presence diagnostic rejects a trailing newline in a raw PID field', () => {
  assert.equal(summarizeUnitProperties({ MainPID: '1234\n' }).mainPIDPresent, false);
});

test('primary system error class is a finite own-data actual-Error observation', () => {
  for (const [code, expected] of [['EACCES', 'permission_denied'], ['EPERM', 'permission_denied'], ['ENOENT', 'not_found'], ['ESRCH', 'process_missing'], ['private_secret', 'unknown']]) {
    const error = Object.assign(new Error('/private/path'), { code }); assert.equal(classifySystemError(error), expected);
    const d = createFailureDiagnostics(); d.primary(error, 'first_start', 'launcher_identity'); assert.equal(d.snapshot().primaryFailure.systemErrorClass, expected);
  }
  assert.equal(classifySystemError({ code: 'EACCES' }), 'unknown');
  const inherited = Object.create(Object.assign(new Error('private'), { code: 'EACCES' })); assert.equal(classifySystemError(inherited), 'unknown');
  let called = false; const getter = new Error('private'); Object.defineProperty(getter, 'code', { get() { called = true; return 'EACCES'; } });
  assert.equal(classifySystemError(getter), 'unknown'); assert.equal(called, false);
});

const fragmentKnownPaths = Object.freeze({ unitFile: '/tmp/owned-unit/fixture.service', runtimeLink: '/run/user/1000/systemd/user/fixture.service' });
const fragmentLinkCheck = Object.freeze({ targetMatchesUnit: true, unitOwnedModeHash: true });
const fragmentSummary = (FragmentPath, paths = fragmentKnownPaths, check = fragmentLinkCheck) => summarizeUnitFragmentIdentity({ LoadState: 'loaded', FragmentPath }, paths, check);
test('baseline observations cannot distinguish owned runtime-link spelling from unrelated fragment', () => {
  const alias = { LoadState: 'loaded', FragmentPath: fragmentKnownPaths.runtimeLink };
  const other = { LoadState: 'loaded', FragmentPath: '/tmp/unrelated-unit/fixture.service' };
  assert.deepEqual(summarizeUnitProperties(alias), summarizeUnitProperties(other));
  assert.equal(summarizeUnitFragmentIdentity(alias, fragmentKnownPaths, fragmentLinkCheck).fragmentPathMatch, 'runtime_link');
  assert.equal(summarizeUnitFragmentIdentity(other, fragmentKnownPaths, fragmentLinkCheck).fragmentPathMatch, 'other');
  for (const record of [alias, other]) assert.notEqual(record.FragmentPath, fragmentKnownPaths.unitFile);
  assert.equal(LIMITATIONS.serviceAccepted, false);
});
for (const [name, value, expected] of [
  ['exact owned file', fragmentKnownPaths.unitFile, 'unit_file'],
  ['exact known runtime link', fragmentKnownPaths.runtimeLink, 'runtime_link'],
  ['unrelated absolute fragment', '/tmp/other/fixture.service', 'other'],
  ['empty', '', 'empty'], ['missing', undefined, 'unknown'], ['relative', 'fixture.service', 'unknown'],
  ['unnormalized', '/tmp/a/../fixture.service', 'unknown'], ['newline', fragmentKnownPaths.unitFile + '\n', 'unknown'],
  ['buffer', Buffer.from(fragmentKnownPaths.unitFile), 'unknown'], ['oversized', '/' + 'x'.repeat(4096), 'unknown']]) {
  test(`fragment comparison is fixed and diagnostic only: ${name}`, () => {
    const result = fragmentSummary(value); assert.equal(result.fragmentPathMatch, expected);
    assert.equal(result.canonicalIdentity, 'not_measured'); assert.equal(result.precedingLinkTargetMatchesUnit, 'verified');
    assert.equal(result.precedingUnitOwnedModeHash, 'verified'); assert.equal(Object.hasOwn(result, 'accepted'), false);
    const text = JSON.stringify(result); assert.equal(text.includes('/tmp/'), false); assert.equal(text.includes('/run/'), false);
  });
}
test('fragment comparison does not normalize identical basename into an owned match', () => {
  assert.equal(fragmentSummary('/tmp/foreign/fixture.service').fragmentPathMatch, 'other');
  assert.equal(fragmentSummary('/run/user/1000/systemd/user/fixture.service.extra').fragmentPathMatch, 'other');
});
test('missing or ambiguous known paths cannot classify a positive owned match', () => {
  for (const paths of [null, {}, { unitFile: fragmentKnownPaths.unitFile },
    { ...fragmentKnownPaths, runtimeLink: fragmentKnownPaths.unitFile }, { ...fragmentKnownPaths, unitFile: '../fixture.service' }]) {
    assert.equal(fragmentSummary(fragmentKnownPaths.runtimeLink, paths).fragmentPathMatch, 'unknown');
  }
});
test('link and file facts require explicit own-data true and never invent canonical identity', () => {
  for (const check of [undefined, null, {}, { targetMatchesUnit: false, unitOwnedModeHash: false },
    { targetMatchesUnit: 1, unitOwnedModeHash: 'true' }, Object.create(fragmentLinkCheck)]) {
    const result = summarizeUnitFragmentIdentity({ LoadState: 'loaded', FragmentPath: fragmentKnownPaths.runtimeLink }, fragmentKnownPaths, check);
    assert.equal(result.precedingLinkTargetMatchesUnit, 'unknown'); assert.equal(result.precedingUnitOwnedModeHash, 'unknown');
    assert.equal(result.canonicalIdentity, 'not_measured');
  }
});
test('fragment diagnostics do not evaluate getters or coerce path objects', () => {
  let called = false; const malicious = { toString() { called = true; return fragmentKnownPaths.unitFile; } };
  const record = {}; Object.defineProperty(record, 'FragmentPath', { get() { called = true; return fragmentKnownPaths.unitFile; } });
  const paths = {}; for (const k of ['unitFile', 'runtimeLink']) Object.defineProperty(paths, k, { get() { called = true; return '/private'; } });
  const check = {}; for (const k of ['targetMatchesUnit', 'unitOwnedModeHash']) Object.defineProperty(check, k, { get() { called = true; return true; } });
  assert.equal(summarizeUnitFragmentIdentity(record, paths, check).fragmentPathMatch, 'unknown');
  assert.equal(fragmentSummary(malicious).fragmentPathMatch, 'unknown'); assert.equal(called, false);
});
test('fragment diagnostics discard inherited fields and hostile descriptor traps', () => {
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('private/path pid=999'); } });
  for (const record of [null, undefined, proxy, Object.create({ LoadState: 'loaded', FragmentPath: fragmentKnownPaths.unitFile })]) {
    const result = summarizeUnitFragmentIdentity(record, proxy, proxy);
    assert.equal(result.fragmentPathMatch, 'unknown'); assert.equal(result.loadState, 'unknown');
    assert.equal(JSON.stringify(result).includes('private'), false);
  }
});
test('fragment collector separates lifecycle and cleanup observations with bounded copies', () => {
  const d = createFragmentIdentityDiagnostics();
  d.observe({ LoadState: 'loaded', FragmentPath: fragmentKnownPaths.runtimeLink }, fragmentKnownPaths, fragmentLinkCheck, 'first_start', 'before_properties', false);
  d.observe({ LoadState: 'not-found', FragmentPath: '' }, fragmentKnownPaths, fragmentLinkCheck, 'first_start', 'before_properties', true);
  const s = d.snapshot(); assert.equal(s.observationCount, 2); assert.equal(s.observationsTruncated, false);
  assert.equal(s.observations[0].context, 'lifecycle'); assert.equal(s.observations[0].subphase, 'before_properties');
  assert.equal(s.observations[1].context, 'cleanup'); assert.equal(s.observations[1].subphase, 'not_applicable');
  assert.equal(s.observations[1].loadState, 'not-found'); assert.equal(s.observations[1].fragmentPathMatch, 'empty');
  s.observations[0].fragmentPathMatch = 'tampered'; s.observations.push({ secret: true });
  assert.equal(d.snapshot().observations[0].fragmentPathMatch, 'runtime_link'); assert.equal(d.snapshot().observations.length, 2);
});
test('fragment collector retains first eight observations and explicitly caps counter at thirty-two', () => {
  const d = createFragmentIdentityDiagnostics(); for (let i = 0; i < 40; i++) d.observe({}, {}, {}, 'first_start', 'before_properties', false);
  const s = d.snapshot(); assert.equal(s.observationCount, 32); assert.equal(s.observations.length, 8); assert.equal(s.observationsTruncated, true);
});
test('fragment collector whitelists phase and subphase without carrying unknown context input', () => {
  const d = createFragmentIdentityDiagnostics(); const hostile = { toString() { throw new Error('private'); } };
  d.observe({}, {}, {}, hostile, hostile, false); d.observe({}, {}, {}, 'first_stop', 'before_properties', false);
  const s = d.snapshot(); assert.equal(s.observations[0].phase, 'unknown'); assert.equal(s.observations[0].subphase, 'not_applicable');
  assert.equal(s.observations[1].subphase, 'not_applicable'); assert.equal(JSON.stringify(s).includes('private'), false);
});

async function ownedFragmentFixture(t) {
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), 'x10-unit-paths-'));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const runtime = `${root}/runtime`; await mkdir(`${runtime}/systemd/user`, { recursive: true, mode: 0o700 });
  const unitFile = `${root}/fixture.service`, runtimeLink = `${runtime}/systemd/user/fixture.service`;
  const bytes = '[Service]\nType=exec\nExecStart=/usr/bin/false\n';
  await writeFile(unitFile, bytes, { mode: 0o600 }); await symlink(unitFile, runtimeLink);
  return { root, runtime, unitFile, runtimeLink, bytes };
}
async function extractedOwnedProperties(fixture, properties) {
  const source = await readFile(script, 'utf8');
  const authority = source.slice(source.indexOf('  async function runtimeParents()'), source.indexOf('  async function properties('));
  const owned = source.slice(source.indexOf('  async function ownedProperties('), source.indexOf('  async function launcherIdentity('));
  const rejectCode = code => { throw Object.assign(new Error(code), { code }); };
  const absent = async file => { try { await lstat(file); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; } };
  const factory = new Function('env', 'lstat', 'process', 'readlink', 'realpath', 'readFile', 'digest', 'report', 'unitFile', 'runtimeLink', 'unitName', 'properties', 'fragments', 'start', 'inCleanup', 'verifyKnownUnitFragmentPaths', 'reject', 'absent', `${authority}${owned}; return ownedProperties;`);
  return factory({ XDG_RUNTIME_DIR: fixture.runtime }, lstat, process, readlink, realpath, readFile, digest,
    { unitSha256: digest(fixture.bytes), phase: 'first_start' }, fixture.unitFile, fixture.runtimeLink, 'fixture.service',
    properties, createFragmentIdentityDiagnostics(), { snapshot: () => ({ lastStep: 'before_properties' }) }, false,
    verifyKnownUnitFragmentPaths, rejectCode, absent);
}
const ownedResponse = fragment => ({ LoadState: 'loaded', FragmentPath: fragment, ControlGroup: '' });
test('actual private owned symlink reproduces baseline literal refusal and passes known canonical paths', async t => {
  const f = await ownedFragmentFixture(t);
  assert.notEqual(f.runtimeLink, f.unitFile);
  assert.equal(await verifyKnownUnitFragmentPaths(ownedResponse(f.runtimeLink), f), true);
  assert.equal(await verifyKnownUnitFragmentPaths(ownedResponse(f.unitFile), f), true);
  const owned = await extractedOwnedProperties(f, async () => ownedResponse(f.runtimeLink));
  assert.equal((await owned()).LoadState, 'loaded');
});
for (const change of ['missing', 'broken', 'cycle', 'regular', 'hardlink', 'retarget']) {
  test(`known runtime alias rejects actual owned fixture change: ${change}`, async t => {
    const f = await ownedFragmentFixture(t); await rm(f.runtimeLink);
    if (change === 'broken') await symlink(`${f.root}/absent.service`, f.runtimeLink);
    if (change === 'cycle') await symlink(f.runtimeLink, f.runtimeLink);
    if (change === 'regular') await writeFile(f.runtimeLink, f.bytes, { mode: 0o600 });
    if (change === 'hardlink') await link(f.unitFile, f.runtimeLink);
    if (change === 'retarget') { const duplicate = `${f.root}/duplicate.service`; await writeFile(duplicate, f.bytes, { mode: 0o600 }); await symlink(duplicate, f.runtimeLink); }
    await assert.rejects(verifyKnownUnitFragmentPaths(ownedResponse(f.runtimeLink), f), { code: 'unit_fragment_identity' });
  });
}
test('foreign duplicate and hardlink manager spellings remain outside the exact allowlist', async t => {
  const f = await ownedFragmentFixture(t), duplicate = `${f.root}/duplicate.service`, hard = `${f.root}/hard.service`;
  await writeFile(duplicate, f.bytes, { mode: 0o600 }); await link(f.unitFile, hard);
  for (const fragment of [duplicate, hard, `${f.root}/absent.service`]) await assert.rejects(verifyKnownUnitFragmentPaths(ownedResponse(fragment), f), { code: 'unit_fragment_identity' });
});
test('canonical alias check rejects a noncanonical known unit parent', async t => {
  const f = await ownedFragmentFixture(t), alias = `${f.root}/parent-alias`; await symlink(f.root, alias);
  const unitFile = `${alias}/fixture.service`; await rm(f.runtimeLink); await symlink(unitFile, f.runtimeLink);
  await assert.rejects(verifyKnownUnitFragmentPaths(ownedResponse(f.runtimeLink), { ...f, unitFile }), { code: 'unit_fragment_identity' });
});
test('known-path verifier rejects invalid metadata without getter evaluation or coercion', async () => {
  let called = false; const getter = {}; for (const key of ['LoadState', 'FragmentPath', 'unitFile', 'runtimeLink']) Object.defineProperty(getter, key, { get() { called = true; return 'loaded'; } });
  const hostile = { toString() { called = true; return fragmentKnownPaths.runtimeLink; } };
  for (const [record, paths] of [[getter, getter], [ownedResponse(hostile), fragmentKnownPaths],
    [ownedResponse(fragmentKnownPaths.runtimeLink), { ...fragmentKnownPaths, unitFile: '../bad' }],
    [{ LoadState: 'not-found', FragmentPath: fragmentKnownPaths.unitFile }, fragmentKnownPaths],
    [ownedResponse(''), fragmentKnownPaths], [ownedResponse('/tmp/foreign'), fragmentKnownPaths],
    [ownedResponse(fragmentKnownPaths.runtimeLink + '\n'), fragmentKnownPaths]]) {
    await assert.rejects(verifyKnownUnitFragmentPaths(record, paths), { code: 'unit_fragment_identity' });
  }
  assert.equal(called, false);
});
test('post-query owned checks reject changed mode and hash for either accepted spelling', async t => {
  for (const change of ['mode', 'hash']) for (const spelling of ['unitFile', 'runtimeLink']) {
    const f = await ownedFragmentFixture(t), owned = await extractedOwnedProperties(f, async () => {
      if (change === 'mode') await chmod(f.unitFile, 0o644); else await writeFile(f.unitFile, 'changed');
      return ownedResponse(f[spelling]);
    });
    await assert.rejects(owned(), { code: 'unit_file_identity' });
  }
});
test('post-query owned checks reject a retargeted exact file spelling and changed runtime parent', async t => {
  for (const change of ['link', 'parent']) {
    const f = await ownedFragmentFixture(t), duplicate = `${f.root}/duplicate.service`; await writeFile(duplicate, f.bytes, { mode: 0o600 });
    const owned = await extractedOwnedProperties(f, async () => {
      if (change === 'link') { await rm(f.runtimeLink); await symlink(duplicate, f.runtimeLink); }
      else await chmod(`${f.runtime}/systemd/user`, 0o777);
      return ownedResponse(f.unitFile);
    });
    await assert.rejects(owned(), { code: change === 'link' ? 'unit_link_identity' : 'unit_directory_identity' });
  }
});
test('post-query canonical and cgroup refusals retain the exact owned guard boundary', async t => {
  const f = await ownedFragmentFixture(t);
  const badGroup = await extractedOwnedProperties(f, async () => ({ ...ownedResponse(f.runtimeLink), ControlGroup: '/foreign' }));
  await assert.rejects(badGroup(), { code: 'unit_cgroup_identity' });
  const wrongLoad = await extractedOwnedProperties(f, async () => ({ ...ownedResponse(f.unitFile), LoadState: 'not-found' }));
  await assert.rejects(wrongLoad(), { code: 'unit_fragment_identity' });
});

test('known-path verifier refuses non-record containers and hostile prototype traps', async () => {
  const fields = ownedResponse(fragmentKnownPaths.unitFile);
  const proxy = new Proxy({}, { getPrototypeOf() { throw new Error('private'); } });
  for (const record of [Object.assign([], fields), Object.assign(() => {}, fields), Object.assign(Object.create({}), fields), proxy]) {
    await assert.rejects(verifyKnownUnitFragmentPaths(record, fragmentKnownPaths), { code: 'unit_fragment_identity' });
  }
  for (const paths of [Object.assign([], fragmentKnownPaths), Object.assign(() => {}, fragmentKnownPaths), Object.assign(Object.create({}), fragmentKnownPaths), proxy]) {
    await assert.rejects(verifyKnownUnitFragmentPaths(fields, paths), { code: 'unit_fragment_identity' });
  }
});

async function syntheticAutomaticStart({ binding = true, lateBinding = binding, identityValid = true, startOK = true, cancelAt = 0, priorStopped = 0, priorReport = null } = {}) {
  const source = await readFile(script, 'utf8'), body = source.slice(source.indexOf('  async function startAndServe()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const reset = source.slice(source.indexOf('  function resetServiceCleanupEvidence()'), source.indexOf('  async function stopOwned()'));
  const calls = [], report = priorReport || { explicitReadinessPasses: 0, nativeSessionsStarted: priorStopped, nativeSessionsStopped: priorStopped, proxyBodyChecks: 0, uploadChecks: 0, streamChecks: 0,
    cleanup: { managerStopped: true, launcherExited: true, nativeGroupsAbsent: true, listeningPortsClosed: true, controlSocketAbsent: true, runtimeLinkAbsent: true, installationRemoved: false, temporaryRootRemoved: false, appSocketsRemaining: 0 } }, sessions = Array.from({ length: priorStopped }, () => ({}));
  let observations = 0, cancelChecks = 0, statusObservations = 0, managerStarted = false;
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const own = async () => { calls.push('properties'); observations++; return !managerStarted ? { ActiveState: 'inactive', MainPID: '0' } : { ActiveState: 'active', SubState: 'running' }; };
  const cli = async (_node, _launcher, args) => { calls.push(`cli_${args[0]}`); if (args[0] === 'info') return { stage: 'running', session: 'one' }; assert.equal(args[0], 'status'); return { binding: ++statusObservations === 1 ? binding : lateBinding, runtime: { identityValid } }; };
  const factory = new Function('start', 'checkCancelled', 'ownedProperties', 'systemctl', 'unitName', 'launcherIdentities', 'launcherIdentity', 'report', 'cli', 'node', 'launcher', 'env', 'until', 'inventorySessions', 'sessions', 'observeNative', 'request', 'gatewayPort', 'reject', 'observeStartPost', `let startRequested = false, lastSession = null, failedStartup = null; ${reset}${body}; return startAndServe;`);
  const start = factory(createStartDiagnostics(), () => { if (++cancelChecks === cancelAt) reject('cancelled'); }, own,
    async (args, timeout) => { calls.push('manager_start'); managerStarted = true; assert.deepEqual(args, ['start', 'fixture.service']); assert.equal(timeout, 15000); return { ok: startOK }; },
    'fixture.service', [], async () => { calls.push('launcher'); return {}; }, report, cli, '/synthetic/node', '/synthetic/launcher', {},
    async fn => { assert.equal(await fn(), true); }, async () => { calls.push('inventory'); sessions.push({ id: 'one' }); }, sessions,
    async () => { calls.push('native'); report.nativeSessionsStarted++; return { id: 'one' }; },
    async (_port, route = '/', body) => { calls.push(`request_${route}`); return { status: 200, body: route === '/echo' ? body : route === '/stream' ? Buffer.alloc(65537, 0x62) : Buffer.from('service-fixture\n') }; }, 0, reject, async () => {});
  let failure = null; try { await start(); } catch (e) { failure = e.code; }
  return { calls, report, failure };
}
test('source-extracted start requires bound status after manager activation without manual bind fallback', async () => {
  const result = await syntheticAutomaticStart(); assert.equal(result.failure, null); assert.equal(result.report.explicitReadinessPasses, 1);
  assert.equal(result.calls.filter(x => x.startsWith('cli_')).join(','), 'cli_status,cli_info,cli_status');
  assert.ok(result.calls.indexOf('manager_start') < result.calls.indexOf('cli_status'));
  assert.ok(result.calls.indexOf('cli_status') < result.calls.indexOf('inventory'));
  assert.ok(result.calls.lastIndexOf('cli_status') > result.calls.indexOf('native'));
  assert.equal(result.report.proxyBodyChecks, 1); assert.equal(result.report.uploadChecks, 1); assert.equal(result.report.streamChecks, 1);
});
for (const [name, options, expected] of [['missing binding', { binding: false }, 'binding_unconfirmed'], ['invalid runtime identity', { identityValid: false }, 'binding_unconfirmed'], ['failed manager start', { startOK: false }, 'unit_start_failed'], ['cancel before start', { cancelAt: 1 }, 'cancelled']]) {
  test(`source-extracted automatic start refuses ${name} without a manual fallback`, async () => {
    const result = await syntheticAutomaticStart(options); assert.equal(result.failure, expected); assert.equal(result.report.explicitReadinessPasses, 0);
    assert.equal(result.report.proxyBodyChecks, 0); assert.equal(result.calls.some(x => x.includes('wait-bind')), false);
    if (expected === 'binding_unconfirmed') assert.equal(result.calls.includes('inventory'), false);
    else assert.equal(result.calls.includes('cli_status'), false);
  });
}

test('source-extracted automatic start retains the later fresh binding check before proxy use', async () => {
  const result = await syntheticAutomaticStart({ binding: true, lateBinding: false });
  assert.equal(result.failure, 'binding_unconfirmed'); assert.equal(result.report.explicitReadinessPasses, 0);
  assert.equal(result.calls.filter(x => x === 'cli_status').length, 2); assert.equal(result.report.nativeSessionsStarted, 1);
  assert.equal(result.report.proxyBodyChecks, 0); assert.equal(result.calls.some(x => x.includes('wait-bind')), false);
});

const serviceCleanupNames = ['managerStopped', 'launcherExited', 'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent'];
const assertServiceCleanup = (report, expected) => { for (const name of serviceCleanupNames) assert.equal(report.cleanup[name], expected, name); };
async function syntheticOwnedStop({ report, failure = null, tlsPort = undefined } = {}) {
  const source = await readFile(script, 'utf8');
  const reset = source.slice(source.indexOf('  function resetServiceCleanupEvidence()'), source.indexOf('  async function stopOwned()'));
  const body = source.slice(source.indexOf('  async function stopOwned()'), source.indexOf('  async function startAndServe()'));
  report ||= { explicitReadinessPasses: 0, proxyBodyChecks: 0, uploadChecks: 0, streamChecks: 0, nativeSessionsStarted: 1, nativeSessionsStopped: 1, cleanup: Object.fromEntries([...serviceCleanupNames.map(name => [name, true]), ['runtimeLinkAbsent', true], ['installationRemoved', false], ['temporaryRootRemoved', false], ['appSocketsRemaining', 0]]) };
  const calls = []; let inventories = 0, properties = 0;
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const inventory = async () => { calls.push('inventory'); inventories++;
    if (failure === 'inventory_before') reject('lifecycle_identity');
    if (failure === 'inventory_after' && inventories === 2) reject('native_cleanup_unknown');
  };
  const owned = async () => { calls.push('properties'); properties++;
    if (failure === 'properties_before' && properties === 1 || failure === 'properties_after' && properties === 2) reject('unit_fragment_identity');
    return { MainPID: failure === 'launcher' && properties === 1 ? '123' : '0', ActiveState: failure === 'state_after' && properties === 2 ? 'active' : 'inactive', Result: 'success' };
  };
  const factory = new Function('report', 'inventorySessions', 'ownedProperties', 'launcherIdentity', 'launcherIdentities', 'systemctl', 'unitName', 'until', 'exitedLauncher', 'sessions', 'nativeStopped', 'absent', 'prefix', 'closedPort', 'gatewayPort', 'healthPort', 'reject', 'tlsPort', `${reset}${body};return stopOwned;`);
  const stop = factory(report, inventory, owned, async () => { reject('unit_launcher_identity'); }, [],
    async (args, timeout) => { calls.push('manager_stop'); assert.deepEqual(args, ['stop', 'fixture.service']); assert.equal(timeout, 35000); return { ok: failure !== 'manager_stop' }; },
    'fixture.service', async fn => { if (failure === 'absence_wait' || !await fn()) reject('observation_timeout'); }, async () => true, [], async () => true,
    async () => failure !== 'control_socket', '/synthetic/prefix', async port => failure !== (port === 1 ? 'gateway_port' : port === 2 ? 'health_port' : 'tls_port'), 1, 2, reject, tlsPort);
  let code = null; try { await stop(); } catch (e) { code = e.code; }
  return { report, calls, code };
}
test('every start invalidates prior service cleanup confirmations even on early cancel or start failure', async () => {
  for (const options of [{ cancelAt: 1 }, { startOK: false }, {}]) {
    const result = await syntheticAutomaticStart({ ...options, priorStopped: 1 });
    assertServiceCleanup(result.report, false);
    assert.equal(result.report.nativeSessionsStopped, 1);
    assert.equal(result.report.nativeSessionsStarted, options.cancelAt || options.startOK === false ? 1 : 2);
    assert.equal(result.report.cleanup.runtimeLinkAbsent, true); assert.equal(result.report.cleanup.installationRemoved, false);
  }
});
for (const [failure, code] of [['inventory_before', 'lifecycle_identity'], ['properties_before', 'unit_fragment_identity'], ['launcher', 'unit_launcher_identity'], ['manager_stop', 'unit_stop_unconfirmed'], ['properties_after', 'unit_fragment_identity'], ['inventory_after', 'native_cleanup_unknown'], ['state_after', 'unit_stop_unconfirmed'], ['absence_wait', 'observation_timeout'], ['control_socket', 'service_resources_live'], ['gateway_port', 'service_resources_live'], ['health_port', 'service_resources_live']]) {
  test(`each stop attempt invalidates stale confirmations before ${failure} refusal`, async () => {
    const result = await syntheticOwnedStop({ failure }); assert.equal(result.code, code); assertServiceCleanup(result.report, false);
    assert.equal(result.report.nativeSessionsStarted, 1); assert.equal(result.report.nativeSessionsStopped, 1);
    assert.equal(result.report.cleanup.runtimeLinkAbsent, true); assert.equal(result.report.cleanup.installationRemoved, false); assert.equal(result.report.cleanup.temporaryRootRemoved, false);
  });
}
test('second-start failure followed by final cleanup uncertainty cannot reuse the first-stop confirmations', async () => {
  const firstStop = await syntheticOwnedStop(); assert.equal(firstStop.code, null); assertServiceCleanup(firstStop.report, true);
  const started = await syntheticAutomaticStart({ startOK: false, priorStopped: 1, priorReport: firstStop.report });
  assert.equal(started.failure, 'unit_start_failed'); assertServiceCleanup(started.report, false);
  const cleanup = await syntheticOwnedStop({ report: started.report, failure: 'inventory_after' });
  assert.equal(cleanup.code, 'native_cleanup_unknown'); assertServiceCleanup(cleanup.report, false);
  assert.equal(cleanup.report.nativeSessionsStarted, 1); assert.equal(cleanup.report.nativeSessionsStopped, 1);
});
test('freshly completed stop restores all five confirmations only after the unchanged checks pass', async () => {
  const result = await syntheticOwnedStop(); assert.equal(result.code, null); assertServiceCleanup(result.report, true);
  assert.equal(result.report.nativeSessionsStarted, 1); assert.equal(result.report.nativeSessionsStopped, 1);
  assert.equal(result.report.cleanup.runtimeLinkAbsent, true); assert.equal(result.report.cleanup.appSocketsRemaining, 0);
});

const hookExpected = Object.freeze({ nodeExecutable: '/synthetic/node', launcher: '/synthetic/install/bin/x10' });
const hookText = (change = {}) => {
  const r = { path: hookExpected.nodeExecutable, argv: `${hookExpected.nodeExecutable} ${hookExpected.launcher} wait-bind --timeout-ms 10000`, ignore: 'no',
    start: 'Sun 2026-10-25 06:00:00 UTC', stop: 'Sun 2026-10-25 06:00:01 UTC', pid: '4321', code: 'exited', status: '1', ...change };
  return `ExecStartPost={ path=${r.path} ; argv[]=${r.argv} ; ignore_errors=${r.ignore} ; start_time=[${r.start}] ; stop_time=[${r.stop}] ; pid=${r.pid} ; code=${r.code} ; status=${r.status} }\n`;
};
const observedHook = text => { const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', text, hookExpected); return d.snapshot().observations[0]; };
for (const status of ['0', '1', '255']) test(`hook observation permits only the bounded exited status ${status}`, () => {
  const r = observedHook(hookText({ status })); assert.equal(r.state, 'completed'); assert.equal(r.codeClass, 'exited'); assert.equal(r.exitStatus, Number(status));
  assert.equal(r.recordChangedSincePreStart, 'unknown'); assert.equal(r.signalClass, 'none');
});
for (const [code, status] of [['killed', '15/TERM'], ['dumped', '11/SEGV']]) test(`hook observation exposes only generic signal class ${code}`, () => {
  const r = observedHook(hookText({ code, status })); assert.equal(r.codeClass, 'signal'); assert.equal(r.signalClass, code); assert.equal(r.exitStatus, null);
  assert.equal(JSON.stringify(r).includes(status), false);
});
for (const [name, text] of Object.entries({ empty: '', missingLF: hookText().slice(0, -1), extraLF: hookText() + '\n', duplicate: hookText() + hookText(),
  field: hookText().replace(' ; pid=', ' ; other=value ; pid='), duplicateField: hookText().replace(' ; pid=', ' ; code=exited ; pid='),
  wrongPath: hookText({ path: '/other/node' }), extraArg: hookText({ argv: `${hookExpected.nodeExecutable} ${hookExpected.launcher} wait-bind --timeout-ms 10000 --other` }),
  wrongLauncher: hookText({ argv: `${hookExpected.nodeExecutable} /other/launcher wait-bind --timeout-ms 10000` }), ignoredFailure: hookText({ ignore: 'yes' }),
  CRLF: hookText().replaceAll('\n', '\r\n'), nonASCII: hookText({ start: 'private-é' }), escape: hookText().replace('ExecStartPost=', '\u001bExecStartPost='), oversized: 'x'.repeat(16385),
  noProperty: hookText().replace('ExecStartPost=', ''), foreignProperty: hookText().replace('ExecStartPost=', 'ExecMain='), leadingSpace: ' ' + hookText(), trailingText: hookText() + 'private' })) {
  test(`hook parser refuses ${name} without returning raw data`, () => { const r = observedHook(text); assert.equal(r.state, 'unknown'); assert.equal(r.diagnosticResult, 'parse_refused'); assert.equal(r.exitStatus, null); });
}
for (const [name, change] of Object.entries({ unexecuted: { pid: '0', start: 'n/a', stop: 'n/a', code: '(null)', status: '0' },
  noStop: { stop: 'n/a' }, badTime: { start: 'private' }, pidOverflow: { pid: '2147483648' }, unknownCode: { code: 'private' },
  negativeExit: { status: '-1' }, largeExit: { status: '256' }, exitedSignalSuffix: { status: '1/HUP' }, signalWithoutSuffix: { code: 'killed', status: '15' },
  zeroSignal: { code: 'killed', status: '0/TERM' }, largeSignal: { code: 'killed', status: '65/TERM' } })) {
  test(`hook record remains unknown for ${name}`, () => { const r = observedHook(hookText(change)); assert.equal(r.state, 'unknown'); assert.equal(r.exitStatus, null); assert.equal(r.recordChangedSincePreStart, 'unknown'); });
}
test('hook snapshots reveal no raw paths, PID, time, command or invocation authority', () => {
  const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', hookText(), hookExpected); d.observe(1, 'failed_start', hookText({ status: '2' }), hookExpected);
  const output = JSON.stringify(d.snapshot()); for (const secret of ['/synthetic', '4321', 'Sun 2026', 'wait-bind', 'nodeExecutable', 'startTime', 'currentInvocationVerified']) assert.equal(output.includes(secret), false);
  assert.equal(d.snapshot().observations[1].recordChangedSincePreStart, false);
});
test('hook record comparison observes only private PID and start-time tuple changes', () => {
  for (const change of [{ pid: '4322' }, { start: 'Sun 2026-10-25 06:00:02 UTC' }]) {
    const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', hookText(), hookExpected); d.observe(1, 'failed_start', hookText(change), hookExpected);
    assert.equal(d.snapshot().observations[1].recordChangedSincePreStart, true);
  }
  const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', hookText({ pid: '0', start: 'n/a', stop: 'n/a', code: '(null)', status: '0' }), hookExpected); d.observe(1, 'failed_start', hookText(), hookExpected);
  assert.equal(d.snapshot().observations[1].recordChangedSincePreStart, 'unknown');
});
test('hook collector ignores getters, coercion and throwing expected-record descriptors', () => {
  let called = false; const expected = {}; for (const k of ['nodeExecutable', 'launcher']) Object.defineProperty(expected, k, { get() { called = true; return 'private'; } });
  const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', hookText(), expected);
  d.observe(1, 'failed_start', { toString() { called = true; return hookText(); } }, hookExpected);
  assert.equal(called, false); assert(d.snapshot().observations.every(x => x.state === 'unknown'));
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('private'); } }); const other = createHookStatusDiagnostics(); other.observe(1, 'before_start', hookText(), proxy);
  assert.equal(other.snapshot().observations[0].state, 'unknown');
});
test('hook collector bounds four records and two attempts with defensive snapshots', () => {
  const d = createHookStatusDiagnostics(); for (const attempt of [1, 2]) for (const stage of ['before_start', 'failed_start']) d.observe(attempt, stage, hookText(), hookExpected);
  d.observe(3, 'before_start', hookText(), hookExpected); d.observe(1, 'failed_start', hookText(), hookExpected);
  const first = d.snapshot(); first.observations[0].exitStatus = 99; first.observations.push({ private: true });
  const s = d.snapshot(); assert.equal(s.observationCount, 4); assert.equal(s.observations.length, 4); assert.equal(s.observationsTruncated, true); assert.equal(s.observations[0].exitStatus, 1);
});
test('duplicate diagnostic stages invalidate a private comparison anchor', () => {
  const d = createHookStatusDiagnostics(); d.observe(1, 'before_start', hookText(), hookExpected); d.observe(1, 'before_start', hookText({ pid: '4322' }), hookExpected); d.observe(1, 'failed_start', hookText({ pid: '4323' }), hookExpected);
  const s = d.snapshot(); assert.equal(s.observations[1].state, 'unknown'); assert.equal(s.observations[2].recordChangedSincePreStart, 'unknown');
});
async function syntheticHookFailure({ query = 'valid', authorityFailure = 0, cancelQuery = 0, collectorThrow = null, snapshotThrow = false, freshChange = null } = {}) {
  const source = await readFile(script, 'utf8');
  const observer = source.slice(source.indexOf('  async function observeStartPost('), source.indexOf('  async function launcherIdentity('));
  const reset = source.slice(source.indexOf('  function resetServiceCleanupEvidence()'), source.indexOf('  async function stopOwned()'));
  const body = source.slice(source.indexOf('  async function startAndServe()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const trace = [], report = { nativeSessionsStarted: 0, nativeSessionsStopped: 0, cleanup: Object.fromEntries(serviceCleanupNames.map(k => [k, true])) };
  let guards = 0, queries = 0, controller; const original = createHookStatusDiagnostics();
  const hooks = { observe(...args) { if (collectorThrow === 'observe') throw new Error('private'); original.observe(...args); }, unavailable(...args) { if (collectorThrow === 'unavailable') throw new Error('private'); original.unavailable(...args); } };
  const start = createStartDiagnostics(), originalSnapshot = start.snapshot;
  const startAdapter = { ...start, snapshot() { if (snapshotThrow && trace.includes('manager_start')) throw new Error('private'); return originalSnapshot(); } };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const own = async observe => { trace.push(observe === false ? 'guard_diagnostic' : 'guard_lifecycle');
    if (observe === false) {
      guards++; if (guards === authorityFailure) throw new Error('private');
      if (guards === 3) {
        if (freshChange === 'ownership') reject('unit_link_identity');
        if (freshChange === 'active') return { ActiveState: 'active', MainPID: '0' };
        if (freshChange === 'pid') return { ActiveState: 'inactive', MainPID: '123' };
        if (freshChange === 'cancel') controller.cancel();
      }
    }
    return { ActiveState: 'inactive', MainPID: '0' };
  };
  const systemctl = async (args, timeout) => {
    if (args[0] === 'start') { trace.push('manager_start'); assert.equal(timeout, 15000); return { ok: false, exitCode: 1, stderr: '', termination: 'exit_nonzero' }; }
    trace.push('hook_query'); queries++; assert.deepEqual(args, ['show', 'fixture.service', '--property=ExecStartPost']); assert.equal(timeout, 2500);
    if (queries === cancelQuery) controller.cancel();
    if (query === 'throw') throw new Error('private');
    return { ok: query !== 'failed', exitCode: query === 'failed' ? 1 : 0, stderr: query === 'stderr' ? 'private' : '', stdout: query === 'malformed' ? 'private' : hookText({ pid: String(4320 + queries) }) };
  };
  const factory = new Function('start', 'hooks', 'ownedProperties', 'systemctl', 'unitName', 'node', 'launcher', 'report', 'checkFailure', 'reject', `${reset}${observer}${body}; let cancelled = false, startRequested = false; const checkCancelled = () => { if (cancelled) reject('cancelled'); }; return { run: startAndServe, cancel() { cancelled = true; } };`);
  controller = factory(startAdapter, hooks, own, systemctl, 'fixture.service', hookExpected.nodeExecutable, hookExpected.launcher, report, null, reject);
  let failure = null; try { await controller.run(); } catch (e) { failure = e.code; }
  return { failure, trace, report, diagnostics: original.snapshot(), queries };
}
test('owned read-only hook queries bracket before and failed-after start without replacing the refusal', async () => {
  const result = await syntheticHookFailure(); assert.equal(result.failure, 'unit_start_failed'); assert.equal(result.queries, 2);
  assert.deepEqual(result.trace, ['guard_lifecycle', 'guard_diagnostic', 'hook_query', 'guard_diagnostic', 'guard_diagnostic', 'manager_start', 'guard_diagnostic', 'hook_query', 'guard_diagnostic']);
  assert.equal(result.diagnostics.observations[1].exitStatus, 1); assert.equal(result.diagnostics.observations[1].recordChangedSincePreStart, true); assertServiceCleanup(result.report, false);
});
for (const query of ['failed', 'stderr', 'malformed', 'throw']) test(`diagnostic ${query} preserves primary start failure`, async () => {
  const r = await syntheticHookFailure({ query }); assert.equal(r.failure, 'unit_start_failed'); assert.equal(r.trace.filter(s => s === 'manager_start').length, 1);
  assert(r.diagnostics.observations.every(o => o.state === 'unknown')); assertServiceCleanup(r.report, false);
});
for (const authorityFailure of [1, 2, 4, 5]) test(`diagnostic owned guard failure ${authorityFailure} has no lifecycle authority`, async () => {
  const r = await syntheticHookFailure({ authorityFailure }); assert.equal(r.failure, 'unit_start_failed'); assert.equal(r.trace.filter(s => s === 'manager_start').length, 1); assertServiceCleanup(r.report, false);
});
test('cancellation during the new pre-start query prevents any mutating start', async () => {
  const r = await syntheticHookFailure({ cancelQuery: 1 }); assert.equal(r.failure, 'cancelled'); assert.equal(r.trace.includes('manager_start'), false); assert.equal(r.queries, 1); assertServiceCleanup(r.report, false);
});
test('cancellation during failed-start diagnostics cannot replace unit_start_failed', async () => {
  const r = await syntheticHookFailure({ cancelQuery: 2 }); assert.equal(r.failure, 'unit_start_failed'); assert.equal(r.trace.filter(s => s === 'manager_start').length, 1); assertServiceCleanup(r.report, false);
});
for (const options of [{ collectorThrow: 'observe' }, { collectorThrow: 'unavailable', query: 'failed' }, { snapshotThrow: true }]) test(`all diagnostic collector failures remain non-authoritative ${JSON.stringify(options)}`, async () => {
  const r = await syntheticHookFailure(options); assert.equal(r.failure, 'unit_start_failed'); assertServiceCleanup(r.report, false);
});

for (const [freshChange, expected] of [['ownership', 'unit_link_identity'], ['active', 'unit_not_stopped'], ['pid', 'unit_not_stopped'], ['cancel', 'cancelled']]) test(`fresh pre-action guard refuses ${freshChange} after diagnostics without any start`, async () => {
  const r = await syntheticHookFailure({ freshChange }); assert.equal(r.failure, expected); assert.equal(r.trace.includes('manager_start'), false); assertServiceCleanup(r.report, false);
});


// These controls execute the actual bounded restart orchestration with synthetic
// observers. They do not activate a manager or grant process authority.
test('invocation property parsing returns a private canonical nonzero correlation value', () => {
  assert.equal(parseInvocationProperty('InvocationID=' + 'a'.repeat(32) + '\n'), 'a'.repeat(32));
});
for (const value of ['', 'InvocationID=\n', 'InvocationID=' + '0'.repeat(32) + '\n',
  'InvocationID=' + 'A'.repeat(32) + '\n', 'InvocationID=' + 'a'.repeat(31) + '\n',
  'InvocationID=' + 'a'.repeat(33) + '\n', 'InvocationID=' + 'a'.repeat(32),
  'InvocationID=' + 'a'.repeat(32) + '\r\n', 'InvocationID=' + 'a'.repeat(32) + '\nOther=private\n',
  Buffer.from('InvocationID=' + 'a'.repeat(32) + '\n'), { toString() { throw new Error('must not coerce'); } }]) {
  test(`invocation property refusal ${typeof value} ${typeof value === 'string' ? value.length : 'nonprimitive'}`, () => {
    assert.throws(() => parseInvocationProperty(value), { code: 'unit_invocation_invalid' });
  });
}
async function syntheticRestart(options = {}) {
  const source = await readFile(script, 'utf8');
  const reset = source.slice(source.indexOf('  function resetServiceCleanupEvidence()'), source.indexOf('  async function stopOwned()'));
  const same = source.slice(source.indexOf('  function sameLauncher('), source.indexOf('  async function ownedInvocation('));
  const body = source.slice(source.indexOf('  async function restartAndServe()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const oldLauncher = { pid: 1101, startTicks: '100', pidNamespace: 'synthetic-pid', networkNamespace: 'synthetic-net' };
  const newLauncher = { ...oldLauncher, pid: 1102, startTicks: '200' };
  const oldSession = { id: 'old', prefix: '/synthetic/runs/old', identity: { synthetic: true } };
  const report = { nativeSessionsStarted: 2, nativeSessionsStopped: 1, explicitReadinessPasses: 2,
    proxyBodyChecks: 2, uploadChecks: 2, streamChecks: 2, managerRestartCommands: 0, completedManagerRestarts: 0,
    journalChecks: 1, restartProof: { oldLauncherExited: false, oldNativeGroupsAbsent: false, freshSession: false, freshInvocation: false },
    cleanup: Object.fromEntries(serviceCleanupNames.map(k => [k, true])) };
  const trace = []; let cancelled = false, nativeReads = 0, journalReads = 0;
  const event = name => { trace.push(name); if (options.cancelAt === name) cancelled = true; };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const checkCancelled = () => { if (cancelled) reject('cancelled'); };
  const deps = {
    report, checkCancelled, sessions: options.noSession ? [] : [oldSession], prefix: '/synthetic', reject,
    node: '/synthetic/node', launcher: '/synthetic/launcher', env: {},
    cli: async (node, launcher, args) => { event('old_session_info'); assert.deepEqual(args, ['info']);
      return { stage: options.staleStage ? 'stopped' : 'running', session: options.staleCurrent ? 'changed' : 'old', sessionPrefix: options.stalePrefix ? '/synthetic/runs/changed' : oldSession.prefix }; },
    start: { step() {} },
    inspectMaster: async () => { event(++nativeReads === 1 ? 'native_initial' : 'native_final'); return options.missingNative ? null : oldSession.identity; },
    ownedInvocation: async () => { event(report.managerRestartCommands ? 'new_invocation' : 'old_invocation');
      return report.managerRestartCommands ? { id: (options.staleInvocation ? 'a' : 'b').repeat(32), launcher: newLauncher } : { id: 'a'.repeat(32), launcher: oldLauncher }; },
    verifyJournalForInvocation: async () => { const at = ++journalReads === 1 ? 'journal_before' : 'journal_after'; event(at);
      if (options.journalFailure === at) reject('journal_unconfirmed'); report.journalChecks++; },
    ownedProperties: async () => { event(report.managerRestartCommands ? 'properties_after' : 'properties_final');
      if (options.authorityFailure && !report.managerRestartCommands) reject('unit_link_identity');
      return { ActiveState: options.inactive ? 'inactive' : 'active', SubState: 'running', Result: 'success' }; },
    launcherIdentity: async () => { event(report.managerRestartCommands ? 'launcher_after' : 'launcher_final');
      return report.managerRestartCommands ? (options.reusedLauncher ? oldLauncher : newLauncher) : (options.changedLauncher ? newLauncher : oldLauncher); },
    unitName: 'fixture.service',
    systemctl: async (args, timeout) => { event('restart_command'); assert.deepEqual(args, ['restart', 'fixture.service']); assert.equal(timeout, 35000); return { ok: options.restartOK !== false }; },
    until: async fn => { event('retirement'); if (!await fn()) reject('observation_timeout'); },
    exitedLauncher: async identity => { event('old_launcher_exit'); assert.deepEqual(identity, oldLauncher); return !options.oldLauncherLive; },
    nativeStopped: async session => { event('old_native_exit'); assert.equal(session, oldSession); return !options.oldNativeLive; },
    observeActiveAndServe: async () => { event('new_serving'); report.nativeSessionsStarted++; report.explicitReadinessPasses++;
      report.proxyBodyChecks++; report.uploadChecks++; report.streamChecks++; return { id: options.reusedSession ? 'old' : 'new' }; },
  };
  const factory = new Function(...Object.keys(deps), `let lastSession = 'old'; ${reset}${same}${body}; return restartAndServe;`);
  let failure = null; try { await factory(...Object.values(deps))(); } catch (e) { failure = e.code; }
  return { report, failure, trace };
}
test('one manager restart verifies old retirement and fresh session before completion', async () => {
  const r = await syntheticRestart(); assert.equal(r.failure, null);
  assert.equal(r.report.managerRestartCommands, 1); assert.equal(r.report.completedManagerRestarts, 1);
  assert.equal(r.report.nativeSessionsStarted, 3); assert.equal(r.report.nativeSessionsStopped, 2);
  assert.equal(r.report.explicitReadinessPasses, 3); assert.equal(r.report.journalChecks, 3);
  assert(Object.values(r.report.restartProof).every(x => x === true)); assertServiceCleanup(r.report, false);
  assert(r.trace.indexOf('native_final') < r.trace.indexOf('properties_final'));
  assert(r.trace.indexOf('old_native_exit') < r.trace.indexOf('new_serving'));
  assert.equal(r.trace.filter(x => x === 'restart_command').length, 1);
});
for (const [option, expected] of [['noSession', 'restart_identity'], ['missingNative', 'restart_identity'],
  ['authorityFailure', 'unit_link_identity'], ['changedLauncher', 'restart_identity'], ['inactive', 'restart_identity'],
  ['staleCurrent', 'restart_identity'], ['staleStage', 'restart_identity'], ['stalePrefix', 'restart_identity']]) {
  test(`restart refuses ${option} before the single mutating request`, async () => {
    const r = await syntheticRestart({ [option]: true }); assert.equal(r.failure, expected);
    assert.equal(r.report.managerRestartCommands, 0); assert.equal(r.report.completedManagerRestarts, 0); assertServiceCleanup(r.report, false);
  });
}
for (const cancelAt of ['native_initial', 'journal_before', 'old_session_info', 'native_final', 'properties_final', 'launcher_final']) {
  test(`restart cancellation at ${cancelAt} prevents mutation`, async () => {
    const r = await syntheticRestart({ cancelAt }); assert.equal(r.failure, 'cancelled');
    assert.equal(r.report.managerRestartCommands, 0); assert.equal(r.report.completedManagerRestarts, 0); assertServiceCleanup(r.report, false);
  });
}
for (const cancelAt of ['restart_command', 'old_launcher_exit', 'new_serving', 'journal_after']) {
  test(`restart cancellation at ${cancelAt} cannot claim completion or repeat restart`, async () => {
    const r = await syntheticRestart({ cancelAt }); assert.equal(r.failure, 'cancelled');
    assert.equal(r.report.managerRestartCommands, 1); assert.equal(r.report.completedManagerRestarts, 0); assertServiceCleanup(r.report, false);
  });
}
for (const [options, code] of [[{ restartOK: false }, 'unit_restart_failed'], [{ oldLauncherLive: true }, 'observation_timeout'],
  [{ oldNativeLive: true }, 'observation_timeout'], [{ reusedLauncher: true }, 'restart_identity'],
  [{ reusedSession: true }, 'session_reused'], [{ staleInvocation: true }, 'unit_invocation_changed'],
  [{ journalFailure: 'journal_before' }, 'journal_unconfirmed'], [{ journalFailure: 'journal_after' }, 'journal_unconfirmed']]) {
  test(`restart incomplete refusal ${JSON.stringify(options)}`, async () => {
    const r = await syntheticRestart(options); assert.equal(r.failure, code); assert.equal(r.report.completedManagerRestarts, 0);
    assert(r.report.managerRestartCommands <= 1); assertServiceCleanup(r.report, false);
    if (options.oldLauncherLive || options.oldNativeLive) { assert.equal(r.report.nativeSessionsStopped, 1); assert.equal(r.report.nativeSessionsStarted, 2); }
  });
}
async function syntheticJournalGuard({ change = null, response = null, cancelled = false } = {}) {
  const source = await readFile(script, 'utf8');
  const same = source.slice(source.indexOf('  function sameLauncher('), source.indexOf('  async function ownedInvocation('));
  const body = source.slice(source.indexOf('  async function verifyJournalForInvocation('), source.indexOf('  async function restartAndServe('));
  const identity = { pid: 2201, startTicks: '10', pidNamespace: 'synthetic-pid', networkNamespace: 'synthetic-net' };
  const expected = { id: 'a'.repeat(32), launcher: identity }; let reads = 0, queryCalls = 0, didCancel = false;
  const report = { journalChecks: 0, journalRecordsObserved: 0, journalRunningMarkers: 0 };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const deps = { report, reject, JOURNAL_RESULT_CODES, unitName: 'fixture.service', process: { getuid: () => 1001 }, start: { step() {} },
    checkCancelled: () => { if (didCancel) reject('cancelled'); },
    ownedInvocation: async () => { reads++; return reads === 2 && change === 'invocation' ? { ...expected, id: 'b'.repeat(32) }
      : reads === 2 && change === 'launcher' ? { ...expected, launcher: { ...identity, startTicks: '11' } } : expected; },
    observeOwnedJournal: async () => { queryCalls++; didCancel = cancelled; return response || { ok: true, code: 'owned_journal_observed',
      journalReadabilityObserved: true, queryAttempts: 1, recordsObserved: 3, runningMarkers: 1 }; },
  };
  const factory = new Function(...Object.keys(deps), `${same}${body}; return verifyJournalForInvocation;`);
  let failure = null; try { await factory(...Object.values(deps))(expected); } catch (e) { failure = e.code; }
  return { report, failure, queryCalls };
}
test('guarded journal increments finite counts only after unchanged current invocation', async () => {
  const r = await syntheticJournalGuard(); assert.equal(r.failure, null); assert.deepEqual(r.report, { journalChecks: 1, journalRecordsObserved: 3, journalRunningMarkers: 1 });
});
for (const change of ['invocation', 'launcher']) test(`journal refuses changed ${change} after the read`, async () => {
  const r = await syntheticJournalGuard({ change }); assert.equal(r.failure, 'unit_invocation_changed'); assert.equal(r.report.journalChecks, 0); assert.equal(r.queryCalls, 1);
});
test('journal cancellation after query cannot increment verified counts', async () => {
  const r = await syntheticJournalGuard({ cancelled: true }); assert.equal(r.failure, 'cancelled'); assert.equal(r.report.journalChecks, 0);
});
for (const response of [{ ok: false }, { ok: true, code: 'wrong' },
  { ok: true, code: 'owned_journal_observed', journalReadabilityObserved: true, queryAttempts: 1, recordsObserved: 129, runningMarkers: 1 },
  { ok: true, code: 'owned_journal_observed', journalReadabilityObserved: true, queryAttempts: 1, recordsObserved: 1, runningMarkers: 2 }]) {
  test(`journal malformed summary cannot claim observation ${JSON.stringify(response)}`, async () => {
    const r = await syntheticJournalGuard({ response }); assert.equal(r.failure, 'journal_unconfirmed'); assert.equal(r.report.journalChecks, 0);
  });
}

for (const code of ['journal_empty', 'journal_record_limit', 'journal_unavailable']) test(`finite journal failure ${code} remains diagnostic without accepting a query`, async () => {
  const r = await syntheticJournalGuard({ response: { ok: false, code } });
  assert.equal(r.failure, code); assert.equal(r.report.journalChecks, 0);
});
test('unknown journal error code remains fixed and cannot publish private text', async () => {
  const r = await syntheticJournalGuard({ response: { ok: false, code: 'private-untrusted-path-or-message' } });
  assert.equal(r.failure, 'journal_unconfirmed'); assert.equal(r.report.journalChecks, 0);
});


// Production orchestration is exercised with independent synthetic transports;
// actual TLS handshakes and the real manager belong to separate required gates.
async function syntheticDownstreamTLS(options = {}) {
  const source = await readFile(script, 'utf8');
  const same = source.slice(source.indexOf('  function sameLauncher('), source.indexOf('  async function ownedInvocation('));
  const body = source.slice(source.indexOf('  async function verifyDownstreamTLS()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const report = { downstreamTLSActivated: true, downstreamTLSSessionChecks: 0, downstreamTLSBodyChecks: 0,
    downstreamTLSUploadChecks: 0, downstreamTLSStreamChecks: 0, downstreamTLS12Checks: 0, downstreamTLS13Checks: 0,
    downstreamTLSCertificateChecks: 0, downstreamTLSWrongCARefusals: 0, downstreamTLSWrongNameRefusals: 0 };
  const sessions = [1, 2, 3].map(i => ({ id: 'session' + i, prefix: '/synthetic/runs/session' + i, identity: { synthetic: i } }));
  const state = { index: 0, cancelled: false, probes: 0, refusals: 0, info: 0, invocations: 0 };
  const tlsFixture = { ca: Buffer.from('synthetic CA'), wrongCA: Buffer.from('synthetic other CA'), expectedCertificate: Buffer.from('synthetic DER') };
  const tlsSessions = new Set(options.duplicate ? ['session1'] : []), trace = [];
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const identity = { pid: 3301, startTicks: '10', pidNamespace: 'synthetic-pid', networkNamespace: 'synthetic-net' };
  const deps = { report, sessions, tlsFixture, tlsSessions, tlsPort: 10443, prefix: '/synthetic',
    node: '/synthetic/node', launcher: '/synthetic/launcher', env: {}, reject, start: { step() {} },
    checkCancelled: () => { if (state.cancelled) reject('cancelled'); },
    cli: async () => { state.info++; trace.push('info'); return { stage: 'running',
      session: options.changedSession && state.info % 2 === 0 ? 'foreign' : sessions[state.index].id,
      sessionPrefix: sessions[state.index].prefix }; },
    inspectMaster: async () => options.nativeMissing ? null : sessions[state.index].identity,
    ownedInvocation: async () => { state.invocations++; return { id: options.changedInvocation && state.invocations % 2 === 0 ? 'b'.repeat(32) : 'a'.repeat(32), launcher: identity }; },
    probeServiceTLS: async (port, route, value) => {
      state.probes++; trace.push(route + ':' + value.version); assert.equal(port, 10443); assert.equal(value.ca, tlsFixture.ca);
      assert.equal(value.expectedCertificate, tlsFixture.expectedCertificate); assert.equal(value.servername, 'localhost');
      if (options.probeFailure === state.probes) reject('tls_probe_timeout');
      if (options.cancelProbe === state.probes) state.cancelled = true;
      const response = route === '/echo' ? value.body : route === '/stream' ? Buffer.alloc(65537, 0x62) : Buffer.from('service-fixture\n');
      return { status: 200, body: options.badBody && state.probes === 1 ? Buffer.from('wrong') : response,
        protocol: options.badProtocol && state.probes === 1 ? 'TLSv1.3' : value.version,
        certificateMatched: options.badCertificate && state.probes === 1 ? false : true };
    },
    expectServiceTLSRefusal: async (_port, value) => {
      state.refusals++; trace.push('refusal');
      if (options.cancelRefusal === state.refusals) state.cancelled = true;
      return { ok: true, code: options.falseRefusal ? 'ECONNREFUSED' : value.ca === tlsFixture.wrongCA ? 'tls_ca_refused' : 'tls_hostname_refused' };
    },
  };
  const factory = new Function(...Object.keys(deps), `let lastSession = 'session1'; ${same}${body}; return { run: verifyDownstreamTLS, select(id) { lastSession = id; } };`);
  const controller = factory(...Object.values(deps)); let failure = null;
  try {
    for (let i = 0; i < (options.rounds || 1); i++) { state.index = i; controller.select(sessions[i].id); await controller.run(); }
  } catch (e) { failure = e.code; }
  return { report, failure, trace, state };
}
test('downstream TLS counts exact handshakes across apply, next start and restart sessions', async () => {
  const r = await syntheticDownstreamTLS({ rounds: 3 }); assert.equal(r.failure, null);
  assert.deepEqual(r.report, { downstreamTLSActivated: true, downstreamTLSSessionChecks: 3, downstreamTLSBodyChecks: 6,
    downstreamTLSUploadChecks: 3, downstreamTLSStreamChecks: 3, downstreamTLS12Checks: 3, downstreamTLS13Checks: 3,
    downstreamTLSCertificateChecks: 12, downstreamTLSWrongCARefusals: 3, downstreamTLSWrongNameRefusals: 3 });
  assert.equal(r.state.probes, 12); assert.equal(r.state.refusals, 6);
});
for (const [option, code] of [['duplicate', 'downstream_tls_session'], ['badBody', 'downstream_tls_body_mismatch'],
  ['badProtocol', 'downstream_tls_unconfirmed'], ['badCertificate', 'downstream_tls_unconfirmed'],
  ['changedSession', 'downstream_tls_session'], ['nativeMissing', 'downstream_tls_session'],
  ['changedInvocation', 'unit_invocation_changed'], ['falseRefusal', 'downstream_tls_ca_unconfirmed']]) {
  test(`downstream TLS refuses ${option} without a verified session`, async () => {
    const r = await syntheticDownstreamTLS({ [option]: true }); assert.equal(r.failure, code); assert.equal(r.report.downstreamTLSSessionChecks, 0);
    if (option === 'falseRefusal') assert.equal(r.report.downstreamTLSWrongCARefusals, 0);
  });
}
for (const probeFailure of [1, 2, 3, 4]) test(`downstream TLS transport failure at probe${probeFailure} is not a negative trust PASS`, async () => {
  const r = await syntheticDownstreamTLS({ probeFailure }); assert.equal(r.failure, 'tls_probe_timeout');
  assert.equal(r.report.downstreamTLSSessionChecks, 0); assert.equal(r.report.downstreamTLSWrongCARefusals, 0); assert.equal(r.report.downstreamTLSWrongNameRefusals, 0);
});
for (const cancelProbe of [1, 2, 3, 4]) test(`downstream TLS cancellation after probe${cancelProbe} cannot count that certificate or session`, async () => {
  const r = await syntheticDownstreamTLS({ cancelProbe }); assert.equal(r.failure, 'cancelled');
  assert.equal(r.report.downstreamTLSCertificateChecks, cancelProbe - 1); assert.equal(r.report.downstreamTLSSessionChecks, 0);
});
for (const cancelRefusal of [1, 2]) test(`downstream TLS cancellation after refusal${cancelRefusal} cannot claim that refusal`, async () => {
  const r = await syntheticDownstreamTLS({ cancelRefusal }); assert.equal(r.failure, 'cancelled'); assert.equal(r.report.downstreamTLSSessionChecks, 0);
  assert.equal(cancelRefusal === 1 ? r.report.downstreamTLSWrongCARefusals : r.report.downstreamTLSWrongNameRefusals, 0);
});
test('TLS listener absence is a fresh cleanup confirmation after actual stop', async () => {
  const r = await syntheticOwnedStop({ tlsPort: 3 }); assert.equal(r.code, null); assert.equal(r.report.cleanup.downstreamTLSPortClosed, true); assertServiceCleanup(r.report, true);
});
test('unknown or still-live TLS listener refuses cleanup and clears prior confirmations', async () => {
  const prior = await syntheticOwnedStop({ tlsPort: 3 });
  assert.equal(prior.report.cleanup.downstreamTLSPortClosed, true);
  const r = await syntheticOwnedStop({ report: prior.report, tlsPort: 3, failure: 'tls_port' }); assert.equal(r.code, 'service_resources_live');
  assert.equal(r.report.cleanup.downstreamTLSPortClosed, false); assertServiceCleanup(r.report, false);
});

const originRevision = 'c'.repeat(32), originRestored = 'd'.repeat(32), originFailed = 'e'.repeat(32);
function rejectedOriginRecord(change = {}, value = {}) {
  return { ok: false, exitCode: 1, termination: 'exit_nonzero', stderr: '',
    stdout: JSON.stringify({ ok: false, outcome: 'rolled_back', revision: originRestored,
      failedRevision: originFailed, restoredContentFrom: originRevision, reason: 'private reason not returned', ...value }), ...change };
}
test('expected-origin adapter accepts only explicit rollback and keeps raw details private', () => {
  assert.deepEqual(assessRejectedOriginApply(rejectedOriginRecord(), originRevision), { revision: originRestored, restoredContentFrom: originRevision });
});
for (const [name, record] of Object.entries({ success: rejectedOriginRecord({ ok: true }), zero: rejectedOriginRecord({ exitCode: 0 }),
  timeout: rejectedOriginRecord({ termination: 'timeout_or_killed' }), signal: rejectedOriginRecord({ termination: 'signal' }),
  stderr: rejectedOriginRecord({ stderr: 'private' }), malformed: rejectedOriginRecord({ stdout: '{' }), huge: rejectedOriginRecord({ stdout: 'x'.repeat(262145) }),
  rejected: rejectedOriginRecord({}, { outcome: 'rejected' }), noOutcome: rejectedOriginRecord({}, { outcome: undefined }), wrongPrior: rejectedOriginRecord({}, { restoredContentFrom: 'a'.repeat(32) }),
  staleRevision: rejectedOriginRecord({}, { revision: originRevision }), sameFailed: rejectedOriginRecord({}, { revision: originFailed }),
  missingFailed: rejectedOriginRecord({}, { failedRevision: undefined }), upperRevision: rejectedOriginRecord({}, { revision: originRestored.toUpperCase() }) })) {
  test(`expected-origin adapter refuses ${name}`, () => assert.throws(() => assessRejectedOriginApply(record, originRevision), { code: 'upstream_tls_rollback_unconfirmed' }));
}

async function syntheticUpstreamSession(options = {}) {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('  async function verifyUpstreamTLS()'), source.indexOf('  async function currentOriginAuthority('));
  const same = source.slice(source.indexOf('  function sameLauncher('), source.indexOf('  async function ownedInvocation('));
  const report = { upstreamTLSActivated: true, upstreamTLSSessionChecks: 0, upstreamTLSBodyChecks: 0, upstreamTLSUploadChecks: 0, upstreamTLSStreamChecks: 0 };
  const sessions = [1, 2, 3].map(i => ({ id: 'session' + i })), originSessions = new Set(options.duplicate ? ['session1'] : []);
  const state = { cancelled: false, requests: 0, authorities: 0, index: 0 };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const identity = { pid: 1, startTicks: '10', pidNamespace: 'p', networkNamespace: 'n' };
  const deps = { report, sessions, originSessions, origin: {}, gatewayPort: 10080, start: { step() {} }, reject,
    checkCancelled: () => { if (state.cancelled) reject('cancelled'); },
    currentOriginAuthority: async () => { state.authorities++; if (options.authorityFailure) reject('unit_fragment_identity');
      return { id: options.changedInvocation && state.authorities % 2 === 0 ? 'b' : 'a', launcher: identity }; },
    request: async (_port, route = '/', body = Buffer.alloc(0)) => { state.requests++; if (options.cancelAt === state.requests) state.cancelled = true;
      if (options.requestFailure === state.requests) reject('observation_timeout');
      return { status: options.badStatus ? 502 : 200, body: options.badBody ? Buffer.from('wrong') : route === '/echo' ? body : route === '/stream' ? Buffer.alloc(65537, 0x62) : Buffer.from('service-fixture\n') }; },
  };
  const factory = new Function(...Object.keys(deps), `let lastSession = 'session1'; ${same}${body}; return { run: verifyUpstreamTLS, select(id) { lastSession = id; } };`);
  const actual = factory(...Object.values(deps)); let failure = null;
  try { for (let i = 0; i < (options.rounds || 1); i++) { actual.select(sessions[i].id); await actual.run(); } } catch (e) { failure = e.code; }
  return { report, state, failure };
}
test('combined origin checks count exactly apply, next start and manager restart sessions', async () => {
  const r = await syntheticUpstreamSession({ rounds: 3 }); assert.equal(r.failure, null);
  assert.deepEqual(r.report, { upstreamTLSActivated: true, upstreamTLSSessionChecks: 3, upstreamTLSBodyChecks: 3, upstreamTLSUploadChecks: 3, upstreamTLSStreamChecks: 3 });
  assert.equal(r.state.requests, 9);
});
for (const [option, code] of [['duplicate', 'upstream_tls_session'], ['badStatus', 'upstream_tls_unconfirmed'], ['badBody', 'upstream_tls_unconfirmed'],
  ['changedInvocation', 'unit_invocation_changed'], ['authorityFailure', 'unit_fragment_identity']]) test(`combined origin session refuses ${option}`, async () => {
  const r = await syntheticUpstreamSession({ [option]: true }); assert.equal(r.failure, code); assert.equal(r.report.upstreamTLSSessionChecks, 0);
});
for (const cancelAt of [1, 2, 3]) test(`combined origin cancel after I/O${cancelAt} does not count session or that operation`, async () => {
  const r = await syntheticUpstreamSession({ cancelAt }); assert.equal(r.failure, 'cancelled'); assert.equal(r.report.upstreamTLSSessionChecks, 0);
  assert.equal([r.report.upstreamTLSBodyChecks, r.report.upstreamTLSUploadChecks, r.report.upstreamTLSStreamChecks][cancelAt - 1], 0);
});
for (const requestFailure of [1, 2, 3]) test(`combined origin I/O${requestFailure} transport failure is not accepted`, async () => {
  const r = await syntheticUpstreamSession({ requestFailure }); assert.equal(r.failure, 'observation_timeout'); assert.equal(r.report.upstreamTLSSessionChecks, 0);
});

async function syntheticOriginRefusals(options = {}) {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('  async function verifyOriginRefusals()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const same = source.slice(source.indexOf('  function sameLauncher('), source.indexOf('  async function ownedInvocation('));
  const report = { upstreamTLSWrongCARefusals: 0, upstreamTLSWrongNameRefusals: 0, upstreamTLSPlaintextRefusals: 0,
    upstreamTLSRollbackChecks: 0, upstreamTLSCandidate502Checks: 0, upstreamTLSNoPostReplayChecks: 0 };
  const state = { cancelled: false, commands: 0, probes: 0, requests: 0, guards: 0, writes: 0, reset: 0, tag: null, counted: new Set(), revision: originRevision };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const identity = { pid: 1, startTicks: '10', pidNamespace: 'p', networkNamespace: 'n' };
  const origin = { port: 10444, ca: Buffer.from('originCA'), expectedCertificate: Buffer.from('originDER'),
    candidate(value) { state.tag = value.tag; assert.match(value.tag, /^[a-f0-9]{32}$/); return { serverBody: 'synthetic input', healthURL: 'http://127.0.0.1:10081/tls-probe/' + value.tag }; },
    count502(tag) { return options.stale502 ? 1 : state.counted.has(tag) ? 1 : 0; },
    counts: () => ({ echoRequests: options.replay && state.commands > 0 ? 1 : 0 }) };
  const deps = { report, origin, tlsFixture: { ca: Buffer.from('downstreamCA'), certificate: 'private cert', certificateKey: 'private key', expectedCertificate: Buffer.from('downstreamDER') },
    tlsPort: 10443, gatewayPort: 10080, parent: '/synthetic', node: '/synthetic/node', launcher: '/synthetic/launcher', env: {},
    sessions: [{ id: 'session1' }], lastSession: 'session1', start: { step() {} }, reject, constants: { O_WRONLY: 1, O_CREAT: 2, O_EXCL: 4, O_NOFOLLOW: 8 }, assessRejectedOriginApply,
    resetServiceCleanupEvidence: () => { state.reset++; }, checkCancelled: () => { if (state.cancelled) reject('cancelled'); },
    randomBytes: () => Buffer.alloc(16, state.commands + 1),
    open: async (_file, flags, mode) => { assert.equal(flags, 15); assert.equal(mode, 0o600); state.writes++; return { async writeFile() {}, async sync() {}, async close() {} }; },
    probeServiceTLS: async (port) => { state.probes++; if (options.cancelProbe === state.probes) state.cancelled = true;
      if (options.originUnreachable && port === origin.port) reject('tls_probe_timeout');
      return { status: options.restoredTLSBad && port === 10443 ? 502 : 200, body: Buffer.from('service-fixture\n'), certificateMatched: true, protocol: 'TLSv1.3' }; },
    currentOriginAuthority: async () => { state.guards++; if (options.guardFailure) reject('unit_fragment_identity');
      return { id: options.changedInvocation && state.guards === 2 ? 'changed' : 'same', launcher: identity }; },
    command: async (_file, args) => { assert.deepEqual(args.slice(0, 3), ['/synthetic/launcher', 'apply', '--file']); state.commands++;
      if (options.cancelCommand) state.cancelled = true;
      if (!options.missing502) state.counted.add(state.tag);
      const prior = state.revision; state.revision = String(state.commands + 3).repeat(32);
      return rejectedOriginRecord(options.commandFailure ? { exitCode: null, termination: 'timeout_or_killed' } : {}, { revision: state.revision, restoredContentFrom: options.wrongPrior ? 'f'.repeat(32) : prior }); },
    cli: async () => ({ lastConfirmedRevision: options.wrongStatus ? 'f'.repeat(32) : state.revision, binding: {}, runtime: { identityValid: true } }),
    request: async () => { state.requests++; return { status: options.restoreBad ? 502 : 200, body: Buffer.from('service-fixture\n') }; },
  };
  const factory = new Function(...Object.keys(deps), `let goodOriginRevision = '${originRevision}'; ${same}${body}; return verifyOriginRefusals;`);
  let failure = null; try { await factory(...Object.values(deps))(); } catch (e) { failure = e.code; }
  return { report, state, failure };
}
test('three origin refusal classes require exact rollback plus matched502 and both restored paths', async () => {
  const r = await syntheticOriginRefusals(); assert.equal(r.failure, null);
  assert.deepEqual(r.report, { phase: 'origin_negative', upstreamTLSWrongCARefusals: 1, upstreamTLSWrongNameRefusals: 1, upstreamTLSPlaintextRefusals: 1,
    upstreamTLSRollbackChecks: 3, upstreamTLSCandidate502Checks: 3, upstreamTLSNoPostReplayChecks: 3 });
  assert.equal(r.state.commands, 3); assert.equal(r.state.probes, 6); assert.equal(r.state.requests, 3); assert.equal(r.state.reset, 3);
});
for (const [option, code] of [['originUnreachable', 'tls_probe_timeout'], ['guardFailure', 'unit_fragment_identity'],
  ['commandFailure', 'upstream_tls_rollback_unconfirmed'], ['missing502', 'upstream_tls_candidate_unconfirmed'], ['stale502', 'upstream_tls_candidate_unconfirmed'],
  ['wrongPrior', 'upstream_tls_rollback_unconfirmed'], ['wrongStatus', 'upstream_tls_rollback_unconfirmed'], ['restoreBad', 'upstream_tls_rollback_unconfirmed'],
  ['restoredTLSBad', 'upstream_tls_rollback_unconfirmed'], ['replay', 'upstream_tls_replay'], ['changedInvocation', 'unit_invocation_changed'], ['cancelCommand', 'cancelled']]) {
  test(`origin negative control refuses ${option} without counting trust failure`, async () => {
    const r = await syntheticOriginRefusals({ [option]: true }); assert.equal(r.failure, code); assert.equal(r.report.upstreamTLSRollbackChecks, 0);
    assert.equal(r.report.upstreamTLSWrongCARefusals, 0); if (['originUnreachable', 'guardFailure'].includes(option)) assert.equal(r.state.commands, 0);
  });
}
for (const cancelProbe of [1, 2]) test(`origin negative cancel after probe${cancelProbe} cannot count rollback`, async () => {
  const r = await syntheticOriginRefusals({ cancelProbe }); assert.equal(r.failure, 'cancelled'); assert.equal(r.report.upstreamTLSRollbackChecks, 0);
  if (cancelProbe === 1) assert.equal(r.state.commands, 0);
});

async function syntheticOriginCleanup(options = {}) {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('    if (origin) {\n      report.cleanup.upstreamTLSPortClosed'), source.indexOf('    report.cleanup.appSocketsRemaining = sockets.size;'));
  const report = { ok: true, cleanup: { upstreamTLSPortClosed: true, readinessRelayPortClosed: true, upstreamTLSOriginClosed: true, readinessRelayClosed: true } };
  const state = { errors: 0, ports: [] };
  const deps = { report, originCreationRequested: options.creationFailed === true, reject: code => { throw Object.assign(new Error(code), { code }); },
    failures: { cleanup() { state.errors++; } },
    origin: options.creationFailed ? null : { port: 10444, readyPort: 10081, close: async () => {
      if (options.closeThrow) throw Object.assign(new Error('private'), { code: 'origin_cleanup_unconfirmed' });
      return { originClosed: !options.originLive, relayClosed: !options.relayLive, originPortClosed: !options.originPortLive, relayPortClosed: !options.relayPortLive }; } },
    closedPort: async port => { state.ports.push(port); return port === 10444 ? !options.independentOriginLive : !options.independentRelayLive; } };
  const f = new Function(...Object.keys(deps), `return (async () => { let originCleanupSafe = false; ${body}; return originCleanupSafe; })();`);
  const safe = await f(...Object.values(deps));
  // The extracted block contains awaits, so invoke it in its own async boundary.
  return { report, state, safe };
}

test('owned origin and relay closure require both server and independent port observations', async () => {
  const r = await syntheticOriginCleanup(); assert.equal(r.safe, true); assert.equal(r.state.errors, 0);
  assert.deepEqual(r.state.ports, [10444, 10081]); assert.equal(Object.values(r.report.cleanup).every(v => v === true), true);
});
for (const option of ['originLive', 'relayLive', 'originPortLive', 'relayPortLive', 'independentOriginLive', 'independentRelayLive', 'closeThrow']) {
  test(`origin closure refuses ${option} and clears stale cleanup proof`, async () => {
    const r = await syntheticOriginCleanup({ [option]: true }); assert.equal(r.safe, false); assert.equal(r.state.errors, 1);
    assert.equal(r.report.ok, false); assert.equal(Object.values(r.report.cleanup).every(v => v === false), true);
  });
}
test('partial origin creation without confirmed handle retains private root', async () => {
  const r = await syntheticOriginCleanup({ creationFailed: true }); assert.equal(r.safe, false); assert.equal(r.report.ok, false); assert.equal(r.state.errors, 1);
});

async function syntheticOriginAuthority(options = {}) {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('  async function currentOriginAuthority('), source.indexOf('  async function verifyOriginRefusals('));
  const known = { id: 'session1', prefix: '/synthetic/runs/session1', identity: { synthetic: true } };
  const state = { cancelled: false, info: 0, native: 0, owned: 0 }, reject = code => { throw Object.assign(new Error(code), { code }); };
  const deps = { prefix: '/synthetic', node: '/synthetic/node', launcher: '/synthetic/launcher', env: {}, reject,
    checkCancelled: () => { if (state.cancelled || options.cancelBefore) reject('cancelled'); },
    cli: async () => { state.info++; if (options.cancelInfo) state.cancelled = true; return { stage: options.wrongStage ? 'stopped' : 'running', session: options.wrongSession ? 'other' : known.id, sessionPrefix: options.wrongPrefix ? '/foreign' : known.prefix }; },
    inspectMaster: async (binary, prefix, identity) => { state.native++; assert.equal(binary, '/synthetic/bin/nginx'); assert.equal(prefix, known.prefix); assert.equal(identity, known.identity);
      if (options.cancelNative) state.cancelled = true; return options.nativeMissing ? null : known.identity; },
    ownedInvocation: async () => { state.owned++; if (state.cancelled) reject('cancelled'); if (options.unitChanged) reject('unit_fragment_identity'); return { synthetic: true }; } };
  const f = new Function(...Object.keys(deps), `${body}; return currentOriginAuthority;`);
  let failure = null, result; try { result = await f(...Object.values(deps))(options.noKnown ? null : known); } catch (e) { failure = e.code; }
  return { failure, result, state };
}
test('fresh origin authority checks exact current session/native then owned active invocation', async () => {
  const r = await syntheticOriginAuthority(); assert.equal(r.failure, null); assert.deepEqual(r.result, { synthetic: true }); assert.equal(r.state.owned, 1);
});
for (const [option, code] of [['noKnown', 'upstream_tls_session'], ['wrongStage', 'upstream_tls_session'], ['wrongSession', 'upstream_tls_session'],
  ['wrongPrefix', 'upstream_tls_session'], ['nativeMissing', 'upstream_tls_session'], ['cancelBefore', 'cancelled'], ['cancelInfo', 'cancelled'],
  ['cancelNative', 'cancelled'], ['unitChanged', 'unit_fragment_identity']]) test(`fresh origin authority refuses ${option} before admitted mutation`, async () => {
  const r = await syntheticOriginAuthority({ [option]: true }); assert.equal(r.failure, code); assert.equal(r.result, undefined);
});

const failureHook = (changes = {}) => {
  const v = { node: '/synthetic/node', launcher: '/synthetic/install/bin/x10', start: 'Sun 2026-10-25 11:00:00 UTC', stop: 'Sun 2026-10-25 11:00:03 UTC', pid: '1234', code: 'exited', status: '1', ...changes };
  return `ExecStartPost={ path=${v.node} ; argv[]=${v.node} ${v.launcher} wait-bind --timeout-ms 10000 ; ignore_errors=no ; start_time=[${v.start}] ; stop_time=[${v.stop}] ; pid=${v.pid} ; code=${v.code} ; status=${v.status} }\n`;
};
const failedCommand = { ok: false, exitCode: 1, termination: 'exit_nonzero', stdout: '', stderr: 'unit start refused\n' };
const failedProps = { LoadState: 'loaded', ActiveState: 'failed', SubState: 'failed', Result: 'exit-code', MainPID: '0' };
const failedExpected = { nodeExecutable: '/synthetic/node', launcher: '/synthetic/install/bin/x10', hookPID: 1234 };
test('expected readiness refusal requires fresh captured hook PID and exact failed state', () => {
  assert.deepEqual(parseFailedStartIdentity(`InvocationID=${'a'.repeat(32)}\nControlPID=1234\n`), { invocation: 'a'.repeat(32), hookPID: 1234 });
  assert.equal(assessFailedReadinessStart(failedCommand, failedProps, failureHook(), failedExpected), true);
  assert.equal(assessFailedReadinessStart(failedCommand, failedProps, failureHook({ status: '1/FAILURE' }), failedExpected), true);
});
for (const [name, text] of Object.entries({ missing: 'ControlPID=1234\n', zero: `InvocationID=${'0'.repeat(32)}\nControlPID=1234\n`, zeroPID: `InvocationID=${'a'.repeat(32)}\nControlPID=0\n`, reusedKey: 'ControlPID=1234\nControlPID=1235\n', upper: `InvocationID=${'A'.repeat(32)}\nControlPID=1234\n`, huge: `InvocationID=${'a'.repeat(32)}\nControlPID=2147483648\n`, trailing: `InvocationID=${'a'.repeat(32)}\nControlPID=1234\n\n` })) {
  test(`failed-start identity refuses ${name}`, () => assert.throws(() => parseFailedStartIdentity(text), { code: 'failed_start_unconfirmed' }));
}
for (const [name, change] of Object.entries({ success: { ok: true, exitCode: 0 }, timeout: { termination: 'timeout_or_killed', exitCode: null }, signal: { termination: 'signal' }, unresolved: { termination: 'unknown' }, unavailable: { termination: 'unavailable' }, otherExit: { exitCode: 2 }, output: { stdout: 'x'.repeat(256 * 1024 + 1) }, noString: { stderr: null } })) {
  test(`expected startup refusal rejects command ${name}`, () => assert.throws(() => assessFailedReadinessStart({ ...failedCommand, ...change }, failedProps, failureHook(), failedExpected), { code: 'failed_start_unconfirmed' }));
}
for (const [name, change] of Object.entries({ live: { MainPID: '1234' }, inactive: { ActiveState: 'inactive' }, activating: { ActiveState: 'activating' }, dead: { SubState: 'dead' }, timeout: { Result: 'timeout' }, protocol: { Result: 'protocol' }, missing: { LoadState: 'not-found' } })) {
  test(`expected startup refusal rejects unit ${name}`, () => assert.throws(() => assessFailedReadinessStart(failedCommand, { ...failedProps, ...change }, failureHook(), failedExpected), { code: 'failed_start_unconfirmed' }));
}
for (const [name, change] of Object.entries({ wrongPID: { pid: '1235' }, noPID: { pid: '0' }, noTime: { start: 'n/a' }, noStop: { stop: 'n/a' }, signal: { code: 'killed', status: '15/TERM' }, success: { status: '0' }, otherExit: { status: '2' }, wrongSuffix: { status: '1/TERM' }, wrongNode: { node: '/other/node' }, wrongLauncher: { launcher: '/other/bin/x10' } })) {
  test(`expected startup refusal rejects hook ${name}`, () => assert.throws(() => assessFailedReadinessStart(failedCommand, failedProps, failureHook(change), failedExpected), { code: 'failed_start_unconfirmed' }));
}
test('failed-start assessors refuse getters without invoking them', () => {
  let invoked = 0; const r = { ...failedCommand }; Object.defineProperty(r, 'ok', { get() { invoked++; return false; } });
  assert.throws(() => assessFailedReadinessStart(r, failedProps, failureHook(), failedExpected), { code: 'failed_start_unconfirmed' }); assert.equal(invoked, 0);
});

test('failed-start pristine invocation query explicitly prints empty id128 rather than inventing zero bytes', async () => {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('  async function verifyFailedReadinessStart()'), source.indexOf('  async function startAndServe()'));
  assert(body.includes("['show', unitName, '--all', '--property=InvocationID']"));
  assert(body.includes("prior.stdout !== 'InvocationID=\\n'"));
  assert(!body.includes("prior.stdout !== `InvocationID=${'0'.repeat(32)}"));
});

for (const cancellationPoint of ['owned_properties', 'pristine_query']) {
  test(`failed-start cancellation during ${cancellationPoint} cannot issue a new manager start`, async () => {
    const source = await readFile(script, 'utf8');
    const body = source.slice(source.indexOf('  async function verifyFailedReadinessStart()'), source.indexOf('  async function startAndServe()'));
    let cancelled = false; const calls = [];
    const refuse = code => { throw Object.assign(new Error(code), { code }); };
    const factory = new Function('resetServiceCleanupEvidence', 'checkCancelled', 'ownedProperties', 'systemctl', 'unitName', 'reject', `${body}; return verifyFailedReadinessStart;`);
    const verify = factory(() => {}, () => { if (cancelled) refuse('cancelled'); },
      async () => { calls.push('owned_properties'); if (cancellationPoint === 'owned_properties') cancelled = true; return { ActiveState: 'inactive', MainPID: '0' }; },
      async args => { calls.push(args[0]); assert.deepEqual(args, ['show', 'fixture.service', '--all', '--property=InvocationID']); if (cancellationPoint === 'pristine_query') cancelled = true; return { ok: true, stderr: '', stdout: 'InvocationID=\n' }; },
      'fixture.service', refuse);
    await assert.rejects(verify(), { code: 'cancelled' });
    assert.equal(calls.includes('start'), false); assert.equal(calls.includes('reset-failed'), false);
  });
}

const pausedDrain = { paused: true, complete: false, failed: false, tlsVerified: true, requestClosed: false, responseIncomplete: true };
const heldDrain = { requested: true, held: true, released: false, completed: false, aborted: false, closed: false };
test('controlled drain requires a still-open verified paused client and unreleased owned origin response', () => {
  assert.equal(assessControlledDrainHold(pausedDrain, heldDrain, false), true);
  assert.equal(assessControlledDrainResult({ ok: true, complete: true, certificateMatched: true, protocol: 'TLSv1.3', body: Buffer.alloc(65537, 0x62) }), true);
});
for (const key of Object.keys(pausedDrain)) {
  test(`controlled drain refuses client ${key} drift or unknown`, () => {
    for (const value of [!pausedDrain[key], undefined, null, 1, 'true']) assert.throws(() => assessControlledDrainHold({ ...pausedDrain, [key]: value }, heldDrain, false), { code: 'controlled_drain_unconfirmed' });
  });
}
for (const key of Object.keys(heldDrain)) {
  test(`controlled drain refuses origin ${key} drift or unknown`, () => {
    for (const value of [!heldDrain[key], undefined, null, 1, 'false']) assert.throws(() => assessControlledDrainHold(pausedDrain, { ...heldDrain, [key]: value }, false), { code: 'controlled_drain_unconfirmed' });
  });
}
test('controlled drain refuses completed or unresolved stop promises before release', () => {
  for (const settled of [true, undefined, null, 0, 'false']) assert.throws(() => assessControlledDrainHold(pausedDrain, heldDrain, settled), { code: 'controlled_drain_unconfirmed' });
});
for (const [name, change] of Object.entries({ partial: { complete: false }, falseSuccess: { ok: false }, wrongCertificate: { certificateMatched: false }, wrongProtocol: { protocol: 'TLSv1.2' }, short: { body: Buffer.alloc(65536, 0x62) }, corrupt: { body: Buffer.alloc(65537, 0x61) }, nonBuffer: { body: 'b'.repeat(65537) } })) {
  test(`controlled drain refuses completed payload ${name}`, () => assert.throws(() => assessControlledDrainResult({ ok: true, complete: true, certificateMatched: true, protocol: 'TLSv1.3', body: Buffer.alloc(65537, 0x62), ...change }), { code: 'controlled_drain_unconfirmed' }));
}
test('controlled drain assessment refuses hostile getter values without evaluation', () => {
  let invoked = false; const value = { ...pausedDrain }; Object.defineProperty(value, 'paused', { get() { invoked = true; return true; } });
  assert.throws(() => assessControlledDrainHold(value, heldDrain, false), { code: 'controlled_drain_unconfirmed' }); assert.equal(invoked, false);
});

test('controlled drain rejects a queued continuation after its successful observation deadline without releasing response', async () => {
  const source = await readFile(script, 'utf8');
  const body = source.slice(source.indexOf('  async function verifyControlledSlowDrain()'), source.indexOf("  process.once('SIGINT', cancel)"));
  const proofKeys = ['clientPaused', 'originResponseHeld', 'sameSessionObserved', 'managerStopPending', 'nativeGroupLiveDuringStop', 'unitDeactivatingObserved', 'incompleteResponseObserved', 'payloadCompleted', 'tlsVerified', 'managerStopCompleted', 'launcherExited', 'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent'];
  const report = { upstreamTLSActivated: true, downstreamTLSActivated: true, controlledSlowDrainChecks: 0,
    controlledSlowDrainProof: Object.fromEntries(proofKeys.map(key => [key, false])) };
  let clock = 0, stopCalls = 0, stopTerminal = false, releaseCalls = 0, resumeCalls = 0, aborted = false, cancelled = false, resolveStop;
  const held = { path: '/slow-stream/' + 'c'.repeat(32), prefixBytes: 4096, totalBytes: 65537,
    snapshot: () => ({ ...heldDrain }), release() { releaseCalls++; return true; },
    async abort() { aborted = true; stopTerminal = true; resolveStop(); return true; } };
  const client = { snapshot: () => ({ ...pausedDrain }), async resume() { resumeCalls++; throw new Error('resume must not run'); }, async cancel() { cancelled = true; return true; } };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const authority = { id: 'b'.repeat(32), launcher: {} }, known = { id: 'a'.repeat(32) };
  const env = { report, origin: { prepareDrain: () => held }, tlsFixture: { ca: Buffer.from('public'), expectedCertificate: Buffer.from('public') },
    sessions: [known], lastSession: known.id, currentOriginAuthority: async () => authority, checkCancelled() {}, reject,
    createPausedTLSClient: async () => client, tlsPort: 12345, assessControlledDrainHold, assessControlledDrainResult,
    sameLauncher: (a, b) => a === b,
    stopOwned: async () => { stopCalls++; return new Promise(resolve => { resolveStop = resolve; }); },
    performance: { now: () => clock },
    // Simulate an already successful observation callback whose awaiting
    // continuation runs late; callback internals are covered separately.
    until: async (_callback, budget) => { assert.equal(budget, 1000); queueMicrotask(() => { clock = 1001; }); },
    failures: { cleanup() { assert.fail('owned cleanup is expected to succeed'); } } };
  const verify = new Function(...Object.keys(env), `${body}; return verifyControlledSlowDrain;`)(...Object.values(env));
  await assert.rejects(verify(), { code: 'controlled_drain_unconfirmed' });
  assert.equal(releaseCalls, 0); assert.equal(resumeCalls, 0); assert.equal(report.controlledSlowDrainChecks, 0);
  assert.equal(stopCalls, 1); assert.equal(stopTerminal, true); assert.equal(aborted, true); assert.equal(cancelled, true);
});

const interruptionHold = { held: true, requested: true, candidateReadyObserved: true, nativeProbeChecks: 1, heldResponses: 1, aborted: false, closed: false, released: false };
const interruptedPrevious = '1'.repeat(32), interruptedCandidate = '2'.repeat(32), interruptedRestored = '3'.repeat(32);
const recoveredInterruption = change => ({ ok: false, exitCode: 1, termination: 'exit_nonzero', stderr: '', stdout: JSON.stringify({ ok: false, outcome: 'rolled_back', reason: 'explicit_recovery', failedRevision: interruptedCandidate, restoredContentFrom: interruptedPrevious, revision: interruptedRestored, ...change }) });
test('interrupted operator recovery accepts only explicit failed apply rollback relationship', () => {
  assert.deepEqual(assessInterruptedRecovery(recoveredInterruption(), interruptedPrevious, interruptedCandidate), { revision: interruptedRestored });
  assert.equal(assessInterruptedProbeHold(interruptionHold), true);
});
for (const key of ['held', 'requested', 'candidateReadyObserved', 'aborted', 'closed', 'released']) {
  test(`interrupted operator refuses readiness hold ${key} drift`, () => {
    for (const value of [!interruptionHold[key], undefined, null, 1, 'true']) assert.throws(() => assessInterruptedProbeHold({ ...interruptionHold, [key]: value }), { code: 'operator_interruption_unconfirmed' });
  });
}
for (const key of ['nativeProbeChecks', 'heldResponses']) {
  test(`interrupted operator refuses readiness hold ${key} unknown or bounds`, () => {
    for (const value of [0, 9, -1, 1.5, undefined, null, '1']) assert.throws(() => assessInterruptedProbeHold({ ...interruptionHold, [key]: value }), { code: 'operator_interruption_unconfirmed' });
  });
}
for (const [name, change] of Object.entries({ successfulApply: { ok: true, outcome: 'applied' }, missingReason: { reason: undefined }, timeoutReason: { reason: 'timeout' }, reconciled: { outcome: 'reconciled' }, wrongCandidate: { failedRevision: '4'.repeat(32) }, wrongContent: { restoredContentFrom: interruptedCandidate }, oldRevision: { revision: interruptedPrevious }, candidateRevision: { revision: interruptedCandidate }, malformedRevision: { revision: 'unknown' } })) {
  test(`interrupted operator refuses recovery ${name}`, () => assert.throws(() => assessInterruptedRecovery(recoveredInterruption(change), interruptedPrevious, interruptedCandidate), { code: 'operator_interruption_unconfirmed' }));
}
for (const [name, change] of Object.entries({ zeroExit: { exitCode: 0 }, unknownExit: { exitCode: null }, wrongExit: { exitCode: 2 }, timeout: { termination: 'timeout_or_killed' }, killed: { termination: 'signal' }, unknown: { termination: 'unknown' }, stderr: { stderr: 'diagnostic' }, missing: { stdout: '' }, badJSON: { stdout: '{' } })) {
  test(`interrupted operator refuses command ${name}`, () => assert.throws(() => assessInterruptedRecovery({ ...recoveredInterruption(), ...change }, interruptedPrevious, interruptedCandidate), { code: 'operator_interruption_unconfirmed' }));
}
test('interrupted operator pure assessors do not invoke hostile getters', () => {
  let called = false; const hold = { ...interruptionHold }; Object.defineProperty(hold, 'held', { get() { called = true; return true; } });
  assert.throws(() => assessInterruptedProbeHold(hold), { code: 'operator_interruption_unconfirmed' }); assert.equal(called, false);
});

test('interrupted apply does not renew held-probe authority through a late queued continuation', async () => {
  const source = await readFile(script, 'utf8');
  const fn = source.slice(source.indexOf('  async function verifyOperatorInterruption()'), source.indexOf('  async function verifyControlledSlowDrain()'));
  const isHeld = fn.slice(fn.indexOf('    const isHeld ='), fn.indexOf('    try {\n      held = origin.prepareReadinessHold', fn.indexOf('    const isHeld =')));
  const observation = fn.slice(fn.indexOf('      await until('), fn.indexOf('      if (!captured ||', fn.indexOf('      await until(')));
  let clock = 0, captureCalls = 0;
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  const env = { held: { snapshot: () => ({ ...interruptionHold }) }, checkCancelled() {}, assessInterruptedProbeHold, classifyOperatorHoldDecision, operatorHoldDiagnostics: createOperatorHoldDiagnostics(),
    performance: { now: () => clock }, reject,
    until: async (callback, budget) => { assert.equal(budget, 2000); assert.equal(await callback(), true); queueMicrotask(() => { clock = 1001; }); },
    operator: { async captureLocks() { captureCalls++; return {}; } } };
  const run = new Function(...Object.keys(env), `return async () => { let heldDeadline = 0; ${isHeld}${observation} };`)(...Object.values(env));
  await assert.rejects(run(), { code: 'operator_interruption_unconfirmed' }); assert.equal(captureCalls, 0);
});

test('hold diagnostics distinguish exact deadline and current probe gap without changing authority', () => {
  assert.equal(classifyOperatorHoldDecision(interruptionHold, 1000, 999), 'current');
  assert.equal(classifyOperatorHoldDecision(interruptionHold, 1000, 1000), 'deadline_expired');
  assert.equal(classifyOperatorHoldDecision({ ...interruptionHold, held: false, heldResponses: 0 }, 1000, 999), 'live_probe_gap');
  assert.equal(classifyOperatorHoldDecision({ ...interruptionHold, held: false, heldResponses: 0 }, 1000, 1001), 'live_probe_gap');
  assert.equal(classifyOperatorHoldDecision(interruptionHold, 0, 1), 'budget_unarmed');
});
for (const [name, change, expected] of [
  ['aborted', { aborted: true }, 'aborted'], ['closed', { closed: true }, 'closed'],
  ['unrequested', { requested: false }, 'candidate_unobserved'], ['unobserved', { candidateReadyObserved: false }, 'candidate_unobserved'],
  ['released', { released: true }, 'invalid'], ['invalid_count', { nativeProbeChecks: 'one' }, 'invalid'],
  ['inconsistent_gap', { held: true, heldResponses: 0 }, 'invalid']]) {
  test(`hold decision classifies ${name} without accepting it`, () => assert.equal(classifyOperatorHoldDecision({ ...interruptionHold, ...change }, 1000, 500), expected));
}
test('hold diagnostics preserve the first actual refusal through later expiry observations', () => {
  const d = createOperatorHoldDiagnostics();
  d.observe('capture_final', 'current', 300, 1000, interruptionHold);
  d.observe('terminate_capture', 'live_probe_gap', 350, 1000, { ...interruptionHold, held: false, heldResponses: 0 });
  d.observe('terminate_final', 'deadline_expired', 1500, 1000, interruptionHold);
  const r = d.snapshot(); assert.equal(r.observationCount, 3); assert.equal(r.firstRefusal.stage, 'terminate_capture');
  assert.equal(r.firstRefusal.reason, 'live_probe_gap'); assert.equal(r.firstRefusal.ageMs, 350); assert.equal(r.firstRefusal.deadlineExpired, false);
  assert.equal(r.observations[2].deadlineExpired, true); assert.equal(r.observations[2].ageMs, 1500);
});
test('hold diagnostics cap observations, counters and timing while retaining the first refusal', () => {
  const d = createOperatorHoldDiagnostics();
  d.observe('capture_final', 'cancelled', 10, 1000, null);
  for (let i = 0; i < 100; i++) d.observe('terminate_final', 'current', i + 20000, 1000, interruptionHold);
  const r = d.snapshot(); assert.equal(r.observationCount, 64); assert.equal(r.observations.length, 8);
  assert.equal(r.observationsTruncated, true); assert.equal(r.firstRefusal.reason, 'cancelled');
  assert(r.observations.every(value => value.ageMs === 10000));
});
test('hold diagnostics publish only allowlisted finite values without raw exception or host data', () => {
  const d = createOperatorHoldDiagnostics();
  d.observe('/private/host pid=12345', new Error('private diagnostic bytes'), Infinity, -1, { nativeProbeChecks: 'private', heldResponses: 999 });
  const r = d.snapshot(), text = JSON.stringify(r);
  assert.equal(r.firstRefusal.stage, 'unknown'); assert.equal(r.firstRefusal.reason, 'invalid');
  assert.equal(r.firstRefusal.ageMs, null); assert.equal(r.firstRefusal.nativeProbeChecks, null); assert.equal(r.firstRefusal.heldResponses, null);
  for (const value of ['private', 'host', '12345', 'Error', 'stack']) assert.equal(text.includes(value), false);
});
test('hold diagnostics snapshots cannot mutate stored refusal or observations', () => {
  const d = createOperatorHoldDiagnostics(); d.observe('capture_final', 'deadline_expired', 1000, 1000, interruptionHold);
  const r = d.snapshot(); r.firstRefusal.reason = 'current'; r.observations[0].reason = 'current'; r.observations.length = 0;
  assert.equal(d.snapshot().firstRefusal.reason, 'deadline_expired'); assert.equal(d.snapshot().observations.length, 1);
});
test('hold diagnostics and classifier refuse getters without reading them', () => {
  let called = false; const value = { ...interruptionHold }; Object.defineProperty(value, 'nativeProbeChecks', { get() { called = true; return 1; } });
  assert.equal(classifyOperatorHoldDecision(value, 1000, 1), 'invalid');
  const d = createOperatorHoldDiagnostics(); d.observe('capture_final', 'invalid', 1, 1000, value);
  assert.equal(d.snapshot().firstRefusal.nativeProbeChecks, null); assert.equal(called, false);
});

test('failure containment refuses a self-consistent restored record with the wrong revision ID', async () => {
  const source = await readFile(script, 'utf8'), start = source.indexOf('          const retired = await operator.retireCapturedLocksAfterFailure()');
  const begin = source.indexOf('          if (recordSha256 !== digest(JSON.stringify(revision))', start);
  const guard = source.slice(begin, source.indexOf('          const body = await request(gatewayPort);', begin));
  assert(guard.includes('restored.value.id !== result.revision'));
  const oldInput = { serverBody: 'old-confirmed', healthURL: 'http://127.0.0.1:4000/ready' };
  const previous = { value: { input: oldInput, inputSha256: digest(JSON.stringify(oldInput)) } }, binding = { pid: 321 };
  const status = { pending: null, lastConfirmedRevision: interruptedRestored, binding, runtime: { identityValid: true }, configUnchanged: true, fragmentMatchesLastConfirmed: true, history: { integrity: true } };
  const reject = code => { throw Object.assign(new Error(code), { code }); };
  async function assess(id) {
    const revision = { id, parent: interruptedPrevious, sourceRevision: interruptedPrevious, input: oldInput, inputSha256: digest(JSON.stringify(oldInput)) };
    const env = { recordSha256: digest(JSON.stringify(revision)), digest, revision, restored: { value: revision }, result: { revision: interruptedRestored }, previousRevision: interruptedPrevious, previous, absent: async () => true, status, originalState: { value: { binding } }, statePath: '/synthetic/state', reject };
    return new Function(...Object.keys(env), `return async () => { ${guard}; return true; };`)(...Object.values(env))();
  }
  assert.equal(await assess(interruptedRestored), true);
  await assert.rejects(assess('4'.repeat(32)), { code: 'operator_interruption_unconfirmed' });
});
