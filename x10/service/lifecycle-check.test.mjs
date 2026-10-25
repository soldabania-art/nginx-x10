import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseArguments, fixtureUnitName, parseUnitProperties, managerEnvironment, LIMITATIONS, assessNodePrerequisites, classifyLifecycleError, createFailureDiagnostics, createStartDiagnostics, summarizeManagerOutcome, summarizeUnitProperties, classifyCommandTermination, classifySystemError, DIAGNOSTIC_PHASES, START_SUBPHASES, CLEANUP_STAGES, summarizeUnitFragmentIdentity, createFragmentIdentityDiagnostics } from './lifecycle-check.mjs';
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
