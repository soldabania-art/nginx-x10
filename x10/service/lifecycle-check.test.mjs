import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseArguments, fixtureUnitName, parseUnitProperties, managerEnvironment, LIMITATIONS } from './lifecycle-check.mjs';
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
    assert.equal(r.runtimeUnitLinked, false); assert.equal(r.serviceAccepted, false); return true;
  });
});
test('actual root CLI refuses before archive read or mutation; nonroot observation is not synthesized', async t => {
  if (process.getuid?.() !== 0) { t.skip('actual root refusal only; real nonroot lifecycle is a separate required CI command'); return; }
  await assert.rejects(run(process.execPath, [script, '--archive', '/absent/safe.tar.gz', '--sha256', hash], { timeout: 5000, maxBuffer: 16384 }), e => {
    assert.equal(e.code, 1); assert.equal(e.stderr, ''); const r = JSON.parse(e.stdout);
    assert.equal(r.code, 'nonroot_required'); assert.equal(r.phase, 'preflight'); assert.equal(r.actualNonrootManagerObserved, false);
    assert.equal(r.actualUnitStarted, false); assert.equal(r.runtimeUnitLinked, false); assert.equal(r.nativeSessionsStarted, 0);
    assert.equal(r.cleanup.temporaryRootRemoved, false); assert.equal(r.serviceAccepted, false); return true;
  });
});
