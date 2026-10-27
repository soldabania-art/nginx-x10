import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, chmod, mkdtemp, readdir, lstat, rm, symlink, link } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { parseOperatorReturnArguments, assessHistoricalOperatorBytes, createImmutableUnitContext,
  assessStoppedServiceUnit, readManagedReturnRevision } from './operator-package-return.mjs';

// Independent pure/private-file controls only. They never invoke the service
// checker CLI, execute candidate/historical operator code, open a network socket,
// run NGINX, send a signal or contact systemd/journal services. Reading a pinned
// public Git object is not an installation or native lifecycle observation.
const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile), digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = 'a'.repeat(64), token = 'b'.repeat(32);
const historicalCommit = 'acb648392e745b5246a5620f2ea6a6286dc06d42';
const historicalSha256 = '4560b8b2503f109f210599a6277bdf5497118e3220c1d2fb6a0c041283c3810d';
const argv = () => ['--archive', '/synthetic/bundle.tar.gz', '--sha256', hash,
  '--historical-cli', '/synthetic/historical-cli.mjs'];
const unitFields = () => ({ prefix: '/synthetic/private/a', node: '/synthetic/private/node',
  unitName: `x10-lifecycle-${token}.service`, unitFile: `/synthetic/private/x10-lifecycle-${token}.service`,
  runtimeLink: `/run/user/${process.getuid()}/systemd/user/x10-lifecycle-${token}.service`, unitSha256: hash });
const stoppedFields = () => ({ unitInactive: true, mainPidZero: true, unitResultSuccess: true,
  launchersAbsent: true, nativeGroupsAbsent: true, listenersClosed: true,
  controlSocketAbsent: true, runtimeLinkAbsent: true, unitNotFound: true });
const refuses = fn => assert.throws(fn, error => {
  assert.equal(typeof error.code, 'string'); assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE|\/synthetic\//); return true;
});
async function temporary(fn) {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-service-return-pure-')); await chmod(parent, 0o700);
  try { return await fn(parent); } finally { await rm(parent, { recursive: true, force: true }); }
}
let historicalSource;
const knownHistorical = async () => {
  if (!historicalSource) historicalSource = execute('git', ['show', `${historicalCommit}:x10/alpha/cli.mjs`],
    { cwd: root, timeout: 5000, maxBuffer: 256 * 1024, encoding: 'buffer' }).then(result => {
      assert.equal(result.stderr.length, 0); assert.equal(result.stdout.length, 68551); assert.equal(digest(result.stdout), historicalSha256);
      return result.stdout;
    });
  return Buffer.from(await historicalSource);
};

test('managed package-return parser accepts only the explicit six-token archive, hash and historical-source input', () => {
  const values = argv(), before = [...values], result = parseOperatorReturnArguments(values);
  assert.deepEqual(result, { archive: values[1], sha256: hash, historicalCli: values[5] }); assert.deepEqual(values, before);
});
for (const [label, value] of [
  ['empty', []], ['missing historical source', argv().slice(0, 4)], ['extra option', [...argv(), '--help']],
  ['extra positional', [...argv(), 'SYNTHETIC_PRIVATE']], ['wrong first flag', ['--sha256', ...argv().slice(1)]],
  ['reordered flags', [...argv().slice(2, 4), ...argv().slice(0, 2), ...argv().slice(4)]],
  ['equals spelling', ['--archive=/synthetic/bundle.tar.gz', ...argv().slice(2)]],
  ['duplicate archive', [...argv().slice(0, 4), '--archive', '/synthetic/other.tar.gz']],
  ['relative archive', ['--archive', 'bundle.tar.gz', ...argv().slice(2)]],
  ['archive traversal', ['--archive', '/synthetic/../bundle.tar.gz', ...argv().slice(2)]],
  ['archive duplicate slash', ['--archive', '/synthetic//bundle.tar.gz', ...argv().slice(2)]],
  ['archive wrong suffix', ['--archive', '/synthetic/bundle.zip', ...argv().slice(2)]],
  ['archive trailing LF', ['--archive', '/synthetic/bundle.tar.gz\n', ...argv().slice(2)]],
  ['archive whitespace', ['--archive', '/synthetic/private bundle.tar.gz', ...argv().slice(2)]],
  ['nonstring archive', ['--archive', { toString: () => '/synthetic/bundle.tar.gz' }, ...argv().slice(2)]],
  ['relative historical source', [...argv().slice(0, 5), 'historical-cli.mjs']],
  ['historical source traversal', [...argv().slice(0, 5), '/synthetic/../historical-cli.mjs']],
  ['historical source NUL', [...argv().slice(0, 5), '/synthetic/historical\0.mjs']],
  ['historical source LF', [...argv().slice(0, 5), '/synthetic/historical-cli.mjs\n']],
  ['historical source whitespace', [...argv().slice(0, 5), '/synthetic/historical source.mjs']],
  ['uppercase hash', [...argv().slice(0, 3), 'A'.repeat(64), ...argv().slice(4)]],
  ['short hash', [...argv().slice(0, 3), 'a'.repeat(63), ...argv().slice(4)]],
  ['hash trailing LF', [...argv().slice(0, 3), hash + '\n', ...argv().slice(4)]],
  ['hash object coercion', [...argv().slice(0, 3), { toString: () => hash }, ...argv().slice(4)]],
]) test(`managed package-return parser refuses ${label}`, () => refuses(() => parseOperatorReturnArguments(value)));

test('historical operator guard identifies exact reviewed source bytes without changing or executing them', async () => {
  const bytes = await knownHistorical(), before = Buffer.from(bytes), result = assessHistoricalOperatorBytes(bytes);
  assert.deepEqual(result, { valid: true, bytes: 68551, sha256: historicalSha256 }); assert.deepEqual(bytes, before);
});
for (const label of ['one byte changed', 'one byte truncated', 'one byte appended', 'same length unrelated', 'nonbuffer string', 'nonbuffer object'])
  test(`historical operator guard refuses ${label} without publishing an unknown content fingerprint`, async () => {
    const original = await knownHistorical(); let bytes = Buffer.from(original);
    if (label === 'one byte changed') bytes[0] ^= 1;
    if (label === 'one byte truncated') bytes = bytes.subarray(0, bytes.length - 1);
    if (label === 'one byte appended') bytes = Buffer.concat([bytes, Buffer.from('\n')]);
    if (label === 'same length unrelated') bytes.fill(0x20);
    if (label === 'nonbuffer string') bytes = original.toString('utf8');
    if (label === 'nonbuffer object') bytes = { toString() { throw new Error('SYNTHETIC_PRIVATE conversion must not run'); } };
    const result = assessHistoricalOperatorBytes(bytes);
    assert.equal(result.valid, false); assert.equal(result.sha256, null);
    assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE|import |export |\/synthetic\//);
  });
test('historical source file inspection is read-only and never evaluates rejected candidate JavaScript', () => temporary(async parent => {
  const source = path.join(parent, 'historical.mjs'), marker = path.join(parent, 'must-not-exist');
  const dangerous = Buffer.from(`import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'SYNTHETIC_PRIVATE');\n`);
  await writeFile(source, dangerous, { mode: 0o400 }); const before = await lstat(source);
  const result = assessHistoricalOperatorBytes(await readFile(source));
  assert.equal(result.valid, false); assert.equal(result.sha256, null); assert.deepEqual(await readdir(parent), ['historical.mjs']);
  assert.deepEqual(await readFile(source), dangerous); assert.equal((await lstat(source)).ino, before.ino); assert.equal((await lstat(source)).mode & 0o7777, 0o400);
}));

test('service unit context captures a frozen private path/recipe identity without granting service authority', () => {
  const fields = unitFields(), before = structuredClone(fields), context = createImmutableUnitContext(fields);
  assert.equal(Object.isFrozen(context), true); assert.deepEqual(fields, before);
  for (const [key, value] of Object.entries(fields)) assert.equal(context[key], value);
  assert.equal(context.binary, fields.prefix + '/bin/nginx'); assert.equal(context.launcher, fields.prefix + '/bin/x10');
  assert.equal(Object.hasOwn(context, 'serviceAccepted'), false); assert.equal(Object.hasOwn(context, 'productionAccepted'), false);
  assert.throws(() => { context.prefix = '/synthetic/private/other'; }, TypeError);
  assert.throws(() => { context.runtimeLink = '/synthetic/private/other'; }, TypeError);
});
test('service contexts retain three distinct unit mappings while caller-selected current package changes', () => {
  const contexts = ['a', 'b', 'a2'].map((name, index) => {
    const value = unitFields(), suffix = String(index + 1).repeat(32), unit = `x10-lifecycle-${suffix}.service`;
    value.prefix = `/synthetic/private/${name}`; value.unitName = unit;
    value.unitFile = '/synthetic/private/' + unit; value.runtimeLink = `/run/user/${process.getuid()}/systemd/user/` + unit;
    return createImmutableUnitContext(value);
  });
  let current = contexts[0]; const captured = contexts.map(context => structuredClone(context));
  current = contexts[1]; current = contexts[2];
  assert.equal(current, contexts[2]); assert.deepEqual(contexts, captured);
  assert.equal(new Set(contexts.map(context => context.unitName)).size, 3);
  assert.equal(new Set(contexts.map(context => context.launcher)).size, 3);
});
for (const [label, mutate] of [
  ['relative prefix', v => { v.prefix = 'relative'; }], ['prefix traversal', v => { v.prefix = '/synthetic/../private/a'; }],
  ['prefix newline', v => { v.prefix += '\n'; }], ['prefix root', v => { v.prefix = '/'; }],
  ['node relative', v => { v.node = 'node'; }], ['node newline', v => { v.node += '\n'; }],
  ['wrong unit name', v => { v.unitName = 'foreign.service'; }], ['unit name LF', v => { v.unitName += '\n'; }],
  ['unit file wrong basename', v => { v.unitFile = '/synthetic/private/units/foreign.service'; }],
  ['runtime link wrong basename', v => { v.runtimeLink = `/run/user/${process.getuid()}/systemd/user/foreign.service`; }],
  ['runtime link wrong manager UID', v => { v.runtimeLink = `/run/user/${process.getuid() + 1}/systemd/user/` + v.unitName; }],
  ['unit file outside installation parent', v => { v.unitFile = '/synthetic/private/units/' + v.unitName; }],
  ['runtime link traversal', v => { v.runtimeLink = '/run/user/1000/systemd/../user/' + v.unitName; }],
  ['unit hash trailing LF', v => { v.unitSha256 += '\n'; }], ['unit hash uppercase', v => { v.unitSha256 = 'A'.repeat(64); }],
  ['extra authority field', v => { v.activate = true; }],
]) test(`service unit context refuses ${label}`, () => { const value = unitFields(); mutate(value); refuses(() => createImmutableUnitContext(value)); });
test('service unit context refuses getters and inherited manager context without evaluation', () => {
  const value = unitFields(); let reads = 0;
  Object.defineProperty(value, 'runtimeLink', { enumerable: true, get() { reads++; throw new Error('SYNTHETIC_PRIVATE'); } });
  refuses(() => createImmutableUnitContext(value)); assert.equal(reads, 0);
  refuses(() => createImmutableUnitContext(Object.create(unitFields())));
});

test('service cleanup close-condition assessor requires all owned unit/resource facts', () => {
  const value = stoppedFields(), before = structuredClone(value);
  assert.equal(assessStoppedServiceUnit(value), true); assert.deepEqual(value, before);
});
for (const key of Object.keys(stoppedFields())) for (const mutation of ['false', 'unknown', 'absent'])
  test(`service cleanup closure refuses ${mutation} ${key}`, () => {
    const value = stoppedFields(); if (mutation === 'absent') delete value[key]; else value[key] = mutation === 'false' ? false : null;
    assert.equal(assessStoppedServiceUnit(value), false);
  });
for (const [label, mutate] of [
  ['truthy string', v => { v.nativeGroupsAbsent = 'true'; }], ['truthy number', v => { v.mainPidZero = 1; }],
  ['extra field', v => { v.forceRemovalAuthorized = true; }], ['symbol field', v => { v[Symbol('private')] = true; }],
]) test(`service cleanup closure refuses ${label}`, () => { const value = stoppedFields(); mutate(value); assert.equal(assessStoppedServiceUnit(value), false); });
test('service cleanup closure refuses a getter without calling it or leaking its exception', () => {
  const value = stoppedFields(); let reads = 0;
  Object.defineProperty(value, 'runtimeLinkAbsent', { enumerable: true, get() { reads++; throw new Error('SYNTHETIC_PRIVATE'); } });
  assert.equal(assessStoppedServiceUnit(value), false); assert.equal(reads, 0);
});
for (const value of [null, undefined, [], true, 'all clean', Object.create(stoppedFields())])
  test(`service cleanup closure refuses unsupported record ${typeof value}`, () => assert.equal(assessStoppedServiceUnit(value), false));


// Exercise the collector's ACTUAL revision reader, not a replacement/stub. The
// producer contract is an immutable0400 manager revision. No native syntax
// checking, process, controller CLI or service activation occurs in these cases.
function managedReturnRevision(mutator = () => {}) {
  const input = { serverBody: 'location / { return 200 "PUBLIC_SYNTHETIC_HTTP"; }',
    healthURL: 'http://127.0.0.1:19081/ready', healthExpectedStatus: 200, healthExpectedBody: 'ready\n' };
  const body = { schemaVersion: 1, id: 'c'.repeat(32), createdAt: '2026-10-27T00:00:00.000Z',
    parent: null, sourceRevision: null, input, inputSha256: digest(JSON.stringify(input)),
    fragmentSha256: digest('PUBLIC_SYNTHETIC_FRAGMENT_CONSISTENCY_ONLY') };
  mutator(body);
  return { ...body, recordSha256: digest(JSON.stringify(body)) };
}
async function immutableRevisionFixture(parent, { mode = 0o400, value = managedReturnRevision() } = {}) {
  const file = path.join(parent, 'revision.json'), bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  await writeFile(file, bytes, { mode, flag: 'wx' });
  return { file, bytes, before: await lstat(file), value };
}
async function assertRevisionPreserved(fixture) {
  assert.deepEqual(await readFile(fixture.file), fixture.bytes);
  const after = await lstat(fixture.file);
  for (const key of ['dev', 'ino', 'uid', 'nlink', 'mode', 'size', 'mtimeMs', 'ctimeMs'])
    assert.equal(after[key], fixture.before[key], `Revision ${key} stays unchanged`);
}
test('actual managed-return reader accepts a checksum-valid immutable0400 revision without changing its bytes or identity', () => temporary(async parent => {
  const f = await immutableRevisionFixture(parent);
  const result = await readManagedReturnRevision(f.file);
  assert.deepEqual(result, f.value); assert.equal((await lstat(f.file)).mode & 0o7777, 0o400);
  await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses the same otherwise-valid0600 revision and preserves it', () => temporary(async parent => {
  const f = await immutableRevisionFixture(parent, { mode: 0o600 });
  await assert.rejects(() => readManagedReturnRevision(f.file)); await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses an invalid record checksum on immutable0400 bytes', () => temporary(async parent => {
  const value = managedReturnRevision(); value.recordSha256 = '0'.repeat(64);
  const f = await immutableRevisionFixture(parent, { value });
  await assert.rejects(() => readManagedReturnRevision(f.file)); await assertRevisionPreserved(f);
}));
test('actual managed-return reader independently refuses input corruption despite a valid outer record checksum', () => temporary(async parent => {
  const value = managedReturnRevision(body => { body.input.serverBody += ' PUBLIC_SYNTHETIC_CHANGED'; });
  const f = await immutableRevisionFixture(parent, { value });
  assert.equal(value.recordSha256, digest(JSON.stringify(Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'recordSha256')))));
  assert.notEqual(value.inputSha256, digest(JSON.stringify(value.input)));
  await assert.rejects(() => readManagedReturnRevision(f.file)); await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses a final symlink without changing the immutable revision', () => temporary(async parent => {
  const f = await immutableRevisionFixture(parent), alias = path.join(parent, 'alias.json'); await symlink(f.file, alias);
  await assert.rejects(() => readManagedReturnRevision(alias));
  assert.equal((await lstat(alias)).isSymbolicLink(), true); await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses a hardlinked revision and preserves both existing names', () => temporary(async parent => {
  const f = await immutableRevisionFixture(parent), alias = path.join(parent, 'alias.json'); await link(f.file, alias);
  const expected = await lstat(f.file);
  await assert.rejects(() => readManagedReturnRevision(f.file)); await assert.rejects(() => readManagedReturnRevision(alias));
  assert.deepEqual(await readFile(f.file), f.bytes); assert.deepEqual(await readFile(alias), f.bytes);
  assert.equal((await lstat(f.file)).ino, expected.ino); assert.equal((await lstat(alias)).ino, expected.ino);
  assert.equal((await lstat(f.file)).nlink, 2); assert.equal((await lstat(alias)).nlink, 2);
  assert.equal((await lstat(f.file)).mode & 0o7777, 0o400);
}));
test('actual managed-return reader refuses a symlink ancestor and preserves the original target', () => temporary(async parent => {
  const original = path.join(parent, 'original'); await import('node:fs/promises').then(fs => fs.mkdir(original, { mode: 0o700 }));
  const f = await immutableRevisionFixture(original), alias = path.join(parent, 'alias-directory'); await symlink(original, alias);
  await assert.rejects(() => readManagedReturnRevision(path.join(alias, 'revision.json'))); await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses a noncanonical relative file path without opening it', () => temporary(async parent => {
  const f = await immutableRevisionFixture(parent);
  await assert.rejects(() => readManagedReturnRevision(path.relative(process.cwd(), f.file))); await assertRevisionPreserved(f);
}));
test('actual managed-return reader refuses a trailing-LF path even when that exact owned file exists', () => temporary(async parent => {
  const file = path.join(parent, 'revision.json\n'), bytes = Buffer.from(JSON.stringify(managedReturnRevision()) + '\n');
  await writeFile(file, bytes, { mode: 0o400 }); const before = await lstat(file);
  await assert.rejects(() => readManagedReturnRevision(file));
  assert.deepEqual(await readFile(file), bytes); assert.equal((await lstat(file)).ino, before.ino); assert.equal((await lstat(file)).mode & 0o7777, 0o400);
}));
