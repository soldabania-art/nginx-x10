import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { digest } from './runtime.mjs';
import { packageIdentity } from './cli.mjs';

// Pure package consistency controls and source-extracted CLI dispatch with
// virtual installation inspection. No daemon, manager, signal or socket runs.
const root = fileURLToPath(new URL('../../', import.meta.url));
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const execute = promisify(execFile);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const control = ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'];
const alpha = ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'];
const selected = schema => ['bin/nginx', 'bin/x10', ...control.map(n => `lib/control/${n}`),
  ...alpha.map(n => `lib/alpha/${n}`), ...(schema === 2 ? ['lib/service/user-unit.mjs'] : [])].sort();
const excluded = ['build.json', 'licenses/NGINX-LICENSE', 'licenses/UPSTREAM.txt', 'examples/candidate-b.json'];
const metadata = relative => ({ bytes: 100 + relative.length,
  sha256: digest(`public-synthetic-runtime:${relative}`), mode: relative.startsWith('bin/') ? '0500' : '0400' });

function manifest(schemaVersion = 2) {
  return { schemaVersion, kind: 'nginx-x10-local-alpha', prefix: '/synthetic/install',
    installationId: 'a'.repeat(32), createdAt: '2026-01-01T00:00:00.000Z',
    nodeRuntime: { executable: '/synthetic/private-node', version: 'v22.23.3' },
    immutable: Object.fromEntries([...selected(schemaVersion), ...excluded].map(n => [n, metadata(n)])) };
}
function rows(m) {
  return selected(m.schemaVersion).map(n => ({ path: n, bytes: m.immutable[n].bytes,
    sha256: m.immutable[n].sha256, mode: m.immutable[n].mode }));
}
const fingerprint = files => digest(JSON.stringify({ schemaVersion: 1, files }));
const refusal = m => assert.throws(() => packageIdentity(m), error => {
  assert.equal(typeof error?.code, 'string');
  assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE|\/synthetic\//);
  return true;
});

for (const schema of [1, 2]) test(`package identity schema${schema} uses the exact canonical runtime rows`, () => {
  const m = manifest(schema), before = structuredClone(m), r = packageIdentity(m), expected = rows(m);
  assert.equal(r.ok, true); assert.equal(r.outcome, 'package_identified');
  assert.equal(r.schemaVersion, 1); assert.equal(r.kind, 'nginx-x10-installed-package-identity');
  assert.equal(r.installationSchemaVersion, schema);
  assert.deepEqual(r.runtimeFiles, expected);
  assert.equal(r.runtimeFiles.length, schema === 2 ? 11 : 10);
  assert.equal(r.runtimePayloadSha256, fingerprint(expected));
  assert.equal(r.operatorPayloadSha256, fingerprint(expected.filter(row => row.path !== 'bin/nginx')));
  assert.equal(r.nativeBinarySha256, m.immutable['bin/nginx'].sha256);
  assert.equal(r.consistencyOnly, true);
  for (const key of ['compatibilityAccepted', 'upgradePerformed', 'rollbackAccepted', 'serviceAccepted', 'productionAccepted']) assert.equal(r[key], false, key);
  assert.deepEqual(m, before);
  const text = JSON.stringify(r);
  for (const value of ['/synthetic/', m.installationId, m.createdAt]) assert.equal(text.includes(value), false);
});

test('runtime fingerprint is invariant under inventory and metadata insertion ordering', () => {
  const m = manifest(), expected = packageIdentity(m);
  m.immutable = Object.fromEntries(Object.entries(m.immutable).reverse().map(([key, value]) =>
    [key, { mode: value.mode, sha256: value.sha256, bytes: value.bytes }]));
  assert.deepEqual(packageIdentity(m), expected);
});
test('returned runtime rows do not alias the inspected manifest metadata', () => {
  const m = manifest(), before = structuredClone(m), r = packageIdentity(m);
  r.runtimeFiles[0].sha256 = '0'.repeat(64); r.runtimeFiles.push({ path: 'not-runtime' });
  assert.deepEqual(m, before);
});
for (const relative of selected(2)) test(`runtime identity changes for selected payload ${relative}`, () => {
  const m = manifest(), prior = packageIdentity(m);
  m.immutable[relative].sha256 = digest(`public-synthetic-candidate:${relative}`);
  const next = packageIdentity(m);
  assert.notEqual(next.runtimePayloadSha256, prior.runtimePayloadSha256);
  assert.equal(next.nativeBinarySha256 === prior.nativeBinarySha256, relative !== 'bin/nginx');
  assert.equal(next.operatorPayloadSha256 === prior.operatorPayloadSha256, relative === 'bin/nginx');
});
test('runtime identity includes byte length even if a claimed content hash is unchanged', () => {
  const m = manifest(), prior = packageIdentity(m); m.immutable['lib/alpha/cli.mjs'].bytes++;
  assert.notEqual(packageIdentity(m).runtimePayloadSha256, prior.runtimePayloadSha256);
});
for (const relative of excluded) test(`nonruntime payload ${relative} cannot create a false runtime difference`, () => {
  const m = manifest(), prior = packageIdentity(m);
  m.immutable[relative] = { bytes: 999, mode: '0400', sha256: digest('public-synthetic-provenance-only') };
  assert.deepEqual(packageIdentity(m), prior);
});
test('installation/provenance/runtime-host metadata never creates a false package version', () => {
  const m = manifest(), prior = packageIdentity(m);
  Object.assign(m, { prefix: '/synthetic/elsewhere', installationId: 'b'.repeat(32),
    createdAt: '2026-12-31T00:00:00.000Z', port: 19876, healthPort: 19877,
    provenance: { checkoutRevision: 'c'.repeat(40) }, nodeRuntime: { executable: '/synthetic/other-node' } });
  assert.deepEqual(packageIdentity(m), prior);
});
test('ignored operational getters and toJSON are never evaluated', () => {
  const m = manifest(); let reads = 0;
  for (const key of ['prefix', 'installationId', 'createdAt', 'provenance', 'nodeRuntime'])
    Object.defineProperty(m, key, { configurable: true, get() { reads++; throw new Error('SYNTHETIC_PRIVATE'); } });
  m.toJSON = () => { reads++; throw new Error('SYNTHETIC_PRIVATE'); };
  assert.equal(packageIdentity(m).ok, true); assert.equal(reads, 0);
});

for (const [label, mutate] of [
  ['unknown schema', m => { m.schemaVersion = 3; }],
  ['schema coercion', m => { m.schemaVersion = '2'; }],
  ['absent schema', m => { delete m.schemaVersion; }],
  ['absent inventory', m => { delete m.immutable; }],
  ['array inventory', m => { m.immutable = []; }],
  ['missing runtime file', m => { delete m.immutable['lib/alpha/runtime.mjs']; }],
  ['missing full inventory file', m => { delete m.immutable['build.json']; }],
  ['foreign runtime path', m => { m.immutable['lib/alpha/unknown.mjs'] = metadata('lib/alpha/unknown.mjs'); }],
  ['runtime traversal path', m => { m.immutable['lib/alpha/../evil.mjs'] = metadata('lib/alpha/../evil.mjs'); }],
  ['schema1 recipe', m => { m.schemaVersion = 1; }],
  ['empty hash', m => { m.immutable['bin/nginx'].sha256 = ''; }],
  ['uppercase hash', m => { m.immutable['bin/nginx'].sha256 = 'A'.repeat(64); }],
  ['short hash', m => { m.immutable['bin/nginx'].sha256 = 'a'.repeat(63); }],
  ['hash with trailing LF', m => { m.immutable['bin/nginx'].sha256 = 'a'.repeat(64) + '\n'; }],
  ['hash coercion', m => { m.immutable['bin/nginx'].sha256 = { toString: () => 'a'.repeat(64) }; }],
  ['zero byte length', m => { m.immutable['bin/nginx'].bytes = 0; }],
  ['negative byte length', m => { m.immutable['bin/nginx'].bytes = -1; }],
  ['fraction byte length', m => { m.immutable['bin/nginx'].bytes = 1.5; }],
  ['string byte length', m => { m.immutable['bin/nginx'].bytes = '100'; }],
  ['unsafe integer length', m => { m.immutable['bin/nginx'].bytes = Number.MAX_SAFE_INTEGER + 1; }],
  ['oversized length', m => { m.immutable['bin/nginx'].bytes = 256 * 1024 * 1024 + 1; }],
  ['nonfinite length', m => { m.immutable['bin/nginx'].bytes = Infinity; }],
  ['executable payload mode', m => { m.immutable['bin/nginx'].mode = '0700'; }],
  ['module payload mode', m => { m.immutable['lib/alpha/cli.mjs'].mode = '0500'; }],
  ['coerced mode', m => { m.immutable['bin/nginx'].mode = 0o500; }],
  ['metadata extra', m => { m.immutable['bin/nginx'].host = 'SYNTHETIC_PRIVATE'; }],
  ['metadata missing', m => { delete m.immutable['bin/nginx'].bytes; }],
  ['metadata array', m => { m.immutable['bin/nginx'] = []; }],
  ['metadata foreign prototype', m => { m.immutable['bin/nginx'] = Object.assign(Object.create({}), m.immutable['bin/nginx']); }],
  ['manifest foreign prototype', m => { Object.setPrototypeOf(m, {}); }],
  ['inventory foreign prototype', m => { Object.setPrototypeOf(m.immutable, {}); }],
  ['symbol inventory extra', m => { m.immutable[Symbol('private')] = {}; }],
  ['nonenumerable inventory extra', m => { Object.defineProperty(m.immutable, 'hidden', { value: {} }); }],
  ['symbol metadata extra', m => { m.immutable['bin/nginx'][Symbol('private')] = true; }],
  ['nonenumerable metadata extra', m => { Object.defineProperty(m.immutable['bin/nginx'], 'hidden', { value: true }); }],
]) test(`package identity refuses ${label}`, () => { const m = manifest(); mutate(m); refusal(m); });
for (const [label, target, key] of [
  ['schema getter', m => m, 'schemaVersion'], ['inventory getter', m => m, 'immutable'],
  ['selected entry getter', m => m.immutable, 'bin/nginx'],
  ['hash getter', m => m.immutable['bin/nginx'], 'sha256'],
  ['bytes getter', m => m.immutable['bin/nginx'], 'bytes'],
  ['mode getter', m => m.immutable['bin/nginx'], 'mode'],
]) test(`package identity refuses ${label} without evaluation`, () => {
  const m = manifest(); let reads = 0;
  Object.defineProperty(target(m), key, { configurable: true, enumerable: true, get() { reads++; throw new Error('SYNTHETIC_PRIVATE'); } });
  refusal(m); assert.equal(reads, 0);
});
for (const value of [null, undefined, [], 'manifest', 1]) test(`package identity refuses nonrecord ${String(value)}`, () => refusal(value));

function extractedMain(text, options = {}) {
  const begin = text.indexOf('export async function main('), end = text.indexOf('\nif (process.argv[1]', begin);
  assert(begin >= 0 && end > begin);
  let output = '', stderr = '', inspections = 0, locks = 0; const masks = [];
  const processStub = { umask(value) { masks.push(value); return 0o022; }, exitCode: 0,
    stdout: { write(value) { output += value; } }, stderr: { write(value) { stderr += value; } } };
  const fail = (code, message = code) => { throw Object.assign(new Error(message), { code }); };
  const installed = async (prefix, allowDrift) => {
    inspections++; assert.equal(prefix, '/synthetic/install'); assert.equal(allowDrift, false);
    if (options.inspectionError) throw options.inspectionError;
    return { prefix, manifest: manifest(), registry: {}, dependencyDrift: [] };
  };
  const lock = () => { locks++; throw new Error('Readonly package dispatch entered mutation lock'); };
  const fn = new AsyncFunction('process', 'parseArgs', 'fail', 'encode', 'path', 'installed', 'lock', 'packageIdentity',
    text.slice(begin, end).replace('export async function main', 'async function main') + '\nreturn main;');
  const ready = fn(processStub, parseArgs, fail, value => JSON.stringify(value) + '\n', path, installed, lock, packageIdentity);
  return { async run(argv, prefix = '/synthetic/install') { await (await ready)(argv, prefix);
    return { stdout: output, stderr, inspections, locks, masks, exitCode: processStub.exitCode,
      value: output ? JSON.parse(output) : null }; } };
}

test('pristine package-info baseline refuses before inspecting an installation', async () => {
  const baseline = (await execute('git', ['show', 'face7a77d6f9f93fc0c5657dc3bd6b44fa962cff:x10/alpha/cli.mjs'],
    { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 })).stdout;
  const result = await extractedMain(baseline).run(['package-info']);
  assert.equal(result.exitCode, 1); assert.equal(result.value.ok, false);
  assert.equal(result.value.code, 'arguments'); assert.equal(result.inspections, 0); assert.equal(result.locks, 0);
});
test('actual package-info dispatch inspects strictly once without lock or state mutation', async () => {
  const r = await extractedMain(source).run(['package-info']);
  assert.equal(r.exitCode, 0); assert.deepEqual(r.value, packageIdentity(manifest()));
  assert.equal(r.stderr, ''); assert.equal(r.inspections, 1); assert.equal(r.locks, 0);
  assert.deepEqual(r.masks, [0o077, 0o022]);
});
for (const argv of [['package-info', '--help'], ['--help', 'package-info'], ['package-info', '--human'],
  ['package-info', '--unknown', 'SYNTHETIC_PRIVATE'],
  ['package-info', '--prefix', '/synthetic/install'], ['package-info', '--output', '/synthetic/output'],
  ['package-info', '--auto-readiness'], ['package-info', 'package-info'], ['package-info', '--', 'status'],
  ['package-info', '--restore', '/synthetic/private']]) test(`package-info refuses argv ${JSON.stringify(argv)}`, async () => {
  const r = await extractedMain(source).run(argv);
  assert.equal(r.exitCode, 1); assert.equal(r.value.ok, false); assert.equal(r.value.code, 'package_info_refused');
  assert.equal(r.inspections, 0); assert.equal(r.locks, 0); assert.equal(r.stderr, '');
  assert.doesNotMatch(r.stdout, /\/synthetic\/|SYNTHETIC_PRIVATE/);
});
test('package-info is unavailable from a source invocation without installed prefix', async () => {
  const r = await extractedMain(source).run(['package-info'], null);
  assert.equal(r.exitCode, 1); assert.equal(r.value.code, 'package_info_refused');
  assert.equal(r.inspections, 0); assert.equal(r.locks, 0);
});
test('an unrelated command value named package-info keeps ordinary argument refusal', async () => {
  const r = await extractedMain(source).run(['status', '--file', 'package-info']);
  assert.equal(r.exitCode, 1); assert.equal(r.value.code, 'arguments');
  assert.equal(r.inspections, 0); assert.equal(r.locks, 0);
});
for (const code of ['dependency_changed', 'alpha_integrity', 'unsafe_path', 'unsafe_permissions'])
  test(`package-info preserves strict inspection refusal ${code} without leaking its message`, async () => {
    const error = Object.assign(new Error('SYNTHETIC_PRIVATE /synthetic/installation'), { code });
    const r = await extractedMain(source, { inspectionError: error }).run(['package-info']);
    assert.equal(r.exitCode, 1); assert.equal(r.value.code, 'package_info_refused');
    assert.equal(r.inspections, 1); assert.equal(r.locks, 0); assert.equal(r.stderr, '');
    assert.doesNotMatch(r.stdout, /SYNTHETIC_PRIVATE|\/synthetic\/|dependency_changed|alpha_integrity|unsafe_path|unsafe_permissions/);
  });
