import test from 'node:test';
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { canonical, owned, simple, exists, same, fail } from './runtime.mjs';

// Private-file and source-extracted orchestration controls only. Native absence,
// package installation, controller status and backup observations are explicitly
// virtual. These controls never execute NGINX, signal a process, start a daemon,
// contact an application or activate a service; real staging is a hosted gate.
const root = fileURLToPath(new URL('../../', import.meta.url));
const source = await fs.readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const execute = promisify(execFile), AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const sha = value => digest(`public-synthetic-stage:${value}`);
const validArgv = () => ['stage', '--source-prefix', '/synthetic/old', '--prefix', '/synthetic/new',
  '--expected-source-payload', sha('old'), '--expected-bundle-manifest', sha('candidate')];
const privateError = code => Object.assign(new Error('SYNTHETIC_PRIVATE /synthetic/private-data'), { code });

function extractedMain(text, options = {}) {
  const begin = text.indexOf('export async function main('), end = text.indexOf('\nif (process.argv[1]', begin);
  assert(begin >= 0 && end > begin);
  let output = '', stderr = '', stages = 0, inspections = 0, locks = 0, args; const masks = [];
  const processStub = { umask(value) { masks.push(value); return 0o022; }, exitCode: 0,
    stdout: { write(value) { output += value; } }, stderr: { write(value) { stderr += value; } } };
  const stagePackage = async values => {
    stages++; args = structuredClone(values); if (options.stageError) throw options.stageError;
    return { ok: true, outcome: 'virtual_stage_only', nativeStarted: false, activationPerformed: false };
  };
  const installed = async () => { inspections++; throw privateError('unexpected_inspection'); };
  const lock = async () => { locks++; throw privateError('unexpected_lock'); };
  const fn = new AsyncFunction('process', 'parseArgs', 'fail', 'encode', 'path', 'stagePackage', 'installed', 'lock',
    text.slice(begin, end).replace('export async function main', 'async function main') + '\nreturn main;');
  const ready = fn(processStub, parseArgs, fail, encode, path, stagePackage, installed, lock);
  return { async run(argv, prefix = null) { await (await ready)(argv, prefix);
    return { stdout: output, stderr, stages, inspections, locks, masks, args,
      exitCode: processStub.exitCode, value: output ? JSON.parse(output) : null }; } };
}

test('staging pristine baseline has no package staging command', async () => {
  const baseline = (await execute('git', ['show', '34eec25a3e4b9bc9da2ac19a9fff2963f1ef75d1:x10/alpha/cli.mjs'],
    { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 })).stdout;
  const result = await extractedMain(baseline).run(validArgv());
  assert.equal(result.exitCode, 1); assert.equal(result.value.ok, false);
  assert.equal(result.stages, 0); assert.equal(result.inspections, 0); assert.equal(result.locks, 0);
});
test('staging dispatch selects the explicitly supplied source and candidate expectations', async () => {
  const r = await extractedMain(source).run(validArgv());
  assert.equal(r.exitCode, 0); assert.equal(r.stages, 1); assert.equal(r.inspections, 0); assert.equal(r.locks, 0);
  assert.deepEqual(r.args, { 'source-prefix': '/synthetic/old', prefix: '/synthetic/new',
    'expected-source-payload': sha('old'), 'expected-bundle-manifest': sha('candidate') });
  assert.equal(r.value.outcome, 'virtual_stage_only'); assert.equal(r.stderr, '');
  assert.deepEqual(r.masks, [0o077, 0o022]);
});
const badArgv = [
  ['no options', ['stage']],
  ['missing source', ['stage', ...validArgv().slice(3)]],
  ['missing target', ['stage', ...validArgv().slice(1, 3), ...validArgv().slice(5)]],
  ['missing source hash', [...validArgv().slice(0, 5), ...validArgv().slice(7)]],
  ['missing bundle hash', validArgv().slice(0, 7)],
  ['duplicate source', [...validArgv(), '--source-prefix', '/synthetic/other']],
  ['duplicate target', [...validArgv(), '--prefix', '/synthetic/other']],
  ['duplicate source hash', [...validArgv(), '--expected-source-payload', sha('other')]],
  ['duplicate bundle hash', [...validArgv(), '--expected-bundle-manifest', sha('other')]],
  ['trailing positional', [...validArgv(), 'status']],
  ['separated positional', [...validArgv(), '--', 'status']],
  ['leading help', ['--help', ...validArgv()]],
  ['trailing help', [...validArgv(), '--help']],
  ['human option', [...validArgv(), '--human']],
  ['binary option', [...validArgv(), '--binary', '/synthetic/foreign']],
  ['manifest option', [...validArgv(), '--manifest', '/synthetic/foreign']],
  ['restore option', [...validArgv(), '--restore', '/synthetic/foreign']],
  ['port option', [...validArgv(), '--port', '19080']],
  ['unknown option', [...validArgv(), '--unknown', 'SYNTHETIC_PRIVATE']],
  ['equals flag spelling', validArgv().join(' ').replace('--prefix /synthetic/new', '--prefix=/synthetic/new').split(' ')],
];
for (const [label, argv] of badArgv) test(`staging refuses malformed argv ${label} before orchestration`, async () => {
  const r = await extractedMain(source).run(argv);
  assert.equal(r.exitCode, 1); assert.equal(r.value.ok, false); assert.equal(r.value.code, 'stage_refused');
  assert.equal(r.stages, 0); assert.equal(r.inspections, 0); assert.equal(r.locks, 0); assert.equal(r.stderr, '');
  assert.doesNotMatch(r.stdout, /SYNTHETIC_PRIVATE|\/synthetic\//);
});
test('staging refuses installed launcher dispatch without inspecting or locking old installation', async () => {
  const r = await extractedMain(source).run(validArgv(), '/synthetic/installed');
  assert.equal(r.exitCode, 1); assert.equal(r.value.code, 'stage_refused');
  assert.equal(r.stages, 0); assert.equal(r.inspections, 0); assert.equal(r.locks, 0);
});
for (const code of ['dependency_changed', 'alpha_integrity', 'stage_source_changed', 'EACCES', 'native_syntax_failed'])
  test(`staging dispatch redacts ${code} failure and never retries candidate execution`, async () => {
    const r = await extractedMain(source, { stageError: privateError(code) }).run(validArgv());
    assert.equal(r.exitCode, 1); assert.equal(r.stages, 1); assert.equal(r.value.code, 'stage_refused');
    assert.equal(r.value.ok, false); assert.equal(r.stderr, '');
    assert.doesNotMatch(r.stdout, /SYNTHETIC_PRIVATE|\/synthetic\/|dependency_changed|alpha_integrity|EACCES/);
    assert.deepEqual(r.masks, [0o077, 0o022]);
  });

const controlNames = ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'];
const alphaNames = ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'];
const staticDirectories = ['bin', 'lib', 'lib/control', 'lib/alpha', 'licenses', 'examples', 'runs'];
const recipePath = 'lib/service/user-unit.mjs';
const bundleNames = version => ['bin/nginx', 'install.mjs', 'LICENSE', 'NOTICE', 'x10/alpha/README.md',
  ...alphaNames.map(n => `x10/alpha/${n}`), ...controlNames.map(n => `x10/control/${n}`),
  ...(version === 2 ? ['x10/service/user-unit.mjs'] : [])].sort();
const payloadMode = relative => ['bin/nginx', 'bin/x10'].includes(relative) ? '0500' : '0400';
const backupFileIdentity = stat => ({ dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode,
  nlink: stat.nlink, size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs });
const imported = await import('./cli.mjs');
async function privateRoot(fn) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'x10-stage-pure-')); await fs.chmod(parent, 0o700);
  try { return await fn(parent); } finally { await fs.rm(parent, { recursive: true, force: true }); }
}
async function inventory(prefix) {
  const entries = [], stack = [''];
  while (stack.length) {
    const relative = stack.pop();
    for (const name of await fs.readdir(path.join(prefix, relative))) {
      const child = path.posix.join(relative, name), stat = await fs.lstat(path.join(prefix, child));
      if (stat.isSymbolicLink() || stat.uid !== process.getuid()) fail('unsafe_path', 'Virtual inventory refuses unsafe entry');
      entries.push({ relative: child, stat }); if (stat.isDirectory()) stack.push(child);
    }
  }
  return entries;
}
async function record(file) {
  const value = JSON.parse(await fs.readFile(file, 'utf8')), { sha256, ...body } = value;
  if (sha256 !== digest(JSON.stringify(body))) fail('alpha_integrity', 'Synthetic record consistency failed');
  return body;
}
async function saveRecord(file, value) {
  await fs.writeFile(file, encode({ ...value, sha256: digest(JSON.stringify(value)) }), { mode: 0o600 });
}
function helpers(extra = {}) {
  const begin = source.indexOf('// Side-by-side package staging.'), end = source.indexOf('// End side-by-side package staging.', begin);
  assert(begin >= 0 && end > begin, 'Production staging helper boundary exists');
  let block = source.slice(begin, end);
  const overrides = ['stagingRead', 'stagingBundle', 'stagingSourceSnapshot', 'stagingLock'];
  for (const name of overrides) if (Object.hasOwn(extra, name)) block = block.replace(`async function ${name}(`, `async function original_${name}(`);
  const dependencies = { ...Object.fromEntries(Object.entries(fs).filter(([name]) => name !== 'default')),
    constants, Buffer, process, path, os, digest, encode, same, fail, simple, exists, owned, canonical,
    backupFileIdentity, bundleNames, payloadMode, controlNames, alphaNames, staticDirectories, recipePath,
    packageIdentity: imported.packageIdentity, inventory, record, load: async file => JSON.parse(await fs.readFile(file, 'utf8')), ...extra };
  return new AsyncFunction(...Object.keys(dependencies), block + '\nreturn { stagingHex, stagingOverlap, stagingRead, stagingBundle, stagingSourceSnapshot, stagingLock, stagePackage };')(...Object.values(dependencies));
}

test('staging file reader hashes actual bytes without changing the private file', () => privateRoot(async parent => {
  const file = path.join(parent, 'record'), bytes = Buffer.from('PUBLIC_SYNTHETIC_RECORD\n');
  await fs.writeFile(file, bytes, { mode: 0o600 }); const before = await fs.lstat(file);
  const r = await (await helpers()).stagingRead(file);
  assert.equal(r.sha256, digest(bytes)); assert.equal(r.size, bytes.length);
  assert.deepEqual(await fs.readFile(file), bytes); assert.equal((await fs.lstat(file)).ino, before.ino);
}));
for (const type of ['symlink', 'hardlink', 'directory', 'limit']) test(`staging file reader refuses ${type} without deleting original`, () => privateRoot(async parent => {
  const file = path.join(parent, 'record'), target = path.join(parent, 'other');
  await fs.writeFile(file, 'PUBLIC_SYNTHETIC_RECORD', { mode: 0o600 });
  let selected = file;
  if (type === 'symlink') { await fs.symlink(file, target); selected = target; }
  if (type === 'hardlink') { await fs.link(file, target); selected = target; }
  if (type === 'directory') selected = parent;
  await assert.rejects(() => (async () => (await helpers()).stagingRead(selected, type === 'limit' ? 1 : 1024))(), error => typeof error.code === 'string');
  assert.equal(await fs.readFile(file, 'utf8'), 'PUBLIC_SYNTHETIC_RECORD');
}));
for (const value of ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'a'.repeat(64) + '\n', 'a'.repeat(64) + '\r', null, 1, { toString: () => 'a'.repeat(64) }])
  test(`staging consistency pin rejects noncanonical value ${typeof value}:${String(value).length}`, async () => {
    const h = await helpers(); assert.equal(h.stagingHex(value), false);
  });
test('staging overlap rejects equality and either nesting but allows siblings with shared name prefix', async () => {
  const h = await helpers();
  for (const [a, b] of [['/a', '/a'], ['/a/b', '/a'], ['/a', '/a/b']]) assert.equal(h.stagingOverlap(a, b), true);
  assert.equal(h.stagingOverlap('/a', '/ab'), false); assert.equal(h.stagingOverlap('/a/b', '/a/c'), false);
});

async function bundleFixture(parent, change) {
  const directory = path.join(parent, 'candidate'); await fs.mkdir(directory, { mode: 0o700 });
  for (const relative of ['bin', 'x10', 'x10/alpha', 'x10/control', 'x10/service']) await fs.mkdir(path.join(directory, relative), { mode: 0o700 });
  const files = {};
  for (const relative of bundleNames(2)) {
    const bytes = Buffer.from(`public-synthetic-NONEXECUTED-payload:${relative}\n`), mode = payloadMode(relative);
    await fs.writeFile(path.join(directory, relative), bytes, { mode: parseInt(mode, 8) });
    files[relative] = { bytes: bytes.length, sha256: digest(bytes), mode };
  }
  const manifest = { schemaVersion: 2, kind: 'nginx-x10-linux-alpha-bundle', platform: { system: 'Linux', machine: os.machine() }, files, nativeVersionOutputSha256: sha('public-native-version'),
    provenance: { upstreamRepository: 'https://github.com/nginx/nginx', upstreamRevision: 'a'.repeat(40), checkoutRevision: 'b'.repeat(40), sourceDiffSha256: sha('public-native-diff'), nginxVersion: 'public-synthetic', compilerFlags: 'public-synthetic-flags', compiledModules: ['ngx_http_module'], dependencyVersionsFromHeaders: { openssl: 'public-synthetic-openssl', pcre2: 'public-synthetic-pcre2', zlib: 'public-synthetic-zlib' }, configureFlags: ['--public-synthetic-configure'] } };
  if (change) await change({ directory, manifest });
  await saveRecord(path.join(directory, 'bundle.json'), manifest);
  return { directory, manifest, h: await helpers({ root: directory + '/' }) };
}
test('staging bundle predicts runtime identity from a complete private NONEXECUTED payload', () => privateRoot(async parent => {
  const { directory, h } = await bundleFixture(parent), before = await inventory(directory), r = await h.stagingBundle();
  assert.equal(r.manifestSha256, digest(await fs.readFile(path.join(directory, 'bundle.json'))));
  assert.equal(r.identity.runtimeFiles.length, 11); assert.equal(r.identity.installationSchemaVersion, 2);
  assert.equal(r.identity.nativeBinarySha256, digest(await fs.readFile(path.join(directory, 'bin/nginx'))));
  assert.equal(r.snapshot.length, before.length + 1); assert.equal(r.snapshot[0].path, ''); assert.equal((await inventory(directory)).length, before.length);
  assert.deepEqual(r.snapshot.map(row => row.path), [...r.snapshot.map(row => row.path)].sort());
  assert.equal(r.identity.compatibilityAccepted, false);
}));
for (const [label, change] of [
  ['missing native version declaration', async ({ manifest }) => { delete manifest.nativeVersionOutputSha256; }],
  ['missing provenance declaration', async ({ manifest }) => { delete manifest.provenance; }],
  ['foreign upstream repository declaration', async ({ manifest }) => { manifest.provenance.upstreamRepository = 'https://example.invalid/nginx'; }],
  ['compiled module name ending LF', async ({ manifest }) => { manifest.provenance.compiledModules[0] += '\n'; }],
  ['wrong dependency header inventory', async ({ manifest }) => { delete manifest.provenance.dependencyVersionsFromHeaders.openssl; manifest.provenance.dependencyVersionsFromHeaders.foreign = 'public-synthetic'; }],
  ['unsupported schema', async ({ manifest }) => { manifest.schemaVersion = 1; }],
  ['foreign architecture', async ({ manifest }) => { manifest.platform.machine = 'unsupported-machine'; }],
  ['extra declared payload', async ({ manifest }) => { manifest.files['x10/foreign.mjs'] = { bytes: 1, sha256: sha('foreign'), mode: '0400' }; }],
  ['missing declared runtime', async ({ manifest }) => { delete manifest.files['x10/alpha/runtime.mjs']; }],
  ['unknown file', async ({ directory }) => { await fs.writeFile(path.join(directory, 'unknown'), 'public', { mode: 0o600 }); }],
  ['unknown directory', async ({ directory }) => { await fs.mkdir(path.join(directory, 'unknown'), { mode: 0o700 }); }],
  ['missing physical runtime', async ({ directory }) => { await fs.rm(path.join(directory, 'x10/alpha/runtime.mjs')); }],
  ['modified physical runtime', async ({ directory }) => { const f = path.join(directory, 'x10/alpha/runtime.mjs'); await fs.chmod(f, 0o600); await fs.writeFile(f, 'different'); await fs.chmod(f, 0o400); }],
  ['hardlinked runtime', async ({ directory }) => { await fs.link(path.join(directory, 'x10/alpha/runtime.mjs'), path.join(directory, 'linked')); }],
  ['runtime metadata extra', async ({ manifest }) => { manifest.files['x10/alpha/runtime.mjs'].private = 'SYNTHETIC_PRIVATE'; }],
  ['runtime metadata hash LF', async ({ manifest }) => { manifest.files['x10/alpha/runtime.mjs'].sha256 += '\n'; }],
  ['runtime metadata wrong mode', async ({ manifest }) => { manifest.files['x10/alpha/runtime.mjs'].mode = '0600'; }],
  ['runtime physical wrong mode', async ({ directory }) => { await fs.chmod(path.join(directory, 'x10/alpha/runtime.mjs'), 0o600); }],
  ['directory wrong mode', async ({ directory }) => { await fs.chmod(path.join(directory, 'x10/alpha'), 0o755); }],
]) test(`staging bundle refuses ${label} before any native execution`, () => privateRoot(async parent => {
  const { directory, h } = await bundleFixture(parent, change);
  await assert.rejects(() => h.stagingBundle(), error => typeof error.code === 'string');
  assert.equal(await exists(directory), true);
}));

async function orchestration(parent, options = {}) {
  const sourcePrefix = path.join(parent, 'old'), targetPrefix = path.join(parent, 'new'), candidateRoot = path.join(parent, 'candidate');
  await fs.mkdir(sourcePrefix, { mode: 0o700 }); await fs.mkdir(candidateRoot, { mode: 0o700 });
  const sourceRecord = path.join(sourcePrefix, 'public-synthetic-record');
  await fs.writeFile(sourceRecord, 'PUBLIC_SYNTHETIC_SOURCE\n', { mode: 0o600 });
  const events = [], oldIdentity = { runtimePayloadSha256: sha('old'), operatorPayloadSha256: sha('old-operator'), nativeBinarySha256: sha('native') };
  const targetIdentity = { runtimePayloadSha256: sha('new'), operatorPayloadSha256: sha('new-operator'), nativeBinarySha256: sha('native') };
  const context = { prefix: sourcePrefix, manifest: { schemaVersion: 2, installationId: 'a'.repeat(32), identity: oldIdentity },
    registry: { current: 'b'.repeat(32), sessions: ['b'.repeat(32)] } };
  const target = { prefix: targetPrefix, manifest: { schemaVersion: 2, installationId: 'd'.repeat(32), identity: targetIdentity, port: 19080, healthPort: 19081 },
    registry: { current: 'e'.repeat(32), sessions: ['e'.repeat(32)] } };
  const life = { stage: 'prepared', session: 'e'.repeat(32), prefix: path.join(targetPrefix, 'runs', 'e'.repeat(32)), runtime: null, controlSocket: null };
  const status = { result: { binding: null, lastConfirmedRevision: 'f'.repeat(32) } };
  const candidate = { manifestSha256: sha('candidate'), identity: targetIdentity, snapshot: [{ path: 'public-synthetic', sha256: sha('candidate-file') }] };
  const backupValue = { source: { installationId: context.manifest.installationId, session: context.registry.current, revision: 'c'.repeat(32) },
    input: { serverBody: 'public-synthetic-http-input', healthURL: 'http://127.0.0.1:19081/ready' }, port: 19080, healthPort: 19081 };
  backupValue.inputSha256 = digest(JSON.stringify(backupValue.input));
  const revisionBody = { id: 'f'.repeat(32), parent: null, sourceRevision: null, input: backupValue.input, inputSha256: backupValue.inputSha256 };
  const revision = { ...revisionBody, recordSha256: digest(JSON.stringify(revisionBody)) };
  const history = { records: [{ type: 'initialized_unbound', details: { revision: revision.id } }] };
  let locked = false, installedCalls = 0, bundleCalls = 0, temporary;
  const operation = name => { events.push(name); if (options.failAt === name) throw privateError(options.code || 'virtual_refusal'); };
  const snapshot = async actual => {
    assert.equal(locked, true); assert.equal(actual.prefix, sourcePrefix); operation('source-snapshot');
    return [{ path: 'public-synthetic-record', sha256: digest(await fs.readFile(sourceRecord)) }];
  };
  const h = await helpers({ root: candidateRoot + '/',
    backupParent: async value => { assert.equal(value, parent); const stat = await owned(value, true, true); assert.equal(stat.mode & 0o7777, 0o700); operation('backup-parent'); },
    stagingBundle: async () => { operation('bundle'); bundleCalls++; const value = structuredClone(candidate); if (options.candidateChanged && bundleCalls > 1) value.snapshot[0].sha256 = sha('changed'); return value; },
    stagingSourceSnapshot: snapshot,
    packageIdentity: value => structuredClone(value.identity),
    stagingLock: async (prefix, callback) => {
      assert.equal(prefix, sourcePrefix); operation('lock'); locked = true; let preserved = false; const lockFile = path.join(sourcePrefix, '.alpha-lock');
      await fs.writeFile(lockFile, 'PUBLIC_SYNTHETIC_OWNED_LOCK', { mode: 0o600, flag: 'wx' });
      try { return await callback(); }
      finally { if (!preserved) await fs.rm(lockFile); locked = false; operation('unlock'); }
    },
    installed: async prefix => {
      if (installedCalls) assert.equal(locked, true); operation(prefix === sourcePrefix ? 'source-inspect' : 'target-inspect'); installedCalls++;
      if (prefix === sourcePrefix) {
        const value = structuredClone(context); if (options.sourceManifestChanged && events.includes('install')) value.manifest.installationId = '9'.repeat(32); return value;
      }
      assert.equal(prefix, targetPrefix); return structuredClone(target);
    },
    backup: async (actual, file) => {
      assert.equal(actual.prefix, sourcePrefix); assert.equal(locked, true); operation('backup'); temporary = path.dirname(file);
      await fs.writeFile(file, encode(backupValue), { mode: 0o600 });
      if (options.unknownTemporary) await fs.writeFile(path.join(temporary, 'unrecognized'), 'PRESERVE_UNKNOWN', { mode: 0o600 });
    },
    readBackup: async file => { operation('backup-read'); return JSON.parse(await fs.readFile(file, 'utf8')); },
    install: async values => {
      assert.equal(locked, true); assert.equal(values.prefix, targetPrefix); assert.equal(values.restore, path.join(temporary, 'declarative.json'));
      assert.deepEqual(Object.keys(values).sort(), ['prefix', 'restore']); operation('install');
      await fs.mkdir(targetPrefix, { mode: 0o700 }); await fs.writeFile(path.join(targetPrefix, 'partial-owned-target'), 'PUBLIC_SYNTHETIC_TARGET', { mode: 0o600 });
      if (options.sourceBytesChanged) await fs.writeFile(sourceRecord, 'PUBLIC_SYNTHETIC_CHANGED');
      if (options.installError) throw privateError('virtual_syntax_failure');
      return { declarativeRestored: options.restoreResult !== false };
    },
    lifecycle: async actual => { assert.equal(actual.prefix, targetPrefix); operation('target-lifecycle'); return structuredClone(life); },
    sessionStatus: async (actual, actualLife) => { assert.equal(actual.prefix, targetPrefix); assert.deepEqual(actualLife, life); operation('target-status'); return { ...structuredClone(status), state: '/synthetic/virtual-state', control: { history: async state => { assert.equal(state, '/synthetic/virtual-state'); return structuredClone(history); } } }; },
    load: async file => { assert.equal(file, path.join(life.prefix, '.x10-control/revisions', status.result.lastConfirmedRevision + '.json')); operation('target-revision'); return structuredClone(revision); },
  });
  if (options.mutate) options.mutate({ context, target, life, status, candidate, backupValue, revision, history });
  const values = { 'source-prefix': sourcePrefix, prefix: targetPrefix, 'expected-source-payload': oldIdentity.runtimePayloadSha256, 'expected-bundle-manifest': sha('candidate') };
  if (options.values) Object.assign(values, options.values({ sourcePrefix, targetPrefix, candidateRoot }));
  return { h, values, events, sourcePrefix, targetPrefix, candidateRoot, sourceRecord, context, target, life, status,
    execute: () => h.stagePackage(values), temporary: () => temporary };
}
test('staging virtual orchestration preserves source bytes, distinguishes operator from native and cleans only its private backup', () => privateRoot(async parent => {
  const f = await orchestration(parent), result = await f.execute();
  assert.equal(result.ok, true); assert.equal(result.outcome, 'package_staged');
  assert.equal(result.runtimePayloadChanged, true); assert.equal(result.operatorPayloadChanged, true); assert.equal(result.nativeBinaryChanged, false);
  assert.equal(result.sourceRuntimePayloadSha256, sha('old')); assert.equal(result.targetRuntimePayloadSha256, sha('new'));
  assert.equal(result.sourcePreserved, true); assert.equal(result.freshTargetIdentities, true);
  for (const key of ['nativeStarted', 'readinessChecked', 'activationPerformed', 'compatibilityAccepted', 'upgradePerformed', 'rollbackAccepted', 'serviceAccepted', 'productionAccepted']) assert.equal(result[key], false, key);
  assert.equal(await fs.readFile(f.sourceRecord, 'utf8'), 'PUBLIC_SYNTHETIC_SOURCE\n');
  assert.equal(await exists(f.targetPrefix), true); assert.equal(await exists(f.candidateRoot), true);
  assert.equal(await exists(f.temporary()), false); assert.equal(f.events.at(-1), 'unlock');
  assert.equal(f.events.filter(e => e === 'install').length, 1); assert.equal(f.events.filter(e => e === 'backup').length, 1);
  assert.doesNotMatch(JSON.stringify(result), /\/tmp\/|PUBLIC_SYNTHETIC|public-synthetic|SYNTHETIC_PRIVATE/);
}));
for (const [label, values] of [
  ['same prefix', f => ({ prefix: f.sourcePrefix })],
  ['target inside source', f => ({ prefix: f.sourcePrefix + '/new' })],
  ['source inside target', f => ({ 'source-prefix': f.targetPrefix + '/old' })],
  ['target inside candidate', f => ({ prefix: f.candidateRoot + '/new' })],
  ['source inside candidate', f => ({ 'source-prefix': f.candidateRoot + '/old' })],
  ['source hash LF', () => ({ 'expected-source-payload': sha('old') + '\n' })],
  ['bundle hash LF', () => ({ 'expected-bundle-manifest': sha('candidate') + '\n' })],
  ['wrong bundle pin', () => ({ 'expected-bundle-manifest': sha('wrong') })],
  ['wrong source pin', () => ({ 'expected-source-payload': sha('wrong') })],
]) test(`staging refuses ${label} before creating target or backup`, () => privateRoot(async parent => {
  const f = await orchestration(parent, { values });
  await assert.rejects(f.execute, error => typeof error.code === 'string');
  assert.equal(f.events.includes('install'), false); assert.equal(f.events.includes('backup'), false); assert.equal(await exists(f.targetPrefix), false);
  assert.equal(await fs.readFile(f.sourceRecord, 'utf8'), 'PUBLIC_SYNTHETIC_SOURCE\n');
}));
for (const label of ['existing target', 'dangling target symlink']) test(`staging refuses ${label} without replacing it`, () => privateRoot(async parent => {
  const f = await orchestration(parent);
  if (label === 'existing target') await fs.mkdir(f.targetPrefix, { mode: 0o700 }); else await fs.symlink(path.join(parent, 'nonexistent'), f.targetPrefix);
  await assert.rejects(f.execute); assert.equal(f.events.includes('backup'), false); assert.equal(f.events.includes('install'), false);
  assert.equal((await fs.lstat(f.targetPrefix)).isSymbolicLink(), label.includes('symlink'));
}));
for (const [label, mutate] of [
  ['source schema1', f => { f.context.manifest.schemaVersion = 1; }],
  ['unchanged actual runtime', f => { Object.assign(f.candidate.identity, f.context.manifest.identity); }],
]) test(`staging refuses ${label} before backup and target creation`, () => privateRoot(async parent => {
  const f = await orchestration(parent, { mutate }); await assert.rejects(f.execute);
  assert.equal(f.events.includes('backup'), false); assert.equal(f.events.includes('install'), false); assert.equal(await exists(f.targetPrefix), false);
}));
for (const [at, code] of [['lock', 'alpha_locked'], ['source-inspect', 'dependency_changed'], ['source-snapshot', 'alpha_live'], ['source-snapshot', 'operator_conflict'], ['backup', 'backup_unsupported'], ['backup-read', 'backup_invalid']])
  test(`staging propagates virtual ${code} refusal at ${at} without installing`, () => privateRoot(async parent => {
    const f = await orchestration(parent, { failAt: at, code }); await assert.rejects(f.execute, { code });
    assert.equal(f.events.includes('install'), false); assert.equal(await exists(f.targetPrefix), false);
    if (f.temporary()) assert.equal(await exists(f.temporary()), false);
    assert.equal(await fs.readFile(f.sourceRecord, 'utf8'), 'PUBLIC_SYNTHETIC_SOURCE\n');
  }));
for (const [label, options] of [
  ['target syntax failure', { installError: true }],
  ['source bytes changed during target install', { sourceBytesChanged: true }],
  ['source manifest changed after target install', { sourceManifestChanged: true }],
  ['candidate snapshot changed', { candidateChanged: true }],
  ['restore result missing', { restoreResult: false }],
  ['target extra session', { mutate: f => { f.target.registry.sessions.push('9'.repeat(32)); } }],
  ['target old installation identity', { mutate: f => { f.target.manifest.installationId = f.context.manifest.installationId; } }],
  ['target old session identity', { mutate: f => { f.life.session = f.backupValue.source.session; } }],
  ['target old revision identity', { mutate: f => { f.status.result.lastConfirmedRevision = f.backupValue.source.revision; } }],
  ['target running stage', { mutate: f => { f.life.stage = 'running'; } }],
  ['target retained native identity', { mutate: f => { f.life.runtime = { publicSyntheticPid: 123 }; } }],
  ['target retained socket', { mutate: f => { f.life.controlSocket = '/synthetic/control'; } }],
  ['target retained binding', { mutate: f => { f.status.result.binding = { publicSyntheticPid: 123 }; } }],
  ['target runtime differs from candidate', { mutate: f => { f.target.manifest.identity = { ...f.target.manifest.identity, runtimePayloadSha256: sha('unexpected') }; } }],
]) test(`staging refuses ${label} and preserves any created target for inspection`, () => privateRoot(async parent => {
  const f = await orchestration(parent, options); await assert.rejects(f.execute, error => typeof error.code === 'string');
  // A changed candidate can be detected by the immediate pre-install recheck,
  // while all other postcondition failures retain the partially created prefix.
  if (f.events.includes('install')) assert.equal(await fs.readFile(path.join(f.targetPrefix, 'partial-owned-target'), 'utf8'), 'PUBLIC_SYNTHETIC_TARGET');
  assert.equal(await exists(f.sourcePrefix), true); assert.equal(await exists(f.candidateRoot), true);
  if (f.temporary()) assert.equal(await exists(f.temporary()), false);
  assert.equal(f.events.at(-1), 'unlock');
}));
test('staging preserves unknown private temporary content and both installation trees', () => privateRoot(async parent => {
  const f = await orchestration(parent, { unknownTemporary: true }); await assert.rejects(f.execute, { code: 'stage_invalid' });
  assert.equal(await fs.readFile(path.join(f.temporary(), 'unrecognized'), 'utf8'), 'PRESERVE_UNKNOWN');
  assert.equal(await exists(f.sourcePrefix), true); assert.equal(await exists(f.candidateRoot), true);
}));

async function sourceSnapshotFixture(parent, options = {}) {
  const prefix = path.join(parent, 'source'); await fs.mkdir(prefix, { mode: 0o700 });
  for (const relative of [...staticDirectories, 'lib/service']) await fs.mkdir(path.join(prefix, relative), { mode: 0o700 });
  const sessions = ['a'.repeat(32), 'b'.repeat(32)], revisions = ['c'.repeat(32), 'd'.repeat(32)], lives = new Map(), calls = [];
  const context = { prefix, manifest: { schemaVersion: 2, immutable: { 'bin/nginx': {} } }, registry: { current: sessions[0], sessions } };
  await fs.writeFile(path.join(prefix, 'bin/nginx'), 'PUBLIC_SYNTHETIC_NONEXECUTED', { mode: 0o500 });
  await fs.writeFile(path.join(prefix, '.alpha-lock'), 'PUBLIC_SYNTHETIC_OWNED_LOCK', { mode: 0o600 });
  for (let index = 0; index < sessions.length; index++) {
    const session = sessions[index], sessionPrefix = path.join(prefix, 'runs', session);
    for (const relative of ['', 'logs', 'temp', 'temp/client', 'temp/proxy', 'temp/fastcgi', 'temp/uwsgi', 'temp/scgi', '.x10-control', '.x10-control/revisions'])
      await fs.mkdir(path.join(sessionPrefix, relative), { mode: 0o700 });
    const life = { session, stage: index === 0 ? 'stopped' : 'prepared', prefix: sessionPrefix, runtime: null, controlSocket: null }; lives.set(session, life);
    const body = { id: revisions[index], input: { serverBody: 'PUBLIC_SYNTHETIC_HTTP', healthURL: 'http://127.0.0.1:19081/ready' } };
    await fs.writeFile(path.join(sessionPrefix, '.x10-control/revisions', revisions[index] + '.json'), encode({ ...body, recordSha256: digest(JSON.stringify(body)) }), { mode: 0o600 });
    await fs.writeFile(path.join(sessionPrefix, 'lifecycle.json'), encode(life), { mode: 0o600 });
  }
  const dependencies = {
    lifecycle: async (actual, session) => { assert.equal(actual, context); calls.push(`life:${session}`); return lives.get(session); },
    stopped: async (actual, life) => { assert.equal(actual, context); calls.push(`absence:${life.session}`); if (options.liveSession === life.session) throw privateError('alpha_live'); },
    sessionStatus: async (actual, life) => {
      assert.equal(actual, context); calls.push(`status:${life.session}`); if (options.dirtySession === life.session) throw privateError('operator_conflict');
      const revision = revisions[sessions.indexOf(life.session)];
      return { state: life.session, result: { lastConfirmedRevision: revision },
        control: { history: async state => { assert.equal(state, life.session); return { records: [{ details: { revision } }] }; } } };
    },
  };
  if (options.change) await options.change({ prefix, context, lives, sessions, revisions });
  const h = await helpers(dependencies);
  return { prefix, context, lives, sessions, revisions, calls, h, execute: () => h.stagingSourceSnapshot(context) };
}
test('staging source snapshot observes every registered session and preserves all existing private bytes', () => privateRoot(async parent => {
  const f = await sourceSnapshotFixture(parent), before = await inventory(f.prefix), r = await f.execute();
  assert.equal(r.length, before.length); assert.equal(r.some(row => row.path === '.alpha-lock'), true);
  assert.deepEqual(r.map(row => row.path), [...r.map(row => row.path)].sort());
  for (const session of f.sessions) assert(f.calls.includes(`absence:${session}`));
  for (const row of r.filter(row => !row.directory)) assert.equal(row.sha256, digest(await fs.readFile(path.join(f.prefix, row.path))));
  const again = await f.execute(); assert.deepEqual(again, r);
}));
for (const stage of ['running', 'stopping', 'faulted']) test(`staging source snapshot refuses ${stage} in a noncurrent registered session`, () => privateRoot(async parent => {
  const f = await sourceSnapshotFixture(parent, { change: async ({ lives, sessions }) => { lives.get(sessions[1]).stage = stage; } });
  await assert.rejects(f.execute, { code: 'stage_requires_stopped' });
  assert.equal(f.calls.includes(`life:${f.sessions[1]}`), true);
}));
for (const which of ['current', 'noncurrent']) test(`staging source snapshot refuses a live ${which} session even if its record says stopped`, () => privateRoot(async parent => {
  const session = (which === 'current' ? 'a' : 'b').repeat(32), f = await sourceSnapshotFixture(parent, { liveSession: session });
  await assert.rejects(f.execute, { code: 'alpha_live' });
}));
for (const which of ['current', 'noncurrent']) test(`staging source snapshot refuses dirty or pending ${which} controller observation`, () => privateRoot(async parent => {
  const session = (which === 'current' ? 'a' : 'b').repeat(32), f = await sourceSnapshotFixture(parent, { dirtySession: session });
  await assert.rejects(f.execute, { code: 'operator_conflict' });
}));
for (const [label, change] of [
  ['unknown root file', async ({ prefix }) => { await fs.writeFile(path.join(prefix, 'operator-data'), 'PRESERVE_UNKNOWN', { mode: 0o600 }); }],
  ['unknown root directory', async ({ prefix }) => { await fs.mkdir(path.join(prefix, 'operator-data'), { mode: 0o700 }); }],
  ['symlink source record', async ({ prefix }) => { await fs.symlink(path.join(prefix, 'bin/nginx'), path.join(prefix, 'operator-link')); }],
  ['hardlinked immutable source', async ({ prefix }) => { await fs.link(path.join(prefix, 'bin/nginx'), path.join(path.dirname(prefix), 'outside-link')); }],
  ['unknown revision', async ({ prefix, sessions }) => { await fs.writeFile(path.join(prefix, 'runs', sessions[0], '.x10-control/revisions', 'e'.repeat(32) + '.json'), '{}', { mode: 0o600 }); }],
  ['unrecognized revision filename', async ({ prefix, sessions }) => { await fs.writeFile(path.join(prefix, 'runs', sessions[0], '.x10-control/revisions', 'operator-note'), 'PRESERVE_UNKNOWN', { mode: 0o600 }); }],
  ['corrupt revision checksum', async ({ prefix, sessions, revisions }) => { const f = path.join(prefix, 'runs', sessions[0], '.x10-control/revisions', revisions[0] + '.json'); const value = JSON.parse(await fs.readFile(f)); value.recordSha256 = '0'.repeat(64); await fs.writeFile(f, encode(value)); }],
  ['wrong source directory mode', async ({ prefix, sessions }) => { await fs.chmod(path.join(prefix, 'runs', sessions[1]), 0o755); }],
]) test(`staging source snapshot refuses ${label} and leaves source files present`, () => privateRoot(async parent => {
  const f = await sourceSnapshotFixture(parent, { change });
  await assert.rejects(f.execute, error => typeof error.code === 'string');
  assert.equal(await fs.readFile(path.join(f.prefix, 'bin/nginx'), 'utf8'), 'PUBLIC_SYNTHETIC_NONEXECUTED');
}));

test('staging lock owns and removes its exact original private lock on success', () => privateRoot(async parent => {
  const h = await helpers(), file = path.join(parent, '.alpha-lock'); let calls = 0;
  const result = await h.stagingLock(parent, async () => {
    calls++; const stat = await fs.lstat(file); assert.equal(stat.mode & 0o7777, 0o600); assert.equal(stat.nlink, 1);
    return 'PUBLIC_SYNTHETIC_RESULT';
  });
  assert.equal(result, 'PUBLIC_SYNTHETIC_RESULT'); assert.equal(calls, 1); assert.equal(await exists(file), false);
}));
test('staging lock refuses an existing operator lock without changing its identity or contents', () => privateRoot(async parent => {
  const h = await helpers(), file = path.join(parent, '.alpha-lock'); await fs.writeFile(file, 'PRESERVE_OWNED_LOCK', { mode: 0o600 });
  const stat = await fs.lstat(file); let calls = 0;
  await assert.rejects(() => h.stagingLock(parent, async () => { calls++; }), { code: 'stage_invalid' });
  assert.equal(calls, 0); assert.equal(await fs.readFile(file, 'utf8'), 'PRESERVE_OWNED_LOCK'); assert.equal((await fs.lstat(file)).ino, stat.ino);
}));
test('staging lock removes only its original lock when callback refuses', () => privateRoot(async parent => {
  const h = await helpers(), file = path.join(parent, '.alpha-lock');
  await assert.rejects(() => h.stagingLock(parent, async () => { throw privateError('virtual_callback_refusal'); }), { code: 'virtual_callback_refusal' });
  assert.equal(await exists(file), false);
}));
for (const type of ['replacement', 'in-place change', 'hardlink']) test(`staging lock preserves ${type} rather than deleting unconfirmed operator data`, () => privateRoot(async parent => {
  const h = await helpers(), file = path.join(parent, '.alpha-lock');
  await assert.rejects(() => h.stagingLock(parent, async () => {
    if (type === 'replacement') { await fs.rename(file, file + '.original'); await fs.writeFile(file, 'PRESERVE_UNKNOWN_LOCK', { mode: 0o600 }); }
    if (type === 'in-place change') await fs.writeFile(file, 'PRESERVE_CHANGED_LOCK');
    if (type === 'hardlink') await fs.link(file, file + '.linked');
  }), { code: 'stage_invalid' });
  assert.equal(await exists(file), true);
  if (type === 'replacement') assert.equal(await fs.readFile(file, 'utf8'), 'PRESERVE_UNKNOWN_LOCK');
  if (type === 'in-place change') assert.equal(await fs.readFile(file, 'utf8'), 'PRESERVE_CHANGED_LOCK');
  if (type === 'hardlink') assert.equal((await fs.lstat(file)).nlink, 2);
}));

for (const [label, mutate] of [
  ['declared target ports changed', f => { f.target.manifest.port++; }],
  ['target revision input differs despite a valid record checksum', f => { f.revision.input = { ...f.revision.input, serverBody: 'PUBLIC_DIFFERENT_INPUT' }; f.revision.inputSha256 = digest(JSON.stringify(f.revision.input)); const { recordSha256, ...body } = f.revision; f.revision.recordSha256 = digest(JSON.stringify(body)); }],
  ['target revision retains old parent', f => { f.revision.parent = '9'.repeat(32); const { recordSha256, ...body } = f.revision; f.revision.recordSha256 = digest(JSON.stringify(body)); }],
  ['target history wrong initialization kind', f => { f.history.records[0].type = 'bound'; }],
  ['target history wrong revision', f => { f.history.records[0].details.revision = '9'.repeat(32); }],
  ['target history copied prior entries', f => { f.history.records.push({ type: 'public-synthetic-old-history' }); }],
]) test(`staging refuses ${label} while retaining the new target`, () => privateRoot(async parent => {
  const f = await orchestration(parent, { mutate });
  await assert.rejects(f.execute, { code: 'stage_invalid' });
  assert.equal(await fs.readFile(path.join(f.targetPrefix, 'partial-owned-target'), 'utf8'), 'PUBLIC_SYNTHETIC_TARGET');
  assert.equal(await fs.readFile(f.sourceRecord, 'utf8'), 'PUBLIC_SYNTHETIC_SOURCE\n');
  assert.equal(await exists(f.temporary()), false);
}));
