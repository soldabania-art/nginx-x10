import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, chmod, lstat, readdir, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import crypto from 'node:crypto';
import vm from 'node:vm';
import path from 'node:path';
import os from 'node:os';

// Source-extracted install/inventory/atomic operations run with virtual native
// creation and build/identity observations. Tempfile controls execute no binary,
// child, signal, socket or service. Occupancy is not a physical native high-water.
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const manager = await readFile(new URL('../control/manager.mjs', import.meta.url), 'utf8');
const hash = x => crypto.createHash('sha256').update(x).digest('hex');
assert.equal(Buffer.byteLength(manager), 51246);
assert.equal(hash(manager), 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289', 'Review control-entry accounting before changing this manager pin');
function body(name) {
  const re = new RegExp(`(?:export )?async function ${name}\\(`), match = re.exec(source); assert(match, name);
  const end = source.indexOf('\n}', match.index); assert(end > match.index); return source.slice(match.index, end + 2).replace(/^export /, '');
}
function constant(name) { const m = new RegExp(`\\b${name}\\s*=\\s*([0-9]+)\\s*;`).exec(source); assert(m, name); return Number(m[1]); }
const limit = constant('INVENTORY_ENTRY_LIMIT'), reserve = constant('INITIAL_PUBLICATION_INSPECTION_RESERVE');
const extracted = ['atomic', 'saveRecord', 'inventory', 'requireSessionInventoryCapacity', 'install'].map(body).join('\n');
const fail = (code, message = code) => { throw Object.assign(new Error(message), { code }); };
function fixture({ occupancy = 4093, restored = false, scanFailure, unsafe, registryFailure, createFailure, beforeCreateFailure, bundled = false } = {}) {
  const prefix = '/parent/installation', entries = new Map(), events = []; let serial = 0, created = false, registryWrites = 0, scans = 0, atScan = null;
  const add = (file, kind = 'file', bytes = '') => { if (file === prefix || file.startsWith(prefix + '/')) entries.set(file, { kind, bytes }); };
  const stat = kind => ({ uid: 1000, mode: kind === 'directory' ? 0o40700 : 0o100600, dev: 1, ino: 1, isSymbolicLink: () => false, isDirectory: () => kind === 'directory', isFile: () => kind === 'file' });
  const count = () => entries.size - (entries.has(prefix) ? 1 : 0);
  const context = {
    path, Buffer, Object, Set, Map, Date, Number, JSON, Error, constants, process: { platform: 'linux', versions: { node: '24' }, env: { HOME: '/operator-home' }, getuid: () => 1000, execPath: '/synthetic-node', version: 'v24.synthetic' },
    root: '/source', controlNames: ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'], alphaNames: ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'],
    recipePath: 'lib/service/user-unit.mjs', staticDirectories: ['bin', 'lib', 'lib/control', 'lib/alpha', 'licenses', 'examples', 'runs'],
    INVENTORY_ENTRY_LIMIT: limit, INITIAL_PUBLICATION_INSPECTION_RESERVE: reserve,
    simple: () => true, canonical: async () => {}, digest: hash, encode: x => JSON.stringify(x) + '\n', id: () => String(++serial).padStart(32, '0'), fail,
    exists: async file => file === '/source/bundle.json' ? bundled : entries.has(file),
    sourceBuild: async () => { if (beforeCreateFailure) fail(beforeCreateFailure); return { binary: '/synthetic-native', source: '/upstream', manifestSha256: 'a'.repeat(64), build: { binary: { sha256: 'b'.repeat(64), bytes: 1 }, upstreamRevision: 'synthetic' }, dependencies: {} }; },
    bundleBuild: async () => ({ bundleSchemaVersion: 2, binary: '/synthetic-native', source: '/upstream', manifestSha256: 'a'.repeat(64), build: { binary: { sha256: 'b'.repeat(64), bytes: 1 }, upstreamRevision: 'synthetic' }, dependencies: {} }),
    readBackup: async () => ({ port: 9080, healthPort: 9081, input: { serverBody: 'restored-literal' } }),
    demo: () => ({ serverBody: 'demo' }), application: () => ({ serverBody: 'application' }),
    readFile: async () => Buffer.from('synthetic-nonexecuted-source'), realpath: async x => x, chmod: async () => {},
    mkdir: async file => add(file, 'directory'), copyFile: async (_file, target) => add(target), writeFile: async (file, bytes) => add(file, 'file', bytes),
    lstat: async file => { if (created && scanFailure === 'lstat') fail('synthetic_lstat'); const s = stat(entries.get(file)?.kind || 'directory'); if (created && unsafe === 'foreign' && file.endsWith('/native-0')) s.uid = 2000; if (created && unsafe === 'symlink' && file.endsWith('/native-0')) s.isSymbolicLink = () => true; return s; },
    owned: async (file, directory) => { if (created) { scans++; events.push('inventory'); atScan = count(); if (scanFailure === 'owned') fail('synthetic_owned'); } return stat(directory ? 'directory' : 'file'); },
    readdir: async file => { if (scanFailure === 'readdir') fail('synthetic_readdir'); return [...entries.keys()].filter(x => x !== prefix && path.dirname(x) === file).map(x => path.basename(x)); },
    open: async (file, flags) => {
      if (flags & constants.O_CREAT) { if (file.includes('.alpha-registry.json')) { registryWrites++; events.push('registry'); if (registryFailure === 'open') fail('synthetic_registry'); } add(file); }
      return { writeFile: async bytes => { if (file.includes('.alpha-registry.json') && registryFailure === 'write') fail('synthetic_registry'); entries.get(file).bytes = bytes; }, sync: async () => {}, close: async () => {} };
    },
    rename: async (from, to) => { const value = entries.get(from); entries.delete(from); entries.set(to, value); },
    createSession: async () => {
      created = true; events.push('create');
      for (let i = 0; count() < occupancy; i++) add(prefix + `/native-${i}`, 'file', `retained-native-${i}`);
      if (createFailure) fail(createFailure);
      return { session: 's', initial: { revision: 'r' }, lifecycle: { prefix: prefix + '/runs/s' } };
    }
  };
  vm.createContext(context); vm.runInContext(extracted + '\nglobalThis.runInstall = install; globalThis.check = requireSessionInventoryCapacity;', context);
  const values = { prefix, ...(restored ? { restore: '/synthetic-backup' } : {}) };
  return { prefix, entries, events, context, count, run: () => context.runInstall(values), registryWrites: () => registryWrites, scans: () => scans, atScan: () => atScan, created: () => created };
}

test('reviewed initial publication/first-inspection reserve is3 and shared bound remains4096', () => { assert.equal(reserve, 3); assert.equal(limit, 4096); });
for (const [n, v] of [['NEW_SESSION_MINIMUM_ENTRIES', 17], ['REGISTRY_PUBLICATION_RESERVE', 1], ['CONTROLLER_MUTATION_ENTRY_RESERVE', 7], ['CONTROLLER_BIND_ENTRY_RESERVE', 3]])
  test(`existing ${n} remains ${v}`, () => assert.equal(constant(n), v));
for (const occupancy of [40, 4092, 4093]) test(`initial occupancy${occupancy} publishes one registry with read-lock headroom`, async () => {
  const f = fixture({ occupancy }); const result = await f.run(); assert.equal(result.outcome, 'installed'); assert.equal(f.atScan(), occupancy); assert.equal(f.registryWrites(), 1); assert.equal(f.count(), occupancy + 1); assert(f.count() + 2 <= limit); assert(f.scans() > 0); assert(f.entries.has(f.prefix + '/.alpha-install.json'));
  assert(f.events.indexOf('create') < f.events.indexOf('inventory')); assert(f.events.indexOf('inventory') < f.events.indexOf('registry'));
});
for (const occupancy of [4094, 4095, 4096, 4097]) test(`postcreate occupancy${occupancy} refuses before registry and preserves incomplete prefix`, async () => {
  const f = fixture({ occupancy }); await assert.rejects(f.run(), e => { assert.equal(e.code, 'inventory_limit'); assert.match(e.message, /incomplete private prefix preserved for inspection/); return true; });
  assert(f.created()); assert.equal(f.registryWrites(), 0); assert.equal(f.count(), occupancy); assert(!f.entries.has(f.prefix + '/.alpha-registry.json')); assert(f.entries.has(f.prefix + '/native-0')); assert(f.entries.has(f.prefix + '/.alpha-install.json'));
});
for (const scanFailure of ['owned', 'readdir', 'lstat']) test(`postcreate inventory ${scanFailure} refusal preserves records without publishing`, async () => {
  const f = fixture({ occupancy: 40, scanFailure }); await assert.rejects(f.run(), { code: `synthetic_${scanFailure}` }); assert(f.created()); assert.equal(f.registryWrites(), 0); assert.equal(f.count(), 40); assert(f.entries.has(f.prefix + '/native-0'));
});
for (const unsafe of ['foreign', 'symlink']) test(`unsafe ${unsafe} postcreate entry is preserved with no registry`, async () => {
  const f = fixture({ occupancy: 40, unsafe }); await assert.rejects(f.run(), { code: 'unsafe_path' }); assert.equal(f.registryWrites(), 0); assert.equal(f.count(), 40); assert(f.entries.has(f.prefix + '/native-0'));
});
for (const bundled of [false, true]) for (const occupancy of [4093, 4094]) test(`${bundled ? 'bundled' : 'source'} restore occupancy${occupancy} uses identical publication admission`, async () => {
  const f = fixture({ occupancy, restored: true, bundled });
  if (occupancy === 4093) { const r = await f.run(); assert.equal(r.declarativeRestored, true); assert.equal(r.nativeStarted, false); assert.equal(r.serviceAccepted, false); assert.equal(f.registryWrites(), 1); }
  else { await assert.rejects(f.run(), { code: 'inventory_limit' }); assert.equal(f.registryWrites(), 0); }
});
for (const registryFailure of ['open', 'write']) test(`registry atomic ${registryFailure} failure is preserved without retry`, async () => {
  const f = fixture({ occupancy: 4093, registryFailure }); await assert.rejects(f.run(), e => { assert.equal(e.code, 'synthetic_registry'); assert.match(e.message, /incomplete private prefix preserved/); return true; }); assert.equal(f.registryWrites(), 1); assert(f.count() <= 4094); assert(f.entries.has(f.prefix + '/native-0'));
});
test('createSession failure still preserves incomplete prefix and does not inventory or publish', async () => {
  const f = fixture({ occupancy: 4097, createFailure: 'synthetic_native' }); await assert.rejects(f.run(), { code: 'synthetic_native' }); assert.equal(f.scans(), 0); assert.equal(f.registryWrites(), 0); assert.equal(f.count(), 4097);
});
test('build refusal still precedes prefix creation and capacity acquisition', async () => {
  const f = fixture({ beforeCreateFailure: 'synthetic_build' }); await assert.rejects(f.run(), { code: 'synthetic_build' }); assert.equal(f.count(), 0); assert(!f.created()); assert.equal(f.scans(), 0);
});
test('actual stage dispatch delegates target creation through install restore before target inspection', () => {
  const s = body('stagePackage'), installAt = s.indexOf('const result = await install({ prefix, restore: file });'); assert(installAt >= 0); assert(installAt < s.indexOf('const target = await installed(prefix)')); assert(s.includes('preserve both installations'));
});
test('new admission is ordered after createSession and before initial registry publication', () => {
  const s = body('install'), create = s.indexOf('const prepared = await createSession(prefix, manifest, seed);'), check = s.indexOf('await requireSessionInventoryCapacity(prefix, INITIAL_PUBLICATION_INSPECTION_RESERVE);'), registry = s.indexOf("await saveRecord(path.join(prefix, '.alpha-registry.json')"); assert(create < check && check < registry); assert.equal(s.match(/requireSessionInventoryCapacity\(/g)?.length, 1); assert(s.includes('incomplete private prefix preserved for inspection'));
});
test('emergency stop and recovery retain their previous capacity behavior', () => { assert(!body('stop').includes('requireSessionInventoryCapacity')); assert(!body('proxy').includes("command === 'recover') await requireSessionInventoryCapacity")); });
test('owned4094-entry tempfile refusal preserves native placeholder and installation record identities', async () => {
  const prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-initial-capacity-')); await chmod(prefix, 0o700);
  try {
    const retained = [['.alpha-install.json', Buffer.from('{"public":"incomplete-installation"}\n'), 0o600], ['native-placeholder', Buffer.from('SYNTHETIC NONEXECUTED NATIVE\n'), 0o500]];
    for (const [name, bytes, mode] of retained) await writeFile(path.join(prefix, name), bytes, { mode });
    for (let start = retained.length; start < 4094; start += 128) await Promise.all(Array.from({ length: Math.min(128, 4094 - start) }, (_, i) => writeFile(path.join(prefix, `retained-${start + i}`), '', { mode: 0o600 })));
    const beforeNames = (await readdir(prefix)).sort(), stats = await Promise.all(retained.map(([name]) => lstat(path.join(prefix, name))));
    const deps = { path, process, fail, INVENTORY_ENTRY_LIMIT: limit, owned: async f => { const s = await lstat(f); assert(s.isDirectory()); assert.equal(s.uid, process.getuid()); assert.equal(s.mode & 0o077, 0); }, lstat, readdir };
    const fn = new (Object.getPrototypeOf(async function () {}).constructor)(...Object.keys(deps), body('inventory') + '\n' + body('requireSessionInventoryCapacity') + '\nreturn requireSessionInventoryCapacity;');
    await assert.rejects((await fn(...Object.values(deps)))(prefix, reserve), { code: 'inventory_limit' });
    assert.deepEqual((await readdir(prefix)).sort(), beforeNames);
    for (let i = 0; i < retained.length; i++) { const [name, bytes] = retained[i], after = await lstat(path.join(prefix, name)); assert.deepEqual(await readFile(path.join(prefix, name)), bytes); for (const k of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[k], stats[i][k]); }
  } finally { await rm(prefix, { recursive: true, force: true }); }
});
