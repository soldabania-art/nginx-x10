import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, lstat, readdir, chmod, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';

// Production helper/control-flow extraction only. Native/controller observations
// below are mocks; owned tempfile checks never start a process, socket or service.
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
function body(name) {
  const start = source.indexOf(`async function ${name}(`); assert(start >= 0, `Missing production helper ${name}`);
  const end = source.indexOf('\n}', start); assert(end > start);
  return source.slice(start, end + 2);
}
const constants = Object.fromEntries(['INVENTORY_ENTRY_LIMIT', 'NEW_SESSION_MINIMUM_ENTRIES', 'REGISTRY_PUBLICATION_RESERVE'].map(name => {
  const match = new RegExp(`\\b${name}\\s*=\\s*([0-9]+)\\s*;`).exec(source); assert(match, `Missing finite constant ${name}`);
  return [name, Number(match[1])];
}));
const extracted = ['inventory', 'requireSessionInventoryCapacity', 'prepareRun'].map(body).join('\n');
const make = deps => new AsyncFunction(...Object.keys({ ...constants, ...deps }), `${extracted}\nreturn {inventory, requireSessionInventoryCapacity, prepareRun};`)(...Object.values({ ...constants, ...deps }));
function filesystem(entries, { failure, unsafe, uid = process.getuid() } = {}) {
  const seen = { owned: 0, readdir: 0, lstat: 0 };
  const root = '/synthetic/capacity';
  return { root, seen,
    owned: async file => { seen.owned++; if (failure === 'owned') fail('synthetic_owned'); assert(entries.get(path.relative(root, file)) === 'directory'); },
    readdir: async file => { seen.readdir++; if (failure === 'readdir') fail('synthetic_readdir'); const relative = path.relative(root, file); return [...entries.keys()].filter(k => k !== '' && path.posix.dirname(k) === (relative || '.')).map(k => path.posix.basename(k)); },
    lstat: async file => { seen.lstat++; if (failure === 'lstat') fail('synthetic_lstat'); const relative = path.relative(root, file), kind = entries.get(relative); assert(kind);
      return { uid: unsafe === relative ? uid + 1 : uid, isSymbolicLink: () => kind === 'symlink', isDirectory: () => kind === 'directory', isFile: () => kind === 'file' }; }
  };
}
const flat = count => new Map([['', 'directory'], ...Array.from({ length: count }, (_, i) => [`entry-${String(i).padStart(5, '0')}`, 'file'])]);
async function runtime(fs, extra = {}) { return make({ path, process, fail, digest, owned: fs.owned, readdir: fs.readdir, lstat: fs.lstat, ...extra }); }
function sessionTree(count, extraRevisions = 0) {
  const rows = new Map([['', 'directory'], ['runs', 'directory']]);
  const dirs = ['logs', 'temp', 'temp/client', 'temp/proxy', 'temp/fastcgi', 'temp/uwsgi', 'temp/scgi', '.x10-control', '.x10-control/revisions'];
  const files = ['nginx.conf', 'lifecycle.json', 'managed.conf', '.x10-control/history.jsonl', '.x10-control/settings.json', '.x10-control/state.json', '.x10-control/revisions/' + 'b'.repeat(32) + '.json'];
  for (let i = 0; i < count; i++) { const base = `runs/${i.toString(16).padStart(32, '0')}`; rows.set(base, 'directory'); for (const dir of dirs) rows.set(`${base}/${dir}`, 'directory'); for (const file of files) rows.set(`${base}/${file}`, 'file'); }
  for (let i = 0; i < extraRevisions; i++) rows.set(`runs/${'0'.repeat(32)}/.x10-control/revisions/extra-${i}.json`, 'file');
  return rows;
}
async function preparation({ rows = flat(10), stage = 'stopped', sessions = 1, extraAfterCreate = 17, failure, corrupt } = {}) {
  const fs = filesystem(rows, failure?.scan ? { failure: failure.scan } : {}), events = [], original = { stage, session: 'a'.repeat(32), prefix: fs.root + '/runs/' + 'a'.repeat(32), runtime: null, controlSocket: null };
  const context = { prefix: fs.root, manifest: {}, registry: { current: original.session, sessions: Array.from({ length: sessions }, (_, i) => i.toString(16).padStart(32, '0')) } }; context.registry.sessions[0] = original.session;
  const before = JSON.stringify(context), input = { healthURL: 'http://127.0.0.1:18081/ready', healthExpectedBody: 'ready\n' };
  const revisionBody = { input, inputSha256: digest(JSON.stringify(input)) }, revision = { ...revisionBody, recordSha256: digest(JSON.stringify(revisionBody)) };
  if (corrupt) revision.recordSha256 = '0'.repeat(64);
  let created = false, published = false;
  const readDirectory = fs.readdir;
  fs.readdir = async (...args) => { if (created && failure?.postScan) fail(failure.postScan); return readDirectory(...args); };
  const operation = name => { events.push(name); if (failure?.at === name) fail(failure.code); };
  const r = await runtime(fs, {
    lifecycle: async () => { operation('lifecycle'); return original; }, stopped: async () => operation('stopped'),
    sessionStatus: async () => { operation('status'); return { result: { lastConfirmedRevision: 'b'.repeat(32) } }; },
    load: async () => { operation('revision'); return revision; },
    createSession: async () => { operation('create'); created = true; for (let i = 0; i < extraAfterCreate; i++) rows.set(`new-session-entry-${i}`, 'file');
      return { session: 'c'.repeat(32), lifecycle: { stage: 'prepared', session: 'c'.repeat(32), runtime: null, controlSocket: null } }; },
    saveRecord: async () => { operation('publish'); published = true; }
  });
  return { fs, rows, context, before, original, events, run: () => r.prepareRun(context), created: () => created, published: () => published };
}

for (const [name, expected] of [['INVENTORY_ENTRY_LIMIT', 4096], ['NEW_SESSION_MINIMUM_ENTRIES', 17], ['REGISTRY_PUBLICATION_RESERVE', 1]])
  test(`reviewed finite ${name} remains ${expected}`, () => assert.equal(constants[name], expected));
for (const count of [0, 1, 4095, 4096]) test(`inventory accepts exactly ${count} cumulative entries`, async () => {
  const fs = filesystem(flat(count)), r = await runtime(fs), result = await r.inventory(fs.root); assert.equal(result.length, count); assert.equal(fs.seen.lstat, count);
});
for (const count of [4097, 4098, 5000]) test(`inventory refuses ${count} entries without acquiring the 4097th leaf`, async () => {
  const fs = filesystem(flat(count)), r = await runtime(fs); await assert.rejects(r.inventory(fs.root), { code: 'inventory_limit' }); assert.equal(fs.seen.lstat, 4096);
});
for (const [count, reserve, accepted] of [[4078, 18, true], [4079, 18, false], [4095, 1, true], [4096, 1, false]])
  test(`capacity ${count}+${reserve} ${accepted ? 'fits' : 'refuses'} the shared4096 bound`, async () => {
    const fs = filesystem(flat(count)), r = await runtime(fs); if (accepted) await r.requireSessionInventoryCapacity(fs.root, reserve); else await assert.rejects(r.requireSessionInventoryCapacity(fs.root, reserve), { code: 'inventory_limit' });
  });
for (const reserve of [0, -1, 1.5, NaN, Infinity, 4097, undefined, null, '1', [], {}, Symbol('public')])
  test(`capacity refuses invalid reserve ${typeof reserve}:${String(reserve)} before filesystem I/O`, async () => {
    const fs = filesystem(flat(1)), r = await runtime(fs); await assert.rejects(r.requireSessionInventoryCapacity(fs.root, reserve), { code: 'inventory_limit' }); assert.deepEqual(fs.seen, { owned: 0, readdir: 0, lstat: 0 });
  });
for (const failure of ['owned', 'readdir', 'lstat']) test(`capacity scan ${failure} failure preserves registry before any session creation`, async () => {
  const f = await preparation({ failure: { scan: failure } }); await assert.rejects(f.run(), { code: `synthetic_${failure}` }); assert.equal(JSON.stringify(f.context), f.before); assert(!f.created()); assert(!f.published());
});
for (const kind of ['symlink', 'foreign']) test(`unsafe ${kind} entry is preserved before creating a session`, async () => {
  const rows = flat(1), fs = filesystem(rows, kind === 'foreign' ? { unsafe: 'entry-00000' } : {}); if (kind === 'symlink') rows.set('entry-00000', 'symlink');
  const r = await runtime(fs); await assert.rejects(r.requireSessionInventoryCapacity(fs.root, 18), { code: 'unsafe_path' }); assert.equal(rows.size, 2);
});
for (const count of [200, 255]) test(`${count} minimal sessions use actual whole-prefix occupancy`, async () => {
  const rows = sessionTree(count), f = await preparation({ rows, sessions: count });
  if (count === 200) { await f.run(); assert(f.created()); assert(f.published()); }
  else { await assert.rejects(f.run(), { code: 'inventory_limit' }); assert(!f.created()); assert(!f.published()); assert.equal(JSON.stringify(f.context), f.before); }
});
test('revision-heavy one-session prefix refuses without relying on a session cap', async () => {
  const rows = sessionTree(1, 4061), f = await preparation({ rows }); assert.equal(rows.size - 1, 4079);
  await assert.rejects(f.run(), { code: 'inventory_limit' }); assert(!f.created()); assert(!f.published()); assert.equal(JSON.stringify(f.context), f.before);
});
test('exact pre4078 and post4095 boundaries publish one fresh session and preserve existing entries', async () => {
  const rows = flat(4078), originalRows = [...rows], f = await preparation({ rows }); await f.run();
  assert(f.created()); assert(f.published()); assert.equal(f.context.registry.sessions.length, 2); assert.equal(f.context.registry.current, 'c'.repeat(32));
  for (const [name, value] of originalRows) assert.equal(rows.get(name), value); assert.equal(rows.size - 1, 4095);
});
for (const added of [18, 30]) test(`post-create ${added}-entry growth refuses before registry mutation and retains orphan data`, async () => {
  const rows = flat(4078), f = await preparation({ rows, extraAfterCreate: added }); await assert.rejects(f.run(), { code: 'session_capacity_unresolved' });
  assert(f.created()); assert(!f.published()); assert.equal(JSON.stringify(f.context), f.before); assert.equal(rows.size - 1, 4078 + added); assert(rows.has('new-session-entry-0'));
});
for (const code of ['EACCES', 'synthetic_post_scan']) test(`post-create ${code} scan error becomes unresolved without registry publication`, async () => {
  const rows = flat(10), f = await preparation({ rows, failure: { postScan: code } });
  await assert.rejects(f.run(), error => { assert.equal(error.code, 'session_capacity_unresolved'); assert.equal(error.cause.code, code); assert.match(error.message, /STOP/); assert.match(error.message, /preserve/); assert.match(error.message, /do not retry/); assert.doesNotMatch(error.message, /synthetic\/capacity/); return true; });
  assert(f.created()); assert(!f.published()); assert.equal(JSON.stringify(f.context), f.before); assert.equal(rows.size - 1, 27);
});
for (const stage of ['prepared', 'running', 'stopping', 'faulted']) test(`${stage} retains the existing lifecycle boundary without new session allocation`, async () => {
  const f = await preparation({ stage, rows: flat(4097) });
  if (stage === 'prepared') { assert.equal(await f.run(), f.original); assert.equal(f.fs.seen.lstat, 0); }
  else await assert.rejects(f.run(), { code: 'stop_required' });
  assert(!f.created()); assert(!f.published()); assert.equal(JSON.stringify(f.context), f.before);
});
test('existing256-session cap still refuses before capacity I/O and creation', async () => {
  const f = await preparation({ sessions: 256 }); await assert.rejects(f.run(), { code: 'session_limit' }); assert.equal(f.fs.seen.lstat, 0); assert(!f.created()); assert(!f.published());
});
test('invalid confirmed revision refuses before capacity I/O and creation', async () => {
  const f = await preparation({ corrupt: true }); await assert.rejects(f.run(), { code: 'alpha_integrity' }); assert.equal(f.fs.seen.lstat, 0); assert(!f.created()); assert(!f.published());
});

test('owned tempfile capacity refusal preserves existing record bytes, identity, mode and timestamps', async () => {
  const prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-capacity-records-')); await chmod(prefix, 0o700);
  try {
    const registry = path.join(prefix, '.alpha-registry.json'), old = Buffer.from('{"public":"unchanged"}\n'); await writeFile(registry, old, { mode: 0o600 });
    await mkdir(path.join(prefix, 'revisions'), { mode: 0o700 }); await writeFile(path.join(prefix, 'revisions', 'old.json'), '{}\n', { mode: 0o400 });
    const names = await readdir(prefix), before = await lstat(registry);
    const owned = async (file, directory = false, privateDirectory = false) => { const s = await lstat(file); assert.equal(s.uid, process.getuid()); assert.equal(s.isSymbolicLink(), false); assert.equal(directory ? s.isDirectory() : s.isFile(), true); if (privateDirectory) assert.equal(s.mode & 0o077, 0); return s; };
    const r = await make({ path, process, fail, digest, owned, readdir, lstat });
    await assert.rejects(r.requireSessionInventoryCapacity(prefix, 4094), { code: 'inventory_limit' });
    const after = await lstat(registry); assert.deepEqual(await readFile(registry), old); for (const k of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[k], before[k]);
    assert.deepEqual(await readdir(prefix), names); assert.deepEqual(await readdir(path.join(prefix, 'revisions')), ['old.json']);
  } finally { await rm(prefix, { recursive: true, force: true }); }
});
