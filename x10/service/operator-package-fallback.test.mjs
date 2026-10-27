import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { assessKeptAReactivationPreparation, forEachUniqueRetiredInstallation,
  main, mainFallback, readManagedHeldState } from './operator-package-return.mjs';
import { checkManagedOperatorReturnFailureReport, checkManagedOperatorReturnReport } from './operator-package-return-proof.mjs';
import { checkManagedOperatorFallbackFailureReport, checkManagedOperatorFallbackReport } from './operator-package-fallback-proof.mjs';

// Only synthetic records and callback schedules are exercised here. Invalid
// argument entry tests refuse before preflight or any native/manager operation.
// No sockets, NGINX, process fixtures, signals or systemd queries are started.
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const ids = { installation: '1'.repeat(32), oldSession: '2'.repeat(32), newSession: '3'.repeat(32),
  oldRevision: '4'.repeat(32), newRevision: '5'.repeat(32) };
const prefix = '/synthetic/kept-a';
const input = () => ({ serverBody: 'location / { return 200 "synthetic P"; }',
  healthURL: 'http://127.0.0.1:19081/ready', healthExpectedStatus: 200, healthExpectedBody: 'ready\n' });
function snapshots() {
  const selected = input(), installationId = ids.installation;
  const make = (session, revision, stage, sessions) => ({
    manifest: { prefix, installationId },
    registry: { installationId, current: session, sessions },
    life: { session, prefix: `${prefix}/runs/${session}`, installationId, stage,
      runtime: stage === 'prepared' ? null : { pid: 4242 }, controlSocket: stage === 'prepared' ? null : `${prefix}/control.sock` },
    status: { binding: stage === 'prepared' ? null : { pid: 4242 }, pending: null,
      configUnchanged: true, fragmentMatchesLastConfirmed: true, history: { integrity: true, entries: stage === 'prepared' ? 1 : 3 },
      lastConfirmedRevision: revision },
    revision: { id: revision, parent: stage === 'prepared' ? null : '6'.repeat(32), sourceRevision: null,
      input: structuredClone(selected), inputSha256: digest(selected) },
  });
  return { prior: make(ids.oldSession, ids.oldRevision, 'stopped', [ids.oldSession]),
    prepared: make(ids.newSession, ids.newRevision, 'prepared', [ids.oldSession, ids.newSession]) };
}
const check = ({ prior, prepared }) => assessKeptAReactivationPreparation(prior, prepared);

test('kept-A preparation accepts the retained installation and P with a second unbound fresh session', () => {
  const pair = snapshots(), before = structuredClone(pair);
  assert.equal(check(pair), true); assert.deepEqual(pair, before);
  assert.equal(pair.prior.manifest.prefix, pair.prepared.manifest.prefix);
  assert.notEqual(pair.prior.registry.current, pair.prepared.registry.current);
});

for (const [label, mutate] of [
  ['fresh installation replacing kept A', p => { p.prepared.manifest.installationId = '7'.repeat(32); }],
  ['different prefix replacing kept A', p => { p.prepared.manifest.prefix = '/synthetic/replacement-a'; }],
  ['manifest installation not a token', p => { p.prepared.manifest.installationId = 'true'; }],
  ['registry belongs to another installation', p => { p.prepared.registry.installationId = '7'.repeat(32); }],
  ['lifecycle belongs to another installation', p => { p.prepared.life.installationId = '7'.repeat(32); }],
  ['same old session selected', p => { p.prepared.registry.current = ids.oldSession; }],
  ['new current session not in registry', p => { p.prepared.registry.current = '8'.repeat(32); }],
  ['lifecycle names another session', p => { p.prepared.life.session = '8'.repeat(32); }],
  ['lifecycle uses old session prefix', p => { p.prepared.life.prefix = p.prior.life.prefix; }],
  ['lifecycle points outside kept prefix', p => { p.prepared.life.prefix = `/synthetic/foreign/runs/${ids.newSession}`; }],
  ['old session discarded', p => { p.prepared.registry.sessions = [ids.newSession]; }],
  ['duplicate new registry sessions', p => { p.prepared.registry.sessions = [ids.newSession, ids.newSession]; }],
  ['unrelated prior session substituted', p => { p.prepared.registry.sessions = ['8'.repeat(32), ids.newSession]; }],
  ['third session added', p => { p.prepared.registry.sessions.push('8'.repeat(32)); }],
  ['new session malformed', p => { p.prepared.registry.current = '3'.repeat(31); }],
  ['running preparation', p => { p.prepared.life.stage = 'running'; }],
  ['stopped preparation', p => { p.prepared.life.stage = 'stopped'; }],
  ['runtime carried into fresh session', p => { p.prepared.life.runtime = { pid: 4242 }; }],
  ['control socket carried into fresh session', p => { p.prepared.life.controlSocket = `${prefix}/control.sock`; }],
  ['old binding carried into fresh session', p => { p.prepared.status.binding = structuredClone(p.prior.status.binding); }],
  ['pending controller operation', p => { p.prepared.status.pending = { revision: ids.newRevision }; }],
  ['configuration changed', p => { p.prepared.status.configUnchanged = false; }],
  ['confirmed fragment changed', p => { p.prepared.status.fragmentMatchesLastConfirmed = false; }],
  ['history integrity unknown', p => { p.prepared.status.history.integrity = null; }],
  ['empty fresh history', p => { p.prepared.status.history.entries = 0; }],
  ['copied old history', p => { p.prepared.status.history.entries = 3; }],
  ['old revision reused', p => { p.prepared.revision.id = ids.oldRevision; p.prepared.status.lastConfirmedRevision = ids.oldRevision; }],
  ['revision not confirmed', p => { p.prepared.status.lastConfirmedRevision = '8'.repeat(32); }],
  ['new revision has an old parent', p => { p.prepared.revision.parent = ids.oldRevision; }],
  ['new revision has source authority', p => { p.prepared.revision.sourceRevision = ids.oldRevision; }],
  ['P body replaced by B input', p => { p.prepared.revision.input.serverBody = 'location / { return 503; }'; p.prepared.revision.inputSha256 = digest(p.prepared.revision.input); }],
  ['P health expectation changed', p => { p.prepared.revision.input.healthExpectedBody = 'wrong\n'; p.prepared.revision.inputSha256 = digest(p.prepared.revision.input); }],
  ['P digest changed alone', p => { p.prepared.revision.inputSha256 = '9'.repeat(64); }],
]) test(`kept-A preparation refuses ${label} without changing the records`, () => {
  const pair = snapshots(); mutate(pair); const before = structuredClone(pair);
  assert.equal(check(pair), false); assert.deepEqual(pair, before);
});

for (const [side, record] of [['prior', null], ['prepared', null], ['prior', undefined],
  ['prepared', undefined], ['prior', []], ['prepared', []]])
  test(`kept-A preparation refuses absent or unsupported ${side} record ${String(record)}`, () => {
    const pair = snapshots(); pair[side] = record; assert.equal(check(pair), false);
  });

function contexts() {
  return [Object.freeze({ prefix: '/synthetic/kept-a', name: 'initial A' }),
    Object.freeze({ prefix: '/synthetic/candidate-b', name: 'failed B' }),
    Object.freeze({ prefix: '/synthetic/kept-a', name: 'fallback A' })];
}
test('cleanup verifies every unit before deleting each installation exactly once in reverse-context order', async () => {
  const selected = Object.freeze(contexts()), seen = [], removed = [], order = [];
  await forEachUniqueRetiredInstallation(selected, async ctx => {
    order.push(`verify ${ctx.name}`); seen.push(ctx); return true;
  }, async ctx => { order.push(`remove ${ctx.name}`); removed.push(ctx); });
  assert.deepEqual(seen, selected);
  assert.deepEqual(removed, [selected[2], selected[1]]);
  assert.deepEqual(order, ['verify initial A', 'verify failed B', 'verify fallback A', 'remove fallback A', 'remove failed B']);
});
for (const failedIndex of [0, 1, 2]) test(`cleanup failure at unit ${failedIndex + 1} prevents every installation removal`, async () => {
  const selected = contexts(), seen = [], removed = [];
  await assert.rejects(() => forEachUniqueRetiredInstallation(selected, async ctx => {
    seen.push(ctx); if (ctx === selected[failedIndex]) throw new Error('synthetic unretired unit'); return true;
  }, async ctx => { removed.push(ctx); }));
  assert.equal(removed.length, 0); assert.deepEqual(seen, selected.slice(0, failedIndex + 1));
});
for (const badResult of [false, null, undefined, 0, 'true', {}])
  test(`cleanup refuses non-true retirement result ${String(badResult)} before any removal`, async () => {
    const selected = contexts(), removed = [];
    await assert.rejects(() => forEachUniqueRetiredInstallation(selected,
      async ctx => ctx === selected[2] ? badResult : true, async ctx => { removed.push(ctx); }));
    assert.deepEqual(removed, []);
  });
test('cleanup waits for the last context verification before starting removal', async () => {
  const selected = contexts(), removed = []; let release, blocked;
  const waiting = new Promise(resolve => { blocked = resolve; });
  const pending = forEachUniqueRetiredInstallation(selected, async ctx => {
    if (ctx === selected[2]) { blocked(); return new Promise(resolve => { release = resolve; }); }
    return true;
  }, async ctx => { removed.push(ctx); });
  await waiting; assert.deepEqual(removed, []); release(true); await pending;
  assert.deepEqual(removed, [selected[2], selected[1]]);
});
test('cleanup propagates removal refusal and never proceeds to another installation', async () => {
  const selected = contexts(), removed = [];
  await assert.rejects(() => forEachUniqueRetiredInstallation(selected, async () => true, async ctx => {
    removed.push(ctx); throw new Error('synthetic changed installation');
  }));
  assert.deepEqual(removed, [selected[2]]);
});
for (const [label, mutate] of [
  ['missing prefix', a => { a[1] = {}; }],
  ['relative prefix', a => { a[1] = { prefix: 'candidate-b' }; }],
  ['traversal prefix', a => { a[1] = { prefix: '/synthetic/../candidate-b' }; }],
  ['LF prefix', a => { a[1] = { prefix: '/synthetic/candidate-b\n' }; }],
  ['root prefix', a => { a[1] = { prefix: '/' }; }],
  ['nonstring prefix', a => { a[1] = { prefix: { toString: () => '/synthetic/candidate-b' } }; }],
]) test(`cleanup refuses ${label} before calling verification or removal`, async () => {
  const selected = contexts(), called = []; mutate(selected);
  await assert.rejects(() => forEachUniqueRetiredInstallation(selected, async () => { called.push('verify'); return true; },
    async () => { called.push('remove'); }));
  assert.deepEqual(called, []);
});
for (const [verify, remove] of [[null, async () => {}], [async () => true, null], [true, async () => {}]])
  test('cleanup rejects unsupported callback types before invoking a callback', async () => {
    await assert.rejects(() => forEachUniqueRetiredInstallation(contexts(), verify, remove));
  });

test('cleanup refuses a sparse context array before any verification or removal', async () => {
  const selected = contexts(), called = []; delete selected[1];
  await assert.rejects(() => forEachUniqueRetiredInstallation(selected, async () => { called.push('verify'); return true; },
    async () => { called.push('remove'); }));
  assert.deepEqual(called, []); assert.equal(Object.hasOwn(selected, 1), false);
});
test('cleanup refuses a prefix accessor without evaluating it or invoking callbacks', async () => {
  let reads = 0; const called = [], selected = contexts();
  selected[1] = Object.defineProperty({}, 'prefix', { enumerable: true, get() { reads++; return '/synthetic/candidate-b'; } });
  await assert.rejects(() => forEachUniqueRetiredInstallation(selected, async () => { called.push('verify'); return true; },
    async () => { called.push('remove'); }));
  assert.equal(reads, 0); assert.deepEqual(called, []);
});

async function privateTree(root, relative = '') {
  const file = path.join(root, relative), stat = await lstat(file);
  const row = { relative, ino: stat.ino, mode: stat.mode, uid: stat.uid, nlink: stat.nlink };
  if (!stat.isDirectory()) return [{ ...row, bytes: (await readFile(file)).toString('hex') }];
  const rows = [row];
  for (const name of (await readdir(file)).sort()) rows.push(...await privateTree(root, path.join(relative, name)));
  return rows;
}
async function heldFixture(fn) {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-held-read-pure-')); await chmod(parent, 0o700);
  try {
    const prefix = path.join(parent, 'a'), session = ids.oldSession, revisionId = ids.oldRevision;
    const sessionPrefix = path.join(prefix, 'runs', session), control = path.join(sessionPrefix, '.x10-control');
    await mkdir(path.join(control, 'revisions'), { recursive: true, mode: 0o700 });
    await mkdir(path.join(prefix, '.alpha-lock'), { mode: 0o700 });
    await mkdir(path.join(control, 'lock'), { mode: 0o700 });
    await mkdir(path.join(prefix, 'bin'), { mode: 0o700 });
    const manifest = { schemaVersion: 2, kind: 'nginx-x10-local-alpha', prefix, installationId: ids.installation };
    const registry = { schemaVersion: 1, installationId: ids.installation, current: session, sessions: [session] };
    const life = { schemaVersion: 1, installationId: ids.installation, session, prefix: sessionPrefix,
      stage: 'running', runtime: { pid: 4242, executable: 'synthetic-not-executed' }, controlSocket: `${prefix}/control.sock` };
    const revisionBody = { id: revisionId, parent: null, sourceRevision: null, input: input(), inputSha256: digest(input()) };
    const revision = { ...revisionBody, recordSha256: digest(revisionBody) }, historyHead = 'a'.repeat(64);
    const state = { schemaVersion: 1, activeRevision: revisionId, previousRevision: null, binding: null, historyHead };
    const files = { manifest: path.join(prefix, '.alpha-install.json'), registry: path.join(prefix, '.alpha-registry.json'),
      lifecycle: path.join(sessionPrefix, 'lifecycle.json'), state: path.join(control, 'state.json'),
      revision: path.join(control, 'revisions', `${revisionId}.json`), pending: path.join(control, 'pending.json'),
      eventCommit: path.join(control, 'event-commit.json') };
    const save = (file, value, mode = 0o600) => writeFile(file, JSON.stringify(value) + '\n', { mode });
    const saveRecord = (file, value) => save(file, { ...value, sha256: digest(value) });
    await saveRecord(files.manifest, manifest); await saveRecord(files.registry, registry); await saveRecord(files.lifecycle, life);
    await save(files.state, state); await save(files.revision, revision, 0o400);
    await writeFile(path.join(prefix, '.alpha-lock', 'owner'), 'synthetic held alpha lock\n', { mode: 0o600 });
    await writeFile(path.join(control, 'lock', 'owner'), 'synthetic held controller lock\n', { mode: 0o600 });
    // A wrong CLI-based reader would try this path while both locks are held.
    // Its bytes are never executed in this pure/private-file test.
    await writeFile(path.join(prefix, 'bin', 'x10'), 'throw new Error("synthetic CLI must never execute");\n', { mode: 0o500 });
    await fn({ parent, prefix, sessionPrefix, files, manifest, registry, life, revision, state,
      expected: { manifest: structuredClone(manifest), registry: structuredClone(registry), revision: structuredClone(revision), status: { history: { head: historyHead } } },
      save, saveRecord });
  } finally { await rm(parent, { recursive: true, force: true }); }
}
test('held startup reader captures matching raw unbound state with both operator locks already present', () => heldFixture(async f => {
  const before = await privateTree(f.parent), expected = structuredClone(f.expected);
  const value = await readManagedHeldState(f.prefix, f.expected);
  assert.deepEqual(value.manifest, f.manifest); assert.deepEqual(value.registry, f.registry);
  assert.deepEqual(value.life, f.life); assert.deepEqual(value.revision, f.revision);
  assert.equal(value.sessionPrefix, f.sessionPrefix); assert.deepEqual(value.status, { binding: null, pending: null });
  assert.deepEqual(f.expected, expected); assert.deepEqual(await privateTree(f.parent), before);
}));
for (const [label, mutate] of [
  ['manifest checksum corruption', async f => { await f.save(f.files.manifest, { ...f.manifest, sha256: 'b'.repeat(64) }); }],
  ['another manifest installation', async f => { await f.saveRecord(f.files.manifest, { ...f.manifest, installationId: 'b'.repeat(32) }); }],
  ['another selected registry session', async f => { await f.saveRecord(f.files.registry, { ...f.registry, current: 'b'.repeat(32), sessions: ['b'.repeat(32)] }); }],
  ['registry checksum corruption', async f => { await f.save(f.files.registry, { ...f.registry, sha256: 'b'.repeat(64) }); }],
  ['lifecycle session mismatch', async f => { await f.saveRecord(f.files.lifecycle, { ...f.life, session: 'b'.repeat(32) }); }],
  ['lifecycle not running', async f => { await f.saveRecord(f.files.lifecycle, { ...f.life, stage: 'prepared' }); }],
  ['missing native runtime', async f => { await f.saveRecord(f.files.lifecycle, { ...f.life, runtime: null }); }],
  ['unexpected lifecycle control socket', async f => { await f.saveRecord(f.files.lifecycle, { ...f.life, controlSocket: null }); }],
  ['committed controller binding', async f => { await f.save(f.files.state, { ...f.state, binding: { pid: 4242 } }); }],
  ['unexpected previous revision', async f => { await f.save(f.files.state, { ...f.state, previousRevision: 'b'.repeat(32) }); }],
  ['different history head', async f => { await f.save(f.files.state, { ...f.state, historyHead: 'b'.repeat(64) }); }],
  ['unknown controller state field', async f => { await f.save(f.files.state, { ...f.state, force: true }); }],
  ['pending operation', async f => { await f.save(f.files.pending, { synthetic: true }); }],
  ['unfinished event commit', async f => { await f.save(f.files.eventCommit, { synthetic: true }); }],
  ['mutable revision mode0600', async f => { await chmod(f.files.revision, 0o600); }],
  ['nonprivate state mode0644', async f => { await chmod(f.files.state, 0o644); }],
  ['revision checksum corruption', async f => { await chmod(f.files.revision, 0o600); await f.save(f.files.revision, { ...f.revision, recordSha256: 'b'.repeat(64) }); await chmod(f.files.revision, 0o400); }],
  ['different valid revision input', async f => { const body = { ...f.revision, input: { ...input(), healthExpectedBody: 'other\n' } }; delete body.recordSha256;
    body.inputSha256 = digest(body.input); await chmod(f.files.revision, 0o600); await f.save(f.files.revision, { ...body, recordSha256: digest(body) }); await chmod(f.files.revision, 0o400); }],
]) test(`held startup reader refuses ${label} while preserving all existing records and held locks`, () => heldFixture(async f => {
  await mutate(f); const before = await privateTree(f.parent), expected = structuredClone(f.expected);
  await assert.rejects(() => readManagedHeldState(f.prefix, f.expected));
  assert.deepEqual(f.expected, expected); assert.deepEqual(await privateTree(f.parent), before);
}));

test('importing the fallback CLI does not install fixture signal listeners or change process exit status', async () => {
  const before = { sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM'), exitCode: process.exitCode };
  const wrapper = await import('./operator-package-fallback.mjs');
  assert.equal(typeof wrapper, 'object');
  assert.deepEqual({ sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM'), exitCode: process.exitCode }, before);
});
test('invalid fallback arguments produce only a finite fallback refusal and release their own listeners', async () => {
  const before = { sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM') };
  const report = await mainFallback([]);
  assert.equal(report.ok, false); assert.equal(report.code, 'usage_refused');
  assert.equal(report.phase, 'arguments'); assert.equal(report.primaryFailure, 'usage_refused'); assert.equal(report.proof, null);
  assert.equal(checkManagedOperatorFallbackFailureReport(report).validFailureReport, true);
  assert.equal(checkManagedOperatorFallbackReport(report).ok, false);
  assert.equal(checkManagedOperatorReturnReport(report).ok, false);
  assert.equal(checkManagedOperatorReturnFailureReport(report).validFailureReport, false);
  assert.deepEqual({ sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM') }, before);
  assert.doesNotMatch(JSON.stringify(report), /\/synthetic\/|SYNTHETIC_PRIVATE/);
});
test('normal entry still emits only the normal refusal contract when arguments are invalid', async () => {
  const report = await main([]);
  assert.equal(report.ok, false); assert.equal(report.code, 'usage_refused');
  assert.equal(checkManagedOperatorReturnFailureReport(report).validFailureReport, true);
  assert.equal(checkManagedOperatorFallbackFailureReport(report).validFailureReport, false);
});
