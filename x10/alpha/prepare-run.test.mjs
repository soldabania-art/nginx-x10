import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

// Source-extracted controls exercise production preparation failure boundaries.
// They neither activate a manager nor establish native service acceptance.
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const helper = source.slice(source.indexOf('async function prepareRun(context) {'), source.indexOf('\nasync function run(prefix, values) {'));
assert(helper.startsWith('async function prepareRun(context) {'));
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const digest = value => createHash('sha256').update(value).digest('hex');
function fail(code) { throw Object.assign(new Error(code), { code }); }
function fixture({ stage = 'stopped', failure = null, sessions = 1, corrupt = null } = {}) {
  const events = [], original = { stage, session: 'a'.repeat(32), prefix: '/synthetic/runs/' + 'a'.repeat(32), runtime: null, controlSocket: null };
  const context = { prefix: '/synthetic', manifest: { installationId: 'synthetic' }, registry: { current: original.session, sessions: Array.from({ length: sessions }, (_, i) => i.toString(16).padStart(32, '0')) } };
  context.registry.sessions[0] = original.session;
  const input = { healthURL: 'http://127.0.0.1:9001/ready', healthExpectedBody: 'ready\n' };
  const body = { input, inputSha256: digest(JSON.stringify(input)) };
  const revision = { ...body, recordSha256: digest(JSON.stringify(body)) };
  if (corrupt === 'record') revision.recordSha256 = '0'.repeat(64);
  if (corrupt === 'input') { revision.inputSha256 = '0'.repeat(64); revision.recordSha256 = digest(JSON.stringify({ input, inputSha256: revision.inputSha256 })); }
  const operation = name => { events.push(name); if (failure?.at === name) fail(failure.code); };
  const dependencies = {
    path, digest, fail,
    lifecycle: async actual => { assert.equal(actual, context); operation('lifecycle'); return original; },
    stopped: async (actual, life) => { assert.equal(actual, context); assert.equal(life, original); operation('stopped'); },
    sessionStatus: async (actual, life) => { assert.equal(actual, context); assert.equal(life, original); operation('status'); return { result: { lastConfirmedRevision: 'b'.repeat(32) } }; },
    load: async file => { assert.equal(file, path.join(original.prefix, '.x10-control/revisions', 'b'.repeat(32) + '.json')); operation('revision'); return revision; },
    createSession: async (prefix, manifest, seed) => { assert.equal(prefix, context.prefix); assert.equal(manifest, context.manifest); assert.equal(seed, input); operation('create'); return { session: 'c'.repeat(32), lifecycle: { stage: 'prepared', session: 'c'.repeat(32), runtime: null, controlSocket: null } }; },
    saveRecord: async (file, registry) => { assert.equal(file, '/synthetic/.alpha-registry.json'); assert.equal(registry, context.registry); assert.equal(registry.current, 'c'.repeat(32)); assert.equal(registry.sessions.at(-1), 'c'.repeat(32)); operation('publish'); },
  };
  const prepare = new AsyncFunction(...Object.keys(dependencies), helper + '\nreturn prepareRun;')(...Object.values(dependencies));
  return { context, original, events, prepare: async () => (await prepare)(context) };
}

test('source preparation reuses a guarded prepared session without writes', async () => {
  const f = fixture({ stage: 'prepared' }), before = JSON.stringify(f.context.registry);
  assert.equal(await f.prepare(), f.original); assert.deepEqual(f.events, ['lifecycle', 'stopped', 'status']);
  assert.equal(JSON.stringify(f.context.registry), before);
});
test('source preparation publishes only after absence, operator integrity and exact confirmed input', async () => {
  const f = fixture(), life = await f.prepare();
  assert.equal(life.stage, 'prepared'); assert.equal(life.runtime, null);
  assert.deepEqual(f.events, ['lifecycle', 'stopped', 'status', 'revision', 'create', 'publish']);
  assert.equal(f.context.registry.current, life.session); assert.equal(f.context.registry.sessions.length, 2);
});
for (const [at, code] of [['lifecycle', 'alpha_integrity'], ['stopped', 'alpha_live'], ['stopped', 'abnormal_exit'], ['status', 'operator_conflict'], ['revision', 'alpha_integrity'], ['create', 'fixture_create_failed'], ['publish', 'fixture_publish_failed']]) {
  test(`source preparation preserves ${code} at ${at} without claiming success`, async () => {
    const f = fixture({ failure: { at, code } });
    await assert.rejects(f.prepare(), { code }); assert.equal(f.events.at(-1), at);
    if (!['create', 'publish'].includes(at)) { assert(!f.events.includes('create')); assert(!f.events.includes('publish')); }
    if (at === 'create') assert(!f.events.includes('publish'));
  });
}
for (const stage of ['running', 'stopping', 'faulted']) {
  test(`source preparation refuses unsupported ${stage} even when absence observer returns`, async () => {
    const f = fixture({ stage }); await assert.rejects(f.prepare(), { code: 'stop_required' });
    assert(!f.events.includes('create')); assert(!f.events.includes('publish'));
  });
}
test('source preparation refuses the session bound before reading or writing a replacement', async () => {
  const f = fixture({ sessions: 256 }); await assert.rejects(f.prepare(), { code: 'session_limit' });
  assert.deepEqual(f.events, ['lifecycle', 'stopped', 'status']);
});
for (const corrupt of ['record', 'input']) {
  test(`source preparation refuses corrupted ${corrupt} integrity before creation`, async () => {
    const f = fixture({ corrupt }); await assert.rejects(f.prepare(), { code: 'alpha_integrity' });
    assert.deepEqual(f.events, ['lifecycle', 'stopped', 'status', 'revision']);
  });
}
