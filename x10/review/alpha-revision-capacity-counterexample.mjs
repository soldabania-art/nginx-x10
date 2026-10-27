// Immutable baseline producer: run from the repository root on exact447 bytes.
// Only pinned-source VM control flow is exercised; no native process, network,
// signal, real controller state or filesystem mutation is performed.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import path from 'node:path';
import assert from 'node:assert/strict';
const sourceCommit = '447565d452755f508652141a0e15eba166cd547a';
const pins = {
  'x10/alpha/cli.mjs': { bytes: 89441, sha256: '7fda15b58a3579f628b6cdb3b0352cf3cc2fff9baa83a2f11cc0c76e7ac3bdaf' },
  'x10/control/manager.mjs': { bytes: 51246, sha256: 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289' },
};
const sources = {};
for (const [file, pin] of Object.entries(pins)) {
  const bytes = readFileSync(file);
  if (bytes.length !== pin.bytes || createHash('sha256').update(bytes).digest('hex') !== pin.sha256)
    throw new Error(`baseline source pin mismatch: ${file}`);
  sources[file] = bytes.toString('utf8');
}
function block(source, startText, endText) {
  const start = source.indexOf(startText), end = source.indexOf(endText, start);
  assert(start >= 0 && end > start, 'pinned source extraction bounds');
  return source.slice(start, end);
}
const manager = sources['x10/control/manager.mjs'];
const candidateCode = block(manager, 'function candidate(', '\nfunction render(');
const controllerCode = candidateCode + block(manager, 'async function rollback(', '\nexport async function recover(')
  .replaceAll('export async function', 'async function') + '\n({ apply, revert });';
const proxyCode = block(sources['x10/alpha/cli.mjs'], 'async function proxy(', '\nexport async function main(') + '\nproxy;';
async function controllerCase(name, initial, outcome, command = 'apply', bound = true) {
  let entries = initial, created = 0, nativeCalls = 0, released = false;
  const validInput = { serverBody: 'location / { return 200 \"synthetic\"; }', healthURL: 'http://127.0.0.1:19081/ready' };
  const events = [], revisions = new Map([['old', { id: 'old', input: validInput, fragmentSha256: 'public' }]]);
  const current = { activeRevision: 'old', binding: bound ? { public: true } : null };
  const settings = { fragment: 'synthetic-fragment' };
  const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
  const api = vm.runInNewContext(controllerCode, {
    fail, message: error => error.message, now: () => '2026-10-27T00:00:00.000Z',
    Buffer, URL,
    lock: async (_state, operation) => { try { return await operation('synthetic-state'); } finally { released = true; } },
    load: async () => ({ settings, current, pending: null }),
    readRevision: async (_settings, id) => { assert(revisions.has(id)); return revisions.get(id); },
    guard: async () => {},
    makeRevision: async (_settings, input, parent, sourceRevision = null) => {
      const revision = { id: `revision-${++created}`, input, parent, sourceRevision, fragmentSha256: 'public' };
      revisions.set(revision.id, revision); entries++; return revision;
    },
    pending: async () => {}, event: async (_settings, _current, type) => { events.push(type); },
    atomic: async () => {}, render: () => 'synthetic-fragment',
    nativeTest: async () => { if (++nativeCalls === 1 && outcome === 'rejected') fail('native_config_rejected', 'synthetic rejection'); },
    verifyHttps: async () => {}, signal: async () => {},
    acknowledged: async () => { if (outcome === 'rolled_back' && nativeCalls === 1) fail('health_gate_failed', 'synthetic health failure'); },
    clearPending: async () => {},
  }, { timeout: 1000 });
  let result, error;
  try { result = await api[command]('synthetic-state', command === 'apply' ? validInput : 'old'); }
  catch (failure) { error = failure.code; }
  assert(released);
  if (!bound) { assert.equal(error, 'unbound'); assert.equal(created, 0); assert.equal(entries, initial); }
  else { assert.equal(result.outcome, outcome); assert.equal(created, outcome === 'rolled_back' ? 2 : 1); assert(entries > 4096); }
  return { name, command, initialCumulativeEntries: initial, resultingCumulativeEntries: entries,
    retainedNewRevisions: created, outcome: result?.outcome ?? error, exceeds4096: entries > 4096, events,
    actualControllerFlowSourceExtracted: true, filesystemAndNativeEffectsMocked: true };
}
async function proxyCase(command) {
  let calls = 0, inventoryReads = 0;
  const api = vm.runInNewContext(proxyCode, {
    path, process: { execPath: 'synthetic-node', stdout: { write() {} }, stderr: { write() {} } },
    lifecycle: async () => ({ session: 'synthetic-session' }),
    controllerState: async () => 'synthetic-state',
    inventory: async () => { inventoryReads++; return new Array(4096); },
    execute: async (_file, args) => { calls++; assert.equal(args[1], command); return { stdout: '', stderr: '' }; },
  }, { timeout: 1000 });
  const result = await api({ prefix: 'synthetic-prefix' }, command, command === 'apply' ? { file: 'synthetic-candidate' } : { revision: 'old' });
  assert.equal(result, null); assert.equal(calls, 1); assert.equal(inventoryReads, 0);
  return { name: `alpha-${command}-forwards-without-inventory-admission`, command,
    declaredCumulativeEntries: 4096, mockedControllerExecutions: calls, inventoryReads,
    actualProxyFlowSourceExtracted: true, childExecutionMocked: true };
}
const results = [
  await controllerCase('apply-success-retains-overbound-revision', 4096, 'applied'),
  await controllerCase('native-rejection-retains-overbound-candidate', 4096, 'rejected'),
  await controllerCase('revert-rollback-retains-two-overbound-revisions', 4095, 'rolled_back', 'revert'),
  await controllerCase('unbound-control-refuses-before-revision', 4096, 'applied', 'apply', false),
  await proxyCase('apply'), await proxyCase('revert'),
];
console.log(JSON.stringify({ kind: 'alpha-controller-revision-capacity-baseline-counterexample', sourceCommit,
  sourceBindings: pins, controls: results.length, pass: results.length, results,
  virtualOnly: true, physicalFixturesExecuted: 0, networkFixturesExecuted: 0, signalsSent: 0,
  limitations: ['Cumulative occupancy is a declared virtual starting count; the source-extracted controller counterexamples count only retained new revisions.',
    'Filesystem, child execution, native test, acknowledgement, signal and durability effects are mocked; no physical high-water or complete transaction reservation is established.',
    'The proxy cases establish lack of inventory acquisition before delegation, not actual physical native execution or a resource exhaustion exploit.',
    'These immutable baseline source pins intentionally refuse changed candidate sources; do not repin this producer after implementation.'] }));
