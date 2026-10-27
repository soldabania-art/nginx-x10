// Immutable baseline producer: invoke by absolute path with exactcd8 (or
// identical2331 CLI/manager bytes) repository root as the working directory.
// All filesystem, child process, runtime, native, signal and clock effects are
// modeled. This is source-extracted virtual control flow, not physical I/O.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import path from 'node:path';
import assert from 'node:assert/strict';
const sourceCommit = 'cd811d9d9d29899859bc3969b496a76481b02dfd';
const sourceBindings = {
  'x10/alpha/cli.mjs': { bytes: 89800, sha256: '4fd2726810b9ff4b8a00c7598c4a97c673cfedf077bde1302e7ad683445336df' },
  'x10/control/manager.mjs': { bytes: 51246, sha256: 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289' },
};
const hash = value => createHash('sha256').update(value).digest('hex'), sources = {};
for (const [file, pin] of Object.entries(sourceBindings)) {
  const bytes = readFileSync(file);
  if (bytes.length !== pin.bytes || hash(bytes) !== pin.sha256) throw new Error(`baseline source pin mismatch: ${file}`);
  sources[file] = bytes.toString('utf8');
}
function block(source, begin, end) {
  const i = source.indexOf(begin), j = source.indexOf(end, i);
  assert(i >= 0 && j > i, 'pinned extraction boundaries');
  return source.slice(i, j);
}
const alpha = sources['x10/alpha/cli.mjs'], manager = sources['x10/control/manager.mjs'];
const proxyCode = block(alpha, 'async function proxy(', '\nexport async function main(') + '\nproxy;';
const waitCode = block(alpha, 'export async function waitBind(', '\nasync function proxy(').replace('export ', '') + '\nwaitBind;';
function functionBlock(name, next) { return block(manager, `async function ${name}(`, next); }
const bindCode = block(manager, 'export async function bind(', '\nasync function rollback(').replace('export ', '');
const eventCode = functionBlock('event', '\nasync function validateCommit(');
const saveCode = block(manager, 'async function save(', '\nasync function exists(');
const durableCode = functionBlock('durableEvent', '\nasync function atomic(');
const controllerCode = durableCode + saveCode + eventCode + bindCode + '\nbind;';
async function proxyCase() {
  let acquisitions = 0, executions = 0;
  const api = vm.runInNewContext(proxyCode, {
    path, CONTROLLER_MUTATION_ENTRY_RESERVE: 7,
    process: { execPath: 'synthetic-node', stdout: { write() {} }, stderr: { write() {} } },
    lifecycle: async () => ({ session: 'synthetic-session' }), controllerState: async () => 'synthetic-state',
    inventory: async () => { acquisitions++; return new Array(4096); },
    requireSessionInventoryCapacity: async () => { acquisitions++; },
    execute: async (_file, args) => { executions++; assert.equal(args[1], 'bind'); return { stdout: '', stderr: '' }; },
  }, { timeout: 1000 });
  const result = await api({ prefix: 'synthetic-prefix' }, 'bind', {});
  assert.equal(result, null); assert.equal(executions, 1); assert.equal(acquisitions, 0);
  return { name: 'alpha-proxy-bind-forwards-at-declared-full-inventory', declaredCumulativeEntries: 4096,
    inventoryAcquisitions: acquisitions, mockedControllerExecutions: executions, actualSourceFlowExtracted: true };
}
async function waitCase(mode) {
  let acquisitions = 0, statusReads = 0, binds = 0, locks = 0, tick = 0;
  const listeners = new Map(), installation = { prefix: 'synthetic-prefix', registry: { current: 'session' }, manifest: {} };
  const life = { session: 'session', stage: 'running', runtime: { synthetic: true }, prefix: 'synthetic-session-prefix' };
  const api = vm.runInNewContext(waitCode, {
    path, Number, Object, Error, CONTROLLER_MUTATION_ENTRY_RESERVE: 7,
    performance: { now: () => mode === 'timeout' && tick++ > 0 ? 10000 : 0 },
    process: {
      on: (name, callback) => listeners.set(name, callback), removeListener: name => listeners.delete(name),
      stderr: { write: () => { if (mode === 'cancel') listeners.get('SIGTERM')(); } },
    },
    installed: async () => installation, lifecycle: async () => life,
    same: (a, b) => JSON.stringify(a) === JSON.stringify(b), inspectMaster: async () => true,
    lock: async (_prefix, operation) => { locks++; return operation(); },
    sessionStatus: async () => { statusReads++; return { control: { bind: async () => { binds++; return { ok: true, outcome: 'bound' }; } }, state: 'synthetic-state' }; },
    load: async () => ({ gateTimeoutMs: 3000 }),
    inventory: async () => { acquisitions++; return new Array(4096); },
    requireSessionInventoryCapacity: async () => { acquisitions++; }, delay: async () => {},
    fail: (code, text) => { throw Object.assign(new Error(text), { code }); },
  }, { timeout: 1000 });
  const result = await api('synthetic-prefix', 10000);
  assert.equal(acquisitions, 0); assert.equal(listeners.size, 0);
  if (mode === 'bound') { assert.equal(statusReads, 1); assert.equal(binds, 1); assert.equal(result.outcome, 'wait_bound'); assert.equal(result.bindingMayHaveCommitted, true); }
  else { assert.equal(statusReads, 0); assert.equal(binds, 0); assert.equal(result.code, mode === 'cancel' ? 'wait_bind_cancelled' : 'wait_bind_timeout'); assert.equal(result.bindingMayHaveCommitted, false); }
  return { name: `alpha-waitBind-${mode}`, declaredCumulativeEntries: 4096, inventoryAcquisitions: acquisitions,
    mockedControllerStatusReads: statusReads, mockedBindAttempts: binds, mockedAlphaLocks: locks,
    outcome: result.outcome, refusalCode: result.code ?? null, bindingMayHaveCommitted: result.bindingMayHaveCommitted,
    callbacksReleased: listeners.size === 0, actualSourceFlowExtracted: true };
}
async function controllerCase(retainTemporary) {
  const entries = new Set(), data = new Map(), base = new Set(['synthetic-state/state.json', 'synthetic-state/history.jsonl']);
  const current = { activeRevision: 'old', binding: null, historyHead: null }, settings = { state: 'synthetic-state' };
  const before = structuredClone(current); data.set('synthetic-state/state.json', JSON.stringify(before));
  let high = 0, atomicCalls = 0;
  const record = () => { high = Math.max(high, entries.size); };
  const api = vm.runInNewContext(controllerCode, {
    path, Buffer, Object, JSON, hash, encode: value => JSON.stringify(value) + '\n', now: () => '2026-10-27T00:00:00.000Z', message: error => error.message,
    lock: async (_state, operation) => { entries.add('controller-lock'); record(); try { return await operation('synthetic-state'); } finally { entries.delete('controller-lock'); } },
    load: async () => ({ settings, current, pending: null }), readRevision: async () => ({ id: 'old', fragmentSha256: 'public' }),
    guard: async () => {}, runtime: async () => ({ syntheticIdentity: true, pid: 1 }), acknowledged: async () => {},
    exists: async file => entries.has(file) || base.has(file), stateShape: value => value,
    json: async file => JSON.parse(data.get(file)), readHistory: async () => [], lstat: async () => ({ size: 0 }),
    commitFile: () => 'synthetic-state/event-commit.json', appendEvent: async () => {},
    atomic: async (file, bytes) => {
      const ordinal = ++atomicCalls, temp = `atomic-temp-${ordinal}`; entries.add(temp); record();
      if (retainTemporary && ordinal === 2) throw Object.assign(new Error('synthetic retained temporary'), { code: 'EIO' });
      entries.delete(temp); if (!base.has(file)) entries.add(file); data.set(file, bytes); record();
    },
    clearCommit: async () => { entries.delete('synthetic-state/event-commit.json'); },
    fail: (code, text) => { throw Object.assign(new Error(text), { code }); },
  }, { timeout: 1000 });
  let result, error;
  try { result = await api('synthetic-state'); } catch (failure) { error = failure.code; }
  assert.equal(high, 3); assert.equal(atomicCalls, 2);
  if (retainTemporary) { assert.equal(error, 'event_commit_incomplete'); assert.equal(entries.size, 2); }
  else { assert.equal(result.outcome, 'bound'); assert.equal(entries.size, 0); }
  return { name: retainTemporary ? 'controller-bind-retained-temporary-overbound-final-state' : 'controller-bind-normal-overbound-transient-control-entries',
    declaredInitialCumulativeEntriesIncludingAlphaLock: 4096, modeledHighWaterCumulativeEntries: 4096 + high,
    modeledFinalCumulativeEntries: 4096 + entries.size, mockedAtomicCalls: atomicCalls, outcome: result?.outcome ?? error,
    retainedNewControllerEntries: entries.size, actualBindAndEventFlowSourceExtracted: true, filesystemAndDurabilityEffectsMocked: true };
}
const results = [await proxyCase(), await waitCase('bound'), await controllerCase(false), await controllerCase(true), await waitCase('cancel'), await waitCase('timeout')];
console.log(JSON.stringify({ kind: 'alpha-bind-capacity-baseline-counterexample', sourceCommit, sourceBindings,
  controls: results.length, pass: results.length, results, virtualOnly: true,
  physicalFixturesExecuted: 0, networkFixturesExecuted: 0, signalsSent: 0,
  limitations: ['Cumulative starting occupancy is declared virtual data; all filesystem, child execution, native runtime, controller identity, signal and clock effects are mocked.',
    'Source-extracted bind/event flow uses abstract atomic primitive accounting; this is not physical high-water measurement or a complete finite-fault proof.',
    'Cancellation uses direct invocation of a mocked callback, not an OS signal. No actual native or controller child executes.',
    'Strict baseline pins intentionally refuse candidate drift; do not refresh these pins after implementation.'] }));
