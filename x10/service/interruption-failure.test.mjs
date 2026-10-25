import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { assessInterruptedRecovery, classifyOperatorHoldDecision, createOperatorHoldDiagnostics } from './lifecycle-check.mjs';

// These controls execute quoted baseline/extracted candidate closures against
// in-memory dependencies. They never create processes, send signals, or unlink
// actual files. Native/service failure containment remains an exact-CI gate.
const lifecycleSource = await readFile(new URL('./lifecycle-check.mjs', import.meta.url), 'utf8');
const operatorSource = await readFile(new URL('./interrupted-operator.mjs', import.meta.url), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const digest = value => createHash('sha256').update(value).digest('hex');
const reject = code => { throw Object.assign(new Error(code), { code }); };
const clone = value => structuredClone(value);

// Exact 680-byte tail from verifyOperatorInterruption on 3bf729a8. Recording
// this counterexample does not reconstruct that hosted run's hidden timing.
const baselineTail = String.raw`    } catch (error) { primary = error; }
    finally {
      try { if (operator && await operator.close() !== true) reject('operator_interruption_unconfirmed'); } catch (error) { failures.cleanup(error, 'operator_close'); if (!primary) primary = error; }
      try { if (held && await held.abort() !== true) reject('operator_interruption_unconfirmed'); } catch (error) { failures.cleanup(error, 'operator_close'); if (!primary) primary = error; }
    }
    if (primary) throw primary;
    checkCancelled();
    if (Object.values(report.operatorInterruptionProof).some(value => value !== true)) reject('operator_interruption_unconfirmed');
    report.operatorInterruptionChecks++;
`;
const initialProofs = () => Object.fromEntries([
  'candidateProbeHeld', 'pendingReloadObserved', 'lastConfirmedPreserved', 'sameServiceObserved',
  'ownedOperatorTerminated', 'staleLocksPreserved', 'lockedRecoveryRefused', 'exactLockRemovalConfirmed',
  'explicitRollbackObserved', 'pendingCleared', 'restoredContentVerified', 'noPostReplay',
  'sameServiceAfterRecovery', 'repeatedRecoveryIdempotent',
].map((key, i) => [key, i < 4]));

test('recorded baseline failure-tail identity is exact and bounded', () => {
  assert.equal(Buffer.byteLength(baselineTail), 680);
  assert.equal(digest(baselineTail), '9461ca72e0e955137a761beef48e1cbb742d95daccf87a000efe62dcef548390');
});

test('baseline close success still reaches outer unit stop with both stale locks and pending state', async () => {
  const events = [], primary = Object.assign(new Error('fixed observed refusal'), { code: 'operator_fixture_not_held' });
  const report = { operatorInterruptionChecks: 0, operatorInterruptionProof: initialProofs() };
  const proofs = clone(report.operatorInterruptionProof), locks = new Set(['alpha', 'controller']); let pending = true;
  const operator = { async close() { events.push('operator.close'); return true; },
    async removeCapturedLocks() { events.push('remove'); locks.clear(); },
    async retireCapturedLocksAfterFailure() { events.push('retire'); locks.clear(); } };
  const held = { async abort() { events.push('hold.abort'); return true; } };
  const run = new AsyncFunction('operator', 'held', 'failures', 'report', 'reject', 'checkCancelled', 'observed',
    'let primary = null; try { throw observed;\n' + baselineTail);
  const cleanup = [];
  await assert.rejects(async () => {
    try { await run(operator, held, { cleanup: (...args) => cleanup.push(args) }, report, reject, () => {}, primary); }
    catch (error) { events.push('unit.stop'); assert.equal(locks.size, 2); assert.equal(pending, true); throw error; }
  }, error => error === primary);
  assert.deepEqual(events, ['operator.close', 'hold.abort', 'unit.stop']); assert.deepEqual(cleanup, []);
  assert.equal(report.operatorInterruptionChecks, 0); assert.deepEqual(report.operatorInterruptionProof, proofs);
});

function operatorHandleFactory() {
  const start = operatorSource.indexOf('  const handle = Object.freeze({');
  const end = operatorSource.indexOf('\n  checkCancelled();\n  child = spawn(', start);
  assert(start >= 0 && end > start, 'candidate operator handle source boundary');
  const body = operatorSource.slice(start, end).replace('const handle =', 'handle =');
  return new Function('env', `
    let captured = env.captured ?? true, terminated = env.terminated ?? true, retired = false;
    let closeConfirmed = env.closeConfirmed ?? true, retirementAttempted = false;
    let closed = true, wrapper = {}, control = {}, decision = true, terminating = null;
    let signalAttempted = false, cleanupAttempted = false, child = { pid: 101 };
    const locks = env.locks, pending = env.pending;
    const alphaLock = 'alpha', controlLock = 'controller', pendingPath = 'pending';
    const { limit, checkCancelled, guards, confirmAbsent, lockRecord, file, unlink, same, fail } = env;
    let handle;
    ${body}
    return { handle, decision: () => ({ captured, terminated, retired, closeConfirmed, retirementAttempted }) };
  `);
}

function virtualOperator(options = {}) {
  const events = [], state = { clock: 0, cancelled: false, absent: true };
  const locks = [
    { meta: { ino: 1, mode: 0o600 }, sha256: 'a'.repeat(64), pid: 101 },
    { meta: { ino: 2, mode: 0o600 }, sha256: 'b'.repeat(64), pid: 102 },
  ];
  const pending = { meta: { ino: 3, mode: 0o600 }, sha256: 'c'.repeat(64) };
  const records = new Map([['alpha', clone(locks[0])], ['controller', clone(locks[1])], ['pending', clone(pending)]]);
  const calls = Object.create(null);
  async function boundary(name, fn) {
    events.push(name); calls[name] = (calls[name] || 0) + 1;
    if (options.before) await options.before(name, calls[name], { state, records, events });
    const result = fn();
    if (options.after) await options.after(name, calls[name], { state, records, events });
    return result;
  }
  const env = { locks, pending, captured: options.captured, terminated: options.terminated, closeConfirmed: options.closeConfirmed,
    same: (a, b) => JSON.stringify(a) === JSON.stringify(b), fail: reject,
    limit() { events.push('limit'); if (state.clock >= 10000) reject('operator_fixture_timeout'); },
    checkCancelled() { events.push('cancel'); if (state.cancelled) reject('operator_fixture_cancelled'); },
    guards: () => boundary('guards', () => true),
    confirmAbsent: () => boundary('absence', () => { if (!state.absent) reject('operator_fixture_exit_unknown'); return true; }),
    lockRecord: name => boundary('lock:' + name, () => { if (!records.has(name)) reject('operator_fixture_lock_changed'); return clone(records.get(name)); }),
    file: name => boundary('file:' + name, () => { if (!records.has(name)) reject('operator_fixture_pending'); return clone(records.get(name)); }),
    unlink: name => boundary('unlink:' + name, () => { assert(['alpha', 'controller'].includes(name)); assert(records.has(name)); records.delete(name); }),
  };
  const result = operatorHandleFactory()(env);
  return { ...result, events, state, records, calls };
}

test('failure retirement uses exactly the original two locks and preserves pending bytes', async () => {
  const f = virtualOperator(); const beforePending = clone(f.records.get('pending'));
  assert.deepEqual(await f.handle.retireCapturedLocksAfterFailure(), { ok: true, alphaRemoved: true, controllerRemoved: true, pendingPreserved: true });
  assert.deepEqual([...f.records.keys()], ['pending']); assert.deepEqual(f.records.get('pending'), beforePending);
  assert.deepEqual(f.events.filter(x => x.startsWith('unlink:')), ['unlink:alpha', 'unlink:controller']);
  assert.equal(f.handle.assertCleanupAuthority(), true); assert.equal(f.decision().retired, true);
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
});

for (const [name, option] of Object.entries({ noOriginalCapture: { captured: false }, noConfirmedClose: { closeConfirmed: false }, noConfirmedTermination: { terminated: false } })) {
  test('failure retirement refuses ' + name + ' without touching records', async () => {
    const f = virtualOperator(option), before = clone([...f.records]);
    await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
    assert.deepEqual([...f.records], before); assert.equal(f.decision().retired, false);
    assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_state' });
  });
}

for (const [name, mutate, code] of [
  ['expiredOriginalDeadline', f => { f.state.clock = 10000; }, 'operator_fixture_timeout'],
  ['cancelledOwner', f => { f.state.cancelled = true; }, 'operator_fixture_cancelled'],
  ['changedAlphaInode', f => { f.records.get('alpha').meta.ino++; }, 'operator_fixture_lock_changed'],
  ['changedControllerHash', f => { f.records.get('controller').sha256 = 'e'.repeat(64); }, 'operator_fixture_lock_changed'],
  ['foreignControllerPID', f => { f.records.get('controller').pid = 103; }, 'operator_fixture_lock_changed'],
  ['changedPendingInode', f => { f.records.get('pending').meta.ino++; }, 'operator_fixture_pending'],
  ['changedPendingHash', f => { f.records.get('pending').sha256 = 'f'.repeat(64); }, 'operator_fixture_pending'],
  ['unknownProcessAbsence', f => { f.state.absent = false; }, 'operator_fixture_exit_unknown'],
]) {
  test('failure retirement refuses ' + name + ' before any unlink and cannot be rearmed', async () => {
    const f = virtualOperator(); mutate(f); const before = clone([...f.records]);
    await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code });
    assert.deepEqual([...f.records], before); assert(!f.events.some(x => x.startsWith('unlink:')));
    assert.equal(f.decision().retired, false); f.state.clock = 0; f.state.cancelled = false; f.state.absent = true;
    await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
  });
}

for (const [name, action, code] of [
  ['changedSecondInode', ({ records }) => { records.get('controller').meta.ino++; }, 'operator_fixture_lock_changed'],
  ['ownerCancelled', ({ state }) => { state.cancelled = true; }, 'operator_fixture_cancelled'],
  ['deadlineExpired', ({ state }) => { state.clock = 10000; }, 'operator_fixture_timeout'],
  ['processReappeared', ({ state }) => { state.absent = false; }, 'operator_fixture_exit_unknown'],
]) {
  test('partial retirement after first unlink refuses ' + name + ' and preserves second lock', async () => {
    const f = virtualOperator({ after(name, _n, env) { if (name === 'unlink:alpha') action(env); } });
    await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code });
    assert.equal(f.records.has('alpha'), false); assert.equal(f.records.has('controller'), true); assert.equal(f.records.has('pending'), true);
    assert.equal(f.decision().retired, false); assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_state' });
    await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
  });
}

test('pending mutation after both unlinks still refuses cleanup authority and preserves the record', async () => {
  const f = virtualOperator({ after(name, _n, { records }) { if (name === 'unlink:controller') records.get('pending').sha256 = 'd'.repeat(64); } });
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_pending' });
  assert.deepEqual([...f.records.keys()], ['pending']); assert.equal(f.decision().retired, false);
  assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_state' });
});

test('a late first-unlink continuation after cancellation cannot retire the second lock or authorize recovery', async () => {
  let entered, resume; const atFirst = new Promise(resolve => { entered = resolve; }), pending = new Promise(resolve => { resume = resolve; });
  const f = virtualOperator({ async after(name) { if (name === 'unlink:alpha') { entered(); await pending; } } });
  const result = f.handle.retireCapturedLocksAfterFailure(); await atFirst; f.state.cancelled = true; resume();
  await assert.rejects(result, { code: 'operator_fixture_cancelled' });
  assert.equal(f.records.has('controller'), true); assert.equal(f.decision().retired, false);
  assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_state' });
});

test('successful retirement authority expires and is revoked by cancellation without a new decision', async () => {
  const f = virtualOperator(); await f.handle.retireCapturedLocksAfterFailure();
  assert.equal(f.handle.assertCleanupAuthority(), true); f.state.clock = 10000;
  assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_timeout' });
  f.state.clock = 0; f.state.cancelled = true;
  assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_cancelled' });
});

test('unconfirmed close cannot unlock failure retirement even with original capture', async () => {
  const f = virtualOperator({ closeConfirmed: false }); f.state.absent = false;
  assert.equal(await f.handle.close(), false);
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
  assert.equal(f.records.size, 3); assert.equal(f.decision().closeConfirmed, false);
});

test('confirmed close of an uncaptured handle never invents original capture authority', async () => {
  const f = virtualOperator({ captured: false, closeConfirmed: false }); assert.equal(await f.handle.close(), true);
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_state' });
  assert.equal(f.records.size, 3); assert.equal(f.decision().captured, false);
});

test('failure-retirement and cleanup-authority APIs reject arguments and keep the original snapshot shape', async () => {
  const f = virtualOperator();
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure({}), { code: 'operator_fixture_state' });
  assert.throws(() => f.handle.assertCleanupAuthority({}), { code: 'operator_fixture_state' });
  assert.deepEqual(Object.keys(f.handle.snapshot()), ['running', 'wrapperCaptured', 'controllerCaptured', 'groupCaptured', 'terminated', 'locksRetired']);
  assert.equal(f.decision().retirementAttempted, false); assert.equal(f.records.size, 3);
});

function failureTail() {
  const start = lifecycleSource.indexOf('  async function verifyOperatorInterruption()');
  const end = lifecycleSource.indexOf('  async function verifyControlledSlowDrain()', start);
  const fn = lifecycleSource.slice(start, end);
  const tail = fn.slice(fn.lastIndexOf('    } catch (error) { primary = error; }'), fn.lastIndexOf('\n  }'));
  assert(tail.includes('operator.retireCapturedLocksAfterFailure()') && tail.includes('operator.assertCleanupAuthority()'));
  return tail;
}

function containmentModel(options = {}) {
  const events = [], awaits = [], calls = Object.create(null), cleanups = [];
  const observed = options.observed === null ? null : Object.assign(new Error('fixed primary refusal'), { code: 'operator_fixture_not_held' });
  const proofs = initialProofs(); if (options.fullProofs) for (const key of Object.keys(proofs)) proofs[key] = true;
  const report = { operatorInterruptionChecks: 0, operatorInterruptionProof: proofs,
    operatorInterruptionContainment: { attempted: false, operatorAbsent: false, holdClosed: false, snapshotRevalidated: false,
      locksRetired: false, recoveryVerified: false, completed: false, disposition: 'not_needed' } };
  const state = { cancelled: false, clock: 0, pendingUnchanged: true, serviceUnchanged: true, postCount: 0,
    pendingAbsent: true, statusPending: null, httpGood: true, tlsGood: true, repeatedOutcome: 'nothing_pending',
    stateSHA: 'confirmed-state', historySHA: 'confirmed-history', closeResult: true, abortResult: true, authorityResult: true,
    retiredResult: { ok: true, alphaRemoved: true, controllerRemoved: true, pendingPreserved: true } };
  const previousRevision = 'a'.repeat(32), failedRevision = 'b'.repeat(32), revision = 'c'.repeat(32);
  const input = { synthetic: 'previous-input' }, inputSha256 = digest(JSON.stringify(input));
  const binding = { syntheticIdentity: 'owned-native' }, snapshot = { failedRevision };
  const restored = { id: revision, parent: previousRevision, sourceRevision: previousRevision, inputSha256, input };
  const recovery = { ok: false, outcome: 'rolled_back', reason: 'explicit_recovery', revision, failedRevision, restoredContentFrom: previousRevision };
  const initialProofSnapshot = clone(report.operatorInterruptionProof);
  async function step(name, fn) {
    const count = calls[name] = (calls[name] || 0) + 1;
    events.push(name); awaits.push(name + ':' + count);
    if (options.before) await options.before(name, count, model);
    const result = fn();
    if (options.after) await options.after(name, count, model);
    return result;
  }
  const operator = {
    close: () => step('operator.close', () => state.closeResult),
    retireCapturedLocksAfterFailure: () => step('retire', () => clone(state.retiredResult)),
    assertCleanupAuthority() { events.push('authority');
      if (state.clock >= 10000) reject('operator_fixture_timeout');
      if (state.cancelled) reject('operator_fixture_cancelled'); return state.authorityResult; },
  };
  const held = { abort: () => step('hold.abort', () => state.abortResult) };
  const env = { operator: options.noOperator ? undefined : operator, held: options.noHold ? undefined : held,
    snapshot: options.noSnapshot ? null : snapshot, normalRetirementAttempted: options.normalRetirementAttempted === true,
    report, failures: { cleanup(error, stage) { cleanups.push({ code: error?.code || 'unknown', stage }); } }, reject,
    checkCancelled() { if (state.cancelled) reject('cancelled'); },
    unchangedPending: value => step('pending.check', () => { assert.equal(value, snapshot); if (!state.pendingUnchanged) reject('operator_fixture_pending'); }),
    sameServiceNoCLI: () => step('service.check', () => { if (!state.serviceUnchanged) reject('unit_invocation_changed'); }),
    node: 'synthetic-node', launcher: 'synthetic-launcher', env: {}, previousRevision,
    command: (_node, args) => step('recover', () => {
      assert.deepEqual(args, ['synthetic-launcher', 'recover']);
      return { ok: false, exitCode: 1, termination: 'exit_nonzero', stderr: '', stdout: JSON.stringify(recovery) };
    }), assessInterruptedRecovery,
    cli: (_node, _launcher, args) => step('cli.' + args[0], () => {
      if (args[0] === 'recover') return { ok: true, outcome: state.repeatedOutcome };
      assert.deepEqual(args, ['status']);
      return { pending: state.statusPending, lastConfirmedRevision: revision, binding: clone(binding), runtime: { identityValid: true },
        configUnchanged: true, fragmentMatchesLastConfirmed: true, history: { integrity: true } };
    }),
    interruptionFile: path => {
      if (path.endsWith('/revisions/' + revision + '.json')) return step('read.restored', () => ({ value: { ...clone(restored), recordSha256: digest(JSON.stringify(restored)) } }));
      if (path.endsWith('/state.json')) return step('read.state', () => ({ sha256: state.stateSHA }));
      if (path.endsWith('/history.jsonl')) return step('read.history', () => ({ sha256: state.historySHA }));
      assert.fail('unexpected synthetic record');
    }, statePath: '/synthetic/state', digest,
    previous: { value: { inputSha256, input } }, originalState: { value: { binding } },
    absent: path => step('pending.absent', () => { assert(path.endsWith('/pending.json')); return state.pendingAbsent; }),
    request: () => step('http', () => ({ status: state.httpGood ? 200 : 503, body: Buffer.from('service-fixture\n') })),
    probeServiceTLS: () => step('tls', () => ({ status: 200, certificateMatched: state.tlsGood, protocol: 'TLSv1.3', body: Buffer.from('service-fixture\n') })),
    gatewayPort: 18001, tlsPort: 18002, tlsFixture: { ca: Buffer.from('synthetic-ca'), expectedCertificate: Buffer.from('synthetic-leaf') },
    beforePosts: 0, origin: { counts: () => ({ echoRequests: state.postCount }) }, observed,
  };
  const run = new AsyncFunction(...Object.keys(env), 'let primary = null; try { if (observed) throw observed;\n' + failureTail());
  const model = { events, awaits, calls, cleanups, state, restored, recovery, report, observed, initialProofSnapshot,
    async run() { return run(...Object.values(env)); } };
  return model;
}

function originalFailurePreserved(model) {
  assert.equal(model.report.operatorInterruptionChecks, 0);
  assert.deepEqual(model.report.operatorInterruptionProof, model.initialProofSnapshot);
}

test('candidate contains captured failure before outer unit stop but never upgrades primary failure', async () => {
  const f = containmentModel();
  await assert.rejects(f.run(), error => error === f.observed); f.events.push('unit.stop');
  assert.deepEqual(f.report.operatorInterruptionContainment, { attempted: true, operatorAbsent: true, holdClosed: true,
    snapshotRevalidated: true, locksRetired: true, recoveryVerified: true, completed: true, disposition: 'contained' });
  assert.deepEqual(f.cleanups, []); originalFailurePreserved(f);
  for (const action of ['operator.close', 'hold.abort', 'retire', 'recover', 'cli.recover']) assert(f.events.indexOf(action) < f.events.indexOf('unit.stop'));
  for (const action of ['recover', 'cli.recover']) assert.equal(f.events[f.events.indexOf(action) - 1], 'authority');
});

test('every actual containment await refusal preserves primary and prevents completed containment', async t => {
  const reference = containmentModel(); await assert.rejects(reference.run(), error => error === reference.observed);
  assert(reference.awaits.length >= 18);
  for (const target of reference.awaits) await t.test(target, async () => {
    const f = containmentModel({ before(name, count) { if (name + ':' + count === target) reject('operator_fixture_identity'); } });
    await assert.rejects(f.run(), error => error === f.observed);
    originalFailurePreserved(f); assert.equal(f.report.operatorInterruptionContainment.completed, false);
    assert(f.cleanups.length >= 1); assert(f.cleanups.every(x => ['operator_close', 'operator_recovery'].includes(x.stage)));
  });
});

for (const [name, options, expected] of [
  ['noCapturedSnapshot', { noSnapshot: true }, 'no_snapshot'],
  ['noOwnedOperatorHandle', { noOperator: true }, 'no_snapshot'],
  ['normalRetirementAlreadyAttempted', { normalRetirementAttempted: true }, 'retirement_already_started'],
]) test('failure containment does not rearm from ' + name, async () => {
  const f = containmentModel(options); await assert.rejects(f.run(), error => error === f.observed);
  originalFailurePreserved(f); assert(!f.events.includes('retire')); assert(!f.events.includes('recover'));
  assert.equal(f.report.operatorInterruptionContainment.completed, false); assert.equal(f.report.operatorInterruptionContainment.disposition, expected);
});

for (const field of ['closeResult', 'abortResult']) for (const value of [false, undefined, 1, 'true']) {
  test('failure containment refuses nonconfirmed ' + field + ' ' + String(value), async () => {
    const f = containmentModel(); f.state[field] = value; await assert.rejects(f.run(), error => error === f.observed);
    assert(!f.events.includes('retire')); assert(!f.events.includes('recover')); originalFailurePreserved(f);
    assert.equal(f.report.operatorInterruptionContainment.completed, false); assert(f.cleanups.length >= 1);
  });
}

for (const field of ['ok', 'alphaRemoved', 'controllerRemoved', 'pendingPreserved']) for (const value of [false, undefined, 1]) {
  test('failure containment requires strict retirement field ' + field + ' ' + String(value), async () => {
    const f = containmentModel(); f.state.retiredResult[field] = value; await assert.rejects(f.run(), error => error === f.observed);
    assert(!f.events.includes('recover')); assert.equal(f.report.operatorInterruptionContainment.completed, false); originalFailurePreserved(f);
  });
}

for (const value of [false, undefined, 1, Promise.resolve(true)]) test('cleanup recovery rejects nontrue synchronous permit ' + String(value), async () => {
  const f = containmentModel(); f.state.authorityResult = value; await assert.rejects(f.run(), error => error === f.observed);
  assert(!f.events.includes('recover')); originalFailurePreserved(f); assert.equal(f.report.operatorInterruptionContainment.completed, false);
});

for (const [name, mutate, noRecovery] of [
  ['changedPendingBeforeRetirement', f => { f.state.pendingUnchanged = false; }, true],
  ['changedUnitIdentity', f => { f.state.serviceUnchanged = false; }, true],
  ['wrongRestoredRecordID', f => { f.restored.id = 'd'.repeat(32); }, false],
  ['wrongRestoredParent', f => { f.restored.parent = 'd'.repeat(32); }, false],
  ['wrongRestoredSource', f => { f.restored.sourceRevision = 'd'.repeat(32); }, false],
  ['selfConsistentWrongInput', f => { f.restored.input = { wrong: true }; f.restored.inputSha256 = digest(JSON.stringify(f.restored.input)); }, false],
  ['pendingFileStillPresent', f => { f.state.pendingAbsent = false; }, false],
  ['statusStillPending', f => { f.state.statusPending = {}; }, false],
  ['HTTPPayloadUnavailable', f => { f.state.httpGood = false; }, false],
  ['TLSCertificateUnverified', f => { f.state.tlsGood = false; }, false],
  ['unexpectedPOSTReplay', f => { f.state.postCount = 1; }, false],
  ['repeatedRecoverChangesState', f => { f.state.repeatedOutcome = 'rolled_back'; }, false],
]) test('failure containment preserves FAIL for ' + name, async () => {
  const f = containmentModel(); mutate(f); await assert.rejects(f.run(), error => error === f.observed);
  if (noRecovery) assert(!f.events.includes('recover'));
  assert.equal(f.report.operatorInterruptionContainment.completed, false); assert(f.cleanups.some(x => x.stage === 'operator_recovery')); originalFailurePreserved(f);
});

for (const operation of ['operator.close', 'retire', 'recover']) test('late ' + operation + ' completion after cancellation cannot upgrade acceptance', async () => {
  let entered, release; const started = new Promise(resolve => { entered = resolve; }), held = new Promise(resolve => { release = resolve; });
  const f = containmentModel({ async after(name) { if (name === operation) { entered(); await held; } } });
  const result = f.run(); await started; f.state.cancelled = true; release();
  await assert.rejects(result, error => error === f.observed); originalFailurePreserved(f);
  assert.equal(f.report.operatorInterruptionContainment.completed, false);
  if (operation !== 'recover') assert(!f.events.includes('recover')); assert(!f.events.includes('cli.recover'));
});

test('original helper deadline expiring after fresh checks refuses the first new cleanup recovery', async () => {
  const f = containmentModel({ after(name, count, model) { if (name === 'service.check' && count === 2) model.state.clock = 10000; } });
  await assert.rejects(f.run(), error => error === f.observed); assert(!f.events.includes('recover'));
  originalFailurePreserved(f); assert.equal(f.report.operatorInterruptionContainment.completed, false);
});

test('state or history mutation by repeated recovery cannot become completed containment', async t => {
  for (const key of ['stateSHA', 'historySHA']) await t.test(key, async () => {
    const f = containmentModel({ after(name, _count, model) { if (name === 'cli.recover') model.state[key] = 'changed'; } });
    await assert.rejects(f.run(), error => error === f.observed); originalFailurePreserved(f);
    assert.equal(f.report.operatorInterruptionContainment.completed, false);
  });
});

test('a normal fully-proved path does not run failure containment', async () => {
  const f = containmentModel({ observed: null, fullProofs: true }); await f.run();
  assert(!f.events.includes('retire')); assert(!f.events.includes('recover'));
  assert.equal(f.report.operatorInterruptionChecks, 1); assert.equal(f.report.operatorInterruptionContainment.completed, false);
  assert.equal(f.report.operatorInterruptionContainment.disposition, 'not_needed');
});

for (const [name, after] of [
  ['lastPreUnlinkAbsence', (name, count, env) => { if (name === 'absence' && count === 3) env.records.get('pending').sha256 = 'd'.repeat(64); }],
  ['firstUnlinkContinuation', (name, _count, env) => { if (name === 'unlink:alpha') env.records.get('pending').sha256 = 'd'.repeat(64); }],
  ['finalAbsenceBeforeRetiredFlag', (name, count, env) => { if (name === 'absence' && count === 5) env.records.get('pending').sha256 = 'd'.repeat(64); }],
]) test('pending drift during ' + name + ' never yields pendingPreserved cleanup authority', async () => {
  const f = virtualOperator({ after });
  await assert.rejects(f.handle.retireCapturedLocksAfterFailure(), { code: 'operator_fixture_pending' });
  assert.equal(f.decision().retired, false); assert.equal(f.records.has('pending'), true);
  assert.throws(() => f.handle.assertCleanupAuthority(), { code: 'operator_fixture_state' });
  if (name === 'lastPreUnlinkAbsence') assert.equal(f.records.has('alpha'), true);
  if (name === 'firstUnlinkContinuation') assert.equal(f.records.has('controller'), true);
});

const currentHold = { held: true, requested: true, candidateReadyObserved: true, nativeProbeChecks: 1,
  heldResponses: 1, aborted: false, closed: false, released: false };
test('diagnostics distinguish a closed probe, live gap and deadline without granting authority', () => {
  assert.equal(classifyOperatorHoldDecision(currentHold, 1000, 999), 'current');
  assert.equal(classifyOperatorHoldDecision(currentHold, 1000, 1000), 'deadline_expired');
  assert.equal(classifyOperatorHoldDecision({ ...currentHold, held: false, heldResponses: 0 }, 1000, 999), 'live_probe_gap');
  assert.equal(classifyOperatorHoldDecision({ ...currentHold, closed: true }, 1000, 999), 'closed');
  assert.equal(classifyOperatorHoldDecision({ ...currentHold, aborted: true }, 1000, 999), 'aborted');
  assert.equal(classifyOperatorHoldDecision({ ...currentHold, requested: false }, 1000, 999), 'candidate_unobserved');
  assert.equal(classifyOperatorHoldDecision(currentHold, 0, 999), 'budget_unarmed');
});

test('later cleanup observations cannot overwrite the first actual hold refusal', () => {
  const d = createOperatorHoldDiagnostics();
  d.observe('terminate_capture', 'deadline_expired', 1001, 1000, currentHold);
  const first = d.snapshot().firstRefusal;
  for (let i = 0; i < 70; i++) d.observe('harness_capture', 'current', i, 1000, currentHold);
  const s = d.snapshot(); assert.deepEqual(s.firstRefusal, first); assert.equal(s.firstRefusal.deadlineExpired, true);
  assert.equal(s.observationCount, 64); assert.equal(s.observations.length, 8); assert.equal(s.observationsTruncated, true);
  s.firstRefusal.reason = 'current'; s.observations[0].reason = 'invalid'; assert.deepEqual(d.snapshot().firstRefusal, first);
  assert.equal(Object.hasOwn(s, 'serviceAccepted'), false);
});

test('hold diagnostics never invoke accessors or disclose unknown reason/stage strings', () => {
  let calls = 0; const hold = { ...currentHold }; Object.defineProperty(hold, 'held', { get() { calls++; return true; } });
  assert.equal(classifyOperatorHoldDecision(hold, 1000, 1), 'invalid'); assert.equal(calls, 0);
  const d = createOperatorHoldDiagnostics(); d.observe('synthetic-private-stage', 'synthetic-private-reason', Infinity, NaN, { nativeProbeChecks: 99, heldResponses: -1 });
  const s = d.snapshot(); assert.equal(s.firstRefusal.stage, 'unknown'); assert.equal(s.firstRefusal.reason, 'invalid');
  assert.equal(s.firstRefusal.nativeProbeChecks, null); assert.equal(s.firstRefusal.heldResponses, null); assert.equal(s.firstRefusal.ageMs, null);
  assert.doesNotMatch(JSON.stringify(s), /synthetic-private/);
});
