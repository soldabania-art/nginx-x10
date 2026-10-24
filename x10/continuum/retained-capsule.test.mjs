// Actual TLS source-only lifetime controls. The observer sees only the native
// JSON/control channel, never keylog bytes, protected mappings or pointers.
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';
import { before, after, test } from 'node:test';
import { prepareProbeHarness, runProbeScenario, cleanupProbeHarness } from './openssl-probe-run.mjs';

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const budget = () => ({
  read: { applicationRecords: '0', handoverRecords: '0', closureRecords: '1' },
  write: { applicationRecords: '0', handoverRecords: '0', closureRecords: '1' },
});
const uint64 = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value)
  && BigInt(value) <= 0xffffffffffffffffn;
const flags = ['captured', 'locked', 'dontDump', 'dontFork', 'readOnly', 'sourceUnchanged'];

function checkedReceipt(message, ready = false) {
  const keys = ['event', 'scenario', 'nonce', 'callSerial', 'generation', ...flags,
    'secretBytes', 'ivBytes', 'sequenceBytes', ...(ready ? ['deadlineMilliseconds'] : ['cleansed', 'unmapped'])];
  assert.ok(message && typeof message === 'object', 'native capsule receipt missing');
  assert.deepEqual(Object.keys(message).sort(), keys.sort(), 'native capsule receipt fields changed');
  assert.equal(message.event, ready ? 'capsule-ready' : 'capsule-cleared');
  assert.equal(message.scenario, 'quiescent-live-hold');
  assert.match(message.nonce, /^[0-9a-f]{32}$/);
  assert.ok(uint64(message.callSerial));
  assert.ok(uint64(message.generation));
  for (const key of flags) assert.equal(message[key], true, 'native protection or source equality failed');
  assert.equal(message.secretBytes, 64); assert.equal(message.ivBytes, 24); assert.equal(message.sequenceBytes, 16);
  if (ready) assert.ok(Number.isSafeInteger(message.deadlineMilliseconds)
    && message.deadlineMilliseconds > 0 && message.deadlineMilliseconds <= 3000);
  else { assert.equal(message.cleansed, true); assert.equal(message.unmapped, true); }
  return message;
}

async function observedNative(run, { memlockZero = false, withholdDiscard = false } = {}) {
  const spawn = cp.spawn, connect = tls.connect;
  const observation = { events: [], commands: [], native: null, closed: null,
    authenticatedClient: false, clientConnections: 0, outputInvalid: false, withheldDiscardWrites: 0 };
  let closePromise;
  cp.spawn = function(command, args = [], options = {}) {
    const native = args.includes('--challenge') && args.includes('--cert') && args.includes('--scenario');
    const child = Reflect.apply(spawn, this, native && memlockZero
      ? ['/usr/bin/prlimit', ['--memlock=0:0', '--', command, ...args], options]
      : [command, args, options]);
    if (!native) return child;
    assert.equal(observation.native, null, 'more than one native source was started');
    observation.native = child;
    closePromise = new Promise(resolve => child.once('close', (code, signal) => {
      observation.closed = { code, signal }; resolve();
    }));
    let pending = '', bytes = 0;
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 65536) { observation.outputInvalid = true; return; }
      pending += chunk.toString('utf8');
      while (pending.includes('\n')) {
        const end = pending.indexOf('\n'), line = pending.slice(0, end); pending = pending.slice(end + 1);
        try {
          const message = JSON.parse(line);
          if (!message || typeof message.event !== 'string' || observation.events.length >= 64) throw Error();
          observation.events.push(message);
        } catch { observation.outputInvalid = true; }
      }
    });
    const write = child.stdin.write;
    child.stdin.write = function(chunk, ...rest) {
      const line = Buffer.isBuffer(chunk) ? chunk.toString('ascii') : String(chunk);
      if (line.length > 512 || observation.commands.length >= 16) observation.outputInvalid = true;
      else observation.commands.push(line);
      if (withholdDiscard && line.startsWith('DISCARD ')) {
        // The real native control pipe receives no decision. Acknowledge only
        // the runner's write callback, then let C's original monotonic hold
        // deadline expire. No native clock, TLS call or return is replaced.
        observation.withheldDiscardWrites++;
        const callback = rest.find(value => typeof value === 'function');
        assert.equal(typeof callback, 'function', 'native discard write callback missing');
        queueMicrotask(() => callback());
        return true;
      }
      return Reflect.apply(write, this, [chunk, ...rest]);
    };
    return child;
  };
  tls.connect = function(...args) {
    const socket = Reflect.apply(connect, this, args);
    observation.clientConnections++;
    socket.once('secureConnect', () => {
      observation.authenticatedClient = socket.authorized && socket.getProtocol() === 'TLSv1.3'
        && socket.getCipher()?.standardName === 'TLS_AES_128_GCM_SHA256'
        && socket.alpnProtocol === 'continuum-c1' && !socket.isSessionReused();
    });
    return socket;
  };
  syncBuiltinESMExports();
  try { return await run(observation); }
  finally {
    cp.spawn = spawn; tls.connect = connect; syncBuiltinESMExports();
    // This is failure cleanup only. Every passing case independently requires
    // the runner to have reaped the exact observed source before reaching here.
    if (observation.native && observation.closed === null) {
      observation.native.kill('SIGTERM');
      await Promise.race([closePromise, delay(1200)]);
      if (observation.closed === null) {
        observation.native.kill('SIGKILL');
        await Promise.race([closePromise, delay(1200)]);
      }
    }
  }
}

const matching = (observation, event) => observation.events.filter(message => message.event === event);
function commonFacts(observation, handledOnly = true) {
  assert.equal(observation.outputInvalid, false, 'native observation exceeded its exact bounded channel');
  assert.equal(observation.authenticatedClient, true, 'actual client authentication was not observed');
  assert.equal(observation.clientConnections, 1);
  assert.ok(observation.native, 'native source was not observed');
  assert.ok(observation.closed, 'runner did not reap its native source');
  if (handledOnly) assert.equal(observation.closed.signal, null, 'forced termination is not handled cleanup');
  else assert.ok([null, 'SIGKILL'].includes(observation.closed.signal), 'baseline exit classification changed');
}
function readyAndCleared(observation) {
  const ready = matching(observation, 'capsule-ready'), cleared = matching(observation, 'capsule-cleared');
  assert.equal(ready.length, 1); assert.equal(cleared.length, 1);
  checkedReceipt(ready[0], true); checkedReceipt(cleared[0]);
  for (const key of ['nonce', 'callSerial', 'generation']) assert.equal(cleared[0][key], ready[0][key]);
  assert.ok(observation.events.indexOf(cleared[0]) > observation.events.indexOf(ready[0]));
  return { ready: ready[0], cleared: cleared[0] };
}
function refusedAfterClear(observation, error, code) {
  commonFacts(observation);
  assert.equal(observation.closed.code, 1);
  assert.equal(error?.code, code);
  const receipts = readyAndCleared(observation);
  const refused = matching(observation, 'hold-refused');
  assert.equal(refused.length, 1);
  assert.ok(observation.events.indexOf(refused[0]) > observation.events.indexOf(receipts.cleared));
  assert.equal(matching(observation, 'hold-released').length, 0);
  assert.equal(matching(observation, 'shutdown').length, 0);
  assert.equal(matching(observation, 'done').length, 0);
  assert.equal(error.capsuleCleanup?.acknowledged, true, 'runner did not acknowledge native cleanup');
  assert.equal(error.capsuleCleanup?.released, false);
  assert.equal(error.capsuleCleanup?.nativeClosed, true);
  assert.equal(error.capsuleCleanup?.forcedTermination, false);
  return receipts;
}

export const retainedCapsuleCases = Object.freeze([
  { kind: 'discard', name: 'real TLS retained protected source copy is cleared before explicit release' },
  { kind: 'abort', name: 'real TLS retained protected source copy is cleared on explicit abort' },
  { kind: 'stale-generation', name: 'real TLS retained capsule refuses a stale generation and clears its copy' },
  { kind: 'late-callback', name: 'real TLS retained capsule timeout revokes a late callback decision' },
  { kind: 'native-expiry', name: 'real TLS retained capsule native deadline clears an unanswered discard' },
  { kind: 'sigterm', name: 'SIGTERM after actual retained capsule readiness clears before source refusal' },
  { kind: 'memlock-zero', name: 'real TLS retained source capture refuses a zero native memlock limit' },
]);

export async function checkRetainedCapsuleLifetime({ kind = 'discard', payloadBytes = 9011 } = {}) {
  assert.ok(retainedCapsuleCases.some(value => value.kind === kind), 'unsupported retained capsule test kind');
  return observedNative(async observation => {
    let entered = 0, context, finishLate, signalSent = false, error, result;
    try {
      result = await runProbeScenario({ scenario: 'quiescent-live-hold', payloadBytes,
        onLiveHold: value => ({ action: 'capture-held', nonce: value.nonce,
          callSerial: value.callSerial, budget: budget() }),
        onCapsuleHold: async value => {
          entered++; context = value;
          assert.equal(value.sourceHeld, true); assert.equal(value.historical, false);
          assert.equal(value.exportAuthority, false); assert.equal(value.semanticExportImport, false); assert.equal(value.migration, false);
          assert.equal(Object.isFrozen(value), true); assert.equal(Object.isFrozen(value.ready), true);
          assert.ok(value.deadlineMilliseconds > 0
            && value.deadlineMilliseconds <= value.nativeDeadlineMilliseconds);
          checkedReceipt(value.ready, true);
          assert.equal(value.generation, value.ready.generation); assert.equal(value.nonce, value.ready.nonce);
          assert.equal(value.callSerial, value.ready.callSerial);
          assert.equal(matching(observation, 'capsule-ready').length, 1);
          assert.equal(matching(observation, 'capsule-cleared').length, 0);
          if (kind === 'sigterm') {
            assert.equal(observation.native.exitCode, null);
            assert.equal(observation.native.signalCode, null);
            signalSent = observation.native.kill('SIGTERM');
            assert.equal(signalSent, true);
            return new Promise(() => {});
          }
          if (kind === 'late-callback') return new Promise(resolve => { finishLate = resolve; });
          await delay(kind === 'discard' ? 47 : 19);
          assert.equal(matching(observation, 'capsule-cleared').length, 0);
          assert.equal(matching(observation, 'hold-released').length, 0);
          return { action: kind === 'abort' ? 'abort' : 'discard', nonce: value.nonce,
            callSerial: value.callSerial,
            generation: kind === 'stale-generation' ? (BigInt(value.generation) === 0xffffffffffffffffn
              ? '1' : (BigInt(value.generation) + 1n).toString()) : value.generation };
        } });
    } catch (caught) { error = caught; }
    if (kind === 'discard') {
      assert.equal(error, undefined); assert.equal(entered, 1); commonFacts(observation);
      assert.equal(observation.closed.code, 0);
      const receipts = readyAndCleared(observation);
      assert.equal(result.outcome, 'pass'); assert.equal(result.negotiated.authorized, true);
      assert.equal(result.liveHold.decision, 'capture-held');
      assert.equal(result.liveHold.capsule.decision, 'discard');
      assert.deepEqual(result.liveHold.capsule.ready, receipts.ready);
      assert.deepEqual(result.liveHold.capsule.cleared, receipts.cleared);
      assert.equal(result.liveHold.capsule.sourceHeld, false); assert.equal(result.liveHold.capsule.historical, true);
      assert.equal(result.wire.passed, true); assert.equal(result.fixtureGracefulShutdown, true);
      assert.equal(result.wire.directions.client.closeNotify, true); assert.equal(result.wire.directions.server.closeNotify, true);
      const released = matching(observation, 'hold-released');
      assert.equal(released.length, 1);
      assert.ok(observation.events.indexOf(released[0]) > observation.events.indexOf(receipts.cleared));
      assert.equal(result.semanticExportImport, false); assert.equal(result.migration, false);
    } else if (kind === 'memlock-zero') {
      commonFacts(observation); assert.equal(entered, 0); assert.equal(error?.code, 'hold_capture');
      assert.equal(matching(observation, 'capsule-ready').length, 0);
      assert.equal(matching(observation, 'capsule-cleared').length, 0);
      assert.equal(matching(observation, 'hold-released').length, 0);
      assert.equal(matching(observation, 'shutdown').length, 0);
    } else {
      assert.equal(entered, 1);
      refusedAfterClear(observation, error, kind === 'abort' ? 'hold_aborted'
        : kind === 'stale-generation' ? 'hold_decision'
          : kind === 'late-callback' ? 'live_capsule_callback_timeout'
            : kind === 'native-expiry' ? 'hold_timeout' : 'hold_capture');
      if (kind === 'native-expiry') {
        assert.equal(observation.withheldDiscardWrites, 1);
        assert.equal(matching(observation, 'hold-refused')[0].code, 'hold_timeout');
        assert.equal(observation.commands.filter(line => line.startsWith('DISCARD ')).length, 1);
      }
      if (kind === 'late-callback') {
        assert.equal(typeof finishLate, 'function');
        const before = observation.commands.length;
        finishLate({ action: 'discard', nonce: context.nonce, callSerial: context.callSerial, generation: context.generation });
        await delay(60);
        assert.equal(observation.commands.length, before, 'late callback wrote a fresh native command');
        assert.equal(observation.commands.some(line => line.startsWith('DISCARD ')), false);
        assert.equal(matching(observation, 'hold-released').length, 0);
      }
    }
    return Object.freeze({ passed: true, kind, actualTLS: true, authenticatedClient: true,
      sourceReadyObserved: entered === 1, nativeClearedObserved: kind !== 'memlock-zero',
      nativeClosed: true, signalSent, lateDecisionRevoked: kind === 'late-callback',
      controlWrites: observation.commands.length - observation.withheldDiscardWrites,
      controlWriteAttempts: observation.commands.length, discardWritesWithheld: observation.withheldDiscardWrites,
      nativeExpiryObserved: kind === 'native-expiry', memlockLimitControl: kind === 'memlock-zero',
      sourceReleased: kind === 'discard', explicitWipeClaimed: kind !== 'memlock-zero',
      wholeProcessWipeClaimed: false, semanticExportImport: false, migration: false });
  }, { memlockZero: kind === 'memlock-zero', withholdDiscard: kind === 'native-expiry' });
}

// Root can supply the exact unchanged baseline API after preparing its own
// isolated build. This records missing capability, not a historical runtime bug.
export async function checkBaselineRetainedRefusal(runScenario) {
  assert.equal(typeof runScenario, 'function');
  return observedNative(async observation => {
    let entered = false, retainedEntered = false, error;
    try {
      await runScenario({ scenario: 'quiescent-live-hold', payloadBytes: 4051,
        onLiveHold: value => { entered = true; return { action: 'capture-held', nonce: value.nonce,
          callSerial: value.callSerial, budget: budget() }; },
        onCapsuleHold: () => { retainedEntered = true; } });
    } catch (caught) { error = caught; }
    commonFacts(observation, false);
    assert.equal(entered, true); assert.equal(retainedEntered, false);
    assert.equal(error?.code, 'live_hold_decision');
    assert.equal(matching(observation, 'capsule-ready').length, 0);
    assert.equal(matching(observation, 'hold-released').length, 0);
    return Object.freeze({ passed: true, actualTLS: true, missingBaselineCapability: true,
      expectedRefusal: 'live_hold_decision', baselineExitSignal: observation.closed.signal,
      explicitWipeClaimed: false, historicalRuntimeBugClaimed: false, migration: false });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  before(async () => { await prepareProbeHarness(); }, { timeout: 1200000 });
  after(async () => { await cleanupProbeHarness(); }, { timeout: 10000 });
  for (const { kind, name } of retainedCapsuleCases) {
    test(name, { timeout: 30000 }, async () => { assert.equal((await checkRetainedCapsuleLifetime({ kind })).passed, true); });
  }
}
