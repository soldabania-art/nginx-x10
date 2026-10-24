// Authored actual-TLS controls for a read-only source API metadata inventory.
// Receipt corruption is a public control-channel fault, not mutated TLS state.
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import { runProbeScenario } from './openssl-probe-run.mjs';

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const metadataKeys = ['schemaVersion', 'allowed', 'reasons', 'probeReasons', 'ledgerCallSerial',
  'server', 'protocolVersion', 'initFinished', 'alpnLength', 'alpnMatchesProfile',
  'finishedLength', 'peerFinishedLength', 'finishedLengthsMatchPrivate', 'verifyMode',
  'verifyResultOk', 'peerCertificatePresent', 'peerChainPresent', 'verifiedChainPresent',
  'sessionPresent', 'sessionReused', 'serverOnlyNoClientAuth', 'gettersMatchPrivate',
  'exporterPreserved', 'sessionApiPreserved', 'resumptionPreserved',
  'postHandshakeAuthPreserved', 'futureKeyUpdatePreserved'];
const envelopeKeys = ['event', 'scenario', 'nonce', 'callSerial', 'immutableRepeatedInventory',
  'semanticExportImport', 'migration', 'nativeNginxIntegration'];
const unsupported = ['exporterPreserved', 'sessionApiPreserved', 'resumptionPreserved',
  'postHandshakeAuthPreserved', 'futureKeyUpdatePreserved'];

function checkedInventory(receipt, context) {
  assert.ok(receipt && typeof receipt === 'object', 'inventory receipt missing');
  assert.deepEqual(Object.keys(receipt).sort(), [...metadataKeys, ...envelopeKeys].sort(),
    'inventory receipt fields differ from the nonsecret contract');
  assert.equal(receipt.event, 'api-inventory');
  assert.equal(receipt.scenario, 'quiescent-live-hold');
  assert.equal(receipt.nonce, context.nonce);
  assert.equal(receipt.callSerial, context.callSerial);
  assert.equal(receipt.ledgerCallSerial, context.callSerial);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.allowed, true);
  assert.equal(receipt.reasons, '0'); assert.equal(receipt.probeReasons, '0');
  assert.equal(receipt.server, 1); assert.equal(receipt.protocolVersion, 772);
  assert.equal(receipt.initFinished, 1);
  assert.equal(receipt.alpnLength, 12); assert.equal(receipt.alpnMatchesProfile, true);
  assert.equal(receipt.finishedLength, 32); assert.equal(receipt.peerFinishedLength, 32);
  assert.equal(receipt.finishedLengthsMatchPrivate, true);
  assert.equal(receipt.verifyMode, 0); assert.equal(receipt.verifyResultOk, true);
  for (const key of ['peerCertificatePresent', 'peerChainPresent', 'verifiedChainPresent', 'sessionReused'])
    assert.equal(receipt[key], false, 'server-only fixture authentication class changed');
  assert.equal(receipt.sessionPresent, true);
  assert.equal(receipt.serverOnlyNoClientAuth, true);
  assert.equal(receipt.gettersMatchPrivate, true);
  assert.equal(receipt.immutableRepeatedInventory, true);
  for (const key of [...unsupported, 'semanticExportImport', 'migration', 'nativeNginxIntegration'])
    assert.equal(receipt[key], false, 'metadata must not claim API preservation or migration');
  return receipt;
}

async function observedNative(kind, run) {
  const spawn = cp.spawn, connect = tls.connect;
  const observation = { events: [], native: null, closed: null, closePromise: null,
    authenticatedClient: false, clientConnections: 0, outputInvalid: false,
    commandWrites: 0, staleCommandsWritten: 0, receiptMutations: 0, duplicateReceipts: 0 };
  cp.spawn = function(command, args = [], options = {}) {
    const child = Reflect.apply(spawn, this, [command, args, options]);
    if (!args.includes('--challenge') || !args.includes('--cert') || !args.includes('--scenario')) return child;
    assert.equal(observation.native, null, 'more than one native source observed');
    observation.native = child;
    observation.closePromise = new Promise(resolve => child.once('close', (code, signal) => {
      observation.closed = { code, signal }; resolve();
    }));
    let pending = '', bytes = 0;
    const emit = child.stdout.emit;
    child.stdout.emit = function(event, chunk, ...rest) {
      if (event !== 'data') return Reflect.apply(emit, this, [event, chunk, ...rest]);
      bytes += chunk.length;
      if (bytes > 65536) { observation.outputInvalid = true; return true; }
      pending += chunk.toString('utf8');
      const delivered = [];
      while (pending.includes('\n')) {
        const end = pending.indexOf('\n');
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        let message;
        try {
          message = JSON.parse(line);
          if (!message || typeof message.event !== 'string' || observation.events.length >= 64) throw Error();
          observation.events.push(message);
        } catch { observation.outputInvalid = true; delivered.push(line); continue; }
        if (message.event === 'api-inventory' && kind === 'malformed-receipt') {
          // The original native metadata was valid. Only the public JSON
          // delivery receives an extra unsupported field; TLS is not patched.
          delivered.push(JSON.stringify({ ...message, unsupportedExtra: true }));
          observation.receiptMutations++;
        } else {
          delivered.push(line);
          if (message.event === 'api-inventory' && kind === 'duplicate-receipt') {
            delivered.push(line); observation.duplicateReceipts++;
          }
        }
      }
      if (delivered.length) return Reflect.apply(emit, this,
        [event, Buffer.from(delivered.join('\n') + '\n'), ...rest]);
      return true;
    };
    child.stdout.once('end', () => { if (pending.length) observation.outputInvalid = true; });
    const write = child.stdin.write;
    child.stdin.write = function(chunk, ...rest) {
      let line = Buffer.isBuffer(chunk) ? chunk.toString('ascii') : String(chunk);
      if (line.startsWith('API_INVENTORY ')) {
        observation.commandWrites++;
        if (kind === 'stale-native-binding') {
          const parts = /^API_INVENTORY ([0-9a-f]{32}) ([1-9][0-9]{0,19})\n$/.exec(line);
          assert.ok(parts, 'inventory command framing changed');
          const serial = BigInt(parts[2]);
          line = `API_INVENTORY ${parts[1]} ${serial === 0xffffffffffffffffn ? 1n : serial + 1n}\n`;
          observation.staleCommandsWritten++;
        }
      }
      return Reflect.apply(write, this, [line, ...rest]);
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
    // Failure cleanup only: a passing case must observe the runner close the
    // exact child before this fallback can send a signal.
    if (observation.native && observation.closed === null) {
      observation.native.kill('SIGTERM');
      await Promise.race([observation.closePromise, pause(1200)]);
      if (observation.closed === null) {
        observation.native.kill('SIGKILL');
        await Promise.race([observation.closePromise, pause(1200)]);
      }
    }
  }
}

const matching = (observation, event) => observation.events.filter(value => value.event === event);
export const apiInventoryCases = Object.freeze([
  { kind: 'inspect', name: 'real held TLS source observes bounded ALPN Finished-length and server-only API metadata' },
  { kind: 'stale-native-binding', name: 'real held TLS API inventory refuses a stale native control serial before observation' },
  { kind: 'malformed-receipt', name: 'real TLS API inventory runner refuses malformed public receipt metadata' },
  { kind: 'duplicate-receipt', name: 'real TLS API inventory runner refuses duplicate public inventory receipts' },
]);

export async function checkApiInventory({ kind = 'inspect', payloadBytes = 23509 } = {}) {
  assert.ok(apiInventoryCases.some(value => value.kind === kind), 'unsupported API inventory test kind');
  return observedNative(kind, async observation => {
    let context, result, error;
    try {
      result = await runProbeScenario({ scenario: 'quiescent-live-hold', payloadBytes,
        onLiveHold: async value => {
          context = value;
          assert.equal(value.sourceHeld, true); assert.equal(value.historical, false);
          assert.equal(value.exportAuthority, false); assert.equal(Object.isFrozen(value), true);
          assert.equal(matching(observation, 'api-inventory').length, 0);
          await pause(kind === 'inspect' ? 83 : 17);
          return { action: 'inspect-api', nonce: value.nonce, callSerial: value.callSerial };
        } });
    } catch (caught) { error = caught; }
    assert.ok(context, 'actual native hold callback was not reached');
    assert.equal(observation.outputInvalid, false);
    assert.equal(observation.authenticatedClient, true);
    assert.equal(observation.clientConnections, 1);
    assert.ok(observation.closed, 'runner did not close the actual native child');
    const receiptFault = ['malformed-receipt', 'duplicate-receipt'].includes(kind);
    if (receiptFault) {
      // Invalid public-channel policy already uses SIGKILL. A normal exit may
      // race that termination; neither outcome proves explicit memory wiping.
      assert.ok([null, 'SIGKILL'].includes(observation.closed.signal),
        'invalid inventory channel termination classification changed');
    } else assert.equal(observation.closed.signal, null,
      'ordinary inventory or native binding refusal must be handled cleanup');
    assert.equal(observation.commandWrites, 1);
    const receipts = matching(observation, 'api-inventory');
    if (kind === 'inspect') {
      assert.equal(error, undefined); assert.equal(observation.closed.code, 0);
      assert.equal(receipts.length, 1);
      const receipt = checkedInventory(receipts[0], context);
      const release = matching(observation, 'hold-released');
      assert.equal(release.length, 1);
      assert.ok(observation.events.indexOf(receipt) > observation.events.findIndex(value => value.event === 'probe' && value.sample === 4));
      assert.ok(observation.events.indexOf(release[0]) > observation.events.indexOf(receipt));
      assert.equal(result.outcome, 'pass'); assert.equal(result.liveHold.decision, 'inspect-api');
      assert.equal(result.apiInventory.sourceHeld, false); assert.equal(result.apiInventory.historical, true);
      assert.equal(result.apiInventory.exportAuthority, false); assert.equal(Object.isFrozen(result.apiInventory), true);
      for (const key of [...metadataKeys, ...envelopeKeys]) assert.equal(result.apiInventory[key], receipt[key]);
      assert.equal(result.wire.passed, true); assert.equal(result.fixtureGracefulShutdown, true);
      assert.equal(result.wire.directions.client.closeNotify, true); assert.equal(result.wire.directions.server.closeNotify, true);
      assert.equal(result.semanticExportImport, false); assert.equal(result.migration, false);
    } else if (kind === 'stale-native-binding') {
      assert.equal(error?.code, 'hold_decision'); assert.equal(result, undefined);
      assert.equal(observation.staleCommandsWritten, 1);
      assert.equal(receipts.length, 0); assert.equal(observation.closed.code, 1);
      assert.equal(matching(observation, 'hold-refused').length, 1);
      assert.equal(matching(observation, 'hold-released').length, 0);
      assert.equal(matching(observation, 'shutdown').length, 0); assert.equal(matching(observation, 'done').length, 0);
      assert.equal(observation.events.some(value => value.event === 'probe' && value.sample >= 3), false);
    } else {
      assert.equal(result, undefined);
      assert.equal(error?.code, kind === 'malformed-receipt'
        ? 'live_api_inventory_event_schema' : 'live_api_inventory_event_order');
      assert.equal(receipts.length, 1);
      checkedInventory(receipts[0], context);
      assert.equal(observation.receiptMutations, kind === 'malformed-receipt' ? 1 : 0);
      assert.equal(observation.duplicateReceipts, kind === 'duplicate-receipt' ? 1 : 0);
      // The trusted C source may already release after its own valid checks.
      // These two cases prove strict JS receipt refusal, not native no-I/O.
    }
    return Object.freeze({ passed: true, kind, actualTLS: true, nodeClientAuthenticatedServer: true,
      clientConnections: 1, nativeClosed: true, sourceHeldDuringCallback: true,
      nativeCloseCode: observation.closed.code, nativeCloseSignal: observation.closed.signal,
      forcedTermination: observation.closed.signal === 'SIGKILL', explicitWipeClaimed: false,
      nativeInventoryReceipts: receipts.length, sourceReleased: matching(observation, 'hold-released').length === 1,
      staleNativeBindingRefused: kind === 'stale-native-binding',
      publicReceiptFault: receiptFault,
      refusalCode: error?.code || null, rawFinishedOrSecretBytesPublished: false,
      semanticExportImport: false, migration: false });
  });
}
