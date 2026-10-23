import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { prepareProbeHarness, runProbeScenario, cleanupProbeHarness } from './openssl-probe-run.mjs';
import { runProbeInterruption } from './openssl-interruption.mjs';

before(async () => { await prepareProbeHarness(); }, { timeout: 1200000 });
after(async () => { await cleanupProbeHarness(); }, { timeout: 10000 });

test('real authenticated TLS quiescent probes are immutable and match observed record sequences', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'quiescent' });
  assert.equal(result.outcome, 'pass');
  assert.equal(result.probe.allowed, true);
  assert.equal(result.probe.reasons, '0');
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.wire.passed, true);
  assert.equal(result.wire.directions.client.closeNotify, true);
  assert.equal(result.wire.directions.server.closeNotify, true);
  assert.equal(result.semanticExportImport, false);
  assert.equal(result.migration, false);
});

test('completed real server KeyUpdate advances monitored generation and refuses generation-zero gate', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'completed-key-update' });
  assert.equal(result.probe.allowed, false);
  assert.equal(result.probe.readGeneration, '0');
  assert.equal(result.probe.writeGeneration, '1');
  assert.equal(result.probe.mutationSerial, '3');
  assert.equal(result.probe.keyUpdate, -1);
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.wire.directions.server.keyUpdates, 1);
  assert.equal(result.fixtureGracefulShutdown, true);
});

test('real requested peer KeyUpdate leaves a read generation and immutable queued response', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'peer-key-update-pending', payloadBytes: 8093 });
  assert.equal(result.outcome, 'pass');
  assert.equal(result.negotiated.authorized, true);
  assert.equal(result.peerReceived.applicationBytesRead, 8093);
  assert.equal(result.peerReceived.keyUpdate, 0);
  assert.equal(result.peerReceived.readGeneration, '1');
  assert.equal(result.peerReceived.writeGeneration, '0');
  assert.equal(result.probe.allowed, false);
  assert.equal(result.probe.reasons, '32832');
  assert.equal(result.probe.readGeneration, '1');
  assert.equal(result.probe.writeGeneration, '0');
  assert.equal(result.probe.keyUpdate, 0);
  assert.equal(result.probe.mutationSerial, '3');
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.fixtureGracefulShutdown, false);
  assert.equal(result.wire, null);
  assert.equal(result.migration, false);
});

test('real requested peer KeyUpdate completes both directions and matches reset wire sequences', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'peer-key-update-completed', payloadBytes: 32791 });
  assert.equal(result.outcome, 'pass');
  assert.equal(result.peerReceived.readGeneration, '1');
  assert.equal(result.peerReceived.writeGeneration, '0');
  assert.equal(result.peerReceived.keyUpdate, 0);
  assert.equal(result.probe.allowed, false);
  assert.equal(result.probe.reasons, '64');
  assert.equal(result.probe.readGeneration, '1');
  assert.equal(result.probe.writeGeneration, '1');
  assert.equal(result.probe.keyUpdate, -1);
  assert.equal(result.probe.mutationSerial, '4');
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.wire.passed, true);
  for (const direction of ['client', 'server']) {
    assert.equal(result.wire.directions[direction].keyUpdates, 1);
    assert.equal(result.wire.directions[direction].beforeCloseNotify.epoch, 1);
    assert.equal(result.wire.directions[direction].closeNotify, true);
  }
  assert.equal(BigInt('0x' + result.probe.readNextSequence), BigInt(result.wire.directions.client.beforeCloseNotify.nextSequence));
  assert.equal(BigInt('0x' + result.probe.writeNextSequence), BigInt(result.wire.directions.server.beforeCloseNotify.nextSequence));
  assert.equal(result.fixtureGracefulShutdown, true);
  assert.equal(result.migration, false);
});

test('the same real read retry completes before echo and clears its outstanding obligation', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'completed-read-retry' });
  assert.equal(result.retryLifecycle.clientApplicationWritesBeforeRetry, 0);
  assert.equal(result.retryLifecycle.ready.outcome, 2);
  assert.equal(result.retryLifecycle.ready.retryCall, 2);
  assert.equal(result.retryLifecycle.ready.applicationBytesRead, 0);
  assert.equal(result.retryLifecycle.completed.call, 2);
  assert.equal(result.retryLifecycle.completed.outcome, 1);
  assert.equal(result.retryLifecycle.completed.retryCall, 0);
  assert.equal(result.retryLifecycle.completed.sameReadArguments, true);
  assert.equal(result.probe.allowed, true);
  assert.equal(result.probe.reasons, '0');
  assert.equal(result.probe.ledgerRetryCall, 0);
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.wire.passed, true);
  assert.equal(result.fixtureGracefulShutdown, true);
  assert.equal(result.migration, false);
});

test('a successful unrelated write preserves the outstanding real read retry', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'unrelated-write-read-retry' });
  assert.equal(result.retryLifecycle.clientApplicationWritesBeforeRetry, 0);
  assert.equal(result.retryLifecycle.ready.outcome, 2);
  assert.equal(result.retryLifecycle.ready.retryCall, 2);
  assert.equal(result.retryLifecycle.completed, null);
  assert.equal(result.probe.allowed, false);
  assert.equal(result.probe.reasons, '16');
  assert.equal(result.probe.ledgerLastCall, 3);
  assert.equal(result.probe.ledgerLastOutcome, 1);
  assert.equal(result.probe.ledgerRetryCall, 2);
  assert.equal(result.probe.sslPending, 0);
  assert.equal(result.probe.sslHasPending, false);
  assert.equal(result.fixtureGracefulShutdown, false);
  assert.equal(result.wire, null);
  assert.equal(result.migration, false);
});

test('the same real write retry completes exact original bytes and clears its outstanding obligation', { timeout: 30000 }, async () => {
  const result = await runProbeScenario({ scenario: 'completed-write-retry', payloadBytes: 65536 });
  const lifecycle = result.writeRetryLifecycle;
  assert.equal(result.outcome, 'pass');
  assert.equal(result.negotiated.authorized, true);
  assert.equal(lifecycle.ready.call, 3);
  assert.equal(lifecycle.ready.outcome, 3);
  assert.equal(lifecycle.ready.retryCall, 3);
  assert.equal(lifecycle.ready.applicationBytesRead, 65536);
  assert.equal(Object.hasOwn(lifecycle.ready, 'applicationBytesWritten'), false);
  assert.equal(lifecycle.refused.allowed, false);
  assert.equal(lifecycle.refused.ledgerRetryCall, 3);
  assert.equal(lifecycle.refused.ledgerLastOutcome, 3);
  assert.ok(lifecycle.refused.wbufLeft > 0);
  assert.equal(lifecycle.immutableRefusedProbes, true);
  assert.equal(lifecycle.bothReadersResumedBeforeRetry, true);
  assert.equal(lifecycle.clientApplicationWrites, 1);
  assert.equal(lifecycle.completed.call, 3);
  assert.equal(lifecycle.completed.outcome, 1);
  assert.equal(lifecycle.completed.retryCall, 0);
  assert.equal(lifecycle.completed.sameWriteArguments, true);
  assert.equal(lifecycle.completed.writeLength, 65536);
  assert.equal(lifecycle.completed.applicationBytesRead, 65536);
  assert.equal(lifecycle.completed.applicationBytesWritten, 65536);
  assert.equal(result.probe.allowed, true);
  assert.equal(result.probe.reasons, '0');
  assert.equal(result.probe.ledgerRetryCall, 0);
  assert.equal(result.probe.ledgerLastCall, 3);
  assert.equal(result.probe.ledgerLastOutcome, 1);
  assert.equal(result.immutableRepeatedProbe, true);
  assert.equal(result.wire.passed, true);
  for (const direction of ['client', 'server']) {
    assert.equal(result.wire.directions[direction].closeNotify, true);
  }
  assert.equal(result.fixtureGracefulShutdown, true);
  assert.equal(result.semanticExportImport, false);
  assert.equal(result.migration, false);
});

for (const scenario of ['partial-header', 'partial-body', 'unread-plaintext', 'empty-read-retry', 'write-backpressure', 'queued-key-update']) {
  test(`real TLS private ${scenario} state refuses the read-only safepoint`, { timeout: 30000 }, async () => {
    const result = await runProbeScenario({ scenario });
    assert.equal(result.outcome, 'pass');
    assert.equal(result.probe.allowed, false);
    assert.notEqual(result.probe.reasons, '0');
    assert.equal(result.fixtureGracefulShutdown, false);
    assert.equal(result.wire, null);
    assert.equal(result.migration, false);
  });
}

// These interrupted runs authenticate TLS and complete the original C READ,
// then stop before its echo. They prove cleanup at that bounded runtime point,
// not graceful TLS closure, semantic export/import or connection migration.
for (const interruption of ['SIGTERM', 'SIGINT']) {
  test(`${interruption} after a real TLS application read reaps the fixture and removes private artifacts`, { timeout: 250000 }, async () => {
    const payloadBytes = interruption === 'SIGTERM' ? 8193 : 32791;
    const result = await runProbeInterruption({ interruption, payloadBytes, checkpoint: 'retry-completed' });
    assert.equal(result.outcome, 'pass');
    assert.equal(result.interruption, interruption);
    assert.equal(result.checkpoint, 'retry-completed');
    assert.equal(result.exitCode, interruption === 'SIGTERM' ? 143 : 130);
    assert.equal(result.signal, null);
    assert.equal(result.authenticatedTLS, true);
    assert.equal(result.nativeHandshake, true);
    assert.equal(result.realReadCompleted, true);
    assert.ok(Number.isSafeInteger(result.applicationBytesRead) && result.applicationBytesRead > 0
      && result.applicationBytesRead <= Math.min(payloadBytes, 16384), 'actual application read was not observed');
    assert.equal(result.originalReadArguments, true);
    assert.equal(result.priorReadRetry, true);
    assert.equal(result.retryCleared, true);
    assert.equal(result.clientApplicationWrites, 1);
    assert.equal(result.echoBytesBeforeSignal, 0);
    assert.equal(result.fixedInterruptionFailure, true);
    assert.equal(result.nativeChildReaped, true);
    assert.equal(result.privatePKIRemoved, true);
    assert.equal(result.fixtureBuildRemoved, true);
    assert.equal(result.pinnedBuildRemoved, true);
    assert.equal(result.privateRunDirectoryEmpty, true);
    assert.equal(result.listenerPortsRebound, 1);
    assert.equal(result.nativeListenerRefused, true);
    assert.equal(result.gracefulTLSClosureClaimed, false);
    assert.equal(result.migration, false);
  });
}

// This is a source-identity control only. The private copy has no runner beside
// it, so an absent early identity guard cannot accidentally execute a TLS run.
test('a cached interruption helper refuses changed source bytes before any build', { timeout: 10000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'x10-c2a-interruption-source-control-'));
  try {
    const source = await readFile(new URL('./openssl-interruption.mjs', import.meta.url));
    const copied = join(directory, 'openssl-interruption.mjs');
    await writeFile(copied, source, { mode: 0o600 });
    const { runProbeInterruption: copiedControl } = await import(pathToFileURL(copied).href);
    await writeFile(copied, Buffer.concat([source, Buffer.from('\n// private cached-import source mutation\n')]), { mode: 0o600 });
    let refusedChangedSource = false;
    try { await copiedControl({ interruption: 'SIGTERM', payloadBytes: 4097, checkpoint: 'retry-completed' }); }
    catch (error) { refusedChangedSource = error?.message === 'interruption_helper_changed'; }
    assert.equal(refusedChangedSource, true, 'cached helper did not refuse its changed source');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
