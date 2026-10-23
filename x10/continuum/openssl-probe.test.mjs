import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { prepareProbeHarness, runProbeScenario, cleanupProbeHarness } from './openssl-probe-run.mjs';

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
