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
