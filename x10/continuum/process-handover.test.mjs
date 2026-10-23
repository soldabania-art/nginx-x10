import assert from 'node:assert/strict';
import test from 'node:test';
import { runProcessHandover } from './process-handover.mjs';

test('broken baseline omitting pending ciphertext cannot continue the record stream', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'drop-pending' }), /fixture_peer_closed|fixture_peer_early_end|fixture_peer_record_failure/);
});

test('target refuses a commit bound to a different imported IR', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'commit-digest' }), /fixture_worker_failure:commit_binding/);
});

test('late corrupted ciphertext after expected application bytes fails', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'trailer-corrupt' }), /fixture_peer_record_failure/);
});

test('late incomplete ciphertext at FIN after expected application bytes fails', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'trailer-truncated' }), /fixture_peer_truncated_record/);
});

test('late valid extra KeyUpdate after expected application bytes fails', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'trailer-key-update' }), /fixture_peer_unexpected_record/);
});

test('late valid empty application record after expected bytes fails', { timeout: 20000 }, async () => {
  await assert.rejects(runProcessHandover({ fault: 'trailer-empty-record' }), /fixture_peer_unexpected_record/);
});

test('real process handover retains one TCP connection and partial KeyUpdate record', { timeout: 20000 }, async () => {
  const report = await runProcessHandover();
  assert.equal(report.outcome, 'pass');
  assert.equal(report.acceptedConnections, 1);
  assert.equal(report.oldProcessExited, true);
  assert.equal(report.sameClientConnection, true);
  assert.equal(report.partialCipherBytesTransferred, 13);
  assert.equal(report.readKeyUpdates, 1);
  assert.equal(report.writeKeyUpdates, 1);
  assert.equal(report.exactApplicationBytes, true);
  assert.equal(report.terminalStateChecked, true);
  assert.equal(report.peerObservedCleanFin, true);
  assert.equal(report.pendingCipherBytesAtEnd, 0);
  assert.equal(report.acceptedEncryptedRecords, 4);
  assert.equal(report.sourceBinaryChanged, false);
  assert.equal(report.tlsLibraryChanged, false);
  assert.equal(report.handshakeImplemented, false);
  assert.equal(report.nativeNginxIntegration, false);
  assert.equal(report.automaticAdapter, false);
});
