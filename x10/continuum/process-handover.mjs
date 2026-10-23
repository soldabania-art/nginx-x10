// Isolated research fixture. The peer starts from synthetic post-handshake keys.
// It proves neither an OpenSSL state bridge nor a native NGINX update.
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { createConnection, createServer } from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { HandoverModel, createHandover, transitionHandover, canWrite, handoverDigest } from './state.mjs';

const WORKER = fileURLToPath(new URL('./process-worker.mjs', import.meta.url));
const DEADLINE = 6000;

function bounded(promise, label, milliseconds = DEADLINE) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`fixture_timeout:${label}`)), milliseconds);
  })]).finally(() => clearTimeout(timer));
}

function channel(layout) {
  const child = fork(WORKER, [layout], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'], execArgv: [] });
  const messages = [];
  const waiters = new Set();
  let exited = false;
  let exitCode;
  let errorSeen = false;
  const closed = new Promise(resolve => child.once('exit', (code, signal) => {
    exited = true;
    exitCode = code;
    for (const wake of waiters) wake();
    resolve({ code, signal });
  }));
  child.on('error', () => { errorSeen = true; for (const wake of waiters) wake(); });
  child.on('message', (message, handle) => {
    if (messages.length >= 64) { child.kill('SIGKILL'); return; }
    messages.push({ message, handle });
    for (const wake of waiters) wake();
  });
  const wait = (kind, predicate = () => true) => bounded(new Promise((resolve, reject) => {
    const wake = () => {
      const failure = messages.find(x => x.message?.kind === 'failure');
      if (errorSeen || failure) {
        const code = failure?.message.reason === 'commit_binding' ? 'commit_binding' : 'protocol';
        waiters.delete(wake); reject(new Error(`fixture_worker_failure:${code}`)); return;
      }
      const index = messages.findIndex(x => x.message?.kind === kind && predicate(x.message));
      if (index >= 0) { waiters.delete(wake); resolve(messages.splice(index, 1)[0]); }
      else if (exited) { waiters.delete(wake); reject(new Error(`fixture_worker_exit:${exitCode}`)); }
    };
    waiters.add(wake);
    wake();
  }), kind);
  const send = (message, handle) => bounded(new Promise((resolve, reject) => {
    child.send(message, handle, { keepOpen: false }, error => error ? reject(new Error('fixture_ipc_failure')) : resolve());
  }), 'ipc_send');
  return { child, wait, send, closed, get exited() { return exited; } };
}

// Independent, deliberately small client record oracle. It does not import
// record.mjs; RFC 8446 HKDF labels, AEAD/AAD and nonce construction live here.
function label(secret, name, length) {
  const text = Buffer.from(`tls13 ${name}`, 'ascii');
  const info = Buffer.concat([Buffer.from([length >> 8, length & 255, text.length]), text, Buffer.from([0])]);
  return createHmac('sha256', secret).update(Buffer.concat([info, Buffer.from([1])])).digest().subarray(0, length);
}
function peerState(secret) { return { secret, sequence: 0n, epoch: 0 }; }
function rotate(state) {
  state.secret = label(state.secret, 'traffic upd', 32);
  state.sequence = 0n;
  state.epoch++;
}
function nonce(state) {
  const value = Buffer.from(label(state.secret, 'iv', 12));
  let seq = state.sequence;
  for (let i = 11; i >= 4; --i) { value[i] ^= Number(seq & 255n); seq >>= 8n; }
  return value;
}
function peerSeal(state, bytes, contentType = 23) {
  const inner = Buffer.concat([bytes, Buffer.from([contentType])]);
  const size = inner.length + 16;
  const header = Buffer.from([23, 3, 3, size >> 8, size & 255]);
  const cipher = createCipheriv('aes-128-gcm', label(state.secret, 'key', 16), nonce(state));
  cipher.setAAD(header);
  const wire = Buffer.concat([header, cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
  state.sequence++;
  return wire;
}
function peerOpen(state, wire) {
  const cipher = createDecipheriv('aes-128-gcm', label(state.secret, 'key', 16), nonce(state));
  cipher.setAAD(wire.subarray(0, 5));
  cipher.setAuthTag(wire.subarray(-16));
  const inner = Buffer.concat([cipher.update(wire.subarray(5, -16)), cipher.final()]);
  state.sequence++;
  let end = inner.length - 1;
  while (end >= 0 && inner[end] === 0) end--;
  if (end < 0) throw new Error('fixture_peer_inner');
  return { type: inner[end], bytes: inner.subarray(0, end) };
}
function attachPeer(socket, inboundState, expectedRecords) {
  let pending = Buffer.alloc(0);
  let bytes = Buffer.alloc(0);
  let failure;
  let recordIndex = 0;
  let terminationExpected = false;
  let sawEnd = false;
  let closed = false;
  const waiters = new Set();
  const wake = () => { for (const callback of waiters) callback(); };
  const fail = (code, destroy = true) => {
    failure ??= new Error(code);
    if (destroy) socket.destroy();
    wake();
  };
  socket.on('error', () => fail('fixture_peer_transport'));
  socket.on('end', () => {
    sawEnd = true;
    if (!terminationExpected) fail('fixture_peer_early_end', false);
    else if (pending.length !== 0) fail('fixture_peer_truncated_record', false);
    else if (recordIndex !== expectedRecords.length) fail('fixture_peer_missing_records', false);
    wake();
  });
  socket.on('close', hadError => {
    closed = true;
    if (hadError) fail('fixture_peer_transport', false);
    else if (!sawEnd) fail('fixture_peer_closed', false);
    wake();
  });
  socket.on('data', chunk => {
    if (failure) return;
    try {
      if (sawEnd) throw new Error('fixture_peer_unexpected_record');
      if (pending.length + chunk.length > 65536) throw new Error('fixture_peer_limit');
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 5) {
        if (!pending.subarray(0, 3).equals(Buffer.from([23, 3, 3]))) throw new Error('fixture_peer_header');
        const size = 5 + pending.readUInt16BE(3);
        if (size < 22 || size > 16645) throw new Error('fixture_peer_size');
        if (pending.length < size) break;
        const value = peerOpen(inboundState, pending.subarray(0, size));
        pending = Buffer.from(pending.subarray(size));
        const expected = expectedRecords[recordIndex];
        if (!expected || value.type !== expected.type || !value.bytes.equals(expected.bytes)) {
          throw new Error('fixture_peer_unexpected_record');
        }
        recordIndex++;
        if (value.type === 23) bytes = Buffer.concat([bytes, value.bytes]);
        else if (value.type === 22 && value.bytes.equals(Buffer.from([24, 0, 0, 1, 0]))) rotate(inboundState);
        else throw new Error('fixture_peer_content');
      }
      if (bytes.length > 65536) throw new Error('fixture_peer_application_limit');
    } catch (error) {
      fail(error?.message === 'fixture_peer_unexpected_record' ? 'fixture_peer_unexpected_record' : 'fixture_peer_record_failure');
    }
    wake();
  });
  return {
    waitBytes: length => bounded(new Promise((resolve, reject) => {
      const callback = () => {
        if (failure) { waiters.delete(callback); reject(failure); }
        else if (bytes.length >= length) { waiters.delete(callback); resolve(Buffer.from(bytes)); }
      };
      waiters.add(callback); callback();
    }), 'peer_application_bytes'),
    expectEnd: () => {
      if (failure) throw failure;
      if (terminationExpected) throw new Error('fixture_peer_duplicate_termination');
      terminationExpected = true;
    },
    waitTerminal: expected => bounded(new Promise((resolve, reject) => {
      const callback = () => {
        if (failure) { waiters.delete(callback); reject(failure); }
        else if (closed) {
          waiters.delete(callback);
          if (!sawEnd || pending.length !== 0 || recordIndex !== expectedRecords.length || !bytes.equals(expected)) {
            reject(new Error('fixture_peer_terminal_state'));
          } else resolve({ cleanFin: true, pendingCipherBytes: 0, acceptedRecords: recordIndex });
        }
      };
      waiters.add(callback); callback();
    }), 'peer_terminal_state'),
  };
}
function write(socket, bytes) {
  return bounded(new Promise((resolve, reject) => socket.write(bytes, error => error ? reject(new Error('fixture_peer_write')) : resolve())), 'peer_write');
}

/** Transfer one live synthetic established-record stream. `drop-pending` is an
 * intentionally broken baseline adapter. `commit-digest` sends a stale binding.
 * Both counterexamples must fail; they are not supported recovery modes. */
export async function runProcessHandover({ fault = null } = {}) {
  const trailerFaults = ['trailer-corrupt', 'trailer-truncated', 'trailer-key-update', 'trailer-empty-record'];
  if (fault !== null && !['drop-pending', 'commit-digest', ...trailerFaults].includes(fault)) throw new Error('fixture_fault');
  let source;
  let target;
  const children = [];
  let client;
  let accepted;
  let transferred;
  let acceptCount = 0;
  const server = createServer({ pauseOnConnect: true }, socket => { accepted = socket; acceptCount++; });
  server.on('error', () => {});
  try {
    // Register each owned child immediately, so a synchronous failure creating
    // the second process still reaches cleanup of the first process.
    source = channel('v1');
    children.push(source);
    target = channel('v2');
    children.push(target);
    await Promise.all([source.wait('ready'), target.wait('ready')]);
    assert.notEqual(source.child.pid, target.child.pid);
    await bounded(new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    }), 'listen');
    const connected = once(server, 'connection');
    client = createConnection({ host: '127.0.0.1', port: server.address().port });
    client.on('error', () => {});
    await bounded(Promise.all([once(client, 'connect'), connected]), 'connect');
    const tuple = [client.localPort, client.remotePort];
    const readSecret = randomBytes(32);
    const writeSecret = randomBytes(32);
    const outgoing = peerState(readSecret);
    const incoming = peerState(writeSecret);
    const before = Buffer.from('before-handover\0', 'utf8');
    const after = Buffer.from('after-handover\0binary\xff', 'latin1');
    const final = Buffer.from('after-key-update', 'utf8');
    const peer = attachPeer(client, incoming, [
      { type: 23, bytes: before }, { type: 22, bytes: Buffer.from([24, 0, 0, 1, 0]) },
      { type: 23, bytes: after }, { type: 23, bytes: final },
    ]);
    const initial = secret => ({ trafficSecretHex: secret.toString('hex'), epoch: '0', sequence: '0' });
    await source.send({ kind: 'start', connectionId: randomBytes(16).toString('hex'), read: initial(readSecret), write: initial(writeSecret) }, accepted);
    await source.wait('active');
    await write(client, peerSeal(outgoing, before));
    assert.deepEqual(await peer.waitBytes(before.length), before);
    await source.wait('progress', m => m.applicationBytes === before.length && m.pendingBytes === 0);

    // A real incomplete encrypted KeyUpdate record is in the old process.
    const update = peerSeal(outgoing, Buffer.from([24, 0, 0, 1, 1]), 22);
    rotate(outgoing);
    const split = 13;
    await write(client, update.subarray(0, split));
    await source.wait('progress', m => m.pendingBytes === split);
    await source.send({ kind: 'freeze', nonce: randomBytes(32).toString('hex') });
    const offer = await source.wait('offer');
    transferred = offer.handle;
    assert.equal(Buffer.from(offer.message.snapshot.ir.pending.readCipher.hex, 'hex').length, split);
    const snapshot = structuredClone(offer.message.snapshot);
    if (fault === 'drop-pending') snapshot.ir.pending.readCipher.hex = '';
    const ir = snapshot.ir;
    const model = new HandoverModel();
    let handover = createHandover(ir, { model });
    const bind = { connectionId: ir.connectionId, transferNonce: ir.ownership.transferNonce,
      epoch: ir.ownership.epoch, irSha256: handoverDigest(ir) };
    assert.equal(canWrite(handover, ir.ownership.source), false);
    assert.equal(canWrite(handover, ir.ownership.target), false);
    await target.send({ kind: 'prepare', snapshot }, offer.handle);
    const prepared = await target.wait('prepared');
    assert.equal(prepared.message.irSha256, bind.irSha256);
    handover = transitionHandover(handover, { ...bind, type: 'prepared', actor: ir.ownership.target });
    handover = transitionHandover(handover, { ...bind, type: 'commit', actor: ir.ownership.source });
    await source.send({ kind: 'retire' });
    assert.deepEqual(await bounded(source.closed, 'old_process_exit'), { code: 0, signal: null });
    handover = transitionHandover(handover, { ...bind, epoch: ir.ownership.nextEpoch, type: 'retire', actor: ir.ownership.source });
    assert.equal(canWrite(handover, ir.ownership.source), false);
    assert.equal(canWrite(handover, ir.ownership.target), true);
    await target.send({ kind: 'commit', irSha256: fault === 'commit-digest' ? '0'.repeat(64) : bind.irSha256 });
    await target.wait('active');

    await write(client, Buffer.concat([update.subarray(split), peerSeal(outgoing, after)]));
    const firstExpected = Buffer.concat([before, after]);
    assert.deepEqual(await peer.waitBytes(firstExpected.length), firstExpected);
    await write(client, peerSeal(outgoing, final));
    const expected = Buffer.concat([before, after, final]);
    assert.deepEqual(await peer.waitBytes(expected.length), expected);
    const progress = await target.wait('progress', m => m.applicationBytes === expected.length);
    assert.equal(progress.message.readEpoch, '1');
    assert.equal(incoming.epoch, 1);
    assert.deepEqual([client.localPort, client.remotePort], tuple);
    assert.equal(acceptCount, 1);
    assert.equal(source.exited, true);
    peer.expectEnd();
    await target.send({ kind: 'stop', trailerFault: trailerFaults.includes(fault) ? fault : null });
    assert.deepEqual(await bounded(target.closed, 'new_process_exit'), { code: 0, signal: null });
    const terminal = await peer.waitTerminal(expected);
    return {
      schemaVersion: 1, recordKind: 'research-process-fixture-result',
      outcome: 'pass', acceptedConnections: acceptCount, oldProcessExited: true,
      sameClientConnection: true, manualLayoutAdapter: ['v1-counter', 'v2-nested-statistics'],
      partialCipherBytesTransferred: split, readKeyUpdates: 1, writeKeyUpdates: 1,
      applicationBytesEchoed: expected.length, exactApplicationBytes: true,
      terminalStateChecked: true, peerObservedCleanFin: terminal.cleanFin,
      pendingCipherBytesAtEnd: terminal.pendingCipherBytes, acceptedEncryptedRecords: terminal.acceptedRecords,
      sourceBinaryChanged: false, tlsLibraryChanged: false, handshakeImplemented: false,
      nativeNginxIntegration: false, automaticAdapter: false, independentPeerRecordCode: true,
    };
  } finally {
    client?.destroy();
    accepted?.destroy();
    transferred?.destroy();
    try {
      if (server.listening) {
        // Close the listener before awaiting any child cleanup that may reject.
        // close() stops accepting synchronously. Its callback may keep waiting
        // on Node's transferred-socket accounting, not socket ownership.
        server.close();
        server.unref();
        assert.equal(server.listening, false);
        assert.equal(server.address(), null);
      }
    } finally {
      // Child cleanup also runs when closing/asserting listener state fails.
      for (const worker of children) if (!worker.exited) worker.child.kill('SIGKILL');
      await Promise.all(children.map(worker => bounded(worker.closed, 'cleanup_child', 2000)));
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runProcessHandover().then(result => console.log(JSON.stringify(result))).catch(() => {
    console.error(JSON.stringify({ outcome: 'fail', reason: 'process_fixture_failed' }));
    process.exitCode = 1;
  });
}
