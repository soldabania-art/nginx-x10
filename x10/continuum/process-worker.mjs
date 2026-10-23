// Research fixture only: post-handshake records with synthetic runtime secrets.
// This is not an OpenSSL exporter, a TLS handshake, or the native NGINX data plane.
import { Socket } from 'node:net';
import {
  sealRecord, openRecord, advanceSequence, updateTrafficState,
  encodeKeyUpdate, parseKeyUpdate, recordLength,
} from './record.mjs';
import { validateContinuationIR, handoverDigest } from './state.mjs';

const layout = process.argv[2];
if (!['v1', 'v2'].includes(layout) || !process.send) process.exit(2);
let phase = 'empty';
let socket;
let reading;
let writing;
let pending = Buffer.alloc(0);
let connectionId;
let preparedDigest;
// The two application handlers deliberately keep their counter differently.
let app = layout === 'v1' ? { acceptedBytes: 0 } : { statistics: { octets: 0 } };
let writes = Promise.resolve();
let failed = false;
const LIMIT = 65536;

function count() {
  return layout === 'v1' ? app.acceptedBytes : app.statistics.octets;
}
function accept(bytes) {
  if (layout === 'v1') app.acceptedBytes += bytes;
  else app.statistics.octets += bytes;
  if (!Number.isSafeInteger(count()) || count() > LIMIT) throw new Error('application_limit');
}
function send(message, handle) {
  return new Promise((resolve, reject) => {
    process.send(message, handle, { keepOpen: false }, error => error ? reject(error) : resolve());
  });
}
function fail(reason) {
  if (failed) return;
  failed = true;
  phase = 'failed';
  socket?.destroy();
  // No exception text: a crypto implementation could include private inputs.
  const code = reason === 'commit_binding' ? 'commit_binding' : 'fixture_protocol_failure';
  if (process.connected) process.send({ kind: 'failure', reason: code }, () => process.exit(1));
  else process.exit(1);
}
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error('schema');
}
function secretState(value) {
  exact(value, ['trafficSecretHex', 'epoch', 'sequence']);
  if (!/^[0-9a-f]{64}$/.test(value.trafficSecretHex) ||
      !/^(0|[1-9][0-9]{0,19})$/.test(value.epoch) ||
      !/^(0|[1-9][0-9]{0,19})$/.test(value.sequence)) throw new Error('state');
  const epoch = BigInt(value.epoch);
  const sequence = BigInt(value.sequence);
  if (epoch > 0xffffffffffffffffn || sequence >= 0xffffffffffffffffn) throw new Error('counter');
  return { trafficSecret: Buffer.from(value.trafficSecretHex, 'hex'), epoch, sequence };
}
function serializeState(value) {
  return { trafficSecretHex: value.trafficSecret.toString('hex'), epoch: String(value.epoch), sequence: String(value.sequence) };
}
function importSnapshot(value) {
  exact(value, ['schema', 'ir', 'applicationBytes']);
  if (value.schema !== 'continuum-process-fixture-v0' ||
      !Number.isSafeInteger(value.applicationBytes) || value.applicationBytes < 0 || value.applicationBytes > LIMIT) {
    throw new Error('snapshot');
  }
  const ir = validateContinuationIR(value.ir);
  if (ir.ownership.source !== 'source-v1' || ir.ownership.target !== 'target-v2' ||
      ir.pending.readCipher.offset !== 0 || ir.pending.writeCipher !== null ||
      ir.pending.readPlain.hex !== '' || ir.pending.writePlain.hex !== '') throw new Error('unsupported_snapshot');
  connectionId = ir.connectionId;
  reading = secretState(ir.read);
  writing = secretState(ir.write);
  pending = Buffer.from(ir.pending.readCipher.hex, 'hex');
  // Explicit, hand-written v1 -> v2 adapter; not automatic program synthesis.
  app = { statistics: { octets: value.applicationBytes } };
  return ir;
}
function enqueueRecord(content, options = {}) {
  if (phase !== 'active') throw new Error('not_owner');
  const record = sealRecord(writing, content, options);
  writing = advanceSequence(writing);
  writes = writes.then(() => new Promise((resolve, reject) => {
    if (phase !== 'active' && phase !== 'freezing' && phase !== 'stopping') return reject(new Error('not_owner'));
    socket.write(record, error => error ? reject(error) : resolve());
  }));
  writes.catch(fail);
}
function processInput(chunk) {
  if (phase !== 'active') return fail();
  if (pending.length + chunk.length > LIMIT) return fail();
  pending = Buffer.concat([pending, chunk]);
  try {
    while (pending.length >= 5) {
      const length = recordLength(pending.subarray(0, 5));
      if (pending.length < length) break;
      const opened = openRecord(reading, pending.subarray(0, length));
      reading = advanceSequence(reading);
      pending = Buffer.from(pending.subarray(length));
      if (opened.contentType === 23) {
        accept(opened.content.length);
        enqueueRecord(opened.content);
      } else if (opened.contentType === 22) {
        const update = parseKeyUpdate(opened.content);
        reading = updateTrafficState(reading);
        if (update.requestUpdate) {
          enqueueRecord(encodeKeyUpdate(false), { contentType: 22 });
          writing = updateTrafficState(writing);
        }
      } else throw new Error('unsupported_content');
    }
    void send({ kind: 'progress', pendingBytes: pending.length, applicationBytes: count(), readEpoch: String(reading.epoch) }).catch(fail);
  } catch { fail(); }
}
function attach(handle) {
  if (!(handle instanceof Socket)) throw new Error('socket');
  socket = handle;
  socket.pause();
  socket.on('error', fail);
  socket.on('data', processInput);
}

process.on('message', async (message, handle) => {
  try {
    if (message?.kind === 'start' && layout === 'v1' && phase === 'empty') {
      if (!/^[0-9a-f]{32}$/.test(message.connectionId)) throw new Error('identity');
      connectionId = message.connectionId;
      reading = secretState(message.read);
      writing = secretState(message.write);
      attach(handle);
      phase = 'active';
      socket.resume();
      await send({ kind: 'active', layout });
    } else if (message?.kind === 'freeze' && layout === 'v1' && phase === 'active') {
      if (!/^[0-9a-f]{64}$/.test(message.nonce)) throw new Error('nonce');
      // The fixture peer is deliberately paused at a known split-record point.
      // Drain Node's own readable queue as IPC does not transfer buffered bytes.
      socket.pause();
      phase = 'freezing';
      socket.removeListener('data', processInput);
      let extra;
      while ((extra = socket.read()) !== null) pending = Buffer.concat([pending, extra]);
      if (pending.length > LIMIT) throw new Error('pending_limit');
      await writes;
      phase = 'frozen';
      const snapshot = {
        schema: 'continuum-process-fixture-v0', applicationBytes: count(),
        ir: validateContinuationIR({
          schema: 'ContinuationIRv0', version: 0, protocol: 'TLS1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256',
          connectionId,
          ownership: { source: 'source-v1', target: 'target-v2', epoch: '0', nextEpoch: '1', transferNonce: message.nonce },
          read: serializeState(reading), write: serializeState(writing),
          pending: { readCipher: { hex: pending.toString('hex'), offset: 0 }, writeCipher: null,
            readPlain: { hex: '', offset: 0 }, writePlain: { hex: '', offset: 0 } },
        }),
      };
      await send({ kind: 'offer', snapshot }, socket);
    } else if (message?.kind === 'prepare' && layout === 'v2' && phase === 'empty') {
      const imported = importSnapshot(message.snapshot);
      preparedDigest = handoverDigest(imported);
      attach(handle);
      phase = 'prepared';
      await send({ kind: 'prepared', pendingBytes: pending.length, applicationBytes: count(), irSha256: preparedDigest });
    } else if (message?.kind === 'commit' && layout === 'v2' && phase === 'prepared') {
      if (message.irSha256 !== preparedDigest) return fail('commit_binding');
      phase = 'active';
      socket.resume();
      await send({ kind: 'active', layout });
    } else if (message?.kind === 'retire' && layout === 'v1' && phase === 'frozen') {
      // No resume path exists after exporting ownership.
      phase = 'retired';
      await send({ kind: 'retired' });
      process.exit(0);
    } else if (message?.kind === 'stop' && layout === 'v2' && phase === 'active') {
      const trailerFaults = ['trailer-corrupt', 'trailer-truncated', 'trailer-key-update', 'trailer-empty-record'];
      if (message.trailerFault !== null && !trailerFaults.includes(message.trailerFault)) throw new Error('trailer_fault');
      // Explicit negative controls for the fixture oracle, never normal output.
      let trailer;
      if (message.trailerFault) {
        const isKeyUpdate = message.trailerFault === 'trailer-key-update';
        const content = isKeyUpdate ? encodeKeyUpdate(false) :
          message.trailerFault === 'trailer-empty-record' ? Buffer.alloc(0) : Buffer.from('unexpected-trailer');
        trailer = sealRecord(writing, content, { contentType: isKeyUpdate ? 22 : 23 });
        writing = advanceSequence(writing);
        if (message.trailerFault === 'trailer-corrupt') trailer[trailer.length - 1] ^= 1;
        if (message.trailerFault === 'trailer-truncated') trailer = trailer.subarray(0, 9);
      }
      phase = 'stopping';
      await writes;
      // Keep the process alive until the peer has observed FIN and replied with
      // its own FIN. process.exit()/destroy() alone can hide unread wire bytes.
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('terminal_close_timeout')), 2000);
        socket.once('close', hadError => {
          clearTimeout(timer);
          hadError ? reject(new Error('terminal_close_error')) : resolve();
        });
        if (trailer) socket.write(trailer);
        socket.end();
      });
      phase = 'stopped';
      process.exit(0);
    } else throw new Error('transition');
  } catch { fail(); }
});
process.on('disconnect', () => { socket?.destroy(); process.exit(1); });
process.on('uncaughtException', fail);
process.on('unhandledRejection', fail);
void send({ kind: 'ready', layout }).catch(fail);
