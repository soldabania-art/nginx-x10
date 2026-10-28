// Standalone synthetic continuation model, not native FD/TLS ownership proof.
// RFC 8446 sections 5.2-5.5 define independent record sequences and TLS bounds.
import { createHash, createHmac, createDecipheriv } from 'node:crypto';

export const MAX_SERIALIZED_BYTES = 262144;
export const MAX_PLAINTEXT_BYTES = 16384;
export const MAX_WIRE_BYTES = 5 + 16385 + 16;
export const U64_MAX = 18446744073709551615n;
// Match the record worker's conservative research per-key usage policy.
export const MAX_RECORDS_PER_KEY = 1n << 24n;
const TOKEN_MODELS = new WeakMap();
const MAX_TRANSFERS = 256;
function reject(code) { throw Object.assign(new Error('Continuation model rejected input'), { code }); }
function exactKeys(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) reject('ir_schema');
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) reject('ir_schema');
  for (const key of keys) { const d = Object.getOwnPropertyDescriptor(value, key); if (!d.enumerable || !('value' in d)) reject('ir_schema'); }
}
const hash = value => createHash('sha256').update(value).digest('hex');
const decimal = value => {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > U64_MAX) reject('ir_counter');
  return value;
};
const hex = (value, maxBytes, exactBytes = null) => {
  if (typeof value !== 'string' || value.length > maxBytes * 2 || value.length % 2 || !/^[a-f0-9]*$/.test(value)
    || (exactBytes !== null && value.length !== exactBytes * 2)) reject('ir_buffer');
  return value;
};
const owner = value => { if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(value)) reject('ir_identity'); return value; };
const frozen = value => { if (value && typeof value === 'object') { for (const child of Object.values(value)) frozen(child); Object.freeze(value); } return value; };
function direction(value) {
  exactKeys(value, ['trafficSecretHex', 'epoch', 'sequence']);
  const result = { trafficSecretHex: hex(value.trafficSecretHex, 32, 32), epoch: decimal(value.epoch), sequence: decimal(value.sequence) };
  if (BigInt(result.sequence) >= MAX_RECORDS_PER_KEY) reject('ir_key_usage');
  return result;
}
function buffer(value, max) {
  exactKeys(value, ['hex', 'offset']); const bytes = hex(value.hex, max), length = bytes.length / 2;
  if (!Number.isSafeInteger(value.offset) || Object.is(value.offset, -0) || value.offset < 0 || (length ? value.offset >= length : value.offset !== 0)) reject('ir_offset');
  return { hex: bytes, offset: value.offset };
}
function wireLength(bytes) {
  if (bytes.length > MAX_WIRE_BYTES) reject('ir_record');
  const prefix = [23, 3, 3];
  for (let i = 0; i < Math.min(bytes.length, 3); i++) if (bytes[i] !== prefix[i]) reject('ir_record');
  if (bytes.length < 5) return null;
  const body = bytes.readUInt16BE(3);
  if (body < 17 || body > 16385 + 16) reject('ir_record');
  return body + 5;
}
// Independent pending-record authentication; no import from the record worker.
function expand(secret, label, size) {
  const name = Buffer.from(`tls13 ${label}`), info = Buffer.concat([Buffer.from([size >> 8, size & 255, name.length]), name, Buffer.from([0])]);
  const block = createHmac('sha256', secret).update(info).update(Buffer.from([1])).digest();
  try { return Buffer.from(block.subarray(0, size)); } finally { block.fill(0); }
}
function authenticatePending(record, state) {
  const wire = Buffer.from(record.hex, 'hex'), secret = Buffer.from(state.trafficSecretHex, 'hex');
  const key = expand(secret, 'key', 16), nonce = Buffer.from(expand(secret, 'iv', 12)), counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(record.sequence)); for (let i = 0; i < 8; i++) nonce[4 + i] ^= counter[i];
  let plain, chunk, tail;
  try {
    const decipher = createDecipheriv('aes-128-gcm', key, nonce); decipher.setAAD(wire.subarray(0, 5));
    decipher.setAuthTag(wire.subarray(-16)); chunk = decipher.update(wire.subarray(5, -16)); tail = decipher.final(); plain = Buffer.concat([chunk, tail]);
    let end = plain.length - 1; while (end >= 0 && plain[end] === 0) end--;
    // A queued KeyUpdate/alert is deliberately outside this application snapshot.
    if (end < 0 || plain[end] !== 23 || end > MAX_PLAINTEXT_BYTES || plain.length > 16385) reject('ir_record');
  } catch { reject('ir_record'); }
  finally { key.fill(0); secret.fill(0); nonce.fill(0); counter.fill(0); chunk?.fill(0); tail?.fill(0); plain?.fill(0); }
}

export function validateContinuationIR(value) {
  exactKeys(value, ['schema', 'version', 'protocol', 'cipherSuite', 'connectionId', 'ownership', 'read', 'write', 'pending']);
  if (value.schema !== 'ContinuationIRv0' || value.version !== 0 || Object.is(value.version, -0)
    || value.protocol !== 'TLS1.3' || value.cipherSuite !== 'TLS_AES_128_GCM_SHA256') reject('ir_profile');
  const connectionId = hex(value.connectionId, 16, 16);
  exactKeys(value.ownership, ['source', 'target', 'epoch', 'nextEpoch', 'transferNonce']);
  const o = value.ownership, ownership = { source: owner(o.source), target: owner(o.target), epoch: decimal(o.epoch), nextEpoch: decimal(o.nextEpoch), transferNonce: hex(o.transferNonce, 32, 32) };
  if (ownership.source === ownership.target || BigInt(ownership.epoch) === U64_MAX || BigInt(ownership.nextEpoch) !== BigInt(ownership.epoch) + 1n) reject('ir_ownership');
  const read = direction(value.read), write = direction(value.write);
  exactKeys(value.pending, ['readCipher', 'writeCipher', 'readPlain', 'writePlain']);
  const readCipher = buffer(value.pending.readCipher, MAX_WIRE_BYTES - 1);
  if (readCipher.offset !== 0) reject('ir_offset');
  const received = Buffer.from(readCipher.hex, 'hex'), length = wireLength(received);
  if (length !== null && received.length >= length) reject('ir_record');
  let writeCipher = null;
  if (value.pending.writeCipher !== null) {
    const p = value.pending.writeCipher; exactKeys(p, ['hex', 'offset', 'epoch', 'sequence']);
    const b = buffer({ hex: p.hex, offset: p.offset }, MAX_WIRE_BYTES);
    const bytes = Buffer.from(b.hex, 'hex'); if (wireLength(bytes) !== bytes.length) reject('ir_record');
    writeCipher = { ...b, epoch: decimal(p.epoch), sequence: decimal(p.sequence) };
    if (writeCipher.epoch !== write.epoch || BigInt(writeCipher.sequence) === U64_MAX || BigInt(writeCipher.sequence) + 1n !== BigInt(write.sequence)) reject('ir_pending_sequence');
    authenticatePending(writeCipher, write);
  }
  const pending = { readCipher, writeCipher, readPlain: buffer(value.pending.readPlain, MAX_PLAINTEXT_BYTES), writePlain: buffer(value.pending.writePlain, MAX_PLAINTEXT_BYTES) };
  return frozen({ schema: 'ContinuationIRv0', version: 0, protocol: 'TLS1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', connectionId, ownership, read, write, pending });
}

// Small bounded parser rejects duplicate decoded keys and deep/container input
// before JSON.parse could silently overwrite fields or allocate an arbitrary tree.
export function parseContinuationIR(input) {
  let text;
  if (typeof input === 'string') { if (input.length > MAX_SERIALIZED_BYTES || Buffer.byteLength(input) > MAX_SERIALIZED_BYTES) reject('ir_input_limit'); text = input; }
  else if (input instanceof Uint8Array) {
    if (input.byteLength > MAX_SERIALIZED_BYTES) reject('ir_input_limit');
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input); } catch { reject('ir_json'); }
  } else reject('ir_json');
  let at = 0, nodes = 0;
  const whitespace = () => { while (/[\x20\x09\x0a\x0d]/.test(text[at] || '\0')) at++; };
  const string = () => {
    const begin = at++; let escaped = false;
    while (at < text.length) {
      const ch = text[at++];
      if (!escaped && ch === '"') {
        if (at - begin > MAX_WIRE_BYTES * 2 + 2) reject('ir_input_limit');
        try { return JSON.parse(text.slice(begin, at)); } catch { reject('ir_json'); }
      }
      if (!escaped && ch === '\\') escaped = true; else escaped = false;
    }
    reject('ir_json');
  };
  const parse = depth => {
    if (depth > 6 || ++nodes > 100) reject('ir_input_limit'); whitespace();
    if (text[at] === '{') {
      at++; whitespace(); const object = Object.create(null), names = new Set();
      if (text[at] === '}') { at++; return object; }
      while (true) {
        if (text[at] !== '"') reject('ir_json'); const name = string();
        if (names.has(name) || names.size >= 12) reject('ir_json'); names.add(name); whitespace();
        if (text[at++] !== ':') reject('ir_json'); object[name] = parse(depth + 1); whitespace();
        if (text[at] === '}') { at++; return object; } if (text[at++] !== ',') reject('ir_json'); whitespace();
      }
    }
    if (text[at] === '"') return string();
    if (text.slice(at, at + 4) === 'null') { at += 4; return null; }
    const match = /^(?:0|[1-9][0-9]{0,5})(?![0-9.eE+-])/.exec(text.slice(at));
    if (!match) reject('ir_json'); at += match[0].length; return Number(match[0]);
  };
  const value = parse(0); whitespace(); if (at !== text.length) reject('ir_json');
  return validateContinuationIR(value);
}

export function handoverDigest(value) { return hash(JSON.stringify(validateContinuationIR(value))); }

export function validateHandoverState(value) {
  exactKeys(value, ['schema', 'phase', 'connectionId', 'transferNonce', 'source', 'target', 'epoch', 'nextEpoch', 'activeOwner', 'writer', 'irSha256']);
  if (value.schema !== 'ContinuationHandoverv0' || !['offer', 'prepared', 'commit', 'retire'].includes(value.phase)) reject('handover_schema');
  hex(value.connectionId, 16, 16); hex(value.transferNonce, 32, 32); hex(value.irSha256, 32, 32);
  owner(value.source); owner(value.target); decimal(value.epoch); decimal(value.nextEpoch);
  if (value.source === value.target || BigInt(value.nextEpoch) !== BigInt(value.epoch) + 1n) reject('handover_schema');
  const committed = ['commit', 'retire'].includes(value.phase);
  if (value.activeOwner !== (committed ? value.target : value.source) || value.writer !== (committed ? value.target : null)) reject('handover_ownership');
  return value;
}

function continuedDirection(before, after) {
  const oldEpoch = BigInt(before.epoch), nextEpoch = BigInt(after.epoch);
  if (nextEpoch < oldEpoch || nextEpoch - oldEpoch > 16n) reject('handover_stale');
  if (nextEpoch === oldEpoch) {
    if (after.trafficSecretHex !== before.trafficSecretHex || BigInt(after.sequence) < BigInt(before.sequence)) reject('handover_stale');
    return;
  }
  // This bounded model validates at most sixteen completed KeyUpdates between
  // transfers. Larger gaps require a new coordinator/explicit reconciliation.
  let secret = Buffer.from(before.trafficSecretHex, 'hex');
  try {
    for (let epoch = oldEpoch; epoch < nextEpoch; epoch++) { const next = expand(secret, 'traffic upd', 32); secret.fill(0); secret = next; }
    if (secret.toString('hex') !== after.trafficSecretHex) reject('handover_stale');
  } finally { secret.fill(0); }
}

// The coordinator scopes nonce and owner-epoch memory. It is deliberately not
// serializable and grants no kernel/socket authority. Snapshots quiesce writes
// at offer; only the target receives a modeled write grant after commit.
export class HandoverModel {
  #connections = new Map();
  #nonces = new Set();
  #tokens = new WeakMap();
  offer(value) {
    const ir = validateContinuationIR(value), o = ir.ownership, prior = this.#connections.get(ir.connectionId);
    if (this.#nonces.size >= MAX_TRANSFERS) reject('handover_limit');
    if (this.#nonces.has(o.transferNonce)) reject('handover_replay');
    if (prior && (prior.phase !== 'retire' || prior.activeOwner !== o.source || prior.nextEpoch !== o.epoch)) reject('handover_stale');
    if (prior) { const previous = this.#tokens.get(prior); continuedDirection(previous.read, ir.read); continuedDirection(previous.write, ir.write); }
    const token = frozen({ schema: 'ContinuationHandoverv0', phase: 'offer', connectionId: ir.connectionId, transferNonce: o.transferNonce,
      source: o.source, target: o.target, epoch: o.epoch, nextEpoch: o.nextEpoch, activeOwner: o.source, writer: null, irSha256: hash(JSON.stringify(ir)) });
    this.#nonces.add(o.transferNonce); this.#tokens.set(token, ir); this.#connections.set(ir.connectionId, token); TOKEN_MODELS.set(token, this); return token;
  }
  #current(token) {
    validateHandoverState(token);
    if (!this.#tokens.has(token) || this.#connections.get(token.connectionId) !== token) reject('handover_stale');
    return this.#tokens.get(token);
  }
  transition(token, event) {
    const ir = this.#current(token);
    exactKeys(event, ['type', 'connectionId', 'transferNonce', 'epoch', 'actor', 'irSha256']);
    if (event.connectionId !== token.connectionId || event.transferNonce !== token.transferNonce || event.irSha256 !== token.irSha256) reject('handover_binding');
    const next = { offer: 'prepared', prepared: 'commit', commit: 'retire' }[token.phase];
    if (!next || event.type !== next) reject('handover_phase');
    if (event.actor !== (next === 'prepared' ? token.target : token.source) || event.epoch !== (next === 'retire' ? token.nextEpoch : token.epoch)) reject('handover_ownership');
    // Recheck the independently validated frozen IR and its digest at each step.
    if (handoverDigest(ir) !== token.irSha256) reject('handover_binding');
    const committed = next === 'commit' || next === 'retire';
    const result = frozen({ ...token, phase: next, activeOwner: committed ? token.target : token.source, writer: committed ? token.target : null });
    validateHandoverState(result); this.#tokens.delete(token); this.#tokens.set(result, ir); this.#connections.set(result.connectionId, result); TOKEN_MODELS.set(result, this); return result;
  }
  canWrite(token, actor) { this.#current(token); return token.writer === actor; }
}
export function createHandover(ir, { model = new HandoverModel() } = {}) {
  if (!(model instanceof HandoverModel)) reject('handover_schema'); return model.offer(ir);
}
export function transitionHandover(state, event) { const model = TOKEN_MODELS.get(state); if (!model) reject('handover_stale'); return model.transition(state, event); }
export function canWrite(state, actor) { const model = TOKEN_MODELS.get(state); if (!model) reject('handover_stale'); return model.canWrite(state, actor); }
