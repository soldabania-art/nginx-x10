// Standalone TLS 1.3 record research primitives, NOT a TLS implementation.
// No handshake, network I/O, snapshot importer, peer identity, replay ledger,
// implicit counter mutation or production key-management contract is provided.
// Source: RFC 8446 §§4.6.3, 5.2–5.5, 7.1–7.3; HKDF Expand: RFC 5869 §2.3.
// https://www.rfc-editor.org/rfc/rfc8446.html
// https://www.rfc-editor.org/rfc/rfc5869.html
import { createCipheriv, createDecipheriv, createHmac } from 'node:crypto';

export const CIPHER_SUITE = 'TLS_AES_128_GCM_SHA256';
export const CONTENT_TYPES = Object.freeze({ alert: 21, handshake: 22, applicationData: 23 });
export const MAX_SEQUENCE = (1n << 64n) - 1n;
export const MAX_EPOCH = MAX_SEQUENCE;
export const MAX_CONTENT_BYTES = 1 << 14;
export const MAX_INNER_PLAINTEXT_BYTES = MAX_CONTENT_BYTES + 1;
export const HEADER_BYTES = 5;
export const AUTH_TAG_BYTES = 16;
export const MAX_CIPHERTEXT_BYTES = MAX_INNER_PLAINTEXT_BYTES + AUTH_TAG_BYTES;
export const MAX_RECORD_BYTES = HEADER_BYTES + MAX_CIPHERTEXT_BYTES;
// Conservative fixture policy below the RFC's approximately 2^24.5 full-size
// AES-GCM records. This is a local API bound, not a complete usage-limit system.
// A caller must reserve a record for KeyUpdate before reaching this bound.
export const MAX_RECORDS_PER_KEY = 1n << 24n;

export class RecordError extends Error {
  constructor(code, message) { super(message); this.name = 'RecordError'; this.code = code; }
}
const fail = (code, message) => { throw new RecordError(code, message); };
const bytes = (value, length, label) => {
  if (!Buffer.isBuffer(value) || (length !== undefined && value.length !== length)) fail('invalid_bytes', `${label} must be a Buffer of the required length`);
  return value;
};
const u64 = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_SEQUENCE) fail('invalid_counter', `${label} must be a uint64 bigint`);
  return value;
};
function state(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'epoch,sequence,trafficSecret') fail('invalid_state', 'A direction requires trafficSecret, epoch and sequence only');
  bytes(value.trafficSecret, 32, 'Traffic secret'); u64(value.epoch, 'Epoch'); u64(value.sequence, 'Sequence');
  return value;
}
function usableState(value) {
  state(value);
  if (value.sequence >= MAX_RECORDS_PER_KEY) fail('key_usage_limit', 'Research per-key record limit reached; rekey or close before further records');
  return value;
}

/** HKDF-Expand-Label using a 32-byte SHA-256 PRK; does NOT perform Extract.
 * label is printable ASCII without the automatically supplied "tls13 " prefix;
 * context is a Buffer of at most 255 bytes, length is 1..8160 bytes.
 * The returned Buffer is secret material and must never be logged/serialized.
 */
export function hkdfExpandLabel(secret, label, context, length) {
  bytes(secret, 32, 'HKDF secret'); bytes(context, undefined, 'HKDF context');
  if (typeof label !== 'string' || !/^[\x20-\x7e]{1,249}$/.test(label) || context.length > 255
    || !Number.isInteger(length) || length < 1 || length > 255 * 32) fail('invalid_hkdf_label', 'HKDF label, context or output length is outside the bounded SHA-256 profile');
  const fullLabel = Buffer.from(`tls13 ${label}`, 'ascii');
  const info = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  info.writeUInt16BE(length, 0); info[2] = fullLabel.length; fullLabel.copy(info, 3);
  info[3 + fullLabel.length] = context.length; context.copy(info, 4 + fullLabel.length);
  const output = Buffer.alloc(length), key = Buffer.from(secret);
  let previous = Buffer.alloc(0), offset = 0;
  try {
    for (let counter = 1; offset < length; counter++) {
      const block = createHmac('sha256', key).update(previous).update(info).update(Buffer.from([counter])).digest();
      previous.fill(0); previous = block;
      const count = Math.min(block.length, length - offset); block.copy(output, offset, 0, count); offset += count;
    }
    return output;
  } catch (error) { output.fill(0); throw error; }
  finally { previous.fill(0); key.fill(0); info.fill(0); }
}

/** Derive independent AES-128-GCM key (16B) and static IV (12B).
 * Both returned Buffers contain secret material. Input is not changed.
 */
export function deriveTrafficKeys(trafficSecret) {
  bytes(trafficSecret, 32, 'Traffic secret');
  return { key: hkdfExpandLabel(trafficSecret, 'key', Buffer.alloc(0), 16), iv: hkdfExpandLabel(trafficSecret, 'iv', Buffer.alloc(0), 12) };
}

/** RFC 8446 §5.3: static IV XOR left-zero-padded uint64 sequence, in BE order.
 * This arithmetic helper accepts every uint64. seal/open apply a lower usage cap.
 */
export function nonceFor(iv, sequence) {
  bytes(iv, 12, 'Static IV'); u64(sequence, 'Sequence');
  const nonce = Buffer.from(iv), encoded = Buffer.alloc(8); encoded.writeBigUInt64BE(sequence);
  for (let i = 0; i < encoded.length; i++) nonce[4 + i] ^= encoded[i];
  encoded.fill(0); return nonce;
}

/** Parse exactly one 5-byte encrypted-record header; return total wire bytes.
 * A caller owns bounded stream assembly. No partial/coalesced records are accepted
 * by openRecord. This profile permits AES-GCM expansion only, not arbitrary AEADs.
 */
export function recordLength(header) {
  bytes(header, HEADER_BYTES, 'Record header');
  if (header[0] !== CONTENT_TYPES.applicationData || header[1] !== 3 || header[2] !== 3) fail('invalid_record_header', 'Expected a TLS 1.3 encrypted record header');
  const length = header.readUInt16BE(3);
  if (length < AUTH_TAG_BYTES + 1 || length > MAX_CIPHERTEXT_BYTES) fail('record_overflow', 'Encrypted record length is outside the AES-128-GCM profile');
  return HEADER_BYTES + length;
}

function contentType(value) {
  if (!Object.values(CONTENT_TYPES).includes(value)) fail('unexpected_message', 'Unsupported TLS inner content type');
  return value;
}

/** Seal exactly one record, without changing its supplied direction state.
 * direction = {trafficSecret: Buffer(32), epoch: bigint, sequence: bigint}.
 * epoch is checked metadata: TLS wire AAD authenticates the 5-byte header only.
 * A caller MUST uniquely own each (secret, sequence) pair and advance sequence
 * after every record; cloning/reusing this stateless input is unsafe.
 * options supports contentType (21/22/23) and zero-padding byte count only.
 */
export function sealRecord(direction, content, options = {}) {
  usableState(direction); bytes(content, undefined, 'Record content');
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || Object.keys(options).some(key => !['contentType', 'padding'].includes(key))) fail('invalid_record_options', 'Only contentType and padding options are supported');
  const type = contentType(options.contentType ?? CONTENT_TYPES.applicationData), padding = options.padding ?? 0;
  if (content.length > MAX_CONTENT_BYTES || !Number.isInteger(padding) || padding < 0 || padding > MAX_CONTENT_BYTES
    || content.length + 1 + padding > MAX_INNER_PLAINTEXT_BYTES) fail('record_overflow', 'Content and padding exceed the TLS inner-plaintext limit');
  if (content.length === 0 && type !== CONTENT_TYPES.applicationData) fail('unexpected_message', 'Handshake and Alert contents cannot be empty');
  const inner = Buffer.alloc(content.length + 1 + padding); content.copy(inner); inner[content.length] = type;
  const header = Buffer.from([CONTENT_TYPES.applicationData, 3, 3, 0, 0]); header.writeUInt16BE(inner.length + AUTH_TAG_BYTES, 3);
  const { key, iv } = deriveTrafficKeys(direction.trafficSecret), nonce = nonceFor(iv, direction.sequence);
  try {
    const cipher = createCipheriv('aes-128-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES }); cipher.setAAD(header);
    return Buffer.concat([header, cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
  } finally { inner.fill(0); key.fill(0); iv.fill(0); nonce.fill(0); }
}

/** Authenticate/decrypt exactly one complete record before exposing plaintext.
 * Returns {content: Buffer, contentType: number, padding: number}; no counter or
 * epoch change is implicit. Handshake/alert semantics remain the caller's job.
 * All AEAD failures use one fixed error; errors never contain key/plaintext bytes.
 */
export function openRecord(direction, record) {
  usableState(direction); bytes(record, undefined, 'Encrypted record');
  if (record.length < HEADER_BYTES || record.length > MAX_RECORD_BYTES) fail('record_overflow', 'Expected one bounded complete encrypted record');
  const total = recordLength(record.subarray(0, HEADER_BYTES));
  if (record.length !== total) fail('invalid_record_length', 'Partial or coalesced encrypted records are not accepted');
  const { key, iv } = deriveTrafficKeys(direction.trafficSecret), nonce = nonceFor(iv, direction.sequence);
  let chunk, tail, inner;
  try {
    const decipher = createDecipheriv('aes-128-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES });
    decipher.setAAD(record.subarray(0, HEADER_BYTES)); decipher.setAuthTag(record.subarray(-AUTH_TAG_BYTES));
    try {
      chunk = decipher.update(record.subarray(HEADER_BYTES, -AUTH_TAG_BYTES)); tail = decipher.final(); inner = Buffer.concat([chunk, tail]);
    } catch { fail('bad_record_mac', 'TLS record authentication failed'); }
    if (inner.length > MAX_INNER_PLAINTEXT_BYTES) fail('record_overflow', 'Decrypted record exceeds the inner-plaintext limit');
    let index = inner.length - 1; while (index >= 0 && inner[index] === 0) index--;
    if (index < 0) fail('unexpected_message', 'TLS inner plaintext contains no content type');
    const type = contentType(inner[index]);
    if (index === 0 && type !== CONTENT_TYPES.applicationData) fail('unexpected_message', 'Handshake and Alert contents cannot be empty');
    return { content: Buffer.from(inner.subarray(0, index)), contentType: type, padding: inner.length - index - 1 };
  } finally { key.fill(0); iv.fill(0); nonce.fill(0); chunk?.fill(0); tail?.fill(0); inner?.fill(0); }
}

/** Explicit post-record increment. Returned secret is a copy; caller owns and
 * retires superseded state. At uint64 exhaustion fail instead of wrapping.
 * A returned sequence at MAX_RECORDS_PER_KEY is exhausted for seal/open.
 */
export function advanceSequence(direction) {
  state(direction);
  if (direction.sequence === MAX_SEQUENCE) fail('sequence_exhausted', 'Record sequence would wrap');
  return { trafficSecret: Buffer.from(direction.trafficSecret), epoch: direction.epoch, sequence: direction.sequence + 1n };
}

/** Derive next application traffic secret ("traffic upd"), increment metadata
 * epoch and reset sequence. This does NOT send/receive a KeyUpdate message.
 * Caller must first seal/open KeyUpdate using the OLD secret and sequence, then
 * install this state in that one direction. It must not retain usable old keys.
 */
export function updateTrafficState(direction) {
  state(direction);
  if (direction.epoch === MAX_EPOCH) fail('epoch_exhausted', 'Traffic epoch would wrap');
  return { trafficSecret: hkdfExpandLabel(direction.trafficSecret, 'traffic upd', Buffer.alloc(0), 32), epoch: direction.epoch + 1n, sequence: 0n };
}

/** Encode only the complete RFC 8446 §4.6.3 KeyUpdate handshake message.
 * Seal this content with contentType=22, under the old sending keys.
 */
export function encodeKeyUpdate(requestUpdate = false) {
  if (typeof requestUpdate !== 'boolean') fail('invalid_key_update', 'KeyUpdate request flag must be boolean');
  return Buffer.from([24, 0, 0, 1, Number(requestUpdate)]);
}

/** Parse exactly one complete, unfragmented KeyUpdate message. No other
 * post-handshake message, fragmentation, request-response policy or state
 * transition is implemented here.
 */
export function parseKeyUpdate(content) {
  bytes(content, 5, 'KeyUpdate message');
  if (content[0] !== 24 || content[1] !== 0 || content[2] !== 0 || content[3] !== 1 || ![0, 1].includes(content[4])) fail('invalid_key_update', 'Expected one complete KeyUpdate message');
  return { requestUpdate: Boolean(content[4]) };
}
