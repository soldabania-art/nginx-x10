// Bounded observer for the C1 fixture, not a TLS endpoint or state adapter.
// RFC 8446 §§4.1–4.4, 4.6.3, 5–7; ALPN encoding: RFC 7301 §3.1.
// https://www.rfc-editor.org/rfc/rfc8446.html
// https://www.rfc-editor.org/rfc/rfc7301.html
// The real Node TLS endpoint validates PKI, hostname and Finished MAC. This
// observer authenticates captured records and their structural boundaries; it
// does not independently verify certificate signatures or Finished transcripts.
import { openRecord, advanceSequence, updateTrafficState, parseKeyUpdate } from './record.mjs';

export const MAX_CAPTURE_BYTES = 512 * 1024;
export const MAX_CAPTURE_CHUNKS = 8192;
export const MAX_CAPTURE_RECORDS = 256;
export const MAX_HANDSHAKE_BYTES = 256 * 1024;
export const MAX_APPLICATION_BYTES = 65536;
const ALPN = Buffer.from('continuum-c1');
const HRR_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex');

export class HandshakeOracleError extends Error {
  constructor(code) { super('TLS capture rejected'); this.name = 'HandshakeOracleError'; this.code = code; }
}
const reject = code => { throw new HandshakeOracleError(code); };
function exact(value, keys, optional = []) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) reject('oracle_input');
  const names = Reflect.ownKeys(value);
  if (keys.some(k => !names.includes(k)) || names.some(k => !keys.includes(k) && !optional.includes(k))) reject('oracle_input');
  for (const k of names) { const d = Object.getOwnPropertyDescriptor(value, k); if (!d.enumerable || !('value' in d)) reject('oracle_input'); }
}
function bytes(value, maximum, minimum = 0) {
  if (!Buffer.isBuffer(value) || value.length < minimum || value.length > maximum) reject('oracle_input');
  return value;
}
function capture(value) {
  const parts = Buffer.isBuffer(value) ? [value] : value;
  if (!Array.isArray(parts) || !parts.length || parts.length > MAX_CAPTURE_CHUNKS) reject('oracle_budget');
  let size = 0;
  for (const part of parts) { bytes(part, MAX_CAPTURE_BYTES); size += part.length; if (size > MAX_CAPTURE_BYTES) reject('oracle_budget'); }
  if (!size) reject('oracle_record');
  return Buffer.concat(parts, size);
}
// Assembly deliberately uses its own outer framing, not recordLength().
function records(wire) {
  const result = [];
  let at = 0;
  while (at < wire.length) {
    if (wire.length - at < 5) reject('oracle_truncated');
    const type = wire[at], version = wire.readUInt16BE(at + 1), length = wire.readUInt16BE(at + 3);
    if (![20, 22, 23].includes(type) || ![0x0301, 0x0303].includes(version)) reject('oracle_record');
    if (length === 0 || length > (type === 23 ? 16401 : 16384)) reject('oracle_record');
    if (type === 23 && (version !== 0x0303 || length < 17)) reject('oracle_record');
    if (wire.length - at < 5 + length) reject('oracle_truncated');
    result.push({ type, version, wire: wire.subarray(at, at + 5 + length), body: wire.subarray(at + 5, at + 5 + length) });
    if (result.length > MAX_CAPTURE_RECORDS) reject('oracle_budget');
    at += 5 + length;
  }
  return result;
}
function cursor(buffer) {
  let at = 0;
  const take = length => { if (!Number.isSafeInteger(length) || length < 0 || length > buffer.length - at) reject('oracle_profile'); const value = buffer.subarray(at, at + length); at += length; return value; };
  const u8 = () => take(1)[0], u16 = () => take(2).readUInt16BE();
  return { take, u8, u16, vec8: () => take(u8()), vec16: () => take(u16()), end: () => { if (at !== buffer.length) reject('oracle_profile'); } };
}
function extensions(encoded) {
  const c = cursor(encoded), values = new Map();
  while (values.size < 64) {
    // Empty input is a valid empty extension vector.
    if (encoded.length === 0) return values;
    const type = c.u16(), value = c.vec16();
    if (values.has(type)) reject('oracle_profile');
    values.set(type, value);
    const consumed = [...values.values()].reduce((n, b) => n + 4 + b.length, 0);
    if (consumed === encoded.length) { c.end(); return values; }
  }
  reject('oracle_budget');
}
function alpn(value, selected) {
  if (!value) reject('oracle_profile');
  const c = cursor(value), list = c.vec16(); c.end();
  const p = cursor(list), names = [];
  let consumed = 0;
  while (consumed < list.length) { const name = p.vec8(); if (!name.length) reject('oracle_profile'); names.push(name); consumed += 1 + name.length; }
  p.end();
  if (!names.some(n => n.equals(ALPN)) || (selected && names.length !== 1)) reject('oracle_profile');
}
function helloBody(all, client) {
  let at = 0, assembled = Buffer.alloc(0), length = null;
  try {
    while (at < all.length && all[at].type === 22) {
      const r = all[at++];
      if (!client && r.version !== 0x0303) reject('oracle_profile');
      if (assembled.length + r.body.length > 65536) reject('oracle_budget');
      const next = Buffer.concat([assembled, r.body]); assembled.fill(0); assembled = next;
      if (assembled.length >= 4) {
        length = 4 + assembled.readUIntBE(1, 3);
        if (length > 65536 || assembled[0] !== (client ? 1 : 2)) reject('oracle_profile');
        if (assembled.length >= length) break;
      }
    }
    if (length === null || assembled.length !== length) reject('oracle_profile');
    return { body: Buffer.from(assembled.subarray(4)), records: at };
  } finally { assembled.fill(0); }
}
function clientHello(body, clientRandom) {
  const c = cursor(body);
  if (c.u16() !== 0x0303 || !c.take(32).equals(clientRandom)) reject('oracle_profile');
  const sessionId = c.vec8(); if (sessionId.length > 32) reject('oracle_profile');
  const suites = c.vec16(), compression = c.vec8(), ext = extensions(c.vec16()); c.end();
  if (!suites.length || suites.length % 2 || !compression.equals(Buffer.from([0])) || ext.has(41) || ext.has(42)) reject('oracle_profile');
  let found = false; for (let i = 0; i < suites.length; i += 2) if (suites.readUInt16BE(i) === 0x1301) found = true;
  const versions = ext.get(43); if (!versions || versions.length < 3 || versions[0] !== versions.length - 1 || versions[0] % 2) reject('oracle_profile');
  let tls13 = false; for (let i = 1; i < versions.length; i += 2) if (versions.readUInt16BE(i) === 0x0304) tls13 = true;
  if (!found || !tls13) reject('oracle_profile'); alpn(ext.get(16), false);
  return sessionId;
}
function serverHello(body, sessionId) {
  const c = cursor(body);
  if (c.u16() !== 0x0303 || c.take(32).equals(HRR_RANDOM) || !c.vec8().equals(sessionId)
    || c.u16() !== 0x1301 || c.u8() !== 0) reject('oracle_profile');
  const ext = extensions(c.vec16()); c.end();
  if (!ext.get(43)?.equals(Buffer.from([3, 4])) || ext.has(41) || ext.has(42)) reject('oracle_profile');
}
function encryptedExtensions(body) {
  const c = cursor(body), ext = extensions(c.vec16()); c.end();
  if (ext.has(42)) reject('oracle_profile');
  alpn(ext.get(16), true);
}
function authenticated(state, wire) {
  try { return openRecord(state, wire); }
  catch { reject('oracle_authentication'); }
}
function direction(all, helloRecords, handshakeSecret, applicationSecret, expected, client, expectedUpdates, ownedStates) {
  let at = helloRecords, ccs = 0, handshakeRecords = 0, messages = 0, pending = Buffer.alloc(0);
  let hs = { trafficSecret: Buffer.from(handshakeSecret), epoch: 0n, sequence: 0n }; ownedStates.push(hs);
  const order = client ? [20] : [8, 11, 15, 20];
  try {
    while (messages < order.length) {
      const r = all[at++]; if (!r) reject('oracle_handshake');
      if (r.type === 20) {
        if (++ccs > 1 || r.version !== 0x0303 || !r.body.equals(Buffer.from([1]))) reject('oracle_profile');
        continue;
      }
      if (r.type !== 23) reject('oracle_handshake');
      const opened = authenticated(hs, r.wire);
      try {
        if (opened.contentType !== 22 || !opened.content.length || pending.length + opened.content.length > MAX_HANDSHAKE_BYTES) reject('oracle_handshake');
        const next = Buffer.concat([pending, opened.content]); pending.fill(0); pending = next;
      } finally { opened.content.fill(0); }
      hs = advanceSequence(hs); ownedStates.push(hs); handshakeRecords++;
      while (pending.length >= 4) {
        const size = pending.readUIntBE(1, 3), type = pending[0];
        if (size > MAX_HANDSHAKE_BYTES || type !== order[messages]) reject('oracle_handshake');
        if (pending.length < 4 + size) break;
        const body = pending.subarray(4, 4 + size);
        if ((type === 20 && size !== 32) || (type !== 20 && size === 0)) reject('oracle_handshake');
        if (type === 8) encryptedExtensions(body);
        const rest = Buffer.from(pending.subarray(4 + size)); pending.fill(0); pending = rest; messages++;
        if (messages === order.length && pending.length) reject('oracle_handshake');
      }
    }
    const preApplicationRecords = at;
    let app = { trafficSecret: Buffer.from(applicationSecret), epoch: 0n, sequence: 0n }; ownedStates.push(app);
    let applicationBytes = 0, applicationRecords = 0, keyUpdates = 0, closed = false;
    for (; at < all.length; at++) {
      if (closed) reject('oracle_trailing');
      const r = all[at]; if (r.type !== 23) reject('oracle_record');
      const opened = authenticated(app, r.wire);
      try {
        app = advanceSequence(app); ownedStates.push(app);
        if (opened.contentType === 23) {
          if (!opened.content.length || applicationBytes + opened.content.length > expected.length
            || !opened.content.equals(expected.subarray(applicationBytes, applicationBytes + opened.content.length))) reject('oracle_application');
          applicationBytes += opened.content.length; applicationRecords++;
        } else if (opened.contentType === 22) {
          let update; try { update = parseKeyUpdate(opened.content); } catch { reject('oracle_key_update'); }
          if (client || update.requestUpdate || ++keyUpdates > expectedUpdates) reject('oracle_key_update');
          app = updateTrafficState(app); ownedStates.push(app);
        } else if (opened.contentType === 21) {
          if (!opened.content.equals(Buffer.from([1, 0])) || applicationBytes !== expected.length || !applicationRecords) reject('oracle_close_notify');
          closed = true;
        } else reject('oracle_record');
      } finally { opened.content.fill(0); }
    }
    if (!closed) reject('oracle_close_notify');
    if (keyUpdates !== expectedUpdates) reject('oracle_key_update');
    return { captureRecords: all.length, preApplicationRecords, helloRecords, compatibilityCCSRecords: ccs,
      encryptedHandshakeRecords: handshakeRecords, applicationRecords, applicationBytes, keyUpdates, closeNotify: true, trailingBytes: 0 };
  } finally { pending.fill(0); }
}

/** All inputs are private caller-owned memory; result contains counts only.
 * `negotiated` must come from the one authorized TLS socket, not a server banner.
 * Four keylog labels must share clientRandom; we bind it to the captured Hello.
 * The no-tickets/no-client-auth profile is explicit. No resynchronization/search
 * past any failed encrypted record is attempted, including the first app record.
 */
export function verifyHandshakeCapture(input) {
  const owned = [], wires = [], hellos = [];
  try {
    exact(input, ['clientToServer', 'serverToClient', 'clientRandom', 'secrets', 'expected', 'negotiated', 'clientFin', 'serverFin'], ['expectedServerKeyUpdates']);
    exact(input.secrets, ['clientHandshake', 'serverHandshake', 'clientApplication', 'serverApplication']);
    for (const secret of Object.values(input.secrets)) bytes(secret, 32, 32);
    bytes(input.clientRandom, 32, 32);
    exact(input.expected, ['clientApplication', 'serverApplication']);
    bytes(input.expected.clientApplication, MAX_APPLICATION_BYTES, 1); bytes(input.expected.serverApplication, MAX_APPLICATION_BYTES, 1);
    exact(input.negotiated, ['protocol', 'cipher', 'alpn', 'authorized']);
    const n = input.negotiated;
    if (n.protocol !== 'TLSv1.3' || n.cipher !== 'TLS_AES_128_GCM_SHA256' || n.alpn !== 'continuum-c1' || n.authorized !== true) reject('oracle_profile');
    if (input.clientFin !== true || input.serverFin !== true) reject('oracle_terminal');
    const updates = input.expectedServerKeyUpdates ?? 0;
    if (updates !== 0 && updates !== 1) reject('oracle_input');
    const cw = capture(input.clientToServer); wires.push(cw);
    const sw = capture(input.serverToClient); wires.push(sw);
    const cr = records(cw), sr = records(sw), ch = helloBody(cr, true); hellos.push(ch.body);
    const sh = helloBody(sr, false); hellos.push(sh.body);
    const sid = clientHello(ch.body, input.clientRandom); serverHello(sh.body, sid);
    const client = direction(cr, ch.records, input.secrets.clientHandshake, input.secrets.clientApplication, input.expected.clientApplication, true, 0, owned);
    const server = direction(sr, sh.records, input.secrets.serverHandshake, input.secrets.serverApplication, input.expected.serverApplication, false, updates, owned);
    return { schemaVersion: 1, recordKind: 'tls13-handshake-wire-oracle', passed: true,
      protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', alpn: 'continuum-c1',
      endpointAuthorizationObserved: true, authenticatedHandshakeBoundary: true,
      independentFinishedMacVerification: false, fullHandshakeVerifier: false,
      directions: { client, server }, capturedStreamComplete: true,
      stateExportImport: false, migration: false, nativeNginxIntegration: false };
  } catch (error) {
    if (error instanceof HandshakeOracleError) throw error;
    reject('oracle_internal');
  } finally {
    for (const state of owned) state.trafficSecret.fill(0);
    for (const buffer of [...wires, ...hellos]) buffer.fill(0);
  }
}
