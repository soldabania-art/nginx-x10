// Metadata-only preparation for an inventory review. This is not a capsule
// exporter, TLS-state verifier, ownership grant or runtime budget enforcer.
// Inputs must originate from the caller's trusted, verified C2a fixture. Matching
// caller-supplied identities is an equality check, not execution attestation.
import { types } from 'node:util';

const CAP = 16777216n;
const PIN = '85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c';
const IDENTITY = ['sourceCommit', 'probeSha256', 'fixtureBinarySha256'];
const NUMERIC = ['sample', 'sslPending', 'packetLength', 'rbufLeft', 'rbufOffset',
  'rbufLength', 'unreadRecordBytes', 'unreadControlBytes', 'wbufLeft',
  'wbufOffset', 'wbufLength', 'wnum', 'staleWpendTot', 'staleWpendRet',
  'readRecordSlots', 'writeBufferSlots', 'rstate', 'rwstate', 'flowState',
  'handshakeState', 'inInit', 'inHandshake', 'encReadState', 'encWriteState',
  'keyUpdate', 'alertDispatch', 'shutdown', 'handshakeFragmentLength', 'initNum',
  'ledgerLastCall', 'ledgerRetryCall', 'ledgerLastOutcome'];
const TEXT = ['event', 'scenario', 'reasons', 'readGeneration', 'writeGeneration',
  'mutationSerial', 'readNextSequence', 'writeNextSequence', 'ledgerCallSerial'];
const BOOLEAN = ['allowed', 'monitorKnown', 'sslHasPending'];
const BUDGET = ['applicationRecords', 'handoverRecords', 'closureRecords'];
const ZERO = ['sslPending', 'packetLength', 'rbufLeft', 'unreadRecordBytes',
  'unreadControlBytes', 'wbufLeft', 'wnum', 'inInit', 'inHandshake',
  'encReadState', 'encWriteState', 'alertDispatch', 'shutdown',
  'handshakeFragmentLength', 'initNum', 'ledgerRetryCall'];

class Refusal extends Error {
  constructor(code) { super(code); this.code = code; }
}
const requireValue = (condition, code) => { if (!condition) throw new Refusal(code); };

// Reject proxies before reflection and inspect descriptors without invoking
// getters. This validates inert metadata, not executable objects or a sandbox.
function record(input, keys, code) {
  requireValue(input !== null && typeof input === 'object' && !types.isProxy(input), code);
  const prototype = Object.getPrototypeOf(input);
  requireValue(prototype === Object.prototype || prototype === null, code);
  const own = Reflect.ownKeys(input);
  requireValue(own.length === keys.length && own.every(key => typeof key === 'string'
    && keys.includes(key)), code);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    requireValue(descriptor !== undefined && Object.hasOwn(descriptor, 'value')
      && descriptor.enumerable === true, code);
    copy[key] = descriptor.value;
  }
  return copy;
}

function identity(input) {
  const value = record(input, IDENTITY, 'identity_schema');
  requireValue(value.sourceCommit === PIN, 'source_pin');
  for (const key of ['probeSha256', 'fixtureBinarySha256']) {
    requireValue(typeof value[key] === 'string' && /^[0-9a-f]{64}$/.test(value[key]),
      'identity_schema');
  }
  return value;
}

function decimal(value, maximum, positive, code) {
  requireValue(typeof value === 'string' && value.length <= 20
    && /^(0|[1-9][0-9]*)$/.test(value), code);
  const number = BigInt(value);
  requireValue(number <= maximum && (!positive || number > 0n), code);
  return number;
}

function probe(input) {
  const value = record(input, [...NUMERIC, ...TEXT, ...BOOLEAN], 'probe_schema');
  for (const key of NUMERIC) {
    requireValue(typeof value[key] === 'number' && Number.isSafeInteger(value[key])
      && !Object.is(value[key], -0) && value[key] <= 262144
      && value[key] >= (key === 'keyUpdate' ? -1 : 0), 'probe_schema');
  }
  for (const key of BOOLEAN) requireValue(typeof value[key] === 'boolean', 'probe_schema');
  for (const key of TEXT) requireValue(typeof value[key] === 'string'
    && value[key].length <= 64, 'probe_schema');
  requireValue(value.event === 'probe' && value.scenario === 'quiescent'
    && value.sample > 0, 'unsupported_profile');
  requireValue(value.allowed && value.reasons === '0' && value.monitorKnown,
    'probe_refused');
  requireValue(value.readGeneration === '0' && value.writeGeneration === '0'
    && value.mutationSerial === '2', 'unsupported_generation');
  requireValue(!value.sslHasPending && ZERO.every(key => value[key] === 0)
    && value.rstate === 240 && value.rwstate === 1 && value.flowState === 4
    && value.handshakeState === 1 && value.keyUpdate === -1
    && [2, 3].includes(value.ledgerLastCall) && value.ledgerLastOutcome === 1,
    'nonquiescent_metadata');
  requireValue(value.rbufOffset <= value.rbufLength
    && value.wbufOffset <= value.wbufLength && value.readRecordSlots <= 1
    && value.writeBufferSlots <= 1, 'probe_bounds');
  decimal(value.ledgerCallSerial, (1n << 64n) - 1n, true, 'ledger_serial');
  for (const key of ['readNextSequence', 'writeNextSequence']) {
    requireValue(/^[0-9a-f]{16}$/.test(value[key]), 'sequence_schema');
    requireValue(BigInt('0x' + value[key]) < CAP, 'sequence_usage');
  }
  return value;
}

function direction(nextHex, input) {
  const value = record(input, BUDGET, 'budget_schema');
  const next = BigInt('0x' + nextHex);
  const application = decimal(value.applicationRecords, CAP, false, 'budget_schema');
  const handover = decimal(value.handoverRecords, CAP, false, 'budget_schema');
  const closure = decimal(value.closureRecords, CAP, true, 'budget_schema');
  const available = CAP - next;
  // Subtract each obligation, so exhausted/maximal input never wraps or uses
  // imprecise Number arithmetic. Every protected record must be accounted for
  // by a future runtime; this calculation alone cannot enforce that contract.
  requireValue(application <= available, 'record_budget_exhausted');
  const afterApplication = available - application;
  requireValue(handover <= afterApplication, 'record_budget_exhausted');
  const afterHandover = afterApplication - handover;
  requireValue(closure <= afterHandover, 'record_budget_exhausted');
  return Object.freeze({ nextSequence: next.toString(), availableRecords: available.toString(),
    plannedRecords: (application + handover + closure).toString(),
    remainingRecords: (afterHandover - closure).toString() });
}

function result(code, budget) {
  const output = { schemaVersion: 1, eligibleForInventoryReview: code === 'metadata_budget_review_only',
    code, semanticExportImport: false, migration: false };
  if (budget !== undefined) output.recordBudget = budget;
  return Object.freeze(output);
}

/** Validate public metadata and a proposed directional record plan only.
 * Never pass secrets or a complete SSL object. A successful result is not a
 * safepoint, approved state inventory, executable capsule or permission for I/O.
 * The expected identity must come from the caller's separately verified build;
 * copying an untrusted request identity into that argument proves nothing. */
export function checkCapsulePreflight(request, expectedSourceIdentity) {
  try {
    const value = record(request, ['schemaVersion', 'sourceIdentity', 'probe', 'budget'], 'request_schema');
    requireValue(value.schemaVersion === 1, 'request_schema');
    const expected = identity(expectedSourceIdentity);
    const actual = identity(value.sourceIdentity);
    requireValue(IDENTITY.every(key => actual[key] === expected[key]), 'identity_mismatch');
    const snapshot = probe(value.probe);
    const budget = record(value.budget, ['read', 'write'], 'budget_schema');
    return result('metadata_budget_review_only', Object.freeze({ capRecords: CAP.toString(),
      read: direction(snapshot.readNextSequence, budget.read),
      write: direction(snapshot.writeNextSequence, budget.write) }));
  } catch (error) {
    return result(error instanceof Refusal ? error.code : 'invalid_input');
  }
}
