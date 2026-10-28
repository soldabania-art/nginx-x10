import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { assessJournalQuery, journalQuerySpec, observeOwnedJournal,
  JOURNAL_MAX_BYTES, JOURNAL_MAX_RECORDS, JOURNAL_MAX_ATTEMPTS, JOURNAL_RESULT_CODES } from './journal-check.mjs';

const known = { uid: 1001, unitName: 'x10-lifecycle-' + 'a'.repeat(32) + '.service', invocationId: 'b'.repeat(32) };
const marker = '  "outcome": "running",';
const row = (overrides = {}) => ({ MESSAGE: marker, _UID: String(known.uid),
  _SYSTEMD_USER_UNIT: known.unitName, _SYSTEMD_INVOCATION_ID: known.invocationId,
  __CURSOR: 'private-synthetic-cursor', __REALTIME_TIMESTAMP: '123456',
  __MONOTONIC_TIMESTAMP: '3456', _BOOT_ID: 'c'.repeat(32), ...overrides });
const record = stdout => ({ exitCode: 0, signal: null, stdout, stderr: '', timedOut: false, outputLimitExceeded: false });
const query = (...rows) => record(rows.map(value => JSON.stringify(value)).join('\n') + '\n');
const assess = (...rows) => assessJournalQuery(query(...rows), known);
function refused(result, code) {
  assert.equal(result.ok, false); assert.equal(result.code, code);
  assert.equal(result.recordsObserved, 0); assert.equal(result.runningMarkers, 0);
  assert.equal(result.journalReadabilityObserved, false);
  assert.equal(result.serviceAccepted, false); assert.equal(result.productionAccepted, false);
}

test('finite frozen refusal classifications exclude success and private error data', () => {
  assert.equal(Object.isFrozen(JOURNAL_RESULT_CODES), true);
  assert.equal(new Set(JOURNAL_RESULT_CODES).size, JOURNAL_RESULT_CODES.length);
  assert.equal(JOURNAL_RESULT_CODES.length, 11);
  assert(JOURNAL_RESULT_CODES.every(code => /^journal_[a-z_]+$/.test(code)));
  assert(!JOURNAL_RESULT_CODES.includes('owned_journal_observed'));
  assert.throws(() => JOURNAL_RESULT_CODES.push('private error'), TypeError);
});

test('only exact attributable running output yields finite readability counts', () => {
  const value = assess(row({ MESSAGE: '{' }), row(), row({ MESSAGE: '}' }));
  assert.deepEqual(value, { ok: true, code: 'owned_journal_observed', queryAttempts: 1,
    recordsObserved: 3, runningMarkers: 1, journalReadabilityObserved: true,
    scope: 'owned-user-unit-journal-readability', serviceAccepted: false, productionAccepted: false });
  const serialized = JSON.stringify(value);
  for (const secret of [known.unitName, known.invocationId, '1001', marker, 'private-synthetic-cursor', '123456'])
    assert(!serialized.includes(secret));
});
test('query specification uses fixed executable, bounds, no inherited environment and three AND attributes', () => {
  const spec = journalQuerySpec(known);
  assert.equal(spec.file, '/usr/bin/journalctl');
  assert.deepEqual(spec.args, ['--no-pager', '--quiet', '--output=json',
    '--output-fields=MESSAGE,_UID,_SYSTEMD_USER_UNIT,_SYSTEMD_INVOCATION_ID', '--lines=129',
    '_UID=1001', `_SYSTEMD_USER_UNIT=${known.unitName}`, `_SYSTEMD_INVOCATION_ID=${known.invocationId}`]);
  assert.equal(spec.options.timeout, 2500); assert.equal(spec.options.maxBuffer, 262144);
  assert.equal(spec.options.cwd, '/'); assert.equal(spec.options.killSignal, 'SIGKILL');
  assert.deepEqual(spec.options.env, { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', XDG_RUNTIME_DIR: '/run/user/1001' });
  assert(!spec.args.some(arg => /--user-unit|--user$|--follow|--directory|--file|--machine|^\+$/.test(arg)));
});
for (const [name, patch] of [['root UID', { uid: 0 }], ['negative UID', { uid: -1 }],
  ['large UID', { uid: 4294967295 }], ['fraction UID', { uid: 1.5 }], ['string UID', { uid: '1001' }],
  ['unit glob', { unitName: 'x10-lifecycle-*.service' }], ['foreign unit', { unitName: 'foreign.service' }],
  ['unit argument', { unitName: known.unitName + ' --all' }], ['zero invocation', { invocationId: '0'.repeat(32) }],
  ['upper invocation', { invocationId: 'B'.repeat(32) }], ['extra field', { extra: true }]]) {
  test(`invalid context ${name} grants no query specification`, () => {
    assert.throws(() => journalQuerySpec({ ...known, ...patch }), { code: 'journal_invalid' });
    refused(assessJournalQuery(query(row()), { ...known, ...patch }), 'journal_invalid');
  });
}
test('context accessors refuse without invocation', () => {
  let calls = 0; const value = { ...known };
  Object.defineProperty(value, 'invocationId', { enumerable: true, get() { calls++; return known.invocationId; } });
  refused(assessJournalQuery(query(row()), value), 'journal_invalid'); assert.equal(calls, 0);
});
for (const field of ['_UID', '_SYSTEMD_USER_UNIT', '_SYSTEMD_INVOCATION_ID']) {
  test(`foreign ${field} cannot contribute any accepted record`, () => {
    refused(assess(row(), row({ [field]: 'foreign-private-value' })), 'journal_identity_mismatch');
  });
}
for (const [name, value] of [['array', ['duplicate']], ['binary', [1, 2, 3]], ['null', null], ['object', {}], ['number', 123]]) {
  test(`ambiguous ${name} MESSAGE refuses`, () => refused(assess(row({ MESSAGE: value })), 'journal_response_invalid'));
}
test('missing attribution, unknown fields and control-bearing messages refuse', () => {
  for (const field of ['_UID', '_SYSTEMD_USER_UNIT', '_SYSTEMD_INVOCATION_ID', 'MESSAGE']) {
    const value = row(); delete value[field]; refused(assess(value), 'journal_response_invalid');
  }
  refused(assess(row({ PRIVATE_DATA: 'should not be accepted' })), 'journal_response_invalid');
  for (const message of [marker + '\n', '\u0000', '\u001b[31m', '\t' + marker])
    refused(assess(row({ MESSAGE: message })), 'journal_response_invalid');
});
test('JSON duplicate or escaped key spelling cannot hide overwritten attribution', () => {
  const encoded = JSON.stringify(row());
  const duplicates = [encoded.replace('{', '{"_UID":"1001",'),
    encoded.replace('{', '{"_SYSTEMD_INVOCATION_ID":"foreign",'),
    encoded.replace('{', '{"\\u005fUID":"foreign",'),
    encoded.replace('"_UID":', '"\\u005fUID":')];
  for (const text of duplicates) refused(assessJournalQuery(record(text + '\n'), known), 'journal_response_invalid');
});
test('empty or missing exact marker remains unknown rather than readiness', () => {
  refused(assessJournalQuery(record(''), known), 'journal_empty');
  for (const message of ['running', '"outcome":"running"', '"outcome": "not_running",', marker + ' extra', '"outcome": "native_starting",'])
    refused(assess(row({ MESSAGE: message })), 'journal_running_marker_missing');
});
test('malformed framing and non-ASCII JSON refuse rather than truncated acceptance', () => {
  const good = JSON.stringify(row());
  for (const text of [good, good + '\n\n', good + '\r\n', '[1]\n', '{}\n', 'invalid\n', good.replace('running', 'runníng') + '\n'])
    refused(assessJournalQuery(record(text), known), 'journal_response_invalid');
});
test('byte limit and record sentinel refuse before counting or publishing output', () => {
  refused(assessJournalQuery(record('x'.repeat(JOURNAL_MAX_BYTES + 1)), known), 'journal_output_limit');
  const accepted = assess(...Array.from({ length: JOURNAL_MAX_RECORDS }, () => row()));
  assert.equal(accepted.ok, true); assert.equal(accepted.recordsObserved, 128);
  refused(assess(...Array.from({ length: JOURNAL_MAX_RECORDS + 1 }, () => row())), 'journal_record_limit');
  refused(assess(row({ MESSAGE: 'x'.repeat(4097) })), 'journal_response_invalid');
});
test('query timeout, output overflow, signal, failure or stderr never yields readability', () => {
  const good = query(row());
  for (const [patch, code] of [[{ timedOut: true }, 'journal_query_timeout'],
    [{ outputLimitExceeded: true }, 'journal_output_limit'], [{ signal: 'SIGTERM' }, 'journal_unavailable'],
    [{ exitCode: 1 }, 'journal_unavailable'], [{ stderr: 'private stderr' }, 'journal_response_invalid'],
    [{ timedOut: null }, 'journal_invalid'], [{ stdout: null }, 'journal_invalid']])
    refused(assessJournalQuery({ ...good, ...patch }, known), code);
});

// Exercise the real bounded retry wrapper with inert dependency stubs. This
// executes no local journal command and grants no manager authority.
const source = await readFile(new URL('./journal-check.mjs', import.meta.url), 'utf8');
const wrapper = source.slice(source.indexOf('export async function observeOwnedJournal(value) {')).replace('export ', '');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
function wrapperFixture(results) {
  let calls = 0, pauses = 0;
  const deps = { context: value => value, journalQuerySpec: value => value, localTool: async () => {},
    query: async () => { const result = results[Math.min(calls++, results.length - 1)]; if (result instanceof Error) throw result; return result; },
    assessJournalQuery, JOURNAL_MAX_ATTEMPTS,
    outcome: (ok, code, attempts) => ({ ok, code, queryAttempts: attempts }),
    setTimeout: (fn, ms) => { assert.equal(ms, 100); pauses++; fn(); } };
  const observe = new AsyncFunction(...Object.keys(deps), wrapper + '\nreturn observeOwnedJournal;')(...Object.values(deps));
  return { observe: async () => (await observe)(known), counts: () => ({ calls, pauses }) };
}
test('asynchronous journal visibility permits bounded missing-only observations', async () => {
  const f = wrapperFixture([record(''), query(row({ MESSAGE: '{' })), query(row())]);
  const value = await f.observe(); assert.equal(value.ok, true); assert.equal(value.queryAttempts, 3);
  assert.deepEqual(f.counts(), { calls: 3, pauses: 2 });
});
test('missing journal marker stops at three attempts without readability', async () => {
  const f = wrapperFixture([record('')]); const result = await f.observe();
  assert.equal(result.ok, false); assert.equal(result.code, 'journal_empty'); assert.equal(result.queryAttempts, 3);
  assert.deepEqual(f.counts(), { calls: 3, pauses: 2 });
});
for (const [name, r] of [['foreign', query(row({ _UID: '1002' }))], ['malformed', record('bad\n')],
  ['timeout', { ...query(row()), timedOut: true }], ['query throw', new Error('private fixture failure')]]) {
  test(`wrapper does not retry ${name}`, async () => {
    const f = wrapperFixture([r]); const result = await f.observe(); assert.equal(result.ok, false);
    assert.deepEqual(f.counts(), { calls: 1, pauses: 0 });
    assert(!JSON.stringify(result).includes('private fixture'));
  });
}
test('actual wrapper refuses a mismatched local UID before reading any journal', async () => {
  if (typeof process.getuid !== 'function') return;
  const value = await observeOwnedJournal({ ...known, uid: process.getuid() === 1001 ? 1002 : 1001 });
  refused({ ...value, queryAttempts: 1 }, 'journal_local_prerequisites_unavailable');
  assert.equal(value.queryAttempts, 0);
});

// Official systemd v255 logs-show.c::output_json inserts these two fields
// unconditionally, although that version's manual lists only four metadata
// fields. The unchanged four-field parser refuses this valid transcript.
const sequenceMetadata = { __SEQNUM: '17', __SEQNUM_ID: 'd'.repeat(32) };
test('public v255 six-field metadata and the old four-field format yield the same finite observation', () => {
  const oldFormat = assess(row()), publicV255 = assess(row(sequenceMetadata));
  assert.equal(oldFormat.ok, true); assert.deepEqual(publicV255, oldFormat);
  const serialized = JSON.stringify(publicV255);
  for (const privateValue of Object.values(sequenceMetadata)) assert(!serialized.includes(privateValue));
});
for (const field of ['__SEQNUM', '__SEQNUM_ID']) {
  test(`sequence metadata ${field} remains optional and string-only`, () => {
    assert.equal(assess(row({ [field]: sequenceMetadata[field] })).ok, true);
    for (const value of [null, [sequenceMetadata[field]], [1, 2], 17, {}, true])
      refused(assess(row({ ...sequenceMetadata, [field]: value })), 'journal_response_invalid');
    for (const value of ['x'.repeat(4097), 'private\nmetadata', '\u0000'])
      refused(assess(row({ ...sequenceMetadata, [field]: value })), 'journal_response_invalid');
  });
  test(`duplicate or noncanonical escaped ${field} is not tolerated`, () => {
    const text = JSON.stringify(row(sequenceMetadata));
    const duplicate = text.replace('{', `{${JSON.stringify(field)}:"private-duplicate",`);
    const escaped = text.replace(JSON.stringify(field) + ':', '"\\u005f' + field.slice(1) + '":');
    refused(assessJournalQuery(record(duplicate + '\n'), known), 'journal_response_invalid');
    refused(assessJournalQuery(record(escaped + '\n'), known), 'journal_response_invalid');
  });
}
for (const field of ['_UID', '_SYSTEMD_USER_UNIT', '_SYSTEMD_INVOCATION_ID']) {
  test(`standard sequence metadata cannot excuse foreign ${field}`, () => {
    refused(assess(row({ ...sequenceMetadata, [field]: 'foreign-private-value' })), 'journal_identity_mismatch');
    const missing = row(sequenceMetadata); delete missing[field];
    refused(assess(missing), 'journal_response_invalid');
  });
}
test('sequence metadata neither broadens unknown fields nor supplies a running marker', () => {
  refused(assess(row({ ...sequenceMetadata, __UNRELATED: 'private-unknown' })), 'journal_response_invalid');
  refused(assess(row({ ...sequenceMetadata, MESSAGE: 'not a running marker' })), 'journal_running_marker_missing');
  const missing = row(sequenceMetadata); delete missing.MESSAGE;
  refused(assess(missing), 'journal_response_invalid');
});
