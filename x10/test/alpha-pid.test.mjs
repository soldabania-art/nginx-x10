import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

// Only the pure parser is source-extracted. Importing alpha.test.mjs here would
// start its physical native fixtures. No process is signalled by these controls.
const source = await readFile(new URL('./alpha.test.mjs', import.meta.url), 'utf8');
const start = source.indexOf('function nativePidReport('), end = source.indexOf('\n}', start) + 2;
assert(start >= 0 && end > start, 'One pure native PID parser is required');
const parserSource = source.slice(start, end);
const nativePidReport = new Function(`return (${parserSource});`)();
const execute = promisify(execFile), root = fileURLToPath(new URL('../../', import.meta.url));

// A fake signal recorder demonstrates the old arithmetic result only; it has
// neither process.kill nor any other real signalling capability.
test('baseline partial numeric PID field can retain a synthetic negative-one target', async () => {
  const baseline = (await execute('git', ['show', '1c257bd85c27e905ddc8d7d2725a7ebc579b81d7:x10/test/alpha.test.mjs'], { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 })).stdout;
  const first = baseline.indexOf('const m = /"(?:pid|candidatePid)": (\\d+)/.exec(runOutput);');
  assert(first >= 0, 'The exact dated baseline callback expression must exist');
  const expression = baseline.slice(first + 'const m = '.length, baseline.indexOf(';', first));
  const capture = new Function('runOutput', `return ${expression};`);
  const partial = '{\n  "candidatePid": 1', complete = `${partial}23,\n`;
  const oldGroups = new Set([Number(capture(partial)[1]), Number(capture(complete)[1])]);
  const syntheticTargets = [...oldGroups].map(pid => -pid);
  assert.deepEqual(syntheticTargets, [-1, -123]);
  assert.equal(nativePidReport(partial), null);
  assert.equal(nativePidReport(complete), 123);
});

for (const [name, text, expected] of [
  ['complete candidate', '  "candidatePid": 123,\n', 123],
  ['complete running PID', '  "pid": 456,\n', 456],
  ['minimum supported PID', '  "candidatePid": 2,\n', 2],
  ['maximum signed-positive PID', '  "candidatePid": 2147483647,\n', 2147483647],
  ['complete field without comma', '  "pid": 42\n', 42],
  ['CRLF field', '  "candidatePid": 43,\r\n', 43],
  ['empty output', '', null],
  ['zero', '  "candidatePid": 0,\n', null],
  ['one', '  "candidatePid": 1,\n', null],
  ['negative one', '  "candidatePid": -1,\n', null],
  ['negative other', '  "pid": -123,\n', null],
  ['positive sign', '  "pid": +123,\n', null],
  ['leading zero', '  "pid": 0123,\n', null],
  ['decimal', '  "pid": 123.0,\n', null],
  ['exponent', '  "pid": 1e3,\n', null],
  ['quoted digits', '  "pid": "123",\n', null],
  ['null', '  "pid": null,\n', null],
  ['missing field newline', '  "candidatePid": 123,', null],
  ['partial first digit', '  "candidatePid": 1', null],
  ['partial later digits', '  "candidatePid": 123', null],
  ['partial CRLF', '  "candidatePid": 123,\r', null],
  ['nonfinite text', '  "pid": Infinity,\n', null],
  ['outside signed-positive bound', '  "pid": 2147483648,\n', null],
  ['outside safe integer', '  "pid": 9007199254740993,\n', null],
  ['very long integer', `  "pid": ${'9'.repeat(512)},\n`, null],
  ['unrelated field', '  "session": 123,\n', null],
  ['field-like message prefix', 'diagnostic: "pid": 123,\n', null],
  ['escaped key within a JSON message', '  "message": "\\\"pid\\\": 123,\\n",\n', null],
  ['null input', null, null],
  ['undefined input', undefined, null],
  ['numeric input', 123, null],
]) test(`native PID field parser: ${name}`, () => {
  assert.equal(nativePidReport(text), expected);
});

test('candidate-only parser ignores a running PID field', () => {
  assert.equal(nativePidReport('  "pid": 456,\n', true), null);
  assert.equal(nativePidReport('  "pid": 456,\n  "candidatePid": 789,\n', true), 789);
  assert.equal(nativePidReport('  "candidatePid": 789,\n', true), 789);
});

test('every partial split waits for the complete numeric field terminator', () => {
  const field = '  "candidatePid": 123456,\r\n';
  for (let index = 0; index < field.length; index++) assert.equal(nativePidReport(field.slice(0, index)), null, `Partial prefix ${index}`);
  assert.equal(nativePidReport(field), 123456);
});

test('synthetic incremental output never registers an incomplete or dangerous PID', () => {
  let output = ''; const groups = new Set();
  for (const chunk of ['{\n  "candidatePid": 1', '23', ',', '\n', '  "outcome": "running"\n}\n']) {
    output += chunk; const pid = nativePidReport(output); if (pid !== null) groups.add(pid);
  }
  assert.deepEqual([...groups], [123]);
  assert.equal(groups.has(1), false); assert.equal(groups.has(0), false);
});


test('nonboolean candidate-only modes refuse instead of coercing authority', () => {
  for (const mode of [null, 0, 1, 'true', {}, []]) assert.equal(nativePidReport('  "candidatePid": 123,\n', mode), null);
});

test('an invalid completed first field is not silently replaced by a later PID', () => {
  assert.equal(nativePidReport('  "candidatePid": 1,\n  "pid": 123,\n'), null);
  assert.equal(nativePidReport('  "candidatePid": 2147483648,\n  "candidatePid": 123,\n', true), null);
});
