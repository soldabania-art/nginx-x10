import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyAlphaArchive, verifyAlphaArchiveFile, PAYLOAD_NAMES, PAYLOAD_NAMES_V1, PAYLOAD_NAMES_V2, MAX_ARCHIVE_BYTES, MAX_TAR_BYTES } from './verify-alpha-archive.mjs';
const hash = b => createHash('sha256').update(b).digest('hex');
const ROOT = 'nginx-x10-alpha/';
function header(name, data, mode, type = '0', magic = 'ustar\0' + '00') {
  const h = Buffer.alloc(512), oct = (n, at, len) => h.write(n.toString(8).padStart(len - 1, '0') + '\0', at);
  h.write(name); oct(mode, 100, 8); oct(0, 108, 8); oct(0, 116, 8); oct(data.length, 124, 12); oct(0, 136, 12);
  h.fill(32, 148, 156); h.write(type, 156); h.write(magic, 257);
  const sum = h.reduce((a, b) => a + b, 0); h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}
function fixture({ edit, extra = [], omit = [], magic, version = 1, inventoryVersion = version } = {}) {
  const names = inventoryVersion === 2 ? PAYLOAD_NAMES_V2 : PAYLOAD_NAMES_V1;
  const directories = ['', 'bin/', 'x10/', 'x10/alpha/', 'x10/control/', ...(inventoryVersion === 2 ? ['x10/service/'] : [])];
  const payloads = Object.fromEntries(names.map(n => [n, Buffer.from(`synthetic ${n}\n`)]));
  const value = { schemaVersion: version, kind: 'nginx-x10-linux-alpha-bundle', platform: { system: 'Linux', machine: 'x86_64' },
    files: Object.fromEntries(names.map(n => [n, { bytes: payloads[n].length, sha256: hash(payloads[n]), mode: n === 'bin/nginx' ? '0500' : '0400' }])),
    provenance: { checkoutRevision: 'a'.repeat(40), upstreamRevision: 'b'.repeat(40), sourceDiffSha256: 'c'.repeat(64) }, nativeVersionOutputSha256: 'd'.repeat(64) };
  if (edit) edit(value, payloads);
  const manifest = Buffer.from(JSON.stringify({ ...value, sha256: hash(JSON.stringify(value)) }));
  const entries = [
    ...directories.map(n => ({ n: ROOT + n, data: Buffer.alloc(0), mode: 0o700, type: '5' })),
    { n: ROOT + 'bundle.json', data: manifest, mode: 0o600 },
    ...names.map(n => ({ n: ROOT + n, data: payloads[n], mode: n === 'bin/nginx' ? 0o500 : 0o400 })), ...extra,
  ].filter(x => !omit.includes(x.n));
  return Buffer.concat([...entries.map(x => header(x.n, x.data, x.mode, x.type, magic)), Buffer.alloc(1024)]);
}
const verify = tar => { const gz = gzipSync(tar); return verifyAlphaArchive(gz, hash(gz)); };
test('accepts complete synthetic POSIX inventory without extracting or executing', () => {
  const r = verify(fixture()); assert.equal(r.valid, true); assert.equal(r.payloadFiles, 13); assert.equal(r.directories, 5); assert.equal(r.sourceCommit, 'a'.repeat(40));
});
test('accepts GNU short-header inventory', () => assert.equal(verify(fixture({ magic: 'ustar  \0' })).valid, true));
test('checksum mismatch refuses corrupt gzip before decompression', () => assert.deepEqual(verifyAlphaArchive(Buffer.from('invalid gzip'), '0'.repeat(64)), { valid: false, code: 'archive_checksum' }));
test('invalid matching gzip is a fixed format refusal', () => { const b = Buffer.from('invalid gzip'); assert.equal(verifyAlphaArchive(b, hash(b)).code, 'archive_invalid'); });
test('rejects compressed input and gzip expansion bounds', () => {
  assert.equal(verifyAlphaArchive(Buffer.alloc(MAX_ARCHIVE_BYTES + 1), '0'.repeat(64)).code, 'archive_input');
  const b = gzipSync(Buffer.alloc(MAX_TAR_BYTES + 512)); assert.equal(verifyAlphaArchive(b, hash(b)).code, 'archive_invalid');
});
test('requires exact lowercase checksum and buffer input', () => {
  for (const v of [null, 'a'.repeat(63), 'A'.repeat(64), 42]) assert.equal(verifyAlphaArchive(Buffer.from('a'), v).code, 'archive_input');
  assert.equal(verifyAlphaArchive('a', 'a'.repeat(64)).valid, false);
});
test('rejects altered header checksum and nonoctal numeric fields', () => {
  const t = fixture(); t[10] ^= 1; assert.equal(verify(t).valid, false);
  const q = fixture(); q[100] = 128; assert.equal(verify(q).valid, false);
});
test('rejects duplicate, unknown, absolute and traversal entries', () => {
  for (const n of [ROOT + 'LICENSE', ROOT + 'unknown', '/outside', ROOT + '../outside'])
    assert.equal(verify(fixture({ extra: [{ n, data: Buffer.from('x'), mode: 0o400 }] })).valid, false);
});
test('rejects symlink hardlink special and extended tar records', () => {
  for (const type of ['1', '2', '3', '4', '6', 'x', 'g', 'L', 'K', 'S'])
    assert.equal(verify(fixture({ omit: [ROOT + 'LICENSE'], extra: [{ n: ROOT + 'LICENSE', data: Buffer.alloc(0), mode: 0o400, type }] })).valid, false);
});
test('rejects missing files/directories and unsafe mode', () => {
  for (const n of [ROOT, ROOT + 'bundle.json', ROOT + 'bin/nginx']) assert.equal(verify(fixture({ omit: [n] })).valid, false);
  assert.equal(verify(fixture({ omit: [ROOT + 'LICENSE'], extra: [{ n: ROOT + 'LICENSE', data: Buffer.from('x'), mode: 0o640 }] })).valid, false);
});
test('rejects payload digest and mode disagreement', () => {
  assert.equal(verify(fixture({ edit: v => { v.files.LICENSE.sha256 = '0'.repeat(64); } })).valid, false);
  assert.equal(verify(fixture({ edit: v => { v.files.LICENSE.mode = '0600'; } })).valid, false);
});
test('rejects manifest inventory and source-identity disagreement', () => {
  assert.equal(verify(fixture({ edit: v => { delete v.files.LICENSE; } })).valid, false);
  assert.equal(verify(fixture({ edit: v => { v.provenance.checkoutRevision = '/private/host/path'; } })).valid, false);
});
test('rejects missing terminator truncated data and nonzero trailing data', () => {
  const t = fixture(); assert.equal(verify(t.subarray(0, t.length - 1024)).valid, false);
  assert.equal(verify(t.subarray(0, t.length - 1)).valid, false);
  assert.equal(verify(Buffer.concat([t, Buffer.from([1]), Buffer.alloc(511)])).valid, false);
});
test('rejects changed manifest self-hash even when tar/gzip checksums are current', () => {
  const t = fixture(), marker = Buffer.from('"sha256":"'); // First payload digest in manifest.
  const i = t.indexOf(marker); t[i + marker.length] = t[i + marker.length] === 97 ? 98 : 97;
  assert.equal(verify(t).valid, false);
});
test('file reader and CLI reject symlinks directory missing inputs and invocation aliases run', () => {
  const d = mkdtempSync(path.join(tmpdir(), 'x10-archive-test-'));
  try {
    const gz = gzipSync(fixture()), archive = path.join(d, 'a.tar.gz'); writeFileSync(archive, gz);
    assert.equal(verifyAlphaArchiveFile(archive, hash(gz)).valid, true);
    symlinkSync(archive, path.join(d, 'link'));
    for (const p of [path.join(d, 'link'), d, path.join(d, 'missing')]) assert.equal(verifyAlphaArchiveFile(p, hash(gz)).code, 'archive_input');
    const cli = fileURLToPath(new URL('./verify-alpha-archive.mjs', import.meta.url));
    symlinkSync(cli, path.join(d, 'alias.mjs'));
    const r = spawnSync(process.execPath, [path.join(d, 'alias.mjs'), '--archive', archive, '--sha256', hash(gz)], { encoding: 'utf8', timeout: 5000 });
    assert.equal(r.status, 0); assert.equal(r.stderr, ''); const result = JSON.parse(r.stdout); assert.equal(result.valid, true);
    assert.equal(result.extracted, false); assert.equal(result.payloadExecuted, false); assert.equal(result.evidenceAuthenticated, false); assert.equal(result.productionAccepted, false);
    const bad = spawnSync(process.execPath, [cli, '--archive', path.join(d, 'do-not-print'), '--sha256', 'invalid'], { encoding: 'utf8', timeout: 5000 });
    assert.equal(bad.status, 1); assert.equal(bad.stderr, ''); assert.equal(bad.stdout.includes(d), false);
  } finally { rmSync(d, { recursive: true, force: true }); }
});


const recipe = 'x10/service/user-unit.mjs', recipeDirectory = ROOT + 'x10/service/';
test('legacy payload export remains the exact frozen schema1 set', () => {
  assert.equal(PAYLOAD_NAMES, PAYLOAD_NAMES_V1); assert.equal(PAYLOAD_NAMES_V1.length, 13); assert.equal(PAYLOAD_NAMES_V2.length, 14);
  assert(Object.isFrozen(PAYLOAD_NAMES_V1)); assert(Object.isFrozen(PAYLOAD_NAMES_V2));
  assert.deepEqual(PAYLOAD_NAMES_V2.filter(n => !PAYLOAD_NAMES_V1.includes(n)), [recipe]);
  assert.deepEqual(PAYLOAD_NAMES_V1.filter(n => !PAYLOAD_NAMES_V2.includes(n)), []);
});
for (const version of [1, 2]) for (const magic of ['ustar\0' + '00', 'ustar  \0'])
  test('accepts exact schema' + version + ' short-header profile ' + JSON.stringify(magic), () => {
    const result = verify(fixture({ version, magic }));
    assert.equal(result.valid, true); assert.equal(result.schemaVersion, version);
    assert.equal(result.payloadFiles, version === 1 ? 13 : 14); assert.equal(result.directories, version === 1 ? 5 : 6);
    assert.equal(result.sourceCommit, 'a'.repeat(40));
  });
for (const version of [0, 3, -1, 1.5, '1', '2', null, true])
  test('rejects unsupported or type-confused schema ' + JSON.stringify(version), () => {
    assert.deepEqual(verify(fixture({ version, inventoryVersion: 2 })), { valid: false, code: 'archive_invalid' });
  });
test('requires an explicit schema version and exact kind even with consistent checksums', () => {
  for (const edit of [v => { delete v.schemaVersion; }, v => { v.kind = 'nginx-x10-linux-alpha-installed'; }, v => { delete v.kind; }])
    assert.equal(verify(fixture({ version: 2, edit })).valid, false);
});
for (const [version, inventoryVersion] of [[1, 2], [2, 1]])
  test('refuses declared schema' + version + ' with complete schema' + inventoryVersion + ' inventory', () => {
    assert.equal(verify(fixture({ version, inventoryVersion })).valid, false);
  });
test('schema1 refuses optional helper or service directory rather than silently upgrading', () => {
  for (const extra of [
    [{ n: recipeDirectory, data: Buffer.alloc(0), mode: 0o700, type: '5' }],
    [{ n: ROOT + recipe, data: Buffer.from('helper'), mode: 0o400 }],
    [{ n: recipeDirectory, data: Buffer.alloc(0), mode: 0o700, type: '5' }, { n: ROOT + recipe, data: Buffer.from('helper'), mode: 0o400 }],
  ]) assert.equal(verify(fixture({ extra })).valid, false);
});
for (const omitted of [ROOT + recipe, recipeDirectory, ROOT + 'x10/alpha/README.md', ROOT + 'bundle.json'])
  test('schema2 refuses missing required entry ' + omitted, () => assert.equal(verify(fixture({ version: 2, omit: [omitted] })).valid, false));
test('schema2 manifest and physical payload must select the same exact profile', () => {
  for (const edit of [v => { delete v.files[recipe]; }, v => { v.files.extra = v.files[recipe]; },
    v => { v.files[recipe].mode = '0500'; }, v => { v.files[recipe].bytes++; },
    v => { v.files[recipe].sha256 = '0'.repeat(64); }])
    assert.equal(verify(fixture({ version: 2, edit })).valid, false);
});
for (const mode of [0o500, 0o600, 0o640, 0o444, 0o777, 0o4400])
  test('schema2 helper rejects unsafe or unexpected mode ' + mode.toString(8), () => {
    assert.equal(verify(fixture({ version: 2, omit: [ROOT + recipe], extra: [{ n: ROOT + recipe, data: Buffer.from('helper'), mode }] })).valid, false);
  });
for (const type of ['1', '2', '3', '4', '5', '6', 'x', 'g', 'L', 'K', 'S'])
  test('schema2 helper rejects link special or extended record type ' + type, () => {
    assert.equal(verify(fixture({ version: 2, omit: [ROOT + recipe], extra: [{ n: ROOT + recipe, data: Buffer.alloc(0), mode: 0o400, type }] })).valid, false);
  });
test('schema2 service directory must be unique empty mode0700 directory', () => {
  for (const extra of [
    { n: recipeDirectory, data: Buffer.alloc(0), mode: 0o755, type: '5' },
    { n: recipeDirectory, data: Buffer.from('data'), mode: 0o700, type: '5' },
    { n: recipeDirectory, data: Buffer.alloc(0), mode: 0o700, type: '0' },
    { n: ROOT + 'x10/service/nested/', data: Buffer.alloc(0), mode: 0o700, type: '5' },
  ]) assert.equal(verify(fixture({ version: 2, omit: [recipeDirectory], extra: [extra] })).valid, false);
  assert.equal(verify(fixture({ version: 2, extra: [{ n: recipeDirectory, data: Buffer.alloc(0), mode: 0o700, type: '5' }] })).valid, false);
});
test('schema2 rejects duplicate helper, unknown sibling, traversal and absolute entries', () => {
  for (const n of [ROOT + recipe, ROOT + 'x10/service/other.mjs', ROOT + 'x10/service/../outside', '/x10/service/user-unit.mjs'])
    assert.equal(verify(fixture({ version: 2, extra: [{ n, data: Buffer.from('x'), mode: 0o400 }] })).valid, false);
});
test('schema2 verifier and CLI stay pre-extraction consistency checks', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'x10-archive-v2-test-'));
  try {
    const gz = gzipSync(fixture({ version: 2 })), archive = path.join(directory, 'v2.tar.gz'); writeFileSync(archive, gz);
    assert.equal(verifyAlphaArchiveFile(archive, hash(gz)).schemaVersion, 2);
    const cli = fileURLToPath(new URL('./verify-alpha-archive.mjs', import.meta.url));
    const r = spawnSync(process.execPath, [cli, '--archive', archive, '--sha256', hash(gz)], { encoding: 'utf8', timeout: 5000 });
    assert.equal(r.status, 0); assert.equal(r.stderr, ''); const result = JSON.parse(r.stdout);
    assert.equal(result.valid, true); assert.equal(result.schemaVersion, 2); assert.equal(result.payloadFiles, 14); assert.equal(result.directories, 6);
    for (const k of ['evidenceAuthenticated', 'payloadExecuted', 'extracted', 'productionAccepted']) assert.equal(result[k], false);
    assert.equal(r.stdout.includes(directory), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
