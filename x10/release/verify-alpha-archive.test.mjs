import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyAlphaArchive, verifyAlphaArchiveFile, PAYLOAD_NAMES, MAX_ARCHIVE_BYTES, MAX_TAR_BYTES } from './verify-alpha-archive.mjs';
const hash = b => createHash('sha256').update(b).digest('hex');
const ROOT = 'nginx-x10-alpha/';
function header(name, data, mode, type = '0', magic = 'ustar\0' + '00') {
  const h = Buffer.alloc(512), oct = (n, at, len) => h.write(n.toString(8).padStart(len - 1, '0') + '\0', at);
  h.write(name); oct(mode, 100, 8); oct(0, 108, 8); oct(0, 116, 8); oct(data.length, 124, 12); oct(0, 136, 12);
  h.fill(32, 148, 156); h.write(type, 156); h.write(magic, 257);
  const sum = h.reduce((a, b) => a + b, 0); h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}
function fixture({ edit, extra = [], omit = [], magic } = {}) {
  const payloads = Object.fromEntries(PAYLOAD_NAMES.map(n => [n, Buffer.from(`synthetic ${n}\n`)]));
  const value = { schemaVersion: 1, kind: 'nginx-x10-linux-alpha-bundle', platform: { system: 'Linux', machine: 'x86_64' },
    files: Object.fromEntries(PAYLOAD_NAMES.map(n => [n, { bytes: payloads[n].length, sha256: hash(payloads[n]), mode: n === 'bin/nginx' ? '0500' : '0400' }])),
    provenance: { checkoutRevision: 'a'.repeat(40), upstreamRevision: 'b'.repeat(40), sourceDiffSha256: 'c'.repeat(64) }, nativeVersionOutputSha256: 'd'.repeat(64) };
  if (edit) edit(value, payloads);
  const manifest = Buffer.from(JSON.stringify({ ...value, sha256: hash(JSON.stringify(value)) }));
  const entries = [
    ...['', 'bin/', 'x10/', 'x10/alpha/', 'x10/control/'].map(n => ({ n: ROOT + n, data: Buffer.alloc(0), mode: 0o700, type: '5' })),
    { n: ROOT + 'bundle.json', data: manifest, mode: 0o600 },
    ...PAYLOAD_NAMES.map(n => ({ n: ROOT + n, data: payloads[n], mode: n === 'bin/nginx' ? 0o500 : 0o400 })), ...extra,
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
