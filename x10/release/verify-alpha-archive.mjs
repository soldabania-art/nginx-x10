#!/usr/bin/env node
// Narrow pre-extraction format/integrity check. Never extracts or executes payloads.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { constants, openSync, closeSync, fstatSync, readSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
export const MAX_TAR_BYTES = 64 * 1024 * 1024;
export const PAYLOAD_NAMES = Object.freeze([
  'bin/nginx', 'install.mjs', 'LICENSE', 'NOTICE', 'x10/alpha/README.md',
  ...['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'].map(n => `x10/alpha/${n}`),
  ...['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'].map(n => `x10/control/${n}`),
].sort());
const ROOT = 'nginx-x10-alpha/';
const DIRS = new Set(['', 'bin/', 'x10/', 'x10/alpha/', 'x10/control/'].map(n => ROOT + n));
const HEX = /^[a-f0-9]{64}$/, REV = /^[a-f0-9]{40}$/;
const digest = b => createHash('sha256').update(b).digest('hex');
const reject = () => { throw new Error('archive_invalid'); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameNames = (a, b) => a.length === b.length && a.slice().sort().every((n, i) => n === b.slice().sort()[i]);
function field(b) {
  const end = b.indexOf(0), data = end < 0 ? b : b.subarray(0, end);
  if (end >= 0 && b.subarray(end).some(n => n !== 0)) reject();
  if (data.some(n => n < 32 || n > 126)) reject();
  return data.toString('ascii');
}
function octal(b) {
  const value = b.toString('ascii');
  if (b.some(n => n > 127) || !/^[ 0]*[0-7]+[\0 ]*$/.test(value)) reject();
  const n = Number.parseInt(value.replace(/[\0 ]+$/g, '').trim(), 8);
  if (!Number.isSafeInteger(n) || n < 0) reject();
  return n;
}
function parseTar(tar) {
  if (tar.length < 1024 || tar.length > MAX_TAR_BYTES || tar.length % 512) reject();
  let offset = 0, terminated = false; const entries = new Map();
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512); offset += 512;
    if (h.every(n => n === 0)) {
      if (tar.length - offset < 512 || tar.subarray(offset).some(n => n !== 0)) reject();
      terminated = true; break;
    }
    if (entries.size >= PAYLOAD_NAMES.length + DIRS.size + 1) reject();
    const checksum = octal(h.subarray(148, 156)); let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
    if (sum !== checksum) reject();
    const magic = h.subarray(257, 265);
    if (!magic.equals(Buffer.from('ustar\0' + '00')) && !magic.equals(Buffer.from('ustar  \0'))) reject();
    // Fixed short inventory needs neither USTAR prefix nor GNU extensions.
    if (h.subarray(345, 500).some(n => n !== 0) || h.subarray(157, 257).some(n => n !== 0)) reject();
    const name = field(h.subarray(0, 100)), size = octal(h.subarray(124, 136)), mode = octal(h.subarray(100, 108));
    octal(h.subarray(108, 116)); octal(h.subarray(116, 124)); octal(h.subarray(136, 148));
    const type = h[156];
    if (entries.has(name) || size > MAX_TAR_BYTES || offset + Math.ceil(size / 512) * 512 > tar.length) reject();
    const directory = type === 53;
    if (directory) { if (!DIRS.has(name) || size !== 0 || mode !== 0o700) reject(); }
    else {
      if ((type !== 48 && type !== 0) || !name.startsWith(ROOT)) reject();
      const relative = name.slice(ROOT.length);
      if (relative !== 'bundle.json' && !PAYLOAD_NAMES.includes(relative)) reject();
      if (mode !== (relative === 'bin/nginx' ? 0o500 : relative === 'bundle.json' ? 0o600 : 0o400)) reject();
      if (relative === 'bundle.json' && (size === 0 || size > 256 * 1024)) reject();
    }
    const data = tar.subarray(offset, offset + size), padding = tar.subarray(offset + size, offset + Math.ceil(size / 512) * 512);
    if (padding.some(n => n !== 0)) reject();
    entries.set(name, { data, mode, directory }); offset += Math.ceil(size / 512) * 512;
  }
  const expected = [...DIRS, ROOT + 'bundle.json', ...PAYLOAD_NAMES.map(n => ROOT + n)];
  if (!terminated || !sameNames([...entries.keys()], expected)) reject();
  return entries;
}

export function verifyAlphaArchive(bytes, trustedSha256) {
  const failure = code => ({ valid: false, code });
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_ARCHIVE_BYTES || typeof trustedSha256 !== 'string' || !HEX.test(trustedSha256)) return failure('archive_input');
  // This ordering is intentional: never decompress bytes with a mismatching digest.
  if (digest(bytes) !== trustedSha256) return failure('archive_checksum');
  try {
    const tar = gunzipSync(bytes, { maxOutputLength: MAX_TAR_BYTES });
    const entries = parseTar(tar), manifestBytes = entries.get(ROOT + 'bundle.json').data;
    const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
    if (!plain(manifest)) reject();
    const { sha256, ...value } = manifest;
    if (!HEX.test(sha256 || '') || digest(JSON.stringify(value)) !== sha256 || value.schemaVersion !== 1
      || value.kind !== 'nginx-x10-linux-alpha-bundle' || !plain(value.files)
      || !sameNames(Object.keys(value.files), PAYLOAD_NAMES)
      || value.platform?.system !== 'Linux' || !['x86_64', 'aarch64'].includes(value.platform?.machine)
      || !HEX.test(value.nativeVersionOutputSha256 || '')) reject();
    for (const name of PAYLOAD_NAMES) {
      const f = value.files[name], actual = entries.get(ROOT + name);
      if (!plain(f) || !sameNames(Object.keys(f), ['sha256', 'bytes', 'mode']) || !HEX.test(f.sha256 || '')
        || !Number.isSafeInteger(f.bytes) || f.bytes !== actual.data.length || f.sha256 !== digest(actual.data)
        || f.mode !== actual.mode.toString(8).padStart(4, '0')) reject();
    }
    const p = value.provenance;
    if (!plain(p) || !REV.test(p.checkoutRevision || '') || !REV.test(p.upstreamRevision || '') || !HEX.test(p.sourceDiffSha256 || '')) reject();
    return { valid: true, code: 'archive_consistent', archiveSha256: trustedSha256, archiveBytes: bytes.length,
      tarBytes: tar.length, payloadFiles: PAYLOAD_NAMES.length, directories: DIRS.size,
      bundleManifestSha256: digest(manifestBytes), binarySha256: value.files['bin/nginx'].sha256,
      sourceCommit: p.checkoutRevision, upstreamCommit: p.upstreamRevision, sourceDiffSha256: p.sourceDiffSha256,
      machine: value.platform.machine };
  } catch { return failure('archive_invalid'); }
}

export function verifyAlphaArchiveFile(file, trustedSha256) {
  let fd;
  try {
    if (typeof file !== 'string' || typeof trustedSha256 !== 'string' || !HEX.test(trustedSha256)) return { valid: false, code: 'archive_input' };
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_ARCHIVE_BYTES) return { valid: false, code: 'archive_input' };
    const bytes = Buffer.alloc(stat.size + 1); let used = 0, count;
    while (used < bytes.length && (count = readSync(fd, bytes, used, bytes.length - used, null)) > 0) used += count;
    const after = fstatSync(fd);
    if (used !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) return { valid: false, code: 'archive_input' };
    return verifyAlphaArchive(bytes.subarray(0, used), trustedSha256);
  } catch { return { valid: false, code: 'archive_input' }; }
  finally { if (fd !== undefined) closeSync(fd); }
}
export function main(argv = process.argv.slice(2)) {
  if (argv.length !== 4 || argv[0] !== '--archive' || argv[2] !== '--sha256' || !HEX.test(argv[3])) return { valid: false, code: 'archive_usage' };
  return verifyAlphaArchiveFile(argv[1], argv[3]);
}
let cli = false;
try { cli = Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { /* Import has no CLI authority. */ }
if (cli) {
  const result = main();
  process.stdout.write(JSON.stringify({ ...result, scope: 'pre-extraction-consistency-only', evidenceAuthenticated: false,
    payloadExecuted: false, extracted: false, productionAccepted: false }) + '\n');
  process.exitCode = result.valid ? 0 : 1;
}
