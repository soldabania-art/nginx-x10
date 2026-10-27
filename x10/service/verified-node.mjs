#!/usr/bin/env node
// Authenticated dependency preparation only; never a service acceptance gate.
import { constants } from 'node:fs';
import { open, lstat, realpath, mkdir, mkdtemp, readdir, unlink, rmdir } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkManagedOperatorReturnReport } from './operator-package-return-proof.mjs';
import { checkManagedOperatorFallbackReport, MAX_MANAGED_OPERATOR_FALLBACK_REPORT_BYTES } from './operator-package-fallback-proof.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PIN = Object.freeze({ version: 'v22.23.3', root: 'node-v22.23.3-linux-x64',
  filename: 'node-v22.23.3-linux-x64.tar.xz',
  sha256: 'df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de',
  fingerprint: '5BE8A3F6C8A5C01D106C0AD820B1A390B168D356' });
// The coordinator freezes these literals together with the producers and workflow.
// These are source consistency pins, not signatures or acceptance authority.
export const MANAGED_PACKAGE_CLEANUP_SOURCE = Object.freeze({
  checkerSha256: '215d03aaf6e427331458a7c244de055c8aa10b5b99a2497570323123a4867e83',
  proofSha256: 'baf6b3dc08ecf79311e95c57a8e16042c93f0f6852e173149bf78df67a2a87de',
});
export const FALLBACK_PACKAGE_CLEANUP_SOURCE = Object.freeze({
  checkerSha256: 'a4cccc20636a1f4f5bf29eb0977d979fcf0da1f931b94d35eae80407094e26e3',
  proofSha256: '6f9291b947f4d5d70d9ccfc79944820e1ef45253cb87388a1d508d5b7bcc2ecb',
});
const MAX_ARCHIVE = 64 * 1024 ** 2, MAX_TAR = 512 * 1024 ** 2;
const MAX_NODE = 256 * 1024 ** 2, MAX_LICENSE = 2 * 1024 ** 2;
const sha = b => createHash('sha256').update(b).digest('hex');
const hex = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
function refuse(code = 'verified_node_refused') { throw Object.assign(new Error(code), { code }); }
function absolute(p) {
  if (typeof p !== 'string' || !/^\/[A-Za-z0-9_./+-]+$/.test(p) || p.length > 1024
      || path.normalize(p) !== p || p === '/' || p.endsWith('/')) refuse();
  return p;
}
function identity(s) { return { uid: s.uid, dev: s.dev, ino: s.ino }; }
function same(a, b) { return a.uid === b.uid && a.dev === b.dev && a.ino === b.ino; }
async function regular(file, max, { uid, mode } = {}) {
  if (await realpath(file) !== file) refuse();
  const f = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.size < 1 || s.size > max || s.nlink !== 1
        || (uid !== undefined && s.uid !== uid) || (mode !== undefined && (s.mode & 0o7777) !== mode)) refuse();
    const b = Buffer.alloc(s.size + 1); let n = 0;
    while (n < b.length) { const r = await f.read(b, n, b.length - n, null); if (!r.bytesRead) break; n += r.bytesRead; }
    const after = await f.stat();
    if (n !== s.size || after.size !== s.size || after.ctimeMs !== s.ctimeMs || after.mtimeMs !== s.mtimeMs) refuse();
    return { bytes: b.subarray(0, n), stat: s };
  } finally { await f.close(); }
}
async function directory(p, mode = 0o700) {
  if (await realpath(p) !== p) refuse();
  const s = await lstat(p);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== mode) refuse();
  return s;
}
async function writeNew(p, bytes, mode, register = null) {
  const f = await open(p, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { if (register) register(identity(await f.stat())); await f.writeFile(bytes); await f.sync(); } finally { await f.close(); }
}
async function tool(p) {
  const { stat } = await regular(p, 8 * 1024 ** 2);
  if (stat.uid !== 0 || (stat.mode & 0o7022) !== 0 || !(stat.mode & 0o100)) refuse('verifier_tool_refused');
}
async function command(exe, args, cwd, limit = 64 * 1024, timeout = 15000, signal = null) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(Object.assign(new Error('cancelled'), { code: 'bootstrap_cancelled' })); return; }
    let child, count = 0, fault = false; const out = [], err = [];
    const fail = () => { fault = true; child?.kill('SIGKILL'); };
    try { child = spawn(exe, args, { cwd, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', HOME: cwd }, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(Object.assign(new Error('tool'), { code: 'verifier_tool_refused' })); return; }
    const timer = setTimeout(fail, timeout);
    signal?.addEventListener('abort', fail, { once: true });
    child.once('error', fail);
    for (const [stream, chunks] of [[child.stdout, out], [child.stderr, err]]) stream.on('data', b => {
      count += b.length; if (count > limit) fail(); else chunks.push(b);
    });
    child.once('close', (code, terminationSignal) => {
      clearTimeout(timer); signal?.removeEventListener('abort', fail);
      if (signal?.aborted) reject(Object.assign(new Error('cancelled'), { code: 'bootstrap_cancelled' }));
      else if (fault || code !== 0 || terminationSignal) reject(Object.assign(new Error('tool'), { code: 'verifier_command_refused' }));
      else resolve({ stdout: Buffer.concat(out), stderr: Buffer.concat(err) });
    });
  });
}
export function parseSignatureStatus(text) {
  if (typeof text !== 'string' || text.length > 32768) refuse('signature_refused');
  const lines = text.trim().split('\n'); let valid = 0;
  const allowed = new Set(['PLAINTEXT', 'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG']);
  for (const line of lines) {
    const m = /^\[GNUPG:\] ([A-Z_]+)(?: (.*))?$/.exec(line);
    if (!m || !allowed.has(m[1])) refuse('signature_refused');
    if (m[1] === 'GOODSIG' && !(m[2] || '').startsWith(PIN.fingerprint.slice(-16) + ' ')) refuse('signature_refused');
    if (m[1] === 'KEY_CONSIDERED' && m[2] !== PIN.fingerprint + ' 0') refuse('signature_refused');
    if (m[1] === 'PLAINTEXT' && !/^74 0 ?$/.test(m[2] || '')) refuse('signature_refused');
    if (m[1] === 'VALIDSIG') {
      const v = (m[2] || '').split(' ');
      // GnuPG status format: signer, dates/times, version/reserved, pubkey,
      // hash, class, optional primary key. Freeze this exact SHA256 release.
      if (v.length < 9 || v.length > 10 || (v[9] || v[0]) !== PIN.fingerprint || v[0] !== PIN.fingerprint
          || v[1] !== '2026-09-23' || v[2] !== '1790183910' || v[3] !== '0'
          || v[4] !== '4' || v[5] !== '0' || v[6] !== '22' || v[7] !== '8' || v[8] !== '01') refuse('signature_refused');
      valid++;
    }
  }
  if (lines.filter(l => l === '[GNUPG:] NEWSIG').length !== 1 || lines.filter(l => l.startsWith('[GNUPG:] SIG_ID ')).length !== 1 || lines.filter(l => l.startsWith('[GNUPG:] PLAINTEXT ')).length !== 1) refuse('signature_refused');
  if (valid !== 1 || lines.filter(l => l.startsWith('[GNUPG:] GOODSIG ')).length !== 1) refuse('signature_refused');
  return true;
}
export function parseChecksumText(text) {
  if (typeof text !== 'string' || text.length > 16384 || /[^\x09\x0a\x0d\x20-\x7e]/.test(text)) refuse('checksum_refused');
  let found = 0;
  for (const line of text.split('\n')) {
    if (!line) continue;
    const m = /^([a-f0-9]{64})  ([A-Za-z0-9_.+/-]+)\r?$/.exec(line);
    if (!m || m[2].startsWith('/') || m[2].split('/').some(p => !p || p === '.' || p === '..')) refuse('checksum_refused');
    if (m[2] === PIN.filename) { if (m[1] !== PIN.sha256) refuse('checksum_refused'); found++; }
  }
  if (found !== 1) refuse('checksum_refused');
  return PIN.sha256;
}
function tarString(b) {
  const end = b.indexOf(0); const x = end < 0 ? b : b.subarray(0, end);
  if (end >= 0 && b.subarray(end).some(v => v !== 0)) refuse('tar_refused');
  if (x.some(v => v < 32 || v > 126)) refuse('tar_refused');
  return x.toString('ascii');
}
function octal(b) {
  const raw = b.toString('ascii');
  if (!/^[ 0-7]+(?:\0[ \0]*)?$/.test(raw)) refuse('tar_refused');
  const s = raw.replace(/\0.*$/, '').trim();
  if (!/^[0-7]+$/.test(s)) refuse('tar_refused');
  const n = parseInt(s, 8); if (!Number.isSafeInteger(n)) refuse('tar_refused'); return n;
}
function tarName(n) {
  if (!n || n.startsWith('/') || n.includes('\\') || n.split('/').some(p => p === '..' || p === '.')) refuse('tar_refused');
  if (!n.startsWith(`${PIN.root}/`) && n !== PIN.root) refuse('tar_refused');
  return n.replace(/\/$/, '');
}
export function parseTar(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_TAR || bytes.length % 512 !== 0) refuse('tar_refused');
  let offset = 0, entries = 0, zeros = 0, longName = null, longLink = null; const selected = {};
  while (offset + 512 <= bytes.length) {
    const h = bytes.subarray(offset, offset + 512); offset += 512;
    if (h.every(v => v === 0)) { zeros++; if (zeros >= 2) { if (bytes.subarray(offset).some(v => v !== 0)) refuse('tar_refused'); break; } continue; }
    if (zeros || ++entries > 100000) refuse('tar_refused');
    let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
    if (octal(h.subarray(148, 156)) !== sum) refuse('tar_refused');
    const magic = tarString(h.subarray(257, 263)); if (!['ustar', 'ustar '].includes(magic)) refuse('tar_refused');
    const size = octal(h.subarray(124, 136)), mode = octal(h.subarray(100, 108));
    const end = offset + size, padded = offset + Math.ceil(size / 512) * 512;
    if (end > bytes.length || padded > bytes.length) refuse('tar_refused');
    const body = bytes.subarray(offset, end); offset = padded;
    const type = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    if (type === 'L' || type === 'K') {
      if (size > 8192 || !size || body[size - 1] !== 0) refuse('tar_refused');
      const value = tarString(body);
      if (type === 'L') { if (longName !== null) refuse('tar_refused'); longName = value; }
      else { if (longLink !== null) refuse('tar_refused'); longLink = value; }
      continue;
    }
    const prefix = magic === 'ustar ' ? '' : tarString(h.subarray(345, 500));
    const name = tarName(longName ?? `${prefix ? prefix + '/' : ''}${tarString(h.subarray(0, 100))}`);
    longName = null;
    // Unselected upstream symlinks are never materialized. Targets are not
    // resolved; their only possible effect here is an explicit selected refusal.
    const link = longLink ?? tarString(h.subarray(157, 257)); longLink = null;
    if (!['0', '5', '1', '2'].includes(type) || (type !== '0' && size !== 0)) refuse('tar_refused');
    const key = name === `${PIN.root}/bin/node` ? 'node' : name === `${PIN.root}/LICENSE` ? 'license' : null;
    if (key) {
      if (selected[key] || type !== '0' || link || (mode & 0o7022) || !size
          || size > (key === 'node' ? MAX_NODE : MAX_LICENSE)
          || (key === 'node' && !(mode & 0o100))) refuse('tar_refused');
      selected[key] = Buffer.from(body);
    }
  }
  if (zeros < 2 || longName !== null || longLink !== null || !selected.node || !selected.license) refuse('tar_refused');
  return selected;
}
async function signature(work, signal) {
  const pin = JSON.parse((await regular(`${HERE}/node-runtime-pin.json`, 32768)).bytes);
  if (pin.schemaVersion !== 1 || pin.version !== PIN.version || pin.platform !== 'linux-x64-glibc'
      || pin.archive?.filename !== PIN.filename || pin.archive.sha256 !== PIN.sha256
      || pin.signature?.primaryFingerprint !== PIN.fingerprint
      || pin.signature.sha256 !== 'e82087fe2cf383fce187b0789eb5ea50fd92f9b68afb4f4e174d65ec59acba4a'
      || pin.signature.keySha256 !== '5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a'
      || pin.signature.path !== 'x10/service/keys/node-v22.23.3-SHASUMS256.asc'
      || pin.signature.keyPath !== 'x10/service/keys/node-v22-release.asc') refuse('pin_refused');
  const key = (await regular(`${HERE}/keys/node-v22-release.asc`, 32768)).bytes;
  const signed = (await regular(`${HERE}/keys/node-v22.23.3-SHASUMS256.asc`, 32768)).bytes;
  if (sha(key) !== pin.signature.keySha256 || sha(signed) !== pin.signature.sha256) refuse('pin_refused');
  await tool('/usr/bin/gpg'); await tool('/usr/bin/gpgv');
  await writeNew(`${work}/key.asc`, key, 0o400); await writeNew(`${work}/signed.asc`, signed, 0o400);
  await command('/usr/bin/gpg', ['--no-options', '--batch', '--no-tty', '--homedir', work,
    '--dearmor', '--output', `${work}/keyring.gpg`, `${work}/key.asc`], work, 65536, 15000, signal);
  const result = await command('/usr/bin/gpgv', ['--homedir', work, '--keyring', `${work}/keyring.gpg`,
    '--status-fd', '1', '--output', `${work}/checksums`, `${work}/signed.asc`], work, 65536, 15000, signal);
  parseSignatureStatus(result.stdout.toString('ascii'));
  parseChecksumText((await regular(`${work}/checksums`, 16384, { uid: process.getuid() })).bytes.toString('ascii'));
  return pin;
}
// Explicit evidence is supplied by the trusted same-UID test coordinator only
// after waiting for the unchanged checker child. It is not an OS process fence.
function managedPackageCleanupEvidence(envelope) {
  try {
    const own = key => {
      const descriptor = Object.getOwnPropertyDescriptor(envelope, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return undefined;
      return descriptor.value;
    };
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(envelope))
        || own('managedPackageCheckerExited') !== true || !Object.is(own('managedPackageCheckerExitCode'), 0)
        || own('sourceManagedPackageSha256') !== MANAGED_PACKAGE_CLEANUP_SOURCE.checkerSha256
        || own('sourceManagedPackageProofSha256') !== MANAGED_PACKAGE_CLEANUP_SOURCE.proofSha256) return false;
    const report = own('managedPackageReport');
    const primary = report && Object.getOwnPropertyDescriptor(report, 'primaryFailure');
    if (!primary || primary.enumerable !== true || !Object.hasOwn(primary, 'value') || primary.value !== null) return false;
    if (checkManagedOperatorReturnReport(report).ok !== true) return false;
    const encoded = JSON.stringify(report);
    return typeof encoded === 'string' && Buffer.byteLength(encoded, 'utf8') <= 12288;
  } catch { return false; }
}
function fallbackPackageCleanupEvidence(envelope) {
  try {
    const own = key => {
      const descriptor = Object.getOwnPropertyDescriptor(envelope, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return undefined;
      return descriptor.value;
    };
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(envelope))
        || own('fallbackPackageCheckerExited') !== true || !Object.is(own('fallbackPackageCheckerExitCode'), 0)
        || own('sourceFallbackPackageSha256') !== FALLBACK_PACKAGE_CLEANUP_SOURCE.checkerSha256
        || own('sourceFallbackPackageProofSha256') !== FALLBACK_PACKAGE_CLEANUP_SOURCE.proofSha256) return false;
    const report = own('fallbackPackageReport');
    if (checkManagedOperatorFallbackReport(report).ok !== true) return false;
    const encoded = JSON.stringify(report);
    return typeof encoded === 'string' && Buffer.byteLength(encoded, 'utf8') <= MAX_MANAGED_OPERATOR_FALLBACK_REPORT_BYTES;
  } catch { return false; }
}
export function cleanupEvidence(e) {
  // Three independently collected, closed reports are required. A successful
  // legacy or normal-return child cannot authorize an unobserved fallback child.
  if (!managedPackageCleanupEvidence(e) || !fallbackPackageCleanupEvidence(e)) return false;
  const r = e?.report;
  if (e?.checkerExited !== true || e.checkerExitCode !== 0 || r?.ok !== true
      || r.code !== 'basic_lifecycle_verified' || r.phase !== 'complete'
      || r.actualNonrootManagerObserved !== true || r.actualUnitStarted !== true
      || r.runtimeUnitLinked !== true || r.runtimeUnitRemoved !== true || r.unitEnabled !== false
      || r.readinessAutomated !== true || r.automaticReadinessAccepted !== false
      || r.failedStartAccepted !== false || r.slowDrainAccepted !== false || r.orphanRecoveryAccepted !== false
      || r.tlsServiceAccepted !== false || r.serviceAccepted !== false || r.productionAccepted !== false || r.subprocessOutputsPublished !== false
      || r.primaryFailure !== null || !Array.isArray(r.cleanupFailures) || r.cleanupFailures.length !== 0
      || r.cleanupFailureCount !== 0 || r.cleanupFailuresTruncated !== false) return false;
  for (const [key, expected] of [['bundleSchemaVersion', 2], ['installSchemaVersion', 2], ['installedRecipeGenerated', true],
    ['restoredHTTPChecks', 1], ['tlsBackupAccepted', false], ['packageUpgradeRollbackAccepted', false]]) {
    const descriptor = Object.getOwnPropertyDescriptor(r, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.value !== expected) return false;
  }
  if (r.failedStartChecks !== 1) return false;
  const failed = r.failedStartProof;
  const failedKeys = ['unhealthyReadinessObserved', 'managerRefused', 'hookExitObserved', 'bindingAbsent',
    'launcherExited', 'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent',
    'failedSessionStopped', 'managerResetConfirmed', 'healthyRestartFresh'];
  if (!failed || typeof failed !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(failed))
      || Reflect.ownKeys(failed).length !== failedKeys.length
      || failedKeys.some(k => {
        const d = Object.getOwnPropertyDescriptor(failed, k);
        return !d || !Object.hasOwn(d, 'value') || d.value !== true;
      })) return false;
  if (r.controlledSlowDrainChecks !== 1) return false;
  const drain = r.controlledSlowDrainProof;
  const drainKeys = ['clientPaused', 'originResponseHeld', 'sameSessionObserved', 'managerStopPending',
    'nativeGroupLiveDuringStop', 'unitDeactivatingObserved', 'incompleteResponseObserved',
    'payloadCompleted', 'tlsVerified', 'managerStopCompleted', 'launcherExited',
    'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent'];
  if (!drain || typeof drain !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(drain))
      || Reflect.ownKeys(drain).length !== drainKeys.length
      || drainKeys.some(k => {
        const d = Object.getOwnPropertyDescriptor(drain, k);
        return !d || !Object.hasOwn(d, 'value') || d.value !== true;
      })) return false;
  if (r.operatorInterruptionChecks !== 1) return false;
  const interrupted = r.operatorInterruptionProof;
  const interruptedKeys = ['candidateProbeHeld', 'pendingReloadObserved', 'lastConfirmedPreserved',
    'sameServiceObserved', 'ownedOperatorTerminated', 'staleLocksPreserved', 'lockedRecoveryRefused',
    'exactLockRemovalConfirmed', 'explicitRollbackObserved', 'pendingCleared', 'restoredContentVerified',
    'noPostReplay', 'sameServiceAfterRecovery', 'repeatedRecoveryIdempotent'];
  if (!interrupted || typeof interrupted !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(interrupted))
      || Reflect.ownKeys(interrupted).length !== interruptedKeys.length
      || interruptedKeys.some(k => {
        const d = Object.getOwnPropertyDescriptor(interrupted, k);
        return !d || !Object.hasOwn(d, 'value') || d.value !== true;
      })) return false;
  if (r.operatorNativeChallengeChecks !== 1) return false;
  const challenge = r.operatorNativeChallengeProof;
  const challengeKeys = ['nativeRouteObserved', 'ownedRequestObserved', 'relayResponseMatched',
    'candidateBindingMatched', 'authorityReobservedBeforeSignal', 'ownedChallengeClosed'];
  if (!challenge || typeof challenge !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(challenge))
      || Reflect.ownKeys(challenge).length !== challengeKeys.length
      || challengeKeys.some(k => {
        const d = Object.getOwnPropertyDescriptor(challenge, k);
        return !d || !Object.hasOwn(d, 'value') || d.value !== true;
      })) return false;
  const restoredDescriptor = Object.getOwnPropertyDescriptor(r, 'restoredHTTPProof');
  const restored = restoredDescriptor && Object.hasOwn(restoredDescriptor, 'value') ? restoredDescriptor.value : null;
  const restoredKeys = ['stoppedConfirmedSource', 'privateBackupCreated', 'sourceUnitRemoved', 'freshUnit',
    'freshInstallation', 'freshSession', 'freshRevision', 'exactInputRestored', 'portsPreserved',
    'bindingInitiallyAbsent', 'freshHistory', 'restoredHTTPServed', 'restoredHTTPRestarted',
    'noPostReplay', 'sourceRecordsPreserved', 'backupPreserved', 'archivePreserved', 'sourceInstallationRemoved'];
  if (!restored || typeof restored !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(restored))
      || Reflect.ownKeys(restored).length !== restoredKeys.length
      || restoredKeys.some(k => {
        const d = Object.getOwnPropertyDescriptor(restored, k);
        return !d || !Object.hasOwn(d, 'value') || d.value !== true;
      })) return false;
  for (const k of ['explicitReadinessPasses', 'nativeSessionsStarted', 'nativeSessionsStopped', 'proxyBodyChecks', 'uploadChecks', 'streamChecks']) if (r[k] !== 5) return false;
  if (r.managerRestartCommands !== 2 || r.completedManagerRestarts !== 2
      || r.journalChecks !== 6 || !Number.isInteger(r.journalRecordsObserved)
      || r.journalRecordsObserved < 6 || r.journalRecordsObserved > 768
      || !Number.isInteger(r.journalRunningMarkers) || r.journalRunningMarkers < 6
      || r.journalRunningMarkers > r.journalRecordsObserved) return false;
  const restart = r.restartProof;
  const proofKeys = ['oldLauncherExited', 'oldNativeGroupsAbsent', 'freshSession', 'freshInvocation'];
  if (!restart || typeof restart !== 'object' || Array.isArray(restart)
      || Object.keys(restart).length !== proofKeys.length
      || proofKeys.some(k => !Object.hasOwn(restart, k) || restart[k] !== true)) return false;
  if (r.downstreamTLSActivated !== true) return false;
  for (const k of ['downstreamTLSSessionChecks', 'downstreamTLSUploadChecks', 'downstreamTLSStreamChecks',
    'downstreamTLS12Checks', 'downstreamTLS13Checks', 'downstreamTLSWrongCARefusals', 'downstreamTLSWrongNameRefusals']) if (r[k] !== 3) return false;
  if (r.downstreamTLSBodyChecks !== 6 || r.downstreamTLSCertificateChecks !== 12) return false;
  if (r.upstreamTLSActivated !== true) return false;
  for (const k of ['upstreamTLSSessionChecks', 'upstreamTLSBodyChecks', 'upstreamTLSUploadChecks',
    'upstreamTLSStreamChecks', 'upstreamTLSRollbackChecks', 'upstreamTLSCandidate502Checks', 'upstreamTLSNoPostReplayChecks']) if (r[k] !== 3) return false;
  for (const k of ['upstreamTLSDirectChecks', 'upstreamTLSWrongCARefusals',
    'upstreamTLSWrongNameRefusals', 'upstreamTLSPlaintextRefusals']) if (r[k] !== 1) return false;
  for (const k of ['managerStopped', 'launcherExited', 'nativeGroupsAbsent', 'listeningPortsClosed', 'controlSocketAbsent', 'runtimeLinkAbsent', 'installationRemoved', 'temporaryRootRemoved', 'downstreamTLSPortClosed', 'upstreamTLSPortClosed', 'readinessRelayPortClosed', 'upstreamTLSOriginClosed', 'readinessRelayClosed']) if (r.cleanup?.[k] !== true) return false;
  return r.cleanup.appSocketsRemaining === 0;
}
async function inspectRuntime(prefix) {
  const root = await directory(prefix), bin = await directory(`${prefix}/bin`);
  const record = await regular(`${prefix}/.verified-node.json`, 16384, { uid: root.uid, mode: 0o400 });
  const { sha256, ...m } = JSON.parse(record.bytes);
  if (!hex(sha256) || sha(JSON.stringify(m)) !== sha256 || m.kind !== 'x10-verified-node-dependency'
      || m.schemaVersion !== 1 || !/^[a-f0-9]{32}$/.test(m.installationId || '')
      || m.version !== PIN.version || m.archiveSha256 !== PIN.sha256 || m.prefix !== prefix
      || !same(m.rootIdentity, identity(root)) || !same(m.binIdentity, identity(bin))) refuse('runtime_identity_refused');
  for (const [file, mode, max] of [['bin/node', 0o500, MAX_NODE], ['LICENSE', 0o400, MAX_LICENSE]]) {
    const item = await regular(`${prefix}/${file}`, max, { uid: root.uid, mode });
    if (sha(item.bytes) !== m.files?.[file]?.sha256 || !same(identity(item.stat), m.files[file].identity)) refuse('runtime_identity_refused');
  }
  if (JSON.stringify((await readdir(prefix)).sort()) !== JSON.stringify(['.verified-node.json', 'LICENSE', 'bin'])
      || JSON.stringify(await readdir(`${prefix}/bin`)) !== '["node"]') refuse('runtime_identity_refused');
  return m;
}
async function clearWork(work, initial) {
  if (!same(identity(await directory(work)), initial)) refuse('verifier_cleanup_refused');
  const allowed = new Set(['key.asc', 'signed.asc', 'keyring.gpg', 'checksums', 'archive.xz']);
  for (const n of await readdir(work)) {
    if (!allowed.has(n)) refuse('verifier_cleanup_refused');
    const s = await lstat(`${work}/${n}`);
    if (!s.isFile() || s.uid !== process.getuid() || s.nlink !== 1) refuse('verifier_cleanup_refused');
    await unlink(`${work}/${n}`);
  }
  await rmdir(work);
}
async function install(archive, prefix) {
  if (process.platform !== 'linux' || process.arch !== 'x64' || typeof process.getuid !== 'function') refuse('platform_refused');
  absolute(archive); absolute(prefix); await directory(path.dirname(prefix));
  try { await lstat(prefix); refuse('prefix_collision'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const work = await mkdtemp(`${path.dirname(prefix)}/.node-verify-`), workId = identity(await directory(work));
  let created = false, completed = false, rootId = null, binId = null; const ownedFiles = new Map();
  const controller = new AbortController(), cancel = () => controller.abort();
  const check = () => { if (controller.signal.aborted) refuse('bootstrap_cancelled'); };
  process.once('SIGTERM', cancel); process.once('SIGINT', cancel);
  try {
    await signature(work, controller.signal); check();
    const capture = await regular(archive, MAX_ARCHIVE);
    if (sha(capture.bytes) !== PIN.sha256) refuse('archive_checksum_refused');
    await writeNew(`${work}/archive.xz`, capture.bytes, 0o400);
    await tool('/usr/bin/xz');
    const tar = await command('/usr/bin/xz', ['--decompress', '--stdout', '--single-stream', `${work}/archive.xz`], work, MAX_TAR, 60000, controller.signal);
    if (tar.stderr.length) refuse('archive_decode_refused');
    const files = parseTar(tar.stdout); check();
    await mkdir(prefix, { mode: 0o700 }); created = true;
    const root = await directory(prefix); rootId = identity(root);
    await mkdir(`${prefix}/bin`, { mode: 0o700 }); const bin = await directory(`${prefix}/bin`); binId = identity(bin);
    await writeNew(`${prefix}/bin/node`, files.node, 0o500, id => ownedFiles.set('bin/node', id));
    await writeNew(`${prefix}/LICENSE`, files.license, 0o400, id => ownedFiles.set('LICENSE', id)); check();
    const m = { schemaVersion: 1, kind: 'x10-verified-node-dependency', version: PIN.version, installationId: randomBytes(16).toString('hex'),
      archiveSha256: PIN.sha256, prefix, rootIdentity: identity(root), binIdentity: identity(bin), files: {} };
    for (const [name, bytes] of [['bin/node', files.node], ['LICENSE', files.license]]) m.files[name] = { sha256: sha(bytes), identity: identity(await lstat(`${prefix}/${name}`)) };
    await writeNew(`${prefix}/.verified-node.json`, JSON.stringify({ ...m, sha256: sha(JSON.stringify(m)) }) + '\n', 0o400, id => ownedFiles.set('.verified-node.json', id));
    await inspectRuntime(prefix); check();
    const version = await command(`${prefix}/bin/node`, ['--version'], work, 256, 5000, controller.signal);
    if (version.stdout.toString('ascii') !== `${PIN.version}\n` || version.stderr.length) refuse('runtime_version_refused');
    await inspectRuntime(prefix); check(); completed = true;
    return { ok: true, code: 'verified_node_installed', version: PIN.version, archiveSha256: PIN.sha256,
      nodeSha256: m.files['bin/node'].sha256, installationId: m.installationId, signatureVerified: true, selectedFiles: 2, runtimeVersionVerified: true };
  } finally {
    // Before any service caller exists, only exact newly-created inode
    // inventory may be removed. Unknown identities are retained, never repaired.
    process.removeListener('SIGTERM', cancel); process.removeListener('SIGINT', cancel);
    if (created && !completed) {
      try {
        if (!rootId || !same(identity(await directory(prefix)), rootId)) refuse();
        const expected = [...ownedFiles.keys()].filter(n => !n.includes('/'));
        if (binId) expected.push('bin');
        if (JSON.stringify((await readdir(prefix)).sort()) !== JSON.stringify(expected.sort())) refuse();
        if (binId && (!same(identity(await directory(`${prefix}/bin`)), binId)
            || JSON.stringify(await readdir(`${prefix}/bin`)) !== JSON.stringify(ownedFiles.has('bin/node') ? ['node'] : []))) refuse();
        for (const [n, id] of ownedFiles) { const st = await lstat(`${prefix}/${n}`); if (!st.isFile() || st.nlink !== 1 || !same(identity(st), id)) refuse(); }
        for (const n of ownedFiles.keys()) await unlink(`${prefix}/${n}`);
        if (binId) await rmdir(`${prefix}/bin`);
        await rmdir(prefix);
      } catch { /* Retain unknown identity; never repair or recursively delete. */ }
    }
    await clearWork(work, workId);
  }
}
async function removeRuntime(prefix) {
  await inspectRuntime(prefix);
  await unlink(`${prefix}/bin/node`); await unlink(`${prefix}/LICENSE`);
  await unlink(`${prefix}/.verified-node.json`); await rmdir(`${prefix}/bin`); await rmdir(prefix);
}
export async function main(argv = process.argv.slice(2)) {
  try {
    let result;
    if (argv.length === 4 && argv[0] === '--archive' && argv[2] === '--prefix') result = await install(absolute(argv[1]), absolute(argv[3]));
    else if (argv.length === 5 && argv[0] === '--cleanup' && argv[1] === '--prefix' && argv[3] === '--service-evidence') {
      const prefix = absolute(argv[2]), file = absolute(argv[4]);
      const receipt = await regular(file, 32768, { uid: process.getuid() });
      if ((receipt.stat.mode & 0o7077) !== 0) refuse('runtime_retained_cleanup_unconfirmed');
      const e = JSON.parse(receipt.bytes);
      if (!cleanupEvidence(e) || e.sourceLifecycleSha256 !== 'e88ef9604b1d955ca3235b04faf4e0cb37266bfef3255e68e27d75dc63ce1370') refuse('runtime_retained_cleanup_unconfirmed');
      for (const [name, expected] of [['operator-package-return.mjs', MANAGED_PACKAGE_CLEANUP_SOURCE.checkerSha256],
        ['operator-package-return-proof.mjs', MANAGED_PACKAGE_CLEANUP_SOURCE.proofSha256],
        ['operator-package-fallback.mjs', FALLBACK_PACKAGE_CLEANUP_SOURCE.checkerSha256],
        ['operator-package-fallback-proof.mjs', FALLBACK_PACKAGE_CLEANUP_SOURCE.proofSha256]]) {
        const source = await regular(path.join(HERE, name), 256 * 1024, { uid: process.getuid() });
        if (sha(source.bytes) !== expected) refuse('runtime_retained_cleanup_unconfirmed');
      }
      const runtime = await inspectRuntime(prefix);
      if (e.runtimeNodeSha256 !== runtime.files['bin/node'].sha256 || e.runtimeInstallationId !== runtime.installationId) refuse('runtime_retained_cleanup_unconfirmed');
      await removeRuntime(prefix); result = { ok: true, code: 'verified_node_removed', runtimeRemoved: true };
    } else refuse('usage_invalid');
    return { ...result, serviceAccepted: false, productionAccepted: false, subprocessOutputsPublished: false };
  } catch (e) {
    const allowed = new Set(['verified_node_refused', 'platform_refused', 'prefix_collision', 'pin_refused', 'signature_refused', 'checksum_refused', 'tar_refused', 'verifier_tool_refused', 'verifier_command_refused', 'archive_checksum_refused', 'archive_decode_refused', 'runtime_identity_refused', 'runtime_version_refused', 'runtime_retained_cleanup_unconfirmed', 'usage_invalid', 'verifier_cleanup_refused', 'bootstrap_cancelled']);
    return { ok: false, code: allowed.has(e.code) ? e.code : 'verified_node_refused', serviceAccepted: false,
      productionAccepted: false, subprocessOutputsPublished: false };
  }
}
let invoked = false;
try { invoked = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* No import side effects. */ }
if (invoked) { const result = await main(); process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.ok ? 0 : 1; }
