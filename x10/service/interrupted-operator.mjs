// Acceptance-only inspection of one owned, detached installed operator group.
// Lock retirement models explicit fixture operator inspection; never production recovery.
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, readFile, readlink, readdir, realpath, unlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
export const INTERRUPTED_OPERATOR_ERROR_CODES = Object.freeze(['operator_fixture_invalid', 'operator_fixture_profile', 'operator_fixture_identity',
  'operator_fixture_locked', 'operator_fixture_not_held', 'operator_fixture_pending', 'operator_fixture_process',
  'operator_fixture_group', 'operator_fixture_timeout', 'operator_fixture_state', 'operator_fixture_output_limit',
  'operator_fixture_signal', 'operator_fixture_cancelled', 'operator_fixture_exit_unknown', 'operator_fixture_lock_changed']);
const fail = c => { throw Object.assign(new Error(c), { code: c }); };
const hash = b => createHash('sha256').update(b).digest('hex');
const pause = ms => new Promise(r => setTimeout(r, ms));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const safe = p => typeof p === 'string' && p.length <= 1024 && /^\/[A-Za-z0-9_./+-]+$/.test(p)
  && p !== '/' && path.posix.normalize(p) === p && !p.endsWith('/');
const identity = s => ({ dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode & 0o7777, nlink: s.nlink, size: s.size, mtimeMs: s.mtimeMs, ctimeMs: s.ctimeMs });
async function dir(p) {
  const s = await lstat(p);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7077) !== 0 || await realpath(p) !== p) fail('operator_fixture_identity');
  return { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode & 0o7777 };
}
async function file(p, max, mode, node = false) {
  if (await realpath(p) !== p) fail('operator_fixture_identity');
  const f = await open(p, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.nlink !== 1 || (node ? ![0, process.getuid()].includes(s.uid) || (s.mode & 0o7022) !== 0 || !(s.mode & 0o100)
      : s.uid !== process.getuid() || (s.mode & 0o7777) !== mode) || s.size < 1 || s.size > max) fail('operator_fixture_identity');
    const buffer = Buffer.alloc(s.size + 1); let used = 0;
    while (used < buffer.length) { const r = await f.read(buffer, used, buffer.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    const bytes = buffer.subarray(0, used), after = await f.stat();
    if (bytes.length !== s.size || !same(identity(s), identity(after))) fail('operator_fixture_identity');
    return { meta: identity(s), sha256: hash(bytes), bytes };
  } finally { await f.close(); }
}
function json(b, code) { try { return JSON.parse(b); } catch { fail(code); } }
async function proc(pid) {
  const b = `/proc/${pid}`;
  const [st, status, exe, cmd, pidns, netns] = await Promise.all([readFile(`${b}/stat`, 'utf8'), readFile(`${b}/status`, 'utf8'),
    readlink(`${b}/exe`), readFile(`${b}/cmdline`), readlink(`${b}/ns/pid`), readlink(`${b}/ns/net`)]);
  if (Buffer.byteLength(st) + Buffer.byteLength(status) + cmd.length > 128 * 1024) fail('operator_fixture_process');
  const fields = st.slice(st.lastIndexOf(') ') + 2).trim().split(/\s+/), uid = /^Uid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
  if (!uid || uid.length !== 4 || uid.some(x => x !== process.getuid()) || ['Z', 'X'].includes(fields[0])
      || !/^[0-9]+$/.test(fields[19])) fail('operator_fixture_process');
  const args = cmd.toString('utf8').split('\0'); if (args.pop() !== '') fail('operator_fixture_process');
  return { pid, ppid: Number(fields[1]), pgid: Number(fields[2]), sid: Number(fields[3]), startTicks: fields[19],
    uid: uid[0], exe, args, pidns, netns };
}
async function absent(pid) { try { await lstat(`/proc/${pid}`); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; } }
async function group(pgid) {
  const names = (await readdir('/proc')).filter(x => /^[1-9][0-9]*$/.test(x));
  if (names.length > 10000) fail('operator_fixture_group'); const members = [];
  for (let i = 0; i < names.length; i += 32) {
    await Promise.all(names.slice(i, i + 32).map(async n => {
      try { const st = await readFile(`/proc/${n}/stat`, 'utf8'), f = st.slice(st.lastIndexOf(') ') + 2).trim().split(/\s+/);
        if (Number(f[2]) === pgid) members.push(Number(n));
      } catch (e) { if (e.code !== 'ENOENT' && e.code !== 'ESRCH') throw e; }
    }));
  }
  return members.sort((a, b) => a - b);
}
// The acceptance helper supports only a direct one-view /proc profile.
// Nested PID views are refused before spawn; no namespace remapping is inferred.
export function parseOperatorProcessProfile(value) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('operator_fixture_profile');
  const keys = ['pid', 'ppid', 'status', 'stat'], o = {};
  if (Reflect.ownKeys(value).length !== keys.length) fail('operator_fixture_profile');
  for (const k of keys) { const d = Object.getOwnPropertyDescriptor(value, k);
    if (!d || !Object.hasOwn(d, 'value')) fail('operator_fixture_profile'); o[k] = d.value; }
  if (!Number.isSafeInteger(o.pid) || o.pid < 2 || !Number.isSafeInteger(o.ppid) || o.ppid < 1
      || typeof o.status !== 'string' || typeof o.stat !== 'string' || Buffer.byteLength(o.status) > 65536 || Buffer.byteLength(o.stat) > 65536) fail('operator_fixture_profile');
  const one = key => { const matches = [...o.status.matchAll(new RegExp('^' + key + ':\\s*([^\\n]+)$', 'gm'))];
    if (matches.length !== 1 || !/^[1-9][0-9]*$/.test(matches[0][1].trim())) fail('operator_fixture_profile'); return Number(matches[0][1].trim()); };
  const first = /^([1-9][0-9]*) \(/.exec(o.stat), end = o.stat.lastIndexOf(') '), f = end < 0 ? [] : o.stat.slice(end + 2).trim().split(/\s+/);
  if (!first || Number(first[1]) !== o.pid || f.length < 20 || ['Z', 'X'].includes(f[0]) || !/^[0-9]+$/.test(f[19])
      || one('Pid') !== o.pid || one('PPid') !== o.ppid || one('NSpid') !== o.pid || Number(f[1]) !== o.ppid
      || one('NSpgid') !== Number(f[2]) || one('NSsid') !== Number(f[3])) fail('operator_fixture_profile');
  return { supported: true, directPIDView: true, directGroupView: true, directSessionView: true };
}
async function boundedProc(p) {
  const f = await open(p, constants.O_RDONLY | constants.O_NOFOLLOW), b = Buffer.alloc(65537); let used = 0;
  try { while (used < b.length) { const r = await f.read(b, used, b.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    if (used > 65536) fail('operator_fixture_profile'); return b.subarray(0, used).toString('utf8'); }
  finally { await f.close(); }
}
export async function inspectOperatorProcessProfile() {
  if (arguments.length || process.platform !== 'linux') fail('operator_fixture_profile');
  try {
    const [status, stat] = await Promise.all([boundedProc('/proc/self/status'), boundedProc('/proc/self/stat')]);
    parseOperatorProcessProfile({ pid: process.pid, ppid: process.ppid, status, stat });
    const [directStatus, directStat] = await Promise.all([boundedProc(`/proc/${process.pid}/status`), boundedProc(`/proc/${process.pid}/stat`)]);
    return parseOperatorProcessProfile({ pid: process.pid, ppid: process.ppid, status: directStatus, stat: directStat });
  } catch { fail('operator_fixture_profile'); }
}
function options(value) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('operator_fixture_invalid');
  const names = ['node', 'launcher', 'prefix', 'sessionPrefix', 'inputFile', 'env', 'isHeld', 'checkCancelled', 'timeoutMs'], o = {};
  for (const k of Reflect.ownKeys(value)) { const d = Object.getOwnPropertyDescriptor(value, k);
    if (typeof k !== 'string' || !names.includes(k) || !d || !Object.hasOwn(d, 'value')) fail('operator_fixture_invalid'); o[k] = d.value; }
  if (process.platform !== 'linux' || typeof process.getuid !== 'function' || !['node', 'launcher', 'prefix', 'sessionPrefix', 'inputFile'].every(k => safe(o[k]))
      || o.launcher !== `${o.prefix}/bin/x10` || !new RegExp('^' + o.prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/runs/[a-f0-9]{32}$').test(o.sessionPrefix)
      || typeof o.isHeld !== 'function' || typeof o.checkCancelled !== 'function' || !Number.isInteger(o.timeoutMs ?? 10000) || (o.timeoutMs ?? 10000) < 500 || (o.timeoutMs ?? 10000) > 10000) fail('operator_fixture_invalid');
  const env = o.env;
  if (!env || ![Object.prototype, null].includes(Object.getPrototypeOf(env))) fail('operator_fixture_invalid');
  const copy = {}, envNames = ['PATH', 'LANG', 'LC_ALL', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS'];
  for (const k of Reflect.ownKeys(env)) { const d = Object.getOwnPropertyDescriptor(env, k);
    if (typeof k !== 'string' || !envNames.includes(k) || !d || !Object.hasOwn(d, 'value') || typeof d.value !== 'string') fail('operator_fixture_invalid'); copy[k] = d.value; }
  if (copy.PATH !== '/usr/bin:/bin' || copy.LANG !== 'C' || copy.LC_ALL !== 'C') fail('operator_fixture_invalid');
  return { ...o, env: copy, timeoutMs: o.timeoutMs ?? 10000 };
}
export async function startOwnedOperator(value) {
  const o = options(value);
  await inspectOperatorProcessProfile();
  const state = `${o.sessionPrefix}/.x10-control`, controller = `${o.prefix}/lib/control/cli.mjs`;
  const dirs = [o.prefix, `${o.prefix}/bin`, `${o.prefix}/lib`, `${o.prefix}/lib/control`, `${o.prefix}/runs`, o.sessionPrefix, state, path.dirname(o.inputFile)];
  const directoryIds = new Map(); for (const p of new Set(dirs)) directoryIds.set(p, await dir(p));
  const files = new Map();
  for (const [p, max, mode, node] of [[o.node, 256 * 1024 * 1024, null, true], [o.launcher, 65536, 0o500], [controller, 256 * 1024, 0o400],
    [o.inputFile, 2 * 1024 * 1024, 0o600], [`${o.prefix}/.alpha-install.json`, 2 * 1024 * 1024, 0o600]]) files.set(p, await file(p, max, mode, node));
  const manifest = json(files.get(`${o.prefix}/.alpha-install.json`).bytes, 'operator_fixture_identity'), { sha256, ...record } = manifest;
  if (sha256 !== hash(JSON.stringify(record)) || record.prefix !== o.prefix || !same(record.rootIdentity, { dev: directoryIds.get(o.prefix).dev, ino: directoryIds.get(o.prefix).ino, uid: process.getuid() })
      || record.nodeRuntime?.executable !== o.node || record.nodeRuntime?.sha256 !== files.get(o.node).sha256) fail('operator_fixture_identity');
  for (const relative of ['bin/x10', 'lib/control/cli.mjs']) {
    const f = files.get(`${o.prefix}/${relative}`), entry = record.immutable?.[relative];
    if (!entry || entry.sha256 !== f.sha256 || entry.bytes !== f.bytes.length || entry.mode !== f.meta.mode.toString(8).padStart(4, '0')) fail('operator_fixture_identity');
  }
  const alphaLock = `${o.prefix}/.alpha-lock`, controlLock = `${state}/lock`, pendingPath = `${state}/pending.json`;
  for (const p of [alphaLock, controlLock]) { try { await lstat(p); fail('operator_fixture_locked'); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
  const startedAt = Date.now(), deadline = performance.now() + o.timeoutMs, namespaces = { pidns: await readlink('/proc/self/ns/pid'), netns: await readlink('/proc/self/ns/net') };
  let child, closed = false, exitCode = null, exitSignal = null, output = 0, outputOverflow = false, spawnFailed = false;
  let wrapper, control, locks, pending, captured = false, terminated = false, retired = false, decision = false, terminating;
  let signalAttempted = false, cleanupAttempted = false;
  const expectedWrapper = [o.node, o.launcher, 'apply', '--file', o.inputFile];
  const expectedControl = [o.node, controller, 'apply', '--state', state, '--file', o.inputFile];
  const limit = () => { if (performance.now() >= deadline) fail('operator_fixture_timeout'); };
  function checkCancelled() { let r; try { r = o.checkCancelled(); } catch { fail('operator_fixture_cancelled'); } if (r !== undefined) fail('operator_fixture_cancelled'); }
  function held() { let result; try { result = o.isHeld(); } catch { fail('operator_fixture_not_held'); } if (result !== true) fail('operator_fixture_not_held'); }
  async function guards() {
    for (const [p, expected] of directoryIds) if (!same(await dir(p), expected)) fail('operator_fixture_identity');
    // Node bytes were pinned before spawn; reread metadata and exact bytes of
    // all mutable fixture inputs before each process or lock action.
    for (const [p, expected] of files) {
      const f = await file(p, p === o.node ? 256 * 1024 * 1024 : 2 * 1024 * 1024, expected.meta.mode, p === o.node);
      if (!same(f.meta, expected.meta) || f.sha256 !== expected.sha256) fail('operator_fixture_identity');
    }
  }
  function checkProcess(p, args, parent) {
    if (p.exe !== o.node || !same(p.args, args) || p.ppid !== parent || p.pgid !== child.pid || p.sid !== child.pid
        || p.pidns !== namespaces.pidns || p.netns !== namespaces.netns) fail('operator_fixture_process');
  }
  async function lockRecord(p) {
    const f = await file(p, 4096, 0o600), r = json(f.bytes, 'operator_fixture_lock_changed');
    if (Object.keys(r).length !== 2 || !Object.hasOwn(r, 'pid') || !Object.hasOwn(r, 'at') || !Number.isSafeInteger(r.pid) || r.pid < 2
        || typeof r.at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.at)
        || !Number.isFinite(Date.parse(r.at)) || Date.parse(r.at) < startedAt - 1000 || Date.parse(r.at) > Date.now() + 1000) fail('operator_fixture_lock_changed');
    return { ...f, pid: r.pid };
  }
  async function currentCapture(requireHeld = true) {
    await guards();
    const a = await lockRecord(alphaLock), c = await lockRecord(controlLock), p = await file(pendingPath, 2 * 1024 * 1024, 0o600);
    if (a.pid !== child.pid || c.pid === a.pid) fail('operator_fixture_process');
    const w = await proc(a.pid), ctl = await proc(c.pid); checkProcess(w, expectedWrapper, process.pid); checkProcess(ctl, expectedControl, w.pid);
    if (wrapper && !same(w, wrapper)) fail('operator_fixture_process');
    if (control && !same(ctl, control)) fail('operator_fixture_process');
    if (!same(await group(child.pid), [a.pid, c.pid].sort((x, y) => x - y))) fail('operator_fixture_group');
    if (locks && (!same(a.meta, locks[0].meta) || a.sha256 !== locks[0].sha256 || !same(c.meta, locks[1].meta) || c.sha256 !== locks[1].sha256)) fail('operator_fixture_lock_changed');
    if (pending && (!same(p.meta, pending.meta) || p.sha256 !== pending.sha256)) fail('operator_fixture_pending');
    if (requireHeld) held(); return { a, c, p, w, ctl };
  }
  async function confirmAbsent() {
    if (!closed || !wrapper || !control || !await absent(wrapper.pid) || !await absent(control.pid) || (await group(child.pid)).length !== 0) fail('operator_fixture_exit_unknown');
  }
  async function stop(acceptance) {
    if (acceptance) limit();
    const before = performance.now(); await currentCapture(acceptance);
    if (acceptance) limit();
    if (closed || (acceptance && outputOverflow) || performance.now() - before > 1000) fail('operator_fixture_process');
    if (acceptance) { held(); checkCancelled(); }
    signalAttempted = true;
    try { process.kill(-child.pid, 'SIGTERM'); } catch { fail('operator_fixture_signal'); }
    const stopDeadline = performance.now() + 5000;
    while (performance.now() < stopDeadline) {
      try { await confirmAbsent(); terminated = true; return { ok: true, wrapperExited: true, controllerExited: true, groupAbsent: true }; }
      catch (e) { if (e.code !== 'operator_fixture_exit_unknown') throw e; }
      await pause(20);
    }
    fail('operator_fixture_exit_unknown');
  }
  const handle = Object.freeze({
    snapshot() { if (arguments.length) fail('operator_fixture_invalid'); return { running: !closed, wrapperCaptured: Boolean(wrapper), controllerCaptured: Boolean(control), groupCaptured: captured, terminated, locksRetired: retired }; },
    async captureLocks() {
      if (arguments.length || captured || decision) fail('operator_fixture_state'); limit(); checkCancelled();
      let latest;
      while (performance.now() < deadline) {
        if (closed || spawnFailed || outputOverflow) fail('operator_fixture_process');
        try { latest = await currentCapture(); break; } catch (e) { if (e.code !== 'ENOENT') throw e; }
        await pause(10);
      }
      if (!latest) fail('operator_fixture_timeout'); limit(); checkCancelled();
      ({ w: wrapper, ctl: control, p: pending } = latest); locks = [latest.a, latest.c]; captured = true;
      return { ok: true, alphaCaptured: true, controllerCaptured: true, pendingCaptured: true };
    },
    async terminate() {
      if (arguments.length || decision || !captured || terminated) fail('operator_fixture_state');
      decision = true; terminating = stop(true); return terminating;
    },
    async removeCapturedLocks() {
      if (arguments.length || !terminated || retired) fail('operator_fixture_state');
      limit(); await guards(); await confirmAbsent();
      const capturedFiles = [alphaLock, controlLock];
      for (let i = 0; i < capturedFiles.length; i++) { const f = await lockRecord(capturedFiles[i]);
        if (!same(f.meta, locks[i].meta) || f.sha256 !== locks[i].sha256 || f.pid !== locks[i].pid) fail('operator_fixture_lock_changed'); }
      const p = await file(pendingPath, 2 * 1024 * 1024, 0o600);
      if (!same(p.meta, pending.meta) || p.sha256 !== pending.sha256) fail('operator_fixture_pending');
      await confirmAbsent(); limit();
      // Explicit manual-fixture action only; no stale-lock production API.
      for (let i = 0; i < capturedFiles.length; i++) { const f = await lockRecord(capturedFiles[i]);
        if (!same(f.meta, locks[i].meta) || f.sha256 !== locks[i].sha256) fail('operator_fixture_lock_changed');
        await confirmAbsent(); limit(); checkCancelled(); await unlink(capturedFiles[i]); }
      retired = true; return { ok: true, alphaRemoved: true, controllerRemoved: true };
    },
    async cancel() {
      if (arguments.length) fail('operator_fixture_invalid');
      try {
        if (terminating) { try { await terminating; } catch { if (signalAttempted) return false; } }
        if (!terminated) {
          if (cleanupAttempted || signalAttempted) return false;
          cleanupAttempted = true;
          if (!captured) {
            const until = performance.now() + 500; let found;
            while (performance.now() < until && !closed) {
              try { found = await currentCapture(false); break; } catch (e) { if (e.code !== 'ENOENT') return false; }
              await pause(10);
            }
            if (!found) return false;
            ({ w: wrapper, ctl: control, p: pending } = found); locks = [found.a, found.c];
          }
          terminating = stop(false); await terminating;
        }
        await confirmAbsent(); return true;
      } catch { return false; }
    },
    async close() { if (arguments.length) fail('operator_fixture_invalid'); return handle.cancel(); }
  });
  checkCancelled();
  child = spawn(o.node, expectedWrapper.slice(1), { detached: true, env: o.env, stdio: ['ignore', 'pipe', 'pipe'] });
  const drain = b => { output += b.length; b.fill(0); if (output > 65536) outputOverflow = true; };
  child.stdout.on('data', drain); child.stderr.on('data', drain);
  child.once('error', () => { spawnFailed = true; });
  child.once('close', (code, signal) => { closed = true; exitCode = code; exitSignal = signal; });
  if (!Number.isInteger(child.pid) || child.pid < 2) fail('operator_fixture_process');
  // Construction always returns the owned child handle after a successful
  // spawn, even if exec identity is not yet observable. No process authority
  // is granted until the complete two-lock capture succeeds.
  const observeUntil = Math.min(deadline, performance.now() + 250);
  while (!closed && performance.now() < observeUntil) {
    try { const observed = await proc(child.pid); checkProcess(observed, expectedWrapper, process.pid); wrapper = observed; break; }
    catch { await pause(10); }
  }
  return handle;
}
