// Optional Linux observation of a captured process set, never a generation fence.
// This module reads /proc only. It does not signal or reconfigure any process.
import { open, opendir, readlink, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { endianness } from 'node:os';
import { performance } from 'node:perf_hooks';

const scope = 'captured-processes-only';
const limits = Object.freeze({ budgetMs: 3000, children: 512, procEntries: 10000, descriptorsPerProcess: 4096,
  descriptorsTotal: 32768, tableBytes: 1024 * 1024, snapshotBytes: 2 * 1024 * 1024 });
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const same = (a, b) => a === b || (a && b && typeof a === 'object' && typeof b === 'object'
  && Array.isArray(a) === Array.isArray(b) && Object.keys(a).length === Object.keys(b).length
  && Object.keys(a).every(k => Object.hasOwn(b, k) && same(a[k], b[k])));
const decimal = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
const pid = value => Number.isSafeInteger(value) && value >= 2 && value <= 2147483647;
const uid = value => Number.isSafeInteger(value) && value >= 0 && value <= 4294967295;
const absolute = value => typeof value === 'string' && value.startsWith('/') && value.length <= 4096 && !value.includes('\0');
const ns = (value, kind) => typeof value === 'string' && new RegExp(`^${kind}:\\[[1-9][0-9]*\\]$`).test(value);
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === expected.length && expected.every(k => Object.hasOwn(value, k));
const masterKeys = ['pid', 'procPid', 'pidNamespace', 'startTicks', 'uid', 'executable', 'commandSha256'];
const processKeys = ['procPid', 'pid', 'parentProcPid', 'startTicks', 'uid', 'executable', 'pidNamespace', 'networkNamespace'];
function fail(text, invalid = false) {
  throw Object.assign(new Error(text), { code: invalid ? 'listener_snapshot_invalid' : 'listener_observation_unavailable' });
}
function masterShape(value) {
  return keys(value, masterKeys) && pid(value.pid) && pid(value.procPid) && uid(value.uid)
    && ns(value.pidNamespace, 'pid') && decimal(value.startTicks) && absolute(value.executable)
    && /^[a-f0-9]{64}$/.test(value.commandSha256);
}
function processShape(value) {
  return keys(value, [...processKeys, 'ownedListenerFds']) && pid(value.pid) && pid(value.procPid)
    && pid(value.parentProcPid) && decimal(value.startTicks) && uid(value.uid) && absolute(value.executable)
    && ns(value.pidNamespace, 'pid') && ns(value.networkNamespace, 'net')
    && Array.isArray(value.ownedListenerFds) && value.ownedListenerFds.length <= limits.descriptorsPerProcess
    && value.ownedListenerFds.every(x => typeof x === 'string' && /^(0|[1-9][0-9]{0,9})$/.test(x))
    && new Set(value.ownedListenerFds).size === value.ownedListenerFds.length;
}

class Budget {
  constructor() { this.started = performance.now(); this.descriptors = 0; }
  check() { if (performance.now() - this.started > limits.budgetMs) fail('Listener observation exceeded its elapsed I/O budget'); }
  async io(operation) { this.check(); const result = await operation(); this.check(); return result; }
  async resource(operation) {
    this.check(); const result = await operation();
    try { this.check(); return result; }
    catch (error) { await result.close(); throw error; }
  }
  async read(file, maximum) {
    const handle = await this.resource(() => open(file, 'r'));
    try {
      const chunks = []; let size = 0;
      while (true) {
        this.check();
        const buffer = Buffer.alloc(Math.min(16384, maximum + 1 - size));
        const { bytesRead } = await this.io(() => handle.read(buffer, 0, buffer.length, null));
        if (!bytesRead) return Buffer.concat(chunks, size).toString('utf8');
        size += bytesRead;
        if (size > maximum) fail(`Proc file exceeds supported byte limit: ${file}`);
        chunks.push(buffer.subarray(0, bytesRead));
      }
    } finally { await handle.close(); }
  }
  async link(file) { const result = await this.io(() => readlink(file)); if (result.length > 4096) fail('Proc link exceeds supported length'); return result; }
}

async function gone(procPid, budget) {
  // An inaccessible file is not evidence of exit. Both directory lookups must
  // specifically report ENOENT; a present new occupant is never accepted here.
  for (let i = 0; i < 2; i++) {
    try { await budget.io(() => lstat(`/proc/${procPid}`)); return false; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return true;
}

async function identity(procPid, budget, allowGone = false) {
  try {
    const base = `/proc/${procPid}`;
    const status = await budget.read(`${base}/status`, 65536);
    const stat = await budget.read(`${base}/stat`, 65536);
    const pids = /^NSpid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
    const owner = /^Uid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
    const parent = Number(/^PPid:\s+(\d+)$/m.exec(status)?.[1]);
    const split = stat.lastIndexOf(') '), fields = stat.slice(split + 2).trim().split(/\s+/);
    if (split < 0 || !stat.startsWith(`${procPid} (`) || fields.length < 20 || fields[0] === 'Z'
      || !decimal(fields[19]) || !pids || pids.length > 32 || pids.some(x => !pid(x))
      || pids[0] !== procPid || !owner || owner.length !== 4 || owner.some(x => !uid(x) || x !== owner[0])
      || !Number.isSafeInteger(parent) || parent < 0 || Number(fields[1]) !== parent)
      fail(`Unsupported or changing proc identity: ${procPid}`);
    return { procPid, pid: pids.at(-1), parentProcPid: parent, startTicks: fields[19], uid: owner[0],
      executable: await budget.link(`${base}/exe`), pidNamespace: await budget.link(`${base}/ns/pid`),
      networkNamespace: await budget.link(`${base}/ns/net`) };
  } catch (error) {
    // An already opened proc file can report ESRCH after process exit.
    // Neither errno proves exit: require two independent ENOENT lookups.
    if (allowGone && ['ENOENT', 'ESRCH'].includes(error.code) && await gone(procPid, budget)) return null;
    throw error;
  }
}

async function masterIdentity(expected, binary, budget) {
  const actual = await identity(expected.procPid, budget);
  const cmdline = await budget.read(`/proc/${expected.procPid}/cmdline`, 65536);
  const title = cmdline.split('\0')[0];
  const commandSha256 = createHash('sha256').update(title).digest('hex');
  const observed = { pid: actual.pid, procPid: actual.procPid, pidNamespace: actual.pidNamespace,
    startTicks: actual.startTicks, uid: actual.uid, executable: actual.executable, commandSha256 };
  if (!same(observed, expected) || actual.executable !== binary || !title.startsWith('nginx: master process ')
    || actual.uid !== process.getuid() || actual.pidNamespace !== await budget.link('/proc/self/ns/pid')
    || actual.networkNamespace !== await budget.link('/proc/self/ns/net'))
    fail('Bound master identity or controller namespace does not match');
  return actual;
}

async function children(master, budget) {
  let text;
  try { text = (await budget.read(`/proc/${master.procPid}/task/${master.procPid}/children`, 16384)).trim(); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    // Some kernels omit task/children. Its absence is not a claim that the
    // master has no children. Inspect a bounded procfs inventory instead.
    if (await gone(master.procPid, budget)) throw error;
    const entries = [], result = [];
    const directory = await budget.resource(() => opendir('/proc'));
    try {
      while (true) {
        const entry = await budget.io(() => directory.read());
        if (!entry) break;
        if (!/^[1-9][0-9]*$/.test(entry.name)) continue;
        if (entry.name === '1') continue; // Namespace init cannot be this master's child.
        if (!pid(Number(entry.name)) || entries.length >= limits.procEntries) fail('Proc inventory exceeds supported limit');
        entries.push(Number(entry.name));
      }
    } finally { await directory.close(); }
    for (const procPid of entries) {
      let status;
      try { status = await budget.read(`/proc/${procPid}/status`, 65536); }
      catch (error) { if (error.code === 'ENOENT' && await gone(procPid, budget)) continue; throw error; }
      const parent = /^PPid:\s+(\d+)$/m.exec(status)?.[1];
      if (parent === undefined) fail('Unclassifiable process during child scan');
      if (Number(parent) === master.procPid) result.push(procPid);
      if (result.length > limits.children) fail('Too many direct children for supported observation');
    }
    return result.sort((a, b) => a - b);
  }
  if (text && !/^[0-9 ]+$/.test(text)) fail('Malformed proc child list');
  const list = text ? text.split(/ +/).map(Number) : [];
  if (list.length > limits.children || list.some(x => !pid(x)) || new Set(list).size !== list.length)
    fail('Unsupported proc child count or identity');
  return list.sort((a, b) => a - b);
}

async function listener(port, master, budget) {
  const inodes = new Set();
  const expectedAddress = endianness() === 'LE' ? '0100007F' : '7F000001';
  for (const [family, width] of [['tcp', 8], ['tcp6', 32]]) {
    const table = await budget.read(`/proc/${master.procPid}/net/${family}`, limits.tableBytes);
    const rows = table.trim().split('\n');
    if (!/^\s*sl\s+local_address\s+(?:rem_address|remote_address)\s+st\b/.test(rows.shift() || '')) fail('Unsupported proc TCP table header');
    for (const row of rows) {
      budget.check();
      const fields = row.trim().split(/\s+/);
      if (fields.length < 10 || !new RegExp(`^[A-Fa-f0-9]{${width}}:[A-Fa-f0-9]{4}$`).test(fields[1] || ''))
        fail('Malformed proc TCP table row');
      const [address, hexPort] = fields[1].toUpperCase().split(':');
      if (fields[3] !== '0A' || parseInt(hexPort, 16) !== port) continue;
      if (family === 'tcp6' || address === '00000000') fail('Wildcard or IPv6 listener makes the managed endpoint unsupported');
      if (address !== expectedAddress) continue;
      if (!decimal(fields[9])) fail('Invalid managed listener inode');
      inodes.add(fields[9]);
    }
  }
  if (inodes.size !== 1) fail('Expected exactly one managed IPv4 TCP LISTEN inode');
  return [...inodes][0];
}

async function descriptors(procPid, inode, budget) {
  for (let attempt = 0; attempt < 3; attempt++) {
    let directory;
    try {
      directory = await budget.resource(() => opendir(`/proc/${procPid}/fd`));
      let count = 0; const owned = [];
      while (true) {
        const entry = await budget.io(() => directory.read());
        if (!entry) return owned.sort((a, b) => Number(a) - Number(b));
        if (!/^(0|[1-9][0-9]{0,9})$/.test(entry.name)) fail('Unsupported proc descriptor entry');
        if (++count > limits.descriptorsPerProcess || ++budget.descriptors > limits.descriptorsTotal)
          fail('Listener observation descriptor limit exceeded');
        const target = await budget.link(`/proc/${procPid}/fd/${entry.name}`);
        if (target === `socket:[${inode}]`) owned.push(entry.name);
      }
    } catch (error) {
      if (error.code !== 'ENOENT' || attempt === 2) throw error;
      if (await gone(procPid, budget)) throw error;
      // A descriptor can close between enumeration and readlink. Retry the
      // whole inventory; never turn that race into a claim of absence.
    } finally { if (directory) await directory.close(); }
  }
}

function options({ master, port, binary } = {}) {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function') fail('Linux /proc observation is required');
  if (!masterShape(master) || !Number.isInteger(port) || port < 1 || port > 65535 || !absolute(binary)
    || master.executable !== binary) fail('Invalid listener observation options', true);
  return { master, port, binary };
}
function validateSnapshot(snapshot, selected) {
  let size;
  try { size = Buffer.byteLength(JSON.stringify(snapshot)); } catch { fail('Snapshot is not JSON data', true); }
  if (size > limits.snapshotBytes || !keys(snapshot, ['schemaVersion', 'scope', 'capturedAt', 'port', 'binary', 'master', 'networkNamespace', 'listenerInode', 'processes', 'sha256']))
    fail('Invalid listener snapshot envelope', true);
  const { sha256, ...record } = snapshot;
  if (snapshot.schemaVersion !== 1 || snapshot.scope !== scope || !/^[a-f0-9]{64}$/.test(sha256)
    || hash(record) !== sha256 || !masterShape(snapshot.master) || !same(snapshot.master, selected.master)
    || snapshot.port !== selected.port || snapshot.binary !== selected.binary
    || !ns(snapshot.networkNamespace, 'net') || !decimal(snapshot.listenerInode)
    || typeof snapshot.capturedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(snapshot.capturedAt)
    || !Number.isFinite(Date.parse(snapshot.capturedAt)) || !Array.isArray(snapshot.processes)
    || !snapshot.processes.length || snapshot.processes.length > limits.children || !snapshot.processes.every(processShape)
    || new Set(snapshot.processes.map(x => x.procPid)).size !== snapshot.processes.length
    || new Set(snapshot.processes.map(x => x.pid)).size !== snapshot.processes.length
    || !snapshot.processes.some(x => x.ownedListenerFds.length)
    || snapshot.processes.some(x => x.parentProcPid !== selected.master.procPid || x.uid !== selected.master.uid
      || x.executable !== selected.binary || x.pidNamespace !== selected.master.pidNamespace || x.networkNamespace !== snapshot.networkNamespace)
    || snapshot.processes.reduce((n, x) => n + x.ownedListenerFds.length, 0) > limits.descriptorsTotal)
    fail('Listener snapshot integrity, scope or identities are invalid', true);
}

async function observed(operation) {
  try { return await operation(); }
  catch (error) {
    if (error.code === 'listener_snapshot_invalid' || error.code === 'listener_observation_unavailable') throw error;
    fail(`Listener observation unresolved (${error.code || 'I/O'}): ${String(error.message).slice(0, 1024)}`);
  }
}

export async function captureTcpListeners(input) {
  const selected = options(input), { master, port, binary } = selected;
  return observed(async () => {
    const budget = new Budget(), actualMaster = await masterIdentity(master, binary, budget);
    const inode = await listener(port, master, budget);
    if (!(await descriptors(master.procPid, inode, budget)).length) fail('Bound master does not own the managed listener');
    const listed = await children(master, budget), processes = [];
    for (const procPid of listed) {
      const before = await identity(procPid, budget);
      if (before.parentProcPid !== master.procPid || before.uid !== master.uid || before.executable !== binary
        || before.pidNamespace !== master.pidNamespace || before.networkNamespace !== actualMaster.networkNamespace)
        fail('Captured child identity is outside the supported native process set');
      const ownedListenerFds = await descriptors(procPid, inode, budget);
      if (!same(before, await identity(procPid, budget))) fail('Child identity changed during listener capture');
      processes.push({ ...before, ownedListenerFds });
    }
    if (!processes.some(x => x.ownedListenerFds.length)) fail('No captured child owns the managed listener');
    if (!same(listed, await children(master, budget))) fail('Observed child-list churn during capture');
    await masterIdentity(master, binary, budget);
    if (await listener(port, master, budget) !== inode) fail('Managed listener changed during capture');
    const record = { schemaVersion: 1, scope, capturedAt: new Date().toISOString(), port, binary, master: { ...master },
      networkNamespace: actualMaster.networkNamespace, listenerInode: inode, processes };
    budget.check();
    return { ...record, sha256: hash(record) };
  });
}

export async function inspectTcpListeners(snapshot, input) {
  const selected = options(input), { master, port, binary } = selected;
  validateSnapshot(snapshot, selected);
  return observed(async () => {
    const budget = new Budget(), actualMaster = await masterIdentity(master, binary, budget);
    if (actualMaster.networkNamespace !== snapshot.networkNamespace || await listener(port, master, budget) !== snapshot.listenerInode)
      fail('Network namespace or managed listener differs from the captured snapshot');
    if (!(await descriptors(master.procPid, snapshot.listenerInode, budget)).length) fail('Bound master no longer owns the managed listener');
    const processes = [];
    for (const captured of snapshot.processes) {
      const { ownedListenerFds: initialFds, ...expected } = captured;
      const before = await identity(captured.procPid, budget, true);
      if (!before) { processes.push({ procPid: captured.procPid, pid: captured.pid, state: 'exited', ownedListenerFds: [] }); continue; }
      if (!same(before, expected)) fail('Captured process identity changed; PID reuse is unresolved');
      let ownedListenerFds;
      try { ownedListenerFds = await descriptors(captured.procPid, snapshot.listenerInode, budget); }
      catch (error) {
        if (['ENOENT', 'ESRCH'].includes(error.code) && await gone(captured.procPid, budget)) {
          processes.push({ procPid: captured.procPid, pid: captured.pid, state: 'exited', ownedListenerFds: [] }); continue;
        }
        throw error;
      }
      const after = await identity(captured.procPid, budget, true);
      if (!after) { processes.push({ procPid: captured.procPid, pid: captured.pid, state: 'exited', ownedListenerFds: [] }); continue; }
      if (!same(after, expected)) fail('Captured process identity changed during descriptor inspection');
      processes.push({ procPid: captured.procPid, pid: captured.pid, state: ownedListenerFds.length ? 'owns-listener' : 'listener-absent', ownedListenerFds });
    }
    await masterIdentity(master, binary, budget);
    if (await listener(port, master, budget) !== snapshot.listenerInode) fail('Managed listener changed during inspection');
    budget.check();
    const closed = processes.every(x => x.state !== 'owns-listener');
    return { scope, state: closed ? 'closed' : 'pending', closed, masterVerified: true,
      port, listenerInode: snapshot.listenerInode, snapshotSha256: snapshot.sha256,
      observedAt: new Date().toISOString(), elapsedMs: Math.round(performance.now() - budget.started), processes,
      limitations: ['Only captured processes are observed; unobserved churn and later generations are outside this snapshot.',
        'Listener absence is not process exit, application health, accepted-connection drain or all-traffic cutover.',
        'Proc identities and descriptor inventories are sampled, with residual check-to-use races.'] };
  });
}
