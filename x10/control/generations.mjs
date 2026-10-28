// Read-only native generation diagnostic for an explicitly selected local API.
// The manager verifies the bound native master and registered files around this call.
import { open, opendir, readlink, lstat, realpath } from 'node:fs/promises';
import { endianness } from 'node:os';
import { createHash } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';

const UINT64_MAX = 18446744073709551615n;
const MAX_PROCESSES = 1024;
const MAX_BODY = 512 * 1024;
const HTTP_DEADLINE_MS = 1500;
const IO_BUDGET_MS = 3000;
function fail(code, message) { throw Object.assign(new Error(message), { code }); }
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value, low, high) => Number.isSafeInteger(value) && value >= low && value <= high;
const u64 = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= UINT64_MAX;

export function validateGenerations(data, masterPid) {
  const rootKeys = ['scope', 'master_pid', 'current_generation', 'available', 'reason', 'excluded_detached', 'processes'];
  const processKeys = ['name', 'pid', 'slot', 'generation', 'birth', 'exiting', 'exited'];
  if (!exact(data, rootKeys) || data.scope !== 'master-process' || data.master_pid !== masterPid
    || !integer(data.master_pid, 2, 2147483647) || typeof data.available !== 'boolean'
    || !['', 'unclassified_process', 'counter_exhausted', 'uninitialized'].includes(data.reason)
    || !(data.current_generation === null || u64(data.current_generation))
    || !integer(data.excluded_detached, 0, MAX_PROCESSES) || !Array.isArray(data.processes)
    || data.processes.length + data.excluded_detached > MAX_PROCESSES)
    fail('generation_schema', 'Native generations response has invalid scope, master identity or envelope');
  const slots = new Set(), pids = new Set(), births = new Set(); let unclassified = 0;
  for (const child of data.processes) {
    if (!exact(child, processKeys) || typeof child.name !== 'string' || !child.name.length
      || Buffer.byteLength(child.name) > 256 || /[\x00-\x1f\x7f]/.test(child.name)
      || !integer(child.pid, 2, 2147483647) || child.pid === masterPid || !integer(child.slot, 0, MAX_PROCESSES - 1)
      || slots.has(child.slot) || pids.has(child.pid) || typeof child.exiting !== 'boolean' || typeof child.exited !== 'boolean'
      || !(child.generation === null || u64(child.generation)) || !(child.birth === null || u64(child.birth)))
      fail('generation_schema', 'Native generation process identity or counter is invalid');
    slots.add(child.slot); pids.add(child.pid);
    if (child.birth !== null) { if (births.has(child.birth)) fail('generation_schema', 'Native process birth IDs are not unique'); births.add(child.birth); }
    if (child.generation !== null && child.birth === null) fail('generation_schema', 'A classified process generation requires a birth identity');
    if (child.generation === null || child.birth === null) unclassified++;
    if (child.generation !== null && (data.current_generation === null || BigInt(child.generation) > BigInt(data.current_generation)))
      fail('generation_schema', 'Native process generation exceeds the installed master generation');
  }
  if (data.available ? data.reason !== '' || data.current_generation === null || unclassified !== 0
    : data.reason === '' || (data.reason === 'unclassified_process'
      ? data.current_generation === null || unclassified === 0
      : data.current_generation !== null || data.processes.some(p => p.birth !== null || p.generation !== null)))
    fail('generation_schema', 'Native generation availability and nullable identities contradict each other');
  return data;
}

export function generationEndpoint({ controlSocket, controlAddress } = {}) {
  if ((controlSocket !== undefined) === (controlAddress !== undefined)) fail('generation_endpoint', 'Exactly one explicit control socket or loopback address is required');
  if (controlSocket !== undefined) {
    if (typeof controlSocket !== 'string' || !/^\/[A-Za-z0-9_./+-]+$/.test(controlSocket)
      || path.resolve(controlSocket) !== controlSocket || Buffer.byteLength(controlSocket) > 107)
      fail('generation_endpoint', 'Control socket must be a simple canonical absolute Unix path of at most 107 bytes');
    return { transport: 'unix', socketPath: controlSocket };
  }
  if (typeof controlAddress !== 'string' || !/^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(controlAddress))
    fail('generation_endpoint', 'Control address must be explicitly 127.0.0.1:port');
  const port = Number(controlAddress.slice(10));
  if (!integer(port, 1, 65535)) fail('generation_endpoint', 'Control port must be 1..65535');
  return { transport: 'tcp', host: '127.0.0.1', port };
}

class Budget {
  constructor() { this.started = performance.now(); }
  check() { if (performance.now() - this.started > IO_BUDGET_MS) fail('generation_timeout', 'Native generation observation exceeded its checked I/O budget'); }
  async io(fn) { this.check(); const value = await fn(); this.check(); return value; }
  async resource(fn) { this.check(); const value = await fn(); try { this.check(); return value; } catch (error) { await value.close(); throw error; } }
  async read(file, cap) {
    const handle = await this.resource(() => open(file, 'r')); const chunks = []; let bytes = 0;
    try {
      while (true) {
        const buffer = Buffer.alloc(Math.min(16384, cap + 1 - bytes));
        const read = await this.io(() => handle.read(buffer, 0, buffer.length, null));
        if (!read.bytesRead) return Buffer.concat(chunks, bytes).toString('utf8');
        bytes += read.bytesRead; if (bytes > cap) fail('generation_endpoint', 'Control endpoint procfs metadata exceeds its byte limit');
        chunks.push(buffer.subarray(0, read.bytesRead));
      }
    } finally { await handle.close(); }
  }
}

async function verifyLifetime(master, budget) {
  const base = `/proc/${master.procPid}`;
  const status = await budget.read(`${base}/status`, 65536);
  const stat = await budget.read(`${base}/stat`, 65536);
  const cmdline = await budget.read(`${base}/cmdline`, 65536);
  const nspid = /^NSpid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
  const fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
  const commandSha256 = createHash('sha256').update(cmdline.split('\0')[0]).digest('hex');
  if (nspid?.[0] !== master.procPid || nspid?.at(-1) !== master.pid
    || Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]) !== master.uid || fields[19] !== master.startTicks
    || ['Z', 'X'].includes(fields[0]) || commandSha256 !== master.commandSha256
    || await budget.io(() => readlink(`${base}/exe`)) !== master.executable)
    fail('generation_endpoint', 'Bound master process lifetime changed during generation inspection');
}

async function ownsDescriptor(procPid, inode, budget) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const directory = await budget.resource(() => opendir(`/proc/${procPid}/fd`)); let owned = false, count = 0;
    try {
      while (true) {
        const entry = await budget.io(() => directory.read()); if (!entry) return owned;
        if (++count > 4096) fail('generation_endpoint', 'Bound master descriptor inventory exceeds 4096 entries');
        if (await budget.io(() => readlink(`/proc/${procPid}/fd/${entry.name}`)) === `socket:[${inode}]`) owned = true;
      }
    } catch (error) {
      if (error.code !== 'ENOENT' || attempt === 2) throw error;
    } finally { await directory.close(); }
  }
  return false;
}

async function ownedEndpoint(endpoint, master, budget) {
  const base = `/proc/${master.procPid}`;
  await verifyLifetime(master, budget);
  const [net, ownNet, pidNS] = await Promise.all([
    budget.io(() => readlink(`${base}/ns/net`)), budget.io(() => readlink('/proc/self/ns/net')),
    budget.io(() => readlink(`${base}/ns/pid`)),
  ]);
  if (net !== ownNet || pidNS !== master.pidNamespace) fail('generation_endpoint', 'Control endpoint and bound master must share the controller network and PID namespaces');
  const inodes = new Set();
  if (endpoint.transport === 'unix') {
    const info = await budget.io(() => lstat(endpoint.socketPath));
    if (!info.isSocket() || info.uid !== master.uid || (info.mode & 0o077) !== 0
      || await budget.io(() => realpath(endpoint.socketPath)) !== endpoint.socketPath)
      fail('generation_endpoint', 'Expected an owned private canonical native control socket');
    const table = await budget.read(`${base}/net/unix`, 1024 * 1024);
    for (const line of table.trim().split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields.length >= 8 && fields.slice(7).join(' ') === endpoint.socketPath && fields[4] === '0001'
        && fields[5] === '01' && (parseInt(fields[3], 16) & 0x10000) !== 0 && /^[1-9][0-9]*$/.test(fields[6])) inodes.add(fields[6]);
    }
  } else {
    const address = endianness() === 'LE' ? '0100007F' : '7F000001';
    const table = await budget.read(`${base}/net/tcp`, 1024 * 1024);
    for (const line of table.trim().split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/), local = fields[1]?.split(':');
      if (fields[3] === '0A' && local?.[0] === address && parseInt(local[1], 16) === endpoint.port
        && /^[1-9][0-9]*$/.test(fields[9])) inodes.add(fields[9]);
    }
  }
  if (inodes.size !== 1) fail('generation_endpoint', 'Expected one selected control LISTEN inode in the bound master namespace');
  const inode = [...inodes][0];
  if (!await ownsDescriptor(master.procPid, inode, budget)) fail('generation_endpoint', 'The selected control endpoint is not owned by the bound native master');
  await verifyLifetime(master, budget);
  return { inode, networkNamespace: net };
}

function fetchGenerations(endpoint) {
  return new Promise((resolve, reject) => {
    const selected = endpoint.transport === 'unix' ? { socketPath: endpoint.socketPath } : { host: endpoint.host, port: endpoint.port };
    const req = http.request({ ...selected, method: 'GET', path: '/1/control/generations', agent: false,
      maxHeaderSize: 16384, headers: { connection: 'close', accept: 'application/json' } }, res => {
      let bytes = 0; const chunks = [];
      res.once('error', reject);
      res.once('aborted', () => reject(Object.assign(new Error('Native generations response was incomplete'), { code: 'generation_unavailable' })));
      if (res.statusCode !== 200) { req.destroy(Object.assign(new Error(`Native generations endpoint returned HTTP ${res.statusCode}`), { code: 'generation_unavailable' })); return; }
      if (!/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] || '') || res.headers['content-encoding']) {
        req.destroy(Object.assign(new Error('Native generations response must be uncompressed application/json'), { code: 'generation_schema' })); return;
      }
      res.on('data', chunk => { bytes += chunk.length; if (bytes > MAX_BODY) req.destroy(Object.assign(new Error('Native generations response exceeds 512 KiB'), { code: 'generation_schema' })); else chunks.push(chunk); });
      res.once('end', () => { try { resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); } catch { reject(Object.assign(new Error('Native generations response is not valid JSON'), { code: 'generation_schema' })); } });
    });
    req.maxHeadersCount = 64;
    const timer = setTimeout(() => req.destroy(Object.assign(new Error('Native generations absolute request deadline exceeded'), { code: 'generation_timeout' })), HTTP_DEADLINE_MS);
    req.once('close', () => clearTimeout(timer)); req.once('error', reject); req.end();
  });
}

export async function inspectNativeGenerations(options, master) {
  const endpoint = generationEndpoint(options), budget = new Budget();
  if (!master || !integer(master.pid, 2, 2147483647) || !integer(master.procPid, 2, 2147483647)) fail('generation_endpoint', 'A verified bound master identity is required');
  try {
    const before = await ownedEndpoint(endpoint, master, budget);
    const data = validateGenerations(await fetchGenerations(endpoint), master.pid); budget.check();
    const after = await ownedEndpoint(endpoint, master, budget);
    if (before.inode !== after.inode || before.networkNamespace !== after.networkNamespace)
      fail('generation_endpoint', 'Selected native control endpoint changed during the observation');
    return { schemaVersion: 1, observedAt: new Date().toISOString(), endpoint, endpointIdentity: after, masterBinding: master,
      native: data, diagnosticOnly: true, limitations: ['Counters belong to this verified master lifetime only.',
        'Metadata classification is not worker readiness, health, listener closure or accepted-connection drain.',
        'Procfs and file guards are sampled; checked I/O budgets cannot cancel a stalled kernel syscall.'] };
  } catch (error) {
    if (['generation_endpoint', 'generation_schema', 'generation_unavailable', 'generation_timeout'].includes(error.code)) throw error;
    fail('generation_endpoint', `Native generation observation is unresolved (${error.code || 'I/O'}): ${String(error.message).slice(0, 512)}`);
  }
}
