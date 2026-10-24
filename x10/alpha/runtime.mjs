// Local alpha process identity. No process is signalled by these helpers.
import { readFile, readdir, readlink, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function fail(code, message) { throw Object.assign(new Error(message), { code }); }
export const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const simple = value => typeof value === 'string' && /^\/[A-Za-z0-9_./+-]+$/.test(value) && path.resolve(value) === value;
export async function owned(file, directory = false, privateDirectory = false) {
  const stat = await lstat(file);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) || stat.uid !== process.getuid()) fail('unsafe_path', `Expected owned regular ${directory ? 'directory' : 'file'}: ${file}`);
  if (privateDirectory ? (stat.mode & 0o077) !== 0 : (stat.mode & 0o022) !== 0) fail('unsafe_permissions', `Unsafe permissions: ${file}`);
  return stat;
}
export async function canonical(file) {
  if (!simple(file) || await realpath(file) !== file) fail('unsafe_path', `Expected simple canonical path: ${file}`);
  return file;
}
export async function exists(file) { try { await lstat(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }

async function procIdentity(procPid, binary, prefix) {
  const base = `/proc/${procPid}`;
  const [status, stat, executable, pidNamespace, networkNamespace, cmdline] = await Promise.all([
    readFile(`${base}/status`, 'utf8'), readFile(`${base}/stat`, 'utf8'), readlink(`${base}/exe`),
    readlink(`${base}/ns/pid`), readlink(`${base}/ns/net`), readFile(`${base}/cmdline`, 'utf8'),
  ]);
  if (Buffer.byteLength(status) + Buffer.byteLength(stat) + Buffer.byteLength(cmdline) > 128 * 1024) fail('runtime_identity', 'Proc identity exceeds supported size');
  const ids = /^NSpid:\s+([0-9\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
  const uid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]);
  const fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
  const title = cmdline.split('\0')[0], tokens = title.replace(/^nginx: master process /, '').trim().split(/\s+/);
  const pair = (flag, expected) => tokens.filter(v => v === flag).length === 1 && tokens[tokens.indexOf(flag) + 1]?.replace(/\/$/, '') === expected.replace(/\/$/, '');
  if (!ids?.length || !Number.isSafeInteger(ids.at(-1)) || ids.at(-1) < 2 || uid !== process.getuid() || executable !== binary
    || ['Z', 'X'].includes(fields[0]) || !/^[0-9]+$/.test(fields[19]) || !title.startsWith('nginx: master process ')
    || tokens[0] !== binary || !pair('-p', prefix) || !pair('-c', path.join(prefix, 'nginx.conf')))
    fail('runtime_identity', 'Process is not this owned alpha native master');
  return { pid: ids.at(-1), procPid: Number(procPid), pidNamespace, startTicks: fields[19], uid, executable, commandSha256: digest(title), networkNamespace };
}

export async function findMasters(binary, prefix) {
  const entries = (await readdir('/proc')).filter(name => /^[1-9][0-9]*$/.test(name));
  if (entries.length > 10000) fail('runtime_identity', 'Proc inventory exceeds supported limit');
  const found = [];
  for (let index = 0; index < entries.length; index += 32) {
    const values = await Promise.all(entries.slice(index, index + 32).map(async name => {
      let status, cmdline;
      try {
        status = await readFile(`/proc/${name}/status`, 'utf8');
        if (Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]) !== process.getuid()) return null;
        cmdline = (await readFile(`/proc/${name}/cmdline`, 'utf8')).split('\0')[0];
        if (!cmdline.startsWith('nginx: master process ')) return null;
        const tokens = cmdline.slice('nginx: master process '.length).trim().split(/\s+/);
        const argument = flag => tokens[tokens.indexOf(flag) + 1]?.replace(/\/$/, '');
        if (argument('-p') !== prefix && argument('-c') !== path.join(prefix, 'nginx.conf')) return null;
        return await procIdentity(name, binary, prefix);
      } catch (error) {
        if (['ENOENT', 'ESRCH'].includes(error.code)) return null;
        if (error.code === 'runtime_identity') {
          // Proc reads are not atomic: a master can disappear after the
          // prefilter and leave an inconsistent identity snapshot. Only an
          // absent entry resolves that observation; existing entries, even
          // zombies, retain the original strict identity refusal.
          try { await lstat(`/proc/${name}`); }
          catch (absence) { if (absence.code === 'ENOENT') return null; throw absence; }
        }
        throw error;
      }
    }));
    found.push(...values.filter(Boolean));
  }
  return found;
}

export async function inspectMaster(binary, prefix, expected, requirePidFile = true) {
  const pidNamespace = await readlink('/proc/self/ns/pid'), networkNamespace = await readlink('/proc/self/ns/net');
  if (expected && (expected.pidNamespace !== pidNamespace || expected.networkNamespace !== networkNamespace)) fail('runtime_namespace', 'Alpha must run in its recorded PID/network namespaces');
  const found = await findMasters(binary, prefix);
  if (!found.length) {
    if (expected) {
      try {
        // A reused/inaccessible proc entry is unresolved, never treated as the
        // recorded process still being safe to signal or remove.
        await lstat(`/proc/${expected.procPid}`);
        fail('runtime_identity', 'Recorded PID now exists without the expected master identity');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    return null;
  }
  if (found.length !== 1 || (expected && !same(found[0], expected))) fail('runtime_identity', 'Alpha master identity changed or is ambiguous');
  const actual = found[0];
  if (actual.pidNamespace !== pidNamespace || actual.networkNamespace !== networkNamespace) fail('runtime_namespace', 'Native master namespace differs from caller');
  if (requirePidFile) {
    const file = path.join(prefix, 'nginx.pid'); await owned(file);
    const text = await readFile(file, 'utf8');
    if (!/^[1-9][0-9]*\n?$/.test(text) || Number(text.trim()) !== actual.pid) fail('runtime_identity', 'PID file does not match the owned alpha master');
  }
  return actual;
}

export async function remainingNativeGroup(binary, expected) {
  if (!expected) return [];
  const entries = (await readdir('/proc')).filter(name => /^[1-9][0-9]*$/.test(name));
  if (entries.length > 10000) fail('runtime_identity', 'Proc inventory exceeds supported limit');
  const members = [];
  for (const procPid of entries) {
    try {
      const stat = await readFile(`/proc/${procPid}/stat`, 'utf8'), fields = stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/);
      if (fields[2] !== String(expected.procPid) || ['Z', 'X'].includes(fields[0])) continue;
      if (await readlink(`/proc/${procPid}/ns/pid`) !== expected.pidNamespace || await readlink(`/proc/${procPid}/exe`) !== binary) fail('runtime_identity', 'Recorded native process group contains an unresolved process');
      const status = await readFile(`/proc/${procPid}/status`, 'utf8'); if (Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]) !== expected.uid) fail('runtime_identity', 'Recorded native process group owner changed');
      members.push(Number(procPid));
    } catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error; }
  }
  return members;
}
