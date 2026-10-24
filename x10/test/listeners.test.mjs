import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, symlink, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// These fixtures redirect /proc reads only inside this isolated test worker.
// Production has no alternate proc root or filesystem-fault switch.
test('captured listener observation: identities, races, refusal and resource cleanup', { timeout: 30000 }, async t => {
  const original = Object.fromEntries(['open', 'opendir', 'readlink', 'lstat'].map(k => [k, fs.promises[k].bind(fs.promises)]));
  const root = await mkdtemp(path.join(os.tmpdir(), 'x10-listener-unit-'));
  const masterProc = 31000, childProc = 31001, port = 18080, inode = '123456';
  const binary = '/fixture/nginx', command = `nginx: master process ${binary} -p /fixture/ -c /fixture/nginx.conf`;
  const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const master = { pid: 1100, procPid: masterProc, pidNamespace: 'pid:[500]', startTicks: '100', uid: process.getuid(), executable: binary,
    commandSha256: createHash('sha256').update(command).digest('hex') };
  const options = { master, binary, port };
  const sourcePath = new URL('../control/listeners.mjs', import.meta.url);
  const sourceBefore = createHash('sha256').update(await readFile(sourcePath)).digest('hex');
  let fault = null, acquired = 0, closed = 0, directories = 0, directoryCloses = 0;
  const map = file => typeof file === 'string' && file.startsWith('/proc') ? `${root}${file.slice(5)}` : file;
  const error = code => Object.assign(new Error(`Injected ${code}`), { code });
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const trackedHandle = handle => {
    acquired++; const close = handle.close.bind(handle);
    handle.close = async () => { const value = await close(); closed++; return value; }; return handle;
  };
  fs.promises.open = async (file, ...args) => {
    if (fault?.kind === 'status-denied' && file === `/proc/${childProc}/status`) throw error('EACCES');
    if (fault?.kind === 'status-absent' && file === `/proc/${childProc}/status`) throw error('ENOENT');
    if (fault?.kind === 'unrelated-denied' && file === '/proc/32000/status') throw error('EACCES');
    if (fault?.kind === 'child-churn' && file === `/proc/${masterProc}/task/${masterProc}/children` && ++fault.reads === 2)
      await writeFile(map(file), `${childProc} 31002 `);
    const handle = trackedHandle(await original.open(map(file), ...args));
    if (fault?.kind === 'read-esrch' && file === `/proc/${fault.target || childProc}/${fault.file || 'status'}`) {
      handle.read = async () => {
        fault.reads = (fault.reads || 0) + 1;
        if (fault.remove) await rm(map(`/proc/${fault.target || childProc}`), { recursive: true });
        throw error('ESRCH');
      };
    }
    if (fault?.kind === 'open-budget' && !fault.triggered) { fault.triggered = true; await pause(3050); }
    return handle;
  };
  fs.promises.opendir = async (file, ...args) => {
    const directory = await original.opendir(map(file), ...args); directories++;
    const close = directory.close.bind(directory);
    directory.close = async () => { const value = await close(); directoryCloses++; return value; };
    if (fault?.kind === 'directory-budget' && !fault.triggered) { fault.triggered = true; await pause(3050); }
    return directory;
  };
  fs.promises.readlink = async (file, ...args) => {
    if (file === `/proc/${childProc}/fd/7`) {
      if (fault?.kind === 'fd-esrch') {
        fault.reads = (fault.reads || 0) + 1;
        if (fault.remove) await rm(map(`/proc/${childProc}`), { recursive: true });
        throw error('ESRCH');
      }
      if (fault?.kind === 'fd-denied') throw error('EACCES');
      if (fault?.kind === 'fd-absent-always') throw error('ENOENT');
      if (fault?.kind === 'fd-absent-once' && !fault.triggered) { fault.triggered = true; throw error('ENOENT'); }
      if (fault?.kind === 'identity-during-fd' && !fault.triggered) { fault.triggered = true; await writeFile(map(`/proc/${childProc}/stat`), stat(childProc, masterProc, '202')); }
    }
    return original.readlink(map(file), ...args);
  };
  fs.promises.lstat = async (file, ...args) => {
    if (fault && ['read-esrch', 'fd-esrch'].includes(fault.kind) && file === `/proc/${childProc}`) {
      fault.lookups = (fault.lookups || 0) + 1;
      if (fault.reappear && fault.lookups === 2) await proc(childProc, 1101, masterProc, '201', 'nginx: worker process');
      if (fault.lookupErrorAt === fault.lookups) throw error(fault.lookupError);
    }
    return original.lstat(map(file), ...args);
  };
  syncBuiltinESMExports();
  const { captureTcpListeners, inspectTcpListeners } = await import(sourcePath.href);
  const header = '  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
  const row = (address = '0100007F', value = inode) => `  0: ${address}:46A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ${process.getuid()} 0 ${value} 1\n`;
  function stat(procPid, parent, start) { return `${procPid} (nginx) S ${[parent, ...Array(17).fill(0), start, 0, 0].join(' ')}\n`; }
  async function proc(procPid, localPid, parent, start, title) {
    const base = map(`/proc/${procPid}`);
    await mkdir(`${base}/ns`, { recursive: true }); await mkdir(`${base}/fd`);
    await writeFile(`${base}/status`, `Name:\tnginx\nPPid:\t${parent}\nUid:\t${Array(4).fill(process.getuid()).join('\t')}\nNSpid:\t${procPid}\t${localPid}\n`);
    await writeFile(`${base}/stat`, stat(procPid, parent, start)); await writeFile(`${base}/cmdline`, `${title}\0`);
    await symlink(binary, `${base}/exe`); await symlink('pid:[500]', `${base}/ns/pid`); await symlink('net:[600]', `${base}/ns/net`);
    await symlink(`socket:[${inode}]`, `${base}/fd/7`);
  }
  async function fresh() {
    fault = null;
    for (const name of await fs.promises.readdir(root)) await rm(path.join(root, name), { recursive: true, force: true });
    await mkdir(`${root}/self/ns`, { recursive: true });
    await symlink('pid:[500]', `${root}/self/ns/pid`); await symlink('net:[600]', `${root}/self/ns/net`);
    await proc(masterProc, master.pid, 1, master.startTicks, command); await proc(childProc, 1101, masterProc, '200', 'nginx: worker process');
    await mkdir(`${root}/${masterProc}/task/${masterProc}`, { recursive: true }); await writeFile(`${root}/${masterProc}/task/${masterProc}/children`, `${childProc} `);
    await mkdir(`${root}/${masterProc}/net`); await writeFile(`${root}/${masterProc}/net/tcp`, header + row());
    await writeFile(`${root}/${masterProc}/net/tcp6`, header.replace('rem_address', 'remote_address'));
  }
  const unavailable = fn => assert.rejects(fn, { code: 'listener_observation_unavailable' });
  const invalid = fn => assert.rejects(fn, { code: 'listener_snapshot_invalid' });
  const signed = value => { const { sha256, ...record } = value; return { ...record, sha256: digest(record) }; };
  async function check(name, fn) {
    await t.test(name, async () => { await fresh(); await fn(); assert.equal(acquired, closed, 'all acquired file handles closed'); assert.equal(directories, directoryCloses, 'all acquired directories closed'); });
  }
  try {
    await check('captures host-view and local PID identity and exact inode ownership', async () => {
      const s = await captureTcpListeners(options); assert.equal(s.scope, 'captured-processes-only'); assert.equal(s.processes.length, 1);
      assert.equal(s.processes[0].procPid, childProc); assert.equal(s.processes[0].pid, 1101); assert.deepEqual(s.processes[0].ownedListenerFds, ['7']);
    });
    await check('present captured descriptor remains pending', async () => { const s = await captureTcpListeners(options); const r = await inspectTcpListeners(s, options); assert.equal(r.closed, false); assert.equal(r.state, 'pending'); });
    await check('descriptor absence with unchanged living identity is closed', async () => { const s = await captureTcpListeners(options); await rm(`${root}/${childProc}/fd/7`); const r = await inspectTcpListeners(s, options); assert.equal(r.closed, true); assert.equal(r.processes[0].state, 'listener-absent'); });
    await check('two absent process directory observations report exited', async () => { const s = await captureTcpListeners(options); await rm(`${root}/${childProc}`, { recursive: true }); assert.equal((await inspectTcpListeners(s, options)).processes[0].state, 'exited'); });
    await check('reused PID with new start ticks stays unresolved', async () => { const s = await captureTcpListeners(options); await writeFile(`${root}/${childProc}/stat`, stat(childProc, masterProc, '201')); await unavailable(() => inspectTcpListeners(s, options)); });
    await check('changed master command stays unresolved', async () => { const s = await captureTcpListeners(options); await writeFile(`${root}/${masterProc}/cmdline`, `${command} changed\0`); await unavailable(() => inspectTcpListeners(s, options)); });
    await check('changed network namespace stays unresolved', async () => { const s = await captureTcpListeners(options); await rm(`${root}/${masterProc}/ns/net`); await symlink('net:[601]', `${root}/${masterProc}/ns/net`); await unavailable(() => inspectTcpListeners(s, options)); });
    await check('master listener ownership is required', async () => { const s = await captureTcpListeners(options); await rm(`${root}/${masterProc}/fd/7`); await unavailable(() => inspectTcpListeners(s, options)); });
    await check('changed managed listener inode stays unresolved', async () => { const s = await captureTcpListeners(options); await writeFile(`${root}/${masterProc}/net/tcp`, header + row('0100007F', '123457')); await unavailable(() => inspectTcpListeners(s, options)); });
    await check('wildcard address is refused', async () => { await writeFile(`${root}/${masterProc}/net/tcp`, header + row() + row('00000000', '123457')); await unavailable(() => captureTcpListeners(options)); });
    await check('same-port TCP6 listener is refused', async () => { await writeFile(`${root}/${masterProc}/net/tcp6`, header + row('00000000000000000000000001000000')); await unavailable(() => captureTcpListeners(options)); });
    await check('multiple exact managed listener inodes are refused', async () => { await writeFile(`${root}/${masterProc}/net/tcp`, header + row() + row('0100007F', '123457')); await unavailable(() => captureTcpListeners(options)); });
    await check('descriptor permission denial cannot become closed', async () => { const s = await captureTcpListeners(options); fault = { kind: 'fd-denied' }; await unavailable(() => inspectTcpListeners(s, options)); });
    await check('process status permission denial cannot become exited', async () => { const s = await captureTcpListeners(options); fault = { kind: 'status-denied' }; await unavailable(() => inspectTcpListeners(s, options)); });
    await check('missing status while process directory exists cannot become exited', async () => { const s = await captureTcpListeners(options); fault = { kind: 'status-absent' }; await unavailable(() => inspectTcpListeners(s, options)); });
    await check('one descriptor ENOENT race is retried as full inventory', async () => { const s = await captureTcpListeners(options); fault = { kind: 'fd-absent-once' }; assert.equal((await inspectTcpListeners(s, options)).closed, false); assert.equal(fault.triggered, true); });
    await check('persistent descriptor ENOENT stays unresolved', async () => { const s = await captureTcpListeners(options); fault = { kind: 'fd-absent-always' }; await unavailable(() => inspectTcpListeners(s, options)); });
    // A proc file opened while alive can return ESRCH at read time after exit.
    // The injected read below is separate from the independent directory proof.
    await check('post-open status ESRCH plus two absent directories reports exited', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', remove: true };
      const r = await inspectTcpListeners(s, options);
      assert.equal(r.processes[0].state, 'exited'); assert.equal(r.closed, true);
      assert.equal(fault.reads, 1); assert.equal(fault.lookups, 2);
    });
    await check('post-open stat ESRCH plus two absent directories reports exited', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', file: 'stat', remove: true };
      assert.equal((await inspectTcpListeners(s, options)).processes[0].state, 'exited');
      assert.equal(fault.reads, 1); assert.equal(fault.lookups, 2);
    });
    await check('post-open status ESRCH with present directory stays unresolved', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch' };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 1);
    });
    await check('post-open stat ESRCH with present directory stays unresolved', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', file: 'stat' };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 1);
    });
    await check('post-open ESRCH with reappearing process directory stays unresolved', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', remove: true, reappear: true };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 2);
    });
    await check('post-open ESRCH with denied absence lookup stays unresolved', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', remove: true, lookupErrorAt: 1, lookupError: 'EACCES' };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 1);
    });
    await check('post-open ESRCH with second lookup ESRCH cannot prove exit', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', remove: true, lookupErrorAt: 2, lookupError: 'ESRCH' };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 2);
    });
    await check('descriptor ESRCH plus two absent directories reports exited', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'fd-esrch', remove: true };
      assert.equal((await inspectTcpListeners(s, options)).processes[0].state, 'exited');
      assert.equal(fault.reads, 1); assert.equal(fault.lookups, 2);
    });
    await check('descriptor ESRCH with present process is not retried or called absent', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'fd-esrch' };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.reads, 1); assert.equal(fault.lookups, 1);
    });
    await check('descriptor ESRCH with reappearing process directory stays unresolved', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'fd-esrch', remove: true, reappear: true };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.lookups, 2);
    });
    await check('capture does not accept post-open child ESRCH as an exit proof', async () => {
      fault = { kind: 'read-esrch', remove: true };
      await unavailable(() => captureTcpListeners(options)); assert.equal(fault.reads, 1); assert.equal(fault.lookups || 0, 0);
    });
    await check('master post-open ESRCH remains unresolved without exit classification', async () => {
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', target: masterProc, remove: true };
      await unavailable(() => inspectTcpListeners(s, options)); assert.equal(fault.reads, 1); assert.equal(fault.lookups || 0, 0);
    });
    await check('one confirmed exited process cannot hide another captured listener owner', async () => {
      await proc(31002, 1102, masterProc, '300', 'nginx: worker process');
      await writeFile(`${root}/${masterProc}/task/${masterProc}/children`, `${childProc} 31002 `);
      const s = await captureTcpListeners(options); fault = { kind: 'read-esrch', remove: true };
      const r = await inspectTcpListeners(s, options);
      assert.equal(r.state, 'pending'); assert.equal(r.closed, false);
      assert.equal(r.processes[0].state, 'exited'); assert.equal(r.processes[1].state, 'owns-listener');
      assert.equal(fault.lookups, 2);
    });
    await check('identity change during descriptor scan stays unresolved', async () => { const s = await captureTcpListeners(options); fault = { kind: 'identity-during-fd' }; await unavailable(() => inspectTcpListeners(s, options)); });
    await check('snapshot tampering is refused before proc inspection', async () => { const s = await captureTcpListeners(options); s.port++; await invalid(() => inspectTcpListeners(s, options)); });
    await check('hash-valid empty captured process set is refused', async () => { const s = await captureTcpListeners(options); s.processes = []; await invalid(() => inspectTcpListeners(signed(s), options)); });
    await check('hash-valid unsupported process count is refused', async () => { const s = await captureTcpListeners(options); s.processes = Array(513).fill(s.processes[0]); await invalid(() => inspectTcpListeners(signed(s), options)); });
    await check('master key insertion order does not change identity', async () => { const reordered = Object.fromEntries(Object.entries(master).reverse()); const s = await captureTcpListeners({ ...options, master: reordered }); assert.equal((await inspectTcpListeners(s, options)).state, 'pending'); });
    await check('missing task children file falls back to bounded PPid scan', async () => { await rm(`${root}/${masterProc}/task/${masterProc}/children`); const s = await captureTcpListeners(options); assert.equal(s.processes.length, 1); assert.equal(s.processes[0].procPid, childProc); });
    await check('unreadable fallback inventory status is unresolved', async () => { await rm(`${root}/${masterProc}/task/${masterProc}/children`); await mkdir(`${root}/32000`); fault = { kind: 'unrelated-denied' }; await unavailable(() => captureTcpListeners(options)); });
    await check('observed child set churn refuses capture', async () => { fault = { kind: 'child-churn', reads: 0 }; await unavailable(() => captureTcpListeners(options)); });
    await check('TCP table byte cap refuses oversized proc input', async () => { await writeFile(`${root}/${masterProc}/net/tcp`, header + ' '.repeat(1024 * 1024)); await unavailable(() => captureTcpListeners(options)); });
    await check('acquired file is closed when elapsed budget expires during open', async () => { fault = { kind: 'open-budget' }; await unavailable(() => captureTcpListeners(options)); assert.equal(fault.triggered, true); });
    await check('acquired directory is closed when elapsed budget expires during opendir', async () => { fault = { kind: 'directory-budget' }; await unavailable(() => captureTcpListeners(options)); assert.equal(fault.triggered, true); });
    assert.equal(createHash('sha256').update(await readFile(sourcePath)).digest('hex'), sourceBefore, 'module unchanged during controls');
  } finally {
    for (const [key, fn] of Object.entries(original)) fs.promises[key] = fn;
    syncBuiltinESMExports(); await rm(root, { recursive: true, force: true });
  }
});
