// Synthetic proc interleavings exercise the real runtime module. They neither
// signal processes nor establish the cause of an earlier native CI failure.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const binary = '/fixture/nginx', prefix = '/fixture/install', procPid = 501;
const pidNamespace = 'pid:[fixture]', networkNamespace = 'net:[fixture]';
const title = `nginx: master process ${binary} -p ${prefix} -c ${prefix}/nginx.conf`;
const uid = process.getuid();
const error = code => Object.assign(new Error(`Synthetic proc error: ${code}`), { code });
const regular = () => ({ uid, mode: 0o100600, isSymbolicLink: () => false, isFile: () => true, isDirectory: () => false });

function fixture(options = {}) {
  const calls = { status: options.initialStatusReads || 0, cmdline: 0, procLstat: 0 };
  const fields = Array(20).fill('0');
  fields[0] = options.state || 'S'; fields[1] = '1';
  fields[2] = String(procPid); fields[19] = options.startTicks || '1234';
  const status = owner => `Uid:\t${owner}\t${owner}\t${owner}\t${owner}\nNSpid:\t${procPid}\n`;
  return {
    calls,
    async readdir(file) { assert.equal(file, '/proc'); return [String(procPid)]; },
    async readFile(file) {
      if (file === `/proc/${procPid}/status`) return status(++calls.status === 1 ? uid : (options.uid ?? uid));
      if (file === `/proc/${procPid}/cmdline`) return `${++calls.cmdline === 1 ? title : (options.title ?? title)}\0`;
      if (file === `/proc/${procPid}/stat`) {
        if (options.statError) throw error(options.statError);
        return `${procPid} (nginx) ${fields.join(' ')}`;
      }
      if (file === `${prefix}/nginx.pid`) return `${options.pidFile ?? procPid}\n`;
      throw error('ENOENT');
    },
    async readlink(file) {
      if (file === '/proc/self/ns/pid') return options.selfPidNamespace || pidNamespace;
      if (file === '/proc/self/ns/net') return options.selfNetworkNamespace || networkNamespace;
      if (file === `/proc/${procPid}/exe`) return options.executable || binary;
      if (file === `/proc/${procPid}/ns/pid`) return options.pidNamespace || pidNamespace;
      if (file === `/proc/${procPid}/ns/net`) return options.networkNamespace || networkNamespace;
      throw error('ENOENT');
    },
    async lstat(file) {
      if (file === `/proc/${procPid}`) {
        calls.procLstat++;
        if (options.procLstatError) throw error(options.procLstatError);
        if (options.absent && (!options.reappears || calls.procLstat === 1)) throw error('ENOENT');
        return regular();
      }
      if (file === `${prefix}/nginx.pid`) return regular();
      throw error('ENOENT');
    },
    async realpath(file) { return file; },
  };
}

async function withRuntime(options, fn) {
  const fs = fixture(options), key = `x10SyntheticProc_${randomUUID()}`;
  // A private import substitution keeps test control out of the product API.
  // The runtime source, validation logic and built-in crypto/path are unchanged.
  globalThis[key] = fs;
  const adapter = `const fs = globalThis[${JSON.stringify(key)}];\n${['readFile', 'readdir', 'readlink', 'lstat', 'realpath'].map(name => `export const ${name} = (...args) => fs.${name}(...args);`).join('\n')}`;
  const adapterUrl = `data:text/javascript;base64,${Buffer.from(adapter).toString('base64')}`;
  const source = await readFile(new URL('../alpha/runtime.mjs', import.meta.url), 'utf8');
  const needle = "from 'node:fs/promises'";
  assert.equal(source.split(needle).length, 2, 'Private fixture must replace exactly one filesystem import');
  const instrumented = `${source.replace(needle, `from '${adapterUrl}'`)}\n//# sourceURL=x10-alpha-runtime-synthetic.mjs\n`;
  try {
    const runtime = await import(`data:text/javascript;base64,${Buffer.from(instrumented).toString('base64')}`);
    const expected = { pid: procPid, procPid, pidNamespace, startTicks: '1234', uid, executable: binary, commandSha256: runtime.digest(title), networkNamespace };
    return await fn(runtime, expected, fs.calls);
  } finally { delete globalThis[key]; }
}

test('synthetic proc exit interleavings require observed directory absence', async t => {
  for (const [name, snapshot] of [['zombie', { state: 'Z' }], ['dead', { state: 'X' }], ['empty command', { title: '' }]]) {
    await t.test(`${name} snapshot followed by two absence checks`, () => withRuntime({ ...snapshot, absent: true }, async (runtime, expected, calls) => {
      assert.equal(await runtime.inspectMaster(binary, prefix, expected, false), null);
      assert.equal(calls.procLstat, 2, 'Both candidate and recorded PID must be absent');
    }));
    await t.test(`${name} snapshot with a persistent directory is refused`, () => withRuntime(snapshot, async (runtime, expected) => {
      await assert.rejects(runtime.inspectMaster(binary, prefix, expected, false), { code: 'runtime_identity' });
    }));
  }
  await t.test('recorded PID reappearing after candidate absence is refused', () => withRuntime({ state: 'Z', absent: true, reappears: true }, async (runtime, expected, calls) => {
    await assert.rejects(runtime.inspectMaster(binary, prefix, expected, false), { code: 'runtime_identity' });
    assert.equal(calls.procLstat, 2);
  }));
  for (const code of ['EACCES', 'EIO', 'ESRCH']) {
    await t.test(`directory recheck ${code} is unresolved`, () => withRuntime({ state: 'Z', procLstatError: code }, async (runtime, expected) => {
      await assert.rejects(runtime.inspectMaster(binary, prefix, expected, false), { code });
    }));
  }
  await t.test('unexpected proc read error propagates', () => withRuntime({ statError: 'EACCES', absent: true }, async (runtime, expected) => {
    await assert.rejects(runtime.inspectMaster(binary, prefix, expected, false), { code: 'EACCES' });
  }));
});

test('synthetic proc identity and pre-signal guards remain strict', async t => {
  await t.test('exact live identity and PID file are accepted', () => withRuntime({}, async (runtime, expected, calls) => {
    assert.deepEqual(await runtime.inspectMaster(binary, prefix, expected), expected);
    assert.equal(calls.procLstat, 0);
  }));
  const changed = [
    ['UID', { uid: uid + 1 }], ['executable', { executable: '/fixture/foreign' }],
    ['start ticks', { startTicks: '9999' }], ['PID namespace', { pidNamespace: 'pid:[foreign]' }],
    ['network namespace', { networkNamespace: 'net:[foreign]' }],
    ['command prefix', { title: title.replace(prefix, '/fixture/foreign') }],
    ['foreign PID file', { pidFile: procPid + 1 }],
  ];
  for (const [name, options] of changed) await t.test(`${name} mismatch is refused`, () => withRuntime(options, async (runtime, expected) => {
    await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_identity' });
  }));
  for (const options of [{ selfPidNamespace: 'pid:[foreign]' }, { selfNetworkNamespace: 'net:[foreign]' }]) {
    await t.test('caller namespace drift is refused before proc reads', () => withRuntime(options, async (runtime, expected, calls) => {
      await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_namespace' });
      assert.equal(calls.status, 0);
    }));
  }
});

test('synthetic remaining native group identity guards remain strict', async t => {
  await t.test('owned live group member remains pending', () => withRuntime({}, async (runtime, expected) => {
    assert.deepEqual(await runtime.remainingNativeGroup(binary, expected), [procPid]);
  }));
  for (const [name, options] of [['executable', { executable: '/fixture/foreign' }], ['namespace', { pidNamespace: 'pid:[foreign]' }], ['UID', { uid: uid + 1, initialStatusReads: 1 }]]) {
    await t.test(`${name} mismatch is unresolved`, () => withRuntime(options, async (runtime, expected) => {
      await assert.rejects(runtime.remainingNativeGroup(binary, expected), { code: 'runtime_identity' });
    }));
  }
});
