// Independent synthetic controls for the pinned alpha runtime candidate.
// Fixture process identifiers and paths are invented; no real process is used.
// Run directly from the repository; results are saved under ignored .build.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const runtimeBytes = await readFile(new URL('../alpha/runtime.mjs', import.meta.url));
assert.equal(hash(runtimeBytes), 'bb9c8974be8a56a73aab3cbccb0948d1234e1d461c16a6d3ad680beb786ebf51');
const binary = '/heldout/nginx', prefix = '/heldout/prefix', uid = process.getuid();
const owner = 'pid:[heldout]', network = 'net:[heldout]';
const title = `nginx: master process ${binary} -p ${prefix} -c ${prefix}/nginx.conf`;
const err = code => Object.assign(new Error('Heldout fixture refusal'), { code });
let count = 0;
const cases = [];
async function scenario(name, options, check) {
  const calls = { stat: 0, status: 0, cmdline: 0, lstat: 0, signals: 0 };
  const regular = { uid, mode: 0o100600, isFile: () => true, isSymbolicLink: () => !!options.symlink, isDirectory: () => false };
  const fs = {
    async readdir() { return options.inventory || ['701']; },
    async readFile(file) {
      if (file.endsWith('/status')) { calls.status++; return `Uid:\t${uid}\nNSpid:\t701\n`; }
      if (file.endsWith('/cmdline')) { calls.cmdline++; return `${calls.cmdline % 2 === 1 ? title : (options.title ?? title)}\0`; }
      if (file.endsWith('/stat')) {
        calls.stat++;
        const fields = Array(20).fill('0'); fields[0] = options.state || 'S'; fields[1] = '1'; fields[2] = '701'; fields[19] = options.start || '42';
        return `701 (nginx) ${fields.join(' ')}${options.oversize ? ' '.repeat(131073) : ''}`;
      }
      if (file === `${prefix}/nginx.pid`) return `${options.pid || 701}\n`;
      throw err('ENOENT');
    },
    async readlink(file) {
      if (file.endsWith('/exe')) return binary;
      if (file.endsWith('/ns/pid')) return owner;
      if (file.endsWith('/ns/net')) return network;
      throw err('ENOENT');
    },
    async lstat(file) {
      if (file === `${prefix}/nginx.pid`) return regular;
      calls.lstat++;
      const action = options.lstat?.[calls.lstat - 1];
      if (typeof action === 'string') throw err(action);
      return regular;
    },
    async realpath(file) { return file; },
  };
  const key = `heldout_${randomUUID()}`; globalThis[key] = fs;
  const adapter = `const f=globalThis[${JSON.stringify(key)}];${['readdir','readFile','readlink','lstat','realpath'].map(n => `export const ${n}=(...a)=>f.${n}(...a);`).join('')}`;
  const adapterUrl = `data:text/javascript;base64,${Buffer.from(adapter).toString('base64')}`;
  const source = runtimeBytes.toString();
  assert.equal(source.split("from 'node:fs/promises'").length, 2);
  const imported = source.replace("from 'node:fs/promises'", `from '${adapterUrl}'`);
  try {
    const runtime = await import(`data:text/javascript;base64,${Buffer.from(imported).toString('base64')}`);
    const expected = { pid: 701, procPid: 701, pidNamespace: owner, startTicks: '42', uid, executable: binary, commandSha256: runtime.digest(title), networkNamespace: network };
    await check(runtime, expected, calls);
    cases.push({ name, passed: true }); count++;
  } finally { delete globalThis[key]; }
}
const rejected = code => async (runtime, expected) => assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code });
for (const code of ['EPERM', 'ENOTDIR']) await scenario(`candidate-directory-${code}-propagates`, { state: 'X', lstat: [code] }, rejected(code));
for (const code of ['EACCES', 'ESRCH', 'EIO']) await scenario(`recorded-directory-${code}-propagates-after-absence`, { state: 'X', lstat: ['ENOENT', code] }, async (runtime, expected, calls) => {
  await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code }); assert.equal(calls.lstat, 2);
});
await scenario('persistent-dead-master-never-stopped', { state: 'X' }, async (runtime, expected, calls) => {
  await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_identity' }); assert.equal(calls.lstat, 1);
});
await scenario('duplicate-prefix-argument-refused', { title: `${title} -p ${prefix}` }, rejected('runtime_identity'));
await scenario('duplicate-config-argument-refused', { title: `${title} -c ${prefix}/nginx.conf` }, rejected('runtime_identity'));
await scenario('live-reused-incarnation-refused-without-absence-check', { start: '43' }, async (runtime, expected, calls) => {
  await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_identity' }); assert.equal(calls.lstat, 0);
});
await scenario('ambiguous-masters-refused', { inventory: ['701', '702'] }, rejected('runtime_identity'));
await scenario('symlink-pid-file-refused', { symlink: true }, rejected('unsafe_path'));
await scenario('oversized-live-identity-refused', { oversize: true }, rejected('runtime_identity'));
await scenario('bounded-proc-inventory-refused-before-reads', { inventory: Array.from({ length: 10001 }, (_, i) => String(i + 10)) }, async (runtime, expected, calls) => {
  await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_identity' }); assert.equal(calls.status, 0); assert.equal(calls.lstat, 0);
});
await scenario('absent-candidate-then-reused-recorded-pid-refused', { state: 'X', lstat: ['ENOENT', null] }, async (runtime, expected, calls) => {
  await assert.rejects(runtime.inspectMaster(binary, prefix, expected), { code: 'runtime_identity' }); assert.equal(calls.lstat, 2);
});
await scenario('dead-snapshot-only-absent-after-two-checks', { state: 'X', lstat: ['ENOENT', 'ENOENT'] }, async (runtime, expected, calls) => {
  assert.equal(await runtime.inspectMaster(binary, prefix, expected), null); assert.equal(calls.lstat, 2);
});
const evidence = { schemaVersion: 1, scope: 'Independent synthetic identity/absence controls; no real native lifecycle executed by reviewer', runtimeSha256: hash(runtimeBytes), fixtureSha256: hash(await readFile(new URL(import.meta.url))), tests: count, passed: count, failed: 0, skipped: 0, cases, limitations: ['Filesystem adapter interleavings are synthetic, not captured historical CI ordering.', 'No signals or actual processes exercised; official native aggregate is separate.', 'No pidfd fencing or proof of atomic process snapshot.'], rawRuntimeLogsIncluded: false, hostPathsIncluded: false, realPIDsIncluded: false };
await mkdir(new URL('../.build/', import.meta.url), { recursive: true });
await writeFile(new URL('../.build/stop-review-safe.json', import.meta.url), JSON.stringify(evidence, null, 2) + '\n');
process.stdout.write(JSON.stringify({ tests: count, passed: count, failed: 0, skipped: 0, runtimeSha256: hash(runtimeBytes) }) + '\n');
