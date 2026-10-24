import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { sha256, validateContract } from '../proof/runner.mjs';

const execute = promisify(execFile), root = fileURLToPath(new URL('../../', import.meta.url));
const cli = path.join(root, 'x10/proof/cli.mjs');
const example = name => path.join(root, 'x10/proof/examples', `${name}.json`);
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const manifest = path.resolve(process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'));
async function run(...args) {
  try { const r = await execute(process.execPath, [cli, ...args, '--binary', binary, '--manifest', manifest], { timeout: 40000, maxBuffer: 512 * 1024 }); return { code: 0, json: JSON.parse(r.stdout), stdout: r.stdout }; }
  catch (error) { if (!Number.isInteger(error.code)) throw error; return { code: error.code, json: JSON.parse(error.stdout), stdout: error.stdout }; }
}
const cleanup = result => {
  for (const check of result.checks) for (const order of check.orders) {
    assert.deepEqual(order.cleanup, { nativeStopped: true, nativeExitCode: 0, nativeSignal: null,
      originStopped: true, openSockets: 0, temporaryRootRemoved: true, forcedCleanup: false });
  }
};

test('native contract kernel detects cross-tenant cache leaks and rejects ineffective repairs', { timeout: 90000 }, async t => {
  const nativeHash = sha256(await readFile(binary)), manifestHash = sha256(await readFile(manifest));
  const before = new Set((await readdir(os.tmpdir())).filter(name => name.startsWith('x10-proof-')));
  let leak;
  await t.test('isolated-key-passes-both-fresh-cache-orders-with-real-native-hits', async () => {
    const result = await run('check', '--contract', example('isolated'));
    assert.equal(result.code, 0, result.stdout); assert.equal(result.json.outcome, 'contract_passed'); assert.equal(result.json.aiIntegration, false);
    assert.equal(result.json.identity.binarySha256, nativeHash); assert.equal(result.json.identity.manifestSha256, manifestHash);
    const [check] = result.json.checks; assert.equal(check.passed, true); assert.equal(check.orders.length, 2);
    assert.deepEqual(check.orders.map(order => order.order), [['tenant-a', 'tenant-b'], ['tenant-b', 'tenant-a']]);
    for (const order of check.orders) {
      assert.deepEqual(order.checks, { tenantIsolation: true, cacheEffective: true });
      assert.deepEqual(order.steps.map(step => step.response.cacheStatus), ['MISS', 'MISS', 'HIT', 'HIT']);
      assert.deepEqual(order.originTrace.map(row => row.tenant), order.order);
    }
    cleanup(result.json); assert(!result.stdout.includes(root.replace(/\/$/, ''))); assert(!result.stdout.includes('/proc/'));
  });
  await t.test('candidate-omitting-tenant-key-fails-with-two-request-witness-and-origin-trace', async () => {
    const result = await run('compare', '--baseline', example('isolated'), '--candidate', example('leaking'));
    assert.equal(result.code, 1, result.stdout); assert.equal(result.json.outcome, 'candidate_violates_contract');
    assert.equal(result.json.checks[0].passed, true); assert.equal(result.json.checks[1].passed, false); leak = result.json.checks[1];
    for (const order of leak.orders) {
      assert.equal(order.checks.tenantIsolation, false); assert.equal(order.originTrace.length, 1);
      const witness = order.counterexample;
      assert.equal(witness.prime.request.headers['X-X10-Test-Tenant'], order.order[0]);
      assert.equal(witness.prime.response.cacheStatus, 'MISS');
      assert.equal(witness.observe.request.headers['X-X10-Test-Tenant'], order.order[1]);
      assert.equal(witness.observe.response.cacheStatus, 'HIT');
      assert.equal(witness.observe.response.body, `tenant:${order.order[0]}\n`);
      assert.equal(witness.observe.matchesTenant, false);
    }
    cleanup(result.json);
  });
  await t.test('unchanged-bad-candidate-reproduces-and-cannot-be-accepted-as-valid-baseline', async () => {
    const repeated = await run('check', '--contract', example('leaking'));
    assert.equal(repeated.code, 1); assert.equal(repeated.json.outcome, 'contract_violated');
    assert.deepEqual(repeated.json.checks[0], leak, 'Same synthetic contract independently reproduces exact safe evidence');
    const badBaseline = await run('compare', '--baseline', example('leaking'), '--candidate', example('isolated'));
    assert.equal(badBaseline.code, 1); assert.equal(badBaseline.json.outcome, 'baseline_violates_contract'); cleanup(badBaseline.json);
  });
  await t.test('disabling-cache-does-not-satisfy-effectiveness-even-when-bodies-are-isolated', async () => {
    const result = await run('compare', '--baseline', example('isolated'), '--candidate', example('cache-disabled'));
    assert.equal(result.code, 1); assert.equal(result.json.outcome, 'candidate_violates_contract');
    for (const order of result.json.checks[1].orders) {
      assert.deepEqual(order.checks, { tenantIsolation: true, cacheEffective: false });
      assert.equal(order.originTrace.length, 4); assert(order.steps.every(step => step.response.cacheStatus === 'NONE'));
    }
    cleanup(result.json);
  });
  await t.test('real-key-repair-passes-and-keeps-caching-instead-of-weakening-the-contract', async () => {
    const result = await run('compare', '--baseline', example('isolated'), '--candidate', example('isolated'));
    assert.equal(result.code, 0); assert.equal(result.json.outcome, 'candidate_passed_checked_contract');
    assert(result.json.checks.every(check => check.passed)); cleanup(result.json);
  });
  await t.test('strict-input-and-mismatched-provenance-refuse-before-any-native-fixture', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'x10-proof-input-')); await chmod(dir, 0o700);
    try {
      const good = JSON.parse(await readFile(example('isolated'), 'utf8'));
      for (const value of [ { ...good, extra: true }, { ...good, resource: '/account; return 200 bad' }, { ...good, resource: '/a//b' },
        { ...good, tenants: ['same', 'same'] }, { ...good, cache: { ...good.cache, extra: true } }, { ...good, cache: { ...good.cache, enabled: 1 } } ]) assert.throws(() => validateContract(value), { code: 'invalid_contract' });
      const invalid = path.join(dir, 'bad.json'); await writeFile(invalid, JSON.stringify({ ...good, destination: 'https://example.com' }));
      const fake = path.join(dir, 'fake-nginx'), marker = path.join(dir, 'executed');
      await writeFile(fake, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o700 });
      try { await execute(process.execPath, [cli, 'check', '--contract', invalid, '--binary', fake, '--manifest', manifest], { timeout: 4000 }); assert.fail('Invalid input accepted'); }
      catch (error) { assert.equal(error.code, 2); assert.equal(JSON.parse(error.stdout).code, 'invalid_contract'); }
      assert(!(await readdir(dir)).includes('executed'), 'Input rejection did not execute selected binary');
      await writeFile(invalid, JSON.stringify({ ...good, kind: 'arbitrary-replay' }));
      const unsupported = await run('check', '--contract', invalid); assert.equal(unsupported.code, 3); assert.equal(unsupported.json.outcome, 'unsupported');
      const badManifest = JSON.parse(await readFile(manifest, 'utf8')); badManifest.binary.sha256 = '0'.repeat(64);
      const manifestFile = path.join(dir, 'manifest.json'); await writeFile(manifestFile, JSON.stringify(badManifest));
      try { await execute(process.execPath, [cli, 'check', '--contract', example('isolated'), '--binary', binary, '--manifest', manifestFile], { timeout: 4000 }); assert.fail('Manifest mismatch accepted'); }
      catch (error) { assert.equal(error.code, 2); assert.equal(JSON.parse(error.stdout).code, 'build_identity'); }
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  await t.test('SIGTERM-during-live-native-request-reaps-only-owned-fixture-and-removes-private-prefix', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'x10-proof-interrupt-')); await chmod(dir, 0o700);
    const track = path.join(dir, 'tracked.json'), preload = path.join(dir, 'fault.mjs');
    // Test-only fault injection: preserve the real spawn and HTTP request, inject
    // SIGTERM at the first tenant request, after the native readiness response.
    // No runner flag or production checkpoint is introduced for this control.
    await writeFile(preload, `import cp from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
const file=${JSON.stringify(track)}; let record, injected=false;
const spawn=cp.spawn;
cp.spawn=function(...args) {
 const child=spawn(...args);
 if (args[1]?.includes('-p') && args[1]?.includes('-c')) { record={pid:child.pid,prefix:args[1][args[1].indexOf('-p')+1],ready:false}; fs.writeFileSync(file,JSON.stringify(record)); }
 return child;
};
syncBuiltinESMExports();
const get=http.get;
http.get=function(...args) {
 if (!injected && args[0]?.headers?.['X-X10-Test-Tenant']) { injected=true; record.ready=true; fs.writeFileSync(file,JSON.stringify(record)); process.kill(process.pid,'SIGTERM'); }
 return get.apply(this,args);
};\n`, { mode: 0o600 });
    let tracked, nativeGone = false;
    try {
      try {
        await execute(process.execPath, ['--import', preload, cli, 'check', '--contract', example('isolated'), '--binary', binary, '--manifest', manifest],
          { timeout: 15000, maxBuffer: 256 * 1024, env: { ...process.env, TMPDIR: dir } });
        assert.fail('Interrupted CLI unexpectedly passed');
      } catch (error) {
        assert.equal(error.code, 2, error.stdout); const result = JSON.parse(error.stdout); assert.equal(result.code, 'interrupted');
      }
      tracked = JSON.parse(await readFile(track, 'utf8')); assert.equal(tracked.ready, true, 'Unique native readiness completed before SIGTERM');
      assert(Number.isInteger(tracked.pid) && tracked.pid > 1); assert(tracked.prefix.startsWith(`${dir}/x10-proof-`));
      assert.throws(() => process.kill(tracked.pid, 0), { code: 'ESRCH' }, 'Only the tracked native child has been reaped');
      nativeGone = true;
      assert.deepEqual((await readdir(dir)).sort(), ['fault.mjs', 'tracked.json']);
    } finally {
      // Emergency cleanup is restricted to the exact group spawned by this control.
      if (!tracked) { try { tracked = JSON.parse(await readFile(track, 'utf8')); } catch {} }
      if (!nativeGone && Number.isInteger(tracked?.pid) && tracked.pid > 1) { try { process.kill(-tracked.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
      await rm(dir, { recursive: true, force: true });
    }
  });
  assert.equal(sha256(await readFile(binary)), nativeHash); assert.equal(sha256(await readFile(manifest)), manifestHash);
  const after = (await readdir(os.tmpdir())).filter(name => name.startsWith('x10-proof-') && !before.has(name));
  assert.deepEqual(after, []);
});
