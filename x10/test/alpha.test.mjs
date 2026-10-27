import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, rmdir, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../alpha/runtime.mjs';
import './alpha-runtime.test.mjs';
import './alpha-pid.test.mjs';
import '../alpha/prepare-run.test.mjs';
import '../alpha/backup.test.mjs';
import '../alpha/package-info.test.mjs';
import '../alpha/stage.test.mjs';
import { assertHostedOperatorReturn } from './package-return.mjs';
import { SHARED_OPERATOR_PEERS, verifySharedOperatorPeerFiles } from '../service/operator-package-return.mjs';
import './package-return-proof.test.mjs';
import { amendRecord, recipeControlNames, recipeAlphaNames, recipeV2Names, recipeV2Dirs, assertInstalledPackageInfo,
  recipeTree, prepareRecipeNode, verifyRecipeNode, recipeNodeCommand, assertRecipeResult } from './alpha-recipe-helpers.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url)), source = path.join(root, 'x10/alpha/cli.mjs');
const manifestFile = path.resolve(process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'));
const binary = path.resolve(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
const execute = promisify(execFile), delay = ms => new Promise(resolve => setTimeout(resolve, ms));
// Native PID report framing. A complete stdout field is a fixture observation,
// not process ownership or an OS-level signal fence.
function nativePidReport(output, candidateOnly = false) {
  if (typeof output !== 'string' || typeof candidateOnly !== 'boolean') return null;
  const match = (candidateOnly
    ? /(?:^|\n)[ \t]*"candidatePid": ([0-9]+),?\r?\n/
    : /(?:^|\n)[ \t]*"(?:pid|candidatePid)": ([0-9]+),?\r?\n/).exec(output);
  if (!match) return null;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) && pid > 1 && pid <= 2147483647 && String(pid) === match[1] ? pid : null;
}
// End native PID report framing.

async function unusedPort() { const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
async function absent(file) { return lstat(file).then(() => false, error => { if (error.code === 'ENOENT') return true; throw error; }); }
async function until(fn, timeout = 6500) {
  const end = performance.now() + timeout; let last;
  while (performance.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { last = e; } await delay(25); }
  throw last || new Error('Alpha fixture deadline');
}
async function cli(file, ...args) {
  try { const r = await execute(process.execPath, [file, ...args], { timeout: 12000, maxBuffer: 2 * 1024 * 1024 }); return { code: 0, ...r, json: args.includes('--human') ? null : JSON.parse(r.stdout) }; }
  catch (error) { if (!Number.isInteger(error.code)) throw error; return { code: error.code, stdout: error.stdout, stderr: error.stderr, json: JSON.parse(error.stdout) }; }
}
async function request(port, route = '/') {
  return new Promise((resolve, reject) => { const req = http.get({ host: '127.0.0.1', port, path: route, agent: false }, res => { let body = ''; res.on('data', b => body += b); res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers })); }); req.setTimeout(1500, () => req.destroy(new Error('request timeout'))); req.on('error', reject); });
}
// A sampled reload gate is not an all-request cutover: old workers may overlap.
async function observedBody(port, expected) { await until(async () => (await request(port)).body === expected); }

test('isolated Linux alpha installs, controls native sessions, restarts and removes only owned data', { timeout: 90000 }, async t => {
  const build = JSON.parse(await readFile(manifestFile, 'utf8'));
  assert.equal(build.binary.path, binary, 'Aggregate-selected manifest and binary must be identical');
  assert.equal(build.binary.sha256, digest(await readFile(binary)));
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install'), launcher = path.join(prefix, 'bin/x10');
  const port = await unusedPort(); let healthPort; do { healthPort = await unusedPort(); } while (healthPort === port);
  let runChild, runOutput = '', runStdout = '', nativePid, firstSession, firstRevision, secondRevision, cancelled = false;
  const nativeGroups = new Set(), launchers = new Set();
  const emergency = () => { cancelled = true; for (const pid of nativeGroups) { try { process.kill(-pid, 'SIGTERM'); } catch {} } for (const child of launchers) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const check = (name, fn) => t.test(name, async () => { assert.equal(cancelled, false); await fn(); });
  const start = async () => {
    runOutput = ''; runStdout = ''; runChild = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(runChild);
    runChild.stdout.on('data', b => { runOutput += b; runStdout += b; const pid = nativePidReport(runStdout); if (pid !== null) { nativePid = pid; nativeGroups.add(nativePid); } });
    runChild.stderr.on('data', b => runOutput += b);
    await until(() => { if (runChild.exitCode !== null || runChild.signalCode !== null) throw new Error(`run exited: ${runOutput}`); return runOutput.includes('"outcome": "running"'); });
    const result = await cli(launcher, 'info'); assert.equal(result.code, 0, result.stdout); return result.json;
  };
  const stop = async () => {
    const result = await cli(launcher, 'stop'); assert.equal(result.code, 0, result.stdout);
    await until(() => runChild.exitCode !== null || runChild.signalCode !== null); assert.equal(runChild.exitCode, 0, runOutput);
    nativeGroups.delete(nativePid); launchers.delete(runChild); return result.json;
  };
  try {
    await check('reject-existing-prefix-symlink-ancestor-unsafe-port-and-mismatched-build', async () => {
      const existing = await cli(source, 'install', '--prefix', parent, '--manifest', manifestFile, '--binary', binary); assert.equal(existing.json.code, 'already_exists');
      const link = path.join(parent, 'link'); await symlink(parent, link);
      const unsafe = await cli(source, 'install', '--prefix', path.join(link, 'new'), '--manifest', manifestFile, '--binary', binary); assert.equal(unsafe.json.code, 'unsafe_path');
      await rm(link);
      const invalid = await cli(source, 'install', '--prefix', prefix, '--port', '80', '--manifest', manifestFile, '--binary', binary); assert.equal(invalid.json.code, 'invalid_port');
      // A runner-owned copy reaches manifest identity checks on non-root hosts;
      // the system Node executable can be owned by a different user there.
      const wrongBinary = path.join(parent, 'mismatched-nginx'); await copyFile(binary, wrongBinary); await chmod(wrongBinary, 0o500);
      try {
        const mismatch = await cli(source, 'install', '--prefix', prefix, '--manifest', manifestFile, '--binary', wrongBinary);
        assert.equal(mismatch.json.code, 'build_identity'); assert(await absent(prefix));
      } finally { await rm(wrongBinary); }
    });
    await check('manifest-verified-new-private-install-prepares-without-listening', async () => {
      const result = await cli(source, 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--manifest', manifestFile, '--binary', binary);
      assert.equal(result.code, 0, result.stdout); firstSession = result.json.session; firstRevision = result.json.revision;
      assert.equal((await lstat(prefix)).mode & 0o777, 0o700); assert.equal(digest(await readFile(path.join(prefix, 'bin/nginx'))), build.binary.sha256);
      assert.equal(result.json.controlApiEnabled, false); assert.match(result.json.healthNote, /demo self-check/);
      assert.equal((await cli(launcher, 'status')).json.binding, null);
      await assert.rejects(request(port)); await assert.rejects(request(healthPort));
      assert((await readFile(path.join(prefix, 'licenses/NGINX-LICENSE'), 'utf8')).includes('Copyright'));
      assert.equal((await cli(launcher, 'run', '--control-address', '127.0.0.1:9999')).json.code, 'arguments');
    });
    await check('foreground-native-start-explicit-bind-status-and-native-demo-self-check', async () => {
      const info = await start(); assert.equal(info.session, firstSession); assert.equal(info.controlSocket, null);
      assert.equal((await cli(launcher, 'bind')).code, 0);
      const status = await cli(launcher, 'status'); assert.equal(status.json.runtime.identityValid, true); assert.equal(status.json.runtime.observedRevision, firstRevision);
      const human = await cli(launcher, 'status', '--human'); assert.equal(human.code, 0); assert.match(human.stdout, /Health and listener drain: not checked/);
      assert.equal((await request(port)).body, 'NGINX X10 local alpha\n'); assert.equal((await request(healthPort, '/__x10_demo_self_check')).body, 'native demo self-check\n');
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'alpha_live');
      assert.equal((await cli(launcher, 'run')).json.code, 'alpha_live');
      const life = JSON.parse(await readFile(path.join(info.sessionPrefix, 'lifecycle.json'), 'utf8'));
      const cmd = (await readFile(`/proc/${life.runtime.procPid}/cmdline`, 'utf8')).split('\0')[0]; assert(!cmd.includes(' -l '));
      const table = await readFile(`/proc/${life.runtime.procPid}/net/tcp`, 'utf8');
      for (const p of [port, healthPort]) { const key = `0100007F:${p.toString(16).padStart(4, '0').toUpperCase()}`; assert(table.split('\n').some(line => line.includes(key) && /\s0A\s/.test(line)), `IPv4 loopback listener ${p}`); }
    });
    await check('apply-revert-history-recover-and-foreign-pidfile-refusal', async () => {
      const applied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(applied.code, 0, applied.stdout); secondRevision = applied.json.revision;
      await observedBody(port, 'NGINX X10 updated local alpha\n');
      const reverted = await cli(launcher, 'revert', '--revision', firstRevision); assert.equal(reverted.code, 0, reverted.stdout); await observedBody(port, 'NGINX X10 local alpha\n');
      const reapplied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(reapplied.code, 0); secondRevision = reapplied.json.revision;
      await observedBody(port, 'NGINX X10 updated local alpha\n');
      assert.equal((await cli(launcher, 'recover')).code, 0); assert.equal((await cli(launcher, 'history')).json.ok, true);
      const pidFile = path.join(prefix, 'runs', firstSession, 'nginx.pid'), original = await readFile(pidFile);
      try { await writeFile(pidFile, `${process.pid}\n`); assert.equal((await cli(launcher, 'stop')).json.code, 'runtime_identity'); assert.equal((await request(port)).body, 'NGINX X10 updated local alpha\n'); }
      finally { await writeFile(pidFile, original); }
    });
    await check('immutable-tamper-refused-and-library-drift-does-not-block-exact-stop', async () => {
      const file = path.join(prefix, 'licenses/UPSTREAM.txt'), bytes = await readFile(file); await chmod(file, 0o600);
      try { await writeFile(file, 'changed'); assert.equal((await cli(launcher, 'status')).json.code, 'alpha_integrity'); }
      finally { await writeFile(file, bytes); await chmod(file, 0o400); }
      const marker = path.join(prefix, '.alpha-install.json'), original = await readFile(marker);
      // Isolated owned record control: never modify actual host libraries.
      try {
        await amendRecord(marker, value => value.dependencies.files[0].sha256 = '0'.repeat(64));
        assert.equal((await cli(launcher, 'bind')).json.code, 'dependency_changed');
        const stopped = await stop(); assert.equal(stopped.outcome, 'stopped'); assert.equal(stopped.dependencyDrift.length, 1);
      } finally { await writeFile(marker, original); }
      assert.equal((await cli(launcher, 'stop')).json.outcome, 'already_stopped');
      const config = path.join(prefix, 'runs', firstSession, 'nginx.conf'), configBytes = await readFile(config);
      try { await writeFile(config, Buffer.concat([configBytes, Buffer.from('# operator changed config\n')])); for (const command of ['run', 'uninstall']) assert.equal((await cli(launcher, command)).json.code, 'operator_conflict'); }
      finally { await writeFile(config, configBytes); }
      try { await chmod(prefix, 0o775); assert.equal((await cli(launcher, 'uninstall')).json.code, 'unsafe_permissions'); }
      finally { await chmod(prefix, 0o700); }
    });
    await check('restart-creates-fresh-session-keeps-confirmed-response-and-old-history', async () => {
      const priorHistory = await readFile(path.join(prefix, 'runs', firstSession, '.x10-control/history.jsonl'));
      const info = await start(); assert.notEqual(info.session, firstSession); assert.equal((await cli(launcher, 'bind')).code, 0);
      assert.equal((await request(port)).body, 'NGINX X10 updated local alpha\n');
      assert.deepEqual(await readFile(path.join(prefix, 'runs', firstSession, '.x10-control/history.jsonl')), priorHistory);
      const status = (await cli(launcher, 'status')).json; assert.equal(status.runtime.identityValid, true); assert.notEqual(status.lastConfirmedRevision, secondRevision);
      await stop(); await assert.rejects(request(port)); await assert.rejects(request(healthPort));
    });
    await check('uninstall-preserves-extra-and-symlink-data-then-cleans-known-stopped-install', async () => {
      const extra = path.join(prefix, 'operator-notes.txt'); await writeFile(extra, 'preserve me', { mode: 0o600 });
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'operator_data_preserved'); assert.equal(await readFile(extra, 'utf8'), 'preserve me'); await rm(extra);
      const outside = path.join(parent, 'outside.txt'); await writeFile(outside, 'outside', { mode: 0o600 }); await symlink(outside, path.join(prefix, 'operator-link'));
      assert.equal((await cli(launcher, 'uninstall')).json.code, 'unsafe_path'); assert.equal(await readFile(outside, 'utf8'), 'outside'); await rm(path.join(prefix, 'operator-link'));
      const result = await cli(launcher, 'uninstall'); assert.equal(result.code, 0, result.stdout); assert(await absent(prefix)); assert.equal(nativeGroups.size, 0); assert.equal(launchers.size, 0);
      assert.deepEqual((await readdir(parent)).sort(), ['outside.txt']);
    });
    await check('checked-bundle-extracts-and-installs-without-original-build-paths', async () => {
      const archive = path.join(parent, 'alpha.tar.gz'), packed = await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary);
      assert.equal(packed.code, 0, packed.stdout); assert.equal(packed.json.binarySha256, build.binary.sha256);
      const alias = path.join(parent, 'pack-alias'); await symlink(parent, alias);
      assert.equal((await cli(source, 'pack', '--output', path.join(alias, 'must-not-create', 'bad.tar.gz'), '--manifest', manifestFile, '--binary', binary)).json.code, 'unsafe_path');
      assert(await absent(path.join(parent, 'must-not-create'))); await rm(alias);
      assert.equal((await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary)).json.code, 'unsafe_output');
      await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
      const bundle = path.join(parent, 'nginx-x10-alpha'), installer = path.join(bundle, 'install.mjs'), target = path.join(parent, 'bundled-install'), targetLauncher = path.join(target, 'bin/x10');
      const bundled = JSON.parse(await readFile(path.join(bundle, 'bundle.json'), 'utf8'));
      assert.equal(bundled.schemaVersion,2);assert.equal(bundled.kind,'nginx-x10-linux-alpha-bundle');
      const expectedBundle=['bin/nginx','install.mjs','LICENSE','NOTICE','x10/alpha/README.md',...recipeAlphaNames.map(n=>'x10/alpha/'+n),...recipeControlNames.map(n=>'x10/control/'+n),'x10/service/user-unit.mjs'].sort();
      assert.equal(expectedBundle.length,14);assert.deepEqual(Object.keys(bundled.files).sort(),expectedBundle);
      const bundleTree=await recipeTree(bundle);assert.deepEqual(bundleTree.directories,['','bin','x10','x10/alpha','x10/control','x10/service']);assert.deepEqual(bundleTree.files,[...expectedBundle,'bundle.json'].sort());
      for(const dir of ['', 'bin','x10','x10/alpha','x10/control','x10/service'])assert.equal((await lstat(path.join(bundle,dir))).mode&0o7777,0o700);
      assert.equal((await lstat(path.join(bundle,'x10/service/user-unit.mjs'))).mode&0o7777,0o400);
      assert.equal(bundled.files['bin/nginx'].sha256, build.binary.sha256); assert(!JSON.stringify(bundled).includes(root.replace(/\/$/, ''))); assert(!JSON.stringify(bundled).includes('/proc/'));
      assert.equal(await absent(path.join(bundle, 'x10/.build')), true); assert.equal(await absent(path.join(bundle, 'runs')), true);
      // Declare the tested Node profile before install. The same verified owned
      // executable installs and generates the recipe; no global-Node fallback.
      const recipeNode=await prepareRecipeNode(parent);
      t.diagnostic(JSON.stringify({suite:'x10-recipe-node-prerequisites',profile:'owned-copy',...recipeNode.sourceObservations,...(await verifyRecipeNode(recipeNode))}));
      const code = path.join(bundle, 'x10/control/listeners.mjs'), saved = await readFile(code); await chmod(code, 0o600);
      try { await writeFile(code, 'changed'); assert.equal((await recipeNodeCommand(recipeNode,installer, 'install', '--prefix', target)).json.code, 'bundle_identity'); assert(await absent(target)); }
      finally { await writeFile(code, saved); await chmod(code, 0o400); }
      const result = await recipeNodeCommand(recipeNode,installer,'install','--prefix',target,'--port',String(port),'--health-port',String(healthPort)); assert.equal(result.code, 0, result.stdout);
      const installedRecord=JSON.parse(await readFile(path.join(target,'.alpha-install.json'),'utf8'));
      assert.equal(installedRecord.schemaVersion,2);assert.equal(Object.keys(installedRecord.immutable).length,15);assert.deepEqual(Object.keys(installedRecord.immutable).sort(),recipeV2Names);
      for(const dir of recipeV2Dirs)assert.equal((await lstat(path.join(target,dir))).mode&0o7777,0o700);
      const generator=await import('../service/user-unit.mjs'),recordedNode=installedRecord.nodeRuntime.executable;
      assert.ok(recordedNode===recipeNode.nodeExecutable,'installed recorded Node path matches declared owned copy');
      assert.ok(installedRecord.nodeRuntime.version===recipeNode.version,'installed recorded Node version matches declared owned copy');
      assert.ok(installedRecord.nodeRuntime.sha256===recipeNode.sha256,'installed recorded Node hash matches declared owned copy');
      const packageIdentity = await assertInstalledPackageInfo(target, targetLauncher,
        (file, ...args) => recipeNodeCommand(recipeNode, file, ...args));
      for(const automatic of [false,true]){
        const recipe=await recipeNodeCommand(recipeNode,targetLauncher,'service-unit',...(automatic?['--auto-readiness']:[]));assertRecipeResult(recipe,{prefix:target,nodeExecutable:recordedNode,automatic});
        assert.equal(recipe.json.unit,generator.renderUserUnit({prefix:target,nodeExecutable:recordedNode,autoReadiness:automatic}));
        assert.equal(await absent(path.join(target,'.alpha-lock')),true);
      }
      let output = '', nativeStdout = '', pid;
      await verifyRecipeNode(recipeNode);
      const child = spawn(recipeNode.nodeExecutable, [targetLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(child);
      child.stdout.on('data', b => { output += b; nativeStdout += b; const reportedPid = nativePidReport(nativeStdout); if (reportedPid !== null) { pid = reportedPid; nativeGroups.add(pid); } }); child.stderr.on('data', b => output += b);
      await until(() => { if (child.exitCode !== null || child.signalCode !== null) throw new Error(output); return output.includes('"outcome": "running"'); });
      assert.equal((await recipeNodeCommand(recipeNode,targetLauncher, 'bind')).code, 0); assert.equal((await request(port)).body, 'NGINX X10 local alpha\n');
      assert.equal((await recipeNodeCommand(recipeNode,targetLauncher, 'apply', '--file', path.join(target, 'examples/candidate-b.json'))).code, 0);
      await observedBody(port, 'NGINX X10 updated local alpha\n'); assert.equal((await recipeNodeCommand(recipeNode,targetLauncher, 'stop')).code, 0);
      await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0, output); launchers.delete(child); nativeGroups.delete(pid);
      // Actual supported-host native -t restore proof. The source has served
      // and confirmed B, but a declarative restore creates an unbound fresh
      // installation; it does not copy process/controller history or start it.
      const sourceRegistry = JSON.parse(await readFile(path.join(target, '.alpha-registry.json'), 'utf8'));
      const sourceSession = path.join(target, 'runs', sourceRegistry.current);
      const preservedPaths = ['.alpha-install.json', '.alpha-registry.json',
        `runs/${sourceRegistry.current}/lifecycle.json`, `runs/${sourceRegistry.current}/.x10-control/state.json`,
        `runs/${sourceRegistry.current}/.x10-control/history.jsonl`];
      const preservedBytes = await Promise.all(preservedPaths.map(relative => readFile(path.join(target, relative))));
      const sourceStatus = await recipeNodeCommand(recipeNode, targetLauncher, 'status');
      assert.equal(sourceStatus.code, 0, sourceStatus.stdout); assert.equal(sourceStatus.json.pending, null);
      const sourceRevision = JSON.parse(await readFile(path.join(sourceSession, '.x10-control/revisions', `${sourceStatus.json.lastConfirmedRevision}.json`), 'utf8'));
      const backupFile = path.join(parent, 'stopped-declarative-backup.json');
      const backedUp = await recipeNodeCommand(recipeNode, targetLauncher, 'backup', '--output', backupFile);
      assert.equal(backedUp.code, 0, backedUp.stdout); assert.equal(backedUp.json.outcome, 'declarative_backup_created');
      assert.equal(backedUp.json.nativeStarted, false); assert.equal(backedUp.json.serviceAccepted, false); assert.equal(backedUp.json.productionAccepted, false);
      const backupBytes = await readFile(backupFile), backupValue = JSON.parse(backupBytes);
      assert.equal((await lstat(backupFile)).mode & 0o7777, 0o600); assert.equal(digest(backupBytes), backedUp.json.sha256);
      assert.deepEqual(backupValue.source, { installationId: installedRecord.installationId, session: sourceRegistry.current, revision: sourceRevision.id });
      assert.deepEqual(backupValue.input, sourceRevision.input); assert.equal(backupValue.inputSha256, sourceRevision.inputSha256);
      assert.equal(backupValue.port, port); assert.equal(backupValue.healthPort, healthPort);
      const restoredTarget = path.join(parent, 'restored-install'), restoredLauncher = path.join(restoredTarget, 'bin/x10');
      const restored = await recipeNodeCommand(recipeNode, installer, 'install', '--prefix', restoredTarget, '--restore', backupFile);
      assert.equal(restored.code, 0, restored.stdout); assert.equal(restored.json.declarativeRestored, true);
      for (const key of ['nativeStarted', 'readinessChecked', 'serviceAccepted', 'productionAccepted']) assert.equal(restored.json[key], false);
      const restoredManifest = JSON.parse(await readFile(path.join(restoredTarget, '.alpha-install.json'), 'utf8'));
      const restoredPackageIdentity = await assertInstalledPackageInfo(restoredTarget, restoredLauncher,
        (file, ...args) => recipeNodeCommand(recipeNode, file, ...args));
      assert.deepEqual(restoredPackageIdentity, packageIdentity,
        'The same installed payload retains its identity across fresh restore identities');
      t.diagnostic(JSON.stringify({ suite: 'x10-package-identity', profile: 'extracted-bundle-read-only',
        runtimePayloadFiles: packageIdentity.runtimeFiles.length,
        runtimePayloadSha256: packageIdentity.runtimePayloadSha256,
        operatorPayloadSha256: packageIdentity.operatorPayloadSha256,
        nativeBinarySha256: packageIdentity.nativeBinarySha256,
        actualInstalledBytesMatched: true, sourceAndRestoredPayloadIdentityMatched: true,
        preparedRecordsAndOwnedLockPreserved: true, invalidArgumentsRefused: true,
        compatibilityAccepted: false, upgradePerformed: false, rollbackAccepted: false,
        serviceAccepted: false, productionAccepted: false }));
      const restoredRegistry = JSON.parse(await readFile(path.join(restoredTarget, '.alpha-registry.json'), 'utf8'));
      const restoredSession = path.join(restoredTarget, 'runs', restored.json.session);
      const restoredLife = JSON.parse(await readFile(path.join(restoredSession, 'lifecycle.json'), 'utf8'));
      const restoredRevision = JSON.parse(await readFile(path.join(restoredSession, '.x10-control/revisions', `${restored.json.revision}.json`), 'utf8'));
      assert.notEqual(restoredManifest.installationId, installedRecord.installationId); assert.notEqual(restored.json.session, sourceRegistry.current);
      assert.notEqual(restored.json.revision, sourceRevision.id); assert.deepEqual(restoredRegistry.sessions, [restored.json.session]);
      assert.equal(restoredRegistry.installationId, restoredManifest.installationId); assert.equal(restoredRegistry.current, restored.json.session);
      assert.equal(restoredLife.stage, 'prepared'); assert.equal(restoredLife.runtime, null); assert.equal(restoredLife.controlSocket, null);
      assert.deepEqual(restoredRevision.input, sourceRevision.input); assert.equal(restoredRevision.inputSha256, sourceRevision.inputSha256);
      assert.equal(restoredRevision.parent, null); assert.equal(restoredRevision.sourceRevision, null);
      assert.equal(restoredManifest.port, port); assert.equal(restoredManifest.healthPort, healthPort);
      const restoredStatus = await recipeNodeCommand(recipeNode, restoredLauncher, 'status');
      assert.equal(restoredStatus.code, 0, restoredStatus.stdout); assert.equal(restoredStatus.json.binding, null); assert.equal(restoredStatus.json.pending, null);
      assert.equal(restoredStatus.json.lastConfirmedRevision, restored.json.revision); assert.equal(restoredStatus.json.configUnchanged, true);
      assert.equal(restoredStatus.json.fragmentMatchesLastConfirmed, true); assert.equal(restoredStatus.json.history.entries, 1);
      const restoredHistory = await recipeNodeCommand(recipeNode, restoredLauncher, 'history');
      assert.equal(restoredHistory.code, 0, restoredHistory.stdout); assert.equal(restoredHistory.json.records.length, 1);
      assert.equal(restoredHistory.json.records[0].type, 'initialized_unbound');
      await assert.rejects(request(port)); await assert.rejects(request(healthPort));
      assert.equal((await recipeNodeCommand(recipeNode, restoredLauncher, 'uninstall')).code, 0); assert(await absent(restoredTarget));
      for (let index = 0; index < preservedPaths.length; index++) assert.deepEqual(await readFile(path.join(target, preservedPaths[index])), preservedBytes[index]);
      assert.deepEqual(await readFile(backupFile), backupBytes); assert.equal(nativeGroups.size, 0); assert.equal(launchers.size, 0);
      t.diagnostic(JSON.stringify({ suite: 'x10-declarative-restore', profile: 'extracted-bundle-native-syntax-unbound',
        stoppedConfirmedSource: true, privateBackupCreated: true, freshInstallation: true, freshSession: true, freshRevision: true,
        exactInputRestored: true, portsPreserved: true, freshHistory: true, bindingAbsent: true, nativeStarted: false,
        readinessChecked: false, listeningPortsClosed: true, sourcePreserved: true, freshInstallationRemoved: true,
        serviceAccepted: false, productionAccepted: false }));
      // A reviewed historical operator payload and the current candidate are
      // genuinely different code bytes with the same compiled native binary.
      // This prepares an unbound target only: it is not an A-to-B-to-A replay.
      await assertHostedPackageStage(t, { parent, bundle, installer, recipeNode,
        currentSource: target, backupFile, backupBytes, sourceRevision, port, healthPort });
      // Interrupt the startup path as soon as a fresh session publishes its native PID.
      let interruptedOutput = '', interruptedStdout = '', interruptedPid;
      await verifyRecipeNode(recipeNode);
      const interrupted = spawn(recipeNode.nodeExecutable, [targetLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(interrupted);
      interrupted.stdout.on('data', b => {
        interruptedOutput += b; interruptedStdout += b;
        const reportedPid = nativePidReport(interruptedStdout, true);
        if (reportedPid !== null && !interruptedPid) { interruptedPid = reportedPid; nativeGroups.add(interruptedPid); interrupted.kill('SIGTERM'); }
      });
      interrupted.stderr.on('data', b => interruptedOutput += b);
      await until(() => interrupted.exitCode !== null || interrupted.signalCode !== null);
      assert.equal(interrupted.signalCode, null, interruptedOutput); assert.equal(interrupted.exitCode, 1); assert(interruptedPid);
      assert.match(interruptedOutput, /run_cancelled/); assert(!interruptedOutput.includes('"outcome": "running"'));
      assert.equal((await recipeNodeCommand(recipeNode,targetLauncher, 'info')).json.stage, 'stopped', interruptedOutput);
      await assert.rejects(request(port)); await assert.rejects(request(healthPort)); nativeGroups.delete(interruptedPid); launchers.delete(interrupted);
      assert.equal((await recipeNodeCommand(recipeNode,targetLauncher, 'uninstall')).code, 0); assert(await absent(target));

      // SIGKILL of the master leaves native workers outside graceful completion.
      const fault = path.join(parent, 'faulted-install'), faultLauncher = path.join(fault, 'bin/x10');
      assert.equal((await recipeNodeCommand(recipeNode,installer, 'install', '--prefix', fault, '--port', String(port), '--health-port', String(healthPort))).code, 0);
      let faultOutput = '', faultStdout = '', faultPid;
      await verifyRecipeNode(recipeNode);
      const faultRun = spawn(recipeNode.nodeExecutable, [faultLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); launchers.add(faultRun);
      faultRun.stdout.on('data', b => { faultOutput += b; faultStdout += b; const reportedPid = nativePidReport(faultStdout); if (reportedPid !== null) { faultPid = reportedPid; nativeGroups.add(faultPid); } }); faultRun.stderr.on('data', b => faultOutput += b);
      await until(() => faultOutput.includes('"outcome": "running"')); assert.equal((await recipeNodeCommand(recipeNode,faultLauncher, 'bind')).code, 0);
      process.kill(faultPid, 'SIGKILL'); await until(() => faultRun.exitCode !== null || faultRun.signalCode !== null); assert.equal(faultRun.exitCode, 1);
      assert.equal((await recipeNodeCommand(recipeNode,faultLauncher, 'info')).json.stage, 'faulted');
      assert.equal((await request(port)).body, 'NGINX X10 local alpha\n', 'actual orphan worker still serves after master SIGKILL');
      for (const command of ['run', 'stop', 'uninstall']) assert.equal((await recipeNodeCommand(recipeNode,faultLauncher, command)).json.code, 'abnormal_exit');
      // Test-owned orphan process group only. Production commands never reap it.
      try { process.kill(-faultPid, 'SIGTERM'); } catch {} await until(async () => { try { await request(port); return false; } catch { return true; } });
      nativeGroups.delete(faultPid); launchers.delete(faultRun);
    });
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    for (const signal of ['SIGQUIT', 'SIGTERM', 'SIGKILL']) {
      for (const pid of nativeGroups) { try { process.kill(-pid, signal); } catch {} }
      for (const child of launchers) if (child.exitCode === null && child.signalCode === null) { try { child.kill(signal === 'SIGQUIT' ? 'SIGTERM' : signal); } catch {} }
      if (nativeGroups.size || launchers.size) await delay(75);
    }
    await rm(parent, { recursive: true, force: true });
  }
});

// Supported-host-only staging proof. The historical CLI is read from a fixed
// reviewed Git blob, never created by editing labels or injecting fake behavior.
// Its current shared peers are separately source-pinned and byte-checked.
async function assertHostedPackageStage(t, { parent, bundle, installer, recipeNode,
  currentSource, backupFile, backupBytes, sourceRevision, port, healthPort }) {
  const historicalCommit = 'acb648392e745b5246a5620f2ea6a6286dc06d42';
  const historicalBlob = 'f036791f3e843c3628964f5c61b0bc0ab903d6f9';
  const historicalCliSha256 = '4560b8b2503f109f210599a6277bdf5497118e3220c1d2fb6a0c041283c3810d';
  const historicalObject = `${historicalCommit}:x10/alpha/cli.mjs`;
  const resolved = await execute('git', ['rev-parse', historicalObject], { cwd: root, timeout: 5000, maxBuffer: 4096 });
  assert.equal(resolved.stdout.trim(), historicalBlob); assert.equal(resolved.stderr, '');
  const historical = await execute('git', ['show', historicalObject],
    { cwd: root, timeout: 5000, encoding: 'buffer', maxBuffer: 256 * 1024 });
  assert.equal(digest(historical.stdout), historicalCliSha256); assert.equal(historical.stderr.length, 0);
  // Legacy CLI and reviewed shared peers have independent fixed source pins.
  // This is a newly assembled pair, not the complete historical acb package.
  const sharedPeers = SHARED_OPERATOR_PEERS.files.map(row => row.path);
  const unchangedPeers = await execute('git', ['diff', '--exit-code', SHARED_OPERATOR_PEERS.commit, '--', ...sharedPeers],
    { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 });
  assert.equal(unchangedPeers.stdout, ''); assert.equal(unchangedPeers.stderr, '',
    'Shared operator modules must match their separately reviewed source');
  await verifySharedOperatorPeerFiles(bundle);
  const candidateCli = await readFile(path.join(bundle, 'x10/alpha/cli.mjs'));
  assert.notEqual(digest(candidateCli), historicalCliSha256,
    'Historical and candidate operator code are genuinely different reviewed bytes');
  const historicalBundle = path.join(parent, 'historical-operator-bundle');
  const bundleTree = await recipeTree(bundle);
  for (const relative of bundleTree.directories)
    await mkdir(path.join(historicalBundle, relative), { mode: 0o700 });
  for (const relative of bundleTree.files) {
    const mode = (await lstat(path.join(bundle, relative))).mode & 0o7777;
    await copyFile(path.join(bundle, relative), path.join(historicalBundle, relative), constants.COPYFILE_EXCL);
    await chmod(path.join(historicalBundle, relative), mode);
  }
  const historicalCli = path.join(historicalBundle, 'x10/alpha/cli.mjs');
  await chmod(historicalCli, 0o600); await writeFile(historicalCli, historical.stdout); await chmod(historicalCli, 0o400);
  await amendRecord(path.join(historicalBundle, 'bundle.json'), record => {
    record.files['x10/alpha/cli.mjs'] = { bytes: historical.stdout.length,
      sha256: historicalCliSha256, mode: '0400' };
  });
  assert.deepEqual(await recipeTree(historicalBundle), bundleTree);
  for (const relative of bundleTree.files) {
    if (['bundle.json', 'x10/alpha/cli.mjs'].includes(relative)) continue;
    assert.deepEqual(await readFile(path.join(historicalBundle, relative)), await readFile(path.join(bundle, relative)),
      'Historical package reassembly preserves every other checked payload byte');
  }
  const candidateBundle = JSON.parse(await readFile(path.join(bundle, 'bundle.json'), 'utf8'));
  const priorBundle = JSON.parse(await readFile(path.join(historicalBundle, 'bundle.json'), 'utf8'));
  const priorBody = { ...priorBundle }; delete priorBody.sha256;
  const candidateBody = { ...candidateBundle }; delete candidateBody.sha256;
  const priorFiles = { ...priorBody.files }; delete priorFiles['x10/alpha/cli.mjs'];
  const candidateFiles = { ...candidateBody.files }; delete candidateFiles['x10/alpha/cli.mjs'];
  assert.deepEqual(priorFiles, candidateFiles);
  assert.deepEqual({ ...priorBody, files: null }, { ...candidateBody, files: null },
    'Native build provenance remains unchanged; this is not a historical published bundle');
  const sourceA = path.join(parent, 'stage-source-a'), launcherA = path.join(sourceA, 'bin/x10');
  const sourceInstall = await recipeNodeCommand(recipeNode, path.join(historicalBundle, 'install.mjs'),
    'install', '--prefix', sourceA, '--restore', backupFile);
  assert.equal(sourceInstall.code, 0, sourceInstall.stdout); assert.equal(sourceInstall.json.declarativeRestored, true);
  assert.equal(sourceInstall.json.nativeStarted, false); assert.equal(sourceInstall.json.readinessChecked, false);
  const sourceManifest = JSON.parse(await readFile(path.join(sourceA, '.alpha-install.json'), 'utf8'));
  const sourceIdentity = await stagingPayloadIdentity(sourceA);
  assert.equal(sourceManifest.immutable['lib/alpha/cli.mjs'].sha256, historicalCliSha256);
  const candidateIdentity = await stagingPayloadIdentity(currentSource);
  assert.notEqual(sourceIdentity.runtimePayloadSha256, candidateIdentity.runtimePayloadSha256);
  assert.notEqual(sourceIdentity.operatorPayloadSha256, candidateIdentity.operatorPayloadSha256);
  assert.equal(sourceIdentity.nativeBinarySha256, candidateIdentity.nativeBinarySha256);
  const beforeTree = await recipeTree(sourceA);
  const beforeFiles = await Promise.all(beforeTree.files.map(async relative => {
    const file = path.join(sourceA, relative), stat = await lstat(file);
    return { relative, bytes: await readFile(file), identity: {
      dev: stat.dev, ino: stat.ino, uid: stat.uid, nlink: stat.nlink,
      mode: stat.mode, size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs } };
  }));
  const bundleManifestSha256 = digest(await readFile(path.join(bundle, 'bundle.json')));
  const stageArgs = (sourcePrefix, targetPrefix, sourcePin = sourceIdentity.runtimePayloadSha256,
    bundlePin = bundleManifestSha256) => ['stage', '--source-prefix', sourcePrefix, '--prefix', targetPrefix,
    '--expected-source-payload', sourcePin, '--expected-bundle-manifest', bundlePin];
  const changedHash = hash => (hash[0] === '0' ? '1' : '0') + hash.slice(1);
  let refusals = 0;
  for (const [name, args] of [
    ['source-pin', stageArgs(sourceA, path.join(parent, 'stage-wrong-source-pin'), changedHash(sourceIdentity.runtimePayloadSha256))],
    ['bundle-pin', stageArgs(sourceA, path.join(parent, 'stage-wrong-bundle-pin'), sourceIdentity.runtimePayloadSha256, changedHash(bundleManifestSha256))],
    ['same-payload', stageArgs(currentSource, path.join(parent, 'stage-same-payload'), candidateIdentity.runtimePayloadSha256)]
  ]) {
    const result = await recipeNodeCommand(recipeNode, installer, ...args);
    assert.equal(result.code, 1, `Staging ${name} refusal`); assert.equal(result.json.ok, false);
    assert.equal(await absent(args[4]), true, 'Refused staging does not create its requested target'); refusals++;
  }
  const targetB = path.join(parent, 'stage-target-b'), launcherB = path.join(targetB, 'bin/x10');
  const staged = await recipeNodeCommand(recipeNode, installer, ...stageArgs(sourceA, targetB));
  assert.equal(staged.code, 0, staged.stdout); assert.equal(staged.json.ok, true);
  const manifestB = JSON.parse(await readFile(path.join(targetB, '.alpha-install.json'), 'utf8'));
  const registryB = JSON.parse(await readFile(path.join(targetB, '.alpha-registry.json'), 'utf8'));
  const registryA = JSON.parse(await readFile(path.join(sourceA, '.alpha-registry.json'), 'utf8'));
  const sessionB = path.join(targetB, 'runs', registryB.current);
  const lifecycleB = JSON.parse(await readFile(path.join(sessionB, 'lifecycle.json'), 'utf8'));
  const statusB = await recipeNodeCommand(recipeNode, launcherB, 'status');
  assert.equal(statusB.code, 0, statusB.stdout); assert.equal(statusB.json.binding, null); assert.equal(statusB.json.pending, null);
  assert.equal(statusB.json.configUnchanged, true); assert.equal(statusB.json.fragmentMatchesLastConfirmed, true);
  assert.equal(statusB.json.history.entries, 1);
  const revisionB = JSON.parse(await readFile(path.join(sessionB, '.x10-control/revisions', `${statusB.json.lastConfirmedRevision}.json`), 'utf8'));
  assert.notEqual(manifestB.installationId, sourceManifest.installationId);
  assert.notEqual(registryB.current, registryA.current); assert.deepEqual(registryB.sessions, [registryB.current]);
  assert.equal(registryB.installationId, manifestB.installationId);
  const statusA = await recipeNodeCommand(recipeNode, launcherA, 'status'); assert.equal(statusA.code, 0, statusA.stdout);
  assert.notEqual(revisionB.id, statusA.json.lastConfirmedRevision);
  assert.deepEqual(revisionB.input, sourceRevision.input); assert.equal(revisionB.inputSha256, sourceRevision.inputSha256);
  assert.equal(revisionB.parent, null); assert.equal(revisionB.sourceRevision, null);
  assert.equal(manifestB.port, port); assert.equal(manifestB.healthPort, healthPort);
  assert.equal(lifecycleB.stage, 'prepared'); assert.equal(lifecycleB.runtime, null); assert.equal(lifecycleB.controlSocket, null);
  assert.equal(lifecycleB.installationId, manifestB.installationId); assert.equal(lifecycleB.session, registryB.current);
  const historyB = await recipeNodeCommand(recipeNode, launcherB, 'history');
  assert.equal(historyB.code, 0, historyB.stdout); assert.equal(historyB.json.records.length, 1);
  assert.equal(historyB.json.records[0].type, 'initialized_unbound');
  const targetIdentity = await stagingPayloadIdentity(targetB);
  assert.deepEqual(targetIdentity, candidateIdentity);
  assert.deepEqual(staged.json, { ok: true, outcome: 'package_staged', schemaVersion: 1,
    kind: 'nginx-x10-side-by-side-package-stage',
    sourceRuntimePayloadSha256: sourceIdentity.runtimePayloadSha256,
    targetRuntimePayloadSha256: targetIdentity.runtimePayloadSha256,
    sourceOperatorPayloadSha256: sourceIdentity.operatorPayloadSha256,
    targetOperatorPayloadSha256: targetIdentity.operatorPayloadSha256,
    sourceNativeBinarySha256: sourceIdentity.nativeBinarySha256,
    targetNativeBinarySha256: targetIdentity.nativeBinarySha256, bundleManifestSha256,
    runtimePayloadChanged: true, operatorPayloadChanged: true, nativeBinaryChanged: false,
    sourcePreserved: true, freshTargetIdentities: true, consistencyOnly: true,
    nativeStarted: false, readinessChecked: false, activationPerformed: false,
    compatibilityAccepted: false, upgradePerformed: false, rollbackAccepted: false,
    serviceAccepted: false, productionAccepted: false });
  assert.equal(staged.stderr, '');
  assert.notEqual(targetIdentity.runtimePayloadSha256, sourceIdentity.runtimePayloadSha256);
  assert.notEqual(targetIdentity.operatorPayloadSha256, sourceIdentity.operatorPayloadSha256);
  assert.equal(targetIdentity.nativeBinarySha256, sourceIdentity.nativeBinarySha256);
  const existingTree = await recipeTree(targetB);
  const existingBytes = await Promise.all(existingTree.files.map(relative => readFile(path.join(targetB, relative))));
  const existingRefusal = await recipeNodeCommand(recipeNode, installer, ...stageArgs(sourceA, targetB));
  assert.equal(existingRefusal.code, 1); assert.equal(existingRefusal.json.ok, false); refusals++;
  assert.deepEqual(await recipeTree(targetB), existingTree);
  for (let index = 0; index < existingTree.files.length; index++)
    assert.deepEqual(await readFile(path.join(targetB, existingTree.files[index])), existingBytes[index],
      'An existing target is refused without overwriting any owned file');
  assert.deepEqual(await recipeTree(sourceA), beforeTree);
  for (const expected of beforeFiles) {
    const file = path.join(sourceA, expected.relative), stat = await lstat(file);
    assert.deepEqual(await readFile(file), expected.bytes, 'Staging preserves every source file byte');
    for (const [key, value] of Object.entries(expected.identity)) assert.equal(stat[key], value, `Source file ${key} preserved`);
  }
  assert.deepEqual(await readFile(backupFile), backupBytes);
  assert.equal(await absent(path.join(sourceA, '.alpha-lock')), true);
  assert.equal(await absent(path.join(targetB, '.alpha-lock')), true);
  await assert.rejects(request(port)); await assert.rejects(request(healthPort));
  assert.equal((await recipeNodeCommand(recipeNode, launcherB, 'uninstall')).code, 0); assert(await absent(targetB));
  assert.equal((await recipeNodeCommand(recipeNode, launcherA, 'uninstall')).code, 0); assert(await absent(sourceA));
  await rm(historicalBundle, { recursive: true }); assert(await absent(historicalBundle));
  t.diagnostic(JSON.stringify({ suite: 'x10-package-stage', profile: 'historical-operator-to-current-extracted-native-syntax-unbound',
    historicalOperatorCommit: historicalCommit, historicalOperatorBlob: historicalBlob,
    historicalOperatorSha256: historicalCliSha256, historicalBundleReassembled: true,
    nativeBuildProvenanceUnchanged: true, runtimePayloadFiles: targetIdentity.runtimeFiles.length,
    sourceRuntimePayloadSha256: sourceIdentity.runtimePayloadSha256,
    targetRuntimePayloadSha256: targetIdentity.runtimePayloadSha256,
    sourceOperatorPayloadSha256: sourceIdentity.operatorPayloadSha256,
    targetOperatorPayloadSha256: targetIdentity.operatorPayloadSha256,
    nativeBinarySha256: targetIdentity.nativeBinarySha256,
    runtimePayloadChanged: true, operatorPayloadChanged: true, nativeBinaryChanged: false,
    exactInputAndPortsPreserved: true, freshInstallation: true, freshSession: true, freshRevision: true,
    freshHistory: true, bindingAbsent: true, nativeStarted: false, readinessChecked: false,
    activationPerformed: false, sourceFilesPreserved: true, backupPreserved: true,
    refusedWithoutOverwrite: refusals, listeningPortsClosed: true, ownedInstallationsRemoved: true,
    historicalBundleRemoved: true, compatibilityAccepted: false, upgradePerformed: false,
    rollbackAccepted: false, serviceAccepted: false, productionAccepted: false }));
}

// Independent actual-byte identity calculation, not the runtime helper under test.
async function stagingPayloadIdentity(prefix) {
  const manifest = JSON.parse(await readFile(path.join(prefix, '.alpha-install.json'), 'utf8'));
  const names = ['bin/nginx', 'bin/x10', ...recipeControlNames.map(name => `lib/control/${name}`),
    ...recipeAlphaNames.map(name => `lib/alpha/${name}`),
    ...(manifest.schemaVersion === 2 ? ['lib/service/user-unit.mjs'] : [])].sort();
  const files = await Promise.all(names.map(async relative => {
    const file = path.join(prefix, relative), bytes = await readFile(file), stat = await lstat(file);
    assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false); assert.equal(stat.nlink, 1);
    return { path: relative, bytes: bytes.length, sha256: digest(bytes), mode: (stat.mode & 0o7777).toString(8).padStart(4, '0') };
  }));
  const fingerprint = selected => digest(JSON.stringify({ schemaVersion: 1, files: selected }));
  return { runtimePayloadSha256: fingerprint(files), operatorPayloadSha256: fingerprint(files.filter(file => file.path !== 'bin/nginx')),
    nativeBinarySha256: files.find(file => file.path === 'bin/nginx').sha256, runtimeFiles: files };
}

// G2 opt-in upstream controls. The original demo lifecycle above stays intact.
async function upstreamTransfer(port, route = '/', { method = 'GET', body = null, limit = 9 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => req.destroy(new Error('upstream request deadline')), 5000);
    const req = http.request({ host: '127.0.0.1', port, path: route, method, agent: false,
      headers: body ? { 'Content-Length': body.length, 'Content-Type': 'application/octet-stream' } : {} }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => { bytes += chunk.length; if (bytes > limit) req.destroy(new Error('upstream response limit')); else chunks.push(chunk); });
      res.on('error', reject);
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }); });
    });
    req.setTimeout(1500, () => req.destroy(new Error('upstream request idle timeout')));
    req.once('error', error => { clearTimeout(timer); reject(error); });
    req.end(body);
  });
}
async function upstreamPorts(upstreamPort) {
  let port, healthPort;
  do { port = await unusedPort(); } while (port === upstreamPort);
  do { healthPort = await unusedPort(); } while (healthPort === port || healthPort === upstreamPort);
  return { port, healthPort };
}

test('application upstream port syntax and collisions refuse before creating a prefix', { timeout: 20000 }, async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-port-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'install');
  try {
    for (const value of ['0', '80', '65536', '09090', '9090.0', '9e3', ' 9090', '9090;return', '9080', '9081']) {
      const result = await cli(source, 'install', '--prefix', prefix, '--port', '9080', '--health-port', '9081', '--upstream-port', value,
        '--manifest', manifestFile, '--binary', binary);
      assert.equal(result.code, 1); assert.equal(result.json.ok, false); assert.equal(result.json.code, 'invalid_upstream_port');
      assert.equal(await absent(prefix), true, 'invalid optional upstream created installation data');
    }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('extracted bundle proxies an independent app and preserves application readiness across config and sessions', { timeout: 120000 }, async t => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-')); await chmod(parent, 0o700);
  let ready = false, readinessBody = 'ready\n', appRequests = 0, echoRequests = 0, runChild, output = '', appStdout = '', nativePid;
  let streamRequests = 0, retainReturnFixture = false;
  const completedPostEffects = []; // Bounded synthetic in-memory echo receipts, not durable business state.
  const groups = new Set(), children = new Set();
  const app = http.createServer((req, res) => {
    appRequests++; res.setHeader('X-App-Marker', 'independent-upstream');
    if (req.url === '/ready' || req.url === '/not-ready') { res.writeHead(ready && req.url === '/ready' ? 200 : 503); res.end(ready ? readinessBody : 'not ready\n'); return; }
    if (req.method === 'POST' && req.url === '/echo') {
      echoRequests++;
      const chunks = []; let bytes = 0;
      req.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) req.destroy(); else chunks.push(chunk); });
      req.on('end', () => {
        if (completedPostEffects.length >= 16) { res.destroy(); return; }
        const body = Buffer.concat(chunks);
        completedPostEffects.push({ bytes: body.length, sha256: digest(body) });
        res.writeHead(200); res.end(body);
      }); return;
    }
    if (req.method === 'GET' && req.url === '/stream') {
      streamRequests++;
      const total = 256 * 1024, chunk = Buffer.alloc(16 * 1024, 0x73);
      let sent = 0, closed = false;
      const closedStream = () => { closed = true; res.removeListener('drain', pump); };
      function pump() {
        if (closed || res.destroyed) return;
        while (sent < total) {
          sent += chunk.length;
          if (!res.write(chunk)) { res.once('drain', pump); return; }
        }
        res.end();
      }
      res.once('close', closedStream); req.once('aborted', closedStream);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': total });
      res.setTimeout(3000, () => res.destroy());
      pump(); return;
    }
    res.writeHead(200); res.end('independent application\n');
  });
  app.requestTimeout = 3000; app.headersTimeout = 3000; app.keepAliveTimeout = 500;
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  const upstreamPort = app.address().port, { port, healthPort } = await upstreamPorts(upstreamPort);
  const prefix = path.join(parent, 'installed'), launcher = path.join(prefix, 'bin/x10');
  const emergency = () => { for (const pid of groups) { try { process.kill(-pid, 'SIGTERM'); } catch {} } for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); };
  process.once('SIGINT', emergency); process.once('SIGTERM', emergency);
  const start = async () => {
    output = ''; appStdout = ''; runChild = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); children.add(runChild);
    runChild.stdout.on('data', chunk => { output += chunk; appStdout += chunk; const reportedPid = nativePidReport(appStdout); if (reportedPid !== null) { nativePid = reportedPid; groups.add(nativePid); } });
    runChild.stderr.on('data', chunk => output += chunk);
    await until(() => { if (runChild.exitCode !== null || runChild.signalCode !== null) throw new Error(output); return output.includes('"outcome": "running"'); });
    const info = await cli(launcher, 'info'); assert.equal(info.code, 0, info.stdout); return info.json;
  };
  const stop = async () => {
    const result = await cli(launcher, 'stop'); assert.equal(result.code, 0, result.stdout);
    await until(() => runChild.exitCode !== null || runChild.signalCode !== null); assert.equal(runChild.exitCode, 0, output);
    children.delete(runChild); groups.delete(nativePid);
  };
  try {
    const archive = path.join(parent, 'alpha.tar.gz');
    const packed = await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary); assert.equal(packed.code, 0, packed.stdout);
    await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
    const bundle = path.join(parent, 'nginx-x10-alpha'), installer = path.join(bundle, 'install.mjs');
    assert.equal(await absent(path.join(bundle, 'x10/.build')), true);
    const installed = await cli(installer, 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--upstream-port', String(upstreamPort));
    assert.equal(installed.code, 0, installed.stdout); assert.match(installed.json.healthNote, /application readiness/);
    const beforePackageRequests = { appRequests, echoRequests };
    await assertInstalledPackageInfo(prefix, launcher, cli);
    assert.deepEqual({ appRequests, echoRequests }, beforePackageRequests,
      'Package inspection must not call application health or replay traffic');
    const first = await start();
    assert.equal((await request(healthPort, '/__x10_demo_self_check')).status, 200);
    assert.equal((await request(port, '/__x10_health')).status, 503, 'native demo must not stand in for application readiness');
    const denied = await cli(launcher, 'bind'); assert.equal(denied.code, 1); assert.equal(denied.json.code, 'health_gate_failed');
    assert.equal((await cli(launcher, 'status')).json.binding, null);
    ready = true; readinessBody = 'private-wrong-readiness-body\n';
    assert.equal((await request(port, '/__x10_health')).status, 200);
    const wrongBody = await cli(launcher, 'bind');
    assert.equal(wrongBody.code, 1, 'HTTP 200 with the wrong body must not bind the application');
    assert.equal(wrongBody.json.code, 'health_gate_failed');
    assert.equal(wrongBody.stdout.includes(readinessBody.trim()), false, 'readiness bodies stay out of diagnostics');
    assert.equal((await cli(launcher, 'status')).json.binding, null);
    readinessBody = 'ready\n'; const bound = await cli(launcher, 'bind'); assert.equal(bound.code, 0, bound.stdout);
    const initialRevision = bound.json.revision;
    const response = await upstreamTransfer(port); assert.equal(response.status, 200); assert.equal(response.body.toString(), 'independent application\n'); assert.equal(response.headers['x-app-marker'], 'independent-upstream');
    const payload = Buffer.alloc(65551); for (let i = 0; i < payload.length; i++) payload[i] = (i * 37) & 255;
    const echoed = await upstreamTransfer(port, '/echo', { method: 'POST', body: payload }); assert.equal(echoed.status, 200); assert.deepEqual(echoed.body, payload);
    assert.equal((await request(port, '/__x10_health')).status, 200);
    const applied = await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json')); assert.equal(applied.code, 0, applied.stdout);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    assert.equal((await cli(launcher, 'revert', '--revision', initialRevision)).code, 0);
    await until(async () => (await request(port)).headers['x-x10-example'] === undefined);
    assert.equal((await cli(launcher, 'apply', '--file', path.join(prefix, 'examples/candidate-b.json'))).code, 0);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    const seed = JSON.parse(await readFile(path.join(prefix, 'examples/candidate-b.json'), 'utf8'));
    assert.equal(seed.healthExpectedStatus, 200); assert.equal(seed.healthExpectedBody, 'ready\n');
    const unhealthy = path.join(parent, 'unhealthy.json'); await writeFile(unhealthy, JSON.stringify({ ...seed, healthURL: `http://127.0.0.1:${upstreamPort}/not-ready` }), { mode: 0o600 });
    const rolled = await cli(launcher, 'apply', '--file', unhealthy); assert.equal(rolled.code, 1); assert.equal(rolled.json.outcome, 'rolled_back'); assert.match(rolled.json.reason, /^No fresh acknowledged healthy revision .*health=503\//);
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    const wrongCandidate = path.join(parent, 'wrong-body.json');
    await writeFile(wrongCandidate, JSON.stringify({ ...seed, healthURL: `http://127.0.0.1:${upstreamPort}/wrong-ready-body` }), { mode: 0o600 });
    const bodyRollback = await cli(launcher, 'apply', '--file', wrongCandidate);
    assert.equal(bodyRollback.code, 1); assert.equal(bodyRollback.json.outcome, 'rolled_back');
    assert.equal(bodyRollback.stdout.includes('independent application'), false, 'application response bodies stay out of rollback diagnostics');
    await until(async () => (await request(port)).headers['x-x10-example'] === 'application-b');
    assert.equal((await cli(launcher, 'recover')).code, 0);
    await stop(); await assert.rejects(request(port));
    const restarted = await start(); assert.notEqual(restarted.session, first.session);
    assert.equal((await cli(launcher, 'bind')).code, 0);
    const afterRestart = await upstreamTransfer(port, '/echo', { method: 'POST', body: payload }); assert.deepEqual(afterRestart.body, payload);
    assert.equal(afterRestart.headers['x-x10-example'], 'application-b'); assert(appRequests > 0); assert.equal(echoRequests, 2, 'POST bodies must not be replayed by gateway operations');
    await stop();
    // Restored application acceptance.
    // A fresh restored foreground runtime serves the same confirmed HTTP input;
    // source history/identity and the backup remain data, never live authority.
    const retainedArchiveBytes = await readFile(archive);
    const sourceRegistry = JSON.parse(await readFile(path.join(prefix, '.alpha-registry.json'), 'utf8'));
    const sourceSession = path.join(prefix, 'runs', sourceRegistry.current);
    const sourceStatus = await cli(launcher, 'status');
    assert.equal(sourceStatus.code, 0, sourceStatus.stdout); assert.equal(sourceStatus.json.pending, null);
    const sourceRevisionPath = path.join(sourceSession, '.x10-control/revisions', `${sourceStatus.json.lastConfirmedRevision}.json`);
    const sourceRevisionBytes = await readFile(sourceRevisionPath), sourceRevision = JSON.parse(sourceRevisionBytes);
    const preservedSourcePaths = ['.alpha-install.json', '.alpha-registry.json',
      `runs/${sourceRegistry.current}/lifecycle.json`, `runs/${sourceRegistry.current}/.x10-control/state.json`,
      `runs/${sourceRegistry.current}/.x10-control/history.jsonl`];
    const preservedSourceBytes = await Promise.all(preservedSourcePaths.map(relative => readFile(path.join(prefix, relative))));
    const sourceManifest = JSON.parse(preservedSourceBytes[0]);
    const sourceLife = JSON.parse(preservedSourceBytes[2]); assert.equal(sourceLife.stage, 'stopped');
    assert.equal(groups.size, 0); assert.equal(children.size, 0);
    await assert.rejects(request(port)); await assert.rejects(request(healthPort));
    const backupFile = path.join(parent, 'application-backup.json');
    const backedUp = await cli(launcher, 'backup', '--output', backupFile);
    assert.equal(backedUp.code, 0, backedUp.stdout); assert.equal(backedUp.json.outcome, 'declarative_backup_created');
    assert.equal(backedUp.json.nativeStarted, false); assert.equal(backedUp.json.serviceAccepted, false); assert.equal(backedUp.json.productionAccepted, false);
    const backupBytes = await readFile(backupFile), backupValue = JSON.parse(backupBytes);
    assert.equal((await lstat(backupFile)).mode & 0o7777, 0o600); assert.equal(digest(backupBytes), backedUp.json.sha256);
    assert.deepEqual(backupValue.source, { installationId: sourceManifest.installationId, session: sourceRegistry.current, revision: sourceRevision.id });
    assert.deepEqual(backupValue.input, sourceRevision.input); assert.deepEqual(backupValue.input, seed);
    assert.equal(backupValue.inputSha256, sourceRevision.inputSha256); assert.equal(backupValue.port, port); assert.equal(backupValue.healthPort, healthPort);
    const restoredPrefix = path.join(parent, 'restored-application'), restoredLauncher = path.join(restoredPrefix, 'bin/x10');
    const restored = await cli(installer, 'install', '--prefix', restoredPrefix, '--restore', backupFile);
    assert.equal(restored.code, 0, restored.stdout); assert.equal(restored.json.declarativeRestored, true);
    for (const key of ['nativeStarted', 'readinessChecked', 'serviceAccepted', 'productionAccepted']) assert.equal(restored.json[key], false);
    const restoredSession = path.join(restoredPrefix, 'runs', restored.json.session);
    const restoredManifest = JSON.parse(await readFile(path.join(restoredPrefix, '.alpha-install.json'), 'utf8'));
    const restoredRegistry = JSON.parse(await readFile(path.join(restoredPrefix, '.alpha-registry.json'), 'utf8'));
    const restoredLife = JSON.parse(await readFile(path.join(restoredSession, 'lifecycle.json'), 'utf8'));
    const restoredRevision = JSON.parse(await readFile(path.join(restoredSession, '.x10-control/revisions', `${restored.json.revision}.json`), 'utf8'));
    assert.notEqual(restoredManifest.installationId, sourceManifest.installationId); assert.notEqual(restored.json.session, sourceRegistry.current);
    assert.notEqual(restored.json.revision, sourceRevision.id); assert.equal(restoredRegistry.installationId, restoredManifest.installationId);
    assert.equal(restoredRegistry.current, restored.json.session); assert.deepEqual(restoredRegistry.sessions, [restored.json.session]);
    assert.equal(restoredLife.stage, 'prepared'); assert.equal(restoredLife.runtime, null); assert.equal(restoredLife.controlSocket, null);
    assert.equal(restoredLife.installationId, restoredManifest.installationId); assert.equal(restoredLife.session, restored.json.session); assert.equal(restoredLife.prefix, restoredSession);
    assert.deepEqual(restoredRevision.input, sourceRevision.input); assert.equal(restoredRevision.inputSha256, sourceRevision.inputSha256);
    assert.equal(restoredRevision.parent, null); assert.equal(restoredRevision.sourceRevision, null);
    assert.equal(restoredManifest.port, port); assert.equal(restoredManifest.healthPort, healthPort);
    const preparedStatus = await cli(restoredLauncher, 'status');
    assert.equal(preparedStatus.code, 0, preparedStatus.stdout); assert.equal(preparedStatus.json.binding, null); assert.equal(preparedStatus.json.pending, null);
    assert.equal(preparedStatus.json.lastConfirmedRevision, restored.json.revision); assert.equal(preparedStatus.json.history.entries, 1);
    const preparedHistory = await cli(restoredLauncher, 'history'); assert.equal(preparedHistory.code, 0, preparedHistory.stdout);
    assert.equal(preparedHistory.json.records.length, 1); assert.equal(preparedHistory.json.records[0].type, 'initialized_unbound');
    await assert.rejects(request(port)); await assert.rejects(request(healthPort)); assert.equal(echoRequests, 2);
    let restoredOutput = '', restoredNativePid, restoredSpawnError;
    const restoredChild = spawn(process.execPath, [restoredLauncher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); children.add(restoredChild);
    restoredChild.once('error', error => { restoredSpawnError = error; });
    restoredChild.stdout.on('data', chunk => {
      restoredOutput += chunk;
      const reportedPid = nativePidReport(restoredOutput);
      if (reportedPid !== null) { restoredNativePid = reportedPid; groups.add(restoredNativePid); }
    });
    // Drain stderr separately; it cannot provide lifecycle/PID observations.
    restoredChild.stderr.on('data', () => {});
    await until(() => {
      if (restoredSpawnError) throw new Error('Restored application launcher spawn failed');
      if (restoredChild.exitCode !== null || restoredChild.signalCode !== null) throw new Error('Restored application launcher exited before running');
      return restoredOutput.includes('"outcome": "running"');
    });
    assert(Number.isSafeInteger(restoredNativePid) && restoredNativePid > 1);
    const runningLife = JSON.parse(await readFile(path.join(restoredSession, 'lifecycle.json'), 'utf8'));
    assert.equal(runningLife.stage, 'running'); assert.equal(runningLife.session, restored.json.session); assert.equal(runningLife.prefix, restoredSession);
    assert.equal(runningLife.runtime.pid, restoredNativePid); assert.equal(runningLife.runtime.executable, path.join(restoredPrefix, 'bin/nginx'));
    ready = true; readinessBody = 'private-restored-wrong-readiness-body\n';
    assert.equal((await request(port, '/__x10_health')).status, 200);
    const restoredWrongBody = await cli(restoredLauncher, 'bind');
    assert.equal(restoredWrongBody.code, 1); assert.equal(restoredWrongBody.json.code, 'health_gate_failed');
    assert.equal(restoredWrongBody.stdout.includes(readinessBody.trim()), false);
    const refusedStatus = await cli(restoredLauncher, 'status');
    assert.equal(refusedStatus.code, 0, refusedStatus.stdout); assert.equal(refusedStatus.json.binding, null); assert.equal(refusedStatus.json.pending, null);
    assert.equal(refusedStatus.json.lastConfirmedRevision, restored.json.revision); assert.equal(echoRequests, 2);
    readinessBody = 'ready\n'; const restoredBound = await cli(restoredLauncher, 'bind');
    assert.equal(restoredBound.code, 0, restoredBound.stdout); assert.equal(restoredBound.json.outcome, 'bound'); assert.equal(restoredBound.json.revision, restored.json.revision);
    const observedRestoredRevision = await request(port, '/__x10_revision');
    assert.equal(observedRestoredRevision.status, 200); assert.equal(observedRestoredRevision.body, restored.json.revision);
    assert.equal(observedRestoredRevision.headers['x-x10-revision'], restored.json.revision);
    const boundStatus = await cli(restoredLauncher, 'status');
    assert.equal(boundStatus.code, 0, boundStatus.stdout); assert.equal(boundStatus.json.pending, null);
    assert.equal(boundStatus.json.lastConfirmedRevision, restored.json.revision); assert.equal(boundStatus.json.runtime.identityValid, true);
    assert.equal(boundStatus.json.runtime.observedRevision, restored.json.revision);
    const { networkNamespace, ...restoredBinding } = runningLife.runtime; assert.deepEqual(boundStatus.json.binding, restoredBinding);
    const restoredGet = await upstreamTransfer(port);
    assert.equal(restoredGet.status, 200); assert.equal(restoredGet.body.toString(), 'independent application\n');
    assert.equal(restoredGet.headers['x-app-marker'], 'independent-upstream'); assert.equal(restoredGet.headers['x-x10-example'], 'application-b');
    assert.equal(echoRequests, 2);
    const restoredEcho = await upstreamTransfer(port, '/echo', { method: 'POST', body: payload });
    assert.equal(restoredEcho.status, 200); assert.deepEqual(restoredEcho.body, payload); assert.equal(restoredEcho.headers['x-x10-example'], 'application-b');
    assert.equal(echoRequests, 3, 'Restore/readiness/GET must not replay POST bodies');
    const restoredStopped = await cli(restoredLauncher, 'stop');
    assert.equal(restoredStopped.code, 0, restoredStopped.stdout); assert.equal(restoredStopped.json.outcome, 'stopped'); assert.equal(restoredStopped.json.session, restored.json.session);
    await until(() => restoredChild.exitCode !== null || restoredChild.signalCode !== null);
    assert.equal(restoredChild.exitCode, 0); assert.equal(restoredChild.signalCode, null);
    const stoppedLife = JSON.parse(await readFile(path.join(restoredSession, 'lifecycle.json'), 'utf8'));
    assert.equal(stoppedLife.stage, 'stopped'); assert.equal(stoppedLife.lastExit.code, 0); assert.equal(stoppedLife.lastExit.signal, null);
    await assert.rejects(request(port)); await assert.rejects(request(healthPort));
    children.delete(restoredChild); groups.delete(restoredNativePid);
    assert.equal((await cli(restoredLauncher, 'uninstall')).code, 0); assert.equal(await absent(restoredPrefix), true);
    for (let index = 0; index < preservedSourcePaths.length; index++) assert.deepEqual(await readFile(path.join(prefix, preservedSourcePaths[index])), preservedSourceBytes[index]);
    assert.deepEqual(await readFile(sourceRevisionPath), sourceRevisionBytes); assert.deepEqual(await readFile(backupFile), backupBytes);
    assert.equal(echoRequests, 3); assert.equal(groups.size, 0); assert.equal(children.size, 0);
    assert.deepEqual(await readFile(archive), retainedArchiveBytes);
    assert.equal((await cli(launcher, 'uninstall')).code, 0); assert.equal(await absent(prefix), true);
    assert.equal(echoRequests, 3); assert.equal(groups.size, 0); assert.equal(children.size, 0);
    // Finite observations only: no PID, path, config, request or readiness body.
    t.diagnostic(JSON.stringify({ suite: 'x10-restored-application', profile: 'extracted-bundle-foreground-http',
      stoppedConfirmedSource: true, privateBackupCreated: true, freshInstallation: true, freshSession: true, freshRevision: true,
      exactInputRestored: true, portsPreserved: true, freshHistory: true, bindingInitiallyAbsent: true, sourceListenersClosedBeforeRestore: true,
      runtimeOwned: true, wrongBodyBindRefused: true, failedBindingAbsent: true, freshRevisionVerified: true, readinessBound: true,
      getExact: true, postExact: true, restoredPostRequests: 1, totalEchoRequests: echoRequests, postReplayObserved: false,
      gracefulStopCompleted: true, ownedProcessGroupAbsent: true, listeningPortsClosed: true, restoredInstallationRemoved: true,
      sourceRecordsPreservedBeforeUninstall: true, sourceInstallationRemoved: true, backupPreserved: true, archivePreserved: true,
      foregroundHTTPAccepted: true, managedServiceAccepted: false,
      tlsBackupAccepted: false, packageUpgradeRollbackAccepted: false, productionAccepted: false }));
    // End restored application acceptance.
    // Separate foreground operator-code A-to-B-to-A replay. The old restored
    // diagnostic above keeps its own three-POST scope; this helper proves new
    // traffic only after verified stops and fresh unbound preparations.
    const returnNode = await prepareRecipeNode(parent);
    const returnEchoBase = echoRequests, returnStreamBase = streamRequests, returnEffectsBase = completedPostEffects.length;
    try {
      await assertHostedOperatorReturn(t, { parent, bundle, installer,
        recipeNode: returnNode, verifyNode: () => verifyRecipeNode(returnNode),
        command: (file, ...args) => recipeNodeCommand(returnNode, file, ...args),
        port, healthPort, upstreamPort, nativePidReport,
        setReadiness: body => { ready = true; readinessBody = body; },
        getEchoRequests: () => echoRequests, getStreamRequests: () => streamRequests,
        getPostEffects: () => completedPostEffects.map(effect => ({ ...effect })),
        preserveForInspection: () => { retainReturnFixture = true; } });
      assert.equal(echoRequests, returnEchoBase + 3,
        'Each separate operator-return leg sends exactly one new POST');
      assert.equal(streamRequests, returnStreamBase + 3,
        'Each separate operator-return leg reads exactly one bounded stream');
      assert.equal(completedPostEffects.length, returnEffectsBase + 3,
        'Three operator-return POST bodies complete at the synthetic application');
      assert.equal(new Set(completedPostEffects.slice(returnEffectsBase).map(effect => effect.sha256)).size, 3,
        'The three new completed synthetic POST effects have distinct payloads');
      assert.equal(groups.size, 0); assert.equal(children.size, 0);
      assert.deepEqual(await readFile(archive), retainedArchiveBytes);
      assert.deepEqual(await readFile(backupFile), backupBytes);
    } catch (error) {
      if (error?.packageReturnCleanupUnknown === true) retainReturnFixture = true;
      throw error;
    }
  } finally {
    process.removeListener('SIGINT', emergency); process.removeListener('SIGTERM', emergency);
    for (const signal of ['SIGQUIT', 'SIGTERM', 'SIGKILL']) { for (const pid of groups) { try { process.kill(-pid, signal); } catch {} } for (const child of children) if (child.exitCode === null && child.signalCode === null) { try { child.kill('SIGTERM'); } catch {} } if (groups.size || children.size) await delay(75); }
    app.closeAllConnections(); await new Promise(resolve => app.close(resolve));
    if (!retainReturnFixture) await rm(parent, { recursive: true, force: true });
  }
});

test('shipped loopback upstream example is immutable in extracted installs and serves bounded echo and stream', { timeout: 40000 }, async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-alpha-upstream-example-')); await chmod(parent, 0o700);
  let child, output = '';
  try {
    const archive = path.join(parent, 'alpha.tar.gz'); assert.equal((await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary)).code, 0);
    await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
    const bundle = path.join(parent, 'nginx-x10-alpha'), prefix = path.join(parent, 'installed'), launcher = path.join(prefix, 'bin/x10');
    const upstreamPort = await unusedPort(), { port, healthPort } = await upstreamPorts(upstreamPort);
    const result = await cli(path.join(bundle, 'install.mjs'), 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), '--upstream-port', String(upstreamPort)); assert.equal(result.code, 0, result.stdout);
    const example = path.join(prefix, 'lib/alpha/upstream-example.mjs'); assert.equal((await lstat(example)).mode & 0o777, 0o400);
    const bytes = await readFile(example); await chmod(example, 0o600);
    try { await writeFile(example, Buffer.concat([bytes, Buffer.from('\n// changed\n')])); assert.equal((await cli(launcher, 'info')).json.code, 'alpha_integrity'); }
    finally { await writeFile(example, bytes); await chmod(example, 0o400); }
    child = spawn(process.execPath, [example, '--port', String(upstreamPort)], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => output += chunk); child.stderr.on('data', chunk => output += chunk);
    await until(async () => { if (child.exitCode !== null || child.signalCode !== null) throw new Error(output); try { return (await request(upstreamPort, '/ready')).status === 200; } catch { return false; } });
    assert.equal((await request(upstreamPort)).body, 'NGINX X10 upstream example\n');
    const payload = Buffer.from([0, 1, 2, 255, 128, 0, 31]); const echoed = await upstreamTransfer(upstreamPort, '/echo', { method: 'POST', body: payload }); assert.deepEqual(echoed.body, payload);
    const streamed = await upstreamTransfer(upstreamPort, '/stream'); assert.equal(streamed.status, 200); assert.equal(streamed.body.length, 8 * 1024 * 1024); assert.equal(digest(streamed.body), digest(Buffer.alloc(8 * 1024 * 1024, 0x78)));
    child.kill('SIGTERM'); await until(() => child.exitCode !== null || child.signalCode !== null); assert.equal(child.exitCode, 0, output);
    assert.equal((await cli(launcher, 'uninstall')).code, 0); assert.equal(await absent(prefix), true);
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await until(() => child.exitCode !== null || child.signalCode !== null, 3000).catch(() => child.kill('SIGKILL')); }
    await rm(parent, { recursive: true, force: true });
  }
});

// Wait-bind fixtures use the actual independently owned alpha installation/native
// master. Their synthetic lock/state perturbations are not a systemd deployment.
async function waitBindFixture(t, { upstream = false } = {}) {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-wait-bind-')); await chmod(parent, 0o700);
  const prefix = path.join(parent, 'installed'), launcher = path.join(prefix, 'bin/x10');
  const port = await unusedPort(); let healthPort; do { healthPort = await unusedPort(); } while (healthPort === port);
  let app, upstreamPort, readyBody = 'ready\n', appRequests = 0, runChild, nativePid, output = '', nativeStdout = '';
  const children = new Set();
  if (upstream) {
    app = http.createServer((req, res) => { appRequests++; res.end(readyBody); });
    app.listen(0, '127.0.0.1'); await once(app, 'listening'); upstreamPort = app.address().port;
  }
  const archive = path.join(parent, 'alpha.tar.gz');
  assert.equal((await cli(source, 'pack', '--output', archive, '--manifest', manifestFile, '--binary', binary)).code, 0);
  await execute('tar', ['-xzf', archive, '-C', parent], { timeout: 10000 });
  const installer = path.join(parent, 'nginx-x10-alpha/install.mjs');
  const installed = await cli(installer, 'install', '--prefix', prefix, '--port', String(port), '--health-port', String(healthPort), ...(upstream ? ['--upstream-port', String(upstreamPort)] : []));
  assert.equal(installed.code, 0, installed.stdout);
  const lifeFile = path.join(installed.json.sessionPrefix, 'lifecycle.json');
  const spawnWait = (...args) => {
    const child = spawn(process.execPath, [launcher, 'wait-bind', ...args], { stdio: ['ignore', 'pipe', 'pipe'] }); children.add(child);
    let stdout = '', stderr = ''; child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b);
    const done = once(child, 'exit').then(([code, signal]) => { children.delete(child); return { code, signal, stdout, stderr, json: JSON.parse(stdout) }; });
    const ready = until(() => stderr.includes('wait-bind: waiting for native startup'));
    return { child, done, ready };
  };
  const start = async () => {
    output = ''; nativeStdout = '';
    runChild = spawn(process.execPath, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] }); children.add(runChild);
    runChild.stdout.on('data', b => { output += b; nativeStdout += b; const reportedPid = nativePidReport(nativeStdout); if (reportedPid !== null) nativePid = reportedPid; }); runChild.stderr.on('data', b => output += b);
    await until(() => { if (runChild.exitCode !== null || runChild.signalCode !== null) throw new Error(output); return output.includes('"outcome": "running"'); });
  };
  const stop = async () => { assert.equal((await cli(launcher, 'stop')).code, 0); await until(() => runChild.exitCode !== null || runChild.signalCode !== null); assert.equal(runChild.exitCode, 0, output); children.delete(runChild); nativePid = null; };
  t.after(async () => {
    for (const signal of ['SIGQUIT', 'SIGTERM', 'SIGKILL']) {
      if (nativePid) { try { process.kill(-nativePid, signal); } catch {} }
      for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      if (nativePid || children.size) await delay(75);
    }
    if (app) { app.closeAllConnections(); await new Promise(resolve => app.close(resolve)); }
    await rm(parent, { recursive: true, force: true });
  });
  return { parent, prefix, launcher, lifeFile, installed: installed.json, start, stop, spawnWait,
    setReadyBody: body => { readyBody = body; }, appRequests: () => appRequests };
}

test('wait-bind refuses malformed budgets before creating a lock and times out a prepared session', { timeout: 20000 }, async t => {
  const f = await waitBindFixture(t);
  for (const budget of ['0', '01', '-1', '1e3', '30001', ' 10000', '10000.0', 'Infinity']) {
    const result = await cli(f.launcher, 'wait-bind', '--timeout-ms', budget);
    assert(['invalid_wait_timeout', 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE'].includes(result.json.code)); assert.equal(await absent(path.join(f.prefix, '.alpha-lock')), true);
  }
  const result = await cli(f.launcher, 'wait-bind', '--timeout-ms', '150');
  assert.equal(result.code, 1); assert.equal(result.json.code, 'wait_bind_timeout'); assert.equal(result.json.bindingMayHaveCommitted, false);
  assert.equal((await cli(f.launcher, 'status')).json.binding, null); assert.equal(await absent(path.join(f.prefix, '.alpha-lock')), true);
});

test('installed wait-bind releases a startup lock and binds exactly the observed native session', { timeout: 25000 }, async t => {
  const f = await waitBindFixture(t);
  const lockFile = path.join(f.prefix, '.alpha-lock'); await writeFile(lockFile, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }), { mode: 0o600, flag: 'wx' });
  const oldBind = await cli(f.launcher, 'bind'); assert.equal(oldBind.json.code, 'alpha_locked', 'Existing bind retains its immediate lock refusal');
  const pending = f.spawnWait('--timeout-ms', '10000'); await delay(150);
  assert.equal(pending.child.exitCode, null); await rm(lockFile);
  await f.start();
  const result = await pending.done; assert.equal(result.code, 0, result.stdout); assert.equal(result.json.outcome, 'wait_bound'); assert.equal(result.json.session, f.installed.session);
  const status = await cli(f.launcher, 'status'); assert(status.json.binding); assert.equal(status.json.runtime.identityValid, true);
  const duplicate = await cli(f.launcher, 'wait-bind'); assert.equal(duplicate.json.code, 'already_bound'); assert.equal(duplicate.json.bindingMayHaveCommitted, true);
  await f.stop();
  assert.equal((await cli(f.launcher, 'wait-bind')).json.code, 'wait_bind_state');
});

test('wait-bind refuses changed, faulted and cancelled prepared sessions without binding', { timeout: 25000 }, async t => {
  const f = await waitBindFixture(t), original = await readFile(f.lifeFile);
  try {
    await amendRecord(f.lifeFile, v => { v.stage = 'faulted'; });
    assert.equal((await cli(f.launcher, 'wait-bind')).json.code, 'wait_bind_state');
  } finally { await writeFile(f.lifeFile, original); }
  const cancelled = f.spawnWait('--timeout-ms', '10000'); await cancelled.ready; cancelled.child.kill('SIGTERM');
  const refusal = await cancelled.done; assert.equal(refusal.code, 1); assert.equal(refusal.json.code, 'wait_bind_cancelled'); assert.equal(refusal.json.bindingMayHaveCommitted, false);
  assert.equal(await absent(path.join(f.prefix, '.alpha-lock')), true);
  const pending = f.spawnWait('--timeout-ms', '10000'); await pending.ready;
  const marker = path.join(f.prefix, '.alpha-registry.json'), registryBytes = await readFile(marker);
  try {
    const { sha256, ...v } = JSON.parse(registryBytes); v.sessions.push('a'.repeat(32));
    const temporary = path.join(f.prefix, 'registry-fixture.tmp');
    await writeFile(temporary, JSON.stringify({ ...v, sha256: digest(JSON.stringify(v)) }), { mode: 0o600, flag: 'wx' });
    const { rename } = await import('node:fs/promises'); await rename(temporary, marker);
    const changed = await pending.done; assert.equal(changed.code, 1); assert.equal(changed.json.code, 'wait_bind_changed');
  } finally { await writeFile(marker, registryBytes); }
  assert.equal((await cli(f.launcher, 'status')).json.binding, null);
});

test('wait-bind makes one real readiness attempt and refuses a wrong HTTP200 body', { timeout: 25000 }, async t => {
  const f = await waitBindFixture(t, { upstream: true }); f.setReadyBody('private-wrong-body\n'); await f.start();
  const result = await cli(f.launcher, 'wait-bind', '--timeout-ms', '10000');
  assert.equal(result.code, 1); assert.equal(result.json.code, 'health_gate_failed'); assert.equal(result.json.bindingMayHaveCommitted, true);
  assert.equal(result.stdout.includes('private-wrong-body'), false); assert(f.appRequests() > 0);
  assert.equal((await cli(f.launcher, 'status')).json.binding, null);
  f.setReadyBody('ready\n'); assert.equal((await cli(f.launcher, 'wait-bind')).json.outcome, 'wait_bound');
  await f.stop();
});

test('wait-bind retains possible durable binding after an injected alpha lock cleanup failure', { timeout: 25000 }, async t => {
  const f = await waitBindFixture(t); await f.start();
  const managerFile = path.join(f.prefix, 'lib/control/manager.mjs'), marker = path.join(f.prefix, '.alpha-install.json');
  const managerBytes = await readFile(managerFile), markerBytes = await readFile(marker), lockFile = path.join(f.prefix, '.alpha-lock');
  // Synthetic installed-library fault: real native bind completes, then only the
  // fixture-owned alpha lock becomes a directory. This is not a native defect.
  const changed = Buffer.from(managerBytes.toString().replace('export async function bind(state) {', 'async function fixtureOriginalBind(state) {') + `\nexport async function bind(state) {\n const result = await fixtureOriginalBind(state);\n const fs = await import('node:fs/promises');\n const lock = new URL('../../../.alpha-lock', 'file://' + state + '/');\n await fs.rm(lock); await fs.mkdir(lock, { mode: 0o700 });\n return result;\n}\n`);
  try {
    await chmod(managerFile, 0o600); await writeFile(managerFile, changed); await chmod(managerFile, 0o400);
    await amendRecord(marker, v => { v.immutable['lib/control/manager.mjs'].sha256 = digest(changed); v.immutable['lib/control/manager.mjs'].bytes = changed.length; });
    const result = await cli(f.launcher, 'wait-bind');
    assert.equal(result.code, 1); assert.equal(result.json.bindingMayHaveCommitted, true);
    assert.equal((await lstat(lockFile)).isDirectory(), true);
  } finally {
    await rm(lockFile, { recursive: true, force: true });
    await chmod(managerFile, 0o600); await writeFile(managerFile, managerBytes); await chmod(managerFile, 0o400); await writeFile(marker, markerBytes);
  }
  const status = await cli(f.launcher, 'status'); assert(status.json.binding, 'Durable bind must not be misreported as absent after alpha cleanup failed');
  await f.stop();
});


// The deterministic baseline ordering starts wait-bind while the prior native
// session is stopped. This reproduces a possible supervisor ordering, not the
// unobserved cause/interleaving of any earlier hosted failure.
test('prepare-run publishes a stable session before concurrent native run and wait-bind', { timeout: 30000 }, async t => {
  const f = await waitBindFixture(t);
  const initial = await cli(f.launcher, 'prepare-run');
  assert.equal(initial.code, 0); assert.equal(initial.json.session, f.installed.session);
  assert.equal(initial.json.nativeStarted, false); assert.equal(initial.json.readinessChecked, false);
  await assert.rejects(request((await cli(f.launcher, 'info')).json.port));
  await f.start(); assert.equal((await cli(f.launcher, 'wait-bind')).code, 0); await f.stop();
  const before = await cli(f.launcher, 'info'); assert.equal(before.json.stage, 'stopped');
  const early = await cli(f.launcher, 'wait-bind');
  assert.equal(early.code, 1); assert.equal(early.json.code, 'wait_bind_state');
  const next = await cli(f.launcher, 'prepare-run');
  assert.equal(next.code, 0); assert.equal(next.json.outcome, 'run_prepared');
  assert.notEqual(next.json.session, before.json.session);
  assert.equal(next.json.nativeStarted, false); assert.equal(next.json.readinessChecked, false);
  const marker = path.join(f.prefix, '.alpha-registry.json'), prepared = await readFile(marker);
  const again = await cli(f.launcher, 'prepare-run');
  assert.equal(again.code, 0); assert.equal(again.json.session, next.json.session);
  assert.deepEqual(await readFile(marker), prepared, 'Preparation must not rotate an already prepared session');
  const info = await cli(f.launcher, 'info'); assert.equal(info.json.stage, 'prepared');
  await assert.rejects(request(info.json.port)); await assert.rejects(request(info.json.healthPort));
  assert.equal((await cli(f.launcher, 'status')).json.binding, null);
  const lockFile = path.join(f.prefix, '.alpha-lock');
  await writeFile(lockFile, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }), { mode: 0o600, flag: 'wx' });
  const pending = f.spawnWait('--timeout-ms', '10000'); await pending.ready;
  await rm(lockFile); await f.start();
  const bound = await pending.done;
  assert.equal(bound.code, 0, bound.stdout); assert.equal(bound.json.session, next.json.session);
  assert.equal(bound.json.outcome, 'wait_bound'); assert.deepEqual(await readFile(marker), prepared);
  await f.stop(); assert.equal((await cli(f.launcher, 'uninstall')).code, 0);
});

test('prepare-run preserves live, faulted, locked and malformed prepared records', { timeout: 25000 }, async t => {
  const f = await waitBindFixture(t), marker = path.join(f.prefix, '.alpha-registry.json');
  const original = await readFile(f.lifeFile), registry = await readFile(marker), lockFile = path.join(f.prefix, '.alpha-lock');
  assert.equal((await cli(f.launcher, 'prepare-run', '--timeout-ms', '10000')).json.code, 'arguments');
  await writeFile(lockFile, '{}', { mode: 0o600, flag: 'wx' });
  try { assert.equal((await cli(f.launcher, 'prepare-run')).json.code, 'alpha_locked'); }
  finally { await rm(lockFile); }
  assert.deepEqual(await readFile(marker), registry); assert.deepEqual(await readFile(f.lifeFile), original);
  try {
    await amendRecord(f.lifeFile, life => { life.stage = 'faulted'; });
    assert.equal((await cli(f.launcher, 'prepare-run')).json.code, 'abnormal_exit');
    assert.deepEqual(await readFile(marker), registry);
  } finally { await writeFile(f.lifeFile, original); }
  try {
    await amendRecord(f.lifeFile, life => { life.controlSocket = path.join(f.prefix, 'unexpected.sock'); });
    assert.equal((await cli(f.launcher, 'prepare-run')).json.code, 'runtime_identity');
    assert.deepEqual(await readFile(marker), registry);
  } finally { await writeFile(f.lifeFile, original); }
  await f.start();
  assert.equal((await cli(f.launcher, 'prepare-run')).json.code, 'alpha_live');
  assert.deepEqual(await readFile(marker), registry); await f.stop();
  assert.equal((await cli(f.launcher, 'uninstall')).code, 0);
});
