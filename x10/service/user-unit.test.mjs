import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, chmod, writeFile, readFile, lstat, rm, symlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectInstallation, main, renderUserUnit, RECIPE_LIMITATIONS } from './user-unit.mjs';
const run = promisify(execFile), cli = fileURLToPath(new URL('./user-unit.mjs', import.meta.url));
const hash = b => createHash('sha256').update(b).digest('hex');
const good = { prefix: '/tmp/x10-example/prefix', nodeExecutable: '/usr/bin/node' };
async function fixture(fn) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'x10-unit-')), prefix = root + '/prefix', nodeExecutable = root + '/node';
  try {
    await mkdir(prefix, { mode: 0o700 }); await mkdir(prefix + '/bin', { mode: 0o700 });
    const launcher = Buffer.from('#!/usr/bin/env node\n// synthetic nonexecuted launcher fixture\n'), node = Buffer.from('synthetic nonexecuted node fixture\n');
    await writeFile(prefix + '/bin/x10', launcher, { mode: 0o500 }); await writeFile(nodeExecutable, node, { mode: 0o500 });
    const s = await lstat(prefix), manifest = {
      schemaVersion: 1, kind: 'nginx-x10-local-alpha', installationId: 'a'.repeat(32), prefix,
      rootIdentity: { dev: s.dev, ino: s.ino, uid: s.uid },
      immutable: { 'bin/x10': { bytes: launcher.length, sha256: hash(launcher), mode: '0500' } },
      nodeRuntime: { version: 'v22.23.3', executable: nodeExecutable, sha256: hash(node) },
    };
    const save = async () => writeFile(prefix + '/.alpha-install.json', JSON.stringify({ ...manifest, sha256: hash(JSON.stringify(manifest)) }), { mode: 0o600 });
    await save();
    await fn({ root, prefix, nodeExecutable, manifest, save });
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('rendered recipe starts the explicit node and only requests guarded launcher stop', () => {
  const unit = renderUserUnit(good);
  assert.match(unit, /ExecStart=\/usr\/bin\/node \/tmp\/x10-example\/prefix\/bin\/x10 run --control-socket \/tmp\/x10-example\/prefix\/control.sock\n/);
  assert.match(unit, /ExecStop=\/usr\/bin\/node \/tmp\/x10-example\/prefix\/bin\/x10 stop\n/);
  for (const line of ['Type=exec', 'Restart=no', 'KillMode=process', 'KillSignal=SIGTERM', 'SendSIGKILL=no', 'TimeoutStartSec=30s', 'TimeoutStopSec=30s', 'UMask=0077', 'UnsetEnvironment=NODE_OPTIONS NODE_PATH NGINX_CTRL']) assert.ok(unit.split('\n').includes(line));
  assert.doesNotMatch(unit, /^ExecStartPost=|^ExecStopPost=|^User=|^Group=|\/bin\/sh|killall|SIGKILL=yes/gm);
  assert.equal(RECIPE_LIMITATIONS.readinessAutomated, false);
  assert.equal(RECIPE_LIMITATIONS.serviceAccepted, false);
});

test('path injection, aliases and unknown options refuse without generating a unit', () => {
  const bad = ['', '/', '/prefix', 'relative', '/tmp/a b', '/tmp/a\nb', '/tmp/a\rb', '/tmp/a%20', '/tmp/a$b', '/tmp/a;b', '/tmp/a\\b', '/tmp/a"b', '/tmp/a\'b', '/tmp/a/../b', '/tmp//a', '/tmp/a/', '/tmp/é'];
  for (const prefix of bad) assert.throws(() => renderUserUnit({ ...good, prefix }), /service_recipe_invalid/);
  for (const nodeExecutable of bad.filter(x => x !== '/prefix')) assert.throws(() => renderUserUnit({ ...good, nodeExecutable }), /service_recipe_invalid/);
  assert.throws(() => renderUserUnit({ ...good, extra: true }), /service_recipe_invalid/);
});

test('AF_UNIX path bound accepts107bytes and refuses108bytes before generation', () => {
  assert.doesNotThrow(() => renderUserUnit({ ...good, prefix: '/tmp/' + 'a'.repeat(89) }));
  assert.throws(() => renderUserUnit({ ...good, prefix: '/tmp/' + 'a'.repeat(90) }), /service_recipe_invalid/);
});

test('read-only inspection binds manifest, launcher and exact recorded node without executing them', () => fixture(async f => {
  const before = await readFile(f.prefix + '/.alpha-install.json');
  const result = await inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable });
  assert.equal(result.installationChecked, true); assert.equal(result.recordedNodeChecked, true);
  assert.equal(result.fullInstallationAccepted, false); assert.equal(result.targetRuntimeAccepted, false);
  assert.deepEqual(await readFile(f.prefix + '/.alpha-install.json'), before);
}));

test('manifest tampering refuses even when its JSON remains valid', () => fixture(async f => {
  const p = f.prefix + '/.alpha-install.json', v = JSON.parse(await readFile(p)); v.installationId = 'b'.repeat(32); await writeFile(p, JSON.stringify(v));
  await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('rehashed root identity mismatch refuses', () => fixture(async f => {
  f.manifest.rootIdentity.ino++; await f.save(); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('launcher content drift and mode drift refuse', () => fixture(async f => {
  await chmod(f.prefix + '/bin/x10', 0o700); await writeFile(f.prefix + '/bin/x10', 'changed'); await chmod(f.prefix + '/bin/x10', 0o500);
  await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('group-visible launcher and nonprivate prefix refuse', () => fixture(async f => {
  await chmod(f.prefix + '/bin/x10', 0o550); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
  await chmod(f.prefix + '/bin/x10', 0o500); await chmod(f.prefix, 0o750); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('prefix and launcher symlinks refuse without following payloads', () => fixture(async f => {
  await symlink(f.prefix, f.root + '/alias'); await assert.rejects(inspectInstallation({ prefix: f.root + '/alias', nodeExecutable: f.nodeExecutable }));
  const launcher = f.prefix + '/bin/x10'; await rm(launcher); await symlink(f.nodeExecutable, launcher); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('node executable path and bytes must equal recorded pin', () => fixture(async f => {
  await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: '/usr/bin/node' }));
  await chmod(f.nodeExecutable, 0o700); await writeFile(f.nodeExecutable, 'changed'); await chmod(f.nodeExecutable, 0o500); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('node symlink and writable executable refuse', () => fixture(async f => {
  await chmod(f.nodeExecutable, 0o777); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
  await chmod(f.nodeExecutable, 0o500); await symlink(f.nodeExecutable, f.root + '/node-link');
  f.manifest.nodeRuntime.executable = f.root + '/node-link'; await f.save(); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.root + '/node-link' }));
}));

test('manifest symlink and oversized manifest refuse', () => fixture(async f => {
  const p = f.prefix + '/.alpha-install.json'; await writeFile(p, Buffer.alloc(2 * 1024 * 1024 + 1)); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
  await rm(p); await symlink(f.nodeExecutable, p); await assert.rejects(inspectInstallation({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('CLI emits only a recipe after inspection; synthetic launchers and node are not run', () => fixture(async f => {
  const { stdout, stderr } = await run(process.execPath, [cli, '--prefix', f.prefix, '--node', f.nodeExecutable], { timeout: 5000, maxBuffer: 65536 });
  assert.equal(stderr, ''); assert.equal(stdout, renderUserUnit({ prefix: f.prefix, nodeExecutable: f.nodeExecutable }));
}));

test('CLI invalid usage and nonexistent installation return fixed sanitized errors', async () => {
  for (const args of [[], ['--prefix', '/tmp/missing', '--node', '/usr/bin/node'], ['--help'], ['--prefix', '/tmp/a', '--node', '/bin/node', '--enable']]) {
    const result = await main(args); assert.equal(result.ok, false); assert.equal(result.code, 'service_recipe_invalid'); assert.equal(result.serviceAccepted, false);
    assert.doesNotMatch(JSON.stringify(result), /\/tmp\/|\/usr\/|\/bin\//);
  }
});

test('CLI invoked through a script alias still executes refusal rather than silent success', () => fixture(async f => {
  const alias = f.root + '/generator.mjs'; await symlink(cli, alias);
  await assert.rejects(run(process.execPath, [alias, '--bad'], { timeout: 5000, maxBuffer: 65536 }), e => {
    assert.equal(e.code, 1); assert.equal(e.stderr, ''); assert.equal(JSON.parse(e.stdout).code, 'service_recipe_invalid'); return true;
  });
}));
