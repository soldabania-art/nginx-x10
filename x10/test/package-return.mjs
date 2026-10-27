// Supported-host fixture only. Importing this module starts no process.
// A fixed legacy CLI plus separately reviewed current shared modules are
// combined with the current native build. This newly assembled private pair
// is not the complete historical runtime or a historical published package.
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { digest, inspectMaster, remainingNativeGroup } from '../alpha/runtime.mjs';
import { checkOperatorReturnProof, canActivateOperatorPackage } from './package-return-proof.mjs';
import { SHARED_OPERATOR_PEERS, verifySharedOperatorPeerFiles } from '../service/operator-package-return.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile), delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const historicalCommit = 'acb648392e745b5246a5620f2ea6a6286dc06d42';
const historicalBlob = 'f036791f3e843c3628964f5c61b0bc0ab903d6f9';
const historicalCliSha256 = '4560b8b2503f109f210599a6277bdf5497118e3220c1d2fb6a0c041283c3810d';
const controlNames = ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'];
const alphaNames = ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'];
const expectedStream = Buffer.alloc(256 * 1024, 0x73);
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const json = async file => JSON.parse(await readFile(file, 'utf8'));
const absent = file => lstat(file).then(() => false, error => { if (error.code === 'ENOENT') return true; throw error; });

async function waitFor(fn, milliseconds = 6500) {
  const end = performance.now() + milliseconds; let last;
  while (performance.now() < end) {
    try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
    await delay(25);
  }
  throw last || new Error('Operator return fixture observation timed out');
}
async function treeSnapshot(prefix) {
  const rows = [], stack = ['']; let total = 0;
  while (stack.length) {
    const relative = stack.pop(), file = path.join(prefix, relative), stat = await lstat(file);
    assert.equal(stat.isSymbolicLink(), false); assert.equal(stat.uid, process.getuid()); assert(rows.length < 4096);
    const identity = { dev: stat.dev, ino: stat.ino, uid: stat.uid, nlink: stat.nlink, mode: stat.mode,
      size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs };
    if (stat.isDirectory()) {
      assert.equal(stat.mode & 0o7777, 0o700);
      // Temporary cooperative locks alter directory timestamps, not file bytes.
      rows.push({ path: relative, directory: true, dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode });
      for (const name of await readdir(file)) stack.push(path.posix.join(relative, name));
    } else {
      assert.equal(stat.isFile(), true); assert.equal(stat.nlink, 1); assert(stat.size <= 64 * 1024 * 1024);
      total += stat.size; assert(total <= 256 * 1024 * 1024);
      const bytes = await readFile(file); assert.equal(bytes.length, stat.size);
      const after = await lstat(file);
      assert.deepEqual({ dev: after.dev, ino: after.ino, uid: after.uid, nlink: after.nlink, mode: after.mode,
        size: after.size, mtimeMs: after.mtimeMs, ctimeMs: after.ctimeMs }, identity);
      rows.push({ path: relative, directory: false, ...identity, sha256: digest(bytes) });
    }
  }
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
async function payload(prefix) {
  const names = ['bin/nginx', 'bin/x10', ...controlNames.map(name => `lib/control/${name}`),
    ...alphaNames.map(name => `lib/alpha/${name}`), 'lib/service/user-unit.mjs'].sort();
  const files = await Promise.all(names.map(async relative => {
    const file = path.join(prefix, relative), stat = await lstat(file);
    assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false); assert.equal(stat.nlink, 1); assert.equal(stat.uid, process.getuid());
    const bytes = await readFile(file);
    const mode = (stat.mode & 0o7777).toString(8).padStart(4, '0');
    assert.equal(mode, relative.startsWith('bin/') ? '0500' : '0400');
    return { path: relative, bytes: bytes.length, sha256: digest(bytes), mode };
  }));
  const fingerprint = rows => digest(JSON.stringify({ schemaVersion: 1, files: rows }));
  return { runtimePayloadSha256: fingerprint(files), operatorPayloadSha256: fingerprint(files.filter(row => row.path !== 'bin/nginx')),
    nativeBinarySha256: files.find(row => row.path === 'bin/nginx').sha256 };
}
async function transfer(port, route = '/', body = null) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path: route, method: body === null ? 'GET' : 'POST', agent: false,
      headers: body === null ? {} : { 'Content-Length': body.length, 'Content-Type': 'application/octet-stream' } }, response => {
      const chunks = []; let bytes = 0;
      response.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) request.destroy(new Error('Operator return response exceeds fixture limit')); else chunks.push(chunk); });
      response.on('error', reject); response.on('end', () => { clearTimeout(timer); resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }); });
    });
    const timer = setTimeout(() => request.destroy(new Error('Operator return request deadline')), 5000);
    request.setTimeout(1500, () => request.destroy(new Error('Operator return idle deadline')));
    request.on('error', error => { clearTimeout(timer); reject(error); }); request.end(body);
  });
}
async function listenerClosed(port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: '127.0.0.1', port }); let settled = false;
    const done = value => { if (settled) return; settled = true; socket.destroy(); resolve(value); };
    socket.setTimeout(1500, () => done(false));
    socket.once('connect', () => done(false));
    // Reset, timeout and malformed HTTP do not prove absence of a listener.
    socket.once('error', error => done(error.code === 'ECONNREFUSED'));
  });
}
async function reassembleHistoricalBundle(parent, bundle) {
  const object = `${historicalCommit}:x10/alpha/cli.mjs`;
  const identity = await execute('git', ['rev-parse', object], { cwd: root, timeout: 5000, maxBuffer: 4096 });
  assert.equal(identity.stdout.trim(), historicalBlob); assert.equal(identity.stderr, '');
  const source = await execute('git', ['show', object], { cwd: root, timeout: 5000, encoding: 'buffer', maxBuffer: 256 * 1024 });
  assert.equal(digest(source.stdout), historicalCliSha256); assert.equal(source.stderr.length, 0);
  // The old CLI pin and the reviewed current shared-peer pin are independent.
  // This assembled pair is not the complete historical runtime package.
  const peers = SHARED_OPERATOR_PEERS.files.map(row => row.path);
  const unchanged = await execute('git', ['diff', '--exit-code', SHARED_OPERATOR_PEERS.commit, '--', ...peers], { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 });
  assert.equal(unchanged.stdout, ''); assert.equal(unchanged.stderr, '');
  await verifySharedOperatorPeerFiles(bundle);
  assert.notEqual(digest(await readFile(path.join(bundle, 'x10/alpha/cli.mjs'))), historicalCliSha256);
  const selected = path.join(parent, 'return-historical-bundle'), original = await treeSnapshot(bundle);
  assert.equal(await absent(selected), true);
  for (const row of original.filter(row => row.directory).sort((a, b) => a.path.length - b.path.length))
    await mkdir(path.join(selected, row.path), { mode: 0o700 });
  for (const row of original.filter(row => !row.directory)) {
    await copyFile(path.join(bundle, row.path), path.join(selected, row.path), constants.COPYFILE_EXCL);
    await chmod(path.join(selected, row.path), row.mode & 0o7777);
  }
  const historicalCli = path.join(selected, 'x10/alpha/cli.mjs');
  await chmod(historicalCli, 0o600); await writeFile(historicalCli, source.stdout); await chmod(historicalCli, 0o400);
  const file = path.join(selected, 'bundle.json'), manifest = await json(file), { sha256, ...body } = manifest;
  assert.equal(digest(JSON.stringify(body)), sha256);
  body.files['x10/alpha/cli.mjs'] = { bytes: source.stdout.length, sha256: historicalCliSha256, mode: '0400' };
  await writeFile(file, encode({ ...body, sha256: digest(JSON.stringify(body)) }));
  for (const row of original.filter(row => !row.directory && !['bundle.json', 'x10/alpha/cli.mjs'].includes(row.path)))
    assert.equal(digest(await readFile(path.join(selected, row.path))), row.sha256);
  const candidate = await json(path.join(bundle, 'bundle.json')), { sha256: candidateHash, ...candidateBody } = candidate;
  const priorFiles = { ...body.files }; delete priorFiles['x10/alpha/cli.mjs'];
  const candidateFiles = { ...candidate.files }; delete candidateFiles['x10/alpha/cli.mjs'];
  assert.deepEqual(priorFiles, candidateFiles); assert.deepEqual({ ...body, files: null }, { ...candidateBody, files: null });
  return { directory: selected, snapshot: await treeSnapshot(selected) };
}

export async function assertHostedOperatorReturn(t, options) {
  const { parent, bundle, installer, recipeNode, verifyNode, command, port, healthPort, upstreamPort,
    setReadiness, getEchoRequests, getPostEffects, getStreamRequests, nativePidReport, preserveForInspection = () => {} } = options;
  const active = new Map(), prefixes = [], phases = [], legs = [], retainedFiles = new Map();
  const ordinalMaps = Object.fromEntries(['installation', 'session', 'revision', 'binding'].map(name => [name, new Map()]));
  const ordinal = (kind, value) => { const map = ordinalMaps[kind], key = JSON.stringify(value); if (!map.has(key)) map.set(key, map.size + 1); return map.get(key); };
  let savedA = null, historical = null, originalBundle = null, completed = false, cleaning = false;
  const checkAbort = () => { if (!cleaning && t.signal?.aborted) throw new Error('Operator return fixture was cancelled'); };
  const invoke = async (file, ...args) => { checkAbort(); const result = await command(file, ...args); assert.equal(result.stderr, '', 'Operator command stderr must remain empty'); return result; };
  const success = async (file, ...args) => { const result = await invoke(file, ...args); assert.equal(result.code, 0, 'Operator command must succeed'); return result.json; };
  const retainFile = async file => { const snapshot = await treeSnapshot(file); retainedFiles.set(file, snapshot); return snapshot; };
  const current = async prefix => {
    const manifest = await json(path.join(prefix, '.alpha-install.json')), registry = await json(path.join(prefix, '.alpha-registry.json'));
    const session = path.join(prefix, 'runs', registry.current), life = await json(path.join(session, 'lifecycle.json'));
    const result = await success(path.join(prefix, 'bin/x10'), 'status');
    assert.equal(result.pending, null); assert.equal(result.configUnchanged, true); assert.equal(result.fragmentMatchesLastConfirmed, true);
    const revision = await json(path.join(session, '.x10-control/revisions', `${result.lastConfirmedRevision}.json`));
    const { recordSha256, ...body } = revision; assert.equal(digest(JSON.stringify(body)), recordSha256);
    assert.equal(digest(JSON.stringify(revision.input)), revision.inputSha256);
    return { manifest, registry, session, life, status: result, revision };
  };
  const prepare = async prefix => {
    const value = await current(prefix);
    assert.equal(value.life.stage, 'prepared'); assert.equal(value.life.runtime, null); assert.equal(value.life.controlSocket, null);
    assert.equal(value.status.binding, null); assert.equal(value.status.history.entries, 1);
    assert.equal(value.revision.parent, null); assert.equal(value.revision.sourceRevision, null);
    assert.deepEqual(value.registry.sessions, [value.registry.current]);
    assert.equal(value.manifest.port, port); assert.equal(value.manifest.healthPort, healthPort);
    return value;
  };
  const start = async (name, prefix, expected, wrongReadiness = false) => {
    checkAbort(); await verifyNode(); checkAbort();
    const launcher = path.join(prefix, 'bin/x10'), child = spawn(recipeNode.nodeExecutable, [launcher, 'run'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const run = { name, prefix, launcher, child, stdout: '', stderr: '', outputError: null, runtime: null, session: null };
    active.set(prefix, run);
    child.once('error', () => { run.outputError = new Error('Owned operator launcher could not spawn'); });
    const capture = (key, bytes) => {
      if (run.outputError) return;
      if (Buffer.byteLength(run[key]) + bytes.length > 2 * 1024 * 1024) { run.outputError = new Error('Operator launcher output exceeded its bound'); return; }
      run[key] += bytes.toString('utf8');
    };
    child.stdout.on('data', bytes => capture('stdout', bytes)); child.stderr.on('data', bytes => capture('stderr', bytes));
    await waitFor(() => { checkAbort(); if (run.outputError) throw run.outputError; if (child.exitCode !== null || child.signalCode !== null) throw new Error('Operator launcher exited before startup'); return run.stdout.includes('"outcome": "running"') && Number.isSafeInteger(nativePidReport(run.stdout)); });
    const started = await current(prefix); assert.equal(started.life.stage, 'running');
    assert.equal(started.registry.current, expected.registry.current); assert.equal(started.revision.id, expected.revision.id);
    assert.equal(started.life.runtime.executable, path.join(prefix, 'bin/nginx'));
    assert.equal(nativePidReport(run.stdout), started.life.runtime.pid);
    assert.deepEqual(await inspectMaster(path.join(prefix, 'bin/nginx'), started.session, started.life.runtime), started.life.runtime);
    run.runtime = started.life.runtime; run.session = started.session; phases.push(`${name}_started`);
    if (wrongReadiness) {
      setReadiness('private-return-wrong-body\n');
      const refused = await invoke(launcher, 'bind'); assert.equal(refused.code, 1); assert.equal(refused.json.code, 'health_gate_failed');
      assert.equal(refused.stdout.includes('private-return-wrong-body'), false);
      const unbound = await current(prefix); assert.equal(unbound.status.binding, null); assert.equal(unbound.revision.id, expected.revision.id);
      phases.push('b_readiness_refused');
    }
    setReadiness('ready\n'); const bound = await success(launcher, 'bind'); assert.equal(bound.outcome, 'bound');
    const checked = await current(prefix), { networkNamespace, ...binding } = run.runtime;
    assert.deepEqual(checked.status.binding, binding); assert.equal(checked.status.runtime.identityValid, true);
    assert.equal(checked.status.runtime.observedRevision, checked.revision.id);
    assert.equal(checked.life.runtime.executable, path.join(prefix, 'bin/nginx'));
    return { run, checked };
  };
  const observeStopped = async prefix => {
    const run = active.get(prefix); assert(run && run.runtime && run.session);
    const value = await current(prefix), binary = path.join(prefix, 'bin/nginx');
    const masterAbsent = (await inspectMaster(binary, run.session, run.runtime, false)) === null;
    const processGroupAbsent = (await remainingNativeGroup(binary, run.runtime)).length === 0;
    const portsClosed = await listenerClosed(port) && await listenerClosed(healthPort);
    return { stage: value.life.stage, runtimeIdentityVerified: same(value.life.runtime, run.runtime), masterAbsent, processGroupAbsent,
      launcherExited: run.child.exitCode !== null || run.child.signalCode !== null, launcherExitCode: run.child.exitCode,
      launcherSignal: run.child.signalCode, portsClosed, operatorLockAbsent: await absent(path.join(prefix, '.alpha-lock')), pendingAbsent: value.status.pending === null };
  };
  const stop = async prefix => {
    const result = await success(path.join(prefix, 'bin/x10'), 'stop'); assert.equal(result.outcome, 'stopped');
    const run = active.get(prefix); await waitFor(() => run.child.exitCode !== null || run.child.signalCode !== null);
    const observation = await observeStopped(prefix); assert.equal(canActivateOperatorPackage(observation), true);
    return observation;
  };
  let beforeEcho, beforeEffects, beforeStreams;
  const expectedEffects = [];
  const serve = async (name, prefix, expectedMarker, inputHash) => {
    const state = await current(prefix), run = active.get(prefix); assert(run && run.runtime && run.session);
    assert.equal(state.session, run.session); assert.deepEqual(state.life.runtime, run.runtime);
    assert.deepEqual(await inspectMaster(path.join(prefix, 'bin/nginx'), run.session, run.runtime), run.runtime);
    const { networkNamespace, ...expectedBinding } = run.runtime;
    assert.deepEqual(state.status.binding, expectedBinding); assert.equal(state.status.runtime.identityValid, true);
    assert.equal(state.status.runtime.observedRevision, state.revision.id);
    const response = await transfer(port);
    assert.equal(response.status, 200); assert.equal(response.body.toString(), 'independent application\n');
    assert.equal(response.headers['x-app-marker'], 'independent-upstream'); assert.equal(response.headers['x-x10-return-state'], expectedMarker);
    const revision = await transfer(port, '/__x10_revision'); assert.equal(revision.status, 200);
    assert.equal(revision.body.toString(), state.revision.id); assert.equal(revision.headers['x-x10-revision'], state.revision.id);
    assert.equal(state.revision.inputSha256, inputHash);
    const requestBody = Buffer.alloc(65551); for (let index = 0; index < requestBody.length; index++) requestBody[index] = (index * 37 + legs.length) & 255;
    const echoed = await transfer(port, '/echo', requestBody); assert.equal(echoed.status, 200); assert.deepEqual(echoed.body, requestBody);
    assert.equal(echoed.headers['x-x10-return-state'], expectedMarker); assert.equal(getEchoRequests(), beforeEcho + legs.length + 1);
    expectedEffects.push({ bytes: requestBody.length, sha256: digest(requestBody) });
    assert.equal(new Set(expectedEffects.map(value => value.sha256)).size, expectedEffects.length);
    assert.deepEqual(getPostEffects(), [...beforeEffects, ...expectedEffects]);
    const stream = await transfer(port, '/stream'); assert.equal(stream.status, 200); assert.equal(stream.body.length, expectedStream.length);
    assert.equal(digest(stream.body), digest(expectedStream)); assert.equal(stream.headers['x-x10-return-state'], expectedMarker);
    assert.equal(getEchoRequests(), beforeEcho + legs.length + 1); assert.deepEqual(getPostEffects(), [...beforeEffects, ...expectedEffects]);
    assert.equal(getStreamRequests(), beforeStreams + legs.length + 1);
    legs.push({ name, identityOrdinals: { installation: ordinal('installation', state.manifest.installationId),
      session: ordinal('session', state.registry.current), revision: ordinal('revision', state.revision.id), binding: ordinal('binding', state.status.binding) },
      inputSha256: state.revision.inputSha256, initialBindingAbsent: true, readinessAccepted: true,
      bindingMatchesOwnedRuntime: true, getExact: true, postExact: true, streamExact: true,
      postEffectsBefore: legs.length, postEffectsAfter: legs.length + 1, stop: null });
    return state;
  };
  try {
    checkAbort(); originalBundle = await treeSnapshot(bundle); historical = await reassembleHistoricalBundle(parent, bundle);
    const sourceA = path.join(parent, 'return-source-a'), targetB = path.join(parent, 'return-target-b'), targetA2 = path.join(parent, 'return-target-a2');
    const launcherA = path.join(sourceA, 'bin/x10'), launcherB = path.join(targetB, 'bin/x10');
    const oldInstaller = path.join(historical.directory, 'install.mjs');
    beforeEcho = getEchoRequests(); beforeEffects = getPostEffects(); beforeStreams = getStreamRequests();
    setReadiness('ready\n'); prefixes.push(sourceA);
    await success(oldInstaller, 'install', '--prefix', sourceA, '--port', String(port), '--health-port', String(healthPort), '--upstream-port', String(upstreamPort));
    const preparedA = await prepare(sourceA), identityA = await payload(sourceA);
    assert.equal(digest(await readFile(path.join(sourceA, 'lib/alpha/cli.mjs'))), historicalCliSha256);
    await start('a', sourceA, preparedA); const stateP = await serve('a', sourceA, undefined, preparedA.revision.inputSha256); phases.push('a_served');
    legs[0].stop = await stop(sourceA); phases.push('a_stopped');
    const backupA = path.join(parent, 'operator-return-a-p.json'); await success(launcherA, 'backup', '--output', backupA); await retainFile(backupA);
    const knownGood = await json(backupA); assert.deepEqual(knownGood.input, stateP.revision.input); assert.equal(knownGood.inputSha256, stateP.revision.inputSha256);
    savedA = await treeSnapshot(sourceA);
    assert.equal(canActivateOperatorPackage(await observeStopped(sourceA)), true);
    const bundleManifestSha256 = digest(await readFile(path.join(bundle, 'bundle.json'))); prefixes.push(targetB);
    const staged = await success(installer, 'stage', '--source-prefix', sourceA, '--prefix', targetB,
      '--expected-source-payload', identityA.runtimePayloadSha256, '--expected-bundle-manifest', bundleManifestSha256);
    assert.equal(staged.outcome, 'package_staged'); assert.equal(staged.activationPerformed, false); assert.equal(staged.nativeStarted, false);
    const preparedB = await prepare(targetB), identityB = await payload(targetB);
    assert.notEqual(identityA.runtimePayloadSha256, identityB.runtimePayloadSha256); assert.notEqual(identityA.operatorPayloadSha256, identityB.operatorPayloadSha256);
    assert.equal(identityA.nativeBinarySha256, identityB.nativeBinarySha256); assert.deepEqual(preparedB.revision.input, stateP.revision.input);
    assert.equal(preparedB.revision.inputSha256, stateP.revision.inputSha256);
    assert.notEqual(preparedB.manifest.installationId, preparedA.manifest.installationId); assert.notEqual(preparedB.registry.current, preparedA.registry.current);
    assert.notEqual(preparedB.revision.id, preparedA.revision.id); assert.deepEqual(await treeSnapshot(sourceA), savedA); phases.push('b_staged');
    assert.equal(canActivateOperatorPackage(await observeStopped(sourceA)), true);
    await start('b', targetB, preparedB, true);
    const candidate = { ...stateP.revision.input, serverBody: `${stateP.revision.input.serverBody}\nadd_header X-X10-Return-State "q" always;` };
    const candidateFile = path.join(parent, 'operator-return-q.json'); await writeFile(candidateFile, encode(candidate), { mode: 0o600, flag: 'wx' }); await retainFile(candidateFile);
    const applied = await success(launcherB, 'apply', '--file', candidateFile); assert.equal(applied.outcome, 'applied');
    // Idempotent observations can repeat while old workers drain. The unique
    // POST below is sent once and is never retried on an ambiguous result.
    await waitFor(async () => (await transfer(port)).headers['x-x10-return-state'] === 'q');
    const stateQ = await current(targetB); assert.deepEqual(stateQ.revision.input, candidate);
    assert.notEqual(stateP.revision.inputSha256, stateQ.revision.inputSha256);
    await serve('b', targetB, 'q', stateQ.revision.inputSha256); phases.push('b_served');
    legs[1].stop = await stop(targetB); phases.push('b_stopped'); assert.deepEqual(await treeSnapshot(sourceA), savedA);
    const backupB = path.join(parent, 'operator-return-b-q.json'); await success(launcherB, 'backup', '--output', backupB); await retainFile(backupB);
    const backup = await json(backupB); assert.deepEqual(backup.input, stateQ.revision.input); assert.equal(backup.inputSha256, stateQ.revision.inputSha256);
    assert.equal(backup.source.installationId, preparedB.manifest.installationId); assert.equal(backup.source.session, preparedB.registry.current);
    assert.equal(backup.source.revision, stateQ.revision.id); assert.equal(backup.port, port); assert.equal(backup.healthPort, healthPort);
    assert.equal(canActivateOperatorPackage(await observeStopped(targetB)), true); prefixes.push(targetA2);
    const restored = await success(oldInstaller, 'install', '--prefix', targetA2, '--restore', backupB);
    assert.equal(restored.declarativeRestored, true); assert.equal(restored.nativeStarted, false); assert.equal(restored.readinessChecked, false);
    const preparedA2 = await prepare(targetA2), identityA2 = await payload(targetA2); assert.deepEqual(identityA2, identityA);
    assert.deepEqual(preparedA2.revision.input, stateQ.revision.input); assert.equal(preparedA2.revision.inputSha256, stateQ.revision.inputSha256);
    for (const previous of [preparedA, preparedB]) {
      assert.notEqual(preparedA2.manifest.installationId, previous.manifest.installationId); assert.notEqual(preparedA2.registry.current, previous.registry.current);
      assert.notEqual(preparedA2.revision.id, previous.revision.id);
    }
    assert.deepEqual(await treeSnapshot(sourceA), savedA); phases.push('a2_restored');
    assert.equal(canActivateOperatorPackage(await observeStopped(targetB)), true);
    await start('a2', targetA2, preparedA2); await serve('a2', targetA2, 'q', preparedA2.revision.inputSha256); phases.push('a2_served');
    legs[2].stop = await stop(targetA2); phases.push('a2_stopped');
    assert.deepEqual(await treeSnapshot(sourceA), savedA);
    for (const [file, snapshot] of retainedFiles) assert.deepEqual(await treeSnapshot(file), snapshot);
    assert.deepEqual(await treeSnapshot(bundle), originalBundle); assert.deepEqual(await treeSnapshot(historical.directory), historical.snapshot);
    assert.equal(getEchoRequests(), beforeEcho + 3); assert.deepEqual(getPostEffects(), [...beforeEffects, ...expectedEffects]); assert.equal(getStreamRequests(), beforeStreams + 3);
    for (const prefix of [...prefixes].reverse()) {
      assert.equal(canActivateOperatorPackage(await observeStopped(prefix)), true);
      await success(path.join(prefix, 'bin/x10'), 'uninstall'); assert.equal(await absent(prefix), true); active.delete(prefix);
    }
    assert.deepEqual(await treeSnapshot(historical.directory), historical.snapshot);
    await rm(historical.directory, { recursive: true }); assert.equal(await absent(historical.directory), true);
    for (const [file, snapshot] of retainedFiles) { assert.deepEqual(await treeSnapshot(file), snapshot); await rm(file); assert.equal(await absent(file), true); }
    phases.push('cleanup');
    const proof = { schemaVersion: 1, kind: 'nginx-x10-operator-package-return-proof',
      packages: { a: identityA, b: identityB, a2: identityA2 },
      inputs: { pSha256: stateP.revision.inputSha256, qSha256: stateQ.revision.inputSha256, a2RestoredSha256: preparedA2.revision.inputSha256 },
      phases, legs,
      staging: { commandExercised: true, sourcePreserved: true, initialBindingAbsent: true, initialInputSha256: preparedB.revision.inputSha256,
        runtimePayloadChanged: true, operatorPayloadChanged: true, nativeBinaryChanged: false },
      controls: { bWrongReadinessRefused: true, bBindingAbsentAfterRefusal: true, retainedAAllFilesPreserved: true,
        retainedABackupPreserved: true, forwardStartedAfterConfirmedStop: true, returnStartedAfterConfirmedStop: true, oldAInstallerRestoredQ: true },
      cleanup: { known: true, ownedProcessesAbsent: true, ownedLaunchersAbsent: true, ownedListenersClosed: true,
        ownedInstallationsRemoved: prefixes.length, historicalBundleRemoved: true, backupFilesRemoved: true },
      limits: { consistencyOnly: true, nativeBinaryUpgradeAccepted: false, liveConnectionPreserved: false,
        applicationSideEffectsReversed: false, managedServiceAccepted: false, productionAccepted: false } };
    assert.equal(checkOperatorReturnProof(proof).ok, true); completed = true;
    t.diagnostic(JSON.stringify({ suite: 'x10-operator-package-return', profile: 'foreground-http-reassembled-reviewed-operator-a-b-a2',
      historicalOperatorCommit: historicalCommit, historicalOperatorBlob: historicalBlob, historicalOperatorSha256: historicalCliSha256,
      historicalBundleReassembled: true, publishedHistoricalBundle: false, completedUniquePostEffects: expectedEffects.length,
      completedStreams: getStreamRequests() - beforeStreams, ...proof }));
    return proof;
  } catch (error) {
    cleaning = true; let cleanupUnknown = false;
    for (const [prefix, run] of active) {
      try {
        if (run.child.exitCode === null && run.child.signalCode === null) {
          // The installed stop checks its exact recorded owned identity before
          // signalling. There is no unverified PID/group or killall fallback.
          const result = await command(run.launcher, 'stop'); assert.equal(result.code, 0);
          await waitFor(() => run.child.exitCode !== null || run.child.signalCode !== null);
        }
        if (!run.runtime || !run.session) throw new Error('Startup ownership was not confirmed');
        assert.equal(canActivateOperatorPackage(await observeStopped(prefix)), true);
      } catch { cleanupUnknown = true; }
    }
    // Failure retains even stopped prefixes and configuration for diagnosis.
    // The caller must not recursively erase the containing private directory.
    preserveForInspection(); error.packageReturnCleanupUnknown = cleanupUnknown; error.packageReturnPreserveForInspection = true;
    throw error;
  } finally { if (!completed && active.size) preserveForInspection(); }
}
