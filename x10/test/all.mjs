#!/usr/bin/env node
// Verify a built native candidate, not a simulated gateway. Never runs load tests.
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, lstat, mkdir, readFile, realpath, stat, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const result = { schemaVersion: 1, suite: 'native-candidate', startedAt: new Date().toISOString(),
  provenance: null, suites: [], success: false,
  limitations: ['Local Linux fixtures, not a complete platform or interoperability matrix.',
    'Generated inputs, TAP assertions and protocol cases are reported separately, not added as interchangeable tests.',
    'Performance measurements require the separate benchmark runner and a quiet measurement window.'] };
let interrupted;
let activeStop;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  interrupted = signal;
  activeStop?.();
});

function options(argv) {
  const parsed = { binary: 'x10/.build/objs/nginx', manifest: 'x10/.build/manifest.json',
    objects: 'x10/.build/objs', source: root, official: false, provenanceOnly: false, output: null };
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i];
    if (name === '--help') return { help: true };
    if (name === '--official') { parsed.official = true; continue; }
    if (name === '--provenance-only') { parsed.provenanceOnly = true; continue; }
    const key = { '--binary': 'binary', '--manifest': 'manifest', '--objs': 'objects',
      '--source': 'source', '--output': 'output' }[name];
    if (!key || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Unknown or incomplete option: ${name}`);
    parsed[key] = argv[++i];
  }
  return parsed;
}

async function git(source, args) {
  return (await execute('git', args, { cwd: source, timeout: 10_000, maxBuffer: 8 * 1024 * 1024 })).stdout;
}

async function provenance(opts) {
  const binary = await realpath(path.resolve(root, opts.binary));
  const source = await realpath(path.resolve(root, opts.source));
  const objects = await realpath(path.resolve(root, opts.objects));
  const manifestPath = path.resolve(root, opts.manifest);
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  const info = await stat(binary);
  await access(binary, constants.X_OK);
  if (!info.isFile()) throw new Error('Selected binary is not a regular executable');
  const binaryHash = digest(await readFile(binary));
  if (manifest.status !== 'built' || manifest.binary?.sha256 !== binaryHash) {
    throw new Error('Built manifest does not identify the selected binary; rebuild before checking');
  }
  const pin = JSON.parse(await readFile(path.join(root, 'x10/upstream.json'), 'utf8'));
  if (manifest.upstreamRevision !== pin.commit) throw new Error('Build upstream revision differs from the project pin');
  const untracked = (await git(source, ['ls-files', '--others', '--exclude-standard', '--', 'src', 'auto', 'conf'])).trim();
  if (untracked) throw new Error('Untracked native source/configuration files are outside the build provenance');
  const sourceDiff = (await execute('git', ['diff', '--binary', pin.commit, '--', 'src', 'auto', 'conf'],
    { cwd: source, encoding: 'buffer', timeout: 10_000, maxBuffer: 8 * 1024 * 1024 })).stdout;
  if (digest(sourceDiff) !== manifest.sourceDiffSha256) {
    throw new Error('Native source changed after the recorded build; rebuild before checking');
  }
  const generatedFiles = {};
  for (const name of ['ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c']) {
    const recorded = manifest.generatedFiles?.[name];
    if (!recorded || !/^[a-f0-9]{64}$/.test(recorded.sha256 || '')) {
      throw new Error(`Build manifest lacks generated input identity for ${name}; rebuild before checking`);
    }
    const file = path.join(objects, name);
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Generated build input is not a regular file: ${name}`);
    const observed = { sha256: digest(await readFile(file)), bytes: info.size,
      mode: (info.mode & 0o7777).toString(8).padStart(4, '0') };
    if (observed.sha256 !== recorded.sha256 || observed.bytes !== recorded.bytes || observed.mode !== recorded.mode) {
      throw new Error(`Generated build input differs from its manifest: ${name}; rebuild before checking`);
    }
    generatedFiles[name] = observed;
  }
  const { stderr } = await execute(binary, ['-V'], { timeout: 10_000, maxBuffer: 256 * 1024 });
  if (stderr.trim() !== manifest.nginxVersionOutput?.trim()) throw new Error('Binary -V differs from its build manifest');
  return { binary, source, objects, manifestPath, manifestSha256: digest(manifestBytes), binarySha256: binaryHash,
    upstreamRevision: pin.commit, checkoutRevision: (await git(source, ['rev-parse', 'HEAD'])).trim(),
    sourceDiffSha256: digest(sourceDiff), generatedFiles, generatedConfigSha256: generatedFiles['ngx_auto_config.h'].sha256, nginxVersion: manifest.nginxVersion,
    compiledModuleCount: manifest.compiledModules.length };
}

function command(file, args, { timeoutMs, env }) {
  return new Promise(resolve => {
    const child = spawn(file, args, { cwd: root, env: { ...process.env, ...env }, detached: true,
      stdio: ['ignore', 'pipe', 'pipe'] });
    const started = Date.now();
    const stdout = [], stderr = [];
    let bytes = 0, stopped = false, timedOut = false, overflow = false, spawnError;
    let hardKill;
    const kill = signal => { if (child.pid) { try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') spawnError ||= error.message; } } };
    const stop = () => {
      if (stopped) return;
      stopped = true;
      kill('SIGTERM');
      // Give fixture handlers time to stop their own deliberately isolated children.
      hardKill = setTimeout(() => kill('SIGKILL'), 6500);
    };
    activeStop = stop;
    if (interrupted) stop();
    const collect = target => data => {
      bytes += data.length;
      if (bytes > 4 * 1024 * 1024) { overflow = true; stop(); }
      else target.push(data);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.on('error', error => { spawnError = error.message; });
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    child.on('close', (exitCode, signal) => {
      clearTimeout(timer);
      if (activeStop === stop) activeStop = undefined;
      if (hardKill) clearTimeout(hardKill);
      // Also stop any descendants left behind by an interrupted harness.
      if (stopped) kill('SIGKILL');
      resolve({ exitCode, signal, elapsedMs: Date.now() - started, timedOut, overflow,
        ...(spawnError ? { spawnError } : {}), stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8') });
    });
  });
}

function jsonChecks(data, kind) {
  if (kind === 'native-control' || kind === 'generations') {
    const generations = kind === 'generations', cleanup = data.cleanup;
    const serial = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
    const snapshot = (value, current) => value?.scope === 'master-process' && value.master_pid === data.identity?.master?.pid &&
      value.available === true && value.reason === '' && serial(value.current_generation) && value.current_generation === current &&
      Number.isInteger(value.excluded_detached) && value.excluded_detached >= 0 &&
      Array.isArray(value.processes) && value.processes.length > 0 && value.processes.length <= 1024 &&
      value.processes.every(p => typeof p.name === 'string' && p.name.length > 0 && p.name.length <= 128 &&
        Number.isSafeInteger(p.pid) && p.pid > 1 && Number.isInteger(p.slot) && p.slot >= 0 && p.slot < 1024 &&
        typeof p.exiting === 'boolean' && typeof p.exited === 'boolean' && serial(p.generation) && serial(p.birth) &&
        BigInt(p.generation) <= BigInt(current)) &&
      new Set(value.processes.map(p => p.pid)).size === value.processes.length &&
      new Set(value.processes.map(p => p.slot)).size === value.processes.length &&
      new Set(value.processes.map(p => p.birth)).size === value.processes.length;
    const valid = data.suite === (generations ? 'native-control-generations' : 'native-control-api-baseline') &&
      data.success === true && data.interrupted === false &&
      Array.isArray(data.tests) && data.tests.length === (generations ? 10 : 9) && data.tests.every(t => t.status === 'passed') &&
      Array.isArray(data.skips) && data.skips.length === 0 && Array.isArray(data.fixtureErrors) && data.fixtureErrors.length === 0 &&
      data.nativeErrorLogRead === true && Array.isArray(data.unexpectedNativeErrors) && data.unexpectedNativeErrors.length === 0 &&
      data.sourceUnchangedDuringTest === true && data.identity?.binaryUnchangedDuringTest === true &&
      Number.isSafeInteger(data.identity.master?.pid) && data.identity.master.pid > 1 &&
      data.identity.harnessUnchangedDuringTest === true && /^[a-f0-9]{64}$/.test(data.identity.binarySha256 || '') &&
      data.transport?.kind === 'tcp' && data.transport.host === '127.0.0.1' && data.transport.automaticFallback === false &&
      Number.isInteger(data.transport.port) && data.transport.port > 0 && data.transport.port <= 65535 &&
      cleanup?.nativeStopped === true && Array.isArray(cleanup.shutdowns) && cleanup.shutdowns.length === 2 &&
      cleanup.shutdowns.every(s => s.mode === 'SIGQUIT' && s.exited === true && s.exitCode === 0 && s.signal === null) &&
      cleanup.fixturesStopped === true && cleanup.openSockets === 0 && cleanup.temporaryRootRemoved === true &&
      Array.isArray(cleanup.errors) && cleanup.errors.length === 0;
    if (!generations) return valid;
    const o = data.observations, r = o?.respawn;
    return valid && data.mode === 'candidate' && data.identity.fixtureUnchangedDuringTest === true &&
      snapshot(o?.initialGeneration, '1') && snapshot(o.afterPatch, '2') && snapshot(o.afterHup, '3') && snapshot(r?.snapshot, '3') &&
      o.rejectedPatch?.status === 422 && o.rejectedPatch.generation === '2' &&
      o.rejectedHup?.generation === '3' && o.rejectedHup.actualRejectionLogged === true &&
      r?.victim?.generation === '3' && r.replacement?.generation === '3' &&
      serial(r.victim.birth) && serial(r.replacement.birth) && BigInt(r.replacement.birth) > BigInt(r.victim.birth) &&
      Number.isSafeInteger(r.victim.pid) && r.victim.pid > 1 && Number.isSafeInteger(r.replacement.pid) && r.replacement.pid > 1 &&
      r.victim.pid !== r.replacement.pid && Number.isInteger(r.victim.slot) && r.victim.slot >= 0 && r.victim.slot < 1024 && r.victim.slot === r.replacement.slot;
  }
  if (kind === 'generation-boundaries') return data.suite === 'native-generation-boundaries' && data.passed === true &&
    Array.isArray(data.tests) && data.tests.length === 20 && data.tests.every(t => t.passed === true) &&
    data.networkUsed === false && data.sourceUnchangedDuringTest === true && data.generatedFilesUnchangedDuringTest === true &&
    data.harnessUnchangedDuringTest === true && data.runnerUnchangedDuringTest === true &&
    data.compileExitCode === 0 && data.executionExitCode === 0 && data.sanitizerDiagnostics === '' &&
    data.sanitizers?.enabled?.includes('address') && data.sanitizers.enabled.includes('undefined') &&
    data.temporaryRootRemoved === true && data.activeChildren === 0 && data.interrupted === null;
  if (kind === 'handover') return data.suite === 'native-reload-listener-observation' && data.success === true &&
    data.nativeErrorLogRead === true && Array.isArray(data.unexpectedNativeErrors) && data.unexpectedNativeErrors.length === 0 &&
    data.interrupted === false && Array.isArray(data.tests) && data.tests.length === 7 && data.tests.every(t => t.status === 'passed') &&
    Array.isArray(data.skips) && data.skips.length === 0 && Array.isArray(data.fixtureErrors) && data.fixtureErrors.length === 0 &&
    data.sourceUnchangedDuringTest === true && data.identity?.binaryUnchangedDuringTest === true &&
    data.identity.harnessUnchangedDuringTest === true && data.identity.observerUnchangedDuringTest === true &&
    /^[a-f0-9]{64}$/.test(data.identity.binarySha256 || '') &&
    data.observations?.observerCapture?.scope === 'captured-processes-only' &&
    /^[a-f0-9]{64}$/.test(data.observations.observerCapture.sha256 || '') &&
    data.observations.observerWhileStopped?.scope === 'captured-processes-only' &&
    data.observations.observerAfterResume?.scope === 'captured-processes-only' &&
    data.observations.observerWhileStopped?.state === 'pending' && data.observations.observerWhileStopped.closed === false &&
    data.observations.observerWhileStopped.processes?.some(p => p.state === 'owns-listener') &&
    data.observations.observerAfterResume?.state === 'closed' && data.observations.observerAfterResume.closed === true &&
    data.observations.observerAfterResume.processes?.length > 0 &&
    data.observations.observerAfterResume.processes.every(p => ['listener-absent', 'exited'].includes(p.state)) &&
    data.observations.observerWhileStopped.snapshotSha256 === data.observations.observerCapture.sha256 &&
    data.observations.observerAfterResume.snapshotSha256 === data.observations.observerCapture.sha256 &&
    data.cleanup?.nativeStopped === true && data.cleanup.nativeExitCode === 0 && data.cleanup.nativeSignal === null &&
    data.cleanup.mode === 'SIGQUIT' && data.cleanup.stoppedWorkerResumeRequested === true &&
    data.cleanup.fixturesStopped === true && data.cleanup.openSockets === 0 && data.cleanup.temporaryRootRemoved === true &&
    Array.isArray(data.cleanup.errors) && data.cleanup.errors.length === 0;
  if (kind === 'adapters' || kind === 'mail-tls' || kind === 'http3' || kind === 'http3-head') {
    const mailTLS = kind === 'mail-tls';
    const cleanup = data.cleanup;
    const expectedSuite = { adapters: 'native-protocol-adapters', 'mail-tls': 'native-mail-tls-baseline', http3: 'native-http3-interop', 'http3-head': 'native-http3-head-interop' }[kind];
    return data.suite === expectedSuite &&
      (mailTLS ? data.passed === true : data.success === true) &&
      Array.isArray(data.tests) && data.tests.length > 0 &&
      data.tests.every(t => mailTLS ? t.passed === true : t.status === 'passed') &&
      Array.isArray(data.skips) && data.skips.length === 0 &&
      data.sourceUnchangedDuringTest === true && data.identity?.binaryUnchangedDuringTest === true &&
      /^[a-f0-9]{64}$/.test(data.identity?.binarySha256 || '') &&
      cleanup?.nativeStopped === true && cleanup.fixturesStopped === true &&
      cleanup.openSockets === 0 && cleanup.temporaryRootRemoved === true &&
      Array.isArray(cleanup.errors) && cleanup.errors.length === 0 &&
      (kind !== 'http3' || (data.protocol?.negotiatedAlpn === 'h3' && data.protocol.nativeHttp3 === 'h3' &&
        data.protocol.nativeRequestProtocol === 'HTTP/3.0' && /^[a-f0-9]{64}$/.test(data.dependencyLockSha256 || '') &&
        data.identity.clientUnchangedDuringTest === true && cleanup.udpTransportsStopped === true &&
        Number.isSafeInteger(cleanup.udpClientsCreated) && cleanup.udpClientsCreated > 0 && cleanup.udpClientsClosed === cleanup.udpClientsCreated)) &&
      (kind !== 'http3-head' || (data.tests.length === 4 && data.interruptedSignal === null &&
        Array.isArray(data.fixtureErrors) && data.fixtureErrors.length === 0 &&
        Array.isArray(data.unexpectedNativeErrors) && data.unexpectedNativeErrors.length === 0 &&
        data.protocol?.nativeHttp3 === 'h3' && data.protocol.nativeRequestProtocol === 'HTTP/3.0' &&
        data.protocol.clientHttpVersion === 30 && data.protocol.requestedHttpVersion === 'V3ONLY' &&
        data.identity.client?.name === 'curl_cffi' && data.identity.client.version === '0.16.3' && data.identity.clientUnchangedDuringTest === true &&
        data.identity.harnessUnchangedDuringTest === true && data.identity.launcherUnchangedDuringTest === true &&
        /^[a-f0-9]{64}$/.test(data.dependencyLockSha256 || '') && cleanup.nativeExit === 0 &&
        cleanup.clientProcessesCompleted === 4 && cleanup.clientSocketsClosed === true));
  }
  if (kind === 'http') return data.success === true && Array.isArray(data.tests) && data.tests.length > 0 && data.tests.every(t => t.status === 'passed');
  if (kind === 'mail') return data.passed === true && Array.isArray(data.tests) && data.tests.length > 0 && data.tests.every(t => t.passed === true);
  if (kind === 'load-client') return data.suite === 'native-http1-load-verification' && data.passed === true &&
    Array.isArray(data.tests) && data.tests.length > 0 && data.tests.every(t => t.passed === true) &&
    data.sourceUnchangedDuringTest === true && data.nativeBinaryUnchangedDuringTest === true &&
    /^[a-f0-9]{64}$/.test(data.nativeBinarySha256 || '') &&
    /^[a-f0-9]{64}$/.test(data.identity?.clientBinarySha256 || '') && /^[a-f0-9]{64}$/.test(data.identity?.buildManifestSha256 || '') &&
    data.sanitizers?.enabled?.includes('address') && data.sanitizers?.enabled?.includes('undefined') && data.sanitizers.diagnostics === '' &&
    data.cleanup?.nativeStopped === true && data.cleanup.fixtureServersClosed === true &&
    data.cleanup.openSockets === 0 && data.cleanup.activeChildren === 0 && data.cleanup.temporaryRootRemoved === true &&
    Array.isArray(data.cleanup.errors) && data.cleanup.errors.length === 0;
  if (kind === 'quic') return data.strict?.failed === 0 && data.strict?.caseCount > 0 && data.sourceUnchangedDuringTest === true;
  if (kind === 'generated') return data.passed === true && data.strict?.failed === 0 &&
    data.strict?.cases > 0 && data.sourceUnchangedDuringTest === true && data.compileExitCode === 0 &&
    data.executionExitCode === 0 && data.sanitizerDiagnostics === '' &&
    data.sanitizers?.enabled?.includes('address') && data.sanitizers?.enabled?.includes('undefined');
  if (kind === 'official') return data.success === true && data.sourceUnchangedDuringTest === true &&
    data.summary?.files > 0 && data.summary?.assertions?.passed > 0 && data.summary?.filesFailed === 0 &&
    data.summary?.assertions?.failed === 0;
  throw new Error(`No result validator for ${kind}`);
}

async function main() {
  const opts = options(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write('Usage: node x10/test/all.mjs [--official] [--provenance-only] [--binary FILE] [--manifest FILE] [--source DIR] [--objs DIR] [--output FILE]\n');
    return;
  }
  if (process.platform !== 'linux') throw new Error('This candidate-check profile currently supports Linux only');
  if (interrupted) throw new Error(`Interrupted by ${interrupted}`);
  result.provenance = await provenance(opts);
  result.mode = opts.provenanceOnly ? 'provenance-only' : 'functional-checks';
  if (opts.provenanceOnly) result.limitations.push('Only source/build identity was checked; no functional suite was run.');
  const p = result.provenance;
  const env = { X10_NGINX_BINARY: p.binary, X10_BUILD_MANIFEST: p.manifestPath };
  const suites = [
    { name: 'http-tls-http2-reload', file: process.execPath, args: ['x10/test/http-baseline.mjs', '--binary', p.binary], kind: 'http' },
    { name: 'stream-mail', file: process.execPath, args: ['x10/test/stream-mail-baseline.mjs'], kind: 'mail' },
    { name: 'mail-tls-starttls', file: process.execPath, args: ['x10/test/mail-tls-baseline.mjs', '--binary', p.binary], kind: 'mail-tls' },
    { name: 'protocol-adapters', file: process.execPath, args: ['x10/test/adapters-baseline.mjs', '--binary', p.binary], kind: 'adapters' },
    { name: 'http3-interop', file: process.execPath, args: ['x10/test/http3-baseline.mjs', '--binary', p.binary], kind: 'http3' },
    { name: 'http3-head-independent-client', file: process.execPath, args: ['x10/test/http3-head.mjs', '--binary', p.binary], kind: 'http3-head' },
    { name: 'native-features', file: process.execPath, args: ['x10/test/features-baseline.mjs', '--binary', p.binary], kind: 'http' },
    { name: 'quic-regression', file: 'bash', args: ['x10/test/runner.sh', '--source', p.source, '--objs', p.objects], kind: 'quic' },
    { name: 'quic-generated-sanitized', file: 'bash', args: ['x10/test/quic-generated.sh', '--source', p.source, '--objs', p.objects], kind: 'generated' },
    { name: 'quic-frame-boundaries', file: 'bash', args: ['x10/test/quic-frames.sh', '--source', p.source, '--objs', p.objects], kind: 'generated', frame: true },
    { name: 'native-load-client-verification', file: process.execPath, args: ['x10/bench/native-load.mjs', '--verify'], kind: 'load-client' },
    { name: 'managed-native-control', file: process.execPath, args: ['--test', '--test-reporter=tap', 'x10/test/control.test.mjs', 'x10/control/record-input.test.mjs', 'x10/test/alpha-recipe.test.mjs', 'x10/test/alpha-decomposition.test.mjs', 'x10/alpha/session-capacity.test.mjs', 'x10/alpha/prepare-run.test.mjs', 'x10/alpha/revision-capacity.test.mjs'], kind: 'tap', requireCompleteTAP: true },
    { name: 'operator-status', file: process.execPath, args: ['--test', '--test-reporter=tap', 'x10/test/operator-status.test.mjs'], kind: 'tap', requireCompleteTAP: true },
    { name: 'local-alpha-lifecycle', file: process.execPath, args: ['--test', '--test-reporter=tap', 'x10/test/alpha.test.mjs'], kind: 'tap', requireCompleteTAP: true },
    { name: 'listener-observer-boundaries', file: process.execPath, args: ['--test', '--test-reporter=tap', 'x10/test/listeners.test.mjs'], kind: 'tap' },
    { name: 'reload-listener-observation', file: process.execPath, args: ['x10/test/handover-baseline.mjs', '--binary', p.binary], kind: 'handover' },
    { name: 'native-control-api', file: process.execPath, args: ['x10/test/control-api-baseline.mjs', '--binary', p.binary, '--source', p.source, '--transport', 'tcp'], kind: 'native-control' },
    { name: 'native-process-generations', file: process.execPath, args: ['x10/test/generations.mjs', '--binary', p.binary, '--source', p.source, '--transport', 'tcp'], kind: 'generations' },
    { name: 'native-generation-boundaries', file: 'bash', args: ['x10/test/generation-boundaries.sh', '--source', p.source, '--objs', p.objects], kind: 'generation-boundaries' },
  ];
  if (opts.official) suites.push({ name: 'official-nginx-tests', file: 'bash', args: ['x10/test/official-tests.sh', '--binary', p.binary], kind: 'official', timeoutMs: 600_000 });
  for (const suite of opts.provenanceOnly ? [] : suites) {
    if (interrupted) break;
    process.stderr.write(`Checking ${suite.name}...\n`);
    const run = await command(suite.file, suite.args, { timeoutMs: suite.timeoutMs || 120_000, env });
    let data, verificationError;
    try {
      if (suite.kind === 'tap') {
        const pass = Number(run.stdout.match(/^# pass (\d+)\s*$/m)?.[1]);
        const fail = Number(run.stdout.match(/^# fail (\d+)\s*$/m)?.[1]);
        data = { format: 'node-test-tap', pass, fail, valid: pass > 0 && fail === 0 };
        if (suite.requireCompleteTAP) {
          data.total = Number(run.stdout.match(/^# tests (\d+)\s*$/m)?.[1]);
          data.skipped = Number(run.stdout.match(/^# skipped (\d+)\s*$/m)?.[1]);
          data.todo = Number(run.stdout.match(/^# todo (\d+)\s*$/m)?.[1]);
          data.cancelled = Number(run.stdout.match(/^# cancelled (\d+)\s*$/m)?.[1]);
          data.valid &&= data.total === pass && data.skipped === 0 && data.todo === 0 && data.cancelled === 0;
        }
      } else data = JSON.parse(run.stdout);
    } catch (error) { verificationError = `Invalid result: ${error.message}`; }
    let valid = false;
    if (data && !verificationError) {
      valid = suite.kind === 'tap' ? data.valid : jsonChecks(data, suite.kind);
      const observedBinaryHash = data.identity?.binarySha256 || data.binary?.sha256;
      if (observedBinaryHash && observedBinaryHash !== p.binarySha256) {
        valid = false; verificationError = 'Suite result identifies different binary bytes';
      }
      if (['mail-tls', 'adapters', 'http3', 'http3-head', 'handover', 'native-control', 'generations'].includes(suite.kind)) {
        if (typeof data.identity?.binary !== 'string' || path.resolve(data.identity.binary) !== p.binary) {
          valid = false; verificationError = 'Protocol suite result does not identify the selected binary path';
        }
      }
      if (suite.kind === 'native-control' || suite.kind === 'generations') {
        const filename = suite.kind === 'generations' ? 'generations.mjs' : 'control-api-baseline.mjs';
        if (data.identity?.harnessSha256 !== digest(await readFile(path.join(root, 'x10/test', filename))) ||
          data.identity?.sourceCheckout !== p.source) {
          valid = false; verificationError = 'Native control result identifies different fixture or source checkout';
        }
        if (suite.kind === 'generations' && data.identity?.fixtureSha256 !== digest(await readFile(path.join(root, 'x10/test/control-api-baseline.mjs')))) {
          valid = false; verificationError = 'Generation result identifies a different shared control fixture';
        }
        const files = ['src/core/nginx.c', 'src/os/unix/ngx_control.c', 'src/os/unix/ngx_process.c',
          'src/os/unix/ngx_process_cycle.c', 'src/core/ngx_cycle.c', 'src/os/unix/ngx_control.h', 'src/os/unix/ngx_process.h'];
        for (const file of files) if (data.identity?.sourceFilesSha256?.[file] !== digest(await readFile(path.join(p.source, file)))) {
          valid = false; verificationError = 'Native control result identifies different native source bytes';
        }
      }
      if (suite.kind === 'generation-boundaries') {
        if (data.sourceSha256 !== digest(await readFile(path.join(p.source, 'src/os/unix/ngx_control.c'))) ||
          data.harnessSha256 !== digest(await readFile(path.join(root, 'x10/test/generation-boundaries.c'))) ||
          data.runnerSha256 !== digest(await readFile(path.join(root, 'x10/test/generation-boundaries.sh'))) ||
          data.generatedConfigSha256 !== p.generatedConfigSha256) {
          valid = false; verificationError = 'Generation boundary result identifies different source or generated config';
        }
        for (const [name, record] of Object.entries(p.generatedFiles)) if (data.generatedFilesSha256?.[name] !== record.sha256) {
          valid = false; verificationError = 'Generation boundary result identifies different generated inputs';
        }
      }
      if (suite.kind === 'http3' && data.dependencyLockSha256 !== digest(await readFile(path.join(root, 'x10/test/http3-baseline.requirements.txt')))) {
        valid = false; verificationError = 'HTTP3 client result identifies a different dependency lock';
      }
      if (suite.kind === 'http3-head') {
        if (data.dependencyLockSha256 !== digest(await readFile(path.join(root, 'x10/test/http3-head.requirements.txt'))) ||
          data.identity?.harnessSha256 !== digest(await readFile(path.join(root, 'x10/test/http3-head.py'))) ||
          data.identity?.launcherSha256 !== digest(await readFile(path.join(root, 'x10/test/http3-head.mjs')))) {
          valid = false; verificationError = 'Independent HTTP3 result identifies different client lock or fixture source';
        }
      }
      if (suite.kind === 'handover') {
        if (data.identity?.harnessSha256 !== digest(await readFile(path.join(root, 'x10/test/handover-baseline.mjs'))) ||
          data.identity?.observerSha256 !== digest(await readFile(path.join(root, 'x10/control/listeners.mjs')))) {
          valid = false; verificationError = 'Handover result identifies different fixture or observer source';
        }
      }
      if (suite.kind === 'load-client') {
        if (data.nativeBinarySha256 !== p.binarySha256 || typeof data.nativeBinaryPath !== 'string' || path.resolve(data.nativeBinaryPath) !== p.binary) {
          valid = false; verificationError = 'Load-client verification did not use the selected native binary';
        }
        const sourceHash = digest(await readFile(path.join(root, 'x10/bench/native-load.c')));
        const wrapperHash = digest(await readFile(path.join(root, 'x10/bench/native-load.mjs')));
        if (data.identity?.clientSourceSha256 !== sourceHash || data.identity?.wrapperSha256 !== wrapperHash) {
          valid = false; verificationError = 'Load-client verification identifies different client/wrapper source';
        }
      }
      if (suite.kind === 'mail' && path.resolve(data.binary || '') !== p.binary) {
        valid = false; verificationError = 'Mail suite result identifies a different binary path';
      }
      if (suite.kind === 'quic' || suite.kind === 'generated') {
        const expected = digest(await readFile(path.join(p.source, 'src/event/quic/ngx_event_quic_transport.c')));
        if (data.sourceSha256 !== expected) { valid = false; verificationError = 'Parser result identifies different source bytes'; }
        if (data.generatedConfigSha256 !== p.generatedConfigSha256) {
          valid = false; verificationError = 'Parser result identifies different generated build headers';
        }
        if (suite.frame && (data.suite !== 'quic-frame-boundaries' || data.generatedFilesUnchangedDuringTest !== true || data.temporaryRootRemoved !== true)) {
          valid = false; verificationError = 'Frame parser result lacks its required identity or cleanup checks';
        }
      }
      if (suite.kind === 'official') {
        const selection = JSON.parse(await readFile(path.join(root, 'x10/test/official-tests.json'), 'utf8'));
        const expectedCount = Object.values(selection.families).reduce((n, files) => n + files.length, 0);
        if (data.source?.revision !== selection.revision || data.summary?.files !== expectedCount) {
          valid = false; verificationError = 'Official result differs from the pinned test selection';
        }
      }
    }
    result.suites.push({ name: suite.name, passed: run.exitCode === 0 && !run.timedOut && !run.overflow && !run.spawnError && valid,
      command: [suite.file, ...suite.args], exitCode: run.exitCode, signal: run.signal, elapsedMs: run.elapsedMs,
      timedOut: run.timedOut, outputLimitExceeded: run.overflow, ...(run.spawnError ? { spawnError: run.spawnError } : {}),
      ...(verificationError ? { verificationError } : {}), result: data || null,
      ...(run.stderr ? { diagnostic: run.stderr.slice(-16_384) } : {}),
      ...(suite.kind === 'tap' || !data ? { output: run.stdout.slice(-32_768) } : {}) });
  }
  // A parallel build or source edit invalidates the entire aggregate.
  const after = await provenance(opts);
  if (after.binarySha256 !== p.binarySha256 || after.sourceDiffSha256 !== p.sourceDiffSha256 ||
      JSON.stringify(after.generatedFiles) !== JSON.stringify(p.generatedFiles) || after.manifestSha256 !== p.manifestSha256) {
    throw new Error('Build or source identity changed during checks; rerun required');
  }
  result.success = !interrupted && (opts.provenanceOnly || result.suites.length > 0) && result.suites.every(suite => suite.passed);
  if (interrupted) result.interrupted = interrupted;
  result.finishedAt = new Date().toISOString();
  const serialized = JSON.stringify(result, null, 2) + '\n';
  if (opts.output) {
    const output = path.resolve(root, opts.output);
    await mkdir(path.dirname(output), { recursive: true });
    const temporary = `${output}.${process.pid}.tmp`;
    await writeFile(temporary, serialized, { mode: 0o600, flag: 'wx' });
    await rename(temporary, output);
  }
  process.stdout.write(serialized);
  if (!result.success) process.exitCode = 1;
}

main().catch(error => {
  result.success = false;
  result.error = error.message;
  result.finishedAt = new Date().toISOString();
  process.stderr.write(`${error.message}\n`);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exitCode = 1;
});
