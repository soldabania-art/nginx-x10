#!/usr/bin/env node
// Verify a built native candidate, not a simulated gateway. Never runs load tests.
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, readFile, realpath, stat, writeFile, rename } from 'node:fs/promises';
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
  const configHash = digest(await readFile(path.join(objects, 'ngx_auto_config.h')));
  const { stderr } = await execute(binary, ['-V'], { timeout: 10_000, maxBuffer: 256 * 1024 });
  if (stderr.trim() !== manifest.nginxVersionOutput?.trim()) throw new Error('Binary -V differs from its build manifest');
  return { binary, source, objects, manifestPath, manifestSha256: digest(manifestBytes), binarySha256: binaryHash,
    upstreamRevision: pin.commit, checkoutRevision: (await git(source, ['rev-parse', 'HEAD'])).trim(),
    sourceDiffSha256: digest(sourceDiff), generatedConfigSha256: configHash, nginxVersion: manifest.nginxVersion,
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
  if (kind === 'http') return data.success === true && Array.isArray(data.tests) && data.tests.length > 0 && data.tests.every(t => t.status === 'passed');
  if (kind === 'mail') return data.passed === true && Array.isArray(data.tests) && data.tests.length > 0 && data.tests.every(t => t.passed === true);
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
  const env = { X10_NGINX_BINARY: p.binary };
  const suites = [
    { name: 'http-tls-http2-reload', file: process.execPath, args: ['x10/test/http-baseline.mjs', '--binary', p.binary], kind: 'http' },
    { name: 'stream-mail', file: process.execPath, args: ['x10/test/stream-mail-baseline.mjs'], kind: 'mail' },
    { name: 'native-features', file: process.execPath, args: ['x10/test/features-baseline.mjs', '--binary', p.binary], kind: 'http' },
    { name: 'quic-regression', file: 'bash', args: ['x10/test/runner.sh', '--source', p.source, '--objs', p.objects], kind: 'quic' },
    { name: 'quic-generated-sanitized', file: 'bash', args: ['x10/test/quic-generated.sh', '--source', p.source, '--objs', p.objects], kind: 'generated' },
    { name: 'managed-native-control', file: process.execPath, args: ['--test', '--test-reporter=tap', 'x10/test/control.test.mjs'], kind: 'tap' },
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
      } else data = JSON.parse(run.stdout);
    } catch (error) { verificationError = `Invalid result: ${error.message}`; }
    let valid = false;
    if (data && !verificationError) {
      valid = suite.kind === 'tap' ? data.valid : jsonChecks(data, suite.kind);
      const observedBinaryHash = data.identity?.binarySha256 || data.binary?.sha256;
      if (observedBinaryHash && observedBinaryHash !== p.binarySha256) {
        valid = false; verificationError = 'Suite result identifies different binary bytes';
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
      after.generatedConfigSha256 !== p.generatedConfigSha256 || after.manifestSha256 !== p.manifestSha256) {
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
