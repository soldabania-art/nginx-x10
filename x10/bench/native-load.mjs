#!/usr/bin/env node
// Build and functionally verify the bounded native load client, not a speed claim.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const source = path.join(root, 'x10/bench/native-load.c');
const buildDirectory = path.join(root, 'x10/.build/native-load');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const payload = Buffer.from(Array.from({ length: 1024 }, (_, i) => 33 + i % 90));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const active = new Set(), terminators = new Map();
let interrupted;
function stop(child, signal = 'SIGTERM') {
  if (!child.pid) return;
  try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  interrupted = signal;
  for (const child of active) terminators.get(child)?.();
});
function run(file, args, { timeoutMs = 3000, env = {}, onSpawn } = {}) {
  return new Promise(resolve => {
    const child = spawn(file, args, { cwd: root, detached: true, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    active.add(child);
    let stdout = '', stderr = '', bytes = 0, spawnError, timedOut = false, hardKill;
    const terminate = () => { stop(child); hardKill ||= setTimeout(() => stop(child, 'SIGKILL'), 750); };
    terminators.set(child, terminate);
    const timer = setTimeout(() => { timedOut = true; terminate(); }, timeoutMs);
    const collect = kind => data => {
      bytes += data.length;
      if (bytes > 1024 * 1024) { spawnError = 'Output limit exceeded'; terminate(); }
      else if (kind === 'stdout') stdout += data.toString(); else stderr += data.toString();
    };
    child.stdout.on('data', collect('stdout')); child.stderr.on('data', collect('stderr'));
    child.once('error', error => { spawnError = error.message; });
    child.once('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(hardKill); stop(child, 'SIGKILL'); terminators.delete(child); active.delete(child);
      resolve({ code, signal, stdout, stderr, timedOut, ...(spawnError ? { spawnError } : {}) });
    });
    onSpawn?.(child);
    if (interrupted) terminate();
  });
}
async function build(sanitized = false) {
  await mkdir(buildDirectory, { recursive: true });
  const name = sanitized ? 'native-load-asan' : 'native-load';
  const binary = path.join(buildDirectory, name), temporary = `${binary}.tmp-${process.pid}`;
  const sourceSha256 = sha(await readFile(source));
  const compiler = await run('cc', ['--version']);
  if (compiler.code !== 0) throw new Error(`Compiler identity failed: ${compiler.stderr}`);
  const args = sanitized
    ? ['-O1', '-g', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', source, '-o', temporary]
    : ['-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', source, '-o', temporary];
  const compiled = await run('cc', args, { timeoutMs: 30000 });
  if (compiled.code !== 0 || compiled.signal || compiled.timedOut || compiled.spawnError) {
    await rm(temporary, { force: true }); throw new Error(`Native client compile failed: ${compiled.stderr}`);
  }
  if (sha(await readFile(source)) !== sourceSha256) { await rm(temporary, { force: true }); throw new Error('Client source changed during compile'); }
  await rename(temporary, binary);
  const stat = await lstat(binary); await access(binary, constants.X_OK);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Compiled client is not a regular executable');
  const check = await run(binary, ['--help'], { env: sanitized ? { ASAN_OPTIONS: 'detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1' } : {} });
  if (check.code !== 0 || !check.stdout.startsWith('Usage: native-load ')) throw new Error('Compiled client help check failed');
  const manifest = { schemaVersion: 1, status: 'built', generatedAt: new Date().toISOString(),
    source: { path: source, sha256: sourceSha256 }, sourceSha256,
    compiler: { command: 'cc', versionOutput: compiler.stdout.trim() || compiler.stderr.trim() }, args,
    binary: { path: binary, sha256: sha(await readFile(binary)), bytes: stat.size, mode: (stat.mode & 0o7777).toString(8).padStart(4, '0') },
    sanitizers: sanitized ? ['address', 'undefined'] : [],
    limitations: ['Local build record, not a signed or reproducible-build attestation.'] };
  const manifestFile = path.join(buildDirectory, sanitized ? 'asan-build.json' : 'build.json');
  await writeFile(`${manifestFile}.tmp-${process.pid}`, JSON.stringify(manifest, null, 2) + '\n');
  await rename(`${manifestFile}.tmp-${process.pid}`, manifestFile);
  return manifest;
}
async function bounded(promise, timeoutMs, label) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(label)), timeoutMs); })]); }
  finally { clearTimeout(timer); }
}
async function listen(server) {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return server.address().port;
}
async function unusedPort() { const server = net.createServer(); const port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
const response = (headers = '', body = payload, status = 'HTTP/1.1 200 OK') => Buffer.concat([Buffer.from(`${status}\r\nContent-Length: 1024\r\n${headers}\r\n`), body]);
async function fixture(mode) {
  const sockets = new Set(), timers = new Set(), errors = [];
  let requests = 0, connections = 0, trigger;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket); socket.setNoDelay(true);
    socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let incoming = Buffer.alloc(0);
    socket.on('data', chunk => {
      incoming = Buffer.concat([incoming, chunk]);
      if (incoming.length > 4096) { errors.push('Unexpected request limit'); socket.destroy(); return; }
      const end = incoming.indexOf('\r\n\r\n'); if (end < 0) return;
      const request = incoming.subarray(0, end + 4).toString(); incoming = incoming.subarray(end + 4);
      if (!request.startsWith('GET /static HTTP/1.1\r\n') || !request.includes('\r\nHost: localhost\r\n') || incoming.length) { errors.push('Unexpected request bytes'); socket.destroy(); return; }
      requests++; trigger?.();
      if (mode === 'no-response' || mode === 'interrupt') return;
      if (mode === 'trickle') {
        socket.write(response().subarray(0, 44)); let i = 44;
        const timer = setInterval(() => { if (!socket.destroyed && i < response().length) socket.write(response().subarray(i, ++i)); }, 15);
        timers.add(timer); socket.once('close', () => { clearInterval(timer); timers.delete(timer); }); return;
      }
      if (mode === 'fragmented') {
        const bytes = response(); let at = 0, index = 0;
        const emit = () => {
          if (socket.destroyed || at === bytes.length) return;
          const n = [1, 2, 7, 13, 47, 113][index++ % 6]; socket.write(bytes.subarray(at, at + n)); at = Math.min(bytes.length, at + n); setImmediate(emit);
        };
        emit(); return;
      }
      if (mode === 'close') { socket.end(response('Connection: close\r\n')); return; }
      if (mode === 'truncated-header') { socket.end('HTTP/1.1 200 OK\r\nContent-Len'); return; }
      if (mode === 'truncated-body') { socket.end(response('', payload.subarray(0, 511))); return; }
      if (mode === 'wrong-body') { const changed = Buffer.from(payload); changed[777] ^= 1; socket.write(response('', changed)); return; }
      if (mode === 'wrong-status') { socket.write(response('', payload, 'HTTP/1.1 503 Unavailable')); return; }
      if (mode === 'status-no-space') { socket.write(response('', payload, 'HTTP/1.1 200')); return; }
      if (mode === 'status-empty-reason') { socket.write(response('', payload, 'HTTP/1.1 200 ')); return; }
      if (mode === 'duplicate-length') { socket.write(response('content-length: 1024\r\n')); return; }
      if (mode === 'junk-length') { socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 1024x\r\n\r\n'), payload])); return; }
      if (mode === 'wrong-length') { socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 1023\r\n\r\n'), payload])); return; }
      if (mode === 'no-length') { socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\n\r\n'), payload])); return; }
      if (mode === 'chunked') { socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n'), payload, Buffer.from('\r\n0\r\n\r\n')])); return; }
      if (mode === 'te-plus-length') { socket.write(response('Transfer-Encoding: chunked\r\n')); return; }
      if (mode === 'encoded') { socket.write(response('Content-Encoding: gzip\r\n')); return; }
      if (mode === 'nul-name') { socket.write(response('X\0Bad: yes\r\n')); return; }
      if (mode === 'folded-header') { socket.write(response(' X-Bad: yes\r\n')); return; }
      if (mode === 'large-header') { socket.write(response(`X-Large: ${'x'.repeat(16400)}\r\n`)); return; }
      if (mode === 'extra-bytes') { socket.write(Buffer.concat([response(), Buffer.from('extra')])); return; }
      socket.write(response());
    });
  });
  const port = await listen(server);
  return { port, sockets, errors, get requests() { return requests; }, get connections() { return connections; }, set trigger(fn) { trigger = fn; },
    async close() {
      for (const timer of timers) clearInterval(timer); timers.clear();
      const closed = [...sockets].map(socket => new Promise(resolve => socket.once('close', resolve)));
      for (const socket of sockets) socket.destroy();
      await bounded(Promise.all([...closed, new Promise(resolve => server.close(resolve))]), 1000, 'Fixture close deadline');
      return sockets.size;
    } };
}
function parsed(runResult, allowDiagnostic = false) {
  if (runResult.spawnError || runResult.timedOut || runResult.signal) throw new Error(`Client did not exit normally: ${JSON.stringify(runResult)}`);
  if (runResult.stderr.trim() && !allowDiagnostic) throw new Error(`Client diagnostic: ${runResult.stderr}`);
  return JSON.parse(runResult.stdout);
}
function invariant(data) {
  const c = data.counters;
  return data.counterInvariant === true && c.admitted === c.completed + c.failed + c.aborted &&
    data.latency.count === c.completed && data.latency.histogram.reduce((n, b) => n + b.count, 0) === c.completed &&
    data.cleanup.openSockets === 0 && data.cleanup.errors === 0;
}
async function verify() {
  const report = { schemaVersion: 1, suite: 'native-http1-load-verification', startedAt: new Date().toISOString(), tests: [], passed: false,
    identity: {}, cleanup: { nativeStopped: true, fixtureServersClosed: true, openSockets: 0, temporaryRootRemoved: true, activeChildren: 0, errors: [] },
    limitations: ['Functional short controls, not performance comparisons or a speedup/no-regression claim.',
      'HTTP/1.1 fixed Content-Length 1024 only; chunked/encoded responses are deliberately rejected.',
      'ASan+UBSan are exercised with leak detection disabled; no LSan coverage is claimed.'] };
  const main = await build(), sanitized = await build(true);
  report.clientBuild = main; report.sanitizerBuild = sanitized;
  report.identity.clientBinarySha256 = main.binary.sha256; report.identity.clientSourceSha256 = main.sourceSha256;
  report.identity.buildManifestSha256 = sha(await readFile(path.join(buildDirectory, 'build.json')));
  report.identity.wrapperSha256 = sha(await readFile(fileURLToPath(import.meta.url)));
  report.sanitizers = { enabled: ['address', 'undefined'], leakDetection: false, diagnostics: '' };
  const sanitizerEnv = { ASAN_OPTIONS: 'detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1' };
  const cases = [
    ['fixed-keepalive', 'valid', true, 20, 1], ['concurrent-keepalive', 'valid', true, 64, 16],
    ['fragmented-response', 'fragmented', true, 3, 1], ['connection-close-reconnect', 'close', true, 4, 1],
    ['empty-status-reason-with-space', 'status-empty-reason', true, 1, 1],
    ['concurrent-failure-aborts-inflight', 'wrong-body', false, 64, 16],
    ...['wrong-body', 'wrong-status', 'status-no-space', 'duplicate-length', 'junk-length', 'wrong-length', 'no-length', 'chunked', 'te-plus-length', 'encoded', 'nul-name', 'folded-header', 'large-header', 'truncated-header', 'truncated-body', 'extra-bytes', 'trickle', 'no-response'].map(mode => [mode, mode, false, mode === 'extra-bytes' ? 2 : 1, 1]),
  ];
  for (const sanitizer of [false, true]) {
    const selection = sanitizer ? cases.filter(([, mode]) => ['fragmented', 'status-no-space', 'duplicate-length', 'chunked', 'wrong-body', 'large-header', 'truncated-body', 'trickle'].includes(mode)) : cases;
    for (const [name, mode, expected, count, concurrency] of selection) {
      if (interrupted) throw new Error(`Interrupted by ${interrupted}`);
      const server = await fixture(mode); let row;
      try {
        const outcome = await run((sanitizer ? sanitized : main).binary.path, ['--port', String(server.port), '--duration-ms', '1000', '--timeout-ms', expected ? '500' : '150', '--max-requests', String(count), '--concurrency', String(concurrency)], { env: sanitizer ? sanitizerEnv : {} });
        const data = parsed(outcome);
        const good = invariant(data) && server.requests > 0 && server.errors.length === 0 &&
          (expected ? outcome.code === 0 && data.success === true && data.counters.completed === count : outcome.code === 1 && data.success === false && data.error !== null);
        if (!good) throw new Error(`Unexpected ${name} result: ${JSON.stringify({ outcome, data, requests: server.requests, errors: server.errors })}`);
        if (mode === 'valid' && concurrency === 1 && data.counters.reusedRequests < 1) throw new Error('Keepalive was not reused');
        if (mode === 'close' && (data.counters.connectionsOpened !== count || data.counters.reusedRequests !== 0)) throw new Error('Connection:close did not reconnect');
        if (['trickle', 'no-response'].includes(mode) && data.error.reason !== 'request_absolute_timeout') throw new Error('Expected absolute deadline rejection');
        row = { name: `${sanitizer ? 'asan-ubsan:' : ''}${name}`, passed: true, expectedSuccess: expected, requestsReceived: server.requests, exitCode: outcome.code, client: data };
      } finally { const left = await server.close(); if (left) throw new Error(`Fixture leaked ${left} sockets`); }
      report.tests.push(row);
    }
  }
  const refused = await run(main.binary.path, ['--port', String(await unusedPort()), '--duration-ms', '50', '--timeout-ms', '150', '--max-requests', '1']);
  const refusedData = parsed(refused);
  if (refused.code !== 1 || refusedData.success !== false || refusedData.error?.reason !== 'socket_connect_error' || !invariant(refusedData)) throw new Error('Refused connection was not a counted failure');
  report.tests.push({ name: 'refused-loopback-connection', passed: true, expectedSuccess: false, exitCode: refused.code, client: refusedData });
  const interruptedFixture = await fixture('interrupt');
  try {
    let child;
    interruptedFixture.trigger = () => stop(child);
    const outcome = await run(main.binary.path, ['--port', String(interruptedFixture.port), '--duration-ms', '1000', '--timeout-ms', '500'], { onSpawn: value => { child = value; } });
    const data = parsed(outcome);
    if (outcome.code !== 1 || data.success !== false || data.interrupted !== 15 || !invariant(data) || !interruptedFixture.requests) throw new Error('Interrupted client did not fail closed');
    report.tests.push({ name: 'SIGTERM-after-received-request', passed: true, expectedSuccess: false, requestsReceived: interruptedFixture.requests, exitCode: outcome.code, client: data });
  } finally { await interruptedFixture.close(); }
  for (const args of [['--port', '80', '--host', 'example.com'], ['--port', '80', '--concurrency', '129'], ['--port', '80', '--path', '/bad\r\nInjected'], ['--port', '80', '--duration-ms', '10001']]) {
    const outcome = await run(main.binary.path, args); const data = parsed(outcome, true);
    if (outcome.code !== 2 || data.success !== false || data.error.reason !== 'invalid_options') throw new Error('Invalid options were accepted');
    report.tests.push({ name: `options-rejected:${args.at(-2)}`, passed: true, expectedSuccess: false, exitCode: outcome.code });
  }
  let prefix, nativeChild, nativeExit;
  try {
    const binary = await realpath(process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'));
    report.nativeBinaryPath = binary; report.nativeBinarySha256 = sha(await readFile(binary));
    const version = await run(binary, ['-V']); if (version.code !== 0) throw new Error('Native -V failed');
    report.nativeVersionOutput = `${version.stdout}${version.stderr}`.trim();
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-native-load-')); await chmod(prefix, 0o700); report.cleanup.temporaryRootRemoved = false;
    const port = await unusedPort();
    await writeFile(path.join(prefix, 'payload.bin'), payload);
    const config = `${process.getuid() === 0 ? `user ${os.userInfo().username};` : ''}
daemon off; master_process off; pid ${prefix}/nginx.pid; error_log ${prefix}/error.log warn;
events { worker_connections 256; }
http { access_log off; default_type application/octet-stream; sendfile on; keepalive_timeout 30s; keepalive_requests 1000000;
client_body_temp_path ${prefix}/body; server { listen 127.0.0.1:${port}; location = /static { alias ${prefix}/payload.bin; } } }
`;
    await writeFile(path.join(prefix, 'nginx.conf'), config);
    const validated = await run(binary, ['-p', `${prefix}/`, '-c', path.join(prefix, 'nginx.conf'), '-t']);
    if (validated.code !== 0) throw new Error(`Native config rejected: ${validated.stderr}`);
    report.cleanup.nativeStopped = false;
    nativeExit = run(binary, ['-p', `${prefix}/`, '-c', path.join(prefix, 'nginx.conf')], { timeoutMs: 10000, onSpawn: value => { nativeChild = value; } });
    const end = Date.now() + 4000;
    let ready = false;
    while (Date.now() < end && !ready && !interrupted) {
      ready = await new Promise(resolve => {
        let connected = false;
        const socket = net.createConnection({ host: '127.0.0.1', port });
        socket.setTimeout(100, () => socket.destroy());
        socket.once('connect', () => { connected = true; socket.destroy(); });
        socket.once('error', () => {}); socket.once('close', () => resolve(connected));
      });
      if (!ready) await delay(20);
    }
    if (!ready) throw new Error('Native listener readiness failed');
    for (const concurrency of [1, 16]) {
      const outcome = await run(main.binary.path, ['--port', String(port), '--duration-ms', '1000', '--timeout-ms', '1000', '--concurrency', String(concurrency), '--max-requests', String(concurrency * 4)]);
      const data = parsed(outcome);
      if (outcome.code !== 0 || data.success !== true || !invariant(data) || data.counters.completed !== concurrency * 4) throw new Error(`Native smoke failed: ${JSON.stringify({ concurrency, outcome, data, nativeStatus:{code:nativeChild.exitCode,signal:nativeChild.signalCode},nativeLog:await readFile(path.join(prefix,'error.log'),'utf8') })}`);
      report.tests.push({ name: `native-nginx-smoke-C${concurrency}`, passed: true, expectedSuccess: true, exitCode: 0, client: data });
    }
    stop(nativeChild, 'SIGQUIT'); const stopped = await nativeExit;
    if (stopped.code !== 0 || stopped.signal || stopped.timedOut || stopped.spawnError) throw new Error(`Native cleanup failed: ${JSON.stringify(stopped)}`);
    const log = await readFile(path.join(prefix, 'error.log'), 'utf8');
    if (/\[(?:crit|alert|emerg)\]/.test(log)) throw new Error('Unexpected critical native log');
    report.cleanup.nativeStopped = true;
    if (sha(await readFile(binary)) !== report.nativeBinarySha256) throw new Error('Native binary changed during verification');
    report.nativeBinaryUnchangedDuringTest = true;
  } finally {
    if (nativeChild && nativeChild.exitCode === null && nativeChild.signalCode === null) { stop(nativeChild, 'SIGKILL'); await nativeExit; }
    if (prefix) { await rm(prefix, { recursive: true, force: true }); report.cleanup.temporaryRootRemoved = true; }
  }
  if (sha(await readFile(fileURLToPath(import.meta.url))) !== report.identity.wrapperSha256 || sha(await readFile(path.join(buildDirectory, 'build.json'))) !== report.identity.buildManifestSha256 || sha(await readFile(source)) !== main.sourceSha256 || sha(await readFile(main.binary.path)) !== main.binary.sha256 || sha(await readFile(sanitized.binary.path)) !== sanitized.binary.sha256) throw new Error('Client source/binary changed during verification');
  report.sourceUnchangedDuringTest = true; report.cleanup.activeChildren = active.size;
  report.passed = !interrupted && active.size === 0 && report.tests.length > 0 && report.tests.every(t => t.passed);
  report.finishedAt = new Date().toISOString(); return report;
}
async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--build' && args.length === 1) { console.log(JSON.stringify(await build(), null, 2)); return; }
  if (args[0] !== '--verify') throw new Error('Use --build or --verify [--output FILE]');
  let output;
  if (args.length > 1) { if (args.length !== 3 || args[1] !== '--output') throw new Error('Use --verify [--output FILE]'); output = path.resolve(args[2]); }
  const result = await verify();
  if (output) { await mkdir(path.dirname(output), { recursive: true }); await writeFile(`${output}.tmp-${process.pid}`, JSON.stringify(result, null, 2) + '\n'); await rename(`${output}.tmp-${process.pid}`, output); }
  console.log(JSON.stringify(result, null, 2)); if (!result.passed) process.exitCode = 1;
}
main().catch(async error => {
  for (const child of active) stop(child, 'SIGKILL');
  console.log(JSON.stringify({ schemaVersion: 1, suite: 'native-http1-load-verification', passed: false, error: error.message, interrupted: interrupted || null }, null, 2));
  process.exitCode = 1;
});
