#!/usr/bin/env node
// Two native NGINX binaries. Node only drives local traffic and the upstream fixture.
import { createHash } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { access, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const hash = data => createHash('sha256').update(data).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const lifecycle = { interrupted: null, activeRequests: new Set() };
const payload = Buffer.alloc(1024);
for (let i = 0; i < payload.length; i++) payload[i] = 33 + (i % 90);

function parseOptions(args) {
  const value = {
    baseline: path.join(root, 'x10/.build/baseline/nginx'),
    candidate: path.join(root, 'x10/.build/objs/nginx'),
    baselineManifest: path.join(root, 'x10/evidence/build-reference.json'),
    candidateManifest: path.join(root, 'x10/evidence/build-fixed.json'),
    durationMs: 1000, warmupMs: 250, repetitions: 2, concurrency: [1, 16],
  };
  const names = {
    '--baseline': 'baseline', '--candidate': 'candidate',
    '--baseline-manifest': 'baselineManifest', '--candidate-manifest': 'candidateManifest',
    '--duration-ms': 'durationMs', '--warmup-ms': 'warmupMs',
    '--repetitions': 'repetitions', '--concurrency': 'concurrency',
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help') return { help: true };
    const key = names[args[i]];
    if (!key || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Unknown or incomplete option: ${args[i]}`);
    const raw = args[++i];
    if (key === 'concurrency') value[key] = raw.split(',').map(Number);
    else value[key] = key.endsWith('Ms') || key === 'repetitions' ? Number(raw) : path.resolve(raw);
  }
  for (const [key, min, max] of [['durationMs', 100, 10_000], ['warmupMs', 50, 5000], ['repetitions', 2, 10]]) {
    if (!Number.isInteger(value[key]) || value[key] < min || value[key] > max) throw new Error(`${key} must be an integer ${min}..${max}`);
  }
  if (value.repetitions % 2) throw new Error('repetitions must be even, so each binary runs first equally often');
  if (!value.concurrency.length || value.concurrency.length > 4 || new Set(value.concurrency).size !== value.concurrency.length ||
      value.concurrency.some(n => !Number.isInteger(n) || n < 1 || n > 128)) throw new Error('concurrency must contain 1..4 unique integers from 1..128');
  if (2 * 2 * value.concurrency.length * value.repetitions * (value.durationMs + value.warmupMs) > 180_000) {
    throw new Error('Requested measured/warmup time exceeds the 180-second local run budget');
  }
  return value;
}

function normalizedVersion(text) {
  // Only build-directory and install-prefix path differences are ignored.
  return text.trim().split('\n').map(line => line.trim().replace(
    /--(?:builddir|prefix)=(?:"[^"]*"|'[^']*'|\S+)/g, match => `${match.slice(0, match.indexOf('='))}=<path>`,
  )).join('\n');
}

async function identity(label, binary, manifestPath) {
  await access(binary, constants.X_OK);
  const binaryBytes = await readFile(binary);
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  if (manifest.status !== 'built' || !manifest.binary?.sha256) throw new Error(`${label} manifest is not a built binary record`);
  const sha256 = hash(binaryBytes);
  if (sha256 !== manifest.binary.sha256) throw new Error(`${label} binary SHA-256 does not match its manifest`);
  const { stdout, stderr } = await execute(binary, ['-V'], { encoding: 'utf8', timeout: 5000 });
  const versionOutput = `${stdout}${stderr}`.trim();
  if (normalizedVersion(versionOutput) !== normalizedVersion(manifest.nginxVersionOutput || '')) {
    throw new Error(`${label} nginx -V does not match its manifest`);
  }
  return {
    label, path: binary, sha256, bytes: binaryBytes.length, versionOutput,
    normalizedVersion: normalizedVersion(versionOutput),
    manifest: {
      path: manifestPath, sha256: hash(manifestBytes), upstreamRevision: manifest.upstreamRevision,
      checkoutRevision: manifest.checkoutRevision, trackedChanges: manifest.trackedChanges,
      sourceChangesFromUpstream: manifest.sourceChangesFromUpstream ?? manifest.trackedChanges,
      sourceDiffSha256: manifest.sourceDiffSha256 ?? null,
      compiler: manifest.compiler, compilerFlags: manifest.compilerFlags,
      dependencies: manifest.dependencyVersionsFromHeaders,
      compiledModules: manifest.compiledModules,
    },
  };
}

function checkComparable(a, b) {
  if (a.normalizedVersion !== b.normalizedVersion) throw new Error('nginx versions, compiler, TLS information or configure flags differ');
  for (const field of ['compiler', 'compilerFlags', 'dependencies', 'compiledModules', 'upstreamRevision']) {
    if (JSON.stringify(a.manifest[field]) !== JSON.stringify(b.manifest[field])) throw new Error(`Build profiles differ: ${field}`);
  }
  if (!Array.isArray(a.manifest.sourceChangesFromUpstream) || a.manifest.sourceChangesFromUpstream.length) {
    throw new Error('Baseline manifest is not the unchanged pinned upstream source');
  }
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function unusedPort() {
  const reservation = net.createServer();
  const port = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  return port;
}

function nginxQuote(value) { return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`; }

function config(prefix, port, upstreamPort) {
  // In user namespaces uid 0 may be mapped while packaged nobody is not.
  const workerUser = process.geteuid?.() === 0 ? `user ${nginxQuote(os.userInfo().username)};\n` : '';
  return `${workerUser}daemon off;
master_process off;
pid ${nginxQuote(path.join(prefix, 'nginx.pid'))};
error_log ${nginxQuote(path.join(prefix, 'error.log'))} warn;
events { worker_connections 1024; }
http {
  access_log off;
  default_type application/octet-stream;
  sendfile on;
  tcp_nopush on;
  keepalive_timeout 30s;
  keepalive_requests 1000000;
  client_body_temp_path ${nginxQuote(path.join(prefix, 'body-temp'))};
  proxy_temp_path ${nginxQuote(path.join(prefix, 'proxy-temp'))};
  upstream fixture { server 127.0.0.1:${upstreamPort}; keepalive 128; }
  server {
    listen 127.0.0.1:${port};
    server_name localhost;
    location = /static { alias ${nginxQuote(path.join(prefix, 'payload.bin'))}; }
    location = /proxy {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_connect_timeout 1s;
      proxy_read_timeout 2s;
      proxy_pass http://fixture;
    }
  }
}
`;
}

function request(port, target, agent) {
  return new Promise((resolve, reject) => {
    if (lifecycle.interrupted) return reject(new Error(`Interrupted by ${lifecycle.interrupted}`));
    const started = performance.now();
    let settled = false;
    const complete = (error, value) => {
      if (settled) return;
      settled = true;
      lifecycle.activeRequests.delete(req);
      if (error) reject(error); else resolve(value);
    };
    const req = http.get({ hostname: '127.0.0.1', port, path: target, agent }, res => {
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > payload.length) req.destroy(new Error('response_body_too_large'));
        else chunks.push(chunk);
      });
      res.on('error', error => complete(error));
      res.on('end', () => {
        if (res.statusCode !== 200) return complete(new Error(`unexpected_status_${res.statusCode}`));
        if (res.headers['content-length'] !== String(payload.length) || !Buffer.concat(chunks).equals(payload)) return complete(new Error('response_body_mismatch'));
        complete(null, { latencyMs: performance.now() - started, reusedSocket: req.reusedSocket });
      });
    });
    lifecycle.activeRequests.add(req);
    req.setTimeout(2000, () => req.destroy(new Error('request_timeout')));
    req.on('error', error => complete(error));
  });
}

function quantile(sorted, q) {
  if (!sorted.length) return null;
  // Nearest rank; a measured response has one latency sample.
  return sorted[Math.max(0, Math.ceil(q * sorted.length) - 1)];
}

async function traffic(port, target, agent, concurrency, durationMs, recordLatency = true) {
  const started = performance.now();
  const deadline = started + durationMs;
  let successful = 0, errors = 0, reused = 0;
  const latencies = [], errorExamples = [];
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (performance.now() < deadline && errors < 100 && !lifecycle.interrupted) {
      try {
        const response = await request(port, target, agent);
        successful++;
        reused += Number(response.reusedSocket);
        if (recordLatency) latencies.push(response.latencyMs);
      } catch (error) {
        errors++;
        if (errorExamples.length < 5) errorExamples.push(error.message);
      }
    }
  }));
  const elapsedMs = performance.now() - started;
  latencies.sort((a, b) => a - b);
  return {
    admissionDurationMs: durationMs, elapsedIncludingDrainMs: elapsedMs,
    successfulResponses: successful, failedRequests: errors, attemptedRequests: successful + errors,
    successfulRequestsPerSecond: successful / (elapsedMs / 1000), keepaliveReusedRequests: reused,
    latencyMs: recordLatency ? { count: latencies.length, p50: quantile(latencies, .5), p95: quantile(latencies, .95), p99: quantile(latencies, .99), max: latencies.at(-1) ?? null } : null,
    errorExamples,
  };
}

async function processSnapshot(pid, pageBytes) {
  const content = await readFile(`/proc/${pid}/stat`, 'utf8');
  const fields = content.slice(content.lastIndexOf(')') + 2).trim().split(/\s+/);
  const userTicks = Number(fields[11]), systemTicks = Number(fields[12]), rssPages = Number(fields[21]);
  if (![userTicks, systemTicks, rssPages].every(Number.isFinite)) throw new Error('Cannot parse Linux process resource counters');
  return { userTicks, systemTicks, rssBytes: rssPages * pageBytes, startTimeTicks: fields[19] };
}

async function resolveCounterPid(childPid) {
  // Some sandboxes expose host /proc even though spawn returns a namespace PID.
  // Select only this Node process's direct child, never an unrelated PID match.
  const self = await readFile('/proc/self/status', 'utf8');
  const selfProcPid = Number(self.match(/^Tgid:\s*(\d+)$/m)?.[1]);
  if (!Number.isInteger(selfProcPid) || selfProcPid < 1) throw new Error('Cannot identify the driver in /proc');
  const candidates = (await readdir('/proc')).filter(name => /^\d+$/.test(name));
  const matches = [];
  for (let offset = 0; offset < candidates.length; offset += 16) {
    await Promise.all(candidates.slice(offset, offset + 16).map(async name => {
      let status;
      try { status = await readFile(`/proc/${name}/status`, 'utf8'); }
      catch (error) { if (['ENOENT', 'EACCES', 'ESRCH'].includes(error.code)) return; throw error; }
      const parent = Number(status.match(/^PPid:\s*(\d+)$/m)?.[1]);
      const namespacePids = status.match(/^NSpid:\s*([\d\t ]+)$/m)?.[1].trim().split(/\s+/).map(Number);
      const nativePid = namespacePids?.at(-1) ?? Number(name);
      if (parent === selfProcPid && nativePid === childPid) matches.push(Number(name));
    }));
  }
  if (matches.length !== 1) throw new Error(`Cannot resolve exactly one direct native child for /proc counters (matches=${matches.length})`);
  return matches[0];
}

async function startNative(binary, prefix, port, report) {
  const args = ['-p', `${prefix}/`, '-c', path.join(prefix, 'nginx.conf')];
  await execute(binary, [...args, '-t'], { encoding: 'utf8', timeout: 5000 });
  if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
  const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  child.output = '';
  child.stdout.on('data', b => { child.output = (child.output + b).slice(-16_384); });
  child.stderr.on('data', b => { child.output = (child.output + b).slice(-16_384); });
  child.failure = null;
  child.on('error', error => { child.failure = error; });
  child.completion = new Promise(resolve => {
    child.on('error', error => resolve({ code: null, signal: null, error: error.message }));
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });
  report.activeChild = child;
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
    if (child.failure || child.exitCode !== null || child.signalCode) throw new Error(`Native NGINX failed at startup: ${child.failure?.message || child.output}`);
    try { await request(port, '/static', false); return child; } catch { await delay(20); }
  }
  throw new Error(`Native NGINX readiness timeout: ${child.output}`);
}

async function stopNative(child) {
  if (!child) return { signal: 'none', result: null };
  if (child.exitCode !== null || child.signalCode || child.failure) return { signal: 'already_exited', result: await child.completion, unexpected: true };
  child.kill('SIGQUIT');
  const bounded = async milliseconds => {
    let timeout;
    try { return await Promise.race([child.completion, new Promise(resolve => { timeout = setTimeout(() => resolve(null), milliseconds); })]); }
    finally { clearTimeout(timeout); }
  };
  let result = await bounded(3000);
  if (!result) {
    child.kill('SIGKILL');
    result = await bounded(1000);
    return { signal: 'SIGKILL', result, forced: true };
  }
  return { signal: 'SIGQUIT', result };
}

async function sample({ label, workload, concurrency, repetition, binary, prefix, port, options, ticksPerSecond, pageBytes, report }) {
  if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
  if (hash(await readFile(binary)) !== report.identities[label].sha256) throw new Error(`${label} binary changed before its sample`);
  const child = await startNative(binary, prefix, port, report);
  const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency, maxFreeSockets: concurrency, scheduling: 'fifo' });
  const result = { index: report.runs.length, binary: label, workload, concurrency, repetition };
  report.runs.push(result);
  let timer;
  try {
    const warmup = await traffic(port, `/${workload}`, agent, concurrency, options.warmupMs, false);
    result.warmup = warmup;
    if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
    if (warmup.failedRequests || !warmup.successfulResponses) throw new Error('Warmup had failed requests or no successful responses');
    const counterPid = await resolveCounterPid(child.pid);
    const start = await processSnapshot(counterPid, pageBytes);
    const rssSamples = [start.rssBytes];
    const sampleErrors = [];
    let sampling = false, pendingSampling = Promise.resolve();
    timer = setInterval(() => {
      if (sampling) return;
      sampling = true;
      pendingSampling = (async () => {
        try {
          const snapshot = await processSnapshot(counterPid, pageBytes);
          if (snapshot.startTimeTicks !== start.startTimeTicks) throw new Error('Native process identity changed during measurement');
          rssSamples.push(snapshot.rssBytes);
        }
        catch (error) { sampleErrors.push(error.message); }
        finally { sampling = false; }
      })();
    }, 25);
    const nodeBefore = process.resourceUsage();
    const loadBefore = os.loadavg();
    result.traffic = await traffic(port, `/${workload}`, agent, concurrency, options.durationMs);
    const nodeAfter = process.resourceUsage();
    clearInterval(timer); timer = null;
    await pendingSampling;
    const end = await processSnapshot(counterPid, pageBytes);
    if (end.startTimeTicks !== start.startTimeTicks) throw new Error('Native process identity changed during measurement');
    rssSamples.push(end.rssBytes);
    const userMs = (end.userTicks - start.userTicks) * 1000 / ticksPerSecond;
    const systemMs = (end.systemTicks - start.systemTicks) * 1000 / ticksPerSecond;
    result.resources = {
      native: {
        processMode: 'single_process_master_off', userCpuMs: userMs, systemCpuMs: systemMs,
        counterIdentity: 'Direct child matched by /proc PPid and NSpid; starttime checked throughout sampling',
        totalCpuMs: userMs + systemMs,
        cpuPercentOfOneLogicalCpu: (userMs + systemMs) / result.traffic.elapsedIncludingDrainMs * 100,
        rssBytes: { first: rssSamples[0], last: end.rssBytes, sampledMax: Math.max(...rssSamples), sampleCount: rssSamples.length, nominalSampleIntervalMs: 25 },
        samplingErrors: sampleErrors,
      },
      nodeDriverAndUpstream: {
        userCpuMs: (nodeAfter.userCPUTime - nodeBefore.userCPUTime) / 1000,
        systemCpuMs: (nodeAfter.systemCPUTime - nodeBefore.systemCPUTime) / 1000,
      },
      hostLoadAverage: { before: loadBefore, after: os.loadavg() },
    };
    if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
    if (sampleErrors.length || result.traffic.failedRequests || !result.traffic.successfulResponses) throw new Error('Measured sample had errors or no successful responses');
    result.success = true;
  } catch (error) { result.success = false; result.error = error.message; throw error; }
  finally {
    if (timer) clearInterval(timer);
    agent.destroy();
    result.cleanup = await stopNative(child);
    report.activeChild = null;
    if (result.cleanup.signal !== 'SIGQUIT' || result.cleanup.result?.code !== 0) {
      result.success = false;
      throw new Error('Native cleanup did not complete with SIGQUIT and exit 0');
    }
    if (hash(await readFile(binary)) !== report.identities[label].sha256) {
      result.success = false;
      throw new Error(`${label} binary changed during its sample`);
    }
  }
}

function summarize(runs) {
  const groups = [];
  for (const workload of ['static', 'proxy']) for (const concurrency of [...new Set(runs.map(r => r.concurrency))]) {
    const group = { workload, concurrency, binaries: {} };
    for (const label of ['baseline', 'candidate']) {
      const samples = runs.filter(r => r.success && r.binary === label && r.workload === workload && r.concurrency === concurrency);
      const rates = samples.map(r => r.traffic.successfulRequestsPerSecond).sort((a, b) => a - b);
      const meanRate = rates.reduce((a, b) => a + b, 0) / rates.length;
      group.binaries[label] = { samples: samples.length, requestsPerSecond: { arithmeticMean: meanRate, min: rates[0] ?? null, max: rates.at(-1) ?? null }, failedRequests: samples.reduce((n, r) => n + r.traffic.failedRequests, 0) };
    }
    const a = group.binaries.baseline.requestsPerSecond.arithmeticMean, b = group.binaries.candidate.requestsPerSecond.arithmeticMean;
    group.candidateToBaselineMeanThroughputRatio = Number.isFinite(a) && a > 0 ? b / a : null;
    groups.push(group);
  }
  return groups;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node x10/bench/compare.mjs [--baseline PATH] [--candidate PATH] [--baseline-manifest PATH] [--candidate-manifest PATH] [--duration-ms 1000] [--warmup-ms 250] [--repetitions 2] [--concurrency 1,16]');
    return;
  }
  const report = {
    schemaVersion: 1, suite: 'native-nginx-local-comparison', startedAt: new Date().toISOString(), success: false,
    options, environment: { platform: os.platform(), release: os.release(), architecture: os.arch(), node: process.version, logicalCpus: os.cpus().length, availableParallelism: os.availableParallelism(), totalMemoryBytes: os.totalmem() },
    methodology: {
      nativeConfiguration: 'Identical config and prefix, daemon off, master_process off, one native process at a time',
      transport: 'Loopback HTTP/1.1, keepalive, closed loop, one outstanding request per client lane, no pipelining',
      workload: 'Static file sendfile on and native reverse proxy, exact 1024-byte response verified for every completed request',
      order: 'For every workload/concurrency pair: even repetition baseline then candidate; odd repetition candidate then baseline',
      timing: 'Warmup excluded; requests admitted until the measured deadline; all admitted requests drain; throughput denominator includes drain',
      latency: 'Nearest-rank quantiles of successful full-response client durations within each sample; no cross-sample pooled quantiles',
      resources: 'Linux /proc single native PID user/system ticks; RSS sampled every 25ms, not a true peak; separate Node self CPU includes both generator and upstream fixture',
    },
    limitations: [
      'Synthetic short local smoke comparison; no confidence interval, regression threshold or global speedup claim.',
      'Closed-loop load and a single Node event loop can be the bottleneck; it drives clients and proxy upstream on the same host.',
      'Host scheduling and other workloads are uncontrolled; balanced order reduces but does not remove noise.',
      'Single-process master-off execution does not measure production multiworker scaling, reloads, TLS, HTTP2/3, QUIC, mail or disk-cold workloads.',
      'Native CPU uses discrete scheduler ticks, and RSS sampling can miss peaks. Setup/warmup CPU is outside the measured interval.',
      'The candidate QUIC parser fix is not exercised by these HTTP1 workloads. Ratios are observations, not evidence that the fix speeds these workloads up.',
    ],
    runs: [], cleanupErrors: [],
  };
  let prefix, upstream;
  const onInterrupt = signal => {
    lifecycle.interrupted ??= signal;
    report.interrupted = lifecycle.interrupted;
    report.success = false;
    for (const req of lifecycle.activeRequests) req.destroy(new Error(`Interrupted by ${signal}`));
  };
  const onSigint = () => onInterrupt('SIGINT');
  const onSigterm = () => onInterrupt('SIGTERM');
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
  try {
    if (os.platform() !== 'linux') throw new Error('Linux is required for this resource-accounted profile');
    const baseline = await identity('baseline', options.baseline, options.baselineManifest);
    const candidate = await identity('candidate', options.candidate, options.candidateManifest);
    checkComparable(baseline, candidate);
    report.identities = { baseline, candidate };
    report.profileComparison = { comparable: true, ignoredVersionFields: ['configure --builddir path', 'configure --prefix path'] };
    const ticksPerSecond = Number((await execute('getconf', ['CLK_TCK'], { timeout: 5000 })).stdout.trim());
    const pageBytes = Number((await execute('getconf', ['PAGESIZE'], { timeout: 5000 })).stdout.trim());
    if (![ticksPerSecond, pageBytes].every(n => Number.isInteger(n) && n > 0)) throw new Error('Cannot determine Linux counter units');
    report.environment.nativeCpuTicksPerSecond = ticksPerSecond;
    report.environment.pageBytes = pageBytes;
    report.environment.allowedCpuList = (await readFile('/proc/self/status', 'utf8')).match(/^Cpus_allowed_list:\s*(.+)$/m)?.[1] ?? null;
    if (lifecycle.interrupted) throw new Error(`Interrupted by ${lifecycle.interrupted}`);
    prefix = await mkdtemp(path.join(os.tmpdir(), 'nginx-x10-bench-'));
    await Promise.all(['body-temp', 'proxy-temp', 'logs'].map(name => mkdir(path.join(prefix, name))));
    await writeFile(path.join(prefix, 'payload.bin'), payload);
    report.payload = { bytes: payload.length, sha256: hash(payload) };
    let upstreamRequests = 0;
    upstream = http.createServer((req, res) => {
      upstreamRequests++;
      req.resume();
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': payload.length });
      res.end(payload);
    });
    upstream.keepAliveTimeout = 60_000;
    upstream.on('error', error => { report.cleanupErrors.push(`upstream: ${error.message}`); });
    const upstreamPort = await listen(upstream);
    const port = await unusedPort();
    const nativeConfig = config(prefix, port, upstreamPort);
    await writeFile(path.join(prefix, 'nginx.conf'), nativeConfig);
    report.nativeConfigTemplate = nativeConfig.replaceAll(prefix, '<private-prefix>').replaceAll(String(upstreamPort), '<upstream-port>').replaceAll(String(port), '<native-port>');
    for (const workload of ['static', 'proxy']) for (const concurrency of options.concurrency) {
      for (let repetition = 0; repetition < options.repetitions; repetition++) {
        for (const label of repetition % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate']) {
          await sample({ label, workload, concurrency, repetition, binary: options[label], prefix, port, options, ticksPerSecond, pageBytes, report });
        }
      }
    }
    report.upstreamRequestsIncludingWarmups = upstreamRequests;
    report.summary = summarize(report.runs);
    report.success = report.runs.length === 4 * options.concurrency.length * options.repetitions && report.runs.every(r => r.success);
  } catch (error) {
    report.error = error.message;
    report.success = false;
  } finally {
    if (report.activeChild) {
      try {
        const cleanup = await stopNative(report.activeChild);
        report.emergencyNativeCleanup = cleanup;
        if (cleanup.signal !== 'SIGQUIT' || cleanup.result?.code !== 0) report.cleanupErrors.push('Emergency native cleanup was not graceful');
      } catch (error) { report.cleanupErrors.push(error.message); }
    }
    delete report.activeChild;
    if (upstream) {
      try { upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); }
      catch (error) { report.cleanupErrors.push(error.message); }
    }
    if (prefix) {
      try { await rm(prefix, { recursive: true, force: true }); }
      catch (error) { report.cleanupErrors.push(error.message); }
    }
    if (report.identities) {
      const identityErrors = [];
      for (const [label, expected] of Object.entries(report.identities)) {
        try {
          if (hash(await readFile(expected.path)) !== expected.sha256) identityErrors.push(`${label} binary changed`);
          if (hash(await readFile(expected.manifest.path)) !== expected.manifest.sha256) identityErrors.push(`${label} manifest changed`);
        } catch (error) { identityErrors.push(`${label}: ${error.message}`); }
      }
      report.profileComparison.identitiesStableAtFinish = identityErrors.length === 0;
      if (identityErrors.length) { report.identityErrors = identityErrors; report.success = false; }
    }
    if (report.cleanupErrors.length) report.success = false;
    if (lifecycle.interrupted) report.success = false;
    process.off('SIGINT', onSigint);
    process.off('SIGTERM', onSigterm);
    report.finishedAt = new Date().toISOString();
    console.log(JSON.stringify(report, null, 2));
    if (!report.success) process.exitCode = lifecycle.interrupted === 'SIGINT' ? 130 : lifecycle.interrupted === 'SIGTERM' ? 143 : 1;
  }
}

main().catch(error => {
  console.log(JSON.stringify({ schemaVersion: 1, suite: 'native-nginx-local-comparison', success: false, error: error.message }, null, 2));
  process.exitCode = 1;
});
