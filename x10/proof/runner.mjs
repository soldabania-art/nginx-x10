// Deterministic native verification kernel. No LLM, imported configs or live replay.
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function untilExit(exited, milliseconds) {
  let timer;
  try { await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, milliseconds); })]); }
  finally { clearTimeout(timer); }
}
const quote = value => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
export class ProofError extends Error {
  constructor(code, message, outcome = 'verification_error') { super(message); this.code = code; this.outcome = outcome; }
}
const fail = (code, message, outcome) => { throw new ProofError(code, message, outcome); };
const exact = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...names].sort());
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function validateContract(value) {
  if (value?.kind && value.kind !== 'tenant-cache-isolation') fail('unsupported_contract', 'Only tenant-cache-isolation is supported', 'unsupported');
  if (!exact(value, ['schemaVersion', 'kind', 'resource', 'tenants', 'cache']) || value.schemaVersion !== 1
    || value.kind !== 'tenant-cache-isolation' || typeof value.resource !== 'string' || !/^\/[a-z][a-z0-9/-]{0,62}$/.test(value.resource) || value.resource.includes('//')
    || !Array.isArray(value.tenants) || value.tenants.length !== 2
    || !value.tenants.every(v => typeof v === 'string' && /^[a-z][a-z0-9-]{0,23}$/.test(v)) || new Set(value.tenants).size !== 2
    || !exact(value.cache, ['enabled', 'key']) || typeof value.cache.enabled !== 'boolean'
    || !['resource', 'resource+tenant'].includes(value.cache.key)) {
    fail('invalid_contract', 'Contract must match the bounded tenant-cache schema', 'invalid_input');
  }
  // Return a detached object so a caller cannot change the verified scenario mid-run.
  return JSON.parse(JSON.stringify(value));
}

export async function readContract(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) fail('invalid_contract_file', 'Contract must be a regular JSON file at most 16 KiB', 'invalid_input');
  let value;
  try { value = JSON.parse(await readFile(file, 'utf8')); }
  catch { fail('invalid_contract_json', 'Contract JSON cannot be decoded', 'invalid_input'); }
  return validateContract(value);
}

// This is consistency with the locally recorded build, not a signature/attestation.
export async function verifyBuild({ binary = process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'),
  manifest = process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'), signal } = {}) {
  if (signal?.aborted) fail('interrupted', 'Verification interrupted');
  if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) < 22) fail('unsupported_host', 'Linux and Node 22+ are required', 'unsupported');
  binary = path.resolve(binary); manifest = path.resolve(manifest);
  const binaryStat = await lstat(binary), manifestStat = await lstat(manifest);
  if (!binaryStat.isFile() || binaryStat.isSymbolicLink() || binaryStat.size > 64 * 1024 * 1024
    || !manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 1024 * 1024
    || await realpath(binary) !== binary) fail('build_identity', 'Selected build files must be canonical regular files');
  await access(binary, constants.X_OK);
  const manifestBytes = await readFile(manifest), bytes = await readFile(binary);
  let build;
  try { build = JSON.parse(manifestBytes); } catch { fail('build_identity', 'Build manifest JSON is invalid'); }
  if (build.status !== 'built' || build.binary?.path !== binary || build.binary?.sha256 !== sha256(bytes)
    || build.binary.bytes !== binaryStat.size || build.binary.mode !== (binaryStat.mode & 0o7777).toString(8).padStart(4, '0')
    || build.binary.executable !== true || !hash(build.sourceDiffSha256)
    || !Array.isArray(build.compiledModules) || build.compiledModules.length === 0) fail('build_identity', 'Selected binary differs from its build manifest');
  const pin = JSON.parse(await readFile(path.join(root, 'x10/upstream.json'), 'utf8'));
  if (build.upstreamRevision !== pin.commit || await realpath(build.workingDirectory) !== root.replace(/\/$/, '')) fail('build_identity', 'Build source or upstream pin differs');
  const untracked = (await execute('git', ['ls-files', '--others', '--exclude-standard', '--', 'src', 'auto', 'conf'], { cwd: root, timeout: 5000, maxBuffer: 1024 * 1024, signal })).stdout.trim();
  const diff = (await execute('git', ['diff', '--binary', pin.commit, '--', 'src', 'auto', 'conf'], { cwd: root, timeout: 5000, maxBuffer: 8 * 1024 * 1024, encoding: 'buffer', signal })).stdout;
  if (untracked || sha256(diff) !== build.sourceDiffSha256) fail('build_identity', 'Native source differs from its recorded build');
  const objects = build.configureArgv?.find(v => typeof v === 'string' && v.startsWith('--builddir='))?.slice(11);
  if (!objects || !path.isAbsolute(objects)) fail('build_identity', 'Generated build directory is not recorded');
  for (const name of ['ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c']) {
    const file = path.join(objects, name), expected = build.generatedFiles?.[name], stat = await lstat(file);
    if (!expected || !stat.isFile() || stat.isSymbolicLink() || sha256(await readFile(file)) !== expected.sha256
      || stat.size !== expected.bytes || (stat.mode & 0o7777).toString(8).padStart(4, '0') !== expected.mode) fail('build_identity', 'Generated build inputs differ');
  }
  const version = (await execute(binary, ['-V'], { timeout: 5000, maxBuffer: 256 * 1024, signal })).stderr.trim();
  if (version !== build.nginxVersionOutput?.trim()) fail('build_identity', 'Native version output differs');
  return { binary, bytes, identity: { binarySha256: sha256(bytes), manifestSha256: sha256(manifestBytes), upstreamRevision: pin.commit,
    sourceDiffSha256: sha256(diff), nginxVersion: build.nginxVersion, compiledModuleCount: build.compiledModules.length } };
}

async function listening(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port;
}
async function unusedPort() {
  const server = net.createServer(); const port = await listening(server);
  await new Promise(resolve => server.close(resolve)); return port;
}
function request(port, route, tenant, requests) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const req = http.get({ host: '127.0.0.1', port, path: route, agent: false,
      headers: tenant ? { 'X-X10-Test-Tenant': tenant } : {} }, response => {
      const chunks = [];
      response.on('data', chunk => { total += chunk.length; if (total > 4096) req.destroy(new ProofError('response_limit', 'Fixture response exceeded 4 KiB')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8'), cacheStatus: response.headers['x-x10-cache'] || 'NONE' }));
    });
    requests.add(req); const timer = setTimeout(() => req.destroy(new ProofError('request_timeout', 'Fixture request deadline expired')), 1500);
    req.on('error', reject); req.once('close', () => { clearTimeout(timer); requests.delete(req); });
  });
}

function config(prefix, port, originPort, ready, contract) {
  const key = contract.cache.key === 'resource+tenant' ? '$request_uri|$http_x_x10_test_tenant' : '$request_uri';
  const user = process.getuid() === 0 ? `user ${quote(os.userInfo().username)};\n` : '';
  return `${user}daemon off;\nmaster_process off;\nworker_processes 1;\npid ${quote(path.join(prefix, 'nginx.pid'))};\nerror_log ${quote(path.join(prefix, 'logs/error.log'))} notice;\nevents { worker_connections 64; }\nhttp {\n access_log off;\n client_body_temp_path ${quote(path.join(prefix, 'body'))};\n proxy_temp_path ${quote(path.join(prefix, 'proxy'))};\n proxy_cache_path ${quote(path.join(prefix, 'cache'))} keys_zone=proof:1m max_size=8m inactive=1m;\n server {\n listen 127.0.0.1:${port};\n server_name localhost;\n location = /__x10_ready_${ready} { return 200 ${quote(ready)}; }\n location = ${contract.resource} {\n  proxy_pass http://127.0.0.1:${originPort};\n  proxy_http_version 1.1;\n  proxy_set_header Connection "";\n  proxy_set_header X-X10-Test-Tenant $http_x_x10_test_tenant;\n  proxy_cache ${contract.cache.enabled ? 'proof' : 'off'};\n  proxy_cache_key "${key}";\n  proxy_cache_valid 200 1m;\n  proxy_cache_lock on;\n  proxy_connect_timeout 1s;\n  proxy_read_timeout 2s;\n  add_header X-X10-Cache $upstream_cache_status always;\n }\n }\n}\n`;
}

async function runOrder(contract, build, order, signal) {
  let prefix, child, exit, origin, stopped = false, interrupted = false, forced = false;
  let nativeOutputBytes = 0, outputOverflow = false;
  const sockets = new Set(), requests = new Set(), originTrace = [], cleanupErrors = [];
  const abort = () => { interrupted = true; for (const req of requests) req.destroy(new ProofError('interrupted', 'Verification interrupted')); for (const socket of sockets) socket.destroy(); if (child?.pid && !exit) { try { process.kill(-child.pid, 'SIGTERM'); } catch {} } };
  signal?.addEventListener('abort', abort, { once: true });
  const deadline = setTimeout(abort, 15000);
  let result;
  try {
    if (signal?.aborted) abort();
    if (interrupted) fail('interrupted', 'Verification interrupted');
    prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-proof-')); await chmod(prefix, 0o700);
    for (const dir of ['logs', 'body', 'proxy', 'cache']) await mkdir(path.join(prefix, dir), { mode: 0o700 });
    const copied = path.join(prefix, 'nginx'); await writeFile(copied, build.bytes, { mode: 0o500, flag: 'wx' });
    origin = http.createServer({ maxHeaderSize: 8192, requestTimeout: 2500, headersTimeout: 2000 }, (req, res) => {
      const tenant = req.headers['x-x10-test-tenant'];
      if (req.method !== 'GET' || req.url !== contract.resource || !contract.tenants.includes(tenant)) { res.writeHead(404); res.end(); return; }
      originTrace.push({ method: req.method, path: req.url, tenant });
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'max-age=60', 'Connection': 'close' }); res.end(`tenant:${tenant}\n`);
    });
    origin.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.setTimeout(3000, () => socket.destroy()); });
    const originPort = await listening(origin), port = await unusedPort(), ready = randomBytes(12).toString('hex');
    const configFile = path.join(prefix, 'nginx.conf'); await writeFile(configFile, config(prefix, port, originPort, ready, contract), { mode: 0o600, flag: 'wx' });
    await execute(copied, ['-t', '-p', `${prefix}/`, '-c', configFile], { timeout: 3000, maxBuffer: 64 * 1024, signal });
    if (interrupted) fail('interrupted', 'Verification interrupted');
    child = spawn(copied, ['-p', `${prefix}/`, '-c', configFile], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const exited = new Promise(resolve => { child.once('error', () => { exit = { spawnError: true }; resolve(exit); }); child.once('close', (code, childSignal) => { exit = { code, signal: childSignal }; resolve(exit); }); });
    const collect = bytes => { nativeOutputBytes += bytes.length; if (nativeOutputBytes > 64 * 1024) { outputOverflow = true; abort(); } };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    // A unique readiness response rejects an unrelated listener in the port-reservation race.
    const readyDeadline = Date.now() + 4000;
    let observed = false;
    while (Date.now() < readyDeadline && !observed) {
      if (exit || interrupted) fail(interrupted ? 'interrupted' : 'native_start', 'Native fixture did not become ready');
      try { const response = await request(port, `/__x10_ready_${ready}`, null, requests); observed = response.status === 200 && response.body === ready; } catch {}
      if (!observed) await delay(20);
    }
    if (!observed) fail('native_start', 'Native fixture readiness deadline expired');
    const steps = [];
    // Warm both tenants, then verify same-tenant hits. Fresh cache for every order.
    for (const tenant of [...order, ...order]) {
      if (interrupted) fail('interrupted', 'Verification interrupted');
      const response = await request(port, contract.resource, tenant, requests);
      // Infrastructure/routing failures are not evidence of cross-tenant leakage.
      if (response.status !== 200 || !contract.tenants.some(id => response.body === `tenant:${id}\n`)) fail('fixture_response', 'Native fixture did not return a recognized tenant response');
      if (steps.length === 0 && response.body !== `tenant:${tenant}\n`) fail('fixture_state', 'Initially empty fixture cache did not return the priming tenant');
      steps.push({ request: { method: 'GET', path: contract.resource, headers: { 'X-X10-Test-Tenant': tenant } },
        expectedBody: `tenant:${tenant}\n`, response, matchesTenant: response.status === 200 && response.body === `tenant:${tenant}\n` });
    }
    const isolation = steps.every(step => step.matchesTenant);
    const cacheEffective = steps.every((step, i) => step.response.cacheStatus === (i < order.length ? 'MISS' : 'HIT'))
      && originTrace.length === order.length && order.every(tenant => originTrace.filter(row => row.tenant === tenant).length === 1);
    const failedIndex = steps.findIndex(step => !step.matchesTenant);
    result = { order, checks: { tenantIsolation: isolation, cacheEffective }, steps, originTrace,
      ...(failedIndex >= 0 ? { counterexample: { kind: 'tenant-cache-response-mismatch', prime: steps[0], observe: steps[failedIndex],
        scope: 'Concrete synthetic sequence on an initially empty cache; not exhaustive isolation proof.' } } : {}) };
    if (sha256(await readFile(copied)) !== build.identity.binarySha256) fail('build_identity', 'Fixture binary changed during execution');
    // Stop this one-process native fixture before removing any owned data.
    process.kill(-child.pid, 'SIGQUIT');
    await untilExit(exited, 2500);
    if (!exit || exit.code !== 0 || exit.signal !== null) fail('native_shutdown', 'Native fixture did not exit cleanly');
    stopped = true;
  } finally {
    clearTimeout(deadline); signal?.removeEventListener('abort', abort);
    for (const req of requests) req.destroy();
    for (const socket of sockets) socket.destroy();
    if (child?.pid && !stopped && !exit) {
      try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') cleanupErrors.push('native_term'); }
      const end = Date.now() + 1000; while (!exit && Date.now() < end) await delay(20);
      if (!exit) { forced = true; try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') cleanupErrors.push('native_kill'); } }
      const killEnd = Date.now() + 1000; while (!exit && Date.now() < killEnd) await delay(20);
      if (!exit) cleanupErrors.push('native_not_reaped');
    }
    if (origin) await new Promise(resolve => origin.close(resolve));
    const socketDeadline = Date.now() + 1000;
    while (sockets.size && Date.now() < socketDeadline) await delay(10);
    if (sockets.size) cleanupErrors.push('open_sockets');
    // Preserve owned diagnostics if a child could not be reaped; do not report removal.
    if (prefix && (!child || exit)) { try { await rm(prefix, { recursive: true, force: true }); } catch { cleanupErrors.push('temporary_root'); } }
    if (cleanupErrors.length) fail('cleanup_failed', 'Owned fixture cleanup did not complete');
    if (outputOverflow) fail('native_output_limit', 'Native output exceeded fixture limit');
    if (result) result.cleanup = { nativeStopped: Boolean(exit), nativeExitCode: exit?.code ?? null, nativeSignal: exit?.signal ?? null,
      originStopped: !origin?.listening, openSockets: sockets.size, temporaryRootRemoved: true, forcedCleanup: forced };
  }
  return result;
}

export async function checkContract(input, build, { signal } = {}) {
  const contract = validateContract(input);
  const orders = [];
  for (const order of [contract.tenants, [...contract.tenants].reverse()]) orders.push(await runOrder(contract, build, order, signal));
  const passed = orders.every(order => order.checks.tenantIsolation && order.checks.cacheEffective);
  return { contractSha256: sha256(JSON.stringify(contract)), kind: contract.kind, resource: contract.resource,
    cache: contract.cache, passed, orders };
}

const limitations = [
  'Deterministic verification kernel; no LLM or automatic repair integration is implemented.',
  'Generated trusted configs only: one Linux HTTP proxy/cache profile, two synthetic tenant labels, one resource, two fresh-cache request orders.',
  'Tenant labels are fixture input, not authenticated identities. No customer secrets, imported configs, production traffic or external upstreams are used.',
  'A pass covers these finite scenarios, not every URI, tenant, timing, module, authorization policy or failure state.',
  'Cache effectiveness is part of the contract: disabling caching does not satisfy it.',
  'Build hashes check local consistency, not signatures, reproducible-build attestation or dynamic-library stability.',
];
export async function verifyContracts({ contract, baseline, candidate, binary, manifest, signal }) {
  if (Boolean(contract) === Boolean(baseline || candidate) || Boolean(baseline) !== Boolean(candidate)) fail('arguments', 'Select one contract or a baseline/candidate pair', 'invalid_input');
  const selected = contract ? [validateContract(contract)] : [validateContract(baseline), validateContract(candidate)];
  if (selected.length === 2 && (selected[0].kind !== selected[1].kind || selected[0].resource !== selected[1].resource
    || JSON.stringify(selected[0].tenants) !== JSON.stringify(selected[1].tenants))) fail('incomparable_contracts', 'Baseline and candidate must test identical resource and tenant identities', 'invalid_input');
  const build = await verifyBuild({ binary, manifest, signal }), before = build.identity;
  const checks = [];
  for (const input of selected) checks.push(await checkContract(input, build, { signal }));
  const after = (await verifyBuild({ binary: build.binary, manifest, signal })).identity;
  if (signal?.aborted) fail('interrupted', 'Verification interrupted');
  if (JSON.stringify(before) !== JSON.stringify(after)) fail('build_identity', 'Build identity changed during verification');
  const passed = checks.every(check => check.passed);
  const outcome = contract ? passed ? 'contract_passed' : 'contract_violated'
    : !checks[0].passed ? 'baseline_violates_contract' : checks[1].passed ? 'candidate_passed_checked_contract' : 'candidate_violates_contract';
  return { schemaVersion: 1, kind: 'nginx-x10-contract-verification', outcome, passed, aiIntegration: false,
    identity: before, checks, limitations };
}
