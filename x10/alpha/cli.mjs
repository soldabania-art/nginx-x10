#!/usr/bin/env node
// Explicit local Linux alpha. Node supervises/controls; native NGINX serves requests.
import { constants } from 'node:fs';
import { access, chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { canonical, digest, exists, fail, inspectMaster, remainingNativeGroup, owned, same, simple } from './runtime.mjs';

const execute = promisify(execFile), root = fileURLToPath(new URL('../../', import.meta.url));
const controlNames = ['cli.mjs', 'manager.mjs', 'listeners.mjs', 'generations.mjs', 'status-format.mjs'];
const alphaNames = ['cli.mjs', 'runtime.mjs', 'upstream-example.mjs'];
const staticDirectories = ['bin', 'lib', 'lib/control', 'lib/alpha', 'licenses', 'examples', 'runs'];
const recipePath = 'lib/service/user-unit.mjs';
const supportedSchema = version => version === 1 || version === 2;
const installedNames = version => ['bin/nginx', 'bin/x10', 'build.json', 'licenses/NGINX-LICENSE', 'licenses/UPSTREAM.txt', 'examples/candidate-b.json',
  ...controlNames.map(name => `lib/control/${name}`), ...alphaNames.map(name => `lib/alpha/${name}`), ...(version === 2 ? [recipePath] : [])].sort();
const bundleNames = version => ['bin/nginx', 'install.mjs', 'LICENSE', 'NOTICE', 'x10/alpha/README.md',
  ...alphaNames.map(name => `x10/alpha/${name}`), ...controlNames.map(name => `x10/control/${name}`), ...(version === 2 ? ['x10/service/user-unit.mjs'] : [])].sort();
const payloadMode = relative => ['bin/nginx', 'bin/x10'].includes(relative) ? '0500' : '0400';
const id = () => randomBytes(16).toString('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const binding = identity => { const { networkNamespace, ...value } = identity; return value; };
const direct = (prefix, relative) => path.join(prefix, relative);

async function load(file, limit = 2 * 1024 * 1024) {
  await owned(file); const stat = await lstat(file); if (stat.size > limit) fail('input_limit', `JSON exceeds limit: ${file}`);
  return JSON.parse(await readFile(file, 'utf8'));
}
async function atomic(file, value) {
  const tmp = `${file}.tmp-${id()}`, handle = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(encode(value)); await handle.sync(); } finally { await handle.close(); }
  await rename(tmp, file); const dir = await open(path.dirname(file), constants.O_RDONLY | constants.O_DIRECTORY);
  try { await dir.sync(); } finally { await dir.close(); }
}
async function saveRecord(file, value) { await atomic(file, { ...value, sha256: digest(JSON.stringify(value)) }); }
async function record(file) {
  const data = await load(file), { sha256, ...value } = data;
  if (!/^[a-f0-9]{64}$/.test(sha256 || '') || digest(JSON.stringify(value)) !== sha256) fail('alpha_integrity', `Record integrity failed: ${file}`);
  return value;
}
async function lock(prefix, fn) {
  const file = path.join(prefix, '.alpha-lock'); let handle, moved = false;
  try { handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') fail('alpha_locked', 'Alpha is locked; stale locks require operator inspection'); throw error; }
  try { await handle.writeFile(encode({ pid: process.pid, at: new Date().toISOString() })); await handle.sync(); return await fn(() => { moved = true; }); }
  finally { await handle.close(); if (!moved) await rm(file); }
}
async function manager(prefix) { return import(pathToFileURL(path.join(prefix, 'lib/control/manager.mjs')).href); }
async function controllerState(prefix, session) { return path.join(prefix, 'runs', session, '.x10-control'); }

async function dependencies(binary) {
  const { stdout } = await execute('ldd', [binary], { timeout: 5000, maxBuffer: 128 * 1024 });
  const paths = new Set();
  for (const line of stdout.split('\n')) {
    if (/not found/.test(line)) fail('dependency_missing', 'Native dynamic dependency is unavailable');
    const value = /(?:=>\s*)?(\/[^\s]+)\s+\(/.exec(line)?.[1]; if (value) paths.add(await realpath(value));
  }
  if (!paths.size) fail('unsupported_binary', 'This alpha requires the recorded Linux dynamic build profile');
  return { kind: 'dynamic-host-libraries', ldd: stdout.trim(), files: await Promise.all([...paths].sort().map(async file => ({ path: file, sha256: digest(await readFile(file)), bytes: (await lstat(file)).size }))) };
}

async function sourceBuild(manifestFile, selectedBinary) {
  manifestFile = path.resolve(manifestFile); await canonical(manifestFile); const bytes = await readFile(manifestFile), build = JSON.parse(bytes);
  const binary = path.resolve(selectedBinary || build.binary?.path || ''); await canonical(binary); const stat = await owned(binary);
  await access(binary, constants.X_OK);
  if (build.status !== 'built' || build.binary?.path !== binary || !build.binary.executable || build.binary.sha256 !== digest(await readFile(binary))
    || build.binary.bytes !== stat.size || build.binary.mode !== (stat.mode & 0o7777).toString(8).padStart(4, '0')
    || !Array.isArray(build.compiledModules) || !build.compiledModules.length || new Set(build.compiledModules).size !== build.compiledModules.length)
    fail('build_identity', 'Selected binary does not match the complete built manifest');
  const version = (await execute(binary, ['-V'], { timeout: 5000, maxBuffer: 256 * 1024 })).stderr;
  if (version.trim() !== build.nginxVersionOutput.trim()) fail('build_identity', 'Native -V differs from build record');
  const source = await canonical(build.workingDirectory), pin = JSON.parse(await readFile(path.join(source, 'x10/upstream.json'), 'utf8'));
  if (build.upstreamRevision !== pin.commit) fail('build_identity', 'Build upstream pin differs');
  const untracked = (await execute('git', ['ls-files', '--others', '--exclude-standard', '--', 'src', 'auto', 'conf'], { cwd: source, timeout: 5000 })).stdout.trim();
  if (untracked) fail('build_identity', 'Untracked native inputs are not represented by the build');
  const diff = (await execute('git', ['diff', '--binary', pin.commit, '--', 'src', 'auto', 'conf'], { cwd: source, timeout: 5000, encoding: 'buffer', maxBuffer: 8 * 1024 * 1024 })).stdout;
  if (digest(diff) !== build.sourceDiffSha256) fail('build_identity', 'Native source differs from the recorded build');
  const objects = build.configureArgv?.find(value => value.startsWith('--builddir='))?.slice(11); await canonical(objects);
  for (const name of ['ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c']) {
    const file = path.join(objects, name), expected = build.generatedFiles?.[name], actual = await owned(file);
    if (!expected || digest(await readFile(file)) !== expected.sha256 || actual.size !== expected.bytes || (actual.mode & 0o7777).toString(8).padStart(4, '0') !== expected.mode) fail('build_identity', `Generated build input differs: ${name}`);
  }
  return { binary, build, manifestSha256: digest(bytes), source, dependencies: await dependencies(binary) };
}

async function bundleBuild() {
  await canonical(root.replace(/\/$/, '')); const manifest = await record(path.join(root, 'bundle.json'));
  const names = bundleNames(manifest.schemaVersion);
  if (!supportedSchema(manifest.schemaVersion) || manifest.kind !== 'nginx-x10-linux-alpha-bundle' || !same(Object.keys(manifest.files || {}).sort(), names)
    || manifest.platform?.system !== 'Linux' || manifest.platform.machine !== os.machine()) fail('bundle_identity', 'Bundle profile or inventory is invalid for this host');
  for (const relative of ['', 'bin', 'x10', 'x10/alpha', 'x10/control', ...(manifest.schemaVersion === 2 ? ['x10/service'] : [])]) {
    const directory = relative ? path.join(root, relative) : root.replace(/\/$/, ''); await canonical(directory); const stat = await owned(directory, true, true);
    if ((stat.mode & 0o7777) !== 0o700) fail('bundle_identity', 'Bundle directory mode differs from its profile');
  }
  for (const [relative, expected] of Object.entries(manifest.files)) {
    const file = path.join(root, relative); await canonical(path.dirname(file)); const stat = await owned(file);
    if (expected.mode !== payloadMode(relative) || stat.size !== expected.bytes || digest(await readFile(file)) !== expected.sha256 || (stat.mode & 0o7777).toString(8).padStart(4, '0') !== expected.mode) fail('bundle_identity', `Bundle file changed: ${relative}`);
  }
  const binary = path.join(root, 'bin/nginx'), version = (await execute(binary, ['-V'], { timeout: 5000, maxBuffer: 256 * 1024 })).stderr.trim();
  if (digest(version) !== manifest.nativeVersionOutputSha256) fail('bundle_identity', 'Bundle native version/build metadata differs');
  const build = { ...manifest.provenance, binary: { path: binary, ...manifest.files['bin/nginx'], executable: true }, status: 'built', platform: manifest.platform };
  return { binary, build, source: root, manifestSha256: digest(await readFile(path.join(root, 'bundle.json'))), dependencies: await dependencies(binary), notice: path.join(root, 'NOTICE'), bundleSchemaVersion: manifest.schemaVersion };
}

export async function pack(values) {
  if (!values.output) fail('arguments', 'pack requires --output FILE.tar.gz');
  const output = path.resolve(values.output);
  if (!simple(output) || !output.endsWith('.tar.gz') || await exists(output)) fail('unsafe_output', 'Choose an absent simple .tar.gz output path');
  const built = await sourceBuild(values.manifest || process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'), values.binary || process.env.X10_NGINX_BINARY);
  let ancestor = path.dirname(output); const missing = [];
  while (!await exists(ancestor)) { missing.push(path.basename(ancestor)); ancestor = path.dirname(ancestor); }
  await canonical(ancestor); await owned(ancestor, true);
  for (const name of missing.reverse()) { ancestor = path.join(ancestor, name); await mkdir(ancestor, { mode: 0o700 }); await canonical(ancestor); await owned(ancestor, true, true); }
  await canonical(path.dirname(output)); await owned(path.dirname(output), true);
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'x10-pack-')), bundle = path.join(temporary, 'nginx-x10-alpha'), archive = path.join(path.dirname(output), `.x10-pack-${id()}.tar.gz`);
  try {
    await mkdir(bundle, { mode: 0o700 }); for (const dir of ['bin', 'x10', 'x10/alpha', 'x10/control', 'x10/service']) await mkdir(path.join(bundle, dir), { mode: 0o700 });
    const files = {}, put = async (relative, bytes, mode = 0o400) => { await writeFile(path.join(bundle, relative), bytes, { mode, flag: 'wx' }); files[relative] = { bytes: bytes.length, sha256: digest(bytes), mode: mode.toString(8).padStart(4, '0') }; };
    await put('bin/nginx', await readFile(built.binary), 0o500);
    for (const name of alphaNames) await put(`x10/alpha/${name}`, await readFile(path.join(root, 'x10/alpha', name)));
    for (const name of controlNames) await put(`x10/control/${name}`, await readFile(path.join(root, 'x10/control', name)));
    await put('x10/service/user-unit.mjs', await readFile(path.join(root, 'x10/service/user-unit.mjs')));
    await put('x10/alpha/README.md', await readFile(path.join(root, 'x10/alpha/README.md')));
    await put('LICENSE', await readFile(path.join(built.source, 'LICENSE'))); await put('NOTICE', await readFile(path.join(root, 'x10/alpha/NOTICE.txt')));
    await put('install.mjs', Buffer.from('import { main } from "./x10/alpha/cli.mjs";\nawait main(process.argv.slice(2));\n'));
    const b = built.build, provenance = { upstreamRepository: b.upstreamRepository, upstreamRevision: b.upstreamRevision, checkoutRevision: b.checkoutRevision,
      sourceDiffSha256: b.sourceDiffSha256, nginxVersion: b.nginxVersion, compiledModules: b.compiledModules,
      dependencyVersionsFromHeaders: b.dependencyVersionsFromHeaders, compilerFlags: b.compilerFlags,
      configureFlags: b.configureArgv.filter(v => v.startsWith('--')).map(v => v.startsWith('--builddir=') ? '--builddir=<build-directory>' : v.startsWith('--prefix=') ? '--prefix=<build-prefix>' : v.includes('=/') ? `${v.split('=')[0]}=<path>` : v) };
    await saveRecord(path.join(bundle, 'bundle.json'), { schemaVersion: 2, kind: 'nginx-x10-linux-alpha-bundle', platform: { system: 'Linux', machine: b.platform.machine },
      files, provenance, nativeVersionOutputSha256: digest(b.nginxVersionOutput.trim()), runtimeNote: 'Dynamic host ABI and Node 22+ required. Checksums are consistency records, not a signature or reproducible-build attestation. Native binary debug/configure metadata can contain build paths.' });
    await execute('tar', ['-czf', archive, '-C', temporary, 'nginx-x10-alpha'], { timeout: 15000, maxBuffer: 128 * 1024 }); await chmod(archive, 0o600);
    await link(archive, output); return { ok: true, outcome: 'packed', output, bytes: (await lstat(output)).size, sha256: digest(await readFile(output)), binarySha256: b.binary.sha256 };
  } finally { await rm(temporary, { recursive: true, force: true }); await rm(archive, { force: true }); }
}

function config(prefix, healthPort) {
  const user = process.getuid() === 0 ? `user ${os.userInfo().username};\n` : '';
  return `${user}daemon off;\nmaster_process on;\nworker_processes 1;\npid ${prefix}/nginx.pid;\nerror_log ${prefix}/logs/error.log notice;\nevents { worker_connections 256; }\nhttp {\n access_log off;\n client_body_temp_path ${prefix}/temp/client;\n proxy_temp_path ${prefix}/temp/proxy;\n fastcgi_temp_path ${prefix}/temp/fastcgi;\n uwsgi_temp_path ${prefix}/temp/uwsgi;\n scgi_temp_path ${prefix}/temp/scgi;\n server { listen 127.0.0.1:${healthPort}; server_name localhost;\n  location = /__x10_demo_self_check { return 200 "native demo self-check\\n"; }\n }\ninclude ${prefix}/managed.conf;\n}\n`;
}
const demo = healthPort => ({ serverBody: 'location = / { return 200 "NGINX X10 local alpha\\n"; }', healthURL: `http://127.0.0.1:${healthPort}/__x10_demo_self_check` });
const application = upstreamPort => ({
  serverBody: `client_max_body_size 16m;\nlocation / { proxy_pass http://127.0.0.1:${upstreamPort}; proxy_http_version 1.1; proxy_next_upstream off; }`,
  healthURL: `http://127.0.0.1:${upstreamPort}/ready`,
  healthExpectedStatus: 200,
  healthExpectedBody: 'ready\n',
});

async function createSession(prefix, manifest, seed) {
  const session = id(), target = path.join(prefix, 'runs', session); await mkdir(target, { mode: 0o700 });
  for (const dir of ['logs', 'temp', 'temp/client', 'temp/proxy', 'temp/fastcgi', 'temp/uwsgi', 'temp/scgi']) await mkdir(path.join(target, dir), { mode: 0o700 });
  await writeFile(path.join(target, 'nginx.conf'), config(target, manifest.healthPort), { mode: 0o600 });
  const control = await manager(prefix), initial = await control.initialize({ prefix: target, binary: path.join(prefix, 'bin/nginx'), port: manifest.port, gateTimeoutMs: 3000 }, seed);
  const lifecycle = { schemaVersion: 1, installationId: manifest.installationId, session, prefix: target, createdAt: new Date().toISOString(), stage: 'prepared', runtime: null, controlSocket: null };
  await saveRecord(path.join(target, 'lifecycle.json'), lifecycle); return { session, initial, lifecycle };
}

// Declarative backup foundation. These records contain sensitive configuration,
// not executable/package/session state, and their hashes are not signatures.
function backupInput(value, port) {
  const keys = ['serverBody', 'healthURL'], explicit = Object.hasOwn(value || {}, 'healthExpectedStatus');
  if (explicit) keys.push('healthExpectedStatus', 'healthExpectedBody');
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !same(Object.keys(value), keys) || typeof value.serverBody !== 'string'
      || Buffer.byteLength(value.serverBody) > 1024 * 1024
      || Buffer.from(value.serverBody, 'utf8').toString('utf8') !== value.serverBody
      || typeof value.healthURL !== 'string'
      || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/[A-Za-z0-9/_.~%-]*$/.test(value.healthURL))
    fail('backup_unsupported', 'Only the declared HTTP candidate input profile is supported');
  let healthPort; try { healthPort = Number(new URL(value.healthURL).port); }
  catch { fail('backup_unsupported', 'Declarative readiness URL is outside the supported HTTP profile'); }
  if (!Number.isInteger(healthPort) || healthPort < 1 || healthPort > 65535 || healthPort === port
      || (explicit && (!Number.isInteger(value.healthExpectedStatus) || value.healthExpectedStatus < 200
        || value.healthExpectedStatus > 299 || typeof value.healthExpectedBody !== 'string'
        || Buffer.byteLength(value.healthExpectedBody) > 4096
        || Buffer.from(value.healthExpectedBody, 'utf8').toString('utf8') !== value.healthExpectedBody)))
    fail('backup_unsupported', 'Declarative readiness input is outside the supported HTTP profile');
  return value;
}
function backupDocument(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !same(Object.keys(value), ['schemaVersion', 'kind', 'source', 'port', 'healthPort', 'input', 'inputSha256', 'sha256'])
      || value.schemaVersion !== 1 || value.kind !== 'nginx-x10-declarative-backup'
      || !value.source || !same(Object.keys(value.source), ['installationId', 'session', 'revision'])
      || Object.values(value.source).some(v => typeof v !== 'string' || !/^[a-f0-9]{32}$/.test(v))
      || ![value.port, value.healthPort].every(p => Number.isInteger(p) && p >= 1024 && p <= 65535)
      || value.port === value.healthPort)
    fail('backup_invalid', 'Declarative backup shape is invalid');
  backupInput(value.input, value.port);
  const { sha256, ...body } = value;
  if (!/^[a-f0-9]{64}$/.test(sha256 || '') || value.inputSha256 !== digest(JSON.stringify(value.input))
      || sha256 !== digest(JSON.stringify(body))) fail('backup_invalid', 'Declarative backup consistency checks failed');
  return value;
}
async function backupParent(parent) {
  await canonical(parent); const leaf = await owned(parent, true, true);
  if ((leaf.mode & 0o7777) !== 0o700) fail('backup_path', 'Backup parent must have mode0700');
  let current = parent, count = 0;
  for (;;) {
    if (++count > 128) fail('backup_path', 'Backup ancestor bound exceeded');
    const stat = await lstat(current), sticky = (stat.mode & 0o1000) && (stat.mode & 0o002);
    if (!stat.isDirectory() || ![0, process.getuid()].includes(stat.uid)
        || ((stat.mode & 0o022) && !sticky)) fail('backup_path', 'Backup ancestor permissions are unsafe');
    if (current === '/') break; current = path.dirname(current);
  }
  return { dev: leaf.dev, ino: leaf.ino, uid: leaf.uid, mode: leaf.mode };
}
const backupFileIdentity = stat => ({ dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode,
  nlink: stat.nlink, size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs });
async function readBackup(file) {
  if (!simple(file)) fail('backup_path', 'Backup input requires a simple absolute path');
  const parent = await backupParent(path.dirname(file)), selected = await lstat(file), limit = 2 * 1024 * 1024;
  if (!selected.isFile() || selected.uid !== process.getuid() || selected.nlink !== 1
      || (selected.mode & 0o7777) !== 0o600 || selected.size < 1 || selected.size > limit)
    fail('backup_path', 'Backup input must be one owned0600 bounded regular file');
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.getuid() || before.nlink !== 1
        || (before.mode & 0o7777) !== 0o600 || before.size < 1 || before.size > limit
        || !same(backupFileIdentity(selected), backupFileIdentity(before)))
      fail('backup_path', 'Backup input must be one owned0600 bounded regular file');
    const bytes = Buffer.alloc(limit + 1); let length = 0;
    try {
      while (length < bytes.length) { const result = await handle.read(bytes, length, bytes.length - length, null); if (!result.bytesRead) break; length += result.bytesRead; }
      const after = await handle.stat();
      if (length !== before.size || !same(backupFileIdentity(before), backupFileIdentity(after))
          || !same(backupFileIdentity(after), backupFileIdentity(await lstat(file)))
          || !same(parent, await backupParent(path.dirname(file)))) fail('backup_path', 'Backup input identity changed while reading');
      const selectedBytes = bytes.subarray(0, length), text = selectedBytes.toString('utf8'); let value;
      if (!Buffer.from(text, 'utf8').equals(selectedBytes)) fail('backup_invalid', 'Backup must use well-formed UTF-8 bytes');
      try { value = JSON.parse(text); } catch { fail('backup_invalid', 'Backup JSON is invalid'); }
      backupDocument(value);
      if (encode(value) !== text) fail('backup_invalid', 'Backup must use its exact canonical JSON encoding');
      return value;
    } finally { bytes.fill(0); }
  } finally { await handle.close(); }
}
async function publishBackup(context, output, value, recheck) {
  if (!simple(output) || output === context.prefix || output.startsWith(`${context.prefix}/`))
    fail('backup_path', 'Choose a new backup file outside the installation');
  backupDocument(value);
  const parentPath = path.dirname(output), parent = await backupParent(parentPath), bytes = Buffer.from(encode(value));
  if (bytes.length > 2 * 1024 * 1024) { bytes.fill(0); fail('backup_invalid', 'Backup exceeds its bounded file profile'); }
  const temporary = path.join(parentPath, `.x10-backup-${id()}`);
  let handle;
  try {
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes); await handle.sync();
    const stat = await handle.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o600 || stat.size !== bytes.length)
      fail('backup_path', 'Private backup temporary identity is invalid');
    await recheck();
    if (!same(parent, await backupParent(parentPath))
        || !same(backupFileIdentity(stat), backupFileIdentity(await lstat(temporary)))) fail('backup_path', 'Backup publication identity changed');
    // link is an atomic, non-overwriting publication. Same-UID cooperative
    // operation is required: this is not an openat-style adversarial fence.
    await link(temporary, output); await rm(temporary);
    const published = await lstat(output);
    if (published.dev !== stat.dev || published.ino !== stat.ino || published.uid !== stat.uid
        || published.nlink !== 1 || (published.mode & 0o7777) !== 0o600 || published.size !== bytes.length)
      fail('backup_path', 'Published backup identity is unconfirmed');
    const directory = await open(parentPath, constants.O_RDONLY | constants.O_DIRECTORY);
    try { await directory.sync(); } finally { await directory.close(); }
    return { ok: true, outcome: 'declarative_backup_created', bytes: bytes.length, sha256: digest(bytes),
      nativeStarted: false, serviceAccepted: false, productionAccepted: false };
  } finally { bytes.fill(0); if (handle) { await handle.close(); await rm(temporary, { force: true }); } }
}
async function backup(context, output) {
  const snapshot = async () => {
    let current;
    for (const session of context.registry.sessions) {
      const life = await lifecycle(context, session);
      if (!['prepared', 'stopped'].includes(life.stage)) fail('backup_requires_stopped', 'Every session must be prepared or cleanly stopped');
      if (life.stage === 'prepared' && (life.runtime !== null || life.controlSocket !== null))
        fail('runtime_identity', 'Prepared backup source must be unbound and unstarted');
      await stopped(context, life); const status = await sessionStatus(context, life);
      if (session === context.registry.current) current = { life, status };
    }
    const { life, status } = current, revision = await load(path.join(life.prefix, '.x10-control/revisions', `${status.result.lastConfirmedRevision}.json`));
    const { recordSha256, ...body } = revision;
    if (revision.id !== status.result.lastConfirmedRevision || digest(JSON.stringify(body)) !== recordSha256
        || digest(JSON.stringify(revision.input)) !== revision.inputSha256) fail('alpha_integrity', 'Confirmed backup input integrity failed');
    backupInput(revision.input, context.manifest.port);
    const bodyValue = { schemaVersion: 1, kind: 'nginx-x10-declarative-backup',
      source: { installationId: context.manifest.installationId, session: life.session, revision: revision.id },
      port: context.manifest.port, healthPort: context.manifest.healthPort, input: revision.input, inputSha256: revision.inputSha256 };
    return backupDocument({ ...bodyValue, sha256: digest(JSON.stringify(bodyValue)) });
  };
  const value = await snapshot();
  return publishBackup(context, output, value, async () => {
    const fresh = await installed(context.prefix);
    if (!same(fresh.manifest, context.manifest) || !same(fresh.registry, context.registry)
        || !same(value, await snapshot())) fail('operator_conflict', 'Backup source changed before publication');
  });
}
// End declarative backup foundation.

export async function install(values) {
  if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) < 22) fail('unsupported', 'Linux and Node 22+ are required');
  const prefix = values.prefix;
  if (!simple(prefix) || prefix === '/' || prefix === process.env.HOME || path.dirname(prefix) === '/') fail('unsafe_prefix', 'Choose a new simple absolute prefix below an existing directory');
  await canonical(path.dirname(prefix));
  const parent = await lstat(path.dirname(prefix));
  const sticky = (parent.mode & 0o1000) && (parent.mode & 0o002);
  if (!parent.isDirectory() || (parent.uid !== process.getuid() && !sticky) || ((parent.mode & 0o022) && !sticky)) fail('unsafe_prefix', 'Parent must be safely owned or a sticky temporary directory');
  if (await exists(prefix)) fail('already_exists', 'Install prefix must not exist');
  const restored = values.restore === undefined ? null : await readBackup(values.restore);
  if (restored && ['port', 'health-port', 'upstream-port'].some(key => values[key] !== undefined))
    fail('arguments', 'Restore preserves declared ports; omit port and upstream options');
  const port = Number(restored?.port ?? values.port ?? 9080), healthPort = Number(restored?.healthPort ?? values['health-port'] ?? 9081);
  if (![port, healthPort].every(p => Number.isInteger(p) && p >= 1024 && p <= 65535) || port === healthPort) fail('invalid_port', 'Distinct unprivileged ports 1024..65535 are required');
  let upstreamPort = null;
  if (values['upstream-port'] !== undefined) {
    const value = values['upstream-port'];
    if (typeof value !== 'string' || !/^[1-9][0-9]{3,4}$/.test(value)
        || Number(value) < 1024 || Number(value) > 65535
        || [port, healthPort].includes(Number(value)))
      fail('invalid_upstream_port', 'Upstream requires a distinct unprivileged decimal loopback port 1024..65535');
    upstreamPort = Number(value);
  }
  const seed = restored ? restored.input : upstreamPort === null ? demo(healthPort) : application(upstreamPort);
  const bundled = await exists(path.join(root, 'bundle.json'));
  if (bundled && (values.manifest || values.binary)) fail('arguments', 'Bundle installation uses its own checked payload; omit --manifest/--binary');
  const built = bundled ? await bundleBuild() : await sourceBuild(values.manifest || process.env.X10_BUILD_MANIFEST || path.join(root, 'x10/.build/manifest.json'), values.binary || process.env.X10_NGINX_BINARY);
  // Validate/capture every source file before creating the install prefix.
  const schemaVersion = bundled ? built.bundleSchemaVersion : 2;
  const copies = [];
  if (schemaVersion === 2) { const file = path.join(root, 'x10/service/user-unit.mjs'); await owned(file); copies.push({ relative: recipePath, bytes: await readFile(file), mode: 0o400 }); }
  for (const name of controlNames) { const file = path.join(root, 'x10/control', name); await owned(file); copies.push({ relative: `lib/control/${name}`, bytes: await readFile(file), mode: 0o400 }); }
  for (const name of alphaNames) { const file = path.join(root, 'x10/alpha', name); await owned(file); copies.push({ relative: `lib/alpha/${name}`, bytes: await readFile(file), mode: 0o400 }); }
  const license = await readFile(path.join(built.source, 'LICENSE')); copies.push({ relative: 'licenses/NGINX-LICENSE', bytes: license, mode: 0o400 });
  copies.push({ relative: 'licenses/UPSTREAM.txt', bytes: Buffer.concat([await readFile(built.notice || path.join(root, 'x10/alpha/NOTICE.txt')), Buffer.from(`\nPinned upstream revision: ${built.build.upstreamRevision}\n`)]), mode: 0o400 });
  const launcher = '#!/usr/bin/env node\nimport { main } from "../lib/alpha/cli.mjs";\nimport { fileURLToPath } from "node:url";\nawait main(process.argv.slice(2), fileURLToPath(new URL("../", import.meta.url)));\n';
  copies.push({ relative: 'bin/x10', bytes: Buffer.from(launcher), mode: 0o500 });
  copies.push({ relative: 'build.json', bytes: Buffer.from(encode(built.build)), mode: 0o400 });
  await mkdir(prefix, { mode: 0o700 });
  try {
    for (const dir of [...staticDirectories, ...(schemaVersion === 2 ? ['lib/service'] : [])]) await mkdir(path.join(prefix, dir), { mode: 0o700 });
    const immutable = {};
    await copyFile(built.binary, path.join(prefix, 'bin/nginx'), constants.COPYFILE_EXCL); await chmod(path.join(prefix, 'bin/nginx'), 0o500);
    immutable['bin/nginx'] = { sha256: built.build.binary.sha256, bytes: built.build.binary.bytes, mode: '0500' };
    for (const item of copies) {
      await writeFile(path.join(prefix, item.relative), item.bytes, { mode: item.mode, flag: 'wx' });
      immutable[item.relative] = { sha256: digest(item.bytes), bytes: item.bytes.length, mode: item.mode.toString(8).padStart(4, '0') };
    }
    const candidate = restored ? { ...seed } : upstreamPort === null
      ? { ...demo(healthPort), serverBody: 'location = / { return 200 "NGINX X10 updated local alpha\\n"; }' }
      : { ...seed, serverBody: `${seed.serverBody}\nadd_header X-X10-Example "application-b" always;` };
    await writeFile(path.join(prefix, 'examples/candidate-b.json'), encode(candidate), { mode: 0o400 });
    immutable['examples/candidate-b.json'] = { sha256: digest(encode(candidate)), bytes: Buffer.byteLength(encode(candidate)), mode: '0400' };
    const stat = await owned(prefix, true, true), manifest = { schemaVersion, kind: 'nginx-x10-local-alpha', installationId: id(), prefix,
      rootIdentity: { dev: stat.dev, ino: stat.ino, uid: stat.uid }, installedAt: new Date().toISOString(), port, healthPort, immutable,
      buildManifestSha256: built.manifestSha256, upstreamRevision: built.build.upstreamRevision, nginxVersion: built.build.nginxVersion,
      sourceDiffSha256: built.build.sourceDiffSha256, compiledModules: built.build.compiledModules, dependencyVersionsFromHeaders: built.build.dependencyVersionsFromHeaders,
      dependencies: built.dependencies, runtimeNote: 'Dynamically linked host-specific local build, not a static or reproducible-build attestation.',
      nodeRuntime: { version: process.version, executable: await realpath(process.execPath), sha256: digest(await readFile(process.execPath)) },
      healthNote: restored ? 'Restored declarative HTTP input only; native syntax checked, no application health or traffic accepted. External files and services are not backed up.' : upstreamPort === null
        ? 'Native demo self-check only; application health is not established.'
        : 'Configured application readiness via loopback HTTP /ready with expected HTTP 200 and exact ready newline body; installation has not checked application health.' };
    await saveRecord(path.join(prefix, '.alpha-install.json'), manifest);
    const prepared = await createSession(prefix, manifest, seed);
    await saveRecord(path.join(prefix, '.alpha-registry.json'), { schemaVersion: 1, installationId: manifest.installationId, current: prepared.session, sessions: [prepared.session] });
    return { ok: true, outcome: 'installed', prefix, launcher: path.join(prefix, 'bin/x10'), session: prepared.session, sessionPrefix: prepared.lifecycle.prefix, revision: prepared.initial.revision, port, healthPort, controlApiEnabled: false, healthNote: manifest.healthNote,
      ...(restored ? { declarativeRestored: true, nativeStarted: false, readinessChecked: false, serviceAccepted: false, productionAccepted: false } : {}) };
  } catch (error) { error.message += `; incomplete private prefix preserved for inspection: ${prefix}`; throw error; }
}

async function installed(prefix, allowDependencyDrift = false) {
  prefix = path.resolve(prefix); await canonical(prefix); const stat = await owned(prefix, true, true), manifest = await record(path.join(prefix, '.alpha-install.json'));
  if (!supportedSchema(manifest.schemaVersion) || manifest.kind !== 'nginx-x10-local-alpha' || manifest.prefix !== prefix || !/^[a-f0-9]{32}$/.test(manifest.installationId || '')
    || (manifest.schemaVersion === 2 && (stat.mode & 0o7777) !== 0o700)
    || !same(manifest.rootIdentity, { dev: stat.dev, ino: stat.ino, uid: stat.uid })) fail('alpha_integrity', 'Installation root identity changed');
  const expectedFiles = installedNames(manifest.schemaVersion);
  if (!same(Object.keys(manifest.immutable || {}).sort(), expectedFiles)) fail('alpha_integrity', 'Installation inventory is incomplete or invalid');
  for (const relative of [...staticDirectories, ...(manifest.schemaVersion === 2 ? ['lib/service'] : [])]) {
    const directory = path.join(prefix, relative); await canonical(directory); const info = await owned(directory, true, true);
    if ((info.mode & 0o7777) !== 0o700) fail('alpha_integrity', 'Installation directory mode differs from its profile');
  }
  for (const [relative, expected] of Object.entries(manifest.immutable)) {
    const file = path.join(prefix, relative); await canonical(path.dirname(file)); const info = await owned(file);
    if (expected.mode !== payloadMode(relative) || (manifest.schemaVersion === 2 && info.nlink !== 1)
        || info.size !== expected.bytes || digest(await readFile(file)) !== expected.sha256 || (info.mode & 0o7777).toString(8).padStart(4, '0') !== expected.mode) fail('alpha_integrity', `Installed file changed: ${relative}`);
  }
  const dependencyDrift = [];
  if (!Array.isArray(manifest.dependencies?.files) || !manifest.dependencies.files.length) fail('alpha_integrity', 'Missing dynamic dependency inventory');
  for (const library of manifest.dependencies.files) {
    const matches = await readFile(library.path).then(async bytes => digest(bytes) === library.sha256 && (await lstat(library.path)).size === library.bytes).catch(() => false);
    if (!matches) dependencyDrift.push(library.path);
  }
  if (dependencyDrift.length && !allowDependencyDrift) fail('dependency_changed', 'Recorded host dynamic libraries changed; prepare a new alpha installation');
  const registry = await record(path.join(prefix, '.alpha-registry.json'));
  if (registry.schemaVersion !== 1 || registry.installationId !== manifest.installationId || !Array.isArray(registry.sessions) || !registry.sessions.length || registry.sessions.length > 256
    || registry.sessions.some(value => !/^[a-f0-9]{32}$/.test(value)) || new Set(registry.sessions).size !== registry.sessions.length || !registry.sessions.includes(registry.current)) fail('alpha_integrity', 'Session registry is inconsistent');
  return { prefix, manifest, registry, dependencyDrift };
}
async function serviceUnit(context, autoReadiness) {
  if (context.manifest.schemaVersion !== 2) fail('service_recipe_unavailable', 'This installed schema has no immutable service recipe');
  const node = context.manifest.nodeRuntime, executable = await realpath(process.execPath);
  const actual = await lstat(executable), mode = actual.mode & 0o7777;
  if (!node || executable !== node.executable || process.version !== node.version
      || !actual.isFile() || ![0, process.getuid()].includes(actual.uid)
      || (mode & 0o7022) !== 0 || (mode & 0o100) === 0 || actual.size < 1 || actual.size > 256 * 1024 * 1024
      || digest(await readFile(executable)) !== node.sha256)
    fail('service_recipe_invalid', 'Recipe requires the exact recorded Node runtime');
  // installed() validated the complete fixed inventory, helper bytes and modes
  // before this import. The command is read-only and never takes alpha's lock.
  const helper = await import(pathToFileURL(path.join(context.prefix, recipePath)).href);
  const value = { prefix: context.prefix, nodeExecutable: executable, autoReadiness };
  await helper.inspectInstallation(value);
  return { ok: true, unit: helper.renderUserUnit(value), ...helper.RECIPE_LIMITATIONS,
    readinessAutomated: autoReadiness, outcome: 'service_unit_generated', activationPerformed: false };
}
async function lifecycle(context, session = context.registry.current) {
  const prefix = path.join(context.prefix, 'runs', session); await canonical(prefix); await owned(prefix, true, true);
  const value = await record(path.join(prefix, 'lifecycle.json'));
  if (value.schemaVersion !== 1 || value.installationId !== context.manifest.installationId || value.session !== session || value.prefix !== prefix
    || !['prepared', 'running', 'stopping', 'stopped', 'faulted'].includes(value.stage)) fail('alpha_integrity', 'Session lifecycle is inconsistent');
  return value;
}
async function sessionStatus(context, life, requireClean = true) {
  const control = await manager(context.prefix), state = await controllerState(context.prefix, life.session), result = await control.status(state);
  if (requireClean && (!result.configUnchanged || !result.fragmentMatchesLastConfirmed || !result.history.integrity || result.pending)) fail('operator_conflict', 'Session has pending or changed operator state; preserve it for recovery/inspection');
  if (result.binding && (!life.runtime || !same(result.binding, binding(life.runtime)))) fail('runtime_identity', 'Controller binding differs from recorded alpha master');
  return { control, state, result };
}
async function stopped(context, life) {
  if (life.stage === 'faulted') fail('abnormal_exit', 'An abnormal native exit requires operator inspection; automatic restart/removal is refused');
  const binary = path.join(context.prefix, 'bin/nginx');
  if (await inspectMaster(binary, life.prefix, life.runtime, false)) fail('alpha_live', 'Native master is still running');
  if ((await remainingNativeGroup(binary, life.runtime)).length) fail('alpha_live', 'Recorded native process group still has live processes');
  const pidFile = path.join(life.prefix, 'nginx.pid');
  if (await exists(pidFile)) {
    await owned(pidFile); const text = await readFile(pidFile, 'utf8');
    if (text !== '' && text !== `${life.runtime?.pid}\n`) fail('runtime_identity', 'Stopped session PID file contains unknown data');
  }
}

// Called only under the existing alpha lock. Preparation publishes one guarded
// session before a supervisor starts run and wait-bind concurrently. It neither
// starts native code nor binds health, and partial writes require inspection.
async function prepareRun(context) {
  const prefix = context.prefix;
  let life = await lifecycle(context);
  await stopped(context, life); const prior = await sessionStatus(context, life);
  if (life.stage !== 'prepared') {
    if (life.stage !== 'stopped') fail('stop_required', 'Confirm the previous session with stop before another run');
    if (context.registry.sessions.length >= 256) fail('session_limit', 'Session bound reached; preserve history and prepare a new installation');
    const revision = await load(path.join(life.prefix, '.x10-control/revisions', `${prior.result.lastConfirmedRevision}.json`));
    const { recordSha256, ...body } = revision;
    if (digest(JSON.stringify(body)) !== recordSha256 || digest(JSON.stringify(revision.input)) !== revision.inputSha256) fail('alpha_integrity', 'Last-confirmed input failed integrity');
    const next = await createSession(prefix, context.manifest, revision.input); life = next.lifecycle;
    context.registry.sessions.push(next.session); context.registry.current = next.session;
    await saveRecord(path.join(prefix, '.alpha-registry.json'), context.registry);
  }
  return life;
}

async function run(prefix, values) {
  let context, life, child, identity, cancelled = false, forwarding = false;
  const forward = async () => {
    cancelled = true;
    if (forwarding || !identity || !child || child.exitCode !== null || child.signalCode !== null) return; forwarding = true;
    try { const actual = await inspectMaster(path.join(prefix, 'bin/nginx'), life.prefix, identity, false); if (actual) process.kill(actual.pid, 'SIGQUIT'); }
    catch (error) { process.stderr.write(`Alpha refused to signal changed runtime: ${error.message}\n`); }
  };
  // Install handlers before a detached native child can exist.
  process.on('SIGINT', forward); process.on('SIGTERM', forward);
  try {
  await lock(prefix, async () => {
    context = await installed(prefix); life = await prepareRun(context);
    let controlSocket = null;
    if (values['control-socket']) {
      controlSocket = path.resolve(values['control-socket']);
      if (!simple(controlSocket) || path.dirname(controlSocket) !== prefix || ['.alpha-lock', '.alpha-install.json', '.alpha-registry.json'].includes(path.basename(controlSocket)) || await exists(controlSocket)) fail('unsafe_control_socket', 'Choose an absent absolute socket path directly inside the private installation');
    }
    if (cancelled) fail('run_cancelled', 'Run cancelled before native startup');
    const binary = path.join(prefix, 'bin/nginx'), env = { ...process.env }; delete env.NGINX_CTRL;
    child = spawn(binary, ['-p', `${life.prefix}/`, '-c', path.join(life.prefix, 'nginx.conf'), ...(controlSocket ? ['-l', `unix:${controlSocket}`] : [])], { env, detached: true, stdio: 'inherit' });
    let spawnError; child.once('error', error => { spawnError = error; });
    process.stdout.write(encode({ ok: true, outcome: 'native_starting', session: life.session, candidatePid: child.pid ?? null, identityVerified: false }));
    const end = performance.now() + 5000;
    while (performance.now() < end) {
      if (cancelled) fail('run_cancelled', 'Run cancelled during native startup');
      if (spawnError || child.exitCode !== null || child.signalCode !== null) fail('native_start_failed', `Native startup failed: ${spawnError?.message || child.exitCode || child.signalCode}`);
      identity = await inspectMaster(binary, life.prefix, null).catch(error => { if (['ENOENT', 'runtime_identity'].includes(error.code)) return null; throw error; });
      if (identity && identity.pid === child.pid) break; identity = null; await delay(20);
    }
    if (!identity) fail('native_start_failed', 'Native did not establish its exact owned identity');
    if (cancelled) fail('run_cancelled', 'Run cancelled during native startup');
    life.stage = 'running'; life.runtime = identity; life.controlSocket = controlSocket;
    await saveRecord(path.join(life.prefix, 'lifecycle.json'), life);
    if (cancelled) fail('run_cancelled', 'Run cancelled while recording native startup');
  }).catch(async error => {
    if (child && child.exitCode === null && child.signalCode === null) {
      let signalled = false; const deadline = performance.now() + 5000;
      while (child.exitCode === null && child.signalCode === null && performance.now() < deadline) {
        if (!signalled) {
          const actual = await inspectMaster(path.join(prefix, 'bin/nginx'), life.prefix, identity || null, false).catch(() => null);
          if (actual?.pid === child.pid) { identity = actual; process.kill(actual.pid, 'SIGQUIT'); signalled = true; }
        }
        await delay(20);
      }
      if (child.exitCode === null && child.signalCode === null) error.message += '; native cleanup remains unresolved: inspect exact owned master, no forced kill sent';
    }
    if (child) {
      life.runtime = identity || life.runtime;
      life.lastExit = { code: child.exitCode, signal: child.signalCode };
      life.stage = child.exitCode === 0 && child.signalCode === null && identity && !(await remainingNativeGroup(path.join(prefix, 'bin/nginx'), identity)).length ? 'stopped' : 'faulted';
      await lock(prefix, () => saveRecord(path.join(life.prefix, 'lifecycle.json'), life)).catch(cleanup => { error.message += `; lifecycle preservation failed: ${cleanup.message}`; });
    }
    throw error;
  });
  process.stdout.write(encode({ ok: true, outcome: 'running', prefix, session: life.session, sessionPrefix: life.prefix, pid: identity.pid, controlSocket: life.controlSocket, applicationHealthChecked: false }));
  const exited = child.exitCode !== null || child.signalCode !== null ? { code: child.exitCode, signal: child.signalCode } : await new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  const finalDeadline = performance.now() + 6500;
  while (true) {
    try {
      await lock(prefix, async () => {
        const current = await lifecycle(context, life.session);
        const normal = exited.code === 0 && exited.signal === null;
        if (normal) await stopped(context, current);
        current.stage = normal ? 'stopped' : 'faulted'; current.lastExit = exited; await saveRecord(path.join(current.prefix, 'lifecycle.json'), current);
      });
      break;
    } catch (error) { if (error.code !== 'alpha_locked' || performance.now() >= finalDeadline) throw error; await delay(50); }
  }
  return { ok: exited.code === 0 && exited.signal === null, outcome: 'native_exited', session: life.session, ...exited };
  } finally { process.removeListener('SIGINT', forward); process.removeListener('SIGTERM', forward); }
}

async function stop(context) {
  const life = await lifecycle(context);
  if (life.stage === 'faulted') fail('abnormal_exit', 'Abnormal native exit preserved; inspect remaining processes and session data manually');
  if (!life.runtime) { await stopped(context, life); return { ok: true, outcome: 'not_started', session: life.session }; }
  const { result } = await sessionStatus(context, life, false), binary = path.join(context.prefix, 'bin/nginx');
  const actual = await inspectMaster(binary, life.prefix, life.runtime);
  if (!actual && !['stopped', 'prepared'].includes(life.stage)) fail('unresolved_exit', 'Wait for the foreground launcher to record native exit; unknown exit is not confirmed stopped');
  if (actual) {
    if (result.binding && !same(result.binding, binding(actual))) fail('runtime_identity', 'Bound and owned master disagree');
    life.stage = 'stopping'; await saveRecord(path.join(life.prefix, 'lifecycle.json'), life);
    // No pidfd_send_signal is available in Node: the verified-to-kill race remains documented.
    const checked = await inspectMaster(binary, life.prefix, life.runtime); if (checked) process.kill(checked.pid, 'SIGQUIT');
    const deadline = performance.now() + 5000;
    while (performance.now() < deadline) { if (!await inspectMaster(binary, life.prefix, life.runtime, false)) break; await delay(25); }
    if (await inspectMaster(binary, life.prefix, life.runtime, false)) fail('stop_pending', 'Graceful stop is still draining; no forced kill was sent');
  }
  await stopped(context, life); life.stage = 'stopped'; await saveRecord(path.join(life.prefix, 'lifecycle.json'), life);
  return { ok: true, outcome: actual ? 'stopped' : 'already_stopped', session: life.session, signal: actual ? 'SIGQUIT' : null, dependencyDrift: context.dependencyDrift };
}

async function inventory(prefix) {
  const entries = [], stack = [''];
  while (stack.length) {
    const relative = stack.pop(), directory = path.join(prefix, relative); await owned(directory, true, true);
    for (const name of await readdir(directory)) {
      if (entries.length > 4096) fail('inventory_limit', 'Installation inventory exceeds supported bound');
      const child = path.posix.join(relative, name), stat = await lstat(path.join(prefix, child));
      if (stat.isSymbolicLink() || stat.uid !== process.getuid()) fail('unsafe_path', `Unowned/symlink entry preserved: ${child}`);
      entries.push({ relative: child, stat }); if (stat.isDirectory()) stack.push(child);
    }
  }
  return entries;
}
async function uninstall(context, moved) {
  const knownFiles = new Set([...Object.keys(context.manifest.immutable), '.alpha-install.json', '.alpha-registry.json', '.alpha-lock']);
  const knownDirs = new Set([...staticDirectories, ...(context.manifest.schemaVersion === 2 ? ['lib/service'] : [])]);
  for (const session of context.registry.sessions) {
    const life = await lifecycle(context, session); await stopped(context, life); const state = await sessionStatus(context, life);
    const history = await state.control.history(state.state), references = new Set();
    const collect = value => { if (typeof value === 'string' && /^[a-f0-9]{32}$/.test(value)) references.add(value); else if (value && typeof value === 'object') for (const item of Object.values(value)) collect(item); };
    collect(history.records); collect(state.result.lastConfirmedRevision);
    const base = `runs/${session}`;
    for (const suffix of ['', '/logs', '/temp', '/temp/client', '/temp/proxy', '/temp/fastcgi', '/temp/uwsgi', '/temp/scgi', '/.x10-control', '/.x10-control/revisions']) knownDirs.add(base + suffix);
    for (const suffix of ['nginx.conf', 'managed.conf', 'nginx.pid', 'lifecycle.json', 'logs/error.log', '.x10-control/settings.json', '.x10-control/state.json', '.x10-control/history.jsonl']) knownFiles.add(`${base}/${suffix}`);
    for (const name of await readdir(path.join(life.prefix, '.x10-control/revisions'))) {
      const key = /^([a-f0-9]{32})\.json$/.exec(name)?.[1]; if (!key || !references.has(key)) fail('operator_data_preserved', 'Orphan or unknown revision files require operator inspection');
      const revision = await load(path.join(life.prefix, '.x10-control/revisions', name)), { recordSha256, ...body } = revision;
      if (digest(JSON.stringify(body)) !== recordSha256) fail('alpha_integrity', 'Revision integrity failed');
      knownFiles.add(`${base}/.x10-control/revisions/${name}`);
    }
    if (life.controlSocket) {
      if (path.dirname(life.controlSocket) !== context.prefix) fail('alpha_integrity', 'Recorded control socket escaped installation');
      knownFiles.add(path.basename(life.controlSocket));
    }
  }
  for (const entry of await inventory(context.prefix)) {
    if (entry.stat.isDirectory() ? !knownDirs.has(entry.relative) : !knownFiles.has(entry.relative)) fail('operator_data_preserved', `Unrecognized data preserved: ${entry.relative}`);
    if (!entry.stat.isDirectory() && !entry.stat.isFile() && !entry.stat.isSocket()) fail('operator_data_preserved', `Special file preserved: ${entry.relative}`);
  }
  const quarantine = `${context.prefix}.uninstall-${id()}`; await mkdir(quarantine, { mode: 0o700 });
  await rename(context.prefix, quarantine); moved();
  const stat = await owned(quarantine, true, true);
  if (!same(context.manifest.rootIdentity, { dev: stat.dev, ino: stat.ino, uid: stat.uid })) fail('alpha_integrity', `Quarantine identity changed; preserved: ${quarantine}`);
  await rm(quarantine, { recursive: true }); return { ok: true, outcome: 'uninstalled', prefix: context.prefix, dependencyDrift: context.dependencyDrift };
}

// Startup waiting only: each observation releases the alpha lock so run can
// finish startup. Once bind begins it is awaited exactly once, never raced or retried.
export async function waitBind(prefix, timeoutMs = 10000) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000)
    fail('invalid_wait_timeout', 'wait-bind timeout must be a canonical decimal 1..30000 milliseconds');
  const deadline = performance.now() + timeoutMs, initial = await installed(prefix);
  const initialLife = await lifecycle(initial);
  if (!['prepared', 'running'].includes(initialLife.stage)) fail('wait_bind_state', 'wait-bind requires a prepared or running session; inspect stopped/faulted state');
  let cancelled = false, bindingAttempted = false;
  const cancel = () => { cancelled = true; };
  const refused = (code, bindingMayHaveCommitted = false) => ({ ok: false, code, outcome: 'wait_bind_refused', bindingMayHaveCommitted,
    error: bindingMayHaveCommitted ? 'Binding was attempted; inspect the same session and do not retry blindly' : 'Startup wait ended before binding was attempted' });
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    process.stderr.write('wait-bind: waiting for native startup\n');
    while (true) {
      if (cancelled) return refused('wait_bind_cancelled');
      if (performance.now() >= deadline) return refused('wait_bind_timeout');
      let result;
      try {
        // Observing a prepared session must not repeatedly steal run's startup
        // lock. Records are atomic; the locked running path revalidates everything.
        const observation = await installed(prefix), observedLife = await lifecycle(observation);
        if (!same(observation.registry, initial.registry) || !same(observation.manifest, initial.manifest))
          fail('wait_bind_changed', 'Installation or session registry changed during startup wait');
        if (!['prepared', 'running'].includes(observedLife.stage))
          fail('wait_bind_state', 'Startup session stopped or faulted; inspection is required');
        if (observedLife.stage === 'prepared' && observedLife.runtime !== null)
          fail('runtime_identity', 'Prepared session has unexpected native identity');
        if (observedLife.stage === 'running') result = await lock(prefix, async () => {
          if (cancelled) return refused('wait_bind_cancelled');
          const context = await installed(prefix);
          if (!same(context.registry, initial.registry) || !same(context.manifest, initial.manifest))
            fail('wait_bind_changed', 'Installation or session registry changed during startup wait');
          const life = await lifecycle(context);
          if (!['prepared', 'running'].includes(life.stage)) fail('wait_bind_state', 'Startup session stopped or faulted; inspection is required');
          if (life.stage === 'prepared') {
            if (life.runtime !== null) fail('runtime_identity', 'Prepared session has unexpected native identity');
            return null;
          }
          if (!life.runtime || !await inspectMaster(path.join(prefix, 'bin/nginx'), life.prefix, life.runtime))
            fail('runtime_identity', 'Running session lacks its exact recorded native master');
          const { control, state } = await sessionStatus(context, life);
          const settings = await load(path.join(state, 'settings.json'));
          // Alpha creates a 3000 ms readiness gate. Changed gate budgets require
          // separate acceptance rather than silently extending this helper's budget.
          if (settings.gateTimeoutMs !== 3000) fail('wait_bind_settings', 'Unsupported readiness gate budget');
          if (cancelled) return refused('wait_bind_cancelled');
          if (deadline - performance.now() < 4000) return refused('wait_bind_timeout');
          let bound;
          try { bindingAttempted = true; bound = await control.bind(state); }
          catch (error) {
            if (cancelled) return refused('wait_bind_cancelled', true);
            error.bindingMayHaveCommitted = true; throw error;
          }
          // A cancellation or cooperative deadline cannot undo durable bind.
          // Keep the result explicit and wait for completion; never leave a late task.
          if (cancelled) return refused('wait_bind_cancelled', true);
          if (performance.now() >= deadline) return refused('wait_bind_late', true);
          return { ...bound, outcome: 'wait_bound', session: life.session, bindingMayHaveCommitted: true };
        });
      } catch (error) {
        if (bindingAttempted) { error.bindingMayHaveCommitted = true; throw error; }
        if (error.code !== 'alpha_locked') throw error;
      }
      if (result) {
        if (result.ok && cancelled) return refused('wait_bind_cancelled', true);
        if (result.ok && performance.now() >= deadline) return refused('wait_bind_late', true);
        return result;
      }
      if (cancelled) return refused('wait_bind_cancelled');
      await delay(Math.max(0, Math.min(50, deadline - performance.now())));
    }
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}

async function proxy(context, command, values) {
  const life = await lifecycle(context), args = [path.join(context.prefix, 'lib/control/cli.mjs'), command, '--state', await controllerState(context.prefix, life.session)];
  for (const flag of ['file', 'revision', 'control-socket', 'control-address']) if (values[flag]) args.push(`--${flag}`, values[flag]);
  if (values.human) args.push('--human');
  const result = await execute(process.execPath, args, { timeout: 70000, maxBuffer: 2 * 1024 * 1024 }).catch(error => {
    if (error.stdout) { process.stdout.write(error.stdout); if (error.stderr) process.stderr.write(error.stderr); error.forwarded = true; } throw error;
  });
  process.stdout.write(result.stdout); if (result.stderr) process.stderr.write(result.stderr); return null;
}

export async function main(argv, installedPrefix = null) {
  const oldMask = process.umask(0o077);
  try {
    const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: Object.fromEntries([
      ...['prefix', 'port', 'health-port', 'upstream-port', 'manifest', 'binary', 'output', 'file', 'revision', 'control-socket', 'control-address', 'timeout-ms', 'restore'].map(name => [name, { type: 'string' }]),
      ['auto-readiness', { type: 'boolean' }], ['human', { type: 'boolean' }], ['help', { type: 'boolean', short: 'h' }],
    ]) });
    const [command] = positionals;
    if (command === 'service-unit' && (argv[0] !== 'service-unit' || ![1, 2].includes(argv.length)
        || (argv.length === 2 && argv[1] !== '--auto-readiness')))
      fail('arguments', 'Use service-unit [--auto-readiness]');
    if (command === 'backup' && (argv.length !== 3 || argv[0] !== 'backup' || argv[1] !== '--output' || values.output !== argv[2]))
      fail('arguments', 'Use backup --output NEW_ABSOLUTE_FILE');
    if (values.restore !== undefined) {
      const flags = argv.filter(value => value.startsWith('--')).map(value => value.split('=')[0]);
      if (command !== 'install' || positionals.length !== 1 || values.help || new Set(flags).size !== flags.length
          || ['port', 'health-port', 'upstream-port'].some(key => values[key] !== undefined))
        fail('arguments', 'Use install --prefix NEW_ABSOLUTE --restore BACKUP_FILE with no repeated options');
    }
    if (values.help) { process.stdout.write('Source: node x10/alpha/cli.mjs install --prefix NEW_ABSOLUTE --port 9080 --health-port 9081 [--upstream-port PORT] [--manifest FILE]\nRestore: node x10/alpha/cli.mjs install --prefix NEW_ABSOLUTE --restore BACKUP_FILE [--manifest FILE]\nBundle: node x10/alpha/cli.mjs pack --output FILE.tar.gz [--manifest FILE]\nInstalled: bin/x10 backup --output NEW_ABSOLUTE_FILE | service-unit [--auto-readiness] | prepare-run | run [--control-socket PRIVATE_ABSOLUTE] | bind | wait-bind [--timeout-ms 1..30000] | status [--human] | info | apply --file JSON | revert --revision ID | history | recover | inspect-generations --control-socket PRIVATE_ABSOLUTE | stop | uninstall\n'); return; }
    if (positionals.length !== 1) fail('arguments', 'Exactly one command is required; use --help');
    const allowed = { install: ['prefix', 'port', 'health-port', 'upstream-port', 'manifest', 'binary', 'restore'], pack: ['output', 'manifest', 'binary'], backup: ['output'], run: ['control-socket'], 'service-unit': ['auto-readiness'], 'prepare-run': [], 'wait-bind': ['timeout-ms'], status: ['human'], apply: ['file'], revert: ['revision'], 'inspect-generations': ['control-socket', 'control-address'], 'snapshot-listeners': [], 'inspect-listeners': ['file'], bind: [], info: [], history: [], recover: [], stop: [], uninstall: [] };
    if (!allowed[command] || Object.keys(values).some(key => !allowed[command].includes(key))) fail('arguments', 'Unsupported command or option for this command');
    let waitTimeout = 10000;
    if (command === 'wait-bind' && values['timeout-ms'] !== undefined) {
      if (!/^[1-9][0-9]{0,4}$/.test(values['timeout-ms']) || Number(values['timeout-ms']) > 30000)
        fail('invalid_wait_timeout', 'wait-bind timeout must be a canonical decimal 1..30000 milliseconds');
      waitTimeout = Number(values['timeout-ms']);
    }
    let result;
    if (command === 'install' || command === 'pack') { if (installedPrefix) fail('arguments', 'Use the source checkout or extracted bundle for installation'); result = command === 'install' ? await install(values) : await pack(values); }
    else {
      if (!installedPrefix) fail('arguments', 'Use the installed PREFIX/bin/x10 launcher for lifecycle commands');
      const prefix = path.resolve(installedPrefix), allowDrift = ['stop', 'uninstall', 'info', 'status', 'history'].includes(command); const inspected = await installed(prefix, allowDrift);
      if (command === 'service-unit') result = await serviceUnit(inspected, values['auto-readiness'] === true);
      else if (command === 'run') result = await run(prefix, values);
      else if (command === 'wait-bind') result = await waitBind(prefix, waitTimeout);
      else result = await lock(prefix, async moved => {
        const context = await installed(prefix, allowDrift);
        if (context.dependencyDrift.length) process.stderr.write('Recorded host libraries changed; only inspection, stop and uninstall remain available.\n');
        if (command === 'prepare-run') {
          const life = await prepareRun(context);
          if (life.stage !== 'prepared' || life.runtime !== null || life.controlSocket !== null)
            fail('runtime_identity', 'Prepared startup session has unexpected runtime state');
          return { ok: true, outcome: 'run_prepared', session: life.session, nativeStarted: false, readinessChecked: false };
        }
        if (command === 'stop') return stop(context);
        if (command === 'uninstall') return uninstall(context, moved);
        if (command === 'backup') return backup(context, values.output);
        if (command === 'info') { const life = await lifecycle(context); return { ok: true, prefix, session: life.session, sessionPrefix: life.prefix, stage: life.stage, port: context.manifest.port, healthPort: context.manifest.healthPort, controlSocket: life.controlSocket, nginxVersion: context.manifest.nginxVersion, moduleCount: context.manifest.compiledModules.length, healthNote: context.manifest.healthNote }; }
        if (!['bind', 'status', 'apply', 'revert', 'history', 'recover', 'inspect-generations', 'snapshot-listeners', 'inspect-listeners'].includes(command)) fail('arguments', 'Unknown alpha command');
        return proxy(context, command, values);
      });
    }
    if (result) { process.stdout.write(encode(result)); if (!result.ok) process.exitCode = 1; }
  } catch (error) {
    const sensitive = argv[0] === 'backup' || argv.some(value => value === '--restore' || value.startsWith('--restore='));
    if (sensitive) process.stdout.write(encode({ ok: false, code: /^[A-Za-z0-9_]{1,64}$/.test(error.code || '') ? error.code : 'backup_restore_refused',
      error: 'Declarative backup or restore refused; preserve any created files for operator inspection' }));
    else if (!error.forwarded) process.stdout.write(encode({ ok: false, code: error.code || 'error', error: error.message, ...(error.bindingMayHaveCommitted === true ? { bindingMayHaveCommitted: true } : {}) }));
    process.exitCode = 1;
  }
  finally { process.umask(oldMask); }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) await main(process.argv.slice(2));
