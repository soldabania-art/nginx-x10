// Research build only. Private paths/logs never belong in public evidence.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const OPENSSL_COMMIT = '85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c';
const OPENSSL_TREE = '4e48caeae2374ee4982c8e44b6a15cf4753229cb';
const REPOSITORY = 'https://github.com/openssl/openssl.git';
const HERE = dirname(fileURLToPath(import.meta.url));
const BUILD_PARENT = resolve(HERE, '../.build');
const MAX_OUTPUT = 8 * 1024 * 1024;
const BUILD_BUDGET_MS = 600000;
const FEATURES = Object.freeze([
  'no-shared', 'no-module', 'no-engine', 'no-async', 'no-ktls', 'no-tests',
  'no-legacy', 'no-asm', 'no-comp', 'no-zlib', 'no-dso', 'no-autoload-config', 'no-fips',
]);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = stage => Object.assign(new Error(`OpenSSL research build failed: ${stage}`), { code: `C2A_BUILD_${stage}` });
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const freeze = value => {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};

async function fingerprint(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size === 0 || info.size > 128 * 1024 * 1024) throw fail('artifact_invalid');
  return digest(await readFile(path));
}

async function executable(name) {
  for (const part of (process.env.PATH || '/usr/bin:/bin').split(delimiter)) {
    if (!part.startsWith('/')) continue;
    const candidate = join(part, name);
    try {
      await access(candidate, constants.X_OK);
      const path = await realpath(candidate);
      if ((await stat(path)).isFile()) return path;
    } catch { /* Try the next directory, without exposing a host path. */ }
  }
  throw fail('tool_unavailable');
}

// A detached process owns its subprocess group. Timeout, abort and excess output
// terminate the entire group, then wait for close; no compiler survives make.
function command(exe, args, { cwd, env, signal, deadline, timeout = 60000, stage }) {
  if (signal?.aborted) return Promise.reject(fail('aborted'));
  const remaining = Math.min(timeout, deadline - Date.now());
  if (remaining <= 0) return Promise.reject(fail('deadline'));
  return new Promise((resolveResult, reject) => {
    let child;
    try { child = spawn(exe, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(fail(stage)); return; }
    let fault = null, bytes = 0, ending = null;
    const chunks = [], outHash = createHash('sha256'), errHash = createHash('sha256');
    const kill = sig => {
      if (!child.pid) return;
      try { process.kill(-child.pid, sig); } catch { /* Already absent. */ }
    };
    const stop = reason => {
      if (fault) return;
      fault = reason;
      kill('SIGTERM');
      ending = new Promise(done => setTimeout(() => { kill('SIGKILL'); done(); }, 250));
    };
    const onAbort = () => stop('aborted');
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => stop('deadline'), remaining);
    const consume = (chunk, hash, retain) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT) { stop('output_limit'); return; }
      hash.update(chunk);
      if (retain) chunks.push(chunk);
    };
    child.stdout.on('data', chunk => consume(chunk, outHash, true));
    child.stderr.on('data', chunk => consume(chunk, errHash, false));
    child.on('error', () => stop(stage));
    child.on('close', async code => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (ending) await ending;
      if (fault || code !== 0) { kill('SIGKILL'); reject(fail(fault || stage)); return; }
      resolveResult({ stdout: Buffer.concat(chunks), stdoutSha256: outHash.digest('hex'), stderrSha256: errHash.digest('hex') });
    });
    // The signal may have been aborted between the initial check and listener.
    if (signal?.aborted) onAbort();
  });
}

/**
 * Fresh isolated pinned build, stable until cleanup(). There is no persistent
 * cache or installed-library fallback. A caller caching this object must await
 * verifyIdentity() before each use. Only identity is safe to publish.
 */
export async function buildOpenSSL({ signal, patchPath = join(HERE, 'openssl-probe.patch') } = {}) {
  if (process.platform !== 'linux' || process.arch !== 'x64') throw fail('unsupported_platform');
  const deadline = Date.now() + BUILD_BUDGET_MS;
  let root = null;
  try {
    const patchInfo = await stat(patchPath);
    if (!patchInfo.isFile() || patchInfo.size === 0 || patchInfo.size > 1024 * 1024) throw fail('patch_invalid');
    const patch = await readFile(patchPath);
    if (!patch.length || patch.length > 1024 * 1024 || patch.includes(0)) throw fail('patch_invalid');
    const patchSha256 = digest(patch);
    const names = ['git', 'perl', 'make', 'cc'];
    const paths = await Promise.all(names.map(executable));
    const tools = Object.fromEntries(names.map((name, i) => [name, paths[i]]));
    await mkdir(BUILD_PARENT, { recursive: true });
    root = await mkdtemp(join(BUILD_PARENT, 'continuum-openssl-'));
    const sourceDir = join(root, 'source'), buildDir = join(root, 'build');
    const savedPatch = join(root, 'instrumentation.patch');
    await Promise.all([mkdir(sourceDir), mkdir(buildDir), mkdir(join(root, 'no-modules'))]);
    await writeFile(savedPatch, patch, { mode: 0o600 });
    const env = {
      PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/false',
      OPENSSL_CONF: '/dev/null', OPENSSL_MODULES: join(root, 'no-modules'),
    };
    // Managed environments may require a network proxy/CA. Preserve only the
    // transport settings, never print their values or copy general secrets.
    for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
      'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'GIT_SSL_CAINFO']) {
      if (process.env[name]) env[name] = process.env[name];
    }
    const run = (exe, args, stage, cwd = sourceDir, timeout = 60000) =>
      command(exe, args, { cwd, env, signal, deadline, timeout, stage });
    const git = (args, stage = 'source_identity') => run(tools.git, args, stage);
    const text = result => result.stdout.toString('utf8').trim();
    await git(['init', '--quiet'], 'source_init');
    await git(['-c', 'credential.helper=', 'fetch', '--no-tags', '--depth=1', REPOSITORY, OPENSSL_COMMIT], 'source_fetch');
    await git(['-c', 'advice.detachedHead=false', 'checkout', '--detach', OPENSSL_COMMIT], 'source_checkout');
    const before = text(await git(['rev-parse', 'HEAD', 'HEAD^{tree}'])).split('\n');
    if (!equal(before, [OPENSSL_COMMIT, OPENSSL_TREE])) throw fail('source_identity');
    if ((await git(['status', '--porcelain=v1', '-z', '--untracked-files=all'])).stdout.length) throw fail('source_dirty');
    if ((await git(['ls-files', '--others', '-z'])).stdout.length) throw fail('source_dirty');
    const sourceEpoch = text(await git(['show', '-s', '--format=%ct', 'HEAD']));
    if (!/^\d{10}$/.test(sourceEpoch)) throw fail('source_epoch');
    env.SOURCE_DATE_EPOCH = sourceEpoch;
    await git(['apply', '--check', '--index', savedPatch], 'patch_check');
    await git(['apply', '--index', savedPatch], 'patch_apply');
    const patchedTree = text(await git(['write-tree']));
    if (!/^[0-9a-f]{40}$/.test(patchedTree) || patchedTree === OPENSSL_TREE) throw fail('patch_identity');
    const compilerVersion = text(await run(tools.cc, ['-dumpfullversion', '-dumpversion'], 'compiler_identity', buildDir));
    const compilerTarget = text(await run(tools.cc, ['-dumpmachine'], 'compiler_identity', buildDir));
    if (!/^[0-9.]{1,40}$/.test(compilerVersion) || !/^[A-Za-z0-9_.+-]{1,100}$/.test(compilerTarget)) throw fail('compiler_identity');
    const configureArgs = [
      join(sourceDir, 'Configure'), 'linux-x86_64', ...FEATURES,
      '--prefix=/continuum-research', '--openssldir=/continuum-research/config',
      `CC=${tools.cc}`, '-O2', '-fno-omit-frame-pointer', '-fno-ident',
      `-ffile-prefix-map=${root}=/continuum-build`,
    ];
    await run(tools.perl, configureArgs, 'configure', buildDir);
    const configCommand = ['-I.', '-Mconfigdata', '-MJSON::PP', '-e',
      'print encode_json({target=>$configdata::config{target},disabled=>[sort keys %configdata::disabled]})'];
    const configuration = JSON.parse(text(await run(tools.perl, configCommand, 'configuration_identity', buildDir)));
    if (configuration.target !== 'linux-x86_64' || !Array.isArray(configuration.disabled)
      || FEATURES.some(flag => !configuration.disabled.includes(flag.slice(3)))
      || configuration.disabled.some(value => typeof value !== 'string' || !/^[a-z0-9+_-]{1,60}$/.test(value))) throw fail('configuration_identity');
    await run(tools.make, ['-j2', 'build_sw'], 'compile', buildDir, BUILD_BUDGET_MS);
    const privatePaths = {
      root, sourceDir, buildDir, includeDir: join(buildDir, 'include'), sourceIncludeDir: join(sourceDir, 'include'),
      libssl: join(buildDir, 'libssl.a'), libcrypto: join(buildDir, 'libcrypto.a'),
      openssl: join(buildDir, 'apps/openssl'), compiler: tools.cc,
    };
    const files = {
      libssl: privatePaths.libssl, libcrypto: privatePaths.libcrypto, openssl: privatePaths.openssl,
      configData: join(buildDir, 'configdata.pm'), makefile: join(buildDir, 'Makefile'),
      configurationHeader: join(buildDir, 'include/openssl/configuration.h'), license: join(sourceDir, 'LICENSE.txt'),
    };
    const hashes = Object.fromEntries(await Promise.all(Object.entries(files).map(async ([name, path]) => [name, await fingerprint(path)])));
    const toolHashes = Object.fromEntries(await Promise.all(Object.entries(tools).map(async ([name, path]) => [name, await fingerprint(path)])));
    const version = text(await run(privatePaths.openssl, ['version'], 'binary_identity', buildDir));
    if (version !== 'OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)'
      && version !== 'OpenSSL 3.0.13 30 Jan 2024') throw fail('binary_identity');
    const providers = text(await run(privatePaths.openssl, ['list', '-providers'], 'provider_identity', buildDir));
    if (!/^Providers:\s+default\s+name: OpenSSL Default Provider\s+version: 3\.0\.13\s+status: active\s*$/.test(providers)) throw fail('provider_identity');
    const identity = freeze({
      schemaVersion: 1, suite: 'continuum-openssl-pinned-build',
      source: { repository: REPOSITORY, commit: OPENSSL_COMMIT, tree: OPENSSL_TREE, patchedTree, licenseSha256: hashes.license },
      patch: { sha256: patchSha256 },
      compiler: { command: 'cc', version: compilerVersion, target: compilerTarget, binarySha256: toolHashes.cc },
      tools: { gitSha256: toolHashes.git, perlSha256: toolHashes.perl, makeSha256: toolHashes.make },
      configuration: {
        target: configuration.target, flags: [...FEATURES, '--prefix=/continuum-research', '--openssldir=/continuum-research/config',
          'CC={compiler}', '-O2', '-fno-omit-frame-pointer', '-fno-ident', '-ffile-prefix-map={privateRoot}=/continuum-build'],
        disabled: configuration.disabled, sourceDateEpoch: sourceEpoch,
        configDataSha256: hashes.configData, makefileSha256: hashes.makefile, configurationHeaderSha256: hashes.configurationHeader,
      },
      provider: { active: ['default'], externalModules: false, autoloadConfiguration: false },
      artifacts: { linkage: 'static-libssl-and-libcrypto', systemRuntimeStatic: false, version,
        libsslSha256: hashes.libssl, libcryptoSha256: hashes.libcrypto, opensslSha256: hashes.openssl },
    });
    let cleaned = false, cleanupPromise;
    const cleanup = async () => {
      if (!cleanupPromise) cleanupPromise = rm(root, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 })
        .then(() => { cleaned = true; }).catch(() => { cleanupPromise = undefined; throw fail('cleanup'); });
      await cleanupPromise;
    };
    const verifyIdentity = async ({ signal: verificationSignal = signal } = {}) => {
      try {
      if (cleaned || signal?.aborted || verificationSignal?.aborted) throw fail('identity_unavailable');
      const verificationDeadline = Date.now() + 30000;
      const combinedSignal = signal && verificationSignal && signal !== verificationSignal
        ? AbortSignal.any([signal, verificationSignal]) : verificationSignal;
      const verifyGit = args => command(tools.git, args, {
        cwd: sourceDir, env, signal: combinedSignal, deadline: verificationDeadline, timeout: 30000, stage: 'source_changed',
      });
      if (digest(await readFile(patchPath)) !== patchSha256 || await fingerprint(savedPatch) !== patchSha256) throw fail('patch_changed');
      const now = text(await verifyGit(['rev-parse', 'HEAD', 'HEAD^{tree}'])).split('\n');
      if (!equal(now, before) || text(await verifyGit(['write-tree'])) !== patchedTree) throw fail('source_changed');
      await verifyGit(['diff', '--exit-code', '--']);
      if ((await verifyGit(['ls-files', '--others', '-z'])).stdout.length) throw fail('source_changed');
      const freshHashes = Object.fromEntries(await Promise.all(Object.entries(files).map(async ([name, path]) => [name, await fingerprint(path)])));
      const freshTools = Object.fromEntries(await Promise.all(Object.entries(tools).map(async ([name, path]) => [name, await fingerprint(path)])));
      if (!equal(freshHashes, hashes) || !equal(freshTools, toolHashes)) throw fail('artifact_changed');
      return identity;
      } catch (error) {
        if (error?.code?.startsWith('C2A_BUILD_')) throw error;
        throw fail('identity_unavailable');
      }
    };
    await verifyIdentity();
    return { privatePaths: Object.freeze(privatePaths), identity, verifyIdentity, cleanup };
  } catch (error) {
    if (root) await rm(root, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 }).catch(() => {});
    if (error?.code?.startsWith('C2A_BUILD_')) throw error;
    throw fail(signal?.aborted ? 'aborted' : 'unavailable');
  }
}
