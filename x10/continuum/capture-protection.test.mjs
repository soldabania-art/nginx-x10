// Public synthetic production-TU controls, not actual TLS or migration evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildOpenSSL } from './openssl-build.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function command(executable, args, signal, timeout = 30000) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(Error('capture protection cancelled')); return; }
    let child, timer, escalation, size = 0, stderrBytes = 0, output = '', failure = false;
    const stop = () => {
      if (failure) return;
      failure = true;
      if (child?.pid) {
        try { process.kill(-child.pid, 'SIGTERM'); } catch { /* absent */ }
        escalation ??= setTimeout(() => {
          try { process.kill(-child.pid, 'SIGKILL'); } catch { /* absent */ }
        }, 250);
      }
    };
    try {
      child = spawn(executable, args, { detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH || '/usr/bin:/bin',
          LANG: 'C', LC_ALL: 'C', TZ: 'UTC', OPENSSL_CONF: '/dev/null',
          ASAN_OPTIONS: 'detect_leaks=0:abort_on_error=1',
          UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=0' },
      });
    } catch { reject(Error('capture protection child unavailable')); return; }
    timer = setTimeout(stop, timeout);
    signal.addEventListener('abort', stop, { once: true });
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > 65536) stop(); else output += chunk.toString('utf8');
    });
    child.stderr.on('data', chunk => {
      size += chunk.length; stderrBytes += chunk.length;
      if (size > 65536) stop();
    });
    child.once('error', stop);
    child.once('close', (code, terminationSignal) => {
      clearTimeout(timer); clearTimeout(escalation);
      signal.removeEventListener('abort', stop);
      if (failure || code !== 0 || terminationSignal !== null || stderrBytes !== 0)
        reject(Error('capture protection child failed'));
      else resolve(output);
    });
    if (signal.aborted) stop();
  });
}

export async function checkCaptureProtection() {
  let build, root;
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once('SIGTERM', interrupt); process.once('SIGINT', interrupt);
  try {
    build = await buildOpenSSL({ signal: cancellation.signal });
    await build.verifyIdentity();
    root = await mkdtemp(join(HERE, '../.build/capture-protection-'));
    const p = build.privatePaths;
    const sources = ['openssl-capture.c', 'openssl-capture.h', 'capture-protection-test.c'];
    const before = await Promise.all(sources.map(name => readFile(join(HERE, name))));
    const binary = join(root, 'controls');
    const common = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
      ...[p.includeDir, p.sourceIncludeDir, p.sourceDir, p.buildDir, HERE]
        .flatMap(path => ['-I', path]),
      join(HERE, 'capture-protection-test.c')];
    const libraries = [p.libssl, p.libcrypto, '-pthread', '-ldl'];
    await command(p.compiler, [...common, '-O2', '-o', binary, ...libraries],
      cancellation.signal, 60000);
    const result = JSON.parse(await command(binary, [], cancellation.signal));
    const sanitized = join(root, 'controls-sanitized');
    await command(p.compiler, [...common, '-O1', '-g', '-fsanitize=address,undefined',
      '-fno-omit-frame-pointer', '-o', sanitized, ...libraries],
    cancellation.signal, 60000);
    const instrumented = JSON.parse(await command(sanitized, [], cancellation.signal));
    assert.deepEqual(instrumented, result);
    for (let i = 0; i < sources.length; i++)
      assert.equal((await readFile(join(HERE, sources[i]))).equals(before[i]), true,
        'capture protection source changed during check');
    await build.verifyIdentity();
    assert.equal(result.passed, true);
    assert.equal(result.scenarios, 18);
    assert.equal(result.actualTLS, false);
    assert.equal(result.syntheticDataOnly, true);
    assert.equal(result.productionTranslationUnit, true);
    assert.equal(result.wholePageCleanse, true);
    assert.equal(result.protectionFlags, true);
    assert.equal(result.guardAndForkControls, 4);
    assert.equal(result.stickyFailure, true);
    assert.equal(result.failedMappingRecovery, true);
    assert.equal(result.unownedMappings, 0);
    return { ...result, sanitizer: { address: true, undefined: true,
      scenarios: result.scenarios, passed: true, leakDetection: false,
      dependencyLibrariesInstrumented: false } };
  } finally {
    try {
      if (root) await rm(root, { recursive: true, force: true });
      await build?.cleanup();
    } finally {
      process.removeListener('SIGTERM', interrupt);
      process.removeListener('SIGINT', interrupt);
    }
  }
}
