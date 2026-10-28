// Synthetic exact-counter controls; no near-limit TLS records are emitted.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, chmod, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const sourceNames = ['openssl-usage.h', 'openssl-probe.h', 'openssl-usage-test.c'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceHashes = async () => Object.fromEntries(await Promise.all(sourceNames.map(async name =>
  [name, sha256(await readFile(join(directory, name)))])));

function command(file, args) {
  const child = spawnSync(file, args, {
    encoding: 'utf8', timeout: 15000, maxBuffer: 65536,
    stdio: ['ignore', 'pipe', 'pipe'], shell: false,
  });
  assert.equal(child.error, undefined, 'synthetic usage command failed');
  assert.equal(child.signal, null, 'synthetic usage command interrupted');
  assert.equal(child.status, 0, 'synthetic usage command unsuccessful');
  assert.equal(child.stderr, '', 'synthetic usage command diagnostics');
  return child.stdout;
}

export async function checkSyntheticUsageBoundaries() {
  // Oracle arithmetic is BigInt; the C candidate instead checks individual
  // bytes. Include each upper byte independently and every uint64 power edge.
  const limit = 1n << 24n;
  const maximum = (1n << 64n) - 1n;
  const values = new Set([0n, 1n, 255n, 256n, limit - 2n, limit - 1n,
    limit, limit + 1n, (1n << 32n) - 1n, 1n << 32n, maximum - 1n, maximum]);
  for (let bit = 0n; bit < 64n; bit += 1n) {
    const edge = 1n << bit;
    for (const offset of [-1n, 0n, 1n]) {
      if (edge + offset <= maximum) values.add(edge + offset);
    }
  }
  const counters = [...values].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  assert.ok(counters.length < 258);
  const before = await sourceHashes();
  const temporary = await mkdtemp(join(tmpdir(), 'x10-c2a-usage-test-'));
  let result;
  try {
    await chmod(temporary, 0o700);
    const binary = join(temporary, 'usage-test');
    command('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-I', directory, join(directory, 'openssl-usage-test.c'), '-o', binary]);
    const rows = command(binary, counters.map(value => value.toString(16).padStart(16, '0')))
      .trimEnd().split('\n');
    assert.equal(rows[0], '0 65536 131072', 'NULL and distinct directional reason bits');
    assert.equal(rows.length, counters.length + 1);
    for (let index = 0; index < counters.length; index += 1) {
      assert.equal(rows[index + 1], counters[index] < limit ? '1' : '0',
        `synthetic counter boundary index ${index}`);
    }
    // A 2^32-truncating predicate and an inclusive cap would disagree with
    // this oracle. These are sensitivity facts, not production defects.
    assert.ok(counters.some(value => value >= limit && (value & 0xffffffffn) < limit));
    assert.ok(counters.some(value => value === limit));
    assert.deepEqual(await sourceHashes(), before, 'usage sources changed during test');
    result = {
      schemaVersion: 1, scope: 'synthetic-counter-predicate-only', passed: true,
      syntheticCounters: counters.length, nullControls: 1,
      directionalReasonConstants: 2, capRecordsPerDirection: '16777216',
      maximumAdmittedNextSequence: '16777215', sourceSha256: before,
      actualNearLimitTLS: false, migration: false,
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  await assert.rejects(stat(temporary), error => error.code === 'ENOENT');
  return { ...result, temporaryRemoved: true };
}
