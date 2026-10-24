import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateReleaseRecord, MAX_RECORD_BYTES } from './check-release-record.mjs';

// Invented unit-only identities and URLs. No artifact exists or is fetched.
function record(stage = 'alpha') {
  const commit = '1'.repeat(40), hash = '2'.repeat(64);
  const kinds = ['authority', 'contract', 'alpha-install', 'service', 'rollback', 'security', 'soak', 'distribution', 'independent'];
  const version = { alpha: '0.1.0-alpha.1', candidate: '0.1.0-rc.1', v1: '1.0.0' }[stage];
  return {
    schemaVersion: 1, kind: 'x10-release-record', stage, version,
    profile: 'ubuntu-24.04-x86_64-node22-v1',
    source: { repository: 'soldabania-art/nginx-x10', commit,
      upstreamCommit: '148c75678cd4171338c31d4ed4c02411736d5fe9', nativeDiffSha256: hash, tree: '5'.repeat(40) },
    build: { eventHead: commit, checkoutCommit: commit, prMergeCommit: null,
      binarySha256: hash, manifestSha256: hash, configurationSha256: hash,
      ci: [{ workflow: 'X10 native compatibility', runId: 1, jobId: 2, attempt: 1, eventHead: commit, checkoutCommit: commit, conclusion: 'success',
        executedSteps: ['Validate release-record contract and refusal controls', 'Compile native profile', 'Native regressions and pinned official compatibility sample',
          'Verify private Unix control transport', 'Build profile without control API', 'Package local Linux alpha',
          'Checksum local Linux alpha'].map(name => ({ name, conclusion: 'success' })) }],
      nodeVersion: '22.0.0', nodeExecutableSha256: hash, os: 'ubuntu', osVersion: '24.04', arch: 'x86_64',
      dependencies: Object.fromEntries(['glibc', 'pcre2', 'openssl', 'zlib', 'libcrypt'].map(k => [k, { version: 'synthetic-unit-only', sha256: hash }])) },
    artifact: { url: `https://github.com/soldabania-art/nginx-x10/releases/download/v${version}/synthetic-unit-only.tar.gz`,
      archiveSha256: hash, payloadManifestSha256: hash, checksumAlgorithm: 'SHA256', checksumIsSignature: false,
      permanent: true, expiresAtUTC: null },
    evidence: kinds.map(kind => ({ id: kind, kind, sourceCommit: commit,
      url: `https://github.com/soldabania-art/nginx-x10/blob/${commit}/synthetic-unit-only.json`, sha256: hash,
      outcome: 'passed', skippedAssertions: 25, expectedTodoFailures: 1, unexpectedFailures: 0,
      durationSeconds: kind === 'soak' ? 3600 : 0 })),
    gates: Object.fromEntries(kinds.map((kind, i) => [`G${i}`, {
      status: stage === 'v1' || i < 3 ? 'accepted' : 'pending',
      evidenceIds: stage === 'v1' || i < 3 ? [kind] : [] }]))
  };
}
const mutate = fn => { const x = record(); fn(x); return x; };
const reject = value => assert.equal(validateReleaseRecord(value).valid, false);

test('synthetic alpha, candidate and v1 declarations pass shape only', () => {
  for (const stage of ['alpha', 'candidate', 'v1']) assert.deepEqual(validateReleaseRecord(record(stage)), { valid: true, errors: [] });
});
test('missing required identity is refused rather than defaulted', () => reject(mutate(x => delete x.source.commit)));
test('unknown schema and keys are refused', () => {
  reject(mutate(x => x.schemaVersion = 2)); reject(mutate(x => x.productionAccepted = true));
  reject(mutate(x => x.source.token = 'synthetic-canary'));
});
test('event head cannot refer to unrelated implementation', () => reject(mutate(x => x.build.eventHead = '3'.repeat(40))));
test('a distinct actual PR merge checkout is allowed with explicit merge identity', () => {
  const x = record(); x.build.prMergeCommit = x.build.checkoutCommit = '3'.repeat(40); x.build.ci[0].checkoutCommit = x.build.checkoutCommit;
  assert.equal(validateReleaseRecord(x).valid, true);
  x.build.prMergeCommit = '4'.repeat(40); reject(x);
});
test('non-PR checkout cannot silently differ from source', () => reject(mutate(x => x.build.checkoutCommit = '3'.repeat(40))));
test('alpha cannot be promoted by setting a single accepted flag', () => reject(mutate(x => x.gates.G8 = { status: 'accepted', evidenceIds: ['independent'] })));
test('v1 declaration requires every mandatory gate', () => { const x = record('v1'); x.gates.G4.status = 'pending'; reject(x); });
test('v1 cannot use expiring CI artifact as permanent distribution', () => {
  const x = record('v1'); x.artifact = { ...x.artifact, permanent: false, expiresAtUTC: '2099-01-01T00:00:00Z',
    url: 'https://github.com/soldabania-art/nginx-x10/actions/runs/123' }; reject(x);
});
test('candidate may document expiring CI artifact with explicit valid date', () => {
  const x = record('candidate'); x.artifact.permanent = false; x.artifact.expiresAtUTC = '2099-01-01T00:00:00Z';
  x.artifact.url = 'https://github.com/soldabania-art/nginx-x10/actions/runs/123';
  assert.equal(validateReleaseRecord(x).valid, true);
  x.artifact.expiresAtUTC = '2099-02-30T00:00:00Z'; reject(x);
});
test('release URL tag and record version must agree', () => reject(mutate(x => x.artifact.url = x.artifact.url.replace('v0.1.0-alpha.1', 'v9.9.9'))));
test('artifact blob identity must match source or actual merge checkout', () => {
  const x = record('candidate'); x.artifact.permanent = false; x.artifact.expiresAtUTC = '2099-01-01T00:00:00Z';
  x.artifact.url = `https://github.com/soldabania-art/nginx-x10/blob/${'4'.repeat(40)}/synthetic.tar.gz`; reject(x);
});
test('checksums cannot declare signature verification', () => reject(mutate(x => x.artifact.checksumIsSignature = true)));
test('accepted gates need existing matching successful evidence', () => {
  reject(mutate(x => x.gates.G2.evidenceIds = ['absent']));
  reject(mutate(x => x.gates.G2.evidenceIds = ['contract']));
  reject(mutate(x => x.evidence.find(y => y.kind === 'alpha-install').outcome = 'not-run'));
});
test('duplicate evidence IDs and source identity mismatch refuse', () => {
  reject(mutate(x => x.evidence[1].id = x.evidence[0].id));
  reject(mutate(x => x.evidence[0].sourceCommit = '4'.repeat(40)));
});
test('explicit skips and expected TODO do not hide unexpected failures', () => {
  const x = record(); assert.equal(validateReleaseRecord(x).valid, true);
  x.evidence[0].unexpectedFailures = 1; reject(x);
});
test('v1 soak evidence cannot claim 59 minutes as 60 minutes', () => { const x = record('v1'); x.evidence.find(y => y.kind === 'soak').durationSeconds = 3599; reject(x); });
test('canonical public URLs cannot carry credentials, query or path traversal', () => {
  reject(mutate(x => x.evidence[0].url += '?token=synthetic-canary'));
  reject(mutate(x => x.evidence[0].url = x.evidence[0].url.replace('/synthetic-unit-only.json', '/../synthetic-unit-only.json')));
});
test('direct API rejects accessors, cycles and nonplain objects without reading a canary', () => {
  let calls = 0; const x = record(); Object.defineProperty(x, 'secret', { enumerable: true, get() { calls++; throw Error('synthetic-canary'); } });
  reject(x); assert.equal(calls, 0); const c = record(); c.cycle = c; reject(c); reject(new Date());
  const hostile = new Proxy({}, { getPrototypeOf() { throw Error('synthetic-canary'); } });
  assert.deepEqual(validateReleaseRecord(hostile), { valid: false, errors: ['record_input'] });
});
test('CLI bounds input and emits fixed diagnostics without payload reflection', () => {
  const dir = mkdtempSync(join(tmpdir(), 'x10-record-unit-'));
  const cli = fileURLToPath(new URL('./check-release-record.mjs', import.meta.url));
  const run = args => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000 });
  try {
    const good = join(dir, 'good.json'); writeFileSync(good, JSON.stringify(record()));
    const ok = run([good]); assert.equal(ok.status, 0); const output = JSON.parse(ok.stdout);
    assert.equal(output.valid, true); assert.equal(output.evidenceAuthenticated, false); assert.equal(output.productionAccepted, false);
    for (const [name, data] of [['invalid.json', '{"synthetic-canary":'], ['big.json', ' '.repeat(MAX_RECORD_BYTES + 1)]]) {
      const path = join(dir, name); writeFileSync(path, data); const result = run([path]);
      assert.equal(result.status, 1); assert.equal(result.stdout.includes('synthetic-canary'), false); assert.equal(result.stderr, '');
    }
    const link = join(dir, 'link.json'); symlinkSync(good, link); assert.equal(run([link]).status, 1);
    assert.equal(run([]).status, 1); assert.equal(run([dir]).status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tree and executed native CI declarations are required and cannot be skipped', () => {
  reject(mutate(x => delete x.source.tree)); reject(mutate(x => delete x.build.ci));
  reject(mutate(x => x.build.ci[0].conclusion = 'skipped'));
  reject(mutate(x => x.build.ci[0].executedSteps[0].conclusion = 'skipped'));
  reject(mutate(x => x.build.ci[0].executedSteps[0].name = 'Metadata scope only'));
  reject(mutate(x => x.build.ci[0].eventHead = '4'.repeat(40)));
});
