// Independent structural controls. All identities/evidence below are synthetic;
// a valid declaration is not a released package or authenticated acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, symlinkSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { validateReleaseRecord, MAX_RECORD_BYTES } from './check-release-record.mjs';

const repository = 'https://github.com/soldabania-art/nginx-x10';
const source = '1'.repeat(40), merge = '2'.repeat(40), digest = 'a'.repeat(64);
const kinds = ['authority', 'contract', 'alpha-install', 'service', 'rollback', 'security', 'soak', 'distribution', 'independent'];
function declaration(stage = 'alpha') {
  const version = stage === 'v1' ? '1.0.0' : stage === 'candidate' ? '1.0.0-rc.1' : '0.1.0-alpha.1';
  return {
    schemaVersion: 1, kind: 'x10-release-record', stage, version,
    profile: 'ubuntu-24.04-x86_64-node22-v1',
    source: { repository: 'soldabania-art/nginx-x10', commit: source, tree: '4'.repeat(40),
      upstreamCommit: '148c75678cd4171338c31d4ed4c02411736d5fe9', nativeDiffSha256: digest },
    build: { eventHead: source, checkoutCommit: source, prMergeCommit: null,
      binarySha256: digest, manifestSha256: digest, configurationSha256: digest,
      nodeVersion: '22.0.0', nodeExecutableSha256: digest,
      os: 'ubuntu', osVersion: '24.04', arch: 'x86_64',
      ci: [{ workflow: 'X10 native compatibility', runId: 1, jobId: 2, attempt: 1,
        eventHead: source, checkoutCommit: source, conclusion: 'success',
        executedSteps: ['Validate release-record contract and refusal controls', 'Compile native profile', 'Native regressions and pinned official compatibility sample',
          'Verify private Unix control transport', 'Build profile without control API',
          'Package local Linux alpha', 'Checksum local Linux alpha']
          .map(name => ({ name, conclusion: 'success' })) }],
      dependencies: Object.fromEntries(['glibc', 'pcre2', 'openssl', 'zlib', 'libcrypt']
        .map(name => [name, { version: 'synthetic-only', sha256: digest }])) },
    artifact: { url: `${repository}/releases/download/v${version}/synthetic.tar.gz`,
      archiveSha256: digest, payloadManifestSha256: digest, checksumAlgorithm: 'SHA256',
      checksumIsSignature: false, permanent: true, expiresAtUTC: null },
    evidence: kinds.map((kind, i) => ({ id: `synthetic-${i}`, kind, sourceCommit: source,
      url: `${repository}/blob/${source}/x10/evidence/synthetic-only.json`, sha256: digest,
      outcome: 'passed', skippedAssertions: 0, expectedTodoFailures: 0,
      unexpectedFailures: 0, durationSeconds: i === 6 ? 3600 : 10 })),
    gates: Object.fromEntries(kinds.map((_, i) => [`G${i}`, {
      status: stage === 'v1' || i <= 2 ? 'accepted' : 'pending',
      evidenceIds: stage === 'v1' || i <= 2 ? [`synthetic-${i}`] : [] }]))
  };
}
function rejected(change, stage = 'alpha') {
  const value = declaration(stage); change(value);
  const result = validateReleaseRecord(value);
  assert.equal(result.valid, false);
  assert.ok(result.errors.length > 0);
  assert.ok(result.errors.every(code => /^record_[a-z]+$/.test(code)));
}

test('independent declarations admit separate event and actual PR merge checkout', () => {
  for (const stage of ['alpha', 'candidate', 'v1']) {
    const record = declaration(stage);
    assert.deepEqual(validateReleaseRecord(record), { valid: true, errors: [] });
    record.build.checkoutCommit = merge; record.build.prMergeCommit = merge; record.build.ci[0].checkoutCommit = merge;
    assert.equal(validateReleaseRecord(record).valid, true);
    record.evidence[0].sourceCommit = merge;
    record.evidence[0].url = `${repository}/blob/${merge}/x10/evidence/synthetic-only.json`;
    assert.equal(validateReleaseRecord(record).valid, true);
  }
});

test('stage promotion requires all preceding gates and correct evidence classes', () => {
  rejected(v => { v.stage = 'v1'; v.version = '1.0.0'; });
  rejected(v => { v.gates.G8 = { status: 'accepted', evidenceIds: ['synthetic-8'] }; });
  rejected(v => { v.gates.G4.status = 'blocked'; }, 'v1');
  rejected(v => { v.gates.G8.evidenceIds = ['synthetic-0']; }, 'v1');
  rejected(v => { v.evidence[8].outcome = 'not-run'; }, 'v1');
});

test('final accepted release cannot substitute expiring CI or signed-checksum claims', () => {
  rejected(v => { v.artifact.url = `${repository}/actions/runs/123`; v.artifact.permanent = false;
    v.artifact.expiresAtUTC = '2026-11-01T00:00:00Z'; }, 'v1');
  rejected(v => { v.artifact.checksumIsSignature = true; });
  rejected(v => { v.artifact.checksumAlgorithm = 'MD5'; });
});

test('release artifact tag and candidate blob identity must describe the declared bytes', () => {
  rejected(v => { v.artifact.url = `${repository}/releases/download/v9.9.9/synthetic.tar.gz`; });
  rejected(v => { v.artifact.permanent = false; v.artifact.expiresAtUTC = '2026-11-01T00:00:00Z';
    v.artifact.url = `${repository}/blob/${'3'.repeat(40)}/archive.tar.gz`; }, 'candidate');
});

test('source evidence and build identities cannot silently refer to another implementation', () => {
  rejected(v => { v.build.eventHead = merge; });
  rejected(v => { v.build.checkoutCommit = merge; });
  rejected(v => { v.build.prMergeCommit = merge; });
  rejected(v => { v.evidence[0].sourceCommit = '3'.repeat(40); });
  rejected(v => { v.evidence[0].url = `${repository}/blob/${merge}/x10/evidence/synthetic-only.json`; });
  rejected(v => { delete v.source.upstreamCommit; });
});

test('referenced evidence IDs are unique, existing and free of unexpected failures', () => {
  rejected(v => { v.evidence.push({ ...v.evidence[0] }); });
  rejected(v => { v.gates.G0.evidenceIds = ['missing-proof']; });
  rejected(v => { v.gates.G0.evidenceIds.push('synthetic-0'); });
  rejected(v => { v.evidence[0].unexpectedFailures = 1; });
  rejected(v => { v.evidence[0].outcome = 'failed'; });
});

test('soak duration boundary remains one hour and explicit skips are separate counts', () => {
  rejected(v => { v.evidence[6].durationSeconds = 3599; }, 'v1');
  const record = declaration('v1');
  record.evidence[6].durationSeconds = 3600;
  record.evidence[5].skippedAssertions = 25; record.evidence[5].expectedTodoFailures = 1;
  assert.equal(validateReleaseRecord(record).valid, true);
  rejected(v => { v.evidence[5].skippedAssertions = -1; }, 'v1');
  rejected(v => { v.evidence[6].durationSeconds = '3600'; }, 'v1');
});

test('unknown root and nested fields do not become hidden authority', () => {
  rejected(v => { v.productionAccepted = true; });
  rejected(v => { v.gates.G8.allPassed = true; });
  rejected(v => { v.build.dependencies.openssl.signatureVerified = true; });
  rejected(v => { v.evidence[0].bearer = 'SYNTHETIC_SECRET_CANARY'; });
  rejected(v => { v.schemaVersion = 2; });
});

test('URLs do not admit credentials, query credentials, fragments or other schemes', () => {
  for (const url of [`https://secret@github.com/soldabania-art/nginx-x10/actions/runs/123`,
    `${repository}/actions/runs/123?token=SYNTHETIC_SECRET_CANARY`,
    `${repository}/actions/runs/123#SYNTHETIC_SECRET_CANARY`,
    'file:///synthetic-only', 'http://127.0.0.1/private', 'https://example.invalid/proof']) {
    rejected(v => { v.evidence[0].url = url; });
  }
});

test('direct JSON boundary refuses cycles, accessors and exotic values without invoking getters', () => {
  let invoked = 0;
  const accessor = declaration();
  Object.defineProperty(accessor, 'extra', { enumerable: true, get() { invoked++; return 'SYNTHETIC_SECRET_CANARY'; } });
  assert.equal(validateReleaseRecord(accessor).valid, false); assert.equal(invoked, 0);
  const cyclic = declaration(); cyclic.extra = cyclic;
  for (const value of [cyclic, new Date(0), undefined, NaN, Object.assign(Object.create({ inherited: true }), declaration())]) {
    const result = validateReleaseRecord(value);
    assert.equal(result.valid, false); assert.ok(!JSON.stringify(result).includes('SYNTHETIC_SECRET_CANARY'));
  }
});

const cli = fileURLToPath(new URL('./check-release-record.mjs', import.meta.url));
function withFiles(run) {
  const root = mkdtempSync(join(tmpdir(), 'x10-record-independent-'));
  try { return run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
function invoke(args, entry = cli) {
  const child = spawnSync(process.execPath, [entry, ...args], { encoding: 'utf8', timeout: 5000, maxBuffer: 8192 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.stderr, '');
  const result = JSON.parse(child.stdout);
  assert.equal(result.scope, 'declared-record-validation-only');
  assert.equal(result.evidenceAuthenticated, false); assert.equal(result.productionAccepted, false);
  assert.ok(!child.stdout.includes('SYNTHETIC_SECRET_CANARY'));
  return { code: child.status, result };
}

test('CLI accepts a declaration without granting acceptance and sanitizes malformed input', () => withFiles(root => {
  const valid = join(root, 'record.json'); writeFileSync(valid, JSON.stringify(declaration('v1')));
  const result = invoke([valid]); assert.equal(result.code, 0); assert.equal(result.result.valid, true);
  const invalid = join(root, 'malformed.json'); writeFileSync(invalid, '{ SYNTHETIC_SECRET_CANARY');
  assert.equal(invoke([invalid]).code, 1);
  assert.equal(invoke([join(root, 'SYNTHETIC_SECRET_CANARY-missing')]).code, 1);
  assert.equal(invoke([]).code, 1);
}));

test('CLI bounds byte input and refuses symlink or nonregular record sources', () => withFiles(root => {
  const large = join(root, 'large.json'); writeFileSync(large, Buffer.alloc(MAX_RECORD_BYTES + 1, 32));
  assert.equal(invoke([large]).code, 1);
  const valid = join(root, 'record.json'); writeFileSync(valid, JSON.stringify(declaration()));
  const link = join(root, 'link.json'); symlinkSync(valid, link);
  assert.equal(invoke([link]).code, 1);
  const directory = join(root, 'directory'); mkdirSync(directory);
  assert.equal(invoke([directory]).code, 1);
}));

// An aliased executable must still run validation or explicitly refuse; an
// empty exit-zero response is not successful validation of a missing record.
test('CLI script aliases cannot silently skip validation with exit zero', () => withFiles(root => {
  const alias = join(root, 'checker-alias.mjs'); symlinkSync(cli, alias);
  const result = invoke([join(root, 'missing-record.json')], alias);
  assert.equal(result.code, 1); assert.equal(result.result.valid, false);
}));

test('build declarations require exact tree and executed native CI identities', () => {
  rejected(v => { delete v.source.tree; });
  rejected(v => { delete v.build.ci; });
  rejected(v => { v.build.ci[0].jobId = 0; });
  rejected(v => { v.build.ci[0].attempt = 0; });
  rejected(v => { v.build.ci[0].eventHead = merge; });
  rejected(v => { v.build.ci[0].checkoutCommit = merge; });
  rejected(v => { v.build.ci[0].executedSteps = []; });
  rejected(v => { v.build.ci[0].executedSteps[0].conclusion = 'skipped'; });
  rejected(v => { v.build.ci[0].conclusion = 'failure'; });
});
