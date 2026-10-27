import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARED_OPERATOR_PEERS, assessSharedPeerBytes,
  verifySharedOperatorPeerFiles } from './operator-package-return.mjs';

// Pure byte controls and owned temporary files only. Importing the collector
// does not run its main function; these tests never invoke an installer,
// native process, service manager, signal, network operation or Git command.
const root = fileURLToPath(new URL('../../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const blob = bytes => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
// Independent literal review pins. Do not derive expectations from the table
// under test, or move this source baseline implicitly with the current checkout.
const expected = {
  profile: 'LEGACY_CLI_WITH_REVIEWED_CURRENT_PEERS',
  commit: '98bc32d4ee9a6c1d6ed198135df01065ad1a65e7',
  files: [
    { path: 'x10/control/cli.mjs', blob: 'fca0a871aa86e96366aae289714498ff52bd28bf', bytes: 4766,
      sha256: '2674c8dc7be76ddc8ca02613fa384787060f5b2f498d1333ee708de78e1568ac' },
    { path: 'x10/control/manager.mjs', blob: '544f318607696879fb23e695097f853e5f8064b0', bytes: 51246,
      sha256: 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289' },
    { path: 'x10/control/listeners.mjs', blob: 'd61efff79ed8d20db4ce924bc52d2b43565ef071', bytes: 18828,
      sha256: 'd2ad8e7ee0df940941bfa9997a022b47903a7fd68c6b44631bb2aaf4b5befcc2' },
    { path: 'x10/control/generations.mjs', blob: 'dbdb2eaf872d2ca7aa0c60318519cf25aaf3152e', bytes: 13323,
      sha256: 'dba28810084f0cbb84275cc200f5bec93150406306c6bd78b06ac2b585815789' },
    { path: 'x10/control/status-format.mjs', blob: '40a39eb3993df1c31ca9c3f54af731504c994ea4', bytes: 4312,
      sha256: '522d932cbfe9ca8493a5f472207da910eb71476ed47f1148dda589a4171929f8' },
    { path: 'x10/alpha/runtime.mjs', blob: 'c4fd0e3cc565fcaf36096d76d0cbc4cc715d4db7', bytes: 7540,
      sha256: 'bb9c8974be8a56a73aab3cbccb0948d1234e1d461c16a6d3ad680beb786ebf51' },
    { path: 'x10/alpha/upstream-example.mjs', blob: '853821879e87f61d43a4696f121938ad29b62516', bytes: 4989,
      sha256: '18c9acbe7d76ed29f4528454fd22608d5da1658b7a760ea1dc26537cd302cd0c' },
    { path: 'x10/service/user-unit.mjs', blob: 'b4ffdff44de65a429bcfba742d357e3d4446d94d', bytes: 9481,
      sha256: 'ae8e34acd2d16a0bbe04884b92d692c2e7e3c76c632c6a26eaa1b0cd38d65d9f' },
  ],
};
const peerBytes = new Map(await Promise.all(expected.files.map(async row =>
  [row.path, await readFile(path.join(root, row.path))])));
function refused(name, bytes) {
  const result = assessSharedPeerBytes(name, bytes);
  assert.deepEqual(result, { valid: false, code: 'shared_peer_refused' });
  assert.equal(Object.isFrozen(result), true);
}

test('shared profile retains all eight ordered independently reviewed peer pins', () => {
  assert.deepEqual(SHARED_OPERATOR_PEERS, expected);
  assert.equal(new Set(expected.files.map(row => row.path)).size, 8);
});
test('shared profile and all its rows are immutable', () => {
  assert.equal(Object.isFrozen(SHARED_OPERATOR_PEERS), true);
  assert.equal(Object.isFrozen(SHARED_OPERATOR_PEERS.files), true);
  for (const row of SHARED_OPERATOR_PEERS.files) assert.equal(Object.isFrozen(row), true);
  assert.throws(() => { SHARED_OPERATOR_PEERS.commit = '0'.repeat(40); }, TypeError);
  assert.throws(() => { SHARED_OPERATOR_PEERS.files[0].sha256 = '0'.repeat(64); }, TypeError);
});
test('unchanged acb peer assumption independently detects exactly the two reader changes', () => {
  // These two hashes identify actual acb records; the other six peer hashes
  // were unchanged. This is the old equality precondition, not a native replay.
  const oldHashes = new Map(expected.files.map(row => [row.path, row.sha256]));
  oldHashes.set('x10/control/cli.mjs', '72972fd1093068d05b788a326962f641fb2871dd7fa4cabb66957fcb3b22775b');
  oldHashes.set('x10/control/manager.mjs', '5073eb2dc194bba659e664c58b259469372625505b7c46798ec9b397095d7822');
  assert.deepEqual(expected.files.filter(row => hash(peerBytes.get(row.path)) !== oldHashes.get(row.path))
    .map(row => row.path), ['x10/control/cli.mjs', 'x10/control/manager.mjs']);
  assert.equal(expected.files.every(row => hash(peerBytes.get(row.path)) === oldHashes.get(row.path)), false);
});
for (const [index, row] of expected.files.entries()) {
  test(`reviewed peer ${row.path} matches exact bytes, SHA256 and Git blob`, () => {
    const bytes = peerBytes.get(row.path);
    assert.equal(bytes.length, row.bytes); assert.equal(hash(bytes), row.sha256); assert.equal(blob(bytes), row.blob);
    const result = assessSharedPeerBytes(row.path, bytes);
    assert.deepEqual(result, { valid: true, code: 'ok' }); assert.equal(Object.isFrozen(result), true);
  });
  test(`reviewed peer ${row.path} refuses same-length byte mutation`, () => {
    const bytes = Buffer.from(peerBytes.get(row.path)); bytes[Math.floor(bytes.length / 2)] ^= 1;
    refused(row.path, bytes);
  });
  test(`reviewed peer ${row.path} refuses truncation`, () => {
    refused(row.path, peerBytes.get(row.path).subarray(0, row.bytes - 1));
  });
  test(`reviewed peer ${row.path} refuses appended bytes`, () => {
    refused(row.path, Buffer.concat([peerBytes.get(row.path), Buffer.from('\n')]));
  });
  test(`reviewed peer ${row.path} refuses non-Buffer byte representations`, () => {
    const bytes = peerBytes.get(row.path);
    for (const value of [bytes.toString('utf8'), new Uint8Array(bytes), bytes.buffer,
      { length: bytes.length, toString: () => bytes.toString('utf8') }, null, undefined]) refused(row.path, value);
  });
  test(`reviewed peer ${row.path} refuses another allowlisted peer's bytes`, () => {
    refused(row.path, peerBytes.get(expected.files[(index + 1) % expected.files.length].path));
  });
}
for (const [name, selector] of [
  ['unknown', 'x10/control/unknown.mjs'], ['traversal', 'x10/control/../control/cli.mjs'],
  ['absolute', path.join(root, expected.files[0].path)], ['empty', ''], ['null', null],
  ['array', [expected.files[0].path]], ['wrapped string', new String(expected.files[0].path)],
  ['number', 1], ['missing', undefined],
]) test(`peer selector refuses ${name} without string coercion`, () => refused(selector, peerBytes.get(expected.files[0].path)));
test('peer selection and byte refusal do not evaluate caller coercion hooks', () => {
  let calls = 0;
  const hostile = { toString() { calls++; throw new Error('coercion must not run'); },
    valueOf() { calls++; throw new Error('coercion must not run'); } };
  refused(hostile, peerBytes.get(expected.files[0].path)); refused(expected.files[0].path, hostile);
  assert.equal(calls, 0);
});
test('revoked selectors and byte proxies give finite refusal results', () => {
  const selector = Proxy.revocable({}, {}); selector.revoke();
  const bytes = Proxy.revocable(Buffer.from(peerBytes.get(expected.files[0].path)), {}); bytes.revoke();
  refused(selector.proxy, peerBytes.get(expected.files[0].path)); refused(expected.files[0].path, bytes.proxy);
});
async function withBundle(operation) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'x10-peer-review-'));
  await chmod(temporary, 0o700);
  try {
    for (const row of expected.files) {
      const target = path.join(temporary, row.path);
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, peerBytes.get(row.path), { mode: 0o400 });
    }
    return await operation(temporary);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}
test('all eight reviewed peers are accepted from an owned read-only temporary bundle unchanged', async () => withBundle(async bundle => {
  const before = await Promise.all(expected.files.map(row => lstat(path.join(bundle, row.path))));
  assert.equal(await verifySharedOperatorPeerFiles(bundle), true);
  for (const [i, row] of expected.files.entries()) {
    const file = path.join(bundle, row.path), after = await lstat(file);
    assert.deepEqual(await readFile(file), peerBytes.get(row.path));
    for (const key of ['ino', 'dev', 'uid', 'mode', 'nlink', 'size']) assert.equal(after[key], before[i][key]);
  }
}));
for (const row of expected.files) test(`bundle verification refuses missing mandatory ${row.path}`, async () => withBundle(async bundle => {
  await rm(path.join(bundle, row.path));
  await assert.rejects(verifySharedOperatorPeerFiles(bundle));
}));
test('bundle verification refuses symlink replacement and preserves its external owned target', async () => withBundle(async bundle => {
  const row = expected.files[0], file = path.join(bundle, row.path), target = path.join(bundle, 'outside-peer');
  await writeFile(target, peerBytes.get(row.path), { mode: 0o400 }); await rm(file); await symlink(target, file);
  await assert.rejects(verifySharedOperatorPeerFiles(bundle));
  assert.deepEqual(await readFile(target), peerBytes.get(row.path)); assert.equal((await lstat(file)).isSymbolicLink(), true);
}));
test('bundle verification refuses writable peer mode without changing the record', async () => withBundle(async bundle => {
  const row = expected.files[0], file = path.join(bundle, row.path); await chmod(file, 0o600);
  await assert.rejects(verifySharedOperatorPeerFiles(bundle));
  assert.equal((await lstat(file)).mode & 0o7777, 0o600); assert.deepEqual(await readFile(file), peerBytes.get(row.path));
}));
test('bundle verification refuses replaced peer bytes while preserving all other peers', async () => withBundle(async bundle => {
  const row = expected.files[1], file = path.join(bundle, row.path), altered = Buffer.from(peerBytes.get(row.path)); altered[0] ^= 1;
  await chmod(file, 0o600); await writeFile(file, altered); await chmod(file, 0o400);
  await assert.rejects(verifySharedOperatorPeerFiles(bundle)); assert.deepEqual(await readFile(file), altered);
  for (const other of expected.files.filter(value => value.path !== row.path))
    assert.deepEqual(await readFile(path.join(bundle, other.path)), peerBytes.get(other.path));
}));

// Integration source guards deliberately inspect only call ordering and pin
// coverage. They do not execute physical alpha/service fixture entry points.
const stageSource = await readFile(new URL('../test/alpha.test.mjs', import.meta.url), 'utf8');
const returnSource = await readFile(new URL('../test/package-return.mjs', import.meta.url), 'utf8');
const managedSource = await readFile(new URL('./operator-package-return.mjs', import.meta.url), 'utf8');
function before(source, first, second) {
  const a = source.indexOf(first), b = source.indexOf(second);
  assert(a >= 0 && b >= 0 && a < b, `Required source ordering: ${first} before ${second}`);
}
test('staging preflight uses the complete shared table and bundle verification before copying', () => {
  const source = stageSource.slice(stageSource.indexOf('async function assertHostedPackageStage('));
  assert(source.includes('const sharedPeers = SHARED_OPERATOR_PEERS.files.map(row => row.path)'));
  assert(source.includes("['diff', '--exit-code', SHARED_OPERATOR_PEERS.commit, '--', ...sharedPeers]"));
  before(source, 'await verifySharedOperatorPeerFiles(bundle)', 'for (const relative of bundleTree.directories)');
  before(source, 'assert.equal(digest(historical.stdout), historicalCliSha256)', 'await verifySharedOperatorPeerFiles(bundle)');
});
test('foreground return preflight uses the complete shared table and verifies peers before copying', () => {
  const source = returnSource.slice(returnSource.indexOf('async function reassembleHistoricalBundle('));
  assert(source.includes('const peers = SHARED_OPERATOR_PEERS.files.map(row => row.path)'));
  assert(source.includes("['diff', '--exit-code', SHARED_OPERATOR_PEERS.commit, '--', ...peers]"));
  before(source, 'await verifySharedOperatorPeerFiles(bundle)', 'const selected =');
  before(source, 'assert.equal(digest(source.stdout), historicalCliSha256)', 'await verifySharedOperatorPeerFiles(bundle)');
});
test('managed collector checks actual bundled peer bytes before constructing legacy assembly', () => {
  before(managedSource, 'const historical = await readHistoricalOperatorFile(input.historicalCli)',
    'await verifySharedOperatorPeerFiles(bundle)');
  before(managedSource, 'await verifySharedOperatorPeerFiles(bundle)', "report.phase = 'historical'");
  before(managedSource, 'await verifySharedOperatorPeerFiles(bundle)', 'await writeFile(oldCli, historical)');
  const start = managedSource.indexOf('export async function verifySharedOperatorPeerFiles(bundle)'),
    end = managedSource.indexOf('\n}', start);
  const source = managedSource.slice(start, end);
  assert(source.includes('for (const pin of SHARED_OPERATOR_PEERS.files)'));
  assert(source.includes('assessSharedPeerBytes(pin.path, value.bytes).valid'));
});
const workflowSource = await readFile(new URL('../../.github/workflows/x10-native.yml', import.meta.url), 'utf8');
test('checkout bootstrap authenticates collector source before importing its fixed shared-peer table', () => {
  const start = workflowSource.indexOf('async function historicalBytes()'),
    end = workflowSource.indexOf('\n          async function run(', start), source = workflowSource.slice(start, end);
  assert(start >= 0 && end > start);
  before(source, 'await checkerPins()', 'await import(pathToFileURL(path.resolve(managedSource)).href)');
  assert(source.includes("SHARED_OPERATOR_PEERS.profile !== 'LEGACY_CLI_WITH_REVIEWED_CURRENT_PEERS'"));
  assert(source.includes(`SHARED_OPERATOR_PEERS.commit !== '${expected.commit}'`));
  assert(source.includes('SHARED_OPERATOR_PEERS.files.length !== 8'));
  assert(source.includes("['diff', '--exit-code', SHARED_OPERATOR_PEERS.commit, '--', ...peers]"));
  assert(source.includes("['rev-parse', SHARED_OPERATOR_PEERS.commit + ':' + row.path]"));
  assert(source.includes('Buffer.from(row.blob +'));
  assert(source.includes('assessSharedPeerBytes(row.path, await readFile(row.path)).valid'));
  before(source, 'for (const row of SHARED_OPERATOR_PEERS.files)', 'return raw.stdout');
  assert.equal(workflowSource.match(/const managedSourceSha = '([a-f0-9]{64})'/)?.[1], hash(Buffer.from(managedSource)));
});
test('new peer controls are wired into the existing managed-return declaration step', () => {
  const start = workflowSource.indexOf('- name: Validate managed operator-package return refusal controls'),
    end = workflowSource.indexOf('- name: Validate managed unhealthy-package fallback refusal controls', start),
    source = workflowSource.slice(start, end);
  assert(start >= 0 && end > start);
  for (const name of ['operator-package-return-proof.test.mjs', 'operator-package-return.test.mjs', 'legacy-cli-peers.test.mjs'])
    assert(source.includes(`x10/service/${name}`));
  assert.equal((workflowSource.match(/- name: Validate managed operator-package return refusal controls/g) || []).length, 1);
});
