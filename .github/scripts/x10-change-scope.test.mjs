import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { refsForEvent, scopeForPaths, classifyChange, readEvent } from './x10-change-scope.mjs';

const A = '1'.repeat(40), B = '2'.repeat(40), C = '3'.repeat(40);
const event = () => ({ action: 'synchronize', before: A, after: B, pull_request: { base: { sha: C }, head: { sha: B } } });
const both = value => { assert.equal(value.native, true); assert.equal(value.research, true); };
const selected = (paths, native, research) => assert.deepEqual(
  (({ native, research }) => ({ native, research }))(scopeForPaths(paths)), { native, research });

test('native, research and workflow changes select the matching real profile', () => {
  for (const name of ['src/core/a.c', 'auto/configure', 'conf/nginx.conf', 'x10/test/a.mjs', 'x10/STATUS.md', '.github/workflows/x10-native.yml']) selected([name], true, false);
  for (const name of ['x10/continuum/record.mjs', 'x10/continuum/new.json', '.github/workflows/x10-continuum.yml']) selected([name], false, true);
  selected(['src/a.c', 'x10/continuum/record.mjs'], true, true);
  for (const name of ['.github/scripts/x10-change-scope.mjs', '.github/scripts/x10-change-scope.test.mjs']) selected([name], true, true);
});

test('only exact root metadata exclusions skip research; nested sources still run', () => {
  selected(['x10/continuum/BACKGROUND.json', 'x10/continuum/PLAN.md'], false, false);
  selected(['x10/continuum/nested/BACKGROUND.json'], false, true);
  selected(['x10/continuum/nested/PLAN.md'], false, true);
  selected(['x10/continuum/BACKGROUND.json.mjs'], false, true);
  selected(['README.md'], false, false);
  selected([], false, false);
});

test('ambiguous or oversized path lists always run both profiles', () => {
  for (const paths of [null, {}, [''], ['/src/a.c'], ['src/../a.c'], ['src//a.c'], ['src/a\nb.c'], ['src\\a.c'], [null], new Array(10001).fill('README.md'), ['a'.repeat(1048577)]]) both(scopeForPaths(paths));
});

test('event selection validates exact commit IDs and synchronize binding', () => {
  assert.deepEqual(refsForEvent('push', { before: A, after: B }), { before: A, after: B, base: null });
  assert.deepEqual(refsForEvent('pull_request', event()), { before: A, after: B, base: C });
  for (const action of ['opened', 'reopened', 'ready_for_review']) assert.deepEqual(refsForEvent('pull_request', { ...event(), action }), { before: C, after: B, base: null });
  const bad = [undefined, {}, { before: '0'.repeat(40), after: B }, { before: A, after: A }, { before: '-bad', after: B }, { before: A, after: 'AB'.repeat(20) }];
  for (const value of bad) assert.equal(refsForEvent('push', value), null);
  for (const value of [{ ...event(), after: C }, { ...event(), before: null }, { ...event(), action: 'edited' }, { ...event(), pull_request: {} }]) assert.equal(refsForEvent('pull_request', value), null);
  assert.equal(refsForEvent('workflow_dispatch', event()), null);
  assert.equal(refsForEvent('pull_request_target', event()), null);
});

test('synchronize uses before/after, checks base ancestry and requests rename-safe bounded Git diff', () => {
  const calls = [];
  const result = classifyChange({ eventName: 'pull_request', event: event(), executeGit: args => {
    calls.push(args); return Buffer.from(args[0] === 'diff' ? 'x10/continuum/BACKGROUND.json\0' : '');
  } });
  assert.equal(result.native, false); assert.equal(result.research, false); assert.equal(result.sourceSha, B);
  assert.deepEqual(calls[0], ['merge-base', '--is-ancestor', C, A]);
  assert.deepEqual(calls[1], ['diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-only', '-z', A, B, '--']);
});

test('missing commits, divergent bases and malformed Git output cannot skip a profile', () => {
  for (const executeGit of [() => { throw new Error('unavailable tree'); }, () => 'README.md\0', () => Buffer.from('README.md'), () => Buffer.from([0xff, 0]), () => Buffer.alloc(1048577)]) {
    both(classifyChange({ eventName: 'push', event: { before: A, after: B }, executeGit }));
  }
  let commands = 0;
  both(classifyChange({ eventName: 'pull_request', event: event(), executeGit: () => { commands++; throw new Error('base advanced'); } }));
  assert.equal(commands, 1);
  both(classifyChange({ eventName: 'pull_request', event: { ...event(), before: undefined }, executeGit: () => { throw new Error('must not use fallback comparison'); } }));
  both(classifyChange({ eventName: 'workflow_dispatch', event: {}, executeGit: () => { throw new Error('manual always runs'); } }));
});

test('CLI handles real delete/rename deltas and invalid event input without exposing payloads', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'x10-ci-scope-'));
  const script = fileURLToPath(new URL('./x10-change-scope.mjs', import.meta.url));
  const git = args => execFileSync('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 });
  const run = (value, eventName = 'push') => {
    const file = path.join(root, 'event.json'), output = path.join(root, 'output.txt');
    writeFileSync(file, JSON.stringify(value)); writeFileSync(output, '');
    const raw = execFileSync(process.execPath, [script], { cwd: root, env: { ...process.env, GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: file, GITHUB_OUTPUT: output }, encoding: 'utf8', timeout: 10000 });
    assert(!raw.includes('private-event-canary'));
    const result = JSON.parse(raw);
    assert.equal(readFileSync(output, 'utf8'), `native=${result.native}\nresearch=${result.research}\n`);
    return result;
  };
  try {
    git(['init', '-q']); git(['config', 'user.name', 'Scope Fixture']); git(['config', 'user.email', 'scope@example.invalid']);
    mkdirSync(path.join(root, 'src')); mkdirSync(path.join(root, 'x10/continuum'), { recursive: true });
    writeFileSync(path.join(root, 'src/a.c'), 'fixture\n'); git(['add', 'src/a.c']); git(['commit', '-qm', 'fixture baseline']);
    const before = git(['rev-parse', 'HEAD']).toString().trim();
    renameSync(path.join(root, 'src/a.c'), path.join(root, 'x10/continuum/a.md')); git(['add', '-A', 'src', 'x10']); git(['commit', '-qm', 'move fixture']);
    const after = git(['rev-parse', 'HEAD']).toString().trim();
    const renamed = run({ before, after, arbitrary: 'private-event-canary' }); assert.equal(renamed.native, true); assert.equal(renamed.research, false);
    writeFileSync(path.join(root, 'src/b.c'), 'new native fixture\n'); git(['add', 'src']); git(['commit', '-qm', 'native fixture']);
    const source = git(['rev-parse', 'HEAD']).toString().trim();
    writeFileSync(path.join(root, 'x10/continuum/BACKGROUND.json'), '{}\n'); git(['add', 'x10']); git(['commit', '-qm', 'metadata fixture']);
    const metadata = git(['rev-parse', 'HEAD']).toString().trim();
    const skipped = run({ before: source, after: metadata }); assert.equal(skipped.native, false); assert.equal(skipped.research, false);
    // The whole PR still includes native changes, while this head update
    // only changes coordination metadata. Exercise real merge-base and diff.
    assert(git(['diff', '--name-only', before, metadata]).toString().includes('src/b.c'));
    const pr = { action: 'synchronize', before: source, after: metadata, pull_request: { base: { sha: before }, head: { sha: metadata } } };
    const synchronized = run(pr, 'pull_request'); assert.equal(synchronized.native, false); assert.equal(synchronized.research, false);
    const opened = run({ ...pr, action: 'opened' }, 'pull_request'); assert.equal(opened.native, true); assert.equal(opened.research, false);
    both(run({ before: A, after: metadata }));
    writeFileSync(path.join(root, 'invalid.json'), '{bad'); assert.equal(readEvent(path.join(root, 'invalid.json')), null);
    writeFileSync(path.join(root, 'invalid.json'), ' '.repeat(1048577)); assert.equal(readEvent(path.join(root, 'invalid.json')), null);
    assert.equal(readEvent(root), null); assert.equal(readEvent(path.join(root, 'absent')), null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
