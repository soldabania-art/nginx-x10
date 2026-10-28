import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { constants } from 'node:fs';
import { readBoundedText, status, history, recover } from './manager.mjs';

// Pure/tempfile controls only: no native executable, subprocess, signal,
// service manager or network operation. All manager fixtures remain unbound.
const MiB = 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const managerSource = await readFile(new URL('./manager.mjs', import.meta.url), 'utf8');
const cliSource = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const renderStart = managerSource.indexOf('function render(');
const renderEnd = managerSource.indexOf('\nasync function makeRevision', renderStart);
assert(renderStart >= 0 && renderEnd > renderStart);
// Rendering constructs an ordinary valid fixture; it is not the reader under
// test and is not treated as an independent native configuration validator.
const render = vm.runInNewContext(`(${managerSource.slice(renderStart, renderEnd)})`);

async function temporary(operation) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'x10-record-input-'));
  await chmod(root, 0o700);
  try { return await operation(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

async function fixture(root, { escapedRevision = false } = {}) {
  const prefix = path.join(root, 'installation'), state = path.join(prefix, '.x10-control');
  await mkdir(prefix, { mode: 0o700 });
  await mkdir(state, { mode: 0o700 });
  await mkdir(path.join(state, 'revisions'), { mode: 0o700 });
  const settings = { schemaVersion: 1, prefix, state, config: path.join(prefix, 'nginx.conf'),
    fragment: path.join(prefix, 'managed.conf'), pidFile: path.join(prefix, 'nginx.pid'),
    binary: '/nonexecuted/native-placeholder', port: 8088, gateTimeoutMs: 500,
    pidNamespace: await readlink('/proc/self/ns/pid'), configSha256: digest('config') };
  const input = { serverBody: escapedRevision ? `# ${'\\'.repeat(MiB - 2)}` : 'location / { return 200 "A"; }',
    healthURL: 'http://127.0.0.1:9090/ready' };
  const revision = { schemaVersion: 1, id: 'a'.repeat(32), createdAt: '2026-10-27T00:00:00.000Z',
    parent: null, sourceRevision: null, input };
  revision.inputSha256 = digest(JSON.stringify(input));
  revision.fragmentSha256 = digest(render(settings, revision));
  revision.recordSha256 = digest(JSON.stringify(revision));
  const current = { schemaVersion: 1, activeRevision: revision.id, previousRevision: null, binding: null, historyHead: null };
  const put = async (relative, value, mode = 0o600) => {
    const file = path.join(state, relative);
    await rm(file, { force: true });
    await writeFile(file, typeof value === 'string' ? value : JSON.stringify(value), { mode });
    return file;
  };
  await put('settings.json', settings); await put('state.json', current);
  await put('history.jsonl', ''); await put(`revisions/${revision.id}.json`, revision, 0o400);
  await writeFile(settings.config, 'config', { mode: 0o600 });
  await writeFile(settings.fragment, render(settings, revision), { mode: 0o600 });
  return { prefix, state, settings, current, revision, put };
}

async function preserved(files, operation) {
  const before = await Promise.all(files.map(async file => ({ file, bytes: await readFile(file), stat: await lstat(file) })));
  await operation();
  for (const prior of before) {
    assert.deepEqual(await readFile(prior.file), prior.bytes);
    const actual = await lstat(prior.file);
    for (const key of ['dev', 'ino', 'uid', 'mode', 'size', 'nlink']) assert.equal(actual[key], prior.stat[key], key);
  }
}

test('bounded text accepts empty, ASCII and multibyte records without changing bytes', async () => temporary(async root => {
  for (const [i, text] of ['', '{"ok":true}\n', 'состояние\n東京'].entries()) {
    const file = path.join(root, String(i)); await writeFile(file, text, { mode: 0o600 });
    await preserved([file], async () => assert.equal(await readBoundedText(file), text));
  }
}));

for (const mode of [0o400, 0o600, 0o640, 0o644, 0o444]) {
  test(`bounded text retains accepted owned mode ${mode.toString(8)}`, async () => temporary(async root => {
    const file = path.join(root, 'record'); await writeFile(file, '{}', { mode });
    await chmod(file, mode);
    await preserved([file], async () => assert.equal(await readBoundedText(file), '{}'));
  }));
}

test('bounded text retains stable owned hardlink compatibility', async () => temporary(async root => {
  const file = path.join(root, 'record'), alias = path.join(root, 'alias');
  await writeFile(file, 'record', { mode: 0o600 }); await link(file, alias);
  assert.equal((await lstat(file)).nlink, 2);
  await preserved([file, alias], async () => assert.equal(await readBoundedText(alias), 'record'));
}));

for (const budget of [2 * MiB, 8 * MiB, 16 * MiB]) {
  test(`bounded text accepts the exact ${budget}-byte budget`, async () => temporary(async root => {
    const file = path.join(root, 'record'); await writeFile(file, 'x'.repeat(budget), { mode: 0o600 });
    const actual = await readBoundedText(file, budget); assert.equal(actual.length, budget);
    assert.equal(actual[0], 'x'); assert.equal(actual.at(-1), 'x');
  }));
  test(`bounded text refuses sparse file one byte above ${budget} before content parsing`, async () => temporary(async root => {
    const file = path.join(root, 'record'), handle = await open(file, 'wx', 0o600);
    try { await handle.truncate(budget + 1); } finally { await handle.close(); }
    await assert.rejects(readBoundedText(file, budget), { code: 'record_limit' });
    assert.equal((await lstat(file)).size, budget + 1);
  }));
}

test('bounded text uses the supplied finite limit error code', async () => temporary(async root => {
  const file = path.join(root, 'record'); await writeFile(file, '12345', { mode: 0o600 });
  await assert.rejects(readBoundedText(file, 4, 'input_limit'), { code: 'input_limit' });
}));

test('bounded text refuses a symlink while preserving its target', async () => temporary(async root => {
  const file = path.join(root, 'record'), alias = path.join(root, 'alias');
  await writeFile(file, 'sentinel', { mode: 0o600 }); await symlink('record', alias);
  await preserved([file], async () => await assert.rejects(readBoundedText(alias)));
  assert.equal((await lstat(alias)).isSymbolicLink(), true);
}));

test('bounded text refuses directories without opening their contents', async () => temporary(async root => {
  await assert.rejects(readBoundedText(root), { code: 'unsafe_path' });
}));

for (const mode of [0o620, 0o602, 0o666]) {
  test(`bounded text refuses group/other writable mode ${mode.toString(8)}`, async () => temporary(async root => {
    const file = path.join(root, 'record'); await writeFile(file, 'sentinel', { mode }); await chmod(file, mode);
    await preserved([file], async () => await assert.rejects(readBoundedText(file), { code: 'unsafe_permissions' }));
  }));
}

test('bounded text rejects malformed UTF-8 instead of silently replacing bytes', async () => temporary(async root => {
  const file = path.join(root, 'record'); await writeFile(file, Buffer.from([0x22, 0xff, 0x22]), { mode: 0o600 });
  await preserved([file], async () => await assert.rejects(readBoundedText(file)));
}));

test('bounded text preserves leading BOM so existing JSON parsing still refuses it', async () => temporary(async root => {
  const file = path.join(root, 'record'), text = '\ufeff{"ok":true}';
  await writeFile(file, text, { mode: 0o600 });
  const actual = await readBoundedText(file);
  assert.equal(actual, text); assert.throws(() => JSON.parse(actual), SyntaxError);
  await preserved([file], async () => assert.equal(await readBoundedText(file), text));
}));

test('bounded text measures multibyte input in bytes rather than characters', async () => temporary(async root => {
  const file = path.join(root, 'record'), text = '東京';
  await writeFile(file, text, { mode: 0o600 });
  assert.equal(await readBoundedText(file, 6), text);
  await assert.rejects(readBoundedText(file, 5), { code: 'record_limit' });
}));

test('unbound valid controller status/history/recover retain existing semantics', async () => temporary(async root => {
  const f = await fixture(root);
  const result = await status(f.state);
  assert.equal(result.ok, true); assert.equal(result.binding, null);
  assert.equal(result.runtime.identityValid, false); assert.equal(result.fragmentMatchesLastConfirmed, true);
  assert.deepEqual(await history(f.state), { ok: true, records: [] });
  assert.deepEqual(await recover(f.state), { ok: true, outcome: 'nothing_pending' });
  await assert.rejects(lstat(path.join(f.state, 'lock')), { code: 'ENOENT' });
}));

test('immutable escaped revision above the metadata budget retains its larger revision budget', async () => temporary(async root => {
  const f = await fixture(root, { escapedRevision: true });
  const revisionFile = path.join(f.state, 'revisions', `${f.revision.id}.json`);
  assert((await lstat(revisionFile)).size > 2 * MiB);
  await preserved([revisionFile], async () => assert.equal((await status(f.state)).ok, true));
}));

for (const record of ['settings.json', 'state.json', 'pending.json', 'event-commit.json']) {
  test(`oversized ${record} refuses without altering records or retaining a lock`, async () => temporary(async root => {
    const f = await fixture(root);
    const value = record === 'settings.json' ? { ...f.settings, ignoredExtra: 'x'.repeat(3 * MiB) }
      : { ignoredExtra: 'x'.repeat(3 * MiB) };
    const oversized = await f.put(record, value);
    await preserved([oversized, path.join(f.state, 'history.jsonl')], async () =>
      await assert.rejects(status(f.state), { code: 'record_limit' }));
    await assert.rejects(lstat(path.join(f.state, 'lock')), { code: 'ENOENT' });
  }));
}

test('oversized revision refuses within its separate budget and keeps immutable data', async () => temporary(async root => {
  const f = await fixture(root), file = path.join(f.state, 'revisions', `${f.revision.id}.json`);
  await f.put(`revisions/${f.revision.id}.json`, ' '.repeat(8 * MiB + 1), 0o400);
  await preserved([file], async () => await assert.rejects(status(f.state), { code: 'record_limit' }));
  await assert.rejects(lstat(path.join(f.state, 'lock')), { code: 'ENOENT' });
}));

test('oversized history retains the existing history_limit refusal', async () => temporary(async root => {
  const f = await fixture(root), file = await f.put('history.jsonl', ' '.repeat(16 * MiB + 1));
  await preserved([file], async () => await assert.rejects(history(f.state), { code: 'history_limit' }));
  await assert.rejects(lstat(path.join(f.state, 'lock')), { code: 'ENOENT' });
}));

test('existing controller lock remains unchanged and is not bypassed for oversized input', async () => temporary(async root => {
  const f = await fixture(root), lock = await f.put('lock', 'existing-lock-sentinel');
  await f.put('settings.json', { ...f.settings, ignoredExtra: 'x'.repeat(3 * MiB) });
  await preserved([lock], async () => await assert.rejects(status(f.state), { code: 'locked' }));
}));

test('BOM-prefixed controller JSON retains its parse refusal and leaves no lock', async () => temporary(async root => {
  const f = await fixture(root), file = await f.put('state.json', '\ufeff' + JSON.stringify(f.current));
  await preserved([file], async () => await assert.rejects(status(f.state), SyntaxError));
  await assert.rejects(lstat(path.join(f.state, 'lock')), { code: 'ENOENT' });
}));

test('CLI loader delegates the two-MiB acquisition bound before parsing', async () => {
  const start = cliSource.indexOf('async function load(file)'), end = cliSource.indexOf('\nlet humanStatus', start);
  assert(start >= 0 && end > start);
  const calls = [], load = vm.runInNewContext(`(${cliSource.slice(start, end)})`, {
    readBoundedText: async (...args) => { calls.push(args); return '{"ok":true}'; }, JSON, Error,
  });
  assert.deepEqual(await load('owned-candidate.json'), { ok: true });
  assert.deepEqual(calls, [['owned-candidate.json', 2 * MiB, 'input_limit']]);
});

test('CLI loader does not parse when bounded acquisition refuses and preserves its error', async () => {
  const start = cliSource.indexOf('async function load(file)'), end = cliSource.indexOf('\nlet humanStatus', start);
  let parses = 0;
  const load = vm.runInNewContext(`(${cliSource.slice(start, end)})`, {
    readBoundedText: async () => { throw Object.assign(new Error('bounded refusal'), { code: 'input_limit' }); },
    JSON: { parse: () => { parses++; throw new Error('unexpected parse'); } }, Error,
  });
  await assert.rejects(load('owned-candidate.json'), error => {
    assert.equal(error.code, 'input_limit'); assert.equal(error.message, 'JSON input exceeds 2 MiB'); return true;
  });
  assert.equal(parses, 0);
  await assert.rejects(load(undefined), /required JSON file argument/);
  assert.equal(parses, 0);
});

// The actual production reader is evaluated with scripted filesystem results
// solely to make otherwise nondeterministic read/identity races reproducible.
// No product-only injection option is introduced, and actual tempfile tests
// above separately exercise the normal fs/promises integration.
function scriptedReader(options = {}) {
  const uid = 42, file = '/synthetic/owned-record';
  const contents = Buffer.from(options.contents ?? '{"ok":true}');
  const initial = { dev: 1, ino: 2, uid, mode: 0o100600, nlink: 1,
    size: contents.length, mtimeMs: 100, ctimeMs: 100, isFile: () => true };
  const selected = { ...initial, ...options.selected };
  const before = { ...selected, ...options.before };
  const after = { ...before, ...options.after };
  const reobserved = { ...after, ...options.reobserved };
  const observed = { pathChecks: 0, opens: 0, fdStats: 0, reads: 0, closes: 0,
    allocations: [], buffers: [], decodes: 0 };
  let offset = 0;
  const handle = {
    stat: async () => {
      observed.fdStats++;
      if (options.statError) throw Object.assign(new Error('synthetic fstat failure'), { code: 'EIO' });
      return observed.fdStats === 1 ? before : after;
    },
    read: async (buffer, start, length, position) => {
      observed.reads++; assert.equal(position, null);
      if (options.readError) throw Object.assign(new Error('synthetic read failure'), { code: 'EIO' });
      if (options.bytesRead !== undefined) return { bytesRead: options.bytesRead };
      const bytesRead = Math.min(length, Math.max(0, contents.length - offset), options.chunkBytes ?? Infinity);
      contents.copy(buffer, start, offset, offset + bytesRead); offset += bytesRead;
      return { bytesRead };
    },
    close: async () => { observed.closes++; },
  };
  const owned = async target => {
    assert.equal(target, file); observed.pathChecks++;
    return observed.pathChecks === 1 ? selected : reobserved;
  };
  const open = async (target, flags) => {
    observed.opens++; assert.equal(target, file);
    assert.equal(flags, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (options.openError) throw Object.assign(new Error('synthetic open failure'), { code: 'EIO' });
    return handle;
  };
  const countedBuffer = { alloc: size => {
    observed.allocations.push(size); const bytes = Buffer.alloc(size); observed.buffers.push(bytes); return bytes;
  } };
  class CountedDecoder {
    constructor(...args) { this.decoder = new TextDecoder(...args); }
    decode(...args) { observed.decodes++; return this.decoder.decode(...args); }
  }
  const start = managerSource.indexOf('export async function readBoundedText(');
  const end = managerSource.indexOf('\nasync function json(', start);
  assert(start >= 0 && end > start);
  const source = managerSource.slice(start, end).replace(/^export /, '');
  const fn = vm.runInNewContext(`(${source})`, {
    owned, open, constants, uid, Buffer: countedBuffer, TextDecoder: CountedDecoder,
    fail: (code, text) => { throw Object.assign(new Error(text), { code }); },
  });
  return { read: (maximum = 64, code = 'record_limit') => fn(file, maximum, code), fn, file, observed };
}

test('oversized selected stat is refused before open, allocation, read or decoding', async () => {
  const f = scriptedReader({ selected: { size: 65 } });
  await assert.rejects(f.read(), { code: 'record_limit' });
  assert.equal(f.observed.opens, 0); assert.deepEqual(f.observed.allocations, []);
  assert.equal(f.observed.reads, 0); assert.equal(f.observed.decodes, 0);
});

test('oversized descriptor stat is refused before allocation/read and closes descriptor', async () => {
  const f = scriptedReader({ before: { size: 65 } });
  await assert.rejects(f.read(), { code: 'record_limit' });
  assert.deepEqual(f.observed.allocations, []); assert.equal(f.observed.reads, 0);
  assert.equal(f.observed.closes, 1); assert.equal(f.observed.decodes, 0);
});

test('selected-to-descriptor replacement refuses before allocation or read', async () => {
  const f = scriptedReader({ before: { ino: 999 } });
  await assert.rejects(f.read(), { code: 'record_changed' });
  assert.deepEqual(f.observed.allocations, []); assert.equal(f.observed.reads, 0);
  assert.equal(f.observed.closes, 1);
});

test('short partial reads complete without exceeding the bounded allocation', async () => {
  const f = scriptedReader({ chunkBytes: 2 }); assert.equal(await f.read(), '{"ok":true}');
  assert.deepEqual(f.observed.allocations, [12]);
  assert(f.observed.reads > 2); assert.equal(f.observed.decodes, 1); assert.equal(f.observed.closes, 1);
  assert(f.observed.buffers.every(bytes => bytes.every(byte => byte === 0)), 'Temporary byte buffer is zeroed');
});

test('EOF before the selected size refuses without decoding and wipes the bounded buffer', async () => {
  const f = scriptedReader({ selected: { size: 12 } });
  await assert.rejects(f.read(), { code: 'record_changed' });
  assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
  assert(f.observed.buffers[0].every(byte => byte === 0));
});

test('growth byte beyond selected size refuses without decoding and wipes the buffer', async () => {
  const f = scriptedReader({ selected: { size: 10 } });
  await assert.rejects(f.read(), { code: 'record_changed' });
  assert.deepEqual(f.observed.allocations, [11]); assert.equal(f.observed.decodes, 0);
  assert.equal(f.observed.closes, 1); assert(f.observed.buffers[0].every(byte => byte === 0));
});

for (const [key, value] of [['dev', 2], ['ino', 3], ['mode', 0o100644], ['nlink', 2], ['size', 12], ['mtimeMs', 101], ['ctimeMs', 101]]) {
  test(`descriptor ${key} drift refuses before decoding`, async () => {
    const f = scriptedReader({ after: { [key]: value } });
    await assert.rejects(f.read(), { code: 'record_changed' });
    assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
    assert(f.observed.buffers[0].every(byte => byte === 0));
  });
  test(`path ${key} drift refuses before decoding`, async () => {
    const f = scriptedReader({ reobserved: { [key]: value } });
    await assert.rejects(f.read(), { code: 'record_changed' });
    assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
  });
}

for (const [name, properties, code] of [
  ['owner change', { uid: 99 }, 'unsafe_path'],
  ['nonregular replacement', { isFile: () => false }, 'unsafe_path'],
  ['group-writable replacement', { mode: 0o100620 }, 'unsafe_permissions'],
  ['lost link identity', { nlink: 0 }, 'unsafe_path'],
  ['post-read oversized growth', { size: 65 }, 'record_limit'],
]) {
  test(`post-read ${name} refuses before decoding`, async () => {
    const f = scriptedReader({ reobserved: properties });
    await assert.rejects(f.read(), { code });
    assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
  });
}

for (const bytesRead of [-1, 1.5, Infinity, NaN, 65]) {
  test(`invalid read byte count ${String(bytesRead)} refuses and closes`, async () => {
    const f = scriptedReader({ bytesRead });
    await assert.rejects(f.read(), { code: 'record_changed' });
    assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
    assert(f.observed.buffers[0].every(byte => byte === 0));
  });
}

for (const failure of ['statError', 'readError']) {
  test(`${failure} preserves refusal and closes any acquired descriptor`, async () => {
    const f = scriptedReader({ [failure]: true });
    await assert.rejects(f.read(), { code: 'EIO' });
    assert.equal(f.observed.decodes, 0); assert.equal(f.observed.closes, 1);
    assert(f.observed.buffers.every(bytes => bytes.every(byte => byte === 0)));
  });
}

test('malformed UTF-8 source bytes refuse and wipe/close after decoder failure', async () => {
  const f = scriptedReader({ contents: Buffer.from([0xff]) });
  await assert.rejects(f.read(), { code: 'record_encoding' });
  assert.equal(f.observed.decodes, 1); assert.equal(f.observed.closes, 1);
  assert(f.observed.buffers[0].every(byte => byte === 0));
});

for (const [name, file, maximum, code] of [
  ['missing file', undefined, 64, 'record_limit'], ['nonstring file', {}, 64, 'record_limit'],
  ['empty file', '', 64, 'record_limit'], ['zero budget', '/synthetic/owned-record', 0, 'record_limit'],
  ['negative budget', '/synthetic/owned-record', -1, 'record_limit'],
  ['fractional budget', '/synthetic/owned-record', 1.5, 'record_limit'],
  ['unbounded budget', '/synthetic/owned-record', Infinity, 'record_limit'],
  ['oversized budget', '/synthetic/owned-record', 16 * MiB + 1, 'record_limit'],
  ['arbitrary failure code', '/synthetic/owned-record', 64, 'unreviewed'],
]) {
  test(`reader refuses ${name} before any filesystem observation`, async () => {
    const f = scriptedReader(); await assert.rejects(f.fn(file, maximum, code), { code: 'record_input' });
    assert.equal(f.observed.pathChecks, 0); assert.equal(f.observed.opens, 0);
    assert.deepEqual(f.observed.allocations, []);
  });
}
