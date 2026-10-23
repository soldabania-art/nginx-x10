#!/usr/bin/env node
// Optimization only: ambiguity runs both profiles. Never prints event contents.
// GitHub PR path filters use the whole three-dot diff, not a synchronize delta.
// https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#git-diff-comparisons
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SHA = /^[0-9a-f]{40}$/;
const MAX_BYTES = 1024 * 1024;
const MAX_FILES = 10000;
const SHARED = new Set(['.github/scripts/x10-change-scope.mjs', '.github/scripts/x10-change-scope.test.mjs']);
const commit = value => typeof value === 'string' && SHA.test(value) && !/^0+$/.test(value);
const runBoth = reason => ({ native: true, research: true, reason, changedFiles: null, sourceSha: null });

export function refsForEvent(eventName, event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  if (eventName === 'push') {
    if (!commit(event.before) || !commit(event.after) || event.before === event.after) return null;
    return { before: event.before, after: event.after, base: null };
  }
  if (eventName !== 'pull_request') return null;
  const base = event.pull_request?.base?.sha, head = event.pull_request?.head?.sha;
  if (!commit(base) || !commit(head)) return null;
  if (event.action === 'synchronize') {
    if (!commit(event.before) || !commit(event.after) || event.after !== head || event.before === event.after) return null;
    return { before: event.before, after: event.after, base };
  }
  if (['opened', 'reopened', 'ready_for_review'].includes(event.action) && base !== head) {
    return { before: base, after: head, base: null };
  }
  return null;
}

export function scopeForPaths(paths) {
  if (!Array.isArray(paths) || paths.length > MAX_FILES) return runBoth('invalid_path_list');
  let native = false, research = false, bytes = 0;
  for (const name of paths) {
    if (typeof name !== 'string' || name.length === 0 || name.startsWith('/') || /[\\\x00-\x1f\x7f]/.test(name)
      || name.split('/').some(part => !part || part === '.' || part === '..')) return runBoth('invalid_path_list');
    bytes += Buffer.byteLength(name) + 1;
    if (bytes > MAX_BYTES) return runBoth('invalid_path_list');
    if (SHARED.has(name)) { native = true; research = true; continue; }
    if (name === '.github/workflows/x10-native.yml') native = true;
    if (name === '.github/workflows/x10-continuum.yml') research = true;
    if (/^(src|auto|conf)\//.test(name)) native = true;
    if (name.startsWith('x10/continuum/')) {
      if (name !== 'x10/continuum/BACKGROUND.json' && !/^x10\/continuum\/[^/]+\.md$/.test(name)) research = true;
    } else if (name.startsWith('x10/')) native = true;
  }
  return { native, research, reason: 'classified_delta', changedFiles: paths.length, sourceSha: null };
}

function git(args) {
  return execFileSync('git', args, { timeout: 10000, maxBuffer: MAX_BYTES, stdio: ['ignore', 'pipe', 'pipe'] });
}

export function classifyChange({ eventName, event, executeGit = git }) {
  try {
    const refs = refsForEvent(eventName, event);
    if (!refs) return runBoth('unavailable_event_refs');
    // A changed/divergent PR base can change the tested merge even when the
    // latest head delta is metadata. Do not optimize that ambiguous case.
    if (refs.base) executeGit(['merge-base', '--is-ancestor', refs.base, refs.before]);
    const raw = executeGit(['diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-only', '-z', refs.before, refs.after, '--']);
    if (!(raw instanceof Uint8Array) || raw.byteLength > MAX_BYTES) return runBoth('invalid_git_output');
    let paths;
    if (raw.byteLength === 0) paths = [];
    else {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
      if (!text.endsWith('\0')) return runBoth('invalid_git_output');
      paths = text.slice(0, -1).split('\0');
    }
    return { ...scopeForPaths(paths), sourceSha: refs.after };
  } catch { return runBoth('event_or_git_unavailable'); }
}

export function readEvent(file) {
  try {
    const info = statSync(file);
    if (!info.isFile() || info.size > MAX_BYTES) return null;
    const bytes = readFileSync(file);
    if (bytes.length > MAX_BYTES) return null;
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { return null; }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = process.argv.length === 2
    ? classifyChange({ eventName: process.env.GITHUB_EVENT_NAME, event: readEvent(process.env.GITHUB_EVENT_PATH) })
    : runBoth('unexpected_arguments');
  // Only literal booleans are written; filenames/payloads never become outputs.
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT,
    `native=${result.native}\nresearch=${result.research}\n`);
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, suite: 'x10-ci-source-scope', ...result })}\n`);
}
