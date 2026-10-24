#!/usr/bin/env node
// Bounded local test aggregate. Raw TAP can contain private in-memory TLS fixture state,
// so this command emits only constant scope labels, counts and exit facts.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MAX_OUTPUT_BYTES = 512 * 1024;
const DEADLINE_MS = 650000;
const STOP_GRACE_MS = 4000;

function countsFromTap(tap) {
  if (!/^TAP version 13\r?$/m.test(tap)) return null;
  const plans = [...tap.matchAll(/^1\.\.([0-9]+)\r?$/gm)];
  const roots = [...tap.matchAll(/^(ok|not ok) ([0-9]+) - (.+)\r?$/gm)];
  if (plans.length !== 1 || roots.length === 0 || Number(plans[0][1]) !== roots.length
    || roots.some((r, i) => r[1] !== 'ok' || Number(r[2]) !== i + 1
      || /(?:^|[/\\])openssl-probe\.test\.mjs$/.test(r[3].trim()))) return null;
  const counts = {};
  for (const label of ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...tap.matchAll(new RegExp(`^# ${label} ([0-9]+)\\r?$`, 'gm'))];
    if (matches.length !== 1) return null;
    const value = Number(matches[0][1]);
    if (!Number.isSafeInteger(value) || value < 0) return null;
    counts[label] = value;
  }
  // The owned suite is deliberately flat. A forged/incomplete footer must
  // not inflate the actual top-level assertions observed above.
  if (counts.suites !== 0 || counts.tests !== roots.length) return null;
  return counts;
}

async function run() {
  const report = {
    schemaVersion: 1, suite: 'continuum-pinned-openssl-state-probe', passed: false,
    testFiles: 1, scope: 'pinned-openssl-read-only-state-observation', nativeNginxMigration: false, realSessionMigration: false,
    counts: null, exitCode: null, signal: null, timedOut: false,
    outputLimitExceeded: false, interrupted: false, runnerError: null,
  };
  if (process.argv.length !== 2) {
    report.runnerError = 'unexpected_arguments';
    return report;
  }
  const tests = ['openssl-probe.test.mjs'].map(name => fileURLToPath(new URL(name, import.meta.url)));
  let child, exit, deadline, escalation, outputBytes = 0, output = '';
  const stop = () => {
    if (!child?.pid || exit) return;
    try { process.kill(-child.pid, 'SIGTERM'); }
    catch (error) { if (error.code !== 'ESRCH') report.runnerError ||= 'child_stop_failed'; }
    if (!escalation) escalation = setTimeout(() => {
      if (exit) return;
      try { process.kill(-child.pid, 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') report.runnerError ||= 'child_stop_failed'; }
    }, STOP_GRACE_MS);
  };
  const interrupt = () => { report.interrupted = true; stop(); };
  process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
  try {
    child = spawn(process.execPath, ['--test', '--test-reporter=tap', '--test-concurrency=1', '--test-timeout=600000', ...tests], {
      detached: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_OPTIONS: '' },
    });
    const collect = chunk => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) { report.outputLimitExceeded = true; stop(); }
      else output += chunk.toString('utf8');
    };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    deadline = setTimeout(() => { report.timedOut = true; stop(); }, DEADLINE_MS);
    exit = await new Promise(resolve => {
      child.once('error', () => { report.runnerError ||= 'child_spawn_failed'; resolve({ code: null, signal: null }); });
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    report.exitCode = exit.code; report.signal = exit.signal;
    report.counts = countsFromTap(output);
    if (!report.counts) report.runnerError ||= 'tap_summary_missing_or_ambiguous';
    const c = report.counts;
    report.passed = exit.code === 0 && exit.signal === null && !report.timedOut
      && !report.outputLimitExceeded && !report.interrupted && report.runnerError === null
      && c !== null && c.tests > 0 && c.pass === c.tests
      && c.fail === 0 && c.cancelled === 0 && c.skipped === 0 && c.todo === 0;
  } catch {
    report.runnerError ||= 'runner_failed';
    stop();
  } finally {
    clearTimeout(deadline); clearTimeout(escalation);
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
  }
  return report;
}

const report = await run();
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.passed ? 0 : 1;
