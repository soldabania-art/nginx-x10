#!/usr/bin/env node
// No dependency installation during tests. The Python client uses actual UDP/H3.
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../../', import.meta.url));
const python = process.env.X10_HTTP3_HEAD_PYTHON || path.join(root, 'x10/.build/http3-head-venv/bin/python');
try {
  await access(python, constants.X_OK);
  const child = spawn(python, [path.join(root, 'x10/test/http3-head.py'), ...process.argv.slice(2)],
    { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let interrupted = false;
  let hardKill, bytes = 0;
  const stdout = [], stderr = [];
  const kill = signal => {
    if (!child.pid) return;
    try { process.kill(-child.pid, signal); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  };
  const stop = signal => {
    if (interrupted) return;
    interrupted = true;
    try { child.kill(signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    hardKill = setTimeout(() => kill('SIGKILL'), 5500);
  };
  const sigint = () => stop('SIGINT');
  const sigterm = () => stop('SIGTERM');
  process.on('SIGINT', sigint);
  process.on('SIGTERM', sigterm);
  const collect = target => value => {
    bytes += value.length;
    if (bytes > 2 * 1024 * 1024) stop('SIGTERM');
    else if (target === stderr) process.stderr.write(value);
    else target.push(value);
  };
  child.stdout.on('data', collect(stdout));
  child.stderr.on('data', collect(stderr));
  const deadline = setTimeout(() => stop('SIGTERM'), 60_000);
  const exit = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  }).finally(() => {
    clearTimeout(deadline);
    if (hardKill) clearTimeout(hardKill);
    process.removeListener('SIGINT', sigint);
    process.removeListener('SIGTERM', sigterm);
  });
  // The Python/native children share this one owned group. Clear descendants
  // even if the interpreter exits unexpectedly before its cleanup handler.
  kill('SIGKILL');
  const text = Buffer.concat(stdout).toString('utf8');
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    process.stdout.write(text);
    process.exitCode = exit.code ?? 1;
  } else {
    const result = JSON.parse(text);
    if (result.suite !== 'native-http3-head-interop' || typeof result.success !== 'boolean')
      throw new Error('Interpreter returned an invalid HTTP3 fixture result');
    process.stdout.write(text);
    process.exitCode = !interrupted && exit.code === 0 && !exit.signal && result.success ? 0 : 1;
  }
} catch (error) {
  process.stdout.write(JSON.stringify({ schemaVersion: 1, suite: 'native-http3-head-interop', success: false,
    tests: [], skips: [], error: `HTTP3 test client unavailable: ${error.message}. Install the pinned lock as documented in x10/test/http3-head.md.` }) + '\n');
  process.exitCode = 1;
}
