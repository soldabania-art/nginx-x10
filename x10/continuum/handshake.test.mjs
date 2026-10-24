import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, access } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runHandshake } from './handshake.mjs';

for (const scenario of ['unknown-ca', 'wrong-hostname', 'tls12-only', 'cipher-mismatch', 'alpn-mismatch']) {
  test(`real TLS rejects ${scenario} before application bytes`, { timeout: 30000 }, async () => {
    const report = await runHandshake({ scenario });
    assert.equal(report.outcome, 'rejected');
    assert.equal(report.rejectedBeforeApplication, true);
    assert.equal(report.clientApplicationBytesWritten, 0);
    assert.equal(report.clientApplicationBytesRead, 0);
  });
}

async function limit(promise, milliseconds, label) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(label)), milliseconds); })]); }
  finally { clearTimeout(timer); }
}
async function exists(path) { try { await access(path); return true; } catch { return false; } }
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } }

for (const interruption of ['SIGTERM', 'SIGINT']) {
  test(`${interruption} during actual native listening reaps child and removes private PKI`, { timeout: 30000 }, async () => {
    const control = await mkdtemp(join(tmpdir(), 'x10-c1-interruption-control-'));
    const runs = join(control, 'runs');
    await mkdir(runs, { mode: 0o700 });
    const preload = join(control, 'hold-native-ready.mjs');
    // Private instrumentation observes actual C readiness, then withholds that
    // stdout event from the runner so the signal reaches a live, stable point.
    // No public checkpoint option is added to the fixture API.
    await writeFile(preload, `
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { dirname } from 'node:path';
const original = childProcess.spawn;
childProcess.spawn = function(command, args, options) {
  const child = original.call(this, command, args, options);
  if (Array.isArray(args) && args.includes('--challenge')) {
    const originalEmit = child.stdout.emit;
    let text = '';
    let sent = false;
    child.stdout.emit = function(event, ...values) {
      if (event === 'data') {
        text += values[0].toString('utf8');
        if (!sent && text.includes('\\n')) {
          const first = JSON.parse(text.slice(0, text.indexOf('\\n')));
          if (first.event === 'listening') {
            sent = true;
            process.send({ kind: 'native-listening', pid: child.pid, port: first.port,
              directory: dirname(args[args.indexOf('--cert') + 1]) });
          }
        }
        return true;
      }
      return originalEmit.call(this, event, ...values);
    };
  }
  return child;
};
syncBuiltinESMExports();
`, { mode: 0o600 });
    const runner = fileURLToPath(new URL('./handshake.mjs', import.meta.url));
    let child;
    let checkpoint;
    let output = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    try {
      child = spawn(process.execPath, ['--import', preload, runner], {
        env: { ...process.env, NODE_OPTIONS: '', TMPDIR: runs }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      });
      const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
      child.on('error', () => {});
      child.stdout.on('data', chunk => { stdoutBytes += chunk.length; });
      child.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes <= 8192) output += chunk.toString('utf8'); });
      checkpoint = await limit(new Promise((resolve, reject) => {
        child.once('error', () => reject(new Error('interruption subprocess start failed')));
        child.once('close', () => reject(new Error('interruption subprocess ended before native readiness')));
        child.on('message', message => { if (message?.kind === 'native-listening') resolve(message); });
      }), 15000, 'native readiness checkpoint timeout');
      assert.ok(Number.isInteger(checkpoint.pid) && checkpoint.pid > 1, 'native child identity missing');
      assert.ok(Number.isInteger(checkpoint.port) && checkpoint.port > 0 && checkpoint.port <= 65535, 'native port missing');
      assert.ok(typeof checkpoint.directory === 'string' && dirname(checkpoint.directory) === runs, 'private directory ownership invalid');
      assert.ok(await exists(join(checkpoint.directory, 'leaf.key')), 'native readiness lacks actual private key');
      assert.ok(alive(checkpoint.pid), 'native child not alive at checkpoint');
      child.kill(interruption);
      const exit = await limit(closed, 6000, 'handled interruption did not exit');
      assert.equal(exit.code, interruption === 'SIGTERM' ? 143 : 130);
      assert.equal(exit.signal, null);
      assert.ok(stdoutBytes === 0 && stderrBytes <= 8192, 'unexpected interruption output size');
      let report;
      try { report = JSON.parse(output.trim()); } catch { throw new Error('interruption output invalid'); }
      assert.equal(report.reason, 'fixture_interrupted');
      assert.ok(!alive(checkpoint.pid), 'native child remains after handled interruption');
      assert.ok(!(await exists(checkpoint.directory)), 'private fixture directory remains after interruption');
      const probe = createServer();
      try {
        await limit(new Promise((resolve, reject) => { probe.once('error', reject); probe.listen(checkpoint.port, '127.0.0.1', resolve); }), 2000, 'owned listener was not released');
      } finally { if (probe.listening) await new Promise(resolve => probe.close(resolve)); }
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      if (checkpoint?.pid && alive(checkpoint.pid)) process.kill(checkpoint.pid, 'SIGKILL');
      await rm(control, { recursive: true, force: true });
    }
  });
}

for (const keyUpdate of [false, true]) {
  test(`real C/OpenSSL TLS1.3 handshake and authenticated record audit, KeyUpdate=${keyUpdate}`, { timeout: 30000 }, async () => {
    const report = await runHandshake({ keyUpdate, payloadBytes: keyUpdate ? 4097 : 257 });
    assert.equal(report.outcome, 'pass');
    assert.deepEqual(report.negotiated, { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', alpn: 'continuum-c1', authorized: true });
    assert.equal(report.resumed, false);
    assert.equal(report.freshChallenge, true);
    assert.equal(report.clientConnections, 1);
    assert.equal(report.serverConnections, 1);
    assert.equal(report.migrationImplemented, false);
    assert.equal(report.openSSLStateExportImport, false);
    assert.equal(report.nativeNginxIntegration, false);
    assert.match(report.identity.serverSourceSha256, /^[a-f0-9]{64}$/);
    assert.match(report.identity.serverBinarySha256, /^[a-f0-9]{64}$/);
    assert.match(report.identity.nodeBinarySha256, /^[a-f0-9]{64}$/);
  });
}
