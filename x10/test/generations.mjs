#!/usr/bin/env node
// Master bookkeeping identity, not listener-close or readiness acknowledgment.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runControlApi } from './control-api-baseline.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const decimal = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);

function valid(data, master) {
  assert.equal(data.scope, 'master-process'); assert.equal(data.master_pid, master.pid);
  assert.equal(data.available, true); assert.equal(data.reason, ''); assert(decimal(data.current_generation));
  assert.equal(data.excluded_detached, 0); assert(Array.isArray(data.processes) && data.processes.length >= 2);
  const births = new Set(), slots = new Set(), pids = new Set();
  for (const p of data.processes) {
    assert.equal(p.name, 'worker process'); assert(Number.isSafeInteger(p.pid) && p.pid > 1);
    assert(Number.isSafeInteger(p.slot) && p.slot >= 0 && p.slot < 1024);
    assert(decimal(p.birth) && decimal(p.generation)); assert.equal(typeof p.exiting, 'boolean'); assert.equal(typeof p.exited, 'boolean');
    assert(BigInt(p.generation) <= BigInt(data.current_generation));
    assert(!births.has(p.birth) && !slots.has(p.slot) && !pids.has(p.pid), 'Birth, slot and PID must be unique within snapshot');
    births.add(p.birth); slots.add(p.slot); pids.add(p.pid);
  }
  return data;
}

export async function runGenerations({ binary, source = root, transport = 'tcp', reference = false }) {
  const before = hash(await readFile(fileURLToPath(import.meta.url)));
  const report = await runControlApi({ binary, source, transport, suite: 'native-control-generations', expectedCases: reference ? 3 : 10,
    exercise: async ctx => {
      const { report, api, master, add, revision, replace } = ctx;
      report.mode = reference ? 'reference-absence' : 'candidate';
      report.limitations.push('Generation/birth are master bookkeeping within one externally verified master lifetime; no worker readiness or listener-close ACK.');
      const get = async () => { const r = await api('/1/control/generations'); assert.equal(r.status, 200); return valid(r.json, master); };
      if (reference) {
        const missing = await api('/1/control/generations'); assert.equal(missing.status, 404); assert.equal(missing.body, '');
        report.observations.referenceAbsence = { expectedStatus: 404, actualStatus: missing.status, missingCapability: true };
        add('pristine-reference-explicitly-lacks-generation-endpoint'); return;
      }
      const initial = await get(); assert.equal(initial.current_generation, '1');
      assert.equal(initial.processes.length, 2); assert(initial.processes.every(p => p.generation === '1' && !p.exiting && !p.exited));
      for (const p of initial.processes) await ctx.resolveWorker(p.pid);
      report.observations.initialGeneration = initial;
      add('initial-master-generation-one-and-unique-process-births');
      const held = ctx.hold(); assert.equal(await held.first, 'first:control-old\n'); assert.equal(held.revision, 'api-a');
      const old = initial.processes.find(p => p.pid === held.workerPid); assert(old);
      const oldIdentity = await ctx.resolveWorker(old.pid);
      process.stderr.write(`Generation fixture old response held: master=${master.pid} worker=${held.workerPid}\n`);
      await replace('api-b'); const reload = await api('/1/control/config', 'PATCH'); assert.equal(reload.status, 200);
      await ctx.until(() => revision('api-b'), 'revision B after control reload');
      const second = await ctx.until(async () => {
        const d = await get(); assert.equal(d.current_generation, '2');
        const prior = d.processes.find(p => p.birth === old.birth); assert(prior && prior.pid === old.pid && prior.generation === '1' && prior.exiting);
        assert.equal(d.processes.filter(p => p.generation === '2' && !p.exiting && !p.exited).length, 2); return d;
      }, 'old and new generation metadata after PATCH');
      assert.equal(held.ended, false); await ctx.sameProcess(oldIdentity); report.observations.afterPatch = second;
      add('successful-control-reload-advances-generation-preserving-old-drain-identity');
      await replace('api-invalid', true); const badPatch = await api('/1/control/config', 'PATCH');
      assert.equal(badPatch.status, 422); assert(badPatch.json.logs.some(line => line.includes('unknown directive "x10_api_deliberately_invalid"')));
      const rejectedPatch = await get(); assert.equal(rejectedPatch.current_generation, '2'); await revision('api-b');
      report.observations.rejectedPatch = { status: badPatch.status, generation: rejectedPatch.current_generation };
      add('rejected-control-reload-does-not-advance-generation');
      await replace('api-c'); await ctx.hup(); await ctx.until(() => revision('api-c'), 'revision C after HUP');
      const third = await ctx.until(async () => {
        const d = await get(); assert.equal(d.current_generation, '3'); assert.equal(d.processes.filter(p => p.generation === '3' && !p.exiting && !p.exited).length, 2);
        const prior = d.processes.find(p => p.birth === old.birth); assert(prior && prior.pid === old.pid && prior.generation === '1'); return d;
      }, 'generation after SIGHUP');
      assert.equal(held.ended, false); await ctx.sameProcess(oldIdentity); report.observations.afterHup = third;
      add('successful-signal-reload-advances-generation-with-old-response-held');
      const beforeLog = await readFile(path.join(ctx.prefix, 'error.log'), 'utf8');
      await replace('api-invalid', true); await ctx.hup();
      await ctx.until(async () => (await readFile(path.join(ctx.prefix, 'error.log'), 'utf8')).slice(beforeLog.length).includes('unknown directive "x10_api_deliberately_invalid"'), 'actual rejected HUP log');
      const rejectedHup = await get(); assert.equal(rejectedHup.current_generation, '3'); await revision('api-c');
      report.observations.rejectedHup = { generation: rejectedHup.current_generation, actualRejectionLogged: true };
      await replace('api-c'); add('rejected-signal-reload-does-not-advance-generation');
      const victim = rejectedHup.processes.find(p => p.generation === '3' && !p.exiting && !p.exited); assert(victim);
      const victimIdentity = await ctx.resolveWorker(victim.pid);
      report.observations.expectedWorkerTermination = { pid: victim.pid, birth: victim.birth, slot: victim.slot, signal: 9 };
      await ctx.killWorker(victimIdentity);
      const respawned = await ctx.until(async () => {
        const d = await get(); assert.equal(d.current_generation, '3');
        const replacement = d.processes.find(p => p.slot === victim.slot && p.pid !== victim.pid && p.birth !== victim.birth && p.generation === '3' && !p.exiting && !p.exited);
        assert(replacement); assert(BigInt(replacement.birth) > BigInt(victim.birth));
        assert(!d.processes.some(p => p.birth === victim.birth));
        return { snapshot: d, replacement };
      }, 'same-generation worker respawn with new birth and reused slot');
      await ctx.resolveWorker(respawned.replacement.pid); await revision('api-c');
      report.observations.respawn = { victim, victimIdentity, ...respawned };
      add('real-worker-respawn-retains-generation-and-reuses-slot-with-new-birth');
      const legacy = await api('/1/control/processes'); assert.equal(legacy.status, 200);
      for (const p of legacy.json) assert.deepEqual(Object.keys(p).sort(), ['exiting', 'name', 'pid']);
      for (const method of ['PATCH', 'POST']) assert.equal((await api('/1/control/generations', method)).status, 405);
      report.observations.readOnlyLegacyCompatibility = { legacyProcesses: legacy.json, rejectedMethods: ['PATCH', 'POST'] };
      add('generation-endpoint-is-read-only-and-legacy-process-schema-is-unchanged');
      assert.equal(held.ended, false); await ctx.sameProcess(oldIdentity); ctx.release();
      const body = await held.done; assert.equal(body, 'first:control-old\nlast:control-old\n');
      const final = await get(); assert.equal(final.current_generation, '3');
      report.observations.completedOldResponse = { body, generation: final.current_generation };
      add('old-generation-response-completes-after-reloads-and-current-worker-respawn');
    } });
  report.identity.fixtureSha256 = report.identity.harnessSha256;
  report.identity.fixtureUnchangedDuringTest = report.identity.harnessUnchangedDuringTest;
  report.identity.harnessSha256 = before;
  report.identity.harnessUnchangedDuringTest = hash(await readFile(fileURLToPath(import.meta.url))) === before;
  report.success &&= report.identity.harnessUnchangedDuringTest;
  return report;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  let binary = process.env.X10_NGINX_BINARY || path.join(root, 'x10/.build/objs/nginx'), source = root, transport = 'tcp', output, reference = false;
  try {
    for (let i = 2; i < process.argv.length; i++) {
      const option = process.argv[i]; if (option === '--reference') { reference = true; continue; }
      if (!['--binary', '--source', '--transport', '--output'].includes(option) || !process.argv[i + 1]) throw new Error(`Unknown/incomplete option ${option}`);
      const value = process.argv[++i];
      if (option === '--binary') binary = value; else if (option === '--source') source = value; else if (option === '--transport') transport = value; else output = path.resolve(value);
    }
    const result = await runGenerations({ binary, source, transport, reference }); const text = JSON.stringify(result, null, 2) + '\n';
    if (output) await writeFile(output, text, { mode: 0o600 }); process.stdout.write(text); process.exitCode = result.success ? 0 : 1;
  } catch (error) {
    process.stdout.write(JSON.stringify({ schemaVersion: 1, suite: 'native-control-generations', success: false, tests: [], skips: [], error: error.message }) + '\n'); process.exitCode = 1;
  }
}
