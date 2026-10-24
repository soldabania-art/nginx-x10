import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assessManagerQuery, main, QUERY_MAX_BYTES, QUERY_TIMEOUT_MS } from './preflight.mjs';
const execute = promisify(execFile), cli = fileURLToPath(new URL('./preflight.mjs', import.meta.url));
const uid = 1001;
const text = (state = 'running') => `Version=255.4-1ubuntu8.17\nSystemState=${state}\nControlGroup=/user.slice/user-${uid}.slice/user@${uid}.service\n`;
const record = stdout => ({ exitCode: 0, signal: null, stdout, stderr: '', timedOut: false, outputLimitExceeded: false });
function refused(value, code) { assert.equal(value.managerAvailable, false); if (code) assert.equal(value.code, code); assert.doesNotMatch(JSON.stringify(value), /Version=|ControlGroup=|\/run\/|user-1001|private-diagnostic/); }

test('exit0 stub baseline overclaims a manager while strict transcript refuses', () => {
  const stub = record('\n"systemd" is not running in this container due to its overhead.\nUse the "service" command to start services instead.\n');
  assert.equal(stub.exitCode === 0, true); refused(assessManagerQuery(stub, uid), 'manager_response_invalid');
});
test('synthetic running manager accepts only narrowly scoped manager properties', () => {
  assert.deepEqual(assessManagerQuery(record(text()), uid), { managerAvailable: true, managerState: 'running', managerDegraded: false, managerVersion: '255.4-1ubuntu8.17' });
});
test('synthetic degraded manager is available without claiming health', () => {
  const r = assessManagerQuery(record(text('degraded')), uid); assert.equal(r.managerAvailable, true); assert.equal(r.managerDegraded, true); assert.equal(r.managerState, 'degraded'); assert.equal(r.serviceAccepted, undefined);
});
test('property order is irrelevant but complete exact keys are required', () => {
  const rows = text().trimEnd().split('\n'); assert.equal(assessManagerQuery(record(rows.reverse().join('\n') + '\n'), uid).managerAvailable, true);
});
for (const [name, stdout] of [
  ['missing', 'Version=255\nSystemState=running\n'],
  ['duplicate', text() + 'Version=255\n'], ['unknown', text() + 'Extra=value\n'],
  ['blank-line', text() + '\n'], ['no-final-newline', text().trimEnd()],
  ['empty-value', text().replace('Version=255.4-1ubuntu8.17', 'Version=')],
  ['carriage-return', text().replace('\n', '\r\n')], ['tab', text().replace('255.', '255\t.')],
  ['nul', text() + '\0'], ['unicode', text().replace('255.', 'é255.')],
  ['system-manager', text().replace(`/user.slice/user-${uid}.slice/user@${uid}.service`, '/')],
  ['other-uid', text().replaceAll(String(uid), '1002')],
  ['init-scope-child', text().replace('.service\n', '.service/init.scope\n')],
  ['relative-cgroup', text().replace('=/user.slice', '=user.slice')],
  ['starting-state', text('starting')], ['maintenance-state', text('maintenance')],
  ['offline-state', text('offline')], ['malformed-version', text().replace('255.4-1ubuntu8.17', 'systemd 255')],
  ['long-version', text().replace('255.4-1ubuntu8.17', '255.' + 'a'.repeat(128))],
]) test(`synthetic transcript refuses ${name}`, () => refused(assessManagerQuery(record(stdout), uid), 'manager_response_invalid'));
for (const [name, changes, code] of [
  ['nonzero', { exitCode: 1 }, 'manager_unavailable'],
  ['signal', { exitCode: null, signal: 'SIGTERM' }, 'manager_unavailable'],
  ['timeout', { timedOut: true }, 'query_timeout'],
  ['output-overflow', { outputLimitExceeded: true }, 'query_output_limit'],
  ['stderr', { stderr: 'private-diagnostic' }, 'manager_response_invalid'],
  ['stdout-overflow', { stdout: 'x'.repeat(QUERY_MAX_BYTES + 1) }, 'query_output_limit'],
  ['combined-overflow', { stderr: 'x'.repeat(QUERY_MAX_BYTES) }, 'query_output_limit'],
  ['string-timeout', { timedOut: 'true' }, 'query_invalid'],
  ['missing-overflow-flag', { outputLimitExceeded: undefined }, 'query_invalid'],
  ['buffer-stdout', { stdout: Buffer.from(text()) }, 'query_invalid'],
]) test(`query failure ${name} never returns raw diagnostics`, () => refused(assessManagerQuery({ ...record(text()), ...changes }, uid), code));
test('root, invalid and unsafe integer UID transcripts refuse', () => {
  for (const value of [0, -1, 1.5, NaN, Infinity, '1001', undefined, 4294967295]) refused(assessManagerQuery(record(text()), value), 'query_invalid');
});
test('CLI rejects all options before any probe and returns fixed nonacceptance flags', async () => {
  for (const argv of [['--help'], ['--uid', '1001'], ['--systemctl', '/bin/false'], ['--machine', 'remote'], null]) {
    const r = await main(argv); refused(r, 'usage_invalid'); assert.equal(r.probeExecuted, false); assert.equal(r.serviceActivated, false); assert.equal(r.serviceAccepted, false); assert.equal(r.productionAccepted, false);
  }
});
test('actual local CLI reports only a bounded prerequisite observation', async () => {
  let r;
  try { r = await execute(process.execPath, [cli], { timeout: 5000, maxBuffer: 32768 }); }
  catch (error) { assert.equal(error.code, 1); r = error; }
  assert.equal(r.stderr, ''); const x = JSON.parse(r.stdout);
  assert.equal(x.serviceActivated, false); assert.equal(x.serviceAccepted, false); assert.equal(x.productionAccepted, false);
  assert.equal(x.scope, 'user-manager-readonly-preflight'); assert.doesNotMatch(r.stdout, /\/run\/|\/usr\/|ControlGroup=|DBUS_SESSION/);
  console.log(JSON.stringify({ suite: 'service-preflight-live-observation', nonroot: typeof process.getuid === 'function' && process.getuid() !== 0, managerAvailable: x.managerAvailable, probeExecuted: x.probeExecuted, reason: x.code ?? null, serviceAccepted: x.serviceAccepted, productionAccepted: x.productionAccepted }));
  if (process.platform === 'linux' && process.getuid?.() === 0) { assert.equal(x.code, 'nonroot_required'); assert.equal(x.probeExecuted, false); assert.equal(x.ok, false); }
});

// A separate child with explicit test-only hooks models metadata and a manager
// reply. It performs no systemctl execution, D-Bus query, unit installation or
// service activation. Production CLI has no hook/UID/executable arguments.
async function simulatedCLI(mode, fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'x10-preflight-test-'));
  try {
    const hook = path.join(dir, 'hook.mjs');
    const source = `import fs from 'node:fs/promises';\nimport cp from 'node:child_process';\nimport {syncBuiltinESMExports} from 'node:module';\nimport assert from 'node:assert/strict';\nprocess.getuid=()=>1001;process.geteuid=()=>${mode === 'uid-mismatch' ? '1002' : '1001'};\nconst ancestors=['/','/usr','/usr/bin','/run','/run/user'];\nfs.realpath=async p=>p;\nfs.lstat=async p=>({uid:p==='/usr/bin/systemctl'||ancestors.includes(p)?0:1001,mode:p==='/usr/bin/systemctl'?0o100755:p.endsWith('/bus')?0o140666:ancestors.includes(p)?0o40755:0o40700,isFile:()=>p==='/usr/bin/systemctl',isDirectory:()=>p!=='/usr/bin/systemctl'&&!p.endsWith('/bus'),isSocket:()=>p.endsWith('/bus')});\ncp.execFile=(file,args,options,done)=>{assert.equal(file,'/usr/bin/systemctl');assert.deepEqual(args,['--user','show','--no-pager','--no-ask-password','--property=Version','--property=SystemState','--property=ControlGroup']);assert.equal(options.timeout,2500);assert.equal(options.maxBuffer,16384);assert.equal(options.killSignal,'SIGKILL');assert.equal(options.cwd,'/');assert.deepEqual(options.env,{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',XDG_RUNTIME_DIR:'/run/user/1001',DBUS_SESSION_BUS_ADDRESS:'unix:path=/run/user/1001/bus'});queueMicrotask(()=>done(${mode === 'timeout' ? "Object.assign(new Error('private-diagnostic'),{killed:true,signal:'SIGKILL'})" : mode === 'overflow' ? "Object.assign(new Error('private-diagnostic'),{code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'})" : 'null'},${JSON.stringify(mode === 'stub' ? 'not a manager\n' : text())},''));return {};};\nsyncBuiltinESMExports();\n`;
    await writeFile(hook, source, { mode: 0o600 });
    await fn(async () => {
      try { return { exitCode: 0, ...await execute(process.execPath, ['--import', pathToFileURL(hook).href, cli], { timeout: 5000, maxBuffer: 32768, env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: 'tcp:host=do-not-contact.invalid', XDG_RUNTIME_DIR: '/untrusted/runtime' } }) }; }
      catch (e) { if (!Number.isInteger(e.code)) throw e; return { exitCode: e.code, stdout: e.stdout, stderr: e.stderr }; }
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
}
for (const mode of ['positive', 'stub', 'timeout', 'overflow', 'uid-mismatch']) test(`synthetic CLI ${mode} confines read-only query and returns no service acceptance`, () => simulatedCLI(mode, async run => {
  const r = await run(); assert.equal(r.stderr, ''); const x = JSON.parse(r.stdout);
  assert.equal(x.serviceActivated, false); assert.equal(x.serviceAccepted, false); assert.equal(x.productionAccepted, false); assert.doesNotMatch(r.stdout, /do-not-contact|untrusted|private-diagnostic|\/run\/|\/usr\//);
  if (mode === 'positive') { assert.equal(r.exitCode, 0); assert.equal(x.ok, true); assert.equal(x.managerAvailable, true); }
  else { assert.equal(r.exitCode, 1); assert.equal(x.ok, false); assert.equal(x.code, { stub: 'manager_response_invalid', timeout: 'query_timeout', overflow: 'query_output_limit', 'uid-mismatch': 'uid_mismatch' }[mode]); }
}));
test('CLI alias still performs refusal and cannot silently exit success', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'x10-preflight-alias-'));
  try { const alias = path.join(dir, 'probe.mjs'); await symlink(cli, alias); await assert.rejects(execute(process.execPath, [alias, '--bad'], { timeout: 5000, maxBuffer: 32768 }), e => e.code === 1 && JSON.parse(e.stdout).code === 'usage_invalid'); }
  finally { await rm(dir, { recursive: true, force: true }); }
});
