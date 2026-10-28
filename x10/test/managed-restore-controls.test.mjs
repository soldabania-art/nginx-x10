import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { digest } from '../alpha/runtime.mjs';
import { assessRestoredHTTPPreparation } from '../service/lifecycle-check.mjs';

// These pure cross-record controls exercise the assessor consumed by the real
// managed-service fixture. They start no daemon, invoke no service manager and
// grant no process, unit, readiness or cleanup authority.
const sourceId = 'a'.repeat(32), sourceSession = 'b'.repeat(32), sourceRevision = 'c'.repeat(32);
const installationId = 'd'.repeat(32), session = 'e'.repeat(32), revisionId = 'f'.repeat(32);
const prefix = '/fixture/restored';
const proofKeys = ['freshInstallation', 'freshSession', 'freshRevision', 'exactInputRestored',
  'portsPreserved', 'bindingInitiallyAbsent', 'freshHistory'];
const input = () => ({ serverBody: 'location / { proxy_pass http://127.0.0.1:18082; }',
  healthURL: 'http://127.0.0.1:18082/ready', healthExpectedStatus: 200, healthExpectedBody: 'ready\n' });

function fixture() {
  const original = input(), inputSha256 = digest(JSON.stringify(original));
  const source = { installationId: sourceId, session: sourceSession, revision: sourceRevision,
    input: structuredClone(original), inputSha256, port: 18080, healthPort: 18081 };
  const backupBody = { schemaVersion: 1, kind: 'nginx-x10-declarative-backup',
    source: { installationId: sourceId, session: sourceSession, revision: sourceRevision },
    port: 18080, healthPort: 18081, input: structuredClone(original), inputSha256 };
  const backup = { ...backupBody, sha256: digest(JSON.stringify(backupBody)) };
  const restoredRevision = { id: revisionId, parent: null, sourceRevision: null,
    input: structuredClone(original), inputSha256 };
  const restored = { prefix,
    manifest: { prefix, installationId, port: 18080, healthPort: 18081 },
    registry: { schemaVersion: 1, installationId, current: session, sessions: [session] },
    lifecycle: { installationId, session, prefix: `${prefix}/runs/${session}`,
      stage: 'prepared', runtime: null, controlSocket: null },
    revision: { ...restoredRevision, recordSha256: digest(JSON.stringify(restoredRevision)) },
    status: { binding: null, pending: null, configUnchanged: true,
      fragmentMatchesLastConfirmed: true, lastConfirmedRevision: revisionId,
      history: { entries: 1, integrity: true } },
    history: { records: [{ sequence: 1, previousHash: null, type: 'initialized_unbound',
      details: { revision: revisionId } }] } };
  return { source, backup, restored };
}

function run(f) { return assessRestoredHTTPPreparation(f.source, f.backup, f.restored); }
function rehashBackup(f) {
  const { sha256, ...body } = f.backup;
  f.backup.sha256 = digest(JSON.stringify(body));
}
function refusal(f) {
  assert.throws(() => run(f), error => {
    assert.equal(error.code, 'restored_http_unconfirmed');
    assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE|\/fixture\//);
    return true;
  });
}

test('restored HTTP preparation accepts fresh related records without runtime authority', () => {
  const f = fixture(), before = structuredClone(f), proof = run(f);
  assert.deepEqual(Object.keys(proof), proofKeys);
  assert(Object.values(proof).every(value => value === true));
  assert.equal(Object.hasOwn(proof, 'serviceAccepted'), false);
  assert.equal(Object.hasOwn(proof, 'productionAccepted'), false);
  assert.equal(Object.hasOwn(proof, 'runtime'), false);
  assert.deepEqual(f, before, 'Assessment preserves source, backup and target records');
});

for (const [name, mutate] of [
  ['source installation', f => { f.backup.source.installationId = installationId; rehashBackup(f); }],
  ['source session', f => { f.backup.source.session = session; rehashBackup(f); }],
  ['source revision', f => { f.backup.source.revision = revisionId; rehashBackup(f); }],
  ['source input hash', f => { f.source.inputSha256 = '0'.repeat(64); }],
  ['source input bytes', f => { f.source.input.healthExpectedBody = 'SYNTHETIC_PRIVATE\n'; }],
  ['backup checksum', f => { f.backup.sha256 = '0'.repeat(64); }],
  ['backup input hash', f => { f.backup.inputSha256 = '0'.repeat(64); rehashBackup(f); }],
  ['self-consistent different backup input', f => { f.backup.input.healthExpectedBody = 'other\n'; f.backup.inputSha256 = digest(JSON.stringify(f.backup.input)); rehashBackup(f); }],
  ['backup gateway port', f => { f.backup.port++; rehashBackup(f); }],
  ['backup health port', f => { f.backup.healthPort++; rehashBackup(f); }],
  ['reused installation', f => { f.restored.manifest.installationId = sourceId; f.restored.registry.installationId = sourceId; f.restored.lifecycle.installationId = sourceId; }],
  ['reused session', f => { f.restored.registry.current = sourceSession; f.restored.registry.sessions = [sourceSession]; f.restored.lifecycle.session = sourceSession; f.restored.lifecycle.prefix = `${prefix}/runs/${sourceSession}`; }],
  ['reused revision', f => { f.restored.revision.id = sourceRevision; f.restored.status.lastConfirmedRevision = sourceRevision; }],
  ['registry installation mismatch', f => { f.restored.registry.installationId = sourceId; }],
  ['registry current mismatch', f => { f.restored.registry.current = sourceSession; }],
  ['borrowed historical sessions', f => { f.restored.registry.sessions.push(sourceSession); }],
  ['duplicate current session', f => { f.restored.registry.sessions.push(session); }],
  ['lifecycle installation mismatch', f => { f.restored.lifecycle.installationId = sourceId; }],
  ['lifecycle session mismatch', f => { f.restored.lifecycle.session = sourceSession; }],
  ['lifecycle prefix mismatch', f => { f.restored.lifecycle.prefix = '/fixture/source'; }],
  ['running lifecycle', f => { f.restored.lifecycle.stage = 'running'; }],
  ['retained runtime identity', f => { f.restored.lifecycle.runtime = { pid: 123 }; }],
  ['retained control socket', f => { f.restored.lifecycle.controlSocket = '/fixture/source/control.sock'; }],
  ['target gateway port', f => { f.restored.manifest.port++; }],
  ['target health port', f => { f.restored.manifest.healthPort++; }],
  ['restored input hash', f => { f.restored.revision.inputSha256 = '0'.repeat(64); }],
  ['restored input bytes', f => { f.restored.revision.input.healthExpectedBody = 'SYNTHETIC_PRIVATE\n'; }],
  ['borrowed revision parent', f => { f.restored.revision.parent = sourceRevision; }],
  ['borrowed revision source', f => { f.restored.revision.sourceRevision = sourceRevision; }],
  ['borrowed live binding', f => { f.restored.status.binding = { pid: 123 }; }],
  ['pending operation', f => { f.restored.status.pending = { stage: 'reload_requested' }; }],
  ['changed config', f => { f.restored.status.configUnchanged = false; }],
  ['changed managed fragment', f => { f.restored.status.fragmentMatchesLastConfirmed = false; }],
  ['wrong confirmed revision', f => { f.restored.status.lastConfirmedRevision = sourceRevision; }],
  ['borrowed history count', f => { f.restored.status.history.entries = 2; }],
  ['damaged history', f => { f.restored.status.history.integrity = false; }],
  ['absent history integrity', f => { delete f.restored.status.history.integrity; }],
  ['borrowed history records', f => { f.restored.history.records.push({ type: 'bound' }); }],
  ['wrong first history type', f => { f.restored.history.records[0].type = 'bound'; }],
  ['borrowed first history revision', f => { f.restored.history.records[0].details.revision = sourceRevision; }],
  ['wrong first history sequence', f => { f.restored.history.records[0].sequence = 2; }],
  ['retained history predecessor', f => { f.restored.history.records[0].previousHash = '1'.repeat(64); }],
]) test(`restored HTTP preparation refuses ${name}`, () => { const f = fixture(); mutate(f); refusal(f); });

for (const field of ['source', 'backup', 'restored']) test(`restored HTTP preparation refuses absent ${field}`, () => {
  const f = fixture(); f[field] = null; refusal(f);
});

for (const field of ['source', 'backup', 'restored']) {
  test(`restored HTTP preparation refuses extra ${field} authority`, () => {
    const f = fixture(); f[field].liveAuthority = true; refusal(f);
  });
  test(`restored HTTP preparation refuses foreign ${field} prototype`, () => {
    const f = fixture(); Object.setPrototypeOf(f[field], { borrowed: true }); refusal(f);
  });
  test(`restored HTTP preparation refuses ${field} accessors without evaluation`, () => {
    const f = fixture(), key = Object.keys(f[field])[0]; let calls = 0;
    Object.defineProperty(f[field], key, { enumerable: true, get() { calls++; throw new Error('SYNTHETIC_PRIVATE'); } });
    refusal(f); assert.equal(calls, 0);
  });
}

test('restored HTTP preparation refuses nested identity accessors without evaluation', () => {
  const f = fixture(); let calls = 0;
  Object.defineProperty(f.restored.manifest, 'installationId', {
    enumerable: true, get() { calls++; return installationId; },
  });
  refusal(f); assert.equal(calls, 0);
});

test('restored HTTP preparation refuses history integrity accessors without evaluation', () => {
  const f = fixture(); let calls = 0;
  Object.defineProperty(f.restored.status.history, 'integrity', {
    enumerable: true, get() { calls++; return true; },
  });
  refusal(f); assert.equal(calls, 0);
});

test('restored HTTP preparation refuses TLS input even with consistent hashes', () => {
  const f = fixture();
  f.source.input.https = { certificate: '/fixture/cert', certificateKey: '/fixture/key' };
  f.source.inputSha256 = digest(JSON.stringify(f.source.input));
  f.backup.input = structuredClone(f.source.input); f.backup.inputSha256 = f.source.inputSha256; rehashBackup(f);
  f.restored.revision.input = structuredClone(f.source.input); f.restored.revision.inputSha256 = f.source.inputSha256;
  refusal(f);
});

for (const selected of ['source', 'backup', 'revision']) for (const key of ['serverBody', 'toJSON']) {
  test(`restored HTTP preparation refuses ${selected} input ${key} accessor without evaluation`, () => {
    const f = fixture(), value = selected === 'revision' ? f.restored.revision.input : f[selected].input;
    let calls = 0;
    Object.defineProperty(value, key, { enumerable: true,
      get() { calls++; throw new Error('SYNTHETIC_PRIVATE'); } });
    refusal(f); assert.equal(calls, 0);
  });
}

// Virtual adapters execute the actual marked orchestration and retirement
// functions. Process, filesystem, manager and traffic observations are synthetic;
// these controls cannot establish that a real service started or was cleaned up.
const serviceSource = await readFile(new URL('../service/lifecycle-check.mjs', import.meta.url), 'utf8');
const retireStart = serviceSource.indexOf('  async function retireStoppedRuntimeUnit() {');
const restoreStart = serviceSource.indexOf('  // Restored managed HTTP acceptance.');
const restoreEnd = serviceSource.indexOf('  // End restored managed HTTP acceptance.');
assert(retireStart >= 0 && restoreStart > retireStart && restoreEnd > restoreStart);
const orchestration = serviceSource.slice(retireStart, restoreStart) + serviceSource.slice(restoreStart, restoreEnd);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

async function virtualOrchestration(options = {}) {
  const f = fixture(), parent = '/fixture/work', oldPrefix = `${parent}/install`, target = `${parent}/restored-http`;
  const restartSession = '1'.repeat(32), restartRevision = '2'.repeat(32), events = [];
  f.restored.prefix = target; f.restored.manifest.prefix = target;
  f.restored.lifecycle.prefix = `${target}/runs/${session}`;
  const makeRevision = id => {
    const body = { id, parent: null, sourceRevision: null, input: structuredClone(f.source.input), inputSha256: f.source.inputSha256 };
    return { ...body, recordSha256: digest(JSON.stringify(body)) };
  };
  const revisions = new Map([[sourceRevision, makeRevision(sourceRevision)], [revisionId, makeRevision(revisionId)], [restartRevision, makeRevision(restartRevision)]]);
  const sourcePrefix = `${oldPrefix}/runs/${sourceSession}`, backupFile = `${parent}/confirmed-http-backup.json`;
  const backupBytes = Buffer.from(JSON.stringify(f.backup)), archive = Buffer.from('synthetic archive');
  const sourceFiles = new Map([
    [`${oldPrefix}/.alpha-install.json`, { prefix: oldPrefix, installationId: sourceId, port: 18080, healthPort: 18081 }],
    [`${oldPrefix}/.alpha-registry.json`, { installationId: sourceId, current: sourceSession, sessions: [sourceSession] }],
    [`${sourcePrefix}/lifecycle.json`, { installationId: sourceId, session: sourceSession, prefix: sourcePrefix, stage: 'stopped', runtime: { pid: 123 } }],
    [`${sourcePrefix}/.x10-control/state.json`, { activeRevision: sourceRevision }],
    [`${sourcePrefix}/.x10-control/history.jsonl`, { type: 'bound' }],
    [`${sourcePrefix}/.x10-control/revisions/${sourceRevision}.json`, revisions.get(sourceRevision)],
  ]);
  const step = name => { events.push(name); if (options.failAt === name) throw Object.assign(new Error('virtual refusal'), { code: 'virtual_refusal' }); };
  const deps = {
    f, options, parent, oldPrefix, target, sourcePrefix, sourceSession, restartSession, restartRevision, session, revisionId,
    sourceRevision, sourceFiles, revisions, backupFile, backupBytes, archive, events, step, digest, assessRestoredHTTPPreparation,
    TOKEN: /^[a-f0-9]{32}$/,
    reject: code => { throw Object.assign(new Error(code), { code }); },
  };
  const run = new AsyncFunction(...Object.keys(deps), String.raw`
    let prefix=oldPrefix, launcher=prefix+'/bin/x10', node='/fixture/node', env={}, unitName='source.service',
      runtimeLink='/fixture/runtime/source.service', unitFile='/fixture/source.service', linked=true, installed=true,
      startRequested=true, failedStartup={}, lastSession=sourceSession, retainedHTTPSource=null, appEchoRequests=2,
      serviceStage=0, sourceLinkRemoved=false, verifying=false;
    const gatewayPort=18080,healthPort=18081,input={archive:'/fixture/archive.tar.gz',sha256:digest(archive)};
    const sessions=[{id:sourceSession,prefix:sourcePrefix,identity:{pid:123}}],launcherIdentities=[{pid:124}];
    const report={nativeSessionsStopped:0,phase:'restore_http',runtimeUnitRemoved:false,
      restoredHTTPProof:{},cleanup:{runtimeLinkAbsent:false}};
    function checkCancelled(){step('cancel');}
    async function stopOwned(){step('stop');if(options.stopReplay)appEchoRequests++;}
    async function checkedRecord(file){step('record:'+file);
      if(sourceFiles.has(file))return structuredClone(sourceFiles.get(file));
      if(file===target+'/.alpha-install.json')return structuredClone(f.restored.manifest);
      if(file===target+'/.alpha-registry.json')return structuredClone(f.restored.registry);
      if(file===target+'/runs/'+session+'/lifecycle.json')return structuredClone(f.restored.lifecycle);
      throw Error('unexpected virtual record');}
    async function interruptionFile(file,json=true){step('file:'+file);
      if(file===backupFile)return {value:structuredClone(f.backup),bytes:verifying&&options.corruptBackup?Buffer.from('changed'):backupBytes};
      if(sourceFiles.has(file)){const value=sourceFiles.get(file);return {value:structuredClone(value),bytes:verifying&&options.corruptSource?Buffer.from('changed'):Buffer.from(JSON.stringify(value))};}
      const id=/\/revisions\/([a-f0-9]{32})\.json$/.exec(file)?.[1];
      if(revisions.has(id))return {value:structuredClone(revisions.get(id)),bytes:Buffer.from(JSON.stringify(revisions.get(id)))};
      throw Error('unexpected virtual file');}
    async function cli(node,selected,args){step('cli:'+args[0]);
      if(selected===oldPrefix+'/bin/x10'&&args[0]==='status')return {pending:null,configUnchanged:true,
        fragmentMatchesLastConfirmed:true,history:{integrity:true},lastConfirmedRevision:sourceRevision};
      if(args[0]==='backup'){if(options.backupReplay)appEchoRequests++;return {outcome:'declarative_backup_created',
        nativeStarted:false,serviceAccepted:false,productionAccepted:false,sha256:digest(backupBytes)};}
      if(args[0]==='install'){if(options.installFailure)throw Object.assign(Error('virtual install refusal'),{code:'virtual_install_refused'});
        if(options.installReplay)appEchoRequests++;return {declarativeRestored:true,nativeStarted:false,readinessChecked:false,
          serviceAccepted:false,productionAccepted:false,session,revision:revisionId};}
      if(args[0]==='history')return structuredClone(f.restored.history);
      if(args[0]==='status'&&serviceStage===0)return structuredClone(f.restored.status);
      if(args[0]==='status')return {lastConfirmedRevision:serviceStage===1?revisionId:restartRevision,
        runtime:{observedRevision:revisionId,identityValid:true},binding:{pid:321},pending:null};
      throw Error('unexpected virtual command');}
    async function lstat(file){step('backup-mode');return{mode:0o100600};}
    async function ownedProperties(){step('unit-inactive');return{ActiveState:options.activeSourceUnit?'active':'inactive',MainPID:'0',Result:'success'};}
    async function exitedLauncher(){step('source-launcher-absence');return !options.sourceLauncherLive;}
    async function nativeStopped(value){step('source-native-absence');if(value.prefix!==sourcePrefix)throw Error('old inventory reinterpreted');return !options.sourceNativeLive;}
    async function closedPort(){step('port-closed');return !options.openSourcePort;}
    async function absent(file){step('absent:'+file);return file.endsWith('control.sock')?!options.sourceSocketLive:sourceLinkRemoved;}
    async function linkAuthority(){step('link-authority');}
    async function rm(file){step('remove-source-link');if(file!=='/fixture/runtime/source.service')throw Error('foreign virtual link');sourceLinkRemoved=true;}
    async function systemctl(args){step('manager:'+args[0]);return{ok:!options.reloadFailure};}
    async function properties(){step('unit-not-found');return{LoadState:options.sourceUnitRetained?'loaded':'not-found',ActiveState:'inactive',MainPID:'0'};}
    async function prepareOwnedRuntimeUnit(){step('prepare-target-unit');
      if(!sourceLinkRemoved||sessions.length||launcherIdentities.length||prefix!==target)throw Error('unretired source inventory');
      unitName=options.reusedUnit?'source.service':'restored.service';runtimeLink='/fixture/runtime/restored.service';linked=true;}
    async function startAndServe(){step('start-target');serviceStage=1;lastSession=session;
      appEchoRequests+=options.startReplay?2:1;sessions.push({id:session,prefix:target+'/runs/'+session,identity:{pid:321}});}
    async function restartAndServe(){step('restart-target');serviceStage=2;lastSession=options.reusedRestartSession?session:restartSession;
      appEchoRequests+=options.restartReplay?2:1;sessions.push({id:lastSession,prefix:target+'/runs/'+lastSession,identity:{pid:322}});}
    async function ownedInvocation(){step('invocation');return{};}
    async function verifyJournalForInvocation(){step('journal');}
    async function archiveBytes(){step('archive');return options.corruptArchive?Buffer.from('changed'):archive;}
    ${orchestration}
    let error=null;try{await restoreConfirmedHTTPService();verifying=true;
      if(options.lateReplay)appEchoRequests++;await verifyRetainedHTTPSource();
    }catch(e){error=e.code||'unexpected_virtual_error';}
    return{error,prefix,installed,linked,sessionCount:sessions.length,launcherCount:launcherIdentities.length,
      sourceLinkRemoved,appEchoRequests,report,retained:!!retainedHTTPSource,
      retainedSourceRecords:retainedHTTPSource?.records.length,
      retainedBackupMatched:retainedHTTPSource?.backupBytes?.equals(backupBytes)===true,events};
  `);
  return run(...Object.values(deps));
}

test('virtual actual restore orchestration retires source before switching identities and sending two POSTs', async () => {
  const r = await virtualOrchestration(); assert.equal(r.error, null);
  assert(r.events.indexOf('unit-not-found') < r.events.indexOf('cli:install'));
  assert(r.events.indexOf('cli:install') < r.events.indexOf('prepare-target-unit'));
  assert(r.events.indexOf('prepare-target-unit') < r.events.indexOf('start-target'));
  assert(r.events.indexOf('start-target') < r.events.indexOf('restart-target'));
  assert.equal(r.appEchoRequests, 4);
  for (const name of ['sourceUnitRemoved', 'restoredHTTPServed', 'restoredHTTPRestarted', 'sourceRecordsPreserved', 'backupPreserved', 'archivePreserved']) assert.equal(r.report.restoredHTTPProof[name], true);
  assert.equal(r.report.serviceAccepted, undefined);
});

for (const [option, code] of [
  ['activeSourceUnit', 'unit_stop_unconfirmed'], ['sourceLauncherLive', 'native_cleanup_unknown'],
  ['sourceNativeLive', 'native_cleanup_unknown'], ['openSourcePort', 'service_resources_live'],
  ['sourceSocketLive', 'service_resources_live'], ['reloadFailure', 'unit_reload_failed'],
  ['sourceUnitRetained', 'unit_removal_unconfirmed'],
]) test(`virtual actual source retirement refuses ${option} before clearing source inventory`, async () => {
  const r = await virtualOrchestration({ [option]: true }); assert.equal(r.error, code);
  assert.equal(r.prefix, '/fixture/work/install'); assert.equal(r.sessionCount, 1); assert.equal(r.launcherCount, 1);
  assert.equal(r.events.includes('cli:install'), false); assert.equal(r.events.includes('start-target'), false);
});

for (const option of ['stopReplay', 'backupReplay', 'installReplay', 'startReplay', 'restartReplay', 'lateReplay', 'reusedUnit', 'reusedRestartSession', 'corruptSource', 'corruptBackup', 'corruptArchive']) {
  test(`virtual actual restored flow refuses ${option}`, async () => {
    const r = await virtualOrchestration({ [option]: true }); assert.equal(r.error, 'restored_http_unconfirmed');
    assert.equal(r.report.restoredHTTPProof.sourceRecordsPreserved, undefined);
  });
}

test('virtual unknown restore install retains source records and backup capture without manufacturing success', async () => {
  const r = await virtualOrchestration({ installFailure: true }); assert.equal(r.error, 'virtual_install_refused');
  assert.equal(r.retained, true); assert.equal(r.sourceLinkRemoved, true); assert.equal(r.installed, false);
  assert.equal(r.retainedSourceRecords, 6); assert.equal(r.retainedBackupMatched, true);
  assert.equal(r.events.includes('start-target'), false); assert.equal(r.report.restoredHTTPProof.restoredHTTPServed, undefined);
});
