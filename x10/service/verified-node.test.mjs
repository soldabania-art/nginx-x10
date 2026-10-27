import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, symlink, readdir, lstat, unlink, rmdir, readFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { PIN, MANAGED_PACKAGE_CLEANUP_SOURCE, FALLBACK_PACKAGE_CLEANUP_SOURCE, parseTar, parseChecksumText, parseSignatureStatus, cleanupEvidence, main } from './verified-node.mjs';
const hash = b => createHash('sha256').update(b).digest('hex');
const nodeMember = `${PIN.root}/bin/node`, licenseMember = `${PIN.root}/LICENSE`;
function member(name, data = Buffer.from('SYNTHETIC_NONEXECUTABLE'), type = '0', mode = 0o755, link = '') {
  const h = Buffer.alloc(512); h.write(name, 0, 100, 'ascii');
  for (const [off, len, val] of [[100, 8, mode], [108, 8, 0], [116, 8, 0], [124, 12, data.length], [136, 12, 0]]) h.write(val.toString(8).padStart(len - 1, '0') + '\0', off, len, 'ascii');
  h.fill(32, 148, 156); h[156] = type.charCodeAt(0); h.write(link, 157, 100, 'ascii'); h.write('ustar\0', 257); h.write('00', 263);
  h.write([...h].reduce((a,b) => a+b, 0).toString(8).padStart(6,'0') + '\0 ', 148);
  return Buffer.concat([h, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}
const tar = (...members) => Buffer.concat([...members, Buffer.alloc(1024)]);
const good = () => tar(member(nodeMember), member(licenseMember, Buffer.from('public license'), '0', 0o644));
const status = () => `[GNUPG:] PLAINTEXT 74 0 \n[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED ${PIN.fingerprint} 0\n[GNUPG:] SIG_ID public 2026-09-23 1790183910\n[GNUPG:] GOODSIG 20B1A390B168D356 Public Signer\n[GNUPG:] VALIDSIG ${PIN.fingerprint} 2026-09-23 1790183910 0 4 0 22 8 01 ${PIN.fingerprint}\n`;
// Public synthetic observations only. This fixture grants no process authority.
function managedPackageProof() {
  const digest=label=>hash(`public-synthetic-managed-return:${label}`);
  const a={runtimePayloadSha256:digest('a'),operatorPayloadSha256:digest('a-operator'),nativeBinarySha256:digest('native')};
  const b={runtimePayloadSha256:digest('b'),operatorPayloadSha256:digest('b-operator'),nativeBinarySha256:a.nativeBinarySha256};
  const p=digest('input-p'),q=digest('input-q');
  const stopped=()=>({unitInactive:true,invocationRetired:true,launcherExited:true,masterAbsent:true,
    nativeGroupsAbsent:true,portsClosed:true,controlSocketAbsent:true,operatorLocksAbsent:true,pendingAbsent:true,
    runtimeLinkAbsent:true,unitNotFound:true});
  return {schemaVersion:1,kind:'nginx-x10-managed-operator-package-return-proof',
    packages:{a,b,a2:{...a}},inputs:{pSha256:p,qSha256:q,a2RestoredSha256:q},
    phases:['a_started','a_served','a_stopped','b_staged','b_started','b_initial_p_observed','b_q_applied',
      'b_served','b_restart_started','b_restarted_served','b_stopped','a2_restored','a2_started','a2_served','a2_stopped','cleanup'],
    legs:['a','b','b_restart','a2'].map((name,i)=>({name,identityOrdinals:{installation:[1,2,2,3][i],unit:[1,2,2,3][i],
      session:i+1,revision:i+1,binding:i+1,invocation:i+1},inputSha256:i===0?p:q,initialBindingAbsent:i===2?null:true,
      readinessAccepted:true,bindingMatchesOwnedRuntime:true,getExact:true,postExact:true,streamExact:true,
      postEffectsBefore:i,postEffectsAfter:i+1})),
    transitions:{beforeB:stopped(),beforeA2:stopped()},
    restart:{commandExercised:true,oldLauncherExited:true,oldMasterAbsent:true,oldNativeGroupsAbsent:true,
      oldInvocationRetired:true,freshSession:true,freshBinding:true,freshInvocation:true,sameUnit:true,samePackage:true,inputPreserved:true,unitActive:true},
    retention:{retainedAAllFilesPreserved:true,retainedABackupPreserved:true,oldAInstallerRestoredQ:true,bInitialPObservedBeforeQ:true},
    counts:{units:3,invocations:4,restarts:1,journalChecks:5,trafficGets:4,posts:4,streams:4,bInitialPGetChecks:1},
    cleanup:{known:true,ownedProcessesAbsent:true,ownedLaunchersAbsent:true,ownedListenersClosed:true,
      ownedUnitsRemoved:3,ownedInstallationsRemoved:3,historicalBundleRemoved:true,backupFilesRemoved:true},
    limits:{consistencyOnly:true,nativeBinaryUpgradeAccepted:false,liveConnectionPreserved:false,
      applicationSideEffectsReversed:false,productionAccepted:false,automaticMigrationAccepted:false,
      allTrafficFenceAccepted:false,restartPreparedBindingObserved:false}};
}
function managedPackageReport() {
  return { schemaVersion:2,kind:'nginx-x10-managed-operator-return-report',ok:true,
    code:'managed_operator_return_verified',phase:'complete',proof:managedPackageProof(),
    primaryFailure:null,
    cleanupFailures:[],cleanupFailureCount:0,cleanupFailuresTruncated:false,
    serviceAccepted:false,productionAccepted:false,subprocessOutputsPublished:false };
}
// Independent public synthetic fallback observations; never actual runtime proof.
function fallbackPackageReport() {
  const digest=label=>hash(`public-synthetic-node-fallback:${label}`);
  const a={runtimePayloadSha256:digest('a'),operatorPayloadSha256:digest('a-operator'),nativeBinarySha256:digest('native')};
  const b={runtimePayloadSha256:digest('b'),operatorPayloadSha256:digest('b-operator'),nativeBinarySha256:a.nativeBinarySha256};
  const input=digest('input-p');
  const facts=keys=>Object.fromEntries(keys.map(key=>[key,true]));
  const stopped=()=>facts(['unitInactive','invocationRetired','launcherExited','masterAbsent','nativeGroupsAbsent',
    'portsClosed','controlSocketAbsent','operatorLocksAbsent','pendingAbsent','runtimeLinkAbsent','unitNotFound']);
  return {schemaVersion:1,kind:'nginx-x10-managed-operator-fallback-report',ok:true,
    code:'managed_operator_fallback_verified',phase:'complete',primaryFailure:null,
    cleanupFailures:[],cleanupFailureCount:0,cleanupFailuresTruncated:false,
    serviceAccepted:false,productionAccepted:false,subprocessOutputsPublished:false,
    proof:{schemaVersion:1,kind:'nginx-x10-managed-operator-package-fallback-proof',
      packages:{a,b,aFallback:{...a}},inputs:{pSha256:input,bStagedSha256:input,aFallbackSha256:input},
      phases:['a_started','a_served','a_stopped','b_staged','b_start_requested','b_failed','b_retired',
        'a_retention_verified','a_prepared','a_reactivated','a_fallback_served','a_fallback_stopped','cleanup'],
      legs:['a','a_fallback'].map((name,index)=>({name,
        identityOrdinals:{installation:1,unit:index?3:1,session:index?3:1,revision:index?3:1,binding:index?2:1,invocation:index?3:1},
        inputSha256:input,initialBindingAbsent:true,readinessAccepted:true,bindingMatchesOwnedRuntime:true,
        getExact:true,postExact:true,streamExact:true,postEffectsBefore:index,postEffectsAfter:index+1})),
      failedB:{identityOrdinals:{installation:2,unit:2,session:2,revision:2,invocation:2},
        ...facts(['readinessHeld','activatingLauncherCaptured','nativeCaptured','invocationCaptured','hookCaptured',
          'wrongBodyObserved','managerRefused','hookExitObserved','bindingAbsent','noPOSTEffects','failedSessionStopped',
          'launcherExited','nativeGroupsAbsent','listeningPortsClosed','controlSocketAbsent','operatorLocksAbsent',
          'managerResetConfirmed','runtimeLinkAbsent','unitNotFound'])},
      transitions:{beforeB:stopped(),afterFallback:stopped()},
      preparation:facts(['freshSession','freshRevision','nullInitialBinding','inputPPreserved','registryTwoSessions',
        'oldSessionPreservedStopped','oneFreshHistoryEntry']),
      retention:facts(['retainedAAllFilesPreservedThroughBFailure','retainedABackupPreserved','keptAPrefixReused',
        'keptAInstallationPreserved','oldAExplicitlyPrepared','oldAInputPreserved']),
      counts:{units:3,installations:2,successfulInvocations:2,failedAttempts:1,restarts:0,journalChecks:2,
        trafficGets:2,posts:2,streams:2},
      cleanup:{known:true,ownedProcessesAbsent:true,ownedLaunchersAbsent:true,ownedListenersClosed:true,
        ownedUnitsRemoved:3,ownedInstallationsRemoved:2,historicalBundleRemoved:true,backupFilesRemoved:true},
      limits:{consistencyOnly:true,nativeBinaryUpgradeAccepted:false,liveConnectionPreserved:false,
        applicationSideEffectsReversed:false,productionAccepted:false,automaticMigrationAccepted:false,
        allTrafficFenceAccepted:false,automaticFallbackAccepted:false}}};
}
function receipt() {
  return { checkerExited:true, checkerExitCode:0,
    fallbackPackageCheckerExited:true,fallbackPackageCheckerExitCode:0,
    sourceFallbackPackageSha256:FALLBACK_PACKAGE_CLEANUP_SOURCE.checkerSha256,
    sourceFallbackPackageProofSha256:FALLBACK_PACKAGE_CLEANUP_SOURCE.proofSha256,
    fallbackPackageReport:fallbackPackageReport(),
    managedPackageCheckerExited:true,managedPackageCheckerExitCode:0,
    sourceManagedPackageSha256:MANAGED_PACKAGE_CLEANUP_SOURCE.checkerSha256,
    sourceManagedPackageProofSha256:MANAGED_PACKAGE_CLEANUP_SOURCE.proofSha256,
    managedPackageReport:managedPackageReport(),
    report:{ ok:true, code:'basic_lifecycle_verified', phase:'complete', actualNonrootManagerObserved:true, actualUnitStarted:true,
    runtimeUnitLinked:true, runtimeUnitRemoved:true, unitEnabled:false,
    bundleSchemaVersion:2, installSchemaVersion:2, installedRecipeGenerated:true,
    readinessAutomated:true, automaticReadinessAccepted:false, failedStartAccepted:false, slowDrainAccepted:false, orphanRecoveryAccepted:false, tlsServiceAccepted:false, serviceAccepted:false, productionAccepted:false, subprocessOutputsPublished:false,
    primaryFailure:null, cleanupFailures:[], cleanupFailureCount:0, cleanupFailuresTruncated:false,
    explicitReadinessPasses:5, nativeSessionsStarted:5, nativeSessionsStopped:5, proxyBodyChecks:5, uploadChecks:5, streamChecks:5,
    managerRestartCommands:2, completedManagerRestarts:2,
    restartProof:{oldLauncherExited:true,oldNativeGroupsAbsent:true,freshSession:true,freshInvocation:true},
    failedStartChecks:1,
    failedStartProof:{unhealthyReadinessObserved:true,managerRefused:true,hookExitObserved:true,bindingAbsent:true,
      launcherExited:true,nativeGroupsAbsent:true,listeningPortsClosed:true,controlSocketAbsent:true,
      failedSessionStopped:true,managerResetConfirmed:true,healthyRestartFresh:true},
    controlledSlowDrainChecks:1,
    controlledSlowDrainProof:{clientPaused:true,originResponseHeld:true,sameSessionObserved:true,managerStopPending:true,
      nativeGroupLiveDuringStop:true,unitDeactivatingObserved:true,incompleteResponseObserved:true,payloadCompleted:true,
      tlsVerified:true,managerStopCompleted:true,launcherExited:true,nativeGroupsAbsent:true,listeningPortsClosed:true,controlSocketAbsent:true},
    operatorInterruptionChecks:1,
    operatorNativeChallengeChecks:1,
    operatorNativeChallengeProof:{nativeRouteObserved:true,ownedRequestObserved:true,relayResponseMatched:true,
      candidateBindingMatched:true,authorityReobservedBeforeSignal:true,ownedChallengeClosed:true},
    operatorInterruptionProof:{candidateProbeHeld:true,pendingReloadObserved:true,lastConfirmedPreserved:true,sameServiceObserved:true,
      ownedOperatorTerminated:true,staleLocksPreserved:true,lockedRecoveryRefused:true,exactLockRemovalConfirmed:true,
      explicitRollbackObserved:true,pendingCleared:true,restoredContentVerified:true,noPostReplay:true,
      sameServiceAfterRecovery:true,repeatedRecoveryIdempotent:true},
    restoredHTTPChecks:1,tlsBackupAccepted:false,packageUpgradeRollbackAccepted:false,
    restoredHTTPProof:{stoppedConfirmedSource:true,privateBackupCreated:true,sourceUnitRemoved:true,freshUnit:true,
      freshInstallation:true,freshSession:true,freshRevision:true,exactInputRestored:true,portsPreserved:true,
      bindingInitiallyAbsent:true,freshHistory:true,restoredHTTPServed:true,restoredHTTPRestarted:true,
      noPostReplay:true,sourceRecordsPreserved:true,backupPreserved:true,archivePreserved:true,sourceInstallationRemoved:true},
    journalChecks:6,journalRecordsObserved:12,journalRunningMarkers:6,
    downstreamTLSActivated:true,downstreamTLSSessionChecks:3,downstreamTLSBodyChecks:6,downstreamTLSUploadChecks:3,downstreamTLSStreamChecks:3,
    downstreamTLS12Checks:3,downstreamTLS13Checks:3,downstreamTLSCertificateChecks:12,downstreamTLSWrongCARefusals:3,downstreamTLSWrongNameRefusals:3,
    upstreamTLSActivated:true,upstreamTLSSessionChecks:3,upstreamTLSBodyChecks:3,upstreamTLSUploadChecks:3,upstreamTLSStreamChecks:3,
    upstreamTLSDirectChecks:1,upstreamTLSWrongCARefusals:1,upstreamTLSWrongNameRefusals:1,upstreamTLSPlaintextRefusals:1,
    upstreamTLSRollbackChecks:3,upstreamTLSCandidate502Checks:3,upstreamTLSNoPostReplayChecks:3,
    cleanup:{ managerStopped:true, launcherExited:true, nativeGroupsAbsent:true, listeningPortsClosed:true, controlSocketAbsent:true, runtimeLinkAbsent:true, installationRemoved:true, temporaryRootRemoved:true, downstreamTLSPortClosed:true, upstreamTLSPortClosed:true, readinessRelayPortClosed:true, upstreamTLSOriginClosed:true, readinessRelayClosed:true, appSocketsRemaining:0 } } };
}
test('legacy service evidence alone cannot authorize private Node cleanup', () => {
  const value=receipt();
  for(const key of ['managedPackageCheckerExited','managedPackageCheckerExitCode',
    'sourceManagedPackageSha256','sourceManagedPackageProofSha256','managedPackageReport'])delete value[key];
  assert.equal(value.report.restoredHTTPProof.restoredHTTPRestarted,true);
  assert.equal(value.report.nativeSessionsStopped,5);assert.equal(value.report.journalChecks,6);
  assert.equal(cleanupEvidence(value),false);
});
test('both managed checker exit and independently frozen source pins are mandatory', () => {
  const invalid={managedPackageCheckerExited:[undefined,false,1,'true'],
    managedPackageCheckerExitCode:[undefined,1,-0,null,'0'],
    sourceManagedPackageSha256:[undefined,'f'.repeat(63),'g'.repeat(64),MANAGED_PACKAGE_CLEANUP_SOURCE.checkerSha256+'\n'],
    sourceManagedPackageProofSha256:[undefined,'f'.repeat(63),'g'.repeat(64),MANAGED_PACKAGE_CLEANUP_SOURCE.proofSha256+'\n']};
  for(const[key,values]of Object.entries(invalid))for(const value of values){
    const e=receipt();e[key]=value;assert.equal(cleanupEvidence(e),false,key);
  }
  assert.equal(cleanupEvidence(receipt()),true);
});
test('managed cleanup envelope requires own enumerable data without evaluating accessors', () => {
  let reads=0;
  for(const key of ['managedPackageCheckerExited','managedPackageCheckerExitCode',
    'sourceManagedPackageSha256','sourceManagedPackageProofSha256','managedPackageReport']){
    const accessor=receipt();Object.defineProperty(accessor,key,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(accessor),false,key);
    const inherited=receipt(),value=inherited[key];delete inherited[key];Object.setPrototypeOf(inherited,{[key]:value});
    assert.equal(cleanupEvidence(inherited),false,key);
    const hidden=receipt();Object.defineProperty(hidden,key,{value:hidden[key],enumerable:false});
    assert.equal(cleanupEvidence(hidden),false,key);
  }
  assert.equal(reads,0);
});
test('managed report must be complete, successful, strict and free of adverse cleanup', () => {
  const mutations=[e=>{delete e.managedPackageReport;},e=>e.managedPackageReport=null,
    e=>e.managedPackageReport.schemaVersion=1,e=>e.managedPackageReport.kind='old-service-report',
    e=>e.managedPackageReport.ok=false,e=>e.managedPackageReport.code='managed_operator_return_refused',
    e=>e.managedPackageReport.phase='a2_started',e=>e.managedPackageReport.proof=null,
    e=>e.managedPackageReport.cleanupFailures=['unknown'],e=>e.managedPackageReport.cleanupFailureCount=1,
    e=>e.managedPackageReport.cleanupFailuresTruncated=true,e=>e.managedPackageReport.serviceAccepted=true,
    e=>e.managedPackageReport.productionAccepted=true,e=>e.managedPackageReport.subprocessOutputsPublished=true,
    e=>e.managedPackageReport.unknown=true,e=>e.managedPackageReport.padding='x'.repeat(12289)];
  for(const mutate of mutations){const e=receipt();mutate(e);assert.equal(cleanupEvidence(e),false);}
});
test('the exact c2 schema1 twelve-field managed report cannot authorize current Node cleanup', () => {
  const e=receipt();e.managedPackageReport.schemaVersion=1;delete e.managedPackageReport.primaryFailure;
  assert.equal(Object.keys(e.managedPackageReport).length,12);
  assert.equal(e.managedPackageReport.ok,true);assert.equal(e.managedPackageReport.proof.counts.invocations,4);
  assert.equal(e.report.restoredHTTPProof.sourceUnitRemoved,true);assert.equal(e.report.nativeSessionsStopped,5);
  assert.equal(cleanupEvidence(e),false);
  const missing=receipt();delete missing.managedPackageReport.primaryFailure;assert.equal(cleanupEvidence(missing),false);
  assert.equal(cleanupEvidence(receipt()),true);
});
test('managed cleanup refuses every non-null primary failure even with success flags and cleanup facts', () => {
  for(const value of [undefined,false,0,'null','controller_state','cleanup_unconfirmed','unknown_failure',
    'SYNTHETIC_PRIVATE_PRIMARY_MUST_NOT_LEAK',{},[],{code:'controller_state'}]){
    const e=receipt();e.managedPackageReport.primaryFailure=value;
    assert.equal(cleanupEvidence(e),false);
  }
});
test('managed primary failure must be own enumerable data and getters are never evaluated', () => {
  let reads=0;
  const accessor=receipt();Object.defineProperty(accessor.managedPackageReport,'primaryFailure',{
    enumerable:true,get(){reads++;return null;}});
  assert.equal(cleanupEvidence(accessor),false);assert.equal(reads,0);
  const inherited=receipt();delete inherited.managedPackageReport.primaryFailure;
  Object.setPrototypeOf(inherited.managedPackageReport,{primaryFailure:null});assert.equal(cleanupEvidence(inherited),false);
  const hidden=receipt();Object.defineProperty(hidden.managedPackageReport,'primaryFailure',{value:null,enumerable:false});
  assert.equal(cleanupEvidence(hidden),false);
});
test('new managed receipt does not relax any exact legacy lifecycle counter', () => {
  for(const[key,value]of [['nativeSessionsStarted',4],['nativeSessionsStopped',4],
    ['managerRestartCommands',1],['completedManagerRestarts',1],['journalChecks',5],
    ['downstreamTLSSessionChecks',2],['upstreamTLSSessionChecks',2]]){
    const e=receipt();e.report[key]=value;assert.equal(cleanupEvidence(e),false,key);
  }
  const e=receipt();e.report.restoredHTTPProof.sourceUnitRemoved=false;assert.equal(cleanupEvidence(e),false);
});
test('managed proof requires the separately declared unit, invocation, restart and journal counts', () => {
  for(const[key,count]of Object.entries(receipt().managedPackageReport.proof.counts))
    for(const value of [undefined,count-1,count+1,String(count),NaN,Infinity]){
      const e=receipt();e.managedPackageReport.proof.counts[key]=value;
      assert.equal(cleanupEvidence(e),false,key);
    }
});
test('one old managed unit, runtime link or process still live retains the private Node', () => {
  for(const transition of ['beforeB','beforeA2'])
    for(const key of Object.keys(receipt().managedPackageReport.proof.transitions[transition])){
      const e=receipt();e.managedPackageReport.proof.transitions[transition][key]=false;
      assert.equal(cleanupEvidence(e),false,`${transition}:${key}`);
    }
  for(const key of Object.keys(receipt().managedPackageReport.proof.restart)){
    const e=receipt();e.managedPackageReport.proof.restart[key]=false;
    assert.equal(cleanupEvidence(e),false,key);
  }
});
test('managed cleanup rejects unknown or incomplete final owned-resource cleanup', () => {
  for(const[key,value]of Object.entries(receipt().managedPackageReport.proof.cleanup)){
    const e=receipt();e.managedPackageReport.proof.cleanup[key]=typeof value==='number'?value-1:false;
    assert.equal(cleanupEvidence(e),false,key);
  }
});
test('active restart intermediate binding absence remains explicitly unobserved', () => {
  for(const value of [undefined,true,false,0,'null']){
    const e=receipt();e.managedPackageReport.proof.legs[2].initialBindingAbsent=value;
    assert.equal(cleanupEvidence(e),false);
  }
  const e=receipt();e.managedPackageReport.proof.limits.restartPreparedBindingObserved=true;
  assert.equal(cleanupEvidence(e),false);
});
test('managed return cannot substitute candidate package bytes or an older declarative input', () => {
  const same=receipt();same.managedPackageReport.proof.packages.a2={...same.managedPackageReport.proof.packages.b};
  assert.equal(cleanupEvidence(same),false);
  const stale=receipt();stale.managedPackageReport.proof.inputs.a2RestoredSha256=stale.managedPackageReport.proof.inputs.pSha256;
  assert.equal(cleanupEvidence(stale),false);
});
test('synthetic tar selection is byte exact and never executes payload', () => {
  const r=parseTar(good()); assert.equal(r.node.toString(),'SYNTHETIC_NONEXECUTABLE'); assert.equal(r.license.toString(),'public license'); assert.deepEqual(Object.keys(r).sort(),['license','node']);
});
test('unknown npm symlinks are skipped, not extracted', () => {
  const r=parseTar(tar(member(`${PIN.root}/bin/npm`, Buffer.alloc(0), '2', 0o777, '../lib/node_modules/npm/bin/npm-cli.js'), member(nodeMember),member(licenseMember)));
  assert.equal(Object.keys(r).length,2);
});
for (const [label, bytes] of [
  ['duplicate selected',tar(member(nodeMember),member(nodeMember),member(licenseMember))],
  ['selected symlink',tar(member(nodeMember,Buffer.alloc(0),'2',0o777,'elsewhere'),member(licenseMember))],
  ['selected hardlink',tar(member(nodeMember,Buffer.alloc(0),'1',0o755,nodeMember),member(licenseMember))],
  ['traversal',tar(member(`${PIN.root}/../bin/node`),member(licenseMember))],
  ['absolute',tar(member(`/${nodeMember}`),member(licenseMember))],
  ['special',tar(member(nodeMember,Buffer.alloc(0),'3'),member(licenseMember))],
  ['world writable',tar(member(nodeMember,undefined,'0',0o777),member(licenseMember))],
  ['setuid',tar(member(nodeMember,undefined,'0',0o4755),member(licenseMember))],
  ['not executable',tar(member(nodeMember,undefined,'0',0o644),member(licenseMember))],
  ['missing license',tar(member(nodeMember))],
  ['missing end blocks',good().subarray(0,-1024)],
  ['partial block',good().subarray(0,-1)],
  ['trailing bytes',Buffer.concat([good(),Buffer.alloc(512,1)])],
]) test(`tar rejects ${label}`,()=>assert.throws(()=>parseTar(bytes)));
test('tar rejects corrupt header checksum and size overflow',()=>{
  const a=good(); a[0]^=1; assert.throws(()=>parseTar(a));
  const b=good(); b.fill(255,124,136); assert.throws(()=>parseTar(b));
});
test('GNU long names are resolved before selected duplicate checks',()=>{
  const ext=member('././@LongLink',Buffer.from(nodeMember+'\0'),'L');
  assert.throws(()=>parseTar(tar(ext,member('placeholder'),member(nodeMember),member(licenseMember))));
  const r=parseTar(tar(ext,member('placeholder'),member(licenseMember))); assert.ok(r.node);
});
test('checksum exact match permits signed other-platform nested filenames',()=>{
  assert.equal(parseChecksumText(`${PIN.sha256}  ${PIN.filename}\n${'1'.repeat(64)}  win-x64/node.exe\n\n`),PIN.sha256);
});
for(const [label,text] of [
  ['missing',`${'1'.repeat(64)}  other.tar.xz\n`],['wrong',`${'1'.repeat(64)}  ${PIN.filename}\n`],
  ['duplicate',`${PIN.sha256}  ${PIN.filename}\n${PIN.sha256}  ${PIN.filename}\n`],
  ['suffix',`${PIN.sha256}  ${PIN.filename}.evil\n`],['traversal',`${PIN.sha256}  ../${PIN.filename}\n`],
  ['extra text',`${PIN.sha256}  ${PIN.filename}\nsecret diagnostic\n`]
]) test(`checksum rejects ${label}`,()=>assert.throws(()=>parseChecksumText(text)));
test('machine signature status requires exact approved signer and primary',()=>assert.equal(parseSignatureStatus(status()),true));
for(const [label,change] of [
  ['bad',s=>s+'[GNUPG:] BADSIG public\n'],['error',s=>s+'[GNUPG:] ERRSIG public\n'],
  ['expired',s=>s+'[GNUPG:] EXPKEYSIG public\n'],['revoked',s=>s+'[GNUPG:] REVKEYSIG public\n'],
  ['unknown',s=>s+'[GNUPG:] NO_PUBKEY public\n'],['duplicate',s=>s+s],
  ['wrong key',s=>s.replaceAll(PIN.fingerprint,'0'.repeat(40))],['wrong hash',s=>s.replace(' 22 8 01 ',' 22 2 01 ')],
  ['missing valid',s=>s.split('\n').filter(l=>!l.includes('VALIDSIG')).join('\n')],['unknown status',s=>s+'[GNUPG:] NEW_PROTOCOL foo\n'],
  ['wrong timestamp',s=>s.replace('1790183910 0 4','not-a-time 0 4')],
  ['unexpected expiry',s=>s.replace('1790183910 0 4','1790183910 99 4')],
  ['wrong algorithm',s=>s.replace(' 0 22 8 01',' 0 1 8 01')],
  ['wrong goodsig',s=>s.replace('GOODSIG 20B1A390B168D356','GOODSIG 0000000000000000')],
  ['second newsig',s=>s+'[GNUPG:] NEWSIG\n']
]) test(`signature status rejects ${label}`,()=>assert.throws(()=>parseSignatureStatus(change(status()))));
test('cleanup evidence requires exited checker and every exact confirmation',()=>{
  assert.equal(cleanupEvidence(receipt()),true);
  for(const k of Object.keys(receipt().report.cleanup)) { const e=receipt();e.report.cleanup[k]=k==='appSocketsRemaining'?1:false; assert.equal(cleanupEvidence(e),false,k); }
  for(const k of ['checkerExited','checkerExitCode']) {const e=receipt();e[k]=k==='checkerExited'?false:1;assert.equal(cleanupEvidence(e),false);}
  for(const k of ['nativeSessionsStopped','explicitReadinessPasses','proxyBodyChecks']){const e=receipt();e.report[k]=1;assert.equal(cleanupEvidence(e),false);}
});
for (const key of ['bundleSchemaVersion', 'installSchemaVersion']) {
  test(`cleanup requires exact installed recipe schema ${key}`, () => {
    for (const value of [undefined, null, false, 0, 1, 3, '2', NaN, Infinity]) {
      const e = receipt(); e.report[key] = value; assert.equal(cleanupEvidence(e), false);
    }
    assert.equal(cleanupEvidence(receipt()), true);
  });
}
test('cleanup requires an actually generated installed recipe', () => {
  for (const value of [undefined, null, false, 0, 1, 'true']) {
    const e = receipt(); e.report.installedRecipeGenerated = value; assert.equal(cleanupEvidence(e), false);
  }
});
for (const [key, expected] of [['bundleSchemaVersion', 2], ['installSchemaVersion', 2], ['installedRecipeGenerated', true]]) {
  test(`cleanup recipe fact ${key} must be own data without evaluating a getter`, () => {
    let reads = 0; const e = receipt();
    Object.defineProperty(e.report, key, { configurable: true, get() { reads++; return expected; } });
    assert.equal(cleanupEvidence(e), false); assert.equal(reads, 0);
    delete e.report[key]; Object.setPrototypeOf(e.report, { [key]: expected });
    assert.equal(cleanupEvidence(e), false);
  });
}
test('a complete old-profile receipt cannot substitute for the installed recipe profile', () => {
  const e = receipt(); for (const key of ['bundleSchemaVersion', 'installSchemaVersion', 'installedRecipeGenerated']) delete e.report[key];
  assert.equal(cleanupEvidence(e), false);
});
test('cleanup refuses the prior combined TLS receipt without the new failed-start control',()=>{
  const e=receipt();delete e.report.failedStartChecks;delete e.report.failedStartProof;
  assert.equal(e.report.upstreamTLSActivated,true);assert.equal(e.report.cleanup.temporaryRootRemoved,true);
  assert.equal(cleanupEvidence(e),false);
});
test('cleanup requires exactly one failed-start control without a broader acceptance claim',()=>{
  for(const value of [undefined,false,0,2,'1',true,NaN,Infinity]){
    const e=receipt();e.report.failedStartChecks=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const value of [undefined,true,0,'false',null]){
    const e=receipt();e.report.failedStartAccepted=value;assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup requires each distinct failed-start refusal, retirement and fresh recovery proof',()=>{
  for(const k of Object.keys(receipt().report.failedStartProof)){
    for(const value of [undefined,false,1,'true',null]){
      const e=receipt();e.report.failedStartProof[k]=value;assert.equal(cleanupEvidence(e),false,k);
    }
    const missing=receipt();delete missing.report.failedStartProof[k];assert.equal(cleanupEvidence(missing),false,k);
  }
});
test('cleanup refuses malformed, inherited and extra failed-start proof fields',()=>{
  for(const value of [undefined,null,[],true,{},Object.create(receipt().report.failedStartProof)]){
    const e=receipt();e.report.failedStartProof=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const extra of ['unverified',Symbol('unverified')]){
    const e=receipt();e.report.failedStartProof[extra]=true;assert.equal(cleanupEvidence(e),false);
  }
  const foreign=receipt();Object.setPrototypeOf(foreign.report.failedStartProof,{unverified:true});
  assert.equal(cleanupEvidence(foreign),false);
  const nonenumerable=receipt();Object.defineProperty(nonenumerable.report.failedStartProof,'unverified',{value:true});
  assert.equal(cleanupEvidence(nonenumerable),false);
});
test('cleanup rejects accessor failed-start proofs without reading them',()=>{
  let reads=0;
  for(const k of Object.keys(receipt().report.failedStartProof)){
    const e=receipt();Object.defineProperty(e.report.failedStartProof,k,{enumerable:true,get(){reads++;return true;}});
    assert.equal(cleanupEvidence(e),false);
  }
  assert.equal(reads,0);
});
test('cleanup accepts the exact null-prototype failed-start data record',()=>{
  const e=receipt();e.report.failedStartProof=Object.assign(Object.create(null),e.report.failedStartProof);
  assert.equal(cleanupEvidence(e),true);
});
test('cleanup refuses the prior complete failed-start profile without controlled drain evidence',()=>{
  const e=receipt();delete e.report.controlledSlowDrainChecks;delete e.report.controlledSlowDrainProof;
  assert.equal(cleanupEvidence(e),false);
});
test('cleanup requires exactly one controlled drain and preserves the broad unaccepted boundary',()=>{
  for(const value of [undefined,null,0,2,'1',true,NaN]){
    const e=receipt();e.report.controlledSlowDrainChecks=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const value of [undefined,null,true,0,'false']){
    const e=receipt();e.report.slowDrainAccepted=value;assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup refuses every missing or partial controlled-drain authority and retirement proof',()=>{
  for(const k of Object.keys(receipt().report.controlledSlowDrainProof)){
    for(const value of [false,undefined,0,1,'true',null]){
      const e=receipt();e.report.controlledSlowDrainProof[k]=value;assert.equal(cleanupEvidence(e),false,k);
    }
    const e=receipt();delete e.report.controlledSlowDrainProof[k];assert.equal(cleanupEvidence(e),false,k);
  }
});
test('cleanup rejects inherited, extra and accessor controlled-drain authority without invoking getters',()=>{
  for(const value of [undefined,null,[],{},true,Object.create(receipt().report.controlledSlowDrainProof)]){
    const e=receipt();e.report.controlledSlowDrainProof=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const k of ['unverified',Symbol('extra')]){
    const e=receipt();e.report.controlledSlowDrainProof[k]=true;assert.equal(cleanupEvidence(e),false);
  }
  let reads=0;
  for(const k of Object.keys(receipt().report.controlledSlowDrainProof)){
    const e=receipt();Object.defineProperty(e.report.controlledSlowDrainProof,k,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(e),false);
  }
  assert.equal(reads,0);
});
test('cleanup accepts an exact null-prototype controlled-drain data record',()=>{
  const e=receipt();e.report.controlledSlowDrainProof=Object.assign(Object.create(null),e.report.controlledSlowDrainProof);
  assert.equal(cleanupEvidence(e),true);
});
test('cleanup refuses the prior drain-only receipt without operator interruption evidence',()=>{
  const e=receipt();delete e.report.operatorInterruptionChecks;delete e.report.operatorInterruptionProof;
  assert.equal(cleanupEvidence(e),false);
});
test('cleanup requires one inspected operator interruption without accepting broad orphan recovery',()=>{
  for(const value of [undefined,null,0,2,'1',true,NaN]){
    const e=receipt();e.report.operatorInterruptionChecks=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const value of [undefined,null,true,0,'false']){
    const e=receipt();e.report.orphanRecoveryAccepted=value;assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup refuses each missing or partial operator, lock and recovery proof',()=>{
  for(const k of Object.keys(receipt().report.operatorInterruptionProof)){
    for(const value of [false,undefined,null,0,1,'true']){
      const e=receipt();e.report.operatorInterruptionProof[k]=value;assert.equal(cleanupEvidence(e),false,k);
    }
    const e=receipt();delete e.report.operatorInterruptionProof[k];assert.equal(cleanupEvidence(e),false,k);
  }
});
test('cleanup rejects inherited, extra and accessor interruption authority without getter evaluation',()=>{
  for(const value of [undefined,null,[],{},true,Object.create(receipt().report.operatorInterruptionProof)]){
    const e=receipt();e.report.operatorInterruptionProof=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const k of ['unverified',Symbol('extra')]){
    const e=receipt();e.report.operatorInterruptionProof[k]=true;assert.equal(cleanupEvidence(e),false);
  }
  let reads=0;
  for(const k of Object.keys(receipt().report.operatorInterruptionProof)){
    const e=receipt();Object.defineProperty(e.report.operatorInterruptionProof,k,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(e),false);
  }
  assert.equal(reads,0);
});
test('cleanup accepts the exact null-prototype interruption data record',()=>{
  const e=receipt();e.report.operatorInterruptionProof=Object.assign(Object.create(null),e.report.operatorInterruptionProof);
  assert.equal(cleanupEvidence(e),true);
});
test('cleanup refuses the prior interruption receipt without a live native challenge',()=>{
  const e=receipt();delete e.report.operatorNativeChallengeChecks;delete e.report.operatorNativeChallengeProof;
  assert.equal(cleanupEvidence(e),false);
});
test('cleanup requires exactly one completed native challenge',()=>{
  for(const value of [undefined,null,0,2,'1',true,NaN]){
    const e=receipt();e.report.operatorNativeChallengeChecks=value;assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup refuses every missing or partial native route, pair, binding and closure proof',()=>{
  for(const key of Object.keys(receipt().report.operatorNativeChallengeProof)){
    for(const value of [false,undefined,null,0,1,'true']){
      const e=receipt();e.report.operatorNativeChallengeProof[key]=value;assert.equal(cleanupEvidence(e),false,key);
    }
    const e=receipt();delete e.report.operatorNativeChallengeProof[key];assert.equal(cleanupEvidence(e),false,key);
  }
});
test('cleanup rejects inherited, extra and accessor native challenge proofs without getter evaluation',()=>{
  for(const value of [undefined,null,[],{},true,Object.create(receipt().report.operatorNativeChallengeProof)]){
    const e=receipt();e.report.operatorNativeChallengeProof=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const key of ['unverified',Symbol('extra')]){
    const e=receipt();e.report.operatorNativeChallengeProof[key]=true;assert.equal(cleanupEvidence(e),false);
  }
  let reads=0;
  for(const key of Object.keys(receipt().report.operatorNativeChallengeProof)){
    const e=receipt();Object.defineProperty(e.report.operatorNativeChallengeProof,key,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(e),false);
  }
  assert.equal(reads,0);
});
test('cleanup accepts an exact null-prototype native challenge data record',()=>{
  const e=receipt();e.report.operatorNativeChallengeProof=Object.assign(Object.create(null),e.report.operatorNativeChallengeProof);
  assert.equal(cleanupEvidence(e),true);
});
test('cleanup refuses the prior complete three-session receipt without restored HTTP evidence',()=>{
  const e=receipt();
  for(const k of ['restoredHTTPChecks','restoredHTTPProof','tlsBackupAccepted','packageUpgradeRollbackAccepted'])delete e.report[k];
  for(const k of ['explicitReadinessPasses','nativeSessionsStarted','nativeSessionsStopped','proxyBodyChecks','uploadChecks','streamChecks'])e.report[k]=3;
  e.report.managerRestartCommands=1;e.report.completedManagerRestarts=1;
  e.report.journalChecks=3;e.report.journalRecordsObserved=6;e.report.journalRunningMarkers=3;
  assert.equal(e.report.cleanup.temporaryRootRemoved,true);assert.equal(e.report.upstreamTLSActivated,true);
  assert.equal(cleanupEvidence(e),false);
});
test('new aggregate counts cannot substitute for the exact restored HTTP proof',()=>{
  const e=receipt();delete e.report.restoredHTTPProof;
  assert.equal(e.report.nativeSessionsStopped,5);assert.equal(e.report.journalChecks,6);
  assert.equal(cleanupEvidence(e),false);
});
test('cleanup requires exactly one restored HTTP check with no broader backup or package acceptance',()=>{
  for(const value of [undefined,null,false,0,2,'1',true,NaN,Infinity]){
    const e=receipt();e.report.restoredHTTPChecks=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const key of ['tlsBackupAccepted','packageUpgradeRollbackAccepted']){
    for(const value of [undefined,null,true,0,'false']){
      const e=receipt();e.report[key]=value;assert.equal(cleanupEvidence(e),false,key);
    }
    const e=receipt();delete e.report[key];assert.equal(cleanupEvidence(e),false,key);
  }
});
test('restored check and unsupported facts must be own data without accessor evaluation',()=>{
  let reads=0;
  for(const [key,value] of [['restoredHTTPChecks',1],['tlsBackupAccepted',false],['packageUpgradeRollbackAccepted',false]]){
    const accessor=receipt();Object.defineProperty(accessor.report,key,{get(){reads++;return value;}});
    assert.equal(cleanupEvidence(accessor),false,key);
    const inherited=receipt();delete inherited.report[key];Object.setPrototypeOf(inherited.report,{[key]:value});
    assert.equal(cleanupEvidence(inherited),false,key);
  }
  assert.equal(reads,0);
});
test('cleanup requires all eighteen independent restored HTTP identity IO and preservation facts',()=>{
  assert.equal(Object.keys(receipt().report.restoredHTTPProof).length,18);
  for(const key of Object.keys(receipt().report.restoredHTTPProof)){
    for(const value of [undefined,null,false,0,1,'true']){
      const e=receipt();e.report.restoredHTTPProof[key]=value;assert.equal(cleanupEvidence(e),false,key);
    }
    const e=receipt();delete e.report.restoredHTTPProof[key];assert.equal(cleanupEvidence(e),false,key);
  }
});
test('cleanup rejects malformed inherited and extra restored HTTP proof data',()=>{
  for(const value of [undefined,null,[],{},true,1,'true',Object.create(receipt().report.restoredHTTPProof)]){
    const e=receipt();e.report.restoredHTTPProof=value;assert.equal(cleanupEvidence(e),false);
  }
  for(const key of ['unverified',Symbol('unverified')]){
    const e=receipt();e.report.restoredHTTPProof[key]=true;assert.equal(cleanupEvidence(e),false);
  }
  const nonenumerable=receipt();Object.defineProperty(nonenumerable.report.restoredHTTPProof,'unverified',{value:true});
  assert.equal(cleanupEvidence(nonenumerable),false);
  const foreign=receipt();Object.setPrototypeOf(foreign.report.restoredHTTPProof,{unverified:true});
  assert.equal(cleanupEvidence(foreign),false);
});
test('cleanup rejects restored HTTP proof and field accessors without evaluating them',()=>{
  let reads=0;
  const top=receipt();Object.defineProperty(top.report,'restoredHTTPProof',{get(){reads++;return receipt().report.restoredHTTPProof;}});
  assert.equal(cleanupEvidence(top),false);
  const inherited=receipt();const proof=inherited.report.restoredHTTPProof;delete inherited.report.restoredHTTPProof;
  Object.setPrototypeOf(inherited.report,{restoredHTTPProof:proof});assert.equal(cleanupEvidence(inherited),false);
  for(const key of Object.keys(proof)){
    const e=receipt();Object.defineProperty(e.report.restoredHTTPProof,key,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(e),false,key);
  }
  assert.equal(reads,0);
});
test('cleanup accepts exact null-prototype restored HTTP proof without accepting TLS backup or package rollback',()=>{
  const e=receipt();e.report.restoredHTTPProof=Object.assign(Object.create(null),e.report.restoredHTTPProof);
  assert.equal(cleanupEvidence(e),true);assert.equal(e.report.tlsBackupAccepted,false);
  assert.equal(e.report.packageUpgradeRollbackAccepted,false);assert.equal(e.report.serviceAccepted,false);
  assert.equal(e.report.productionAccepted,false);
});
test('cleanup refuses stale session profiles and mixed five-session counts',()=>{
  const counters=['explicitReadinessPasses','nativeSessionsStarted','nativeSessionsStopped','proxyBodyChecks','uploadChecks','streamChecks'];
  const old=receipt();for(const k of counters)old.report[k]=2;
  delete old.report.restartProof;delete old.report.managerRestartCommands;delete old.report.completedManagerRestarts;
  delete old.report.journalChecks;delete old.report.journalRecordsObserved;delete old.report.journalRunningMarkers;
  assert.equal(cleanupEvidence(old),false);
  for(const k of counters)for(const value of [undefined,2,3,4,6,'5',NaN]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
});
test('cleanup requires exactly two completed restarts and all four own exit/freshness proofs',()=>{
  for(const k of ['managerRestartCommands','completedManagerRestarts'])for(const value of [undefined,0,1,3,'2',true]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  for(const k of Object.keys(receipt().report.restartProof))for(const value of [undefined,false,1,'true']){const e=receipt();e.report.restartProof[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  for(const value of [null,[],true,{},Object.create(receipt().report.restartProof)]){const e=receipt();e.report.restartProof=value;assert.equal(cleanupEvidence(e),false);}
  const extra=receipt();extra.report.restartProof.unverified=true;assert.equal(cleanupEvidence(extra),false);
});
test('cleanup bounds journal evidence without accepting absent or inconsistent markers',()=>{
  for(const value of [undefined,0,2,3,5,7,'6',true]){const e=receipt();e.report.journalChecks=value;assert.equal(cleanupEvidence(e),false);}
  for(const k of ['journalRecordsObserved','journalRunningMarkers'])for(const value of [undefined,0,2,3,5,769,6.5,'6',NaN,Infinity]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  const inconsistent=receipt();inconsistent.report.journalRecordsObserved=6;inconsistent.report.journalRunningMarkers=7;assert.equal(cleanupEvidence(inconsistent),false);
  for(const count of [6,768]){const e=receipt();e.report.journalRecordsObserved=count;e.report.journalRunningMarkers=count;assert.equal(cleanupEvidence(e),true);}
});
test('cleanup refuses the earlier HTTP-only three-session receipt even with a stale closed TLS port claim',()=>{
  for(const claimedClosed of [undefined,true]){
    const e=receipt();for(const k of Object.keys(e.report))if(k.startsWith('downstreamTLS'))delete e.report[k];
    if(claimedClosed===undefined)delete e.report.cleanup.downstreamTLSPortClosed;
    else e.report.cleanup.downstreamTLSPortClosed=claimedClosed;
    assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup requires exact downstream TLS protocol, certificate and refusal counts',()=>{
  const expected={downstreamTLSSessionChecks:3,downstreamTLSBodyChecks:6,downstreamTLSUploadChecks:3,downstreamTLSStreamChecks:3,
    downstreamTLS12Checks:3,downstreamTLS13Checks:3,downstreamTLSCertificateChecks:12,downstreamTLSWrongCARefusals:3,downstreamTLSWrongNameRefusals:3};
  for(const [k,count] of Object.entries(expected))for(const value of [undefined,false,0,count-1,count+1,String(count),NaN,Infinity]){
    const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);
  }
});
test('cleanup requires observed TLS activation and keeps full TLS/service acceptance false',()=>{
  for(const value of [undefined,false,1,'true']){const e=receipt();e.report.downstreamTLSActivated=value;assert.equal(cleanupEvidence(e),false);}
  for(const value of [undefined,true,0,'false']){const e=receipt();e.report.tlsServiceAccepted=value;assert.equal(cleanupEvidence(e),false);}
});
test('cleanup requires the additional current-attempt TLS listener closure',()=>{
  for(const value of [undefined,false,1,'true']){
    const e=receipt();e.report.cleanup.downstreamTLSPortClosed=value;
    assert.equal(e.report.cleanup.listeningPortsClosed,true);assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup refuses downstream-only receipts even with retained origin and relay closure claims',()=>{
  for(const retainedClosure of [false,true]){
    const e=receipt();for(const k of Object.keys(e.report))if(k.startsWith('upstreamTLS'))delete e.report[k];
    if(!retainedClosure)for(const k of ['upstreamTLSPortClosed','readinessRelayPortClosed','upstreamTLSOriginClosed','readinessRelayClosed'])delete e.report.cleanup[k];
    assert.equal(cleanupEvidence(e),false);
  }
});
test('cleanup requires exact per-session origin IO, rollback, 502 and no-replay observations',()=>{
  for(const k of ['upstreamTLSSessionChecks','upstreamTLSBodyChecks','upstreamTLSUploadChecks','upstreamTLSStreamChecks',
    'upstreamTLSRollbackChecks','upstreamTLSCandidate502Checks','upstreamTLSNoPostReplayChecks']){
    for(const value of [undefined,false,0,2,4,'3',NaN,Infinity]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  }
});
test('cleanup requires independently observed origin trust and plaintext refusals',()=>{
  for(const k of ['upstreamTLSDirectChecks','upstreamTLSWrongCARefusals','upstreamTLSWrongNameRefusals','upstreamTLSPlaintextRefusals']){
    for(const value of [undefined,false,0,2,3,'1',NaN,Infinity]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  }
  for(const value of [undefined,false,1,'true']){const e=receipt();e.report.upstreamTLSActivated=value;assert.equal(cleanupEvidence(e),false);}
});
test('cleanup requires both owned server closures and separately observed origin and relay ports closed',()=>{
  for(const k of ['upstreamTLSPortClosed','readinessRelayPortClosed','upstreamTLSOriginClosed','readinessRelayClosed']){
    for(const value of [undefined,false,1,'true']){
      const e=receipt();e.report.cleanup[k]=value;
      assert.equal(e.report.cleanup.listeningPortsClosed,true);assert.equal(e.report.cleanup.downstreamTLSPortClosed,true);
      assert.equal(cleanupEvidence(e),false,k);
    }
  }
});
test('cleanup refuses partial origin activation despite completed earlier session and cleanup claims',()=>{
  const cases=[e=>e.report.upstreamTLSRollbackChecks=2,e=>e.report.upstreamTLSCandidate502Checks=2,
    e=>e.report.upstreamTLSNoPostReplayChecks=2,e=>e.report.primaryFailure={phase:'first_start',code:'origin_apply_failed'},
    e=>e.report.cleanupFailures=[{stage:'origin_cleanup',code:'origin_cleanup_unknown'}]];
  for(const mutate of cases){const e=receipt();mutate(e);assert.equal(cleanupEvidence(e),false);}
});
test('cleanup refuses mixed failure and broader acceptance claims despite successful cleanup booleans',()=>{
  const mutations=[
    e=>e.report.primaryFailure={phase:'restart',code:'unit_start_failed'},
    e=>e.report.cleanupFailures=[{stage:'unit_cleanup',code:'native_cleanup_unknown'}],
    e=>e.report.cleanupFailureCount=1,e=>e.report.cleanupFailuresTruncated=true,
    e=>e.report.readinessAutomated=false,e=>e.report.automaticReadinessAccepted=true,
    e=>e.report.serviceAccepted=true,e=>e.report.productionAccepted=true,e=>e.report.subprocessOutputsPublished=true,
  ];
  for(const mutate of mutations){const e=receipt();mutate(e);assert.equal(cleanupEvidence(e),false);}
  for(const k of ['primaryFailure','cleanupFailures','cleanupFailureCount','cleanupFailuresTruncated','readinessAutomated','automaticReadinessAccepted','serviceAccepted','productionAccepted','subprocessOutputsPublished']){const e=receipt();delete e.report[k];assert.equal(cleanupEvidence(e),false,k);}
});
test('public usage refusals publish no paths or exception data',async()=>{
  const r=await main(['--archive','/private/secret','--prefix','/private/secret','--trust-key','forged']);
  assert.equal(r.code,'usage_invalid');assert.equal(JSON.stringify(r).includes('/private'),false);
});
test('prefix collision is refused before archive access and is preserved',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','owned',{mode:0o600});
  try {const r=await main(['--archive',p+'/missing','--prefix',p+'/runtime']);assert.equal(r.code,'prefix_collision');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'owned');}
  finally {await unlink(p+'/runtime/sentinel');await rmdir(p+'/runtime');await rmdir(p);}
});
test('symlink parent is refused without touching its target',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/real',{mode:0o700});await symlink(p+'/real',p+'/alias');
  try {assert.equal((await main(['--archive',p+'/missing','--prefix',p+'/alias/runtime'])).ok,false);assert.deepEqual(await readdir(p+'/real'),[]);}
  finally {await unlink(p+'/alias');await rmdir(p+'/real');await rmdir(p);}
});
test('actual pinned public signature verified then wrong archive refused before decode or execution',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await writeFile(p+'/archive.xz',Buffer.from('NOT_AN_EXECUTABLE_OR_ARCHIVE'),{mode:0o600});
  try {const r=await main(['--archive',p+'/archive.xz','--prefix',p+'/runtime']);assert.equal(r.code,'archive_checksum_refused');assert.deepEqual(await readdir(p),['archive.xz']);assert.equal(r.serviceAccepted,false);}
  finally {await unlink(p+'/archive.xz');await rmdir(p);}
});
test('cleanup refuses incomplete lifecycle evidence and retains arbitrary prefix',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/receipt.json',JSON.stringify({checkerExited:true,checkerExitCode:0,report:{ok:true}}),{mode:0o600});
  try {const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.ok((await lstat(p+'/runtime')).isDirectory());}
  finally {await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup preserves runtime contents when a complete-looking receipt lacks owned journal evidence',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const e=receipt();e.report.journalRunningMarkers=0;await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
  try {const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);}
  finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup preserves runtime contents when exact-source receipt has incomplete TLS refusal evidence',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const e=receipt(),source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];
  e.report.downstreamTLSWrongCARefusals=2;await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
  try {const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);}
  finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup preserves runtime when exact-source receipt lacks failed-start or fresh recovery proof',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  try {
    for(const mutate of [e=>{delete e.report.failedStartProof;},e=>{e.report.failedStartProof.healthyRestartFresh=false;},e=>{e.report.failedStartProof.nativeGroupsAbsent=false;}]){
      const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];mutate(e);
      await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
      const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);
      assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');
      assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);
    }
  } finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup retains private runtime for exact-source missing, early-completion or incomplete drain evidence',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  try {
    for(const mutate of [e=>{delete e.report.controlledSlowDrainProof;},e=>{e.report.controlledSlowDrainProof.managerStopPending=false;},
      e=>{e.report.controlledSlowDrainProof.payloadCompleted=false;},e=>{e.report.controlledSlowDrainProof.nativeGroupsAbsent=false;}]){
      const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];mutate(e);
      await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
      const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);
      assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');
      assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);
    }
  } finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup retains runtime when interruption, recovery or native challenge remains unconfirmed',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  try {
    for(const mutate of [e=>{delete e.report.operatorInterruptionProof;},e=>{e.report.operatorInterruptionProof.exactLockRemovalConfirmed=false;},
      e=>{e.report.operatorInterruptionProof.ownedOperatorTerminated=false;},e=>{e.report.operatorInterruptionProof.explicitRollbackObserved=false;},
      e=>{delete e.report.operatorNativeChallengeProof;},e=>{e.report.operatorNativeChallengeProof.nativeRouteObserved=false;},
      e=>{e.report.operatorNativeChallengeProof.authorityReobservedBeforeSignal=false;},e=>{e.report.operatorNativeChallengeProof.ownedChallengeClosed=false;}]){
      const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];mutate(e);
      await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
      const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);
      assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');
      assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);
    }
  } finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup preserves runtime sentinel for exact-source incomplete origin and relay evidence',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  const mutations=[e=>e.report.upstreamTLSNoPostReplayChecks=2,e=>e.report.cleanup.readinessRelayClosed=false,
    e=>e.report.cleanup.upstreamTLSOriginClosed=false];
  try {
    for(const mutate of mutations){
      const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];mutate(e);
      await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
      const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);
      assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');
      assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);
    }
  } finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('cleanup retains the private runtime for exact-source incomplete restored HTTP evidence',async()=>{
  const p=await mkdtemp('/tmp/x10-node-test-');await mkdir(p+'/runtime',{mode:0o700});
  await writeFile(p+'/runtime/sentinel','preserve',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  const mutations=[e=>{delete e.report.restoredHTTPProof;},e=>{e.report.restoredHTTPProof.sourceUnitRemoved=false;},
    e=>{e.report.restoredHTTPProof.restoredHTTPRestarted=false;},e=>{e.report.restoredHTTPProof.noPostReplay=false;},
    e=>{e.report.restoredHTTPProof.sourceRecordsPreserved=false;},e=>{e.report.restoredHTTPProof.sourceInstallationRemoved=false;},
    e=>{e.report.tlsBackupAccepted=true;},e=>{e.report.packageUpgradeRollbackAccepted=true;}];
  try {
    for(const mutate of mutations){
      const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];mutate(e);
      await writeFile(p+'/receipt.json',JSON.stringify(e),{mode:0o600});
      const r=await main(['--cleanup','--prefix',p+'/runtime','--service-evidence',p+'/receipt.json']);
      assert.equal(r.code,'runtime_retained_cleanup_unconfirmed');assert.equal(await readFile(p+'/runtime/sentinel','utf8'),'preserve');
      assert.deepEqual(await readdir(p+'/runtime'),['sentinel']);
    }
  } finally {await unlink(p+'/runtime/sentinel');await unlink(p+'/receipt.json');await rmdir(p+'/runtime');await rmdir(p);}
});
test('missing or unsafe new managed evidence preserves existing runtime bytes and directory identity',async()=>{
  const p=await mkdtemp('/tmp/x10-node-managed-test-'),prefix=p+'/runtime',file=p+'/receipt.json';
  await mkdir(prefix,{mode:0o700});await writeFile(prefix+'/sentinel','public-synthetic-retain',{mode:0o600});
  const before=await lstat(prefix),source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  const lifecyclePin=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];
  const mutations=[e=>{delete e.managedPackageReport;},e=>{delete e.managedPackageCheckerExited;},
    e=>e.managedPackageCheckerExitCode=1,e=>e.sourceManagedPackageSha256+='\n',
    e=>e.sourceManagedPackageProofSha256+='\n',e=>e.managedPackageReport.schemaVersion=1,
    e=>e.managedPackageReport.proof.cleanup.known=false,
    e=>e.managedPackageReport.proof.transitions.beforeA2.unitInactive=false,
    e=>e.managedPackageReport.proof.transitions.beforeB.runtimeLinkAbsent=false,
    e=>e.managedPackageReport.proof.transitions.beforeB.unitNotFound=false,
    e=>e.managedPackageReport.proof.counts.journalChecks=4,
    e=>e.managedPackageReport.padding='x'.repeat(12289)];
  try{
    for(const mutate of mutations){
      const e=receipt();e.sourceLifecycleSha256=lifecyclePin;mutate(e);
      await writeFile(file,JSON.stringify(e),{mode:0o600});
      const result=await main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
      assert.equal(result.code,'runtime_retained_cleanup_unconfirmed');assert.equal(result.ok,false);
      assert.equal(await readFile(prefix+'/sentinel','utf8'),'public-synthetic-retain');
      const after=await lstat(prefix);assert.equal(after.dev,before.dev);assert.equal(after.ino,before.ino);
      assert.deepEqual(await readdir(prefix),['sentinel']);
      assert.equal(JSON.stringify(result).includes(p),false);
    }
  } finally {await unlink(prefix+'/sentinel');await unlink(file);await rmdir(prefix);await rmdir(p);}
});
test('combined evidence remains bounded at the original 32KiB before any runtime removal',async()=>{
  const p=await mkdtemp('/tmp/x10-node-managed-test-'),prefix=p+'/runtime',file=p+'/receipt.json';
  await mkdir(prefix,{mode:0o700});await writeFile(prefix+'/sentinel','retain',{mode:0o600});
  const e=receipt();e.padding='x'.repeat(32769);await writeFile(file,JSON.stringify(e),{mode:0o600});
  try{
    assert((await lstat(file)).size>32768);
    const result=await main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
    assert.equal(result.ok,false);assert.equal(await readFile(prefix+'/sentinel','utf8'),'retain');
    assert.deepEqual(await readdir(prefix),['sentinel']);
  } finally {await unlink(prefix+'/sentinel');await unlink(file);await rmdir(prefix);await rmdir(p);}
});
test('legacy or non-null managed primary failure preserves private runtime files before inspection',async()=>{
  const p=await mkdtemp('/tmp/x10-node-primary-test-'),prefix=p+'/runtime',file=p+'/receipt.json';
  await mkdir(prefix,{mode:0o700});await writeFile(prefix+'/sentinel','public-synthetic-retain',{mode:0o600});
  const source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  const lifecyclePin=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1],before=await lstat(prefix);
  const mutations=[e=>{e.managedPackageReport.schemaVersion=1;delete e.managedPackageReport.primaryFailure;},
    e=>{delete e.managedPackageReport.primaryFailure;},e=>e.managedPackageReport.primaryFailure='controller_state',
    e=>e.managedPackageReport.primaryFailure='cleanup_unconfirmed',
    e=>e.managedPackageReport.primaryFailure='SYNTHETIC_PRIVATE_PRIMARY_MUST_NOT_LEAK'];
  try{
    for(const mutate of mutations){
      const e=receipt();e.sourceLifecycleSha256=lifecyclePin;mutate(e);
      await writeFile(file,JSON.stringify(e),{mode:0o600});
      const result=await main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
      assert.equal(result.code,'runtime_retained_cleanup_unconfirmed');assert.equal(result.ok,false);
      assert.equal(await readFile(prefix+'/sentinel','utf8'),'public-synthetic-retain');
      const after=await lstat(prefix);assert.equal(after.dev,before.dev);assert.equal(after.ino,before.ino);
      assert.deepEqual(await readdir(prefix),['sentinel']);
      assert.equal(JSON.stringify(result).includes('SYNTHETIC_PRIVATE_PRIMARY'),false);
      assert.equal(JSON.stringify(result).includes(p),false);
    }
  } finally {await unlink(prefix+'/sentinel');await unlink(file);await rmdir(prefix);await rmdir(p);}
});

test('the accepted two-child envelope cannot authorize an unobserved fallback child',()=>{
  const e=receipt();
  for(const key of ['fallbackPackageCheckerExited','fallbackPackageCheckerExitCode','sourceFallbackPackageSha256',
    'sourceFallbackPackageProofSha256','fallbackPackageReport'])delete e[key];
  assert.equal(e.report.nativeSessionsStopped,5);assert.equal(e.managedPackageReport.proof.counts.invocations,4);
  assert.equal(cleanupEvidence(e),false);
});
test('fallback child must close successfully and independently match wrapper and proof pins',()=>{
  const cases={fallbackPackageCheckerExited:[undefined,false,1,'true'],
    fallbackPackageCheckerExitCode:[undefined,1,-0,null,'0'],
    sourceFallbackPackageSha256:[undefined,'f'.repeat(63),'g'.repeat(64),FALLBACK_PACKAGE_CLEANUP_SOURCE.checkerSha256+'\n'],
    sourceFallbackPackageProofSha256:[undefined,'f'.repeat(63),'g'.repeat(64),FALLBACK_PACKAGE_CLEANUP_SOURCE.proofSha256+'\n']};
  for(const[key,values]of Object.entries(cases))for(const value of values){
    const e=receipt();e[key]=value;assert.equal(cleanupEvidence(e),false,key);
  }
  assert.equal(cleanupEvidence(receipt()),true);
});
test('fallback envelope fields require own enumerable data and never evaluate accessors',()=>{
  let reads=0;
  for(const key of ['fallbackPackageCheckerExited','fallbackPackageCheckerExitCode','sourceFallbackPackageSha256',
    'sourceFallbackPackageProofSha256','fallbackPackageReport']){
    const accessor=receipt();Object.defineProperty(accessor,key,{get(){reads++;return true;}});
    assert.equal(cleanupEvidence(accessor),false,key);
    const inherited=receipt(),value=inherited[key];delete inherited[key];Object.setPrototypeOf(inherited,{[key]:value});
    assert.equal(cleanupEvidence(inherited),false,key);
    const hidden=receipt();Object.defineProperty(hidden,key,{value:hidden[key],enumerable:false});
    assert.equal(cleanupEvidence(hidden),false,key);
  }
  assert.equal(reads,0);
});
test('fallback success is a complete separate bounded report with no adverse primary or cleanup',()=>{
  const mutations=[e=>{delete e.fallbackPackageReport;},e=>e.fallbackPackageReport=null,
    e=>e.fallbackPackageReport.schemaVersion=2,e=>e.fallbackPackageReport.kind='nginx-x10-managed-operator-return-report',
    e=>e.fallbackPackageReport.ok=false,e=>e.fallbackPackageReport.code='managed_operator_fallback_refused',
    e=>e.fallbackPackageReport.phase='b_failed',e=>e.fallbackPackageReport.proof=null,
    e=>e.fallbackPackageReport.primaryFailure='failed_start_refused',e=>{delete e.fallbackPackageReport.primaryFailure;},
    e=>e.fallbackPackageReport.cleanupFailures=['owned_unit_cleanup_unconfirmed'],
    e=>e.fallbackPackageReport.cleanupFailureCount=1,e=>e.fallbackPackageReport.cleanupFailuresTruncated=true,
    e=>e.fallbackPackageReport.serviceAccepted=true,e=>e.fallbackPackageReport.productionAccepted=true,
    e=>e.fallbackPackageReport.subprocessOutputsPublished=true,e=>e.fallbackPackageReport.unknown=true,
    e=>e.fallbackPackageReport.padding='x'.repeat(12289)];
  for(const mutate of mutations){const e=receipt();mutate(e);assert.equal(cleanupEvidence(e),false);}
});
test('normal return reports cannot substitute for fallback or conversely',()=>{
  const normal=receipt();normal.fallbackPackageReport=normal.managedPackageReport;
  assert.equal(cleanupEvidence(normal),false);
  const fallback=receipt();fallback.managedPackageReport=fallback.fallbackPackageReport;
  assert.equal(cleanupEvidence(fallback),false);
});
test('fallback report accessors and inherited data are refused without evaluation',()=>{
  let reads=0;
  for(const key of Object.keys(receipt().fallbackPackageReport)){
    const e=receipt();Object.defineProperty(e.fallbackPackageReport,key,{enumerable:true,get(){reads++;return null;}});
    assert.equal(cleanupEvidence(e),false,key);
  }
  const inherited=receipt();Object.setPrototypeOf(inherited.fallbackPackageReport,{unverified:true});
  assert.equal(cleanupEvidence(inherited),false);assert.equal(reads,0);
});
test('fallback cleanup can consume exact null-prototype observation records',()=>{
  const e=receipt();e.fallbackPackageReport=Object.assign(Object.create(null),e.fallbackPackageReport);
  e.fallbackPackageReport.proof.failedB=Object.assign(Object.create(null),e.fallbackPackageReport.proof.failedB);
  assert.equal(cleanupEvidence(e),true);
});
test('each distinct failed-B capture, hook, absence and retirement fact remains mandatory',()=>{
  for(const key of Object.keys(receipt().fallbackPackageReport.proof.failedB).filter(key=>key!=='identityOrdinals')){
    for(const value of [undefined,false,1,'true']){
      const e=receipt();e.fallbackPackageReport.proof.failedB[key]=value;assert.equal(cleanupEvidence(e),false,key);
    }
  }
});
test('fallback cannot use fresh installation or reuse retired session invocation and binding ordinals',()=>{
  for(const[key,values]of Object.entries({installation:[2,3],unit:[1,2],session:[1,2],revision:[1,2],binding:[1,3],invocation:[1,2]})){
    for(const value of values){const e=receipt();e.fallbackPackageReport.proof.legs[1].identityOrdinals[key]=value;
      assert.equal(cleanupEvidence(e),false,key);}
  }
  for(const key of Object.keys(receipt().fallbackPackageReport.proof.failedB.identityOrdinals)){
    const e=receipt();e.fallbackPackageReport.proof.failedB.identityOrdinals[key]=1;assert.equal(cleanupEvidence(e),false,key);
  }
});
test('all kept-A preparation and retention facts remain required through explicit reactivation',()=>{
  for(const section of ['preparation','retention'])for(const key of Object.keys(receipt().fallbackPackageReport.proof[section])){
    const e=receipt();e.fallbackPackageReport.proof[section][key]=false;assert.equal(cleanupEvidence(e),false,`${section}:${key}`);
  }
});
test('failure-profile counters cannot be replaced by normal return or legacy counts',()=>{
  for(const[key,value]of Object.entries(receipt().fallbackPackageReport.proof.counts)){
    const e=receipt();e.fallbackPackageReport.proof.counts[key]=value+1;assert.equal(cleanupEvidence(e),false,key);
  }
  const zero=receipt();zero.fallbackPackageReport.proof.counts.restarts=-0;assert.equal(cleanupEvidence(zero),false);
});
test('fallback requires both successful traffic legs without replay or extra B POST effects',()=>{
  for(const index of [0,1])for(const key of ['getExact','postExact','streamExact','initialBindingAbsent','readinessAccepted','bindingMatchesOwnedRuntime']){
    const e=receipt();e.fallbackPackageReport.proof.legs[index][key]=false;assert.equal(cleanupEvidence(e),false,key);
  }
  for(const[key,value]of [['postEffectsBefore',2],['postEffectsAfter',3]]){
    const e=receipt();e.fallbackPackageReport.proof.legs[1][key]=value;assert.equal(cleanupEvidence(e),false,key);
  }
});
test('kept-A fallback must retain old package bytes and input P with unchanged native binary',()=>{
  const candidate=receipt();candidate.fallbackPackageReport.proof.packages.aFallback={...candidate.fallbackPackageReport.proof.packages.b};
  assert.equal(cleanupEvidence(candidate),false);
  const input=receipt();input.fallbackPackageReport.proof.inputs.aFallbackSha256=hash('public-synthetic-different-input');
  assert.equal(cleanupEvidence(input),false);
  const native=receipt();native.fallbackPackageReport.proof.packages.aFallback.nativeBinarySha256=hash('public-synthetic-different-native');
  assert.equal(cleanupEvidence(native),false);
});
test('fallback final cleanup requires all contexts retired and exactly two unique installations removed',()=>{
  for(const section of ['beforeB','afterFallback'])for(const key of Object.keys(receipt().fallbackPackageReport.proof.transitions[section])){
    const e=receipt();e.fallbackPackageReport.proof.transitions[section][key]=false;assert.equal(cleanupEvidence(e),false,key);
  }
  for(const[key,value]of Object.entries(receipt().fallbackPackageReport.proof.cleanup)){
    const e=receipt();e.fallbackPackageReport.proof.cleanup[key]=typeof value==='number'?value-1:false;
    assert.equal(cleanupEvidence(e),false,key);
  }
});
test('fallback receipt cannot claim automatic fallback, native upgrade or full acceptance',()=>{
  for(const key of Object.keys(receipt().fallbackPackageReport.proof.limits).filter(key=>key!=='consistencyOnly')){
    const e=receipt();e.fallbackPackageReport.proof.limits[key]=true;assert.equal(cleanupEvidence(e),false,key);
  }
});
test('a third report never relaxes accepted normal and legacy source or lifecycle admission',()=>{
  const cases=[e=>{delete e.managedPackageReport;},e=>e.managedPackageReport.proof.counts.invocations=2,
    e=>e.managedPackageReport.proof.transitions.beforeA2.unitNotFound=false,e=>e.sourceManagedPackageSha256+='\n',
    e=>e.report.nativeSessionsStopped=4,e=>e.report.journalChecks=5,e=>e.report.restoredHTTPProof.sourceUnitRemoved=false];
  for(const mutate of cases){const e=receipt();mutate(e);assert.equal(cleanupEvidence(e),false);}
});
test('missing, failed or malformed fallback evidence retains exact private runtime directory and sentinel bytes',async()=>{
  const p=await mkdtemp('/tmp/x10-node-fallback-test-'),prefix=p+'/runtime',file=p+'/receipt.json';
  await mkdir(prefix,{mode:0o700});await writeFile(prefix+'/sentinel','public-synthetic-retain',{mode:0o600});
  const before=await lstat(prefix),source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
  const lifecyclePin=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];
  const mutations=[e=>{delete e.fallbackPackageReport;},e=>e.fallbackPackageCheckerExited=false,
    e=>e.fallbackPackageCheckerExitCode=1,e=>e.sourceFallbackPackageSha256+='\n',e=>e.sourceFallbackPackageProofSha256+='\n',
    e=>e.fallbackPackageReport.proof.failedB.hookExitObserved=false,e=>e.fallbackPackageReport.proof.failedB.noPOSTEffects=false,
    e=>e.fallbackPackageReport.proof.retention.retainedAAllFilesPreservedThroughBFailure=false,
    e=>e.fallbackPackageReport.proof.preparation.registryTwoSessions=false,
    e=>e.fallbackPackageReport.primaryFailure='SYNTHETIC_PRIVATE_FALLBACK_MUST_NOT_LEAK'];
  try{
    for(const mutate of mutations){
      const e=receipt();e.sourceLifecycleSha256=lifecyclePin;mutate(e);await writeFile(file,JSON.stringify(e),{mode:0o600});
      const result=await main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
      assert.equal(result.code,'runtime_retained_cleanup_unconfirmed');assert.equal(result.ok,false);
      assert.equal(await readFile(prefix+'/sentinel','utf8'),'public-synthetic-retain');
      const after=await lstat(prefix);assert.equal(after.dev,before.dev);assert.equal(after.ino,before.ino);
      assert.deepEqual(await readdir(prefix),['sentinel']);
      assert.equal(JSON.stringify(result).includes('SYNTHETIC_PRIVATE_FALLBACK'),false);assert.equal(JSON.stringify(result).includes(p),false);
    }
  } finally {await unlink(prefix+'/sentinel');await unlink(file);await rmdir(prefix);await rmdir(p);}
});
test('the three complete synthetic reports fit the unchanged 32KiB envelope bound',()=>{
  const e=receipt();
  assert(Buffer.byteLength(JSON.stringify(e),'utf8')<32768);
  assert.equal(cleanupEvidence(e),true);
});

// This local cleanup fixture uses an inert regular file, never an executable
// dependency or service. It checks admission reaches actual owned-file removal.
async function syntheticRuntime(prefix) {
  await mkdir(prefix,{mode:0o700});await mkdir(prefix+'/bin',{mode:0o700});
  const inert=Buffer.from('PUBLIC_SYNTHETIC_NONEXECUTABLE_NODE_PLACEHOLDER');
  await writeFile(prefix+'/bin/node',inert,{mode:0o500});
  await writeFile(prefix+'/LICENSE','public synthetic license',{mode:0o400});
  const identity=s=>({uid:s.uid,dev:s.dev,ino:s.ino});
  const m={schemaVersion:1,kind:'x10-verified-node-dependency',version:PIN.version,installationId:'a'.repeat(32),
    archiveSha256:PIN.sha256,prefix,rootIdentity:identity(await lstat(prefix)),binIdentity:identity(await lstat(prefix+'/bin')),files:{}};
  for(const name of ['bin/node','LICENSE'])m.files[name]={sha256:hash(await readFile(prefix+'/'+name)),identity:identity(await lstat(prefix+'/'+name))};
  await writeFile(prefix+'/.verified-node.json',JSON.stringify({...m,sha256:hash(JSON.stringify(m))})+'\n',{mode:0o400});
  return m;
}
function sourceBoundReceipt(source,runtime) {
  const e=receipt();e.sourceLifecycleSha256=/sourceLifecycleSha256 !== '([a-f0-9]{64})'/.exec(source)[1];
  e.runtimeNodeSha256=runtime.files['bin/node'].sha256;e.runtimeInstallationId=runtime.installationId;
  return e;
}
test('all three exact-source synthetic reports permit removal of an owned inert dependency without execution',async()=>{
  const p=await mkdtemp('/tmp/x10-node-inert-test-'),prefix=p+'/runtime',file=p+'/receipt.json';
  try {
    const runtime=await syntheticRuntime(prefix),source=await readFile(new URL('./verified-node.mjs',import.meta.url),'utf8');
    await writeFile(file,JSON.stringify(sourceBoundReceipt(source,runtime)),{mode:0o600});
    const result=await main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
    assert.equal(result.code,'verified_node_removed');assert.equal(result.ok,true);assert.equal(result.runtimeRemoved,true);
    await assert.rejects(lstat(prefix),{code:'ENOENT'});assert.deepEqual(await readdir(p),['receipt.json']);
  } finally {await rm(p,{recursive:true,force:true});}
});
test('actual reread of every changed package source retains inert dependency despite matching envelope pins',async()=>{
  const p=await mkdtemp('/tmp/x10-node-source-test-'),prefix=p+'/runtime',file=p+'/receipt.json',copy=p+'/checker';
  try {
    await mkdir(copy,{mode:0o700});
    for(const name of ['verified-node.mjs','operator-package-return.mjs','operator-package-return-proof.mjs',
      'operator-package-fallback.mjs','operator-package-fallback-proof.mjs'])
      await writeFile(copy+'/'+name,await readFile(new URL('./'+name,import.meta.url)),{mode:0o600});
    const source=await readFile(copy+'/verified-node.mjs','utf8'),runtime=await syntheticRuntime(prefix);
    const e=sourceBoundReceipt(source,runtime);await writeFile(file,JSON.stringify(e),{mode:0o600});
    const isolated=await import(new URL('file://'+copy+'/verified-node.mjs'));
    const before=await lstat(prefix),bytes=await readFile(prefix+'/bin/node');
    for(const name of ['operator-package-return.mjs','operator-package-return-proof.mjs',
      'operator-package-fallback.mjs','operator-package-fallback-proof.mjs']){
      const original=await readFile(copy+'/'+name);
      await writeFile(copy+'/'+name,Buffer.concat([original,Buffer.from('\n// public synthetic drift\n')]));
      const result=await isolated.main(['--cleanup','--prefix',prefix,'--service-evidence',file]);
      assert.equal(result.code,'runtime_retained_cleanup_unconfirmed',name);assert.equal(result.ok,false,name);
      assert.deepEqual(await readFile(prefix+'/bin/node'),bytes);assert.equal((await lstat(prefix)).ino,before.ino);
      assert.equal(JSON.stringify(result).includes(p),false);await writeFile(copy+'/'+name,original);
    }
  } finally {await rm(p,{recursive:true,force:true});}
});
