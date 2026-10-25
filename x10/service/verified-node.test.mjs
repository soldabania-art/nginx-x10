import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, symlink, readdir, lstat, unlink, rmdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { PIN, parseTar, parseChecksumText, parseSignatureStatus, cleanupEvidence, main } from './verified-node.mjs';
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
function receipt() {
  return { checkerExited:true, checkerExitCode:0, report:{ ok:true, code:'basic_lifecycle_verified', phase:'complete', actualNonrootManagerObserved:true, actualUnitStarted:true,
    runtimeUnitLinked:true, runtimeUnitRemoved:true, unitEnabled:false,
    readinessAutomated:true, automaticReadinessAccepted:false, serviceAccepted:false, productionAccepted:false, subprocessOutputsPublished:false,
    primaryFailure:null, cleanupFailures:[], cleanupFailureCount:0, cleanupFailuresTruncated:false,
    explicitReadinessPasses:3, nativeSessionsStarted:3, nativeSessionsStopped:3, proxyBodyChecks:3, uploadChecks:3, streamChecks:3,
    managerRestartCommands:1, completedManagerRestarts:1,
    restartProof:{oldLauncherExited:true,oldNativeGroupsAbsent:true,freshSession:true,freshInvocation:true},
    journalChecks:3,journalRecordsObserved:6,journalRunningMarkers:3,
    cleanup:{ managerStopped:true, launcherExited:true, nativeGroupsAbsent:true, listeningPortsClosed:true, controlSocketAbsent:true, runtimeLinkAbsent:true, installationRemoved:true, temporaryRootRemoved:true, appSocketsRemaining:0 } } };
}
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
test('cleanup refuses the stale two-session profile and mixed session counts',()=>{
  const counters=['explicitReadinessPasses','nativeSessionsStarted','nativeSessionsStopped','proxyBodyChecks','uploadChecks','streamChecks'];
  const old=receipt();for(const k of counters)old.report[k]=2;
  delete old.report.restartProof;delete old.report.managerRestartCommands;delete old.report.completedManagerRestarts;
  delete old.report.journalChecks;delete old.report.journalRecordsObserved;delete old.report.journalRunningMarkers;
  assert.equal(cleanupEvidence(old),false);
  for(const k of counters)for(const value of [undefined,2,4,'3',NaN]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
});
test('cleanup requires exactly one completed restart and all four own exit/freshness proofs',()=>{
  for(const k of ['managerRestartCommands','completedManagerRestarts'])for(const value of [undefined,0,2,'1',true]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  for(const k of Object.keys(receipt().report.restartProof))for(const value of [undefined,false,1,'true']){const e=receipt();e.report.restartProof[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  for(const value of [null,[],true,{},Object.create(receipt().report.restartProof)]){const e=receipt();e.report.restartProof=value;assert.equal(cleanupEvidence(e),false);}
  const extra=receipt();extra.report.restartProof.unverified=true;assert.equal(cleanupEvidence(extra),false);
});
test('cleanup bounds journal evidence without accepting absent or inconsistent markers',()=>{
  for(const value of [undefined,0,2,4,'3',true]){const e=receipt();e.report.journalChecks=value;assert.equal(cleanupEvidence(e),false);}
  for(const k of ['journalRecordsObserved','journalRunningMarkers'])for(const value of [undefined,0,2,385,3.5,'3',NaN,Infinity]){const e=receipt();e.report[k]=value;assert.equal(cleanupEvidence(e),false,k);}
  const inconsistent=receipt();inconsistent.report.journalRecordsObserved=3;inconsistent.report.journalRunningMarkers=4;assert.equal(cleanupEvidence(inconsistent),false);
  for(const count of [3,384]){const e=receipt();e.report.journalRecordsObserved=count;e.report.journalRunningMarkers=count;assert.equal(cleanupEvidence(e),true);}
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
