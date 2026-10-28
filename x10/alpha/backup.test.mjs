import test from 'node:test';
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// These controls use real private temporary files and source-extracted production
// helpers, with explicitly virtual native absence/status observations. They never
// start, signal or claim acceptance of a native daemon or service.
const source = await fs.readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile), AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const digest = value => createHash('sha256').update(value).digest('hex');
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const simple = value => typeof value === 'string' && /^\/[A-Za-z0-9_./+-]+$/.test(value) && path.resolve(value) === value;
const id = () => randomBytes(16).toString('hex');
const fail = (code,message=code) => { throw Object.assign(new Error(message), { code }); };
const input = () => ({ serverBody:'location / { return 200 "restored"; }',healthURL:'http://127.0.0.1:18081/ready',healthExpectedStatus:200,healthExpectedBody:'ready\n' });
function document(mutate = () => {}) {
  const value = {schemaVersion:1,kind:'nginx-x10-declarative-backup',source:{installationId:'a'.repeat(32),session:'b'.repeat(32),revision:'c'.repeat(32)},port:18080,healthPort:18081,input:input(),inputSha256:digest(JSON.stringify(input()))};
  mutate(value); return {...value,sha256:digest(JSON.stringify(value))};
}
const mark = '// Declarative backup foundation.', endMark = '// End declarative backup foundation.';
const start = source.indexOf(mark), end = source.indexOf(endMark);
assert(start >= 0 && end > start, 'production backup helper boundary exists');
const block = source.slice(start, end);
async function owned(file,directory=false,privateDirectory=false) {
  const stat=await fs.lstat(file);
  if (stat.isSymbolicLink() || (directory?!stat.isDirectory():!stat.isFile()) || stat.uid!==process.getuid()) fail('unsafe_path');
  if (privateDirectory?(stat.mode&0o077)!==0:(stat.mode&0o022)!==0) fail('unsafe_permissions');
  return stat;
}
async function canonical(file) {
  if(typeof file!=='string'||!/^\/[A-Za-z0-9_./+-]+$/.test(file)||path.resolve(file)!==file||await fs.realpath(file)!==file) fail('unsafe_path');
  return file;
}
async function helpers(extra={}) {
  const deps={...Object.fromEntries(Object.entries(fs).filter(([key])=>key!=='default')),path,constants,Buffer,process,digest,encode,same,simple,id,fail,owned,canonical,...extra};
  return new AsyncFunction(...Object.keys(deps),(extra.publishBackup?block.replace('async function publishBackup(', 'async function originalPublishBackup('):block)+'\nreturn {backupInput,backupDocument,readBackup,publishBackup,backup};')(...Object.values(deps));
}
async function temporary(fn) {
  const parent=await fs.mkdtemp(path.join(os.tmpdir(),'x10-backup-qa-'));await fs.chmod(parent,0o700);
  try { return await fn(parent); } finally { await fs.rm(parent,{recursive:true,force:true}); }
}
async function absent(file){return fs.lstat(file).then(()=>false,e=>{if(e.code==='ENOENT')return true;throw e;});}
async function refusal(fn){await assert.rejects(fn,error=>typeof error?.code==='string');}

// The dated pristine source is optional input only to this explicit baseline
// control. No baseline process/native binary is executed.
test('backup baseline has no backup command and restore is not an install option',async()=>{
  const baseline=(await execute('git',['show','eb577ff140b376b68c2cd10984deb736d3a9ed67:x10/alpha/cli.mjs'],{cwd:root,timeout:5000,maxBuffer:256*1024})).stdout;
  const main=baseline.slice(baseline.indexOf('export async function main('),baseline.indexOf('\nif (process.argv[1]'));
  let output='';const fakeProcess={umask:()=>0o077,stdout:{write:v=>output+=v},exitCode:0};
  const run=new AsyncFunction('process','parseArgs','fail','encode',main.replace('export async function','async function')+'\nreturn main;')(fakeProcess,parseArgs,fail,encode);
  for(const args of [['backup','--output','/synthetic/backup.json'],['install','--restore','/synthetic/backup.json','--prefix','/synthetic/new']]){
    output='';fakeProcess.exitCode=0;await (await run)(args,'/synthetic');assert.equal(fakeProcess.exitCode,1);assert.equal(JSON.parse(output).code,args[0]==='backup'?'arguments':'ERR_PARSE_ARGS_UNKNOWN_OPTION');
  }
});

test('backup strict document preserves exact declared input and ports',async()=>{
  const h=await helpers(),value=document(),copy=h.backupDocument(value);
  assert.deepEqual(copy,value);assert.deepEqual(value.input,input());assert.equal(value.port,18080);assert.equal(value.healthPort,18081);
});
for(const [name,mutate] of [
  ['schema',v=>v.schemaVersion=2],['kind',v=>v.kind='runtime-backup'],['unknown-field',v=>v.binding={pid:123}],
  ['source-extra',v=>v.source.pid=123],['source-id',v=>v.source.session='bad'],['privileged-port',v=>v.port=80],
  ['equal-ports',v=>v.healthPort=v.port],['noninteger-port',v=>v.port='18080'],
  ['input-hash',v=>v.inputSha256='0'.repeat(64)],['https-material',v=>{v.input.https={certificate:'/private/cert'};v.inputSha256=digest(JSON.stringify(v.input));}],
  ['input-extra',v=>{v.input.pid=123;v.inputSha256=digest(JSON.stringify(v.input));}],
  ['nonloopback-health',v=>{v.input.healthURL='http://example.invalid/ready';v.inputSha256=digest(JSON.stringify(v.input));}],
  ['health-credentials',v=>{v.input.healthURL='http://user:secret@127.0.0.1:18081/ready';v.inputSha256=digest(JSON.stringify(v.input));}],
  ['status-without-body',v=>{delete v.input.healthExpectedBody;v.inputSha256=digest(JSON.stringify(v.input));}],
  ['body-without-status',v=>{delete v.input.healthExpectedStatus;v.inputSha256=digest(JSON.stringify(v.input));}],
  ['oversize-body',v=>{v.input.serverBody='x'.repeat(1024*1024+1);v.inputSha256=digest(JSON.stringify(v.input));}],
]) test(`backup strict document refuses ${name}`,async()=>{const h=await helpers();assert.throws(()=>h.backupDocument(document(mutate)),error=>typeof error.code==='string');});

test('backup strict document refuses checksum mismatch and reordered top-level fields',async()=>{
  const h=await helpers(),v=document();v.sha256='0'.repeat(64);assert.throws(()=>h.backupDocument(v));
  const {schemaVersion,...rest}=document();assert.throws(()=>h.backupDocument({...rest,schemaVersion}));
});

test('backup reader accepts only bounded canonical private single-link file',()=>temporary(async parent=>{
  const h=await helpers(),file=path.join(parent,'backup.json'),v=document();await fs.writeFile(file,encode(v),{mode:0o600});
  assert.deepEqual(await h.readBackup(file),v);assert.equal((await fs.lstat(file)).mode&0o7777,0o600);
}));
for(const [name,change] of [
  ['truncated',text=>text.slice(0,-10)],['duplicate-key',text=>text.replace('"schemaVersion": 1,','"schemaVersion": 1,\n  "schemaVersion": 1,')],
  ['compact',text=>JSON.stringify(JSON.parse(text))],['trailing-data',text=>text+'{}'],['leading-space',text=>' '+text],
  ['malformed-secret',()=>'{"serverBody":"SYNTHETIC_SECRET_MUST_NOT_LEAK", INVALID'],
  ['oversized',()=>'x'.repeat(2*1024*1024+1)],
]) test(`backup reader refuses ${name} without returning raw input`,()=>temporary(async parent=>{
  const h=await helpers(),file=path.join(parent,'backup.json');await fs.writeFile(file,change(encode(document())),{mode:0o600});
  await assert.rejects(()=>h.readBackup(file),error=>{assert.doesNotMatch(String(error.message),/SYNTHETIC_SECRET_MUST_NOT_LEAK/);return typeof error.code==='string';});
}));
for(const mode of [0o400,0o640,0o660,0o644,0o700])test(`backup reader refuses mode ${mode.toString(8)}`,()=>temporary(async parent=>{
  const h=await helpers(),file=path.join(parent,'backup.json');await fs.writeFile(file,encode(document()),{mode:0o600});await fs.chmod(file,mode);await refusal(()=>h.readBackup(file));
}));
test('backup reader refuses symlink hardlink and ancestor alias',()=>temporary(async parent=>{
  const h=await helpers(),file=path.join(parent,'backup.json'),alias=path.join(parent,'alias');await fs.writeFile(file,encode(document()),{mode:0o600});
  await fs.symlink(file,alias);await refusal(()=>h.readBackup(alias));await fs.rm(alias);await fs.link(file,alias);await refusal(()=>h.readBackup(file));await fs.rm(alias);
  const directory=path.join(parent,'directory');await fs.symlink(parent,directory);await refusal(()=>h.readBackup(path.join(directory,'backup.json')));
}));

function commandHarness(extra={}) {
  const text=source.slice(source.indexOf('export async function main('),source.indexOf('\nif (process.argv[1]'));
  let output='',called=0;
  const fakeProcess={umask:()=>0o077,stdout:{write:value=>output+=value},stderr:{write:()=>{}},exitCode:0};
  const dependencies={process:fakeProcess,parseArgs,fail,encode,path,
    installed:async()=>{called++;fail('fixture_unexpected_installation_access');},
    install:async()=>{called++;return{ok:true};},pack:async()=>{called++;return{ok:true};},...extra};
  const pending=new AsyncFunction(...Object.keys(dependencies),text.replace('export async function','async function')+'\nreturn main;')(...Object.values(dependencies));
  return{run:async (args,installedPrefix=null)=>{output='';called=0;fakeProcess.exitCode=0;await(await pending)(args,installedPrefix);return{code:fakeProcess.exitCode,json:JSON.parse(output),called};}};
}
for(const args of [
  ['backup','--help'],['backup','--output','/synthetic/out','--help'],['backup','--output','/synthetic/out','--output','/synthetic/other'],
  ['backup','--output','/synthetic/out','--prefix','/synthetic/install'],['backup','--output','/synthetic/out','extra'],
  ['install','--restore','/synthetic/backup','--prefix','/synthetic/new','--help'],
  ['install','--restore','/synthetic/backup','--restore','/synthetic/other','--prefix','/synthetic/new'],
]) test(`backup command refuses ambiguous grammar before access: ${args.join(' ')}`,async()=>{
  const h=commandHarness(),r=await h.run(args);assert.equal(r.code,1);assert.equal(r.json.code,'arguments');assert.equal(r.called,0);
});

test('backup reader refuses an owned FIFO without waiting for a writer',()=>temporary(async parent=>{
  const h=await helpers(),fifo=path.join(parent,'fifo');await execute('mkfifo',[fifo],{timeout:3000});await fs.chmod(fifo,0o600);
  await refusal(()=>h.readBackup(fifo));
}));
test('backup reader refuses a directory and unsafe immediate parent',()=>temporary(async parent=>{
  const h=await helpers();await refusal(()=>h.readBackup(parent));const file=path.join(parent,'backup.json');await fs.writeFile(file,encode(document()),{mode:0o600});
  await fs.chmod(parent,0o750);try{await refusal(()=>h.readBackup(file));}finally{await fs.chmod(parent,0o700);}
}));

test('backup publication is exclusive private complete and rechecked before publication',()=>temporary(async parent=>{
  const h=await helpers(),prefix=path.join(parent,'install'),output=path.join(parent,'backup.json');await fs.mkdir(prefix,{mode:0o700});
  let checked=0;const result=await h.publishBackup({prefix},output,document(),async()=>{checked++;assert.equal(await absent(output),true);});
  assert.equal(checked,1);assert.equal(result.ok,true);assert.equal(result.outcome,'declarative_backup_created');
  for(const key of ['nativeStarted','serviceAccepted','productionAccepted'])assert.equal(result[key],false);
  assert.deepEqual(Object.keys(result),['ok','outcome','bytes','sha256','nativeStarted','serviceAccepted','productionAccepted']);
  const bytes=await fs.readFile(output);assert.equal(result.bytes,bytes.length);assert.equal(result.sha256,digest(bytes));assert.deepEqual(JSON.parse(bytes),document());
  const stat=await fs.lstat(output);assert.equal(stat.mode&0o7777,0o600);assert.equal(stat.nlink,1);assert.deepEqual((await fs.readdir(parent)).sort(),['backup.json','install']);
}));
for(const kind of ['file','symlink','directory','hardlink'])test(`backup publication refuses existing ${kind} without replacement`,()=>temporary(async parent=>{
  const h=await helpers(),prefix=path.join(parent,'install'),output=path.join(parent,'backup.json'),sentinel=path.join(parent,'sentinel');await fs.mkdir(prefix,{mode:0o700});await fs.writeFile(sentinel,'preserve',{mode:0o600});
  if(kind==='file')await fs.writeFile(output,'old',{mode:0o600});if(kind==='symlink')await fs.symlink(sentinel,output);if(kind==='directory')await fs.mkdir(output,{mode:0o700});if(kind==='hardlink')await fs.link(sentinel,output);
  const before=await fs.lstat(output);await refusal(()=>h.publishBackup({prefix},output,document(),async()=>{}));const after=await fs.lstat(output);
  assert.equal(after.ino,before.ino);assert.equal(after.mode,before.mode);assert.equal(await fs.readFile(sentinel,'utf8'),'preserve');
  if(kind==='file')assert.equal(await fs.readFile(output,'utf8'),'old');assert.equal((await fs.readdir(parent)).some(n=>n.startsWith('.x10-backup-')),false);
}));
test('backup publication refuses inside-installation and aliased/unsafe parents',()=>temporary(async parent=>{
  const h=await helpers(),prefix=path.join(parent,'install');await fs.mkdir(prefix,{mode:0o700});
  for(const output of [prefix,path.join(prefix,'secret.json')])await refusal(()=>h.publishBackup({prefix},output,document(),async()=>assert.fail('recheck reached')));
  const alias=path.join(parent,'alias');await fs.symlink(parent,alias);await refusal(()=>h.publishBackup({prefix},path.join(alias,'backup.json'),document(),async()=>{}));await fs.rm(alias);
  await fs.chmod(parent,0o750);try{await refusal(()=>h.publishBackup({prefix},path.join(parent,'backup.json'),document(),async()=>{}));}finally{await fs.chmod(parent,0o700);}
  assert.equal(await absent(path.join(parent,'backup.json')),true);
}));
test('backup publication preserves source recheck failure and removes unpublished temporary',()=>temporary(async parent=>{
  const h=await helpers(),prefix=path.join(parent,'install'),output=path.join(parent,'backup.json');await fs.mkdir(prefix,{mode:0o700});
  await assert.rejects(()=>h.publishBackup({prefix},output,document(),async()=>fail('operator_conflict')),{code:'operator_conflict'});
  assert.equal(await absent(output),true);assert.deepEqual(await fs.readdir(parent),['install']);
}));

function virtualSource(extra={}) {
  const events=[],session='b'.repeat(32),revisionId='c'.repeat(32),older='d'.repeat(32);
  const context={prefix:'/synthetic/install',manifest:{installationId:'a'.repeat(32),port:18080,healthPort:18081},registry:{current:session,sessions:[older,session]}};
  const lives=new Map(context.registry.sessions.map(s=>[s,{stage:'stopped',session:s,prefix:path.join(context.prefix,'runs',s),runtime:null,controlSocket:null}]));
  const status={lastConfirmedRevision:revisionId,binding:null,pending:null,configUnchanged:true,fragmentMatchesLastConfirmed:true,history:{integrity:true}};
  const body={id:revisionId,input:input(),inputSha256:digest(JSON.stringify(input()))};
  const revision={...body,recordSha256:digest(JSON.stringify(body))};let published=null,recheckCount=0;
  const deps={
    lifecycle:async(actual,s=context.registry.current)=>{assert.equal(actual,context);events.push('lifecycle:'+s);return lives.get(s);},
    stopped:async(actual,life)=>{assert.equal(actual,context);events.push('stopped:'+life.session);},
    sessionStatus:async(actual,life)=>{assert.equal(actual,context);events.push('status:'+life.session);return{result:status};},
    load:async file=>{assert.equal(file,path.join(lives.get(session).prefix,'.x10-control/revisions',revisionId+'.json'));events.push('revision');return revision;},
    installed:async prefix=>{assert.equal(prefix,context.prefix);events.push('installed-recheck');return context;},
    publishBackup:async(actual,output,value,recheck)=>{assert.equal(actual,context);assert.equal(output,'/synthetic/backup.json');events.push('publication');await recheck();recheckCount++;published=value;return{ok:true};},
    ...extra,
  };
  return{context,lives,status,revision,events,get published(){return published;},get recheckCount(){return recheckCount;},run:async()=>{const h=await helpers(deps);return h.backup(context,'/synthetic/backup.json');}};
}
test('backup virtual source guards every registered session twice and preserves exact declared input only',async()=>{
  const f=virtualSource();assert.deepEqual(await f.run(),{ok:true});assert.equal(f.recheckCount,1);assert.deepEqual(f.published,document());
  for(const session of f.context.registry.sessions)for(const name of ['lifecycle','stopped','status'])assert.equal(f.events.filter(e=>e===name+':'+session).length,2);
  assert.equal(f.events.filter(e=>e==='installed-recheck').length,1);assert.equal(f.published.binding,undefined);assert.equal(f.published.runtime,undefined);assert.equal(f.published.history,undefined);assert.equal(f.published.dependencies,undefined);
});
for(const stage of ['running','stopping','faulted'])for(const which of ['current','historical'])test(`backup refuses ${which} ${stage} despite virtual absence`,async()=>{
  const f=virtualSource(),session=which==='current'?f.context.registry.current:f.context.registry.sessions[0];f.lives.get(session).stage=stage;
  await assert.rejects(()=>f.run(),{code:'backup_requires_stopped'});assert.equal(f.published,null);assert.equal(f.events.includes('publication'),false);
});
for(const field of ['runtime','controlSocket'])test(`backup refuses prepared ${field} retention`,async()=>{
  const f=virtualSource(),life=f.lives.get(f.context.registry.current);life.stage='prepared';life[field]=field==='runtime'?{pid:123}:'/synthetic/socket';
  await assert.rejects(()=>f.run(),{code:'runtime_identity'});assert.equal(f.published,null);
});
for(const [at,code] of [['stopped','alpha_live'],['stopped','runtime_namespace'],['sessionStatus','operator_conflict'],['sessionStatus','operator_locked'],['load','alpha_integrity']])test(`backup preserves ${code} from ${at} before publication`,async()=>{
  const f=virtualSource({[at]:async()=>fail(code)});await assert.rejects(()=>f.run(),{code});assert.equal(f.published,null);assert.equal(f.events.includes('publication'),false);
});
for(const corruption of ['record','input','revision'])test(`backup refuses confirmed ${corruption} inconsistency`,async()=>{
  const f=virtualSource();if(corruption==='record')f.revision.recordSha256='0'.repeat(64);if(corruption==='input')f.revision.inputSha256='0'.repeat(64);if(corruption==='revision')f.revision.id='e'.repeat(32);
  await assert.rejects(()=>f.run(),{code:'alpha_integrity'});assert.equal(f.published,null);assert.equal(f.events.includes('publication'),false);
});
test('backup source recheck catches changed current confirmed input before link',async()=>{
  let calls=0;const f=virtualSource({load:async()=>{calls++;if(calls===2)fail('alpha_integrity');return f.revision;}});
  await assert.rejects(()=>f.run(),{code:'alpha_integrity'});assert.equal(calls,2);assert.equal(f.published,null);
});

function installFunction(dependencies) {
  const text=source.slice(source.indexOf('export async function install(values) {'),source.indexOf('\nasync function installed(prefix,'));
  const finite=Object.fromEntries(['INVENTORY_ENTRY_LIMIT','INITIAL_PUBLICATION_INSPECTION_RESERVE'].map(name=>{const m=new RegExp(`\\b${name}\\s*=\\s*([0-9]+)\\s*;`).exec(source);assert(m,name);return[name,Number(m[1])];}));
  const capacity=['inventory','requireSessionInventoryCapacity'].map(name=>{const start=source.indexOf(`async function ${name}(`),end=source.indexOf('\n}',start);assert(start>=0&&end>start);return source.slice(start,end+2);}).join('\n');
  const bound={...dependencies,...finite};
  return new AsyncFunction(...Object.keys(bound),capacity+'\n'+text.replace('export async function','async function')+'\nreturn install;')(...Object.values(bound));
}
for(const key of ['port','health-port','upstream-port'])test(`restore install refuses ${key} before any build or prefix write`,()=>temporary(async parent=>{
  const prefix=path.join(parent,'new'),backupFile=path.join(parent,'backup.json');let builds=0;
  const dependencies={...Object.fromEntries(Object.entries(fs).filter(([k])=>k!=='default')),process,path,Buffer,constants,simple,canonical,fail,
    exists:async file=>!await absent(file),readBackup:async()=>document(),sourceBuild:async()=>{builds++;assert.fail('build must not run');}};
  const install=await installFunction(dependencies);await assert.rejects(()=>install({prefix,restore:backupFile,[key]:'18080'}),{code:'arguments'});
  assert.equal(builds,0);assert.equal(await absent(prefix),true);
}));

test('restore virtual build prepares new installation records with literal input and no transferred runtime',()=>temporary(async parent=>{
  const prefix=path.join(parent,'new'),backupFile=path.join(parent,'backup.json'),binary=path.join(parent,'native-placeholder');
  const binaryBytes=Buffer.from('SYNTHETIC NONEXECUTED NATIVE BYTES\n');await fs.writeFile(binary,binaryBytes,{mode:0o500});
  const restored=document(),sourceBytes=encode(restored);await fs.writeFile(backupFile,sourceBytes,{mode:0o600});let builds=0,created=0,captured=null;
  const saved=[],freshInstallation='e'.repeat(32),freshSession='f'.repeat(32),freshRevision='1'.repeat(32);
  const build={binary:{sha256:digest(binaryBytes),bytes:binaryBytes.length},upstreamRevision:'2'.repeat(40),nginxVersion:'synthetic-not-executed',sourceDiffSha256:'3'.repeat(64),compiledModules:['synthetic-only'],dependencyVersionsFromHeaders:{scope:'virtual-build'}};
  const dependencies={...Object.fromEntries(Object.entries(fs).filter(([k])=>k!=='default')),process,path,os,Buffer,constants,simple,canonical,owned,fail,digest,encode,root,id:()=>freshInstallation,
    controlNames:['cli.mjs','manager.mjs','listeners.mjs','generations.mjs','status-format.mjs'],alphaNames:['cli.mjs','runtime.mjs','upstream-example.mjs'],
    staticDirectories:['bin','lib','lib/control','lib/alpha','licenses','examples','runs'],recipePath:'lib/service/user-unit.mjs',exists:async file=>!await absent(file),
    readBackup:async file=>{assert.equal(file,backupFile);return restored;},sourceBuild:async()=>{builds++;return{binary,build,source:root,manifestSha256:'4'.repeat(64),dependencies:{scope:'fresh-virtual-library-inventory'},notice:path.join(root,'x10/alpha/NOTICE.txt')};},
    createSession:async(actual,manifest,seed)=>{created++;assert.equal(actual,prefix);assert.equal(manifest.installationId,freshInstallation);assert.deepEqual(seed,restored.input);captured=structuredClone({manifest,seed});return{session:freshSession,initial:{revision:freshRevision},lifecycle:{prefix:path.join(prefix,'runs',freshSession),stage:'prepared',runtime:null,controlSocket:null}};},
    saveRecord:async(file,value)=>{saved.push({file,value:structuredClone(value)});await fs.writeFile(file,encode({...value,sha256:digest(JSON.stringify(value))}),{mode:0o600,flag:'wx'});},
  };
  const install=await installFunction(dependencies),result=await install({prefix,restore:backupFile});
  assert.equal(builds,1);assert.equal(created,1);assert.equal(result.ok,true);assert.equal(result.declarativeRestored,true);
  for(const key of ['nativeStarted','readinessChecked','controlApiEnabled','serviceAccepted','productionAccepted'])assert.equal(result[key],false);
  assert.equal(result.port,restored.port);assert.equal(result.healthPort,restored.healthPort);assert.equal(result.session,freshSession);assert.equal(result.revision,freshRevision);
  assert.notEqual(captured.manifest.installationId,restored.source.installationId);assert.notEqual(result.session,restored.source.session);assert.notEqual(result.revision,restored.source.revision);
  assert.deepEqual(captured.seed,restored.input);assert.equal(captured.manifest.dependencies.scope,'fresh-virtual-library-inventory');
  assert.match(result.healthNote,/Restored declarative HTTP input/);assert.match(result.healthNote,/no application health or traffic accepted/);
  assert.equal(saved.length,2);assert.deepEqual(saved[1].value,{schemaVersion:1,installationId:freshInstallation,current:freshSession,sessions:[freshSession]});
  assert.equal(saved[0].value.binding,undefined);assert.equal(saved[0].value.runtime,undefined);assert.equal(saved[0].value.history,undefined);assert.equal(saved[0].value.source,undefined);
  assert.equal(await fs.readFile(backupFile,'utf8'),sourceBytes);assert.deepEqual(await fs.readdir(path.join(prefix,'runs')),[],'virtual session stub performs no daemon/native work');
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(prefix,'examples/candidate-b.json'),'utf8')),restored.input);
}));

for(const condition of ['pending','configUnchanged','fragmentMatchesLastConfirmed','history'])test(`backup uses actual source sessionStatus refusal for ${condition}`,async()=>{
  const context={prefix:'/synthetic/install'},life={session:'b'.repeat(32),runtime:null};
  const result={configUnchanged:true,fragmentMatchesLastConfirmed:true,history:{integrity:true},pending:null,binding:null};
  if(condition==='pending')result.pending={stage:'reload_requested'};else if(condition==='history')result.history.integrity=false;else result[condition]=false;
  const text=source.slice(source.indexOf('async function sessionStatus('),source.indexOf('\nasync function stopped('));
  const dependencies={manager:async()=>({status:async()=>result}),controllerState:async()=>'/synthetic/state',fail,same,binding:value=>value};
  const status=await new AsyncFunction(...Object.keys(dependencies),text+'\nreturn sessionStatus;')(...Object.values(dependencies));
  await assert.rejects(()=>status(context,life),{code:'operator_conflict'});
});
for(const changed of ['manifest','registry'])test(`backup rejects freshly reread ${changed} drift before publication`,async()=>{
  const f=virtualSource({installed:async()=>{const fresh=structuredClone(f.context);if(changed==='manifest')fresh.manifest.installationId='e'.repeat(32);else fresh.registry.current='e'.repeat(32);return fresh;}});
  await assert.rejects(()=>f.run(),{code:'operator_conflict'});assert.equal(f.published,null);
});

test('backup reader closes rejected descriptor and never reads an invalid file identity',()=>temporary(async parent=>{
  const file=path.join(parent,'backup.json');await fs.writeFile(file,encode(document()),{mode:0o600});let closed=0,reads=0;
  const real=await fs.lstat(file),h=await helpers({open:async()=>({stat:async()=>({...real,isFile:()=>false}),read:async()=>{reads++;assert.fail('refused descriptor must not be read');},close:async()=>{closed++;}})});
  await refusal(()=>h.readBackup(file));assert.equal(closed,1);assert.equal(reads,0);
}));
test('backup reader closes descriptor after read failure without claiming a backup',()=>temporary(async parent=>{
  const file=path.join(parent,'backup.json');await fs.writeFile(file,encode(document()),{mode:0o600});let closed=0;
  const real=await fs.lstat(file),h=await helpers({open:async()=>({stat:async()=>real,read:async()=>fail('fixture_read_error'),close:async()=>{closed++;}})});
  await assert.rejects(()=>h.readBackup(file),{code:'fixture_read_error'});assert.equal(closed,1);
}));

test('backup reader refuses noncanonical malformed UTF8 bytes even if decoder replacement preserves hashes',()=>temporary(async parent=>{
  const h=await helpers(),file=path.join(parent,'backup.json');
  const value=document(v=>{v.input.serverBody='location / { return 200 "\ufffd"; }';v.inputSha256=digest(JSON.stringify(v.input));});
  const canonical=Buffer.from(encode(value)),replacement=Buffer.from('\ufffd'),offset=canonical.indexOf(replacement);assert(offset>=0);
  const invalid=Buffer.concat([canonical.subarray(0,offset),Buffer.from([0xff]),canonical.subarray(offset+replacement.length)]);
  await fs.writeFile(file,invalid,{mode:0o600});await refusal(()=>h.readBackup(file));
}));

for(const command of ['backup','restore'])test(`backup public ${command} failure envelope omits raw exception input and path`,async()=>{
  const failure=()=>{throw Object.assign(new Error('SYNTHETIC_SECRET_EXCEPTION /synthetic/private/config'),{code:'bad\nSYNTHETIC_SECRET_CODE'});};
  const h=commandHarness({installed:failure,install:failure});
  const args=command==='backup'?['backup','--output','/synthetic/private/backup']:['install','--prefix','/synthetic/new','--restore','/synthetic/private/backup'];
  const r=await h.run(args,command==='backup'?'/synthetic/install':null);assert.equal(r.code,1);assert.equal(r.json.ok,false);
  assert.deepEqual(Object.keys(r.json),['ok','code','error']);assert.equal(r.json.code,'backup_restore_refused');
  assert.doesNotMatch(JSON.stringify(r.json),/SYNTHETIC_SECRET|\/synthetic\//);
});
