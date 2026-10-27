// Baseline counterexample only: run from repository root. No native process,
// network, signal or service is exercised. Source pins refuse drift.
import { readFileSync as pinnedRead } from 'node:fs';
import { createHash as pinnedHash } from 'node:crypto';
if (pinnedHash('sha256').update(pinnedRead('x10/control/manager.mjs')).digest('hex') !== '5073eb2dc194bba659e664c58b259469372625505b7c46798ec9b397095d7822') throw new Error('baseline source pin mismatch');
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,readlink,symlink,lstat} from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';import vm from 'node:vm';import{createHash}from'node:crypto';
import {status,history,recover} from '../control/manager.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const source=await readFile(new URL('../control/manager.mjs',import.meta.url),'utf8');
const render=vm.runInNewContext('('+source.slice(source.indexOf('function render('),source.indexOf('\nasync function makeRevision'))+')');
const parent=await mkdtemp(path.join(os.tmpdir(),'x10-control-static-'));await import('node:fs/promises').then(x=>x.chmod(parent,0o700));
const records=[];let seq=0;
async function fixture(){const prefix=path.join(parent,'p'+seq++);const state=path.join(prefix,'.x10-control');await mkdir(prefix,{mode:0o700});await mkdir(state,{mode:0o700});await mkdir(path.join(state,'revisions'),{mode:0o700});const settings={schemaVersion:1,prefix,state,config:path.join(prefix,'nginx.conf'),fragment:path.join(prefix,'managed.conf'),pidFile:path.join(prefix,'nginx.pid'),binary:'/nonexecuted/native-placeholder',port:8088,gateTimeoutMs:500,pidNamespace:await readlink('/proc/self/ns/pid'),configSha256:hash('config')};const rev={schemaVersion:1,id:'a'.repeat(32),createdAt:'2026-10-27T00:00:00.000Z',parent:null,sourceRevision:null,input:{serverBody:'location / {return 200 "A";}',healthURL:'http://127.0.0.1:9090/ready'}};rev.inputSha256=hash(JSON.stringify(rev.input));rev.fragmentSha256=hash(render(settings,rev));rev.recordSha256=hash(JSON.stringify(rev));const stateRecord={schemaVersion:1,activeRevision:rev.id,previousRevision:null,binding:null,historyHead:null};const put=async(p,v,mode=0o600)=>writeFile(path.join(state,p),typeof v==='string'?v:JSON.stringify(v),{mode});await put('settings.json',settings);await put('state.json',stateRecord);await put('history.jsonl','');await put('revisions/'+rev.id+'.json',rev,0o400);await writeFile(settings.config,'config',{mode:0o600});await writeFile(settings.fragment,render(settings,rev),{mode:0o600});return{prefix,state,settings,put,stateRecord,rev};}
async function test(name,fn){await fn();records.push({name,pass:true});}
try{
 await test('valid-unbound-status-no-network',async()=>{const f=await fixture();const s=await status(f.state);assert.equal(s.ok,true);assert.equal(s.binding,null);assert.equal(s.runtime.identityValid,false);assert.equal(s.fragmentMatchesLastConfirmed,true);await assert.rejects(lstat(path.join(f.state,'lock')),{code:'ENOENT'});});
 await test('valid-empty-history',async()=>{const f=await fixture();assert.deepEqual(await history(f.state),{ok:true,records:[]});});
 await test('unknown-state-property-refused',async()=>{const f=await fixture();await f.put('state.json',{...f.stateRecord,unknown:true});await assert.rejects(status(f.state),{code:'state_integrity'});});
 await test('null-pending-not-absence',async()=>{const f=await fixture();await f.put('pending.json','null');await assert.rejects(status(f.state),{code:'journal_integrity'});});
 await test('false-intent-not-absence',async()=>{const f=await fixture();await f.put('event-commit.json','false');await assert.rejects(status(f.state),{code:'commit_integrity'});});
 await test('state-symlink-refused',async()=>{const f=await fixture();await rm(path.join(f.state,'state.json'));await symlink('../nginx.conf',path.join(f.state,'state.json'));await assert.rejects(status(f.state),{code:'unsafe_path'});});
 await test('partial-history-refused',async()=>{const f=await fixture();await f.put('history.jsonl','{}');await assert.rejects(history(f.state),{code:'history_integrity'});});
 await test('history-head-mismatch-refused',async()=>{const f=await fixture();await f.put('state.json',{...f.stateRecord,historyHead:'b'.repeat(64)});await assert.rejects(history(f.state),{code:'history_integrity'});});
 await test('existing-lock-retained',async()=>{const f=await fixture();await f.put('lock','sentinel');await assert.rejects(history(f.state),{code:'locked'});assert.equal(await readFile(path.join(f.state,'lock'),'utf8'),'sentinel');});
 await test('recover-nothing-pending-does-not-repair-or-activate',async()=>{const f=await fixture();assert.deepEqual(await recover(f.state),{ok:true,outcome:'nothing_pending'});assert.deepEqual(JSON.parse(await readFile(path.join(f.state,'state.json'),'utf8')),f.stateRecord);});
 await test('damaged-revision-refused',async()=>{const f=await fixture();await rm(path.join(f.state,'revisions',f.rev.id+'.json'));await f.put('revisions/'+f.rev.id+'.json',{...f.rev,inputSha256:'0'.repeat(64)},0o400);await assert.rejects(status(f.state),{code:'revision_integrity'});});
 await test('oversized-settings-extra-property-accepted-unbounded-disk-json',async()=>{const f=await fixture();await f.put('settings.json',{...f.settings,operatorExtra:'x'.repeat(3*1024*1024)});assert.equal((await status(f.state)).ok,true);});
 await test('oversize-history-refused',async()=>{const f=await fixture();await f.put('history.jsonl',' '.repeat(16*1024*1024+1));await assert.rejects(history(f.state),{code:'history_limit'});});
}finally{await rm(parent,{recursive:true,force:true});}
console.log(JSON.stringify({kind:'independent-control-tempfile-source-review',tests:records.length,pass:records.length,fail:0,records,physicalFixturesExecuted:0,networkFixturesExecuted:0,subprocessesExecuted:0,signalsSent:0,serviceAccepted:false,productionAccepted:false}));
