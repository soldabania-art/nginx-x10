// Baseline counterexample only: run from repository root. No native process,
// network, signal or service is exercised. Source pins refuse drift.
import { readFileSync as pinnedRead } from 'node:fs';
import { createHash as pinnedHash } from 'node:crypto';
if (pinnedHash('sha256').update(pinnedRead('x10/alpha/cli.mjs')).digest('hex') !== '2e8a04f64d04601f205ab05b724a93f60866ef37ad83b682f6f8df0f54f808fa') throw new Error('baseline source pin mismatch');
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
const source=await readFile('x10/alpha/cli.mjs','utf8');
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const dirs=['logs','temp','temp/client','temp/proxy','temp/fastcgi','temp/uwsgi','temp/scgi','.x10-control','.x10-control/revisions'];
const files=['nginx.conf','lifecycle.json','managed.conf','.x10-control/history.jsonl','.x10-control/settings.json','.x10-control/state.json','.x10-control/revisions/'+'a'.repeat(32)+'.json'];
const checks=[];
const prefix='/synthetic/inventory';
function tree(count){
 const entries=new Map([['',true],['runs',true]]);
 for(let i=0;i<count;i++){const b='runs/'+i.toString(16).padStart(32,'0');entries.set(b,true);for(const d of dirs)entries.set(b+'/'+d,true);for(const f of files)entries.set(b+'/'+f,false);}
 return entries;
}
const inventoryBlock=source.slice(source.indexOf('async function inventory(prefix) {'),source.indexOf('\nasync function uninstall(',source.indexOf('async function inventory(prefix) {')));
async function runInventory(count){
 const entries=tree(count);let seen=0;
 const owned=async(file,directory)=>{assert(entries.get(path.relative(prefix,file))===true);};
 const readdir=async file=>{const parent=path.relative(prefix,file);return [...entries.keys()].filter(k=>k!==''&&path.posix.dirname(k)===(parent||'.')).map(k=>path.posix.basename(k));};
 const lstat=async file=>{const d=entries.get(path.relative(prefix,file));assert.notEqual(d,undefined);seen++;return {uid:process.getuid(),isSymbolicLink:()=>false,isDirectory:()=>d,isFile:()=>!d};};
 const fn=await new AsyncFunction('path','owned','readdir','lstat','process','fail',inventoryBlock+'\nreturn inventory;')(path,owned,readdir,lstat,process,fail);
 try {let actual=await fn(prefix);return {sessions:count,minimumTreeEntries:entries.size-1,seen,ok:true,returned:actual.length};} catch(e){return {sessions:count,minimumTreeEntries:entries.size-1,seen,ok:false,code:e.code};}
}
const within=await runInventory(200);assert(within.ok);checks.push({name:'200-minimal-sessions-within-current-inventory-bound',...within});
const max=await runInventory(256);assert.equal(max.ok,false);assert.equal(max.code,'inventory_limit');assert(max.minimumTreeEntries>4096);checks.push({name:'documented256-minimal-sessions-exceed-inventory-bound',...max});
const digest=v=>createHash('sha256').update(v).digest('hex');
const body={input:{healthURL:'http://127.0.0.1:18081/ready'}};body.inputSha256=digest(JSON.stringify(body.input));
const revision={...body,recordSha256:digest(JSON.stringify(body))};
const current='a'.repeat(32),next='f'.repeat(32);
const context={prefix:'/synthetic/install',manifest:{},registry:{current,sessions:Array.from({length:255},(_,i)=>i.toString(16).padStart(32,'0'))}};context.registry.sessions[0]=current;
const life={stage:'stopped',session:current,prefix:'/synthetic/install/runs/'+current};let published=false;
const deps={path,digest,fail,lifecycle:async()=>life,stopped:async()=>{},sessionStatus:async()=>({result:{lastConfirmedRevision:'b'.repeat(32)}}),load:async()=>revision,createSession:async()=>({session:next,lifecycle:{stage:'prepared',session:next,runtime:null,controlSocket:null}}),saveRecord:async()=>{published=true;}};
const prepareBlock=source.slice(source.indexOf('async function prepareRun(context) {'),source.indexOf('\nasync function run(prefix, values) {'));
const prepare=await new AsyncFunction(...Object.keys(deps),prepareBlock+'\nreturn prepareRun;')(...Object.values(deps));
await prepare(context);assert.equal(context.registry.sessions.length,256);assert(published);checks.push({name:'prepareRun-accepts255-to256-source-sessions',sessions:context.registry.sessions.length,published:true,observationsVirtual:true});
const result={kind:'alpha-inventory-session-bound-counterexample',sourceBase:'60a470a57ec9381b149b8dced0ad7131d9fbec7a',controls:checks.length,pass:checks.length,checks,minimalPerSessionEntries:17,virtualOnly:true,physicalFixturesExecuted:0,networkFixturesExecuted:0,signalsSent:0,limits:['Preparation controller/native observations are virtual; production helper control flow and inventory walker are source-extracted unchanged.','This reproduces inconsistent finite supported bounds, not an actual256-native-session installation or exploit.']};
console.log(JSON.stringify(result));
