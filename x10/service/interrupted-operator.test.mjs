import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, realpath, lstat, rm, rename, copyFile, chmod, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { startOwnedOperator, parseOperatorProcessProfile, inspectOperatorProcessProfile, INTERRUPTED_OPERATOR_ERROR_CODES } from './interrupted-operator.mjs';
const digest = b => createHash('sha256').update(b).digest('hex'), wait = ms => new Promise(r => setTimeout(r, ms));
let nodeParent, ownNode;
const supportedProfile = await inspectOperatorProcessProfile().then(()=>true,e=>{if(e.code==='operator_fixture_profile')return false;throw e;});
const processTest=(name,fn)=>test(name,{skip:supportedProfile?false:'operator_fixture_profile: direct PID/group/session view required; no local process-group acceptance'},fn);
before(async()=>{if(!supportedProfile)return;nodeParent=await mkdtemp(path.join(os.tmpdir(),'x10-owned-node-'));ownNode=nodeParent+'/node';await copyFile(await realpath(process.execPath),ownNode);await chmod(ownNode,0o500);});
after(async()=>{if(nodeParent&&retainedFixtureRoots.size===0)await rm(nodeParent,{recursive:true});});
const retainedFixtureRoots = new Set();
const wrapperSource = extra => `import {writeFile} from 'node:fs/promises';import {writeFileSync} from 'node:fs';import {spawn} from 'node:child_process';import path from 'node:path';
const prefix=path.dirname(path.dirname(process.argv[1]));const state=prefix+'/runs/${'a'.repeat(32)}/.x10-control';
await writeFile(prefix+'/.alpha-lock',JSON.stringify({pid:process.pid,at:new Date().toISOString()},null,2)+'\\n',{mode:0o600,flag:'wx'});
const children=[],closed=new Set();let reason=null;
const finish=()=>{if(reason&&closed.size===children.length)process.exit(reason==='signal'?0:3)};
const make=args=>{const c=spawn(process.execPath,args,{stdio:'ignore'});children.push(c);c.once('close',()=>{closed.add(c);if(!reason)reason='unexpected_child_exit';finish()});return c};
make([prefix+'/lib/control/cli.mjs','apply','--state',state,'--file',process.argv[4]]);
${extra ? "make(['-e','setTimeout(()=>process.exit(3),10000)']);" : ''}
process.on('SIGTERM',()=>{if(!reason){reason='signal';writeFileSync(prefix+'/.fixture-term-observed','SIGTERM\\n',{mode:0o600,flag:'wx'})}finish()});
setTimeout(()=>{if(!reason){reason='expiry';writeFileSync(prefix+'/.fixture-expired','expiry\\n',{mode:0o600,flag:'wx'})}for(const c of children)if(!closed.has(c))c.kill('SIGTERM');finish()},9000);`;
const controlSource = `import {writeFile} from 'node:fs/promises';const state=process.argv[4];await writeFile(state+'/lock',JSON.stringify({pid:process.pid,at:new Date().toISOString()},null,2)+'\\n',{mode:0o600,flag:'wx'});await writeFile(state+'/pending.json',JSON.stringify({stage:'reload_requested',id:'${'b'.repeat(32)}'})+'\\n',{mode:0o600,flag:'wx'});setTimeout(()=>process.exit(3),10000);`;
async function fixtureGroup(pgid) {
 const names=(await readdir('/proc')).filter(x=>/^[1-9][0-9]*$/.test(x));assert(names.length<=10000);const members=[];
 for(const n of names){try{const st=await readFile('/proc/'+n+'/stat','utf8'),f=st.slice(st.lastIndexOf(') ')+2).trim().split(/\s+/);if(Number(f[2])===pgid)members.push(Number(n));}catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}}
 return members;
}
async function fixture(fn, extra = false) {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'x10-operator-test-')), prefix = parent+'/install', sessionPrefix = prefix+'/runs/'+'a'.repeat(32);
  for (const p of [prefix,prefix+'/bin',prefix+'/lib',prefix+'/lib/control',prefix+'/runs',sessionPrefix,sessionPrefix+'/.x10-control']) await mkdir(p,{mode:0o700});
  const launcher=prefix+'/bin/x10', controller=prefix+'/lib/control/cli.mjs', inputFile=parent+'/input.json', node=ownNode;
  const w=Buffer.from(wrapperSource(extra)), c=Buffer.from(controlSource); await writeFile(launcher,w,{mode:0o500});await writeFile(controller,c,{mode:0o400});await writeFile(inputFile,'{}\n',{mode:0o600});
  const st=await lstat(prefix), record={prefix,rootIdentity:{dev:st.dev,ino:st.ino,uid:process.getuid()},nodeRuntime:{executable:node,sha256:digest(await readFile(node))},immutable:{'bin/x10':{sha256:digest(w),bytes:w.length,mode:'0500'},'lib/control/cli.mjs':{sha256:digest(c),bytes:c.length,mode:'0400'}}};
  await writeFile(prefix+'/.alpha-install.json',JSON.stringify({...record,sha256:digest(JSON.stringify(record))},null,2)+'\n',{mode:0o600});
  let held=true, cancelled=false, h, fixturePID;
  const o={node,launcher,prefix,sessionPrefix,inputFile,env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},isHeld:()=>held,checkCancelled:()=>{if(cancelled)throw new Error('fixture_cancelled');},timeoutMs:10000};
  try {
    await fn({o,parent,prefix,sessionPrefix,setHeld:v=>held=v,setCancelled:v=>cancelled=v,
      async start(){h=await startOwnedOperator(o);return h;},
      async ready(){const deadline=Date.now()+2000;while(Date.now()<deadline){try{const a=JSON.parse(await readFile(prefix+'/.alpha-lock'));const b=JSON.parse(await readFile(sessionPrefix+'/.x10-control/lock'));await readFile(sessionPrefix+'/.x10-control/pending.json');fixturePID=a.pid;return {wrapper:a.pid,controller:b.pid};}catch{await wait(10);}}throw new Error('fixture_not_ready');}
    });
  } finally {
    if(h)await h.close();
    // This test-only owner separately inspects its exact created group after
    // negative controls revoke the helper. Only a supported direct PID view
    // reaches these fixtures. Unknown cleanup preserves all private files.
    if(!fixturePID){try{fixturePID=JSON.parse(await readFile(prefix+'/.alpha-lock')).pid;}catch{}}
    let clean=false;
    try {
      if(fixturePID){
        try{const argv=(await readFile('/proc/'+fixturePID+'/cmdline')).toString().split('\0');
          if(argv[0]!==node||argv[1]!==launcher)throw new Error('fixture_owner_changed');
          process.kill(-fixturePID,'SIGTERM');
        }catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}
        const end=Date.now()+3000;
        while(Date.now()<end){const members=await fixtureGroup(fixturePID);let ownerAbsent=false;
          try{await lstat('/proc/'+fixturePID);}catch(e){if(e.code==='ENOENT')ownerAbsent=true;else throw e;}
          if(ownerAbsent&&members.length===0){clean=true;break;}await wait(10);
        }
      }else clean=!h;
      assert.equal(clean,true,'fixture_cleanup_unconfirmed_preserved');
    } catch(e) {retainedFixtureRoots.add(parent);throw e;}
    if(clean)await rm(parent,{recursive:true});
  }

}
test('fixed error allowlist is frozen and contains no runtime identities',()=>{assert(Object.isFrozen(INTERRUPTED_OPERATOR_ERROR_CODES));assert.equal(new Set(INTERRUPTED_OPERATOR_ERROR_CODES).size,INTERRUPTED_OPERATOR_ERROR_CODES.length);assert(INTERRUPTED_OPERATOR_ERROR_CODES.every(x=>/^operator_fixture_[a-z_]+$/.test(x)));});
processTest('actual own Node wrapper/control group is captured, terminated and only explicit locks retired',async()=>{
  await fixture(async f=>{
    const h=await f.start();await f.ready();assert.deepEqual(await h.captureLocks(),{ok:true,alphaCaptured:true,controllerCaptured:true,pendingCaptured:true});
    assert.deepEqual(h.snapshot(),{running:true,wrapperCaptured:true,controllerCaptured:true,groupCaptured:true,terminated:false,locksRetired:false});
    const pending=await readFile(f.sessionPrefix+'/.x10-control/pending.json');
    assert.deepEqual(await h.terminate(),{ok:true,wrapperExited:true,controllerExited:true,groupAbsent:true});
    assert.equal(await readFile(f.prefix+'/.fixture-term-observed','utf8'),'SIGTERM\n');await assert.rejects(lstat(f.prefix+'/.fixture-expired'),{code:'ENOENT'});
    assert.equal((await lstat(f.prefix+'/.alpha-lock')).isFile(),true);assert.equal((await lstat(f.sessionPrefix+'/.x10-control/lock')).isFile(),true);
    assert.deepEqual(await h.removeCapturedLocks(),{ok:true,alphaRemoved:true,controllerRemoved:true});assert.equal(await h.close(),true);
    assert.deepEqual(await readFile(f.sessionPrefix+'/.x10-control/pending.json'),pending);
    await assert.rejects(h.terminate(),{code:'operator_fixture_state'});await assert.rejects(h.removeCapturedLocks(),{code:'operator_fixture_state'});
  });
});
processTest('explicit cancellation cleans captured operator group after hold authority was revoked',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();f.setHeld(false);assert.equal(await h.close(),true);assert.equal(await readFile(f.prefix+'/.fixture-term-observed','utf8'),'SIGTERM\n');await assert.rejects(lstat(f.prefix+'/.fixture-expired'),{code:'ENOENT'});assert.equal(h.snapshot().terminated,true);assert.equal(h.snapshot().locksRetired,false);});
});
processTest('intentional cancellation refuses lost hold but guarded cleanup still retires owned group',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();f.setHeld(false);await assert.rejects(h.terminate(),{code:'operator_fixture_not_held'});assert.equal(await h.close(),true);assert.equal(await readFile(f.prefix+'/.fixture-term-observed','utf8'),'SIGTERM\n');await assert.rejects(lstat(f.prefix+'/.fixture-expired'),{code:'ENOENT'});});
});
processTest('capture refuses a false or promise hold without issuing a signal',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();f.setHeld(false);await assert.rejects(h.captureLocks(),{code:'operator_fixture_not_held'});assert.equal(h.snapshot().running,true);});
  await fixture(async f=>{f.o.isHeld=()=>Promise.resolve(true);const h=await f.start();await f.ready();await assert.rejects(h.captureLocks(),{code:'operator_fixture_not_held'});assert.equal(h.snapshot().running,true);});
});
processTest('foreign extra group member refuses capture instead of broad signaling',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await assert.rejects(h.captureLocks(),{code:'operator_fixture_group'});assert.equal(h.snapshot().groupCaptured,false);},true);
});
processTest('replacement lock inode refuses explicit retirement without deleting pending state',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();await h.terminate();const p=f.prefix+'/.alpha-lock',b=await readFile(p);await rename(p,p+'.saved');await writeFile(p,b,{mode:0o600,flag:'wx'});await assert.rejects(h.removeCapturedLocks(),{code:'operator_fixture_lock_changed'});assert.equal((await lstat(p)).isFile(),true);assert.equal((await lstat(f.sessionPrefix+'/.x10-control/pending.json')).isFile(),true);});
});
processTest('foreign lock owner refuses capture before any group authority',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await writeFile(f.sessionPrefix+'/.x10-control/lock',JSON.stringify({pid:process.pid,at:new Date().toISOString()})+'\n',{mode:0o600});await assert.rejects(h.captureLocks(),{code:'operator_fixture_process'});assert.equal(h.snapshot().groupCaptured,false);});
});
processTest('captured pending mutation refuses termination and lock retirement',async()=>{
  await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();await writeFile(f.sessionPrefix+'/.x10-control/pending.json','{"stage":"altered"}\n',{mode:0o600});await assert.rejects(h.terminate(),{code:'operator_fixture_pending'});assert.equal(h.snapshot().terminated,false);await assert.rejects(h.removeCapturedLocks(),{code:'operator_fixture_state'});});
});
test('invalid input and inherited/getter options refuse without evaluation',async()=>{
  let calls=0;const o={};Object.defineProperty(o,'node',{get(){calls++;return '/untrusted';}});await assert.rejects(startOwnedOperator(o),{code:'operator_fixture_invalid'});assert.equal(calls,0);
  for(const v of [null,[],{},Object.create({node:'/fake'}),{prefix:'/tmp/../escape'}])await assert.rejects(startOwnedOperator(v),{code:'operator_fixture_invalid'});
});
processTest('preexisting locks are not adopted or overwritten',async()=>{
  await fixture(async f=>{await writeFile(f.prefix+'/.alpha-lock','preserve\n',{mode:0o600});await assert.rejects(f.start(),{code:'operator_fixture_locked'});assert.equal(await readFile(f.prefix+'/.alpha-lock','utf8'),'preserve\n');});
});

const sample = () => ({pid:100,ppid:50,status:'Pid:\t100\nPPid:\t50\nNSpid:\t100\nNSpgid:\t100\nNSsid:\t100\n',stat:'100 (node) S 50 100 100 '+Array(15).fill('0').join(' ')+' 12345\n'});
test('bounded profile parser accepts only one direct PID/group/session view',()=>{assert.deepEqual(parseOperatorProcessProfile(sample()),{supported:true,directPIDView:true,directGroupView:true,directSessionView:true});});
for(const key of ['NSpid','NSpgid','NSsid'])test('profile refuses nested '+key+' rather than inferring a mapping',()=>{const v=sample();v.status=v.status.replace(key+':\t100',key+':\t999 100');assert.throws(()=>parseOperatorProcessProfile(v),{code:'operator_fixture_profile'});});
test('profile rejects mismatched, duplicate, malformed and excessive observations',()=>{
 for(const mutate of [v=>v.pid=101,v=>v.ppid=51,v=>v.status+='NSpid:\t100\n',v=>v.status=v.status.replace('NSpgid:\t100','NSpgid:\t101'),v=>v.status=v.status.replace('NSsid:\t100','NSsid:\t101'),v=>v.stat='invalid',v=>v.status='x'.repeat(65537)]){const v=sample();mutate(v);assert.throws(()=>parseOperatorProcessProfile(v),{code:'operator_fixture_profile'});}
});
test('profile rejects getters and non-data values without evaluating them',()=>{let calls=0;const v=sample();Object.defineProperty(v,'status',{get(){calls++;return''}});assert.throws(()=>parseOperatorProcessProfile(v),{code:'operator_fixture_profile'});assert.equal(calls,0);});
test('actual process profile is either direct or a fixed pre-spawn refusal',async()=>{
 if(supportedProfile){assert.equal((await inspectOperatorProcessProfile()).supported,true);return;}
 await assert.rejects(inspectOperatorProcessProfile(),{code:'operator_fixture_profile'});
 await assert.rejects(startOwnedOperator({node:'/absent/node',launcher:'/absent/install/bin/x10',prefix:'/absent/install',sessionPrefix:'/absent/install/runs/'+'a'.repeat(32),inputFile:'/absent/input.json',env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},isHeld:()=>false,checkCancelled:()=>{}}),{code:'operator_fixture_profile'});
});

processTest('failure-only lock retirement preserves primary refusal while reusing captured cleanup authority',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();f.setHeld(false);
  await assert.rejects(h.terminate(),{code:'operator_fixture_not_held'});assert.equal(await h.close(),true);
  const pending=await readFile(f.sessionPrefix+'/.x10-control/pending.json');
  assert.deepEqual(await h.retireCapturedLocksAfterFailure(),{ok:true,alphaRemoved:true,controllerRemoved:true,pendingPreserved:true});
  assert.equal(h.assertCleanupAuthority(),true);assert.deepEqual(await readFile(f.sessionPrefix+'/.x10-control/pending.json'),pending);
  assert.equal(h.snapshot().locksRetired,true);await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
 });
});
processTest('failure lock retirement never adopts a cleanup-only unaccepted capture',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();assert.equal(await h.close(),true);
  assert.equal(h.snapshot().groupCaptured,false);await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
  assert.throws(()=>h.assertCleanupAuthority(),{code:'operator_fixture_state'});assert.equal((await lstat(f.prefix+'/.alpha-lock')).isFile(),true);
 });
});
processTest('failure lock retirement refuses a live operator and requires explicit successful close',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});assert.equal(h.snapshot().running,true);
  await h.terminate();await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
  assert.equal(await h.close(),true);assert.equal((await h.retireCapturedLocksAfterFailure()).pendingPreserved,true);
 });
});
processTest('changed captured lock refuses failure retirement and consumes the one-shot decision',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();assert.equal(await h.close(),true);
  const lock=f.prefix+'/.alpha-lock',bytes=await readFile(lock);await rename(lock,lock+'.saved');await writeFile(lock,bytes,{mode:0o600,flag:'wx'});
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_lock_changed'});
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});await assert.rejects(h.removeCapturedLocks(),{code:'operator_fixture_state'});
  assert.equal(h.snapshot().locksRetired,false);assert.equal((await lstat(lock)).isFile(),true);
 });
});
processTest('changed pending state refuses failure retirement without deleting either captured lock',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();assert.equal(await h.close(),true);
  await writeFile(f.sessionPrefix+'/.x10-control/pending.json','{"stage":"changed"}\n',{mode:0o600});
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_pending'});
  for(const p of[f.prefix+'/.alpha-lock',f.sessionPrefix+'/.x10-control/lock'])assert.equal((await lstat(p)).isFile(),true);
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
 });
});
processTest('failure lock cleanup keeps original expiry and never renews an expired capture',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();assert.equal(await h.close(),true);
  const {performance}=await import('node:perf_hooks'),old=Object.getOwnPropertyDescriptor(performance,'now'),future=performance.now()+20000;
  Object.defineProperty(performance,'now',{configurable:true,value:()=>future});
  try{await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_timeout'});assert.equal(h.snapshot().locksRetired,false);}
  finally{if(old)Object.defineProperty(performance,'now',old);else delete performance.now;}
  assert.equal((await lstat(f.prefix+'/.alpha-lock')).isFile(),true);await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
 });
});
processTest('failure lock retirement respects current cancellation and retains unknown state',async()=>{
 await fixture(async f=>{const h=await f.start();await f.ready();await h.captureLocks();assert.equal(await h.close(),true);f.setCancelled(true);
  await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_cancelled'});
  assert.equal((await lstat(f.prefix+'/.alpha-lock')).isFile(),true);assert.equal(h.snapshot().locksRetired,false);
  f.setCancelled(false);await assert.rejects(h.retireCapturedLocksAfterFailure(),{code:'operator_fixture_state'});
 });
});
processTest('fixed held stages identify the same unchanged capture and terminate authority checks',async()=>{
 await fixture(async f=>{const stages=[];f.o.isHeld=stage=>{stages.push(stage);return true};const h=await f.start();await f.ready();await h.captureLocks();await h.terminate();
  assert.deepEqual(stages,['capture_final','terminate_capture','terminate_final']);await h.removeCapturedLocks();assert.equal(await h.close(),true);
 });
});
