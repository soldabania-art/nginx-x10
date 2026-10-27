import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, chmod, lstat, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import vm from 'node:vm';

// Actual production functions run against virtual or owned tempfile I/O only.
// No controller process, native test, signal, socket or service is started.
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const managerSource = await readFile(new URL('../control/manager.mjs', import.meta.url), 'utf8');
// The mocked primitive accounting must be independently reviewed if any manager bytes change.
assert.equal(Buffer.byteLength(managerSource), 51246);
assert.equal(crypto.createHash('sha256').update(managerSource).digest('hex'), 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289', 'Review controller primitive accounting before updating this source pin');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const fail = code => { throw Object.assign(new Error(code), { code }); };
function body(name) {
  const start = source.indexOf(`async function ${name}(`); assert(start >= 0, `Missing production ${name}`);
  const end = source.indexOf('\n}', start); assert(end > start); return source.slice(start, end + 2);
}
function constant(name) { const m = new RegExp(`\\b${name}\\s*=\\s*([0-9]+)\\s*;`).exec(source); assert(m, `Missing finite ${name}`); return Number(m[1]); }
const limit = constant('INVENTORY_ENTRY_LIMIT'), reserve = constant('CONTROLLER_MUTATION_ENTRY_RESERVE'), bindReserve = constant('CONTROLLER_BIND_ENTRY_RESERVE');
const extracted = ['inventory', 'requireSessionInventoryCapacity', 'proxy'].map(body).join('\n');
async function runtime(deps) {
  return new AsyncFunction(...Object.keys(deps), `${extracted}\nreturn {inventory, requireSessionInventoryCapacity, proxy};`)(...Object.values(deps));
}
function virtual({ count = 0, failure = null, unsafe = null, stdout = 'synthetic result\n', stderr = '', executeError = null } = {}) {
  const prefix = '/synthetic/alpha-prefix', session = 'a'.repeat(32), events = [], outputs = { stdout: [], stderr: [] };
  const rows = new Map(Array.from({ length: count }, (_, i) => [`entry-${String(i).padStart(5, '0')}`, 'file']));
  if (unsafe === 'symlink' && count) rows.set(rows.keys().next().value, 'symlink');
  const context = { prefix, manifest: {}, registry: { current: session, sessions: [session] } }, before = JSON.stringify(context);
  const deps = {
    path, fail, INVENTORY_ENTRY_LIMIT: limit, CONTROLLER_MUTATION_ENTRY_RESERVE: reserve, CONTROLLER_BIND_ENTRY_RESERVE: bindReserve,
    process: { execPath: '/synthetic/node', getuid: () => 1000, stdout: { write: value => outputs.stdout.push(value) }, stderr: { write: value => outputs.stderr.push(value) } },
    owned: async file => { events.push('owned'); assert.equal(file, prefix); if (failure === 'owned') fail('synthetic_owned'); },
    readdir: async file => { events.push('readdir'); assert.equal(file, prefix); if (failure === 'readdir') fail('synthetic_readdir'); return [...rows.keys()]; },
    lstat: async file => { events.push('lstat'); if (failure === 'lstat') fail('synthetic_lstat'); const kind = rows.get(path.basename(file)); assert(kind); return { uid: unsafe === 'foreign' ? 1001 : 1000, isSymbolicLink: () => kind === 'symlink', isDirectory: () => false }; },
    lifecycle: async actual => { events.push('lifecycle'); assert.equal(actual, context); if (failure === 'lifecycle') fail('synthetic_lifecycle'); return { session }; },
    controllerState: async (actual, id) => { events.push('controllerState'); assert.equal(actual, prefix); assert.equal(id, session); if (failure === 'controllerState') fail('synthetic_controllerState'); return `${prefix}/runs/${session}/.x10-control`; },
    execute: async (file, args, options) => { events.push('execute'); calls.push({ file, args, options }); if (executeError) throw executeError; return { stdout, stderr }; }
  };
  const calls = [];
  return { prefix, rows, context, before, deps, events, outputs, calls, async run(command, values = {}) { return (await runtime(deps)).proxy(context, command, values); } };
}

test('reviewed control reserve is7 while inventory remains4096', () => { assert.equal(reserve, 7); assert.equal(limit, 4096); });
for (const command of ['apply', 'revert']) {
  test(`${command} admits4089 cumulative entries before exactly one controller execute`, async () => {
    const f = virtual({ count: 4089 }); assert.equal(await f.run(command), null); assert.equal(f.calls.length, 1);
    assert.deepEqual(f.events.slice(0, 4), ['lifecycle', 'controllerState', 'owned', 'readdir']); assert.equal(f.events.at(-1), 'execute');
    assert.equal(f.events.filter(e => e === 'lstat').length, 4089); assert.equal(JSON.stringify(f.context), f.before);
  });
  for (const count of [4090, 4096, 4097]) test(`${command} refuses${count} entries before process execution and preserves context`, async () => {
    const f = virtual({ count }); const before = [...f.rows]; await assert.rejects(f.run(command), { code: 'inventory_limit' });
    assert.equal(f.calls.length, 0); assert.equal(JSON.stringify(f.context), f.before); assert.deepEqual([...f.rows], before); assert.deepEqual(f.outputs, { stdout: [], stderr: [] });
  });
  for (const failure of ['owned', 'readdir', 'lstat']) test(`${command} preserves a ${failure} scan failure without controller execution`, async () => {
    const f = virtual({ count: 1, failure }); await assert.rejects(f.run(command), { code: `synthetic_${failure}` }); assert.equal(f.calls.length, 0); assert.equal(JSON.stringify(f.context), f.before);
  });
  for (const unsafe of ['symlink', 'foreign']) test(`${command} refuses an existing ${unsafe} entry without removing it`, async () => {
    const f = virtual({ count: 1, unsafe }); const before = [...f.rows]; await assert.rejects(f.run(command), { code: 'unsafe_path' }); assert.equal(f.calls.length, 0); assert.deepEqual([...f.rows], before);
  });
}
test('bind uses its separate reviewed reserve without changing apply/revert reserve7', async () => {
  assert.equal(bindReserve, 3); const f = virtual({ count: limit - bindReserve });
  await f.run('bind'); assert.equal(f.calls.length, 1); assert(f.events.includes('readdir'));
  assert.equal(reserve, 7);
});
for (const command of ['status', 'history', 'recover', 'inspect-generations', 'snapshot-listeners', 'inspect-listeners'])
  test(`${command} keeps its existing independent path without new inventory admission`, async () => {
    const f = virtual({ count: 4097, failure: 'owned' }); await f.run(command); assert.deepEqual(f.events, ['lifecycle', 'controllerState', 'execute']); assert.equal(f.calls.length, 1);
  });
for (const failure of ['lifecycle', 'controllerState']) test(`existing ${failure} refusal precedes scan and execute`, async () => {
  const f = virtual({ failure }); await assert.rejects(f.run('apply'), { code: `synthetic_${failure}` }); assert(!f.events.includes('owned')); assert.equal(f.calls.length, 0);
});
test('admitted proxy preserves all existing argument forwarding, timeout, bounds and output', async () => {
  const f = virtual({ stdout: 'public-output\n', stderr: 'public-error\n' }), values = { file: '/synthetic/input.json', revision: 'b'.repeat(32), 'control-socket': '/synthetic/control.sock', 'control-address': 'private-address', human: true };
  await f.run('apply', values); assert.equal(f.calls.length, 1); const c = f.calls[0];
  assert.equal(c.file, '/synthetic/node'); assert.deepEqual(c.args, [path.join(f.prefix, 'lib/control/cli.mjs'), 'apply', '--state', `${f.prefix}/runs/${'a'.repeat(32)}/.x10-control`, '--file', values.file, '--revision', values.revision, '--control-socket', values['control-socket'], '--control-address', values['control-address'], '--human']);
  assert.deepEqual(c.options, { timeout: 70000, maxBuffer: 2 * 1024 * 1024 }); assert.deepEqual(f.outputs, { stdout: ['public-output\n'], stderr: ['public-error\n'] });
});
test('admitted controller error forwards existing stdout/stderr and propagates its identity', async () => {
  const error = Object.assign(new Error('synthetic controller refusal'), { code: 'synthetic_controller', stdout: 'public-out\n', stderr: 'public-err\n' }), f = virtual({ executeError: error });
  await assert.rejects(f.run('revert'), e => e === error); assert.equal(error.forwarded, true); assert.deepEqual(f.outputs, { stdout: ['public-out\n'], stderr: ['public-err\n'] });
});
test('controller error without stdout retains existing non-forwarded behavior', async () => {
  const error = Object.assign(new Error('synthetic failure'), { code: 'synthetic_controller', stderr: 'not-forwarded' }), f = virtual({ executeError: error });
  await assert.rejects(f.run('apply'), e => e === error); assert.equal(error.forwarded, undefined); assert.deepEqual(f.outputs, { stdout: [], stderr: [] });
});
test('existing stopped-session pre18/post1 admissions are retained outside proxy mutation guard', () => {
  const prepare = body('prepareRun'); assert.match(prepare, /requireSessionInventoryCapacity\(prefix, NEW_SESSION_MINIMUM_ENTRIES \+ REGISTRY_PUBLICATION_RESERVE\)/); assert.match(prepare, /requireSessionInventoryCapacity\(prefix, REGISTRY_PUBLICATION_RESERVE\)/);
  assert.equal(constant('NEW_SESSION_MINIMUM_ENTRIES'), 17); assert.equal(constant('REGISTRY_PUBLICATION_RESERVE'), 1);
  assert(!body('stop').includes('CONTROLLER_MUTATION_ENTRY_RESERVE')); assert(!body('prepareRun').includes('CONTROLLER_MUTATION_ENTRY_RESERVE'));
});
test('owned tempfile admission refusal preserves old record bytes, modes, identity and timestamps', async () => {
  const prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-revision-capacity-')); await chmod(prefix, 0o700);
  try {
    const files = [['.alpha-registry.json', Buffer.from('{"public":"old-registry"}\n'), 0o600], ['old-revision.json', Buffer.from('{"public":"old-revision"}\n'), 0o400]];
    for (const [name, bytes, mode] of files) await writeFile(path.join(prefix, name), bytes, { mode });
    const count = 4090; for (let start = 2; start < count; start += 128) await Promise.all(Array.from({ length: Math.min(128, count - start) }, (_, i) => writeFile(path.join(prefix, `entry-${start + i}`), '', { mode: 0o600 })));
    const beforeNames = (await readdir(prefix)).sort(), before = await Promise.all(files.map(([name]) => lstat(path.join(prefix, name)))); let executed = false;
    const f = virtual(); f.context.prefix = prefix;
    const deps = { ...f.deps, process: { ...f.deps.process, getuid: () => process.getuid() }, readdir, lstat,
      lifecycle: async () => ({ session: 'a'.repeat(32) }), controllerState: async () => path.join(prefix, 'state'), execute: async () => { executed = true; throw Error('must not execute'); },
      owned: async (file, directory = false, privateDirectory = false) => { const s = await lstat(file); assert.equal(s.uid, process.getuid()); assert.equal(s.isSymbolicLink(), false); assert.equal(directory ? s.isDirectory() : s.isFile(), true); if (privateDirectory) assert.equal(s.mode & 0o077, 0); return s; }
    };
    const r = await runtime(deps); await assert.rejects(r.proxy(f.context, 'apply', {}), { code: 'inventory_limit' }); assert.equal(executed, false);
    for (let i = 0; i < files.length; i++) { const [name, bytes] = files[i], after = await lstat(path.join(prefix, name)); assert.deepEqual(await readFile(path.join(prefix, name)), bytes); for (const key of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[key], before[i][key]); }
    assert.deepEqual((await readdir(prefix)).sort(), beforeNames);
  } finally { await rm(prefix, { recursive: true, force: true }); }
});

// Independent finite control-flow model enumerates its declared fault choices.
// Representative nonallocating errors are included; this is not all OS failures. Controller functions
// are verbatim; only filesystem primitive effects and native observations are mocked.
async function controlHeadroomProof(source) {
function extract(name){const start=source.indexOf(`async function ${name}(`);if(start<0)throw Error(name);let level=0,opened=false;for(let i=source.indexOf('{',start);i<source.length;i++){if(source[i]==='{'){level++;opened=true;}if(source[i]==='}'&&!--level&&opened)return source.slice(start,i+1);}throw Error(name);}
const names=['activate','rollback','event','pending','save','durableEvent','clearPending','makeRevision'];
// Function slices are evaluated verbatim; braces in template literals remain balanced in these slices.
const body=names.map(extract).join('\n')+'\nglobalThis.activate=activate;';
const assertions=[
 ['atomic-single-creation',extract('atomic').match(/await open\(temporary,/g)?.length===1],
 ['atomic-single-rename',extract('atomic').match(/await rename\(temporary, file\)/g)?.length===1],
 ['revision-single-exclusive-creation',extract('makeRevision').includes('O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW')],
 ['activate-one-candidate',extract('activate').match(/await makeRevision/g)?.length===1],
 ['rollback-one-restored',extract('rollback').match(/await makeRevision/g)?.length===1],
 ['event-incomplete-short-circuits-restore',extract('activate').includes("if (error.code === 'event_commit_incomplete') throw error;")],
 ['no-creation-history-append',!extract('appendEvent').includes('O_CREAT')],
];
if(assertions.some(x=>!x[1]))throw Error('static source contract');
const currentTemplate={activeRevision:'old',previousRevision:null,binding:{},historyHead:null};
async function run(decisions,mode){
 let index=0,high=0,nextId=0,branchMarker=null;const steps=[],entries=new Set(),data=new Map();const current=structuredClone(currentTemplate),settings={state:'/p/.x10-control',fragment:'/p/managed.conf',port:8080};
 const baseFiles=['/p/.x10-control/state.json','/p/.x10-control/history.jsonl','/p/managed.conf'];for(const x of baseFiles)data.set(x,x.endsWith('state.json')?JSON.stringify(current):'');
 function record(label){high=Math.max(high,entries.size);steps.push({label,additionalEntries:entries.size,entries:[...entries]});}
 function add(file,label){if(!baseFiles.includes(file))entries.add(file);record(label);}
 function choice(kind){const n=decisions[index++];if(n===undefined){branchMarker??={branch:true,arity:kind==='atomic'?4:kind==='revision'?3:2,index:index-1};throw branchMarker;}return n;}
 const fail=()=>Object.assign(new Error('modeled IO failure'),{code:'EIO'});function noalloc(label){if(choice('nonalloc'))throw Object.assign(fail(),{modelPoint:label});}
 let tests=0,acks=0;
 const context={path,Buffer,URL,Object,JSON,Date,now:()=> 'synthetic-time',message:e=>e.message,encode:x=>JSON.stringify(x)+'\n',hash:x=>crypto.createHash('sha256').update(x).digest('hex'),candidate:x=>x,render:()=> 'syntheticfragment',verifyHttps:async()=>{noalloc('verifyHttps');},constants:{O_WRONLY:1,O_CREAT:2,O_EXCL:4,O_NOFOLLOW:8},randomBytes:()=>({toString:()=>String(++nextId).padStart(32,'0')}),
 lock:async(_state,op)=>{add('/p/.x10-control/lock','controller-lock');try{return await op(settings.state);}finally{entries.delete('/p/.x10-control/lock');record('controller-unlock');}},load:async()=>{noalloc('load');return{settings,current,pending:null};},guard:async()=>{noalloc('guard');},readRevision:async(_s,id)=>{noalloc('readRevision');return{id,input:{healthURL:'http://127.0.0.1:8090/'},fragmentSha256:'fragment'};},
 nativeTest:async()=>{noalloc('nativeTest');if(mode==='native-rejected'&&++tests===1)throw Object.assign(new Error('native rejected'),{code:'native_config_rejected'});},signal:async()=>{noalloc('signal');},acknowledged:async()=>{noalloc('acknowledged');if(mode==='rolled-back'&&++acks===1)throw Object.assign(new Error('gate failed'),{code:'health_gate_failed'});},fail:(code,text)=>{throw Object.assign(new Error(text),{code});},exists:async f=>{noalloc('exists');return entries.has(f)||baseFiles.includes(f);},stateShape:x=>x,json:async f=>{noalloc('json');return JSON.parse(data.get(f));},readHistory:async()=>{noalloc('readHistory');return[];},lstat:async()=>{noalloc('lstat');return{size:0};},appendEvent:async()=>{noalloc('appendEvent');},clearCommit:async()=>{noalloc('clearCommit-before-rm');entries.delete('/p/.x10-control/event-commit.json');record('clear-event-intent');noalloc('clearCommit-after-rm-sync');},commitFile:()=>'/p/.x10-control/event-commit.json',syncDirectory:async()=>{noalloc('syncDirectory');},
 open:async f=>{const c=choice('revision');if(c===1)throw fail();add(f,'revision-created');return{writeFile:async bytes=>{data.set(f,bytes);if(c===2)throw fail();},sync:async()=>{},close:async()=>{}};},
 atomic:async(file,bytes)=>{const c=choice('atomic'),temp=file+'.tmp-model-'+index; if(c===1)throw fail();add(temp,'atomic-temp '+file);if(c===2)throw fail();entries.delete(temp);add(file,'atomic-rename '+file);data.set(file,bytes);if(c===3)throw fail();},rm:async f=>{noalloc('rm-before');entries.delete(f);record('remove '+f);},};
 vm.createContext(context);vm.runInContext(body,context);
 let outcome;try{outcome=await context.activate(settings.state,async()=>({input:{healthURL:'http://127.0.0.1:8090/'},sourceRevision:null}));}catch(e){if(e.branch)return {branch:e};outcome={error:e.code||'error'};}
 if(branchMarker)return {branch:branchMarker};return{high,steps,outcome,decisions,mode};
}
const reports=[];let executions=0;for(const mode of ['applied','native-rejected','rolled-back']){const queue=[[]];let max=0,witness=null,finished=0;while(queue.length){const d=queue.pop(),r=await run(d,mode);executions++;if(r.branch){for(let n=0;n<r.branch.arity;n++)queue.push([...d,n]);}else{finished++;if(r.high>max){max=r.high;witness=r;}}}reports.push({mode,maxAdditionalEntries:max,finishedPaths:finished,witness});}

return {reports,executions,staticChecks:assertions,max:Math.max(...reports.map(x=>x.maxAdditionalEntries))};
}
let proofPromise;
const proof = () => proofPromise ??= controlHeadroomProof(managerSource);
for (const mode of ['applied', 'native-rejected', 'rolled-back']) test(`source-extracted ${mode} phase/fault paths stay within reviewed7 control entries`, async () => {
  const p = await proof(), r = p.reports.find(x => x.mode === mode); assert(r); assert(r.finishedPaths > 0); assert(r.maxAdditionalEntries <= 7); assert.equal(p.staticChecks.length, 7); assert(p.staticChecks.every(([,pass]) => pass));
});
test('retained-temp failure witness refutes6 and reaches7 additional control entries', async () => {
  const p = await proof(); assert.equal(p.max, 7); assert.equal(p.reports.reduce((n,r) => n+r.finishedPaths,0), 4165); assert.equal(p.executions, 6093); assert(p.reports.some(r => r.maxAdditionalEntries === 7));
});
