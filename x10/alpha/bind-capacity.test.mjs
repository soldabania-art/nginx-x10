import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, chmod, lstat, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import vm from 'node:vm';

// Source functions execute only against virtual or owned tempfile observations.
// Process callbacks, controller calls, native identities and clock are mocked;
// no child, OS signal, socket, network or service is started.
const source = await readFile(new URL('./cli.mjs', import.meta.url), 'utf8');
const manager = await readFile(new URL('../control/manager.mjs', import.meta.url), 'utf8');
assert.equal(Buffer.byteLength(manager), 51246);
assert.equal(crypto.createHash('sha256').update(manager).digest('hex'), 'd6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289', 'Review virtual syscall accounting before changing this manager pin');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const fail = (code, message = code) => { throw Object.assign(new Error(message), { code }); };
function body(name) {
  const start = source.indexOf(`async function ${name}(`); assert(start >= 0, `Missing production ${name}`);
  const end = source.indexOf('\n}', start); assert(end > start); return source.slice(start, end + 2);
}
function constant(name) { const m = new RegExp(`\\b${name}\\s*=\\s*([0-9]+)\\s*;`).exec(source); assert(m, `Missing ${name}`); return Number(m[1]); }
const limit = constant('INVENTORY_ENTRY_LIMIT'), reserve = constant('CONTROLLER_BIND_ENTRY_RESERVE');
const extracted = ['inventory', 'requireSessionInventoryCapacity', 'proxy', 'waitBind'].map(body).join('\n');
async function runtime(deps) { return new AsyncFunction(...Object.keys(deps), `${extracted}\nreturn { inventory, requireSessionInventoryCapacity, proxy, waitBind };`)(...Object.values(deps)); }
function fixture(options = {}) {
  const prefix = '/synthetic/bind-prefix', session = 'a'.repeat(32), rows = new Map(Array.from({ length: options.count ?? 0 }, (_, i) => [`entry-${String(i).padStart(5, '0')}`, 'file']));
  const installation = { prefix, manifest: { public: 'manifest' }, registry: { current: session, sessions: [session] } }, before = JSON.stringify(installation);
  const listeners = new Map(), events = [], outputs = { stdout: [], stderr: [] }, calls = [];
  let clock = 0, delayed = 0, installedReads = 0;
  const life = { stage: options.stage ?? 'running', session, prefix: `${prefix}/runs/${session}`, runtime: { synthetic: true } };
  if (life.stage === 'prepared') life.runtime = options.preparedRuntime ? { synthetic: true } : null;
  if (options.unsafe === 'symlink' && rows.size) rows.set(rows.keys().next().value, 'symlink');
  const hook = name => options.hooks?.[name]?.(api);
  const deps = {
    path, Number, fail, INVENTORY_ENTRY_LIMIT: limit, CONTROLLER_BIND_ENTRY_RESERVE: reserve, CONTROLLER_MUTATION_ENTRY_RESERVE: constant('CONTROLLER_MUTATION_ENTRY_RESERVE'),
    performance: { now: () => clock },
    process: { execPath: '/synthetic/node', getuid: () => 1000,
      on: (name, callback) => listeners.set(name, callback), removeListener: name => listeners.delete(name),
      stdout: { write: value => outputs.stdout.push(value) }, stderr: { write: value => { outputs.stderr.push(value); hook('stderr'); } } },
    same: (a, b) => JSON.stringify(a) === JSON.stringify(b),
    installed: async () => { events.push('installed'); installedReads++; if (options.changedRegistry && installedReads > 1) return { ...installation, registry: { ...installation.registry, current: 'b'.repeat(32) } }; return installation; },
    lifecycle: async () => { events.push('lifecycle'); hook('lifecycle'); if (options.lifeFailure) fail('synthetic_lifecycle'); return life; },
    controllerState: async () => { events.push('controllerState'); return `${prefix}/runs/${session}/.x10-control`; },
    inspectMaster: async () => { events.push('identity'); hook('identity'); return options.identity !== false; },
    lock: async (_prefix, operation) => { events.push('alpha-lock'); hook('lock'); return operation(); },
    owned: async file => { events.push('owned'); hook('owned'); assert.equal(file, prefix); if (options.scanFailure === 'owned') fail('synthetic_owned'); },
    readdir: async file => { events.push('readdir'); assert.equal(file, prefix); if (options.scanFailure === 'readdir') fail('synthetic_readdir'); return [...rows.keys()]; },
    lstat: async file => { events.push('lstat'); if (options.scanFailure === 'lstat') fail('synthetic_lstat'); const kind = rows.get(path.basename(file)); assert(kind); return { uid: options.unsafe === 'foreign' ? 1001 : 1000, isSymbolicLink: () => kind === 'symlink', isDirectory: () => false }; },
    sessionStatus: async () => { events.push('status'); hook('status'); if (options.statusError) throw options.statusError; return { state: 'synthetic-state', control: { bind: async () => { events.push('bind'); hook('bind'); if (options.bindError) throw options.bindError; return { ok: true, outcome: 'bound' }; } } }; },
    load: async () => { events.push('settings'); hook('settings'); return { gateTimeoutMs: options.gateTimeout ?? 3000 }; },
    delay: async () => { events.push('delay'); delayed++; if (options.preparedThenRunning) { life.stage = 'running'; life.runtime = { synthetic: true }; } else clock = 10000; },
    execute: async (file, args, settings) => { events.push('execute'); calls.push({ file, args, settings }); if (options.executeError) throw options.executeError; return { stdout: options.stdout ?? '', stderr: options.stderr ?? '' }; },
  };
  const api = { deps, prefix, installation, before, life, rows, events, outputs, calls, listeners, cancel() { assert(listeners.has('SIGTERM')); listeners.get('SIGTERM')(); }, setClock(value) { clock = value; }, get delayed() { return delayed; },
    async proxy(command = 'bind', values = {}) { return (await runtime(deps)).proxy(installation, command, values); },
    async wait(timeout = 10000) { try { return await (await runtime(deps)).waitBind(prefix, timeout); } finally { assert.equal(listeners.size, 0, 'All mocked callbacks released'); } } };
  return api;
}
function noController(f) { for (const name of ['execute', 'status', 'bind']) assert(!f.events.includes(name), `${name} must not run`); }
function preserved(f, rows) { assert.equal(JSON.stringify(f.installation), f.before); assert.deepEqual([...f.rows], rows); }

test('bind reserve3 keeps fixed4096 and prior stopped/apply reserves', () => {
  assert.equal(reserve, 3); assert.equal(limit, 4096); assert.equal(constant('CONTROLLER_MUTATION_ENTRY_RESERVE'), 7);
  assert.equal(constant('NEW_SESSION_MINIMUM_ENTRIES'), 17); assert.equal(constant('REGISTRY_PUBLICATION_RESERVE'), 1);
  assert(!body('stop').includes('CONTROLLER_BIND_ENTRY_RESERVE')); assert(!body('prepareRun').includes('CONTROLLER_BIND_ENTRY_RESERVE'));
});
for (const kind of ['proxy', 'wait']) {
  test(`${kind} bind admits4093 actual entries before exactly one controller operation`, async () => {
    const f = fixture({ count: 4093 }), rows = [...f.rows]; const result = await f[kind]();
    if (kind === 'proxy') { assert.equal(result, null); assert.equal(f.calls.length, 1); assert(f.events.indexOf('readdir') < f.events.indexOf('execute')); }
    else { assert.equal(result.outcome, 'wait_bound'); assert.equal(result.bindingMayHaveCommitted, true); assert.equal(f.events.filter(x => x === 'status').length, 1); assert.equal(f.events.filter(x => x === 'bind').length, 1); assert(f.events.indexOf('readdir') < f.events.indexOf('status')); }
    assert.equal(f.events.filter(x => x === 'lstat').length, 4093); preserved(f, rows);
  });
  for (const count of [4094, 4096, 4097]) test(`${kind} bind refuses${count} cumulative entries before controller work`, async () => {
    const f = fixture({ count }), rows = [...f.rows]; await assert.rejects(f[kind](), error => error.code === 'inventory_limit' && error.bindingMayHaveCommitted !== true);
    noController(f); preserved(f, rows); assert.deepEqual(f.outputs.stdout, []);
  });
  for (const scanFailure of ['owned', 'readdir', 'lstat']) test(`${kind} bind preserves ${scanFailure} failure before controller work`, async () => {
    const f = fixture({ count: 1, scanFailure }), rows = [...f.rows]; await assert.rejects(f[kind](), { code: `synthetic_${scanFailure}` }); noController(f); preserved(f, rows);
  });
  for (const unsafe of ['symlink', 'foreign']) test(`${kind} bind preserves ${unsafe} entry on refusal`, async () => {
    const f = fixture({ count: 1, unsafe }), rows = [...f.rows]; await assert.rejects(f[kind](), { code: 'unsafe_path' }); noController(f); preserved(f, rows);
  });
}
for (const command of ['status', 'history', 'recover', 'inspect-generations', 'snapshot-listeners', 'inspect-listeners']) test(`${command} remains outside bind admission`, async () => {
  const f = fixture({ count: 4097, scanFailure: 'owned' }); await f.proxy(command); assert.deepEqual(f.events, ['lifecycle', 'controllerState', 'execute']);
});
test('admitted proxy bind retains argument forwarding, bounded execution and output', async () => {
  const f = fixture({ stdout: 'public-result\n', stderr: 'public-warning\n' }), values = { file: '/synthetic/input', revision: 'b'.repeat(32), 'control-socket': '/synthetic/socket', 'control-address': 'private-address', human: true };
  await f.proxy('bind', values); assert.equal(f.calls.length, 1); const c = f.calls[0];
  assert.equal(c.file, '/synthetic/node'); assert.deepEqual(c.settings, { timeout: 70000, maxBuffer: 2 * 1024 * 1024 });
  assert.deepEqual(c.args, [path.join(f.prefix, 'lib/control/cli.mjs'), 'bind', '--state', `${f.prefix}/runs/${'a'.repeat(32)}/.x10-control`, '--file', values.file, '--revision', values.revision, '--control-socket', values['control-socket'], '--control-address', values['control-address'], '--human']);
  assert.deepEqual(f.outputs, { stdout: ['public-result\n'], stderr: ['public-warning\n'] });
});
test('admitted proxy bind propagates and forwards controller refusal', async () => {
  const error = Object.assign(new Error('public refusal'), { code: 'synthetic_controller', stdout: 'public-out', stderr: 'public-err' }), f = fixture({ executeError: error });
  await assert.rejects(f.proxy(), x => x === error); assert.equal(error.forwarded, true); assert.deepEqual(f.outputs, { stdout: ['public-out'], stderr: ['public-err'] });
});
for (const timeout of [0, 30001, 1.5, '10000']) test(`waitBind refuses invalid timeout ${String(timeout)} before observations`, async () => {
  const f = fixture(); await assert.rejects(f.wait(timeout), { code: 'invalid_wait_timeout' }); assert.deepEqual(f.events, []);
});
test('prepared wait releases observation path then admits running session under alpha lock', async () => {
  const f = fixture({ stage: 'prepared', preparedThenRunning: true }); const r = await f.wait(); assert.equal(r.outcome, 'wait_bound'); assert.equal(f.delayed, 1); assert.equal(f.events.filter(x => x === 'alpha-lock').length, 1); assert.equal(f.events.filter(x => x === 'readdir').length, 1);
});
for (const stage of ['stopped', 'faulted']) test(`waitBind refuses ${stage} before inventory/controller work`, async () => {
  const f = fixture({ stage }); await assert.rejects(f.wait(), { code: 'wait_bind_state' }); noController(f); assert(!f.events.includes('owned'));
});
test('waitBind preserves registry-change refusal before locked admission', async () => {
  const f = fixture({ changedRegistry: true }); await assert.rejects(f.wait(), { code: 'wait_bind_changed' }); noController(f); assert(!f.events.includes('owned'));
});
test('waitBind preserves exact identity refusal before admission', async () => {
  const f = fixture({ identity: false }); await assert.rejects(f.wait(), { code: 'runtime_identity' }); noController(f); assert(!f.events.includes('owned'));
});
test('waitBind preserves unsupported readiness budget refusal before bind', async () => {
  const f = fixture({ gateTimeout: 5000 }); await assert.rejects(f.wait(), { code: 'wait_bind_settings' }); assert(f.events.includes('status')); assert(!f.events.includes('bind'));
});
test('cancellation before waiting prevents inventory, controller work and leaves no callback', async () => {
  const f = fixture({ hooks: { stderr: x => x.cancel() } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_cancelled'); assert.equal(r.bindingMayHaveCommitted, false); noController(f); assert(!f.events.includes('owned'));
});
test('cancellation at locked entry prevents admission/controller work', async () => {
  const f = fixture({ hooks: { lock: x => x.cancel() } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_cancelled'); assert.equal(r.bindingMayHaveCommitted, false); noController(f); assert(!f.events.includes('owned'));
});
test('cancellation during inventory cannot grant bind authority', async () => {
  const f = fixture({ hooks: { owned: x => x.cancel() } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_cancelled'); assert.equal(r.bindingMayHaveCommitted, false); assert(!f.events.includes('bind'));
});
test('inventory time consuming readiness margin refuses before bind', async () => {
  const f = fixture({ hooks: { owned: x => x.setClock(7000) } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_timeout'); assert.equal(r.bindingMayHaveCommitted, false); assert(!f.events.includes('bind'));
});
test('cancel after bind keeps possible committed state explicit', async () => {
  const f = fixture({ hooks: { bind: x => x.cancel() } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_cancelled'); assert.equal(r.bindingMayHaveCommitted, true); assert.equal(f.events.filter(x => x === 'bind').length, 1);
});
test('late bind result is awaited once and marked possibly committed', async () => {
  const f = fixture({ hooks: { bind: x => x.setClock(10001) } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_late'); assert.equal(r.bindingMayHaveCommitted, true); assert.equal(f.events.filter(x => x === 'bind').length, 1);
});
test('bind rejection keeps original error and possible commit marker', async () => {
  const error = Object.assign(new Error('public bind error'), { code: 'synthetic_bind' }), f = fixture({ bindError: error }); await assert.rejects(f.wait(), x => x === error); assert.equal(error.bindingMayHaveCommitted, true); assert.equal(f.events.filter(x => x === 'bind').length, 1);
});
test('cancel plus bind rejection is explicit possible-commit cancellation', async () => {
  const error = Object.assign(new Error('public bind error'), { code: 'synthetic_bind' }), f = fixture({ bindError: error, hooks: { bind: x => x.cancel() } }); const r = await f.wait(); assert.equal(r.code, 'wait_bind_cancelled'); assert.equal(r.bindingMayHaveCommitted, true);
});
test('pre-bind status error is not marked as a possible bind commit', async () => {
  const error = Object.assign(new Error('public status error'), { code: 'synthetic_status' }), f = fixture({ statusError: error }); await assert.rejects(f.wait(), x => x === error); assert.notEqual(error.bindingMayHaveCommitted, true); assert(!f.events.includes('bind'));
});
test('owned tempfile4094 refusal preserves all records, modes, identity and timestamps', async () => {
  const prefix = await mkdtemp(path.join(os.tmpdir(), 'x10-bind-capacity-')); await chmod(prefix, 0o700);
  try {
    const files = [['.alpha-registry.json', Buffer.from('{"public":"retained-registry"}\n'), 0o600], ['state.json', Buffer.from('{"public":"retained-state"}\n'), 0o600], ['revision.json', Buffer.from('{"public":"retained-revision"}\n'), 0o400]];
    for (const [name, bytes, mode] of files) await writeFile(path.join(prefix, name), bytes, { mode });
    for (let start = files.length; start < 4094; start += 128) await Promise.all(Array.from({ length: Math.min(128, 4094 - start) }, (_, i) => writeFile(path.join(prefix, `entry-${start + i}`), '', { mode: 0o600 })));
    const names = (await readdir(prefix)).sort(), stats = await Promise.all(files.map(([name]) => lstat(path.join(prefix, name))));
    const f = fixture(); f.installation.prefix = prefix; let executions = 0;
    const deps = { ...f.deps, readdir, lstat, process: { ...f.deps.process, getuid: () => process.getuid() },
      owned: async (file, directory = false, privateDirectory = false) => { const s = await lstat(file); assert.equal(s.uid, process.getuid()); assert.equal(s.isSymbolicLink(), false); assert.equal(directory ? s.isDirectory() : s.isFile(), true); if (privateDirectory) assert.equal(s.mode & 0o077, 0); return s; },
      lifecycle: async () => ({ session: 'a'.repeat(32) }), controllerState: async () => 'synthetic-state', execute: async () => { executions++; throw Error('must not execute'); } };
    await assert.rejects((await runtime(deps)).proxy(f.installation, 'bind', {}), { code: 'inventory_limit' }); assert.equal(executions, 0);
    for (let i = 0; i < files.length; i++) { const [name, bytes] = files[i], after = await lstat(path.join(prefix, name)); assert.deepEqual(await readFile(path.join(prefix, name)), bytes); for (const key of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[key], stats[i][key]); }
    assert.deepEqual((await readdir(prefix)).sort(), names);
  } finally { await rm(prefix, { recursive: true, force: true }); }
});

// Actual controller functions run with virtual syscall fault outcomes. This finite
// representative model is shared once; its paths/executions are not TAP counts.
async function controllerBindProof(manager) {
const createHash = crypto.createHash;
const managerHash=createHash('sha256').update(manager).digest('hex');
if(Buffer.byteLength(manager)!==51246||managerHash!=='d6d1c325c4098fe8ea43dfa08c938a9f58e90075c42c8590d0816dbe793a7289')throw Error('manager source pin drift');
function extract(name){const re=new RegExp('(?:export )?async function '+name+'\\('),m=re.exec(manager);if(!m)throw Error(name);let n=0;const b=manager.indexOf('{',m.index);for(let i=b;i<manager.length;i++){if(manager[i]==='{')n++;else if(manager[i]==='}'&&--n===0)return manager.slice(m.index,i+1).replace(/^export /,'');}throw Error('unterminated '+name);}
const names=['bind','lock','atomic','syncDirectory','appendEvent','clearCommit','event','save','durableEvent','status'];
const actual=names.map(extract).join('\n')+'\nglobalThis.testBind=bind; globalThis.testStatus=status;';
const statics=[['bind-one-event',extract('bind').match(/await event\(/g)?.length===1],['bind-no-revision',!extract('bind').includes('makeRevision')],['bind-no-retry',!extract('bind').match(/while\s*\(|for\s*\(/)],['atomic-single-temp',extract('atomic').match(/await open\(temporary,/g)?.length===1],['append-no-create',!extract('appendEvent').includes('O_CREAT')],['sequential-atomic',extract('event').includes('await save(commitFile(settings), intent);')&&extract('event').includes("await save(path.join(settings.state, 'state.json'), after);")],['clear-is-remove-and-sync',extract('clearCommit').includes('await rm(commitFile(settings)); await syncDirectory(settings.state);')]];
if(statics.some(x=>!x[1]))throw Error('static source contract');
const state='/installation/runs/session/.x10-control';
async function trial(decisions,precondition='normal',withStatus=false){
 let next=0,serial=0,branch=null,high=0;
 const added=new Set(),steps=[],baseFiles=new Set([state+'/state.json',state+'/history.jsonl']);
 const dirs=new Set(['/installation','/installation/runs','/installation/runs/session',state]);
 const current={activeRevision:'old',historyHead:null,binding:precondition==='already-bound'?{pid:1}:null};
 const settings={state,prefix:path.dirname(state),config:path.dirname(state)+'/nginx.conf',fragment:path.dirname(state)+'/managed.conf',configSha256:createHash('sha256').update('config').digest('hex')};
 baseFiles.add(settings.config);baseFiles.add(settings.fragment);
 const data=new Map([[state+'/state.json',JSON.stringify(current)],[state+'/history.jsonl',''],[settings.config,'config'],[settings.fragment,'fragment']]);
 if(precondition==='existing-commit'){baseFiles.add(state+'/event-commit.json');data.set(state+'/event-commit.json','{}');}
 if(precondition==='existing-lock')baseFiles.add(state+'/lock');
 function record(label){high=Math.max(high,added.size);steps.push({label,additionalEntries:added.size,entries:[...added].map(p=>p.slice('/installation/'.length))});}
 function add(file,label){if(!baseFiles.has(file)&&!dirs.has(file))added.add(file);record(label);}
 function remove(file,label){added.delete(file);record(label);}
 function choose(label,arity=2){if(branch)throw branch;const x=decisions[next++];if(x===undefined){branch={branch:true,index:next-1,label,arity};throw branch;}return x;}
 function failure(){return Object.assign(new Error('modeled IO failure'),{code:'EIO'});}
 function check(label){if(choose(label)===1)throw failure();}
 const constants={O_WRONLY:1,O_CREAT:2,O_EXCL:4,O_NOFOLLOW:8,O_RDONLY:16,O_DIRECTORY:32,O_APPEND:64};
 const context={path,Buffer,Object,JSON,Date,constants,process:{platform:'linux',pid:1},uid:1,canonicalState:s=>s,now:()=> 'synthetic-time',encode:x=>JSON.stringify(x),hash:x=>createHash('sha256').update(x).digest('hex'),message:e=>e.message,commitFile:s=>s.state+'/event-commit.json',
 realpath:async p=>{check('realpath');return p;},owned:async()=>{check('owned');},load:async()=>{check('load');return{settings,current,pending:precondition==='pending'?{}:null,history:[]};},readRevision:async()=>{check('readRevision');return{id:'old',fragmentSha256:createHash('sha256').update('fragment').digest('hex')};},guard:async()=>{check('guard');},runtime:async()=>{check('runtime');return{pid:1};},acknowledged:async()=>{check('acknowledged');},exists:async f=>{check('exists');return baseFiles.has(f)||added.has(f);},readFile:async f=>{check('readFile '+f);return data.get(f);},request:async()=>{check('request');return{revision:'old'};},stateShape:x=>x,json:async f=>{check('json');return JSON.parse(data.get(f));},readHistory:async()=>{check('readHistory');return[];},lstat:async()=>{check('lstat');return{size:0};},fail:(code,message)=>{throw Object.assign(new Error(message),{code});},randomBytes:()=>({toString:()=>String(++serial).padStart(16,'0')}),
 open:async(f,flags)=>{const creating=Boolean(flags&constants.O_CREAT),existing=baseFiles.has(f)||added.has(f);const op=choose('open '+f,creating?3:2);if(op===1)throw failure();if(creating&&existing)throw Object.assign(new Error('exists'),{code:'EEXIST'});if(creating)add(f,'created '+f);if(op===2)throw failure();return{writeFile:async bytes=>{check('writeFile '+f);data.set(f,bytes);},sync:async()=>{check('sync '+f);},close:async()=>{check('close '+f);}};},
 rename:async(from,to)=>{const op=choose('rename '+to,3);if(op===1)throw failure();remove(from,'rename source removed');add(to,'renamed '+to);if(data.has(from))data.set(to,data.get(from));if(op===2)throw failure();},
 rm:async f=>{const op=choose('rm '+f,3);if(op===1)throw failure();remove(f,'removed '+f);if(op===2)throw failure();},
 };
 vm.createContext(context);vm.runInContext(actual,context);
 let outcome;try{if(withStatus){const status=await context.testStatus(state);if(!status.configUnchanged||!status.fragmentMatchesLastConfirmed||status.pending)throw Error('invalid modeled status');}outcome=await context.testBind(state);}catch(e){outcome={error:e.code||'unclassified'};}
 if(branch)return{branch};return{high,outcome,steps,decisions,precondition,withStatus};
}
async function explore(precondition,withStatus=false){const queue=[[]];let executions=0,terminalPaths=0,maxAdditionalEntries=0,witness=null;while(queue.length){const decisions=queue.pop();const r=await trial(decisions,precondition,withStatus);executions++;if(executions>250000)throw Error('finite model budget exhausted');if(r.branch){for(let i=0;i<r.branch.arity;i++)queue.push([...decisions,i]);}else{terminalPaths++;if(!witness||r.high>maxAdditionalEntries){maxAdditionalEntries=r.high;witness=r;}}}return{precondition,withStatus,executions,terminalPaths,maxAdditionalEntries,witness};}
const normal=await explore('normal');const statusThenBind=await explore('normal',true);const preconditions=[];for(const p of ['already-bound','pending','existing-commit','existing-lock'])preconditions.push(await explore(p));
const report={schemaVersion:1,sourceCommit:'2331e8cf3e5c44053972e502f8afd96fff3953a7',sourceBinding:{path:'x10/control/manager.mjs',bytes:Buffer.byteLength(manager),sha256:managerHash},sourceExtractedFunctions:names,staticChecks:statics.map(([name,pass])=>({name,pass})),normal,statusThenBind,preconditions,totalExecutions:normal.executions+statusThenBind.executions+preconditions.reduce((n,p)=>n+p.executions,0),totalTerminalPaths:normal.terminalPaths+statusThenBind.terminalPaths+preconditions.reduce((n,p)=>n+p.terminalPaths,0),maxAdditionalEntries:Math.max(normal.maxAdditionalEntries,statusThenBind.maxAdditionalEntries,...preconditions.map(p=>p.maxAdditionalEntries)),guardThresholds:{limit:4096,reserve:3,admitAtExisting4093:true,refuseAtExisting4094:true},modelPrimitiveOutcomes:{creatingOpen:['success','failure-before-create','failure-after-create'],existingOpen:['success','failure'],writeSyncClose:['success','failure'],rename:['success','failure-before-rename','failure-after-rename'],rm:['success','failure-before-removal','failure-after-removal']},preconditionsAndLimits:['Existing alpha lock is already part of the sampled whole-prefix inventory','Required state/history files and private control directories already exist; source load and event checks refuse unsupported states','Status observation takes and releases its controller lock before binding; failure of its cleanup propagates and prevents bind from starting','Bind creates no revision and has no rollback/retry path','Only declared controller-file effects are modeled; native/runtime helpers and concurrent/direct writers are outside this cooperative reserve','Representative filesystem failure classes and ambiguous post-effect failures are modeled, not every possible OS behavior or physical high-water'],physicalFixturesExecuted:0,networkFixturesExecuted:0,signalsSent:0};
if(report.maxAdditionalEntries!==3)throw Error('unexpected bound '+report.maxAdditionalEntries);

return report;
}
let bindProofPromise;
const bindProof = () => bindProofPromise ??= controllerBindProof(manager);
for (const mode of ['normal', 'statusThenBind']) test(`actual-source ${mode} syscall fault paths fit reserve3`, async () => {
  const p = await bindProof(), r = p[mode]; assert(r.terminalPaths > 0); assert.equal(r.maxAdditionalEntries, 3); assert(p.staticChecks.every(x => x.pass));
});
test('unsupported controller preconditions refuse without a three-entry mutation', async () => {
  const p = await bindProof(); assert.equal(p.preconditions.length, 4);
  for (const r of p.preconditions) assert(r.maxAdditionalEntries <= (r.precondition === 'existing-lock' ? 0 : 1));
});
test('shared source-bound enumeration retains max3 including status-before-bind failures', async () => {
  const p = await bindProof(); assert.equal(p.totalTerminalPaths, 1715); assert.equal(p.totalExecutions, 3165); assert.equal(p.maxAdditionalEntries, 3);
  assert.equal(p.normal.terminalPaths, 741); assert.equal(p.statusThenBind.terminalPaths, 801);
});
