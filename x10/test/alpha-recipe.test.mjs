// Read-only installed-command controls: only private Node copies and inert
// synthetic native bytes. No native session, network or signal fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, link, lstat, mkdir, readFile, readdir, rename, rm, rmdir, writeFile } from 'node:fs/promises';
import { digest } from '../alpha/runtime.mjs';
import { assertInstalledPackageInfo, installedRecipeFixture, recipeCli,
  assertRecipeResult, observeRecipeNode, verifyRecipeNode, rawRecipeNodeCommand, recipeNodeCommand } from './alpha-recipe-helpers.mjs';
const absent = file => lstat(file).then(() => false, error => { if (error.code === 'ENOENT') return true; throw error; });

test('installed package-info identifies checked nonexecuted payload without state or lock writes',
  { timeout: 20000 }, () => installedRecipeFixture(async f => {
    const result = await assertInstalledPackageInfo(f.prefix, f.launcher,
      (file, ...args) => recipeNodeCommand(f.recipeNode, file, ...args));
    assert.equal(result.runtimeFiles.length, 11);
    assert.equal(result.nativeBinarySha256, f.manifest.immutable['bin/nginx'].sha256);
    assert.equal(result.compatibilityAccepted, false); assert.equal(result.upgradePerformed, false);
    assert.equal(result.rollbackAccepted, false); assert.equal(result.productionAccepted, false);
  }));
test('installed recipe command emits manual and automatic units from installed files without activation or alpha lock',{timeout:15000},()=>installedRecipeFixture(async f=>{
  const marker=await readFile(f.prefix+'/.alpha-install.json'),registry=await readFile(f.prefix+'/.alpha-registry.json');
  const lock=f.prefix+'/.alpha-lock';await writeFile(lock,'operator-owned-lock\n',{mode:0o600});const lockBefore=await readFile(lock),lockStat=await lstat(lock);
  for(const automatic of [false,true]){
    const r=await recipeCli(f,'service-unit',...(automatic?['--auto-readiness']:[]));assertRecipeResult(r,{...f,automatic});
    assert.deepEqual(await readFile(lock),lockBefore);assert.equal((await lstat(lock)).ino,lockStat.ino);
  }
  assert.deepEqual(await readFile(f.prefix+'/.alpha-install.json'),marker);assert.deepEqual(await readFile(f.prefix+'/.alpha-registry.json'),registry);
  assert.deepEqual(await readdir(f.prefix+'/runs'),[]);assert.equal(await absent(f.prefix+'/control.sock'),true);
}));
test('installed recipe command exactflags refuse unknown values duplicates and lifecycle options',{timeout:20000},()=>installedRecipeFixture(async f=>{
  for(const args of [['--auto-readiness','--auto-readiness'],['--auto-readiness=true'],['--auto-readiness','true'],['--node',f.nodeExecutable],['--prefix',f.prefix],['--output',f.parent+'/unit'],['--control-socket',f.prefix+'/sock'],['--help'],['extra']]){
    const r=await recipeCli(f,'service-unit',...args);assert.equal(r.code,1);assert.equal(r.json.ok,false);
    assert.equal(await absent(f.prefix+'/.alpha-lock'),true);assert.equal(await absent(f.parent+'/unit'),true);
  }
}));
test('installed recipe command preserves strict legacyv1 profile and refuses recipe without sniffing optional helper',{timeout:15000},()=>installedRecipeFixture(async f=>{
  const helper=f.prefix+'/lib/service/user-unit.mjs';await rm(helper);await rmdir(f.prefix+'/lib/service');delete f.manifest.immutable['lib/service/user-unit.mjs'];f.manifest.schemaVersion=1;await f.save();
  const record=await readFile(f.prefix+'/.alpha-install.json');const r=await recipeCli(f,'service-unit');assert.equal(r.code,1);assert.equal(r.json.code,'service_recipe_unavailable');
  assert.deepEqual(await readFile(f.prefix+'/.alpha-install.json'),record);assert.equal(await absent(f.prefix+'/.alpha-lock'),true);assert.equal(await absent(helper),true);
  await mkdir(f.prefix+'/lib/service',{mode:0o700});await writeFile(helper,'throw new Error("must not import optional legacy helper");',{mode:0o400});
  const again=await recipeCli(f,'service-unit');assert.equal(again.code,1);assert.equal(again.json.code,'service_recipe_unavailable');assert.deepEqual(await readFile(f.prefix+'/.alpha-install.json'),record);
}));
test('installed recipe command validates helper bytes before dynamic import',{timeout:15000},()=>installedRecipeFixture(async f=>{
  const helper=f.prefix+'/lib/service/user-unit.mjs',sentinel=f.parent+'/imported';await chmod(helper,0o600);
  await writeFile(helper,`await (await import('node:fs/promises')).writeFile(${JSON.stringify(sentinel)},'unexpected import');\nthrow new Error('must not import tampered helper');\n`);await chmod(helper,0o400);
  const r=await recipeCli(f,'service-unit');assert.equal(r.code,1);assert.equal(r.json.code,'alpha_integrity');assert.equal(await absent(sentinel),true);assert.equal(await absent(f.prefix+'/.alpha-lock'),true);
}));
for(const key of ['version','executable','sha256'])test('installed recipe command validates actual recordedNode '+key+' before dynamic import',{timeout:15000},()=>installedRecipeFixture(async f=>{
  const helper=f.prefix+'/lib/service/user-unit.mjs',sentinel=f.parent+'/imported',bytes=Buffer.from(`await (await import('node:fs/promises')).writeFile(${JSON.stringify(sentinel)},'unexpected import');\nthrow new Error('must not import before recorded node validation');\n`);
  await chmod(helper,0o600);await writeFile(helper,bytes);await chmod(helper,0o400);f.manifest.immutable['lib/service/user-unit.mjs']={bytes:bytes.length,sha256:digest(bytes),mode:'0400'};
  if(key==='version')f.manifest.nodeRuntime.version='v22.0.0';if(key==='executable')f.manifest.nodeRuntime.executable=f.parent+'/different-node';if(key==='sha256')f.manifest.nodeRuntime.sha256='0'.repeat(64);await f.save();
  const r=await recipeCli(f,'service-unit');assert.equal(r.code,1);assert.equal(await absent(sentinel),true);assert.equal(await absent(f.prefix+'/.alpha-lock'),true);
}));
for(const mutation of ['missingHelper','unknownVersion','missingOtherFile','wrongHelperMode','wrongDirectoryMode','helperHardlink'])test('installed recipe command refuses fullprofile '+mutation,{timeout:15000},()=>installedRecipeFixture(async f=>{
  if(mutation==='missingHelper')delete f.manifest.immutable['lib/service/user-unit.mjs'];if(mutation==='unknownVersion')f.manifest.schemaVersion=3;
  if(mutation==='missingOtherFile')delete f.manifest.immutable['lib/control/listeners.mjs'];
  if(mutation==='helperHardlink')await link(f.prefix+'/lib/service/user-unit.mjs',f.parent+'/helper-alias');
  if(mutation==='wrongHelperMode')await chmod(f.prefix+'/lib/service/user-unit.mjs',0o600);if(mutation==='wrongDirectoryMode')await chmod(f.prefix+'/lib/service',0o750);await f.save();
  const r=await recipeCli(f,'service-unit');assert.equal(r.code,1);assert.equal(await absent(f.prefix+'/.alpha-lock'),true);
}));

// Exact prior command admission gate; no fake native execution is involved.
const recipeBaselineGate="    const allowed = { install: ['prefix', 'port', 'health-port', 'upstream-port', 'manifest', 'binary'], pack: ['output', 'manifest', 'binary'], run: ['control-socket'], 'prepare-run': [], 'wait-bind': ['timeout-ms'], status: ['human'], apply: ['file'], revert: ['revision'], 'inspect-generations': ['control-socket', 'control-address'], 'snapshot-listeners': [], 'inspect-listeners': ['file'], bind: [], info: [], history: [], recover: [], stop: [], uninstall: [] };\n    if (!allowed[command] || Object.keys(values).some(key => !allowed[command].includes(key))) fail('arguments', 'Unsupported command or option for this command');";
test('installed recipe baseline exact command gate rejects service-unit before any runtime action',()=>{
  assert.equal(Buffer.byteLength(recipeBaselineGate),631);assert.equal(digest(recipeBaselineGate),'c2fd2c9011e1e9ec0e6c4b4f046a71168067a30e27ad9089a1ecb07450e2df04');
  const gate=new Function('command','values','fail',recipeBaselineGate+';return true;');
  assert.throws(()=>gate('service-unit',{},code=>{throw Object.assign(new Error(code),{code});}),{code:'arguments'});
  assert.equal(gate('info',{},()=>assert.fail('legacy info must remain available')),true);
});

test('installed recipe controlled unsafe Node mode refuses unchanged product guard',{timeout:15000},async t=>installedRecipeFixture(async f=>{
  const installBefore=await readFile(f.prefix+'/.alpha-install.json');await chmod(f.nodeExecutable,0o520);
  try{
    const unsafe=await observeRecipeNode(f.recipeNode);assert.equal(unsafe.exactMode,false);assert.equal(unsafe.identityCommandExecuted,false);assert.equal(unsafe.versionMatched,false);assert.equal(unsafe.executableMatched,false);
    assert.ok(digest(await readFile(f.nodeExecutable))===f.recipeNode.sha256,'controlled unsafe mode leaves exact known Node bytes unchanged');
    t.diagnostic(JSON.stringify({suite:'x10-recipe-node-prerequisites',profile:'controlled-unsafe-mode',...unsafe}));
    await assert.rejects(verifyRecipeNode(f.recipeNode),/recipe Node prerequisite: exactMode/);
    // Explicit negative control deliberately bypasses fixture preflight only;
    // the unchanged product must refuse this current unsafe Node executable.
    const refused=await rawRecipeNodeCommand(f.recipeNode,f.launcher,'service-unit');assert.equal(refused.code,1);assert.equal(refused.json.code,'service_recipe_invalid');
    assert.equal(await absent(f.prefix+'/.alpha-lock'),true);assert.deepEqual(await readFile(f.prefix+'/.alpha-install.json'),installBefore);
  }finally{await chmod(f.nodeExecutable,0o500);}
  assert.deepEqual(await readFile(f.prefix+'/.alpha-install.json'),installBefore);
}));

test('installed recipe Node preflight refuses changed executable bytes before any identity child runs',{timeout:15000},()=>installedRecipeFixture(async f=>{
  const sentinel=f.parent+'/unsafe-node-ran',replacement=f.parent+'/changed-node';
  const changed=Buffer.alloc(f.recipeNode.bytes,0x20);changed.write(`#!/bin/sh\nprintf unexpected > ${sentinel}\nexit 0\n#`);
  // Replace only the newly owned copy; never write into a previously executed
  // inode, which can legitimately refuse an in-place write with ETXTBSY.
  await writeFile(replacement,changed,{mode:0o500,flag:'wx'});await rename(replacement,f.nodeExecutable);
  const refused=await observeRecipeNode(f.recipeNode);assert.equal(refused.byteCountMatched,true);assert.equal(refused.hashMatched,false);assert.equal(refused.identityCommandExecuted,false);assert.equal(refused.versionMatched,false);assert.equal(await absent(sentinel),true);
  await assert.rejects(verifyRecipeNode(f.recipeNode),/recipe Node prerequisite: (byteCountMatched|hashMatched)/);assert.equal(await absent(sentinel),true);
}));
