// Shared test helpers only. Importing this module registers no tests or fixture.
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { digest } from '../alpha/runtime.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile);

export async function amendRecord(file, mutate) {
  const record = JSON.parse(await readFile(file, 'utf8')), { sha256, ...body } = record; mutate(body);
  await writeFile(file, `${JSON.stringify({ ...body, sha256: digest(JSON.stringify(body)) }, null, 2)}\n`);
}

// Read-only installed-command controls use real installed modules and Node,
// synthetic NONEXECUTED native bytes and no session/native/process-group start.
export const recipeControlNames=['cli.mjs','manager.mjs','listeners.mjs','generations.mjs','status-format.mjs'];
export const recipeAlphaNames=['cli.mjs','runtime.mjs','upstream-example.mjs'];
const recipeV2Names=['bin/nginx','bin/x10','build.json','licenses/NGINX-LICENSE','licenses/UPSTREAM.txt','examples/candidate-b.json',
  ...recipeControlNames.map(n=>'lib/control/'+n),...recipeAlphaNames.map(n=>'lib/alpha/'+n),'lib/service/user-unit.mjs'].sort();
const recipeV2Dirs=['bin','lib','lib/control','lib/alpha','lib/service','licenses','examples','runs'];
// Independent installed-byte comparison. This never imports the package helper
// under test and grants no process, compatibility, upgrade or rollback authority.
export async function assertInstalledPackageInfo(prefix, launcher, invoke) {
  const manifest = JSON.parse(await readFile(path.join(prefix, '.alpha-install.json'), 'utf8'));
  const names = ['bin/nginx', 'bin/x10',
    ...recipeControlNames.map(name => `lib/control/${name}`),
    ...recipeAlphaNames.map(name => `lib/alpha/${name}`),
    ...(manifest.schemaVersion === 2 ? ['lib/service/user-unit.mjs'] : [])].sort();
  const files = await Promise.all(names.map(async relative => {
    const bytes = await readFile(path.join(prefix, relative)), stat = await lstat(path.join(prefix, relative));
    assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false);
    return { path: relative, bytes: bytes.length, sha256: digest(bytes),
      mode: (stat.mode & 0o7777).toString(8).padStart(4, '0') };
  }));
  const fingerprint = selected => digest(JSON.stringify({ schemaVersion: 1, files: selected }));
  const expected = { ok: true, outcome: 'package_identified', schemaVersion: 1,
    kind: 'nginx-x10-installed-package-identity', installationSchemaVersion: manifest.schemaVersion,
    runtimePayloadSha256: fingerprint(files),
    operatorPayloadSha256: fingerprint(files.filter(file => file.path !== 'bin/nginx')),
    nativeBinarySha256: files.find(file => file.path === 'bin/nginx').sha256, runtimeFiles: files,
    consistencyOnly: true, compatibilityAccepted: false, upgradePerformed: false,
    rollbackAccepted: false, serviceAccepted: false, productionAccepted: false };
  const lock = path.join(prefix, '.alpha-lock'), sentinel = Buffer.from('package-info-owned-lock-sentinel\n');
  await writeFile(lock, sentinel, { mode: 0o600, flag: 'wx' });
  const lockIdentity = await lstat(lock);
  try {
    const before = await recipeTree(prefix);
    const beforeBytes = await Promise.all(before.files.map(relative => readFile(path.join(prefix, relative))));
    const result = await invoke(launcher, 'package-info');
    assert.equal(result.code, 0, 'Installed package inspection succeeds with an existing operator lock');
    assert.equal(result.stderr, ''); assert.deepEqual(result.json, expected);
    assert.equal(result.stdout.includes(prefix), false);
    assert.equal(result.stdout.includes(manifest.installationId), false);
    for (const args of [['package-info', '--human'], ['package-info', 'package-info']]) {
      const refused = await invoke(launcher, ...args);
      assert.equal(refused.code, 1); assert.equal(refused.json.code, 'package_info_refused');
      assert.equal(refused.stdout.includes(prefix), false);
    }
    // Excluding a file from the runtime fingerprint must not bypass the full
    // existing immutable-installation and host-dependency verification.
    const example = path.join(prefix, 'examples/candidate-b.json'), exampleBytes = await readFile(example);
    try {
      await chmod(example, 0o600); await writeFile(example, Buffer.concat([exampleBytes, Buffer.from(' ')]));
      const refused = await invoke(launcher, 'package-info');
      assert.equal(refused.code, 1); assert.equal(refused.json.code, 'package_info_refused');
      assert.equal(refused.stdout.includes(prefix), false);
    } finally { await writeFile(example, exampleBytes); await chmod(example, 0o400); }
    const marker = path.join(prefix, '.alpha-install.json'), markerBytes = await readFile(marker);
    try {
      await amendRecord(marker, value => { value.dependencies.files[0].sha256 = '0'.repeat(64); });
      const refused = await invoke(launcher, 'package-info');
      assert.equal(refused.code, 1); assert.equal(refused.json.code, 'package_info_refused');
      assert.equal(refused.stdout.includes(prefix), false);
    } finally { await writeFile(marker, markerBytes); }
    assert.deepEqual(await recipeTree(prefix), before);
    for (let index = 0; index < before.files.length; index++)
      assert.deepEqual(await readFile(path.join(prefix, before.files[index])), beforeBytes[index],
        'Package inspection and refusals preserve every prepared installation file');
    const afterLock = await lstat(lock);
    for (const key of ['dev', 'ino', 'uid', 'mode', 'size', 'mtimeMs', 'ctimeMs'])
      assert.equal(afterLock[key], lockIdentity[key], 'Package inspection preserves the existing lock identity');
    assert.deepEqual(await readFile(lock), sentinel);
    return result.json;
  } finally {
    const current = await lstat(lock);
    assert.equal(current.dev, lockIdentity.dev); assert.equal(current.ino, lockIdentity.ino);
    await rm(lock);
  }
}
export async function recipeTree(base){
  const directories=[],files=[];
  async function visit(relative){directories.push(relative);for(const name of await readdir(path.join(base,relative))){const child=relative?relative+'/'+name:name,stat=await lstat(path.join(base,child));if(stat.isDirectory())await visit(child);else{assert.equal(stat.isFile(),true);assert.equal(stat.isSymbolicLink(),false);files.push(child);}}}
  await visit('');return{directories:directories.sort(),files:files.sort()};
}
export async function prepareRecipeNode(parent){
  const directory=await lstat(parent),sourceNode=await realpath(process.execPath),sourceStat=await lstat(sourceNode);
  assert.ok(await realpath(parent)===parent,'recipe Node parent is canonical');
  assert.ok(directory.isDirectory()&&directory.uid===process.getuid()&&(directory.mode&0o7777)===0o700,'recipe Node parent is private and owned');
  assert.ok(sourceStat.isFile()&&sourceStat.size>0&&sourceStat.size<=256*1024*1024,'trusted current Node source is regular and bounded');
  const sourceHash=digest(await readFile(sourceNode)),nodeExecutable=path.join(parent,'recipe-node');
  await copyFile(sourceNode,nodeExecutable,constants.COPYFILE_EXCL);await chmod(nodeExecutable,0o500);
  const afterSource=await lstat(sourceNode),afterHash=digest(await readFile(sourceNode));
  assert.ok(['dev','ino','uid','size','mode','mtimeMs','ctimeMs'].every(key=>sourceStat[key]===afterSource[key])&&afterHash===sourceHash,'trusted current Node source stayed stable across copy');
  const sourceObservations=Object.freeze({sourceCanonical:true,sourceRegular:true,sourceBounded:true,sourceStableBytes:true,
    sourceOwnerEligibleForService:[0,process.getuid()].includes(sourceStat.uid),sourceModeEligibleForService:(sourceStat.mode&0o7022)===0&&(sourceStat.mode&0o100)!==0});
  const receipt=Object.freeze({nodeExecutable,version:process.version,sha256:sourceHash,bytes:sourceStat.size,sourceObservations});
  await verifyRecipeNode(receipt);return receipt;
}
export async function observeRecipeNode(receipt){
  const stat=await lstat(receipt.nodeExecutable),canonical=await realpath(receipt.nodeExecutable);
  const observations={regularFile:stat.isFile()&&!stat.isSymbolicLink(),canonicalPath:canonical===receipt.nodeExecutable,ownedByRunner:stat.uid===process.getuid(),
    exactMode:(stat.mode&0o7777)===0o500,singleLink:stat.nlink===1,boundedSize:stat.size>0&&stat.size<=256*1024*1024,
    byteCountMatched:stat.size===receipt.bytes,hashMatched:false};
  // File identity and bounded bytes must be checked before executing the copy.
  // Refused metadata never grants authority to run an identity probe.
  if(Object.entries(observations).some(([key,value])=>key!=='hashMatched'&&value!==true))
    return{...observations,identityCommandExecuted:false,versionMatched:false,executableMatched:false,stderrEmpty:false};
  const bytes=await readFile(receipt.nodeExecutable);observations.byteCountMatched=bytes.length===receipt.bytes;
  observations.hashMatched=digest(bytes)===receipt.sha256;
  if(!observations.byteCountMatched||!observations.hashMatched)
    return{...observations,identityCommandExecuted:false,versionMatched:false,executableMatched:false,stderrEmpty:false};
  const result=await execute(receipt.nodeExecutable,['-p','JSON.stringify({version:process.version,executable:process.execPath})'],{timeout:12000,maxBuffer:4096});
  let observed;try{observed=JSON.parse(result.stdout);}catch{assert.fail('recipe Node bounded identity output is valid JSON');}
  return{...observations,identityCommandExecuted:true,versionMatched:observed?.version===receipt.version,
    executableMatched:observed?.executable===receipt.nodeExecutable,stderrEmpty:result.stderr===''};
}
export async function verifyRecipeNode(receipt){
  const observations=await observeRecipeNode(receipt);
  for(const [key,value] of Object.entries(observations))assert.ok(value===true,'recipe Node prerequisite: '+key);
  return observations;
}
export async function rawRecipeNodeCommand(receipt,file,...args){
  try{const r=await execute(receipt.nodeExecutable,[file,...args],{timeout:12000,maxBuffer:2*1024*1024});return{code:0,...r,json:JSON.parse(r.stdout)};}
  catch(error){if(!Number.isInteger(error.code))throw error;return{code:error.code,stdout:error.stdout,stderr:error.stderr,json:JSON.parse(error.stdout)};}
}
export async function recipeNodeCommand(receipt,file,...args){await verifyRecipeNode(receipt);return rawRecipeNodeCommand(receipt,file,...args);}
export async function installedRecipeFixture(fn){
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-installed-recipe-'));await chmod(parent,0o700);
  const prefix=parent+'/install',launcher=prefix+'/bin/x10';
  try{
    await mkdir(prefix,{mode:0o700});for(const name of recipeV2Dirs)await mkdir(prefix+'/'+name,{mode:0o700});
    const immutable={},put=async(relative,bytes,mode=0o400)=>{await writeFile(prefix+'/'+relative,bytes,{mode});immutable[relative]={bytes:bytes.length,sha256:digest(bytes),mode:mode.toString(8).padStart(4,'0')};};
    await put('bin/nginx',Buffer.from('#!/bin/sh\n# Synthetic nonexecuted native placeholder.\nexit 99\n'),0o500);
    await put('bin/x10',Buffer.from('#!/usr/bin/env node\nimport { main } from "../lib/alpha/cli.mjs";\nimport { fileURLToPath } from "node:url";\nawait main(process.argv.slice(2), fileURLToPath(new URL("../", import.meta.url)));\n'),0o500);
    for(const name of recipeControlNames)await put('lib/control/'+name,await readFile(root+'x10/control/'+name));
    for(const name of recipeAlphaNames)await put('lib/alpha/'+name,await readFile(root+'x10/alpha/'+name));
    await put('lib/service/user-unit.mjs',await readFile(root+'x10/service/user-unit.mjs'));
    for(const name of ['build.json','licenses/NGINX-LICENSE','licenses/UPSTREAM.txt','examples/candidate-b.json'])await put(name,Buffer.from('{}\n'));
    const dep=Buffer.from('synthetic private dependency\n'),depfile=parent+'/dependency';await writeFile(depfile,dep,{mode:0o600});
    const st=await lstat(prefix),recipeNode=await prepareRecipeNode(parent),nodeExecutable=recipeNode.nodeExecutable,installId='a'.repeat(32),session='b'.repeat(32);
    const manifest={schemaVersion:2,kind:'nginx-x10-local-alpha',installationId:installId,prefix,rootIdentity:{dev:st.dev,ino:st.ino,uid:st.uid},
      immutable,dependencies:{kind:'dynamic-host-libraries',files:[{path:depfile,bytes:dep.length,sha256:digest(dep)}]},
      nodeRuntime:{version:recipeNode.version,executable:nodeExecutable,sha256:recipeNode.sha256},compiledModules:['synthetic_nonexecuted']};
    const save=async()=>{await writeFile(prefix+'/.alpha-install.json',JSON.stringify({...manifest,sha256:digest(JSON.stringify(manifest))}),{mode:0o600});};
    const registry={schemaVersion:1,installationId:installId,current:session,sessions:[session]};
    await writeFile(prefix+'/.alpha-registry.json',JSON.stringify({...registry,sha256:digest(JSON.stringify(registry))}),{mode:0o600});await save();
    await fn({parent,prefix,launcher,manifest,save,nodeExecutable,recipeNode,put});
  }finally{await rm(parent,{recursive:true,force:true});}
}
export async function recipeCli(f,...args){return recipeNodeCommand(f.recipeNode,f.launcher,...args);}

export function assertRecipeResult(result,{prefix,nodeExecutable,automatic=false}){
  assert.equal(result.code,0,result.stdout);assert.equal(result.stderr,'');
  assert.deepEqual(Object.keys(result.json),['ok','unit','scope','readinessAutomated','startupHealthAccepted','serviceAccepted','productionAccepted','outcome','activationPerformed']);
  assert.equal(result.json.ok,true);assert.equal(result.json.outcome,'service_unit_generated');assert.equal(result.json.scope,'systemd-user-recipe-only');
  for(const key of ['activationPerformed','startupHealthAccepted','serviceAccepted','productionAccepted'])assert.equal(result.json[key],false);
  assert.equal(result.json.readinessAutomated,automatic);assert(result.json.unit.includes(`ExecStart=${nodeExecutable} ${prefix}/bin/x10 run --control-socket ${prefix}/control.sock\n`));
  assert.equal(result.json.unit.includes('ExecStartPre='),automatic);assert.equal(result.json.unit.includes('ExecStartPost='),automatic);
  assert.doesNotMatch(result.json.unit,/systemctl|enable-linger|\/bin\/sh|killall/);
}
