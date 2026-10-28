// Baseline counterexample only: run from repository root. No native process,
// network, signal or service is exercised. Source pins refuse drift.
import { readFileSync as pinnedRead } from 'node:fs';
import { createHash as pinnedHash } from 'node:crypto';
if (pinnedHash('sha256').update(pinnedRead('x10/control/cli.mjs')).digest('hex') !== '72972fd1093068d05b788a326962f641fb2871dd7fa4cabb66957fcb3b22775b') throw new Error('baseline source pin mismatch');
import assert from 'node:assert/strict';import vm from 'node:vm';import {readFile,writeFile}from'node:fs/promises';
const source=await readFile(new URL('../control/cli.mjs',import.meta.url),'utf8');
const chunk=source.slice(source.indexOf('async function load(file)'),source.indexOf('\nlet humanStatus'));
const cases=[];let allocations=[];
async function assess(name,size,valid){let observedCalls=0;const load=vm.runInNewContext('('+chunk+')',{readFile:async(...args)=>{observedCalls++;assert.deepEqual(args,['owned-json-fixture']);allocations.push(size);return Buffer.from('"'+'x'.repeat(size-2)+'"');},Buffer,JSON,Error});let passed=false;try{await load('owned-json-fixture');assert.equal(valid,true);passed=true;}catch(error){assert.equal(valid,false);assert.match(error.message,/exceeds 2 MiB/);passed=true;}assert.equal(observedCalls,1);cases.push({name,bytesReturnedByUnboundedReadFile:size,loaderRefused:!valid,readFileCompletedBeforeRejection:!valid,pass:passed});}
await assess('at2MiB-validJSON',2*1024*1024,true);await assess('above2MiB-readCompletesBeforeRefusal',2*1024*1024+1,false);await assess('at3MiB-readCompletesBeforeRefusal',3*1024*1024,false);
console.log(JSON.stringify({kind:'source-extracted-CLI-load-read-order-contract',tests:3,pass:3,fail:0,cases,sourceExtractionExact:true,readFileIsMocked:true,actualOOMExecuted:false,subprocessesExecuted:0,networkFixturesExecuted:0,signalsSent:0}));
