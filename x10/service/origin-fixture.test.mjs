import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { EventEmitter } from 'node:events';
import { chmod, mkdtemp, readFile, rm, lstat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { X509Certificate } from 'node:crypto';
import { createOriginFixture, routeOriginReadiness, queryOriginReadiness, originPortClosed,
  ORIGIN_FIXTURE_ERROR_CODES } from './origin-fixture.mjs';
import { probeServiceTLS, expectServiceTLSRefusal } from './tls-fixture.mjs';

const tag = 'a'.repeat(32), otherTag = 'b'.repeat(32);
const observed = (status = 200, marker = tag, body = 'ready\n') => ({ status, tag: marker, body: Buffer.from(body) });
const listen = async s => { s.listen(0, '127.0.0.1'); await once(s, 'listening'); return s.address().port; };
const close = s => new Promise(resolve => { s.closeAllConnections(); s.close(resolve); });
function request(port, route = '/') {
  return new Promise((resolve, reject) => {
    const req = http.get({host: '127.0.0.1', port, path: route, agent: false}, res => {
      const chunks = []; res.on('data', b => chunks.push(b)); res.on('error', reject);
      res.on('end', () => resolve({status: res.statusCode, body: Buffer.concat(chunks)}));
    }); req.setTimeout(2000, () => req.destroy()); req.on('error', reject);
  });
}

test('finite public failure codes are frozen and bounded', () => {
  assert(Object.isFrozen(ORIGIN_FIXTURE_ERROR_CODES)); assert.equal(ORIGIN_FIXTURE_ERROR_CODES.length, 11);
  assert.equal(new Set(ORIGIN_FIXTURE_ERROR_CODES).size, 11);
  assert.deepEqual(ORIGIN_FIXTURE_ERROR_CODES.slice(0,7),['origin_fixture_invalid','origin_fixture_failed','origin_cleanup_unconfirmed','origin_query_failed','origin_query_timeout','origin_query_limit','origin_response_invalid']);
  assert.deepEqual(ORIGIN_FIXTURE_ERROR_CODES.slice(7),['origin_challenge_invalid','origin_challenge_failed','origin_challenge_timeout','origin_challenge_identity']);
  assert(ORIGIN_FIXTURE_ERROR_CODES.every(c => /^origin_[a-z_]+$/.test(c)));
});
test('baseline unbound readiness accepts old route but candidate refuses it', () => {
  const old = observed(); assert.equal(({status: old.status, body: old.body}).status, 200);
  assert.equal(routeOriginReadiness(old, otherTag).status, 503);
});
test('matching bound readiness preserves success and actual502 body', () => {
  assert.deepEqual(routeOriginReadiness(observed(), tag), {status: 200, body: Buffer.from('ready\n')});
  assert.deepEqual(routeOriginReadiness(observed(502, tag, 'TLS refused\n'), tag), {status: 502, body: Buffer.from('TLS refused\n')});
});
test('missing, duplicate, malformed and oversized marker/body refuse', () => {
  for (const marker of [undefined, '', 'x'.repeat(32), tag + ', ' + tag]) assert.equal(routeOriginReadiness({...observed(),tag:marker}, tag).status, 503);
  for (const expected of ['', undefined, 'x'.repeat(32)]) assert.equal(routeOriginReadiness(observed(), expected).status, 503);
  assert.equal(routeOriginReadiness({...observed(),body: Buffer.alloc(4097)},tag).status,503);
});
test('HTTP query requests only regular native ready and preserves exact tag/status', async () => {
  const server = http.createServer((req,res) => { assert.equal(req.url,'/ready'); res.setHeader('X-X10-TLS-Probe',tag); res.writeHead(502); res.end('native TLS refused\n'); });
  const port = await listen(server); try { const result = await queryOriginReadiness(port); assert.equal(result.status,502); assert.equal(result.tag,tag); assert.equal(result.body.toString(),'native TLS refused\n'); } finally { await close(server); }
});
test('HTTP query rejects absent and duplicate native marker', async () => {
  for (const marker of [undefined,[tag,tag]]) {
    const server = http.createServer((_q,res) => { if (marker) res.setHeader('X-X10-TLS-Probe',marker); res.end('ready\n'); });
    const port=await listen(server); try { await assert.rejects(queryOriginReadiness(port),{code:'origin_response_invalid'}); } finally { await close(server); }
  }
});
test('HTTP query rejects output overflow and a truncated response', async () => {
  for (const truncate of [false,true]) {
    const server=http.createServer((_q,res)=>{res.setHeader('X-X10-TLS-Probe',tag); if(truncate){res.writeHead(200,{'content-length':50});res.write('part');setImmediate(()=>res.destroy());}else res.end(Buffer.alloc(4097));});
    const port=await listen(server); try { await assert.rejects(queryOriginReadiness(port),e=>['origin_query_limit','origin_query_failed','origin_response_invalid'].includes(e.code)); } finally { await close(server); }
  }
});
test('timeout and connection refusal cannot supply native ready', async () => {
  const server=http.createServer(()=>{}), port=await listen(server);
  try { await assert.rejects(queryOriginReadiness(port),{code:'origin_query_timeout'}); } finally { await close(server); }
  assert.equal(await originPortClosed(port),true); await assert.rejects(queryOriginReadiness(port),{code:'origin_query_failed'});
});
test('factory rejects arbitrary options/accessors/ports before PKI', async () => {
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-origin-invalid-')); await chmod(parent,0o700);
  try {
    for (const value of [{gatewayPort:80},{gatewayPort:18000,other:true},{gatewayPort:18000,body:'bad'},Object.defineProperty({},'gatewayPort',{get(){throw new Error('must not call');},enumerable:true})]) await assert.rejects(createOriginFixture(parent,value),{code:'origin_fixture_invalid'});
    await assert.rejects(lstat(path.join(parent,'pki')),{code:'ENOENT'});
  } finally { await rm(parent,{recursive:true}); }
});
test('source-extracted query late callback cannot validate after settled timeout', async () => {
  const source=await readFile(new URL('./origin-fixture.mjs',import.meta.url),'utf8');
  const start=source.indexOf('export function queryOriginReadiness('),end=source.indexOf('\nfunction listen(',start);
  assert(start>0&&end>start);let callback,absolute,idle,destroys=0,clear=0;
  const req=new EventEmitter();req.setTimeout=(_ms,fn)=>{idle=fn;};req.end=()=>{};req.destroy=()=>{destroys++;req.emit('close');};
  const fakeHTTP={request(_options,fn){callback=fn;return req;}};
  const fn=new Function('http','fail','validPort','setTimeout','clearTimeout',source.slice(start,end).replace('export function','function')+';return queryOriginReadiness;')(fakeHTTP,c=>{throw Object.assign(new Error(c),{code:c});},p=>Number.isInteger(p),fn=>{absolute=fn;return 1;},()=>{clear++;});
  const pending=new Set(),promise=fn(18000,pending);absolute();await assert.rejects(promise,{code:'origin_query_timeout'});assert.equal(destroys,1);assert.equal(pending.size,0);assert.equal(clear,1);
  const late=new EventEmitter();late.destroy=()=>{};Object.defineProperty(late,'rawHeaders',{get(){throw new Error('late validation forbidden');}});callback(late);idle();absolute();req.emit('error',new Error('fixed late event'));
  assert.equal(destroys,1);assert.equal(clear,1);
});
test('source-extracted close waits for pending request and socket close events', async () => {
  const source=await readFile(new URL('./origin-fixture.mjs',import.meta.url),'utf8');
  const start=source.indexOf('  async function close() {'),end=source.indexOf('\n  try {\n    pki =',start);
  assert(start>0&&end>start);const pending=new Set(),originSockets=new Set([{}]),relaySockets=new Set([{}]);
  const request={destroy(){setTimeout(()=>{pending.delete(request);originSockets.clear();relaySockets.clear();},30);}};pending.add(request);
  const fn=new Function('pending','originSockets','relaySockets','closeServer','originPortClosed','fail',
    'let closing=false;let origin,relay,port,readyPort,drain=null,readinessHold=null;const abortDrain=()=>{};const abortReadinessHold=()=>{};const readinessHoldClosed=()=>true;const closeNativeChallenge=async()=>true;'+source.slice(start,end)+';return close;')(pending,originSockets,relaySockets,async()=>true,async()=>true,c=>{throw Object.assign(new Error(c),{code:c});});
  const before=performance.now();assert.deepEqual(await fn(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});assert(performance.now()-before>=20);assert.equal(pending.size,0);assert.equal(originSockets.size,0);assert.equal(relaySockets.size,0);
});
test('source-extracted close refuses missing owned request close confirmation', async () => {
  const source=await readFile(new URL('./origin-fixture.mjs',import.meta.url),'utf8');
  const start=source.indexOf('  async function close() {'),end=source.indexOf('\n  try {\n    pki =',start);
  const pending=new Set([{destroy(){}}]);
  const fn=new Function('pending','originSockets','relaySockets','closeServer','originPortClosed','fail',
    'let closing=false;let origin,relay,port,readyPort,drain=null,readinessHold=null;const abortDrain=()=>{};const abortReadinessHold=()=>{};const readinessHoldClosed=()=>true;const closeNativeChallenge=async()=>true;'+source.slice(start,end)+';return close;')(pending,new Set(),new Set(),async()=>true,async()=>true,c=>{throw Object.assign(new Error(c),{code:c});});
  await assert.rejects(fn(),{code:'origin_cleanup_unconfirmed'});assert.equal(pending.size,1);
});

test('real private HTTPS origin, candidate relay and known-owned cleanup', {timeout:30000}, async t => {
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-origin-live-')); await chmod(parent,0o700);
  let fixture, status=200, marker=tag, nativeRequests=0, hold=false;
  const native=http.createServer((_q,res)=>{nativeRequests++; if(hold)return;res.setHeader('X-X10-TLS-Probe',marker);res.writeHead(status);res.end(status===200?'ready\n':'TLS refused\n');});
  const gatewayPort=await listen(native);
  try {
    fixture=await createOriginFixture(parent,{gatewayPort}); const options={ca:fixture.ca,expectedCertificate:fixture.expectedCertificate};
    await t.test('distinct private PKI and key mode with caller-owned asset retention',async()=>{assert.equal((await lstat(fixture.directory)).mode&0o777,0o700);assert.equal((await lstat(fixture.certificateKey)).mode&0o777,0o600);assert.notDeepEqual(fixture.ca,fixture.wrongCA);});
    await t.test('real TLS1.2 andTLS1.3 verify CA/name/exactleaf before exact bytes',async()=>{for(const version of ['TLSv1.2','TLSv1.3']){const r=await probeServiceTLS(fixture.port,'/',{...options,version});assert.equal(r.protocol,version);assert.equal(r.status,200);assert.equal(r.body.toString(),'service-fixture\n');}});
    await t.test('real authenticated upload and streamed bytes preserved',async()=>{const body=Buffer.alloc(65551,0x73);const r=await probeServiceTLS(fixture.port,'/echo',{...options,method:'POST',body});assert.deepEqual(r.body,body);const stream=await probeServiceTLS(fixture.port,'/stream',options);assert.deepEqual(stream.body,Buffer.alloc(65537,0x62));assert.equal(fixture.counts().echoRequests,1);});
    await t.test('real wrong CA/name fail exact expected authorizations',async()=>{assert.equal((await expectServiceTLSRefusal(fixture.port,{...options,ca:fixture.wrongCA})).code,'tls_ca_refused');assert.equal((await expectServiceTLSRefusal(fixture.port,{...options,servername:'wrong.invalid'})).code,'tls_hostname_refused');});
    await t.test('candidate exact native HTTPS controls cannot weaken verification',()=>{const good=fixture.candidate({tag});assert.match(good.serverBody,/proxy_ssl_verify on;/);assert.match(good.serverBody,/proxy_ssl_name localhost;/);assert.match(good.healthURL,new RegExp(`/tls-probe/${tag}$`));assert.match(fixture.candidate({tag:otherTag,trust:'wrong'}).serverBody,/wrong-ca\.crt/);assert.match(fixture.candidate({tag:'c'.repeat(32),name:'wrong.invalid'}).serverBody,/proxy_ssl_name wrong\.invalid;/);assert.match(fixture.candidate({tag:'d'.repeat(32),target:'plaintext'}).serverBody,new RegExp(`https://127.0.0.1:${fixture.readyPort}`));for(const v of [{tag},{tag,trust:'ignore'},{tag,name:'x;bad'},{tag,target:'http'},{tag,extra:true}])assert.throws(()=>fixture.candidate(v),{code:'origin_fixture_invalid'});});
    await t.test('readiness retains its input tag through old route and actual502',async()=>{let r=await request(fixture.readyPort,`/tls-probe/${tag}`);assert.equal(r.status,200);marker=otherTag;r=await request(fixture.readyPort,`/tls-probe/${tag}`);assert.equal(r.status,503);marker=tag;status=502;r=await request(fixture.readyPort,`/tls-probe/${tag}`);assert.equal(r.status,502);assert.equal(fixture.count502(tag),1);assert.equal(fixture.count502(otherTag),0);assert.equal(fixture.counts().relay502,1);status=200;assert.equal((await request(fixture.readyPort,`/tls-probe/${tag}`)).status,200);});
    await t.test('unknown candidate and management recursion paths never queried',async()=>{const before=nativeRequests;for(const route of ['/tls-probe/'+'f'.repeat(32),'/__x10_health','/tls-probe/'+tag+'?x'])assert.equal((await request(fixture.readyPort,route)).status,503);assert.equal(nativeRequests,before);});
    await t.test('plaintext origin refusal is not mislabeled CA/name authorization',async()=>{await assert.rejects(expectServiceTLSRefusal(fixture.readyPort,options),{code:'tls_refusal_unexpected'});});
    await t.test('close cancels in-flight relay and proves both ports absent',async()=>{hold=true;const pending=request(fixture.readyPort,`/tls-probe/${tag}`).catch(()=>null);await new Promise(r=>setTimeout(r,30));assert.deepEqual(await fixture.close(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});await pending;assert.deepEqual(await fixture.close(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});assert.throws(()=>fixture.candidate({tag}),{code:'origin_fixture_invalid'});assert.equal((await lstat(fixture.certificateKey)).isFile(),true);});
  } finally { if(fixture) await fixture.close(); await close(native); await rm(parent,{recursive:true}); }
});

test('partial setup failure after HTTPS listen closes owned origin before rejection', {timeout:20000},async()=>{
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-origin-partial-'));await chmod(parent,0o700);
  const oldHTTP=http.createServer,oldHTTPS=https.createServer;let originPort;
  https.createServer=function(...args){const server=oldHTTPS.apply(this,args);server.once('listening',()=>{originPort=server.address().port;});return server;};
  http.createServer=()=>{throw new Error('fixed synthetic relay creation failure');};
  try{await assert.rejects(createOriginFixture(parent,{gatewayPort:18000}),{code:'origin_fixture_failed'});assert(Number.isInteger(originPort));assert.equal(await originPortClosed(originPort),true);assert.equal((await lstat(path.join(parent,'pki','server.key'))).isFile(),true);}
  finally{http.createServer=oldHTTP;https.createServer=oldHTTPS;await rm(parent,{recursive:true});}
});

async function heldClient(fixture, route) {
  let resolveFirst, resolveDone, rejectDone, bytes=0, ended=false, failed=false;
  const first = new Promise(resolve => { resolveFirst=resolve; });
  const done = new Promise((resolve,reject) => { resolveDone=resolve; rejectDone=reject; }); done.catch(()=>{});
  const chunks=[];
  const req=https.get({host:'127.0.0.1',port:fixture.port,path:route,servername:'localhost',ca:fixture.ca,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',agent:false},res=>{
    assert.equal(res.statusCode,200);assert.equal(res.headers['content-length'],'65537');
    assert.equal(res.socket.authorized,true);assert.equal(res.socket.getProtocol(),'TLSv1.3');
    res.on('data',b=>{bytes+=b.length;chunks.push(b);if(bytes>=4096)resolveFirst();});
    res.once('end',()=>{ended=true;resolveDone(Buffer.concat(chunks));});
    res.once('error',e=>{failed=true;rejectDone(e);});
  });
  req.once('error',e=>{failed=true;rejectDone(e);});
  req.setTimeout(10000,()=>req.destroy(new Error('fixed held fixture test deadline')));
  await Promise.race([first,done.then(()=>{throw new Error('stream ended before held prefix');})]);
  return {done,snapshot:()=>({bytes,ended,failed}),cancel:()=>req.destroy()};
}
async function withDrainFixture(fn) {
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-origin-drain-'));await chmod(parent,0o700);let fixture;
  try {fixture=await createOriginFixture(parent,{gatewayPort:18000});await fn(fixture);}
  finally {if(fixture)await fixture.close();await rm(parent,{recursive:true});}
}
const later=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function drainRouteStatus(fixture,route) {
  return new Promise((resolve,reject)=>{
    const req=https.get({host:'127.0.0.1',port:fixture.port,path:route,servername:'localhost',ca:fixture.ca,
      minVersion:'TLSv1.3',maxVersion:'TLSv1.3',agent:false},res=>{
      let bytes=0;res.on('data',b=>{bytes+=b.length;if(bytes>4096)res.destroy(new Error('fixed status response limit'));});
      res.once('end',()=>resolve(res.statusCode));res.once('error',reject);
    });req.setTimeout(2000,()=>req.destroy(new Error('fixed status deadline')));req.once('error',reject);
  });
}

test('held HTTPS origin sends bounded prefix without EOF until explicit single release', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  const cap=fixture.prepareDrain();assert(Object.isFrozen(cap));assert.match(cap.path,/^\/slow-stream\/[a-f0-9]{32}$/);
  assert.deepEqual(cap.snapshot(),{held:false,requested:false,released:false,completed:false,aborted:false,closed:false});
  const forged=cap.snapshot();forged.held=true;forged.released=true;assert.equal(cap.snapshot().held,false);assert.equal(cap.snapshot().released,false);
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
  assert.throws(()=>fixture.prepareDrain(),{code:'origin_fixture_invalid'});
  const client=await heldClient(fixture,cap.path);
  try {
    await later(80);assert.equal(client.snapshot().bytes,4096);assert.equal(client.snapshot().ended,false);
    assert.deepEqual(cap.snapshot(),{held:true,requested:true,released:false,completed:false,aborted:false,closed:false});
    assert.equal(await drainRouteStatus(fixture,cap.path),404);assert.equal(cap.snapshot().held,true);
    assert.equal(cap.release(),true);assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
    assert.deepEqual(await client.done,Buffer.alloc(65537,0x62));await later(20);
    assert.deepEqual(cap.snapshot(),{held:false,requested:true,released:true,completed:true,aborted:false,closed:true});
    assert.equal(await cap.abort(),true);assert.equal(cap.snapshot().completed,true);
    for(const route of [cap.path,'/slow-stream/'+'0'.repeat(32),cap.path+'?replay=1']){
      assert.equal(await drainRouteStatus(fixture,route),404);
    }
    assert.equal(fixture.counts().echoRequests,0);assert.equal(fixture.counts().relay502,0);
  } finally {client.cancel();await cap.abort();}
}));

test('held capability abort is idempotent and cannot complete or release late', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  const cap=fixture.prepareDrain(),client=await heldClient(fixture,cap.path);
  assert.equal(await cap.abort(),true);await assert.rejects(client.done);assert.equal(await cap.abort(),true);
  assert.deepEqual(cap.snapshot(),{held:false,requested:true,released:false,completed:false,aborted:true,closed:true});
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});assert.throws(()=>fixture.prepareDrain(),{code:'origin_fixture_invalid'});
}));

test('prepared capability can be cancelled before request without fabricating close event', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  assert.throws(()=>fixture.prepareDrain({}),{code:'origin_fixture_invalid'});
  const cap=fixture.prepareDrain();assert.equal(await cap.abort(),true);assert.equal(await cap.abort(),true);
  assert.deepEqual(cap.snapshot(),{held:false,requested:false,released:false,completed:false,aborted:true,closed:false});
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
  assert.equal(await drainRouteStatus(fixture,cap.path),404);
}));

test('origin close aborts held response and confirms owned server ports before late actions', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  const cap=fixture.prepareDrain(),client=await heldClient(fixture,cap.path);
  assert.deepEqual(await fixture.close(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});
  await assert.rejects(client.done);assert.equal(cap.snapshot().completed,false);assert.equal(cap.snapshot().aborted,true);assert.equal(cap.snapshot().closed,true);
  assert.equal(await cap.abort(),true);assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});assert.throws(()=>fixture.prepareDrain(),{code:'origin_fixture_invalid'});
}));

test('held capability expiry aborts without sending remainder or granting completion', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  const cap=fixture.prepareDrain(),client=await heldClient(fixture,cap.path);
  await assert.rejects(client.done);assert.equal(client.snapshot().bytes,4096);assert.equal(client.snapshot().ended,false);
  assert.equal(cap.snapshot().released,false);assert.equal(cap.snapshot().completed,false);assert.equal(cap.snapshot().aborted,true);
  assert.equal(await cap.abort(),true);assert.equal(cap.snapshot().closed,true);assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
}));

test('peer disconnect while held cannot grant completion or revive the handle', {timeout:15000},async()=>withDrainFixture(async fixture=>{
  const cap=fixture.prepareDrain(),client=await heldClient(fixture,cap.path);client.cancel();await assert.rejects(client.done);
  const deadline=performance.now()+1000;while(!cap.snapshot().closed&&performance.now()<deadline)await later(10);
  assert.deepEqual(cap.snapshot(),{held:false,requested:true,released:false,completed:false,aborted:true,closed:true});
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});assert.equal(await cap.abort(),true);
}));

function verifiedOriginReady(fixture) {
  return new Promise((resolve,reject)=>{
    const req=https.get({host:'127.0.0.1',port:fixture.port,path:'/ready',servername:'localhost',ca:fixture.ca,
      minVersion:'TLSv1.3',maxVersion:'TLSv1.3',agent:false},res=>{
      if(!res.socket.authorized||!res.socket.getPeerCertificate(true).raw.equals(new X509Certificate(fixture.expectedCertificate).raw)){
        res.destroy(new Error('fixed origin leaf mismatch'));return;
      }
      const chunks=[];let bytes=0;res.on('data',b=>{bytes+=b.length;if(bytes>4096)res.destroy(new Error('fixed origin ready bound'));else chunks.push(b);});
      res.once('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks)}));res.once('error',reject);
    });req.setTimeout(1000,()=>req.destroy(new Error('fixed origin ready deadline')));req.once('error',reject);
  });
}
async function withReadinessFixture(fn) {
  const parent=await mkdtemp(path.join(os.tmpdir(),'x10-origin-ready-hold-'));await chmod(parent,0o700);let fixture;
  const control={marker:tag,status:200,body:'ready\n',requests:0,delay:false,delayed:[],healthTag:tag,proxyPending:new Set(),nativeSpec:null,nativeMode:'good',nativeResponses:new Set(),lateTimers:new Set()};
  const native=http.createServer(async(req,res)=>{
    if(control.nativeSpec&&req.url===control.nativeSpec.route){
      const spec=control.nativeSpec,mode=control.nativeMode;
      const target=mode==='wrong-relay-nonce'?spec.target.replace(spec.nonce,'f'.repeat(32)):spec.target;
      const upstream=http.get(target,{agent:false,headers:{connection:'close'}},reply=>{
        const headers={...reply.headers};control.nativeResponses.add(res);res.once('close',()=>control.nativeResponses.delete(res));
        if(mode!=='direct-relay'){
          headers['x-x10-native-challenge']=mode==='wrong-native-nonce'?'f'.repeat(32):mode==='duplicate-native-nonce'?[spec.nonce,spec.nonce]:spec.nonce;
          headers['x-x10-native-candidate']=mode==='wrong-native-tag'?otherTag:spec.tag;
        }
        if(mode==='wrong-relay-header')headers['x-x10-relay-challenge']='f'.repeat(32);
        if(mode==='wrong-content-length')headers['content-length']='1';
        res.writeHead(reply.statusCode,headers);res.flushHeaders();
        reply.on('data',chunk=>{
          const write=()=>{if(res.destroyed)return;if(mode==='wrong-prefix')res.write(Buffer.alloc(chunk.length,0x00));else if(mode!=='stall-prefix')res.write(chunk);if(mode==='early-eof')res.end();};
          if(mode==='late-prefix'){const timer=setTimeout(()=>{control.lateTimers.delete(timer);write();},250);control.lateTimers.add(timer);}else write();
        });reply.once('end',()=>res.end());reply.once('error',()=>res.destroy());
      });control.proxyPending.add(upstream);upstream.once('close',()=>control.proxyPending.delete(upstream));upstream.once('error',()=>res.destroy());res.once('close',()=>upstream.destroy());return;
    }
    if(req.url==='/__x10_health'){
      const upstream=http.get({host:'127.0.0.1',port:fixture.readyPort,path:`/tls-probe/${control.healthTag}`,agent:false},reply=>{
        res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);
      });control.proxyPending.add(upstream);upstream.once('close',()=>control.proxyPending.delete(upstream));
      upstream.once('error',()=>res.destroy());res.once('close',()=>upstream.destroy());return;
    }
    if(req.url!=='/ready'){res.writeHead(404);res.end('not found\n');return;}
    control.requests++;assert.equal(req.url,'/ready');
    try{
      const upstream=await verifiedOriginReady(fixture);assert.equal(upstream.status,200);assert.equal(upstream.body.toString(),'ready\n');
      if(control.delay){control.delayed.push(res);return;}
      if(!res.destroyed){res.setHeader('X-X10-TLS-Probe',control.marker);res.writeHead(control.status);res.end(control.body);}
    }catch{res.destroy();}
  });
  try{const gatewayPort=await listen(native);control.gatewayPort=gatewayPort;fixture=await createOriginFixture(parent,{gatewayPort});await fn(fixture,control);}
  finally{for(const timer of control.lateTimers)clearTimeout(timer);for(const request of control.proxyPending)request.destroy();if(fixture)await fixture.close();await close(native);await rm(parent,{recursive:true});}
}
function startHeldReadinessRequest(fixture,candidateTag,timeoutMs=10000) {
  let headers=false,ended=false;let resolveDone,rejectDone;
  const done=new Promise((resolve,reject)=>{resolveDone=resolve;rejectDone=reject;});done.catch(()=>{});
  const req=http.get({host:'127.0.0.1',port:fixture.readyPort,path:`/tls-probe/${candidateTag}`,agent:false},res=>{
    headers=true;const chunks=[];res.on('data',b=>chunks.push(b));res.once('error',rejectDone);
    res.once('end',()=>{ended=true;resolveDone({status:res.statusCode,body:Buffer.concat(chunks)});});
  });req.setTimeout(timeoutMs,()=>req.destroy(new Error('fixed readiness hold deadline')));req.once('error',rejectDone);
  return {done,snapshot:()=>({headers,ended}),cancel:()=>req.destroy()};
}
async function waitFor(fn){const deadline=performance.now()+1500;while(performance.now()<deadline){if(fn())return;await later(10);}assert.fail('fixed fixture observation deadline');}

test('readiness hold requires one newly registered never-queried candidate', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  assert.throws(()=>fixture.prepareReadinessHold(tag),{code:'origin_fixture_invalid'});
  fixture.candidate({tag:otherTag});control.marker=otherTag;assert.equal((await request(fixture.readyPort,`/tls-probe/${otherTag}`)).status,200);
  assert.throws(()=>fixture.prepareReadinessHold(otherTag),{code:'origin_fixture_invalid'});
  fixture.candidate({tag});for(const input of [undefined,'',Buffer.from(tag),{toString:()=>tag},'f'.repeat(32)])assert.throws(()=>fixture.prepareReadinessHold(input),{code:'origin_fixture_invalid'});
  assert.throws(()=>fixture.prepareReadinessHold(tag,{}),{code:'origin_fixture_invalid'});
  const cap=fixture.prepareReadinessHold(tag);assert(Object.isFrozen(cap));assert.deepEqual(cap.snapshot(),{held:false,requested:false,candidateReadyObserved:false,nativeProbeChecks:0,heldResponses:0,aborted:false,closed:false,released:false});
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});assert.throws(()=>fixture.prepareReadinessHold(tag),{code:'origin_fixture_invalid'});
  assert.equal(await cap.abort(),true);assert.equal(await cap.abort(),true);assert.equal(cap.snapshot().closed,true);assert.equal(cap.snapshot().nativeProbeChecks,0);
}));

test('readiness hold observes real verified origin route before withholding all healthy HTTP response', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  fixture.candidate({tag:otherTag});fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag);
  const client=startHeldReadinessRequest(fixture,tag);await waitFor(()=>cap.snapshot().held);
  const snapshot=cap.snapshot();assert.deepEqual(snapshot,{held:true,requested:true,candidateReadyObserved:true,nativeProbeChecks:1,heldResponses:1,aborted:false,closed:false,released:false});
  snapshot.aborted=true;snapshot.held=false;assert.equal(cap.snapshot().held,true);
  await later(100);assert.deepEqual(client.snapshot(),{headers:false,ended:false});assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
  control.marker=otherTag;assert.equal((await request(fixture.readyPort,`/tls-probe/${otherTag}`)).status,200);assert.equal(cap.snapshot().held,true);
  assert.equal(await cap.abort(),true);await assert.rejects(client.done);assert.equal(cap.snapshot().closed,true);assert.equal(cap.snapshot().heldResponses,0);assert.equal(cap.snapshot().released,false);
  const before=control.requests;assert.equal((await request(fixture.readyPort,`/tls-probe/${tag}`)).status,503);assert.equal(control.requests,before);
  assert.equal((await request(fixture.readyPort,`/tls-probe/${otherTag}`)).status,200);
  const stream=fixture.prepareDrain();assert.equal(await stream.abort(),true);
}));

test('stale marker, wrong readiness body and failed status never grant held authority', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag);
  for(const change of [{marker:otherTag,status:200,body:'ready\n'},{marker:tag,status:200,body:'wrong\n'},{marker:tag,status:503,body:'ready\n'}]){
    Object.assign(control,change);assert.equal((await request(fixture.readyPort,`/tls-probe/${tag}`)).status,503);
    assert.equal(cap.snapshot().held,false);assert.equal(cap.snapshot().candidateReadyObserved,false);assert.equal(cap.snapshot().nativeProbeChecks,0);
  }
  assert.equal(await cap.abort(),true);assert.equal(cap.snapshot().closed,true);
}));

test('readiness hold caps eight validated responses and rejects overflow without querying native', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag),clients=Array.from({length:8},()=>startHeldReadinessRequest(fixture,tag));
  await waitFor(()=>cap.snapshot().heldResponses===8);assert.equal(cap.snapshot().nativeProbeChecks,8);assert.equal(control.requests,8);
  assert.equal((await request(fixture.readyPort,`/tls-probe/${tag}`)).status,503);assert.equal(control.requests,8);
  for(const client of clients)assert.deepEqual(client.snapshot(),{headers:false,ended:false});
  assert.equal(await cap.abort(),true);await Promise.all(clients.map(client=>assert.rejects(client.done)));
  assert.equal(cap.snapshot().closed,true);assert.equal(cap.snapshot().heldResponses,0);assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
}));

test('aborted pending native query cannot gain authority when its late response arrives', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  fixture.candidate({tag});control.delay=true;const cap=fixture.prepareReadinessHold(tag),client=startHeldReadinessRequest(fixture,tag);
  await waitFor(()=>control.delayed.length===1);assert.equal(cap.snapshot().held,false);assert.equal(cap.snapshot().nativeProbeChecks,0);
  assert.equal(await cap.abort(),true);await assert.rejects(client.done);
  for(const res of control.delayed){res.setHeader('X-X10-TLS-Probe',tag);res.writeHead(200);res.end('ready\n');}
  await later(50);assert.deepEqual(cap.snapshot(),{held:false,requested:true,candidateReadyObserved:false,nativeProbeChecks:0,heldResponses:0,aborted:true,closed:true,released:false});
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
}));

test('readiness hold expires by abort only and never supplies a healthy reply', {timeout:15000},async()=>withReadinessFixture(async(fixture)=>{
  fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag),client=startHeldReadinessRequest(fixture,tag);await waitFor(()=>cap.snapshot().held);
  await assert.rejects(client.done);assert.deepEqual(client.snapshot(),{headers:false,ended:false});assert.equal(await cap.abort(),true);
  assert.equal(cap.snapshot().aborted,true);assert.equal(cap.snapshot().closed,true);assert.equal(cap.snapshot().held,false);assert.equal(cap.snapshot().released,false);
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});
}));

test('origin close drains held readiness responses and refuses every late action', {timeout:15000},async()=>withReadinessFixture(async(fixture)=>{
  fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag),client=startHeldReadinessRequest(fixture,tag);await waitFor(()=>cap.snapshot().held);
  assert.deepEqual(await fixture.close(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});await assert.rejects(client.done);
  assert.equal(cap.snapshot().aborted,true);assert.equal(cap.snapshot().closed,true);assert.equal(await cap.abort(),true);
  assert.throws(()=>cap.release(),{code:'origin_fixture_invalid'});assert.throws(()=>fixture.prepareReadinessHold(tag),{code:'origin_fixture_invalid'});
}));

test('c1cf baseline controller350ms closure leaves a live-probe gap before the original1000ms budget', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  fixture.candidate({tag});const cap=fixture.prepareReadinessHold(tag),start=performance.now();
  const source=await readFile(new URL('../control/manager.mjs',import.meta.url),'utf8');
  const first=source.indexOf('function request(settings, target,'),last=source.indexOf('\nasync function acknowledged(',first);
  assert(first>0&&last>first);const controllerRequest=new Function('http',source.slice(first,last)+';return request;')(http);
  const controller=controllerRequest({port:control.gatewayPort},'/__x10_health');controller.catch(()=>{});
  await waitFor(()=>cap.snapshot().held);assert.equal(cap.snapshot().heldResponses,1);
  await assert.rejects(controller,/Probe (absolute|idle) deadline exceeded/);await waitFor(()=>cap.snapshot().heldResponses===0);
  const elapsed=performance.now()-start,s=cap.snapshot();
  assert(elapsed>=300&&elapsed<1000);assert.equal(s.candidateReadyObserved,true);assert.equal(s.nativeProbeChecks,1);
  assert.equal(s.held,false);assert.equal(s.aborted,false);assert.equal(s.closed,false);
  assert.equal(await cap.abort(),true);
}));

function declareNativeChallenge(fixture,control) {
  const input=fixture.candidate({tag}),held=fixture.prepareReadinessHold(tag),location=held.nativeLocation;
  const route=/^location = (\/__x10-native-challenge\/([a-f0-9]{32})) \{ proxy_pass (http:\/\/127\.0\.0\.1:([0-9]+)\/native-challenge\/([a-f0-9]{32})\/([a-f0-9]{32}));/.exec(location);
  assert(route);assert.equal(Number(route[4]),fixture.readyPort);assert.equal(route[5],tag);assert.equal(route[2],route[6]);
  assert(location.includes(`add_header X-X10-Native-Challenge "${route[2]}" always;`));assert(location.includes(`add_header X-X10-Native-Candidate "${tag}" always;`));
  for(const directive of ['proxy_buffering off;','proxy_pass_request_headers off;','proxy_cache off;','proxy_next_upstream off;','proxy_ignore_client_abort off;'])assert(location.includes(directive));
  control.nativeSpec={route:route[1],nonce:route[2],target:route[3],tag:route[5]};input.serverBody+='\n'+location;
  assert.equal(input.serverBody.split(location).length,2);return {held,input};
}
const nativeBooleans=['nativeRouteObserved','ownedRequestObserved','relayResponseMatched','currentRequestOpen','responseIncomplete','relayResponseOpen','socketOpen','pairMatched'];
function assertNativeLive(snapshot){assert.equal(snapshot.held,true);assert.equal(snapshot.requested,true);assert.equal(snapshot.candidateReadyObserved,true);assert.equal(snapshot.nativeProbeChecks,1);assert.equal(snapshot.heldResponses,1);assert.equal(snapshot.aborted,false);assert.equal(snapshot.closed,false);assert.equal(snapshot.released,false);for(const key of nativeBooleans)assert.equal(snapshot[key],true);}
async function actualControllerRequest(control) {
  const source=await readFile(new URL('../control/manager.mjs',import.meta.url),'utf8');
  const first=source.indexOf('function request(settings, target,'),last=source.indexOf('\nasync function acknowledged(',first);
  const run=new Function('http',source.slice(first,last)+';return request;')(http);
  return run({port:control.gatewayPort},'/__x10_health');
}

test('owned native challenge stays physically live across the controller350ms probe gap', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);
  const controller=actualControllerRequest(control);controller.catch(()=>{});await waitFor(()=>held.snapshot().held);
  const deadline=performance.now()+1000,owned=await held.openNativeChallenge(deadline);assert(Object.isFrozen(owned));assertNativeLive(owned.snapshot());
  await assert.rejects(controller,/Probe (absolute|idle) deadline exceeded/);await waitFor(()=>held.snapshot().heldResponses===0);
  assert(performance.now()<deadline);assert.equal(held.snapshot().held,false);assertNativeLive(owned.snapshot());
  const forged=owned.snapshot();forged.pairMatched=false;assertNativeLive(owned.snapshot());
  await assert.rejects(held.openNativeChallenge(deadline),{code:'origin_challenge_invalid'});
  assert.equal(await owned.abort(),true);assert.equal(await owned.abort(),true);assert.equal(owned.snapshot().held,false);assert.equal(owned.snapshot().closed,true);
  assert.equal(await held.abort(),true);
}));

for(const mode of ['wrong-native-nonce','wrong-native-tag','duplicate-native-nonce','wrong-relay-header','wrong-relay-nonce','direct-relay','wrong-prefix','wrong-content-length']){
  test('owned challenge refuses '+mode+' without granting a handle', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
    const {held}=declareNativeChallenge(fixture,control);control.nativeMode=mode;
    await assert.rejects(held.openNativeChallenge(performance.now()+700),e=>['origin_challenge_identity','origin_challenge_failed','origin_challenge_timeout'].includes(e.code));
    assert.equal(await held.abort(),true);assert.equal(held.snapshot().aborted,true);
    await assert.rejects(held.openNativeChallenge(performance.now()+500),{code:'origin_challenge_invalid'});
  }));
}

test('early gateway EOF cannot retain physically live challenge authority', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);control.nativeMode='early-eof';let owned;
  try{owned=await held.openNativeChallenge(performance.now()+700);}catch(error){assert(/^origin_challenge_/.test(error.code));}
  if(owned){const end=performance.now()+150;while(owned.snapshot().socketOpen&&performance.now()<end)await later(5);assert.equal(owned.snapshot().socketOpen,false);assert.equal(owned.snapshot().held,false);assert.equal(await owned.abort(),true);}
  assert.equal(await held.abort(),true);
}));

test('old gateway route without the native challenge location cannot manufacture proof', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);control.nativeSpec=null;
  await assert.rejects(held.openNativeChallenge(performance.now()+500),e=>/^origin_challenge_/.test(e.code));
  assert.equal(await held.abort(),true);assert.equal(held.snapshot().aborted,true);
}));

test('own challenge rejects caller-selected routes and invalid or enlarged deadlines', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);
  for(const deadline of [undefined,NaN,Infinity,-1,0,'1000',{},performance.now()-1,performance.now()+5000])await assert.rejects(held.openNativeChallenge(deadline),{code:'origin_challenge_invalid'});
  await assert.rejects(held.openNativeChallenge(performance.now()+500,{port:fixture.readyPort,path:'/ready'}),{code:'origin_challenge_invalid'});
  const owned=await held.openNativeChallenge(performance.now()+500);assertNativeLive(owned.snapshot());assert.equal(await owned.abort(),true);assert.equal(await held.abort(),true);
}));

test('own response authority expires at its original deadline even before global8s expiry', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control),deadline=performance.now()+250;
  const owned=await held.openNativeChallenge(deadline);assertNativeLive(owned.snapshot());await later(300);
  assert.equal(owned.snapshot().held,false);assert.equal(owned.snapshot().aborted,true);assert.equal(await owned.abort(),true);assert.equal(await held.abort(),true);
}));

test('aborted pending challenge cannot resolve through a late prefix callback', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);control.nativeMode='late-prefix';
  const opening=held.openNativeChallenge(performance.now()+700);opening.catch(()=>{});await waitFor(()=>control.nativeResponses.size===1);
  assert.equal(await held.abort(),true);await assert.rejects(opening,e=>/^origin_challenge_/.test(e.code));await later(300);
  assert.equal(held.snapshot().closed,true);await assert.rejects(held.openNativeChallenge(performance.now()+500),{code:'origin_challenge_invalid'});
}));

test('challenge absolute timeout rejects stalled prefix and cannot rearm after late callback', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);control.nativeMode='late-prefix';
  await assert.rejects(held.openNativeChallenge(performance.now()+100),e=>/^origin_challenge_/.test(e.code));await later(300);
  await assert.rejects(held.openNativeChallenge(performance.now()+500),{code:'origin_challenge_invalid'});assert.equal(await held.abort(),true);
}));

test('global8s expiry refuses a new challenge without extending or replacing its capability', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control);await later(8050);
  await assert.rejects(held.openNativeChallenge(performance.now()+500),{code:'origin_challenge_invalid'});
  assert.equal(held.snapshot().aborted,true);assert.equal(await held.abort(),true);
}));

test('closing an origin with a live owned challenge observes every local socket close', {timeout:15000},async()=>withReadinessFixture(async(fixture,control)=>{
  const {held}=declareNativeChallenge(fixture,control),owned=await held.openNativeChallenge(performance.now()+700);
  assertNativeLive(owned.snapshot());assert.deepEqual(await fixture.close(),{originClosed:true,relayClosed:true,originPortClosed:true,relayPortClosed:true});
  assert.equal(owned.snapshot().held,false);assert.equal(owned.snapshot().closed,true);assert.equal(await owned.abort(),true);assert.equal(await held.abort(),true);
}));
