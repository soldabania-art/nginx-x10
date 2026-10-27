import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createVerifiedRoutePermit, verifiedRouteExchange } from './tls-verified-route.mjs';

// All agents, requests, responses and sockets below are EventEmitter-only virtual
// objects. No HTTP/TLS socket, native process, signal or service is created.
// The baseline control constructs one possible route interleaving; it neither
// reproduces nor explains an exact historical native worker schedule.
const root = fileURLToPath(new URL('../../', import.meta.url));
const execute = promisify(execFile);
const tag = 'a'.repeat(32), origin = 'authenticated-origin';
const body = Buffer.from('PUBLIC_SYNTHETIC_TLS_APP\n');
const postBody = Buffer.from([0, 1, 2, 255, 128, 0, 31]);
const streamBody = Buffer.alloc(4096, 0x5a);
const goodHeaders = () => ({ 'x-x10-tls-probe': tag, 'x-tls-app': origin, connection: 'keep-alive' });
const virtualTest = (name, fn) => test(name, { timeout: 2000 }, fn);
class VirtualSocket extends EventEmitter {
  constructor() { super(); this.destroyed = false; this.writable = true; this.writableEnded = false; this.connecting = false; }
  destroy() { if (!this.destroyed) { this.destroyed = true; this.writable = false; this.emit('close'); } return this; }
}
function transport(plans = []) {
  const agents = [], requests = [], responses = [], sockets = [], unhandledErrors = [];
  class VirtualAgent {
    constructor() { this.socket = new VirtualSocket(); sockets.push(this.socket); this.destroyCalls = 0; this.createCalls = 0; this.destroyed = false; this.freeSockets = { virtual: [] }; }
    createConnection(_options, callback) { this.createCalls++; if (callback) callback(null, this.socket); return this.socket; }
    destroy() { this.destroyCalls++; this.destroyed = true; this.freeSockets.virtual = []; this.socket.destroy(); }
  }
  const createAgent = () => { const agent = new VirtualAgent(); agents.push(agent); return agent; };
  const emitError = (emitter, error) => { if (emitter.listenerCount('error')) emitter.emit('error', error); else unhandledErrors.push(error); };
  const request = (options, callback) => {
    const plan = plans[requests.length] || {}, agent = options.agent || createAgent();
    const selected = plan.replaceSocket ? new VirtualSocket() : agent.socket;
    if (plan.replaceSocket) sockets.push(selected);
    const req = new EventEmitter();
    Object.assign(req, { options, socket: undefined, reusedSocket: false,
      destroyed: false, ends: [], timeoutMs: null, timeoutCallback: null, selected });
    req.reusedSocket = plan.reusedSocket === undefined ? (options.method !== 'GET' || options.path === '/stream') : plan.reusedSocket;
    agent.freeSockets.virtual = agent.freeSockets.virtual.filter(socket => socket !== selected);
    requests.push(req); let ended = false, responseScheduled = false, emittedSocket = false, associatedResponse = null;
    const closeRequest = () => { req.emit('close'); };
    req.setTimeout = (ms, fn) => { req.timeoutMs = ms; req.timeoutCallback = fn; return req; };
    req.destroy = error => {
      if (!req.destroyed) { req.destroyed = true; req.socket?.destroy?.(); selected.destroy(); queueMicrotask(() => { if (error || plan.destroyError) emitError(req, error || new Error('PUBLIC_SYNTHETIC_ECONNRESET')); if (plan.destroyResponseError && associatedResponse) { emitError(associatedResponse, new Error('PUBLIC_SYNTHETIC_RESPONSE_RESET')); associatedResponse.emit('close'); } closeRequest(); }); }
      return req;
    };
    const deliver = () => {
      if (!ended || !emittedSocket || responseScheduled || req.destroyed) return;
      responseScheduled = true;
      queueMicrotask(() => {
        if (req.destroyed) return;
        if (plan.timeoutAfterEnd) { req.timeoutCallback?.(); return; }
        if (plan.errorAfterEnd) { emitError(req, new Error('SYNTHETIC_PRIVATE transport failure')); closeRequest(); return; }
        if (plan.neverRespond) return;
        const res = new EventEmitter(), expected = options.method === 'POST' ? postBody : options.path === '/stream' ? streamBody : body;
        Object.assign(res, { statusCode: plan.status ?? 200, headers: { ...goodHeaders(), ...plan.headers },
          socket: selected, complete: false, destroyed: false, req });
        res.destroy = error => { if (!res.destroyed) { res.destroyed = true; queueMicrotask(() => { if (error) emitError(res, error); res.emit('close'); closeRequest(); }); } return res; };
        responses.push(res); associatedResponse = res; if (plan.beforeResponse) plan.beforeResponse(selected, req, res); callback(res);
        if (plan.responseAborted) { res.emit('aborted'); res.emit('close'); closeRequest(); return; }
        const chunks = plan.chunks || [plan.body === undefined ? expected : plan.body];
        for (const chunk of chunks) { if (res.destroyed || req.destroyed) break; res.emit('data', chunk); }
        if (!res.destroyed && !req.destroyed) { res.complete = true; if (plan.missingComplete) delete res.complete; if (plan.detachSocketBeforeEnd) res.socket = null; res.emit('end'); res.emit('close'); closeRequest(); queueMicrotask(() => { if (!agent.destroyed && !selected.destroyed) agent.freeSockets.virtual.push(selected); }); }
      });
    };
    req.end = value => {
      req.ends.push(value === undefined ? Buffer.alloc(0) : Buffer.from(value)); ended = true;
      if (plan.onEnd) plan.onEnd(req, selected);
      deliver(); return req;
    };
    queueMicrotask(() => {
      if (req.destroyed) return;
      if (plan.agentRedial) {
        let observed; agent.createConnection({}, error => { observed = error; }); req.redialError = observed;
        if (observed) { req.destroy(observed); return; }
      }
      if (plan.beforeSocket) plan.beforeSocket(selected, req);
      req.socket = plan.actualSocketMismatch ? new VirtualSocket() : selected; if (plan.actualSocketMismatch) sockets.push(req.socket); emittedSocket = true;
      for (let index = 0; index < (plan.socketEvents || 1); index++) req.emit('socket', selected);
      deliver();
    });
    return req;
  };
  return { agents, requests, responses, sockets, unhandledErrors, createAgent, request,
    options: { port: 19080, tag, body, origin, postBody, streamBody,
      createAgent, request, maxGetAttempts: 3, retryDelayMs: 0, requestTimeoutMs: 25, acquireTimeoutMs: 500 } };
}
const postRequests = t => t.requests.filter(req => req.options.method === 'POST');
const writes = t => postRequests(t).flatMap(req => req.ends).filter(value => value.length > 0);
const refusal = async fn => assert.rejects(fn, error => {
  assert.equal(error.code, 'tls_verified_route_refused'); assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE|127\.0\.0\.1|19080/); return true;
});
function agentsDestroyed(t) { assert(t.agents.every(agent => agent.destroyed)); }

virtualTest('baseline fresh-socket transfer can send one POST onto an unverified old route after a successful new-route GET', async () => {
  const historical = (await execute('git', ['show', '6401c8f0fe4690a4daea0abac43d2e0efd91c0ad:x10/test/alpha-tls.test.mjs'],
    { cwd: root, timeout: 5000, maxBuffer: 256 * 1024 })).stdout;
  const begin = historical.indexOf('function transfer('), end = historical.indexOf('\n// This is fixture route binding', begin);
  assert(begin >= 0 && end > begin);
  const t = transport([{ body }, { status: 503, body: Buffer.from('PUBLIC_OLD_ROUTE_REFUSED') }]);
  const transfer = new Function('http', 'https', 'Buffer', 'setTimeout', 'clearTimeout',
    historical.slice(begin, end) + '\nreturn transfer;')({ request: t.request }, { request: t.request }, Buffer, setTimeout, clearTimeout);
  const good = await transfer(19080), posted = await transfer(19080, '/echo', { method: 'POST', body: postBody });
  assert.equal(good.status, 200); assert.deepEqual(good.body, body); assert.equal(posted.status, 503);
  assert.notEqual(t.requests[0].selected, t.requests[1].selected);
  assert.equal(writes(t).length, 1); assert.deepEqual(writes(t)[0], postBody);
  // The baseline itself has no reusable agent to clean; these owned virtual
  // agents are disposed by this synthetic transport after the observation.
  for (const agent of t.agents) agent.destroy();
});
virtualTest('verified route sends exactly one POST and stream on the same previously observed virtual socket', async () => {
  const t = transport(), result = await verifiedRouteExchange(t.options);
  assert.equal(result.routeVerified, true); assert.equal(result.sameSocket, true); assert.equal(result.postAttempts, 1);
  assert.equal(result.postBytes, postBody.length); assert.equal(result.streamBytes, streamBody.length);
  assert.equal(result.postRetried, false); assert.equal(result.allWorkerFenceAccepted, false); assert.equal(result.agentDestroyed, true);
  assert.equal(t.requests.length, 3); assert.equal(writes(t).length, 1); assert.deepEqual(writes(t)[0], postBody);
  assert.equal(t.requests[0].selected, t.requests[1].selected); assert.equal(t.requests[1].selected, t.requests[2].selected);
  agentsDestroyed(t);
});
for (const [label, plan] of [
  ['wrong body', { body: Buffer.from('PUBLIC_WRONG_BODY') }], ['wrong status', { status: 503 }],
  ['wrong tag', { headers: { 'x-x10-tls-probe': 'b'.repeat(32) } }],
  ['missing tag', { headers: { 'x-x10-tls-probe': undefined } }],
  ['ambiguous tag', { headers: { 'x-x10-tls-probe': [tag, tag] } }],
  ['wrong origin', { headers: { 'x-tls-app': 'unverified-origin' } }],
  ['missing origin', { headers: { 'x-tls-app': undefined } }],
]) virtualTest(`verified route retries only GET for ${label} using a fresh destroyed agent`, async () => {
  const t = transport([plan, {}, {}, {}]), result = await verifiedRouteExchange(t.options);
  assert.equal(result.getAttempts, 2); assert.equal(t.agents.length, 2); assert.equal(t.requests.length, 4);
  assert.equal(t.requests[0].options.method, 'GET'); assert.equal(t.requests[1].options.method, 'GET');
  assert.notEqual(t.requests[0].selected, t.requests[1].selected); assert.equal(writes(t).length, 1); agentsDestroyed(t);
});
virtualTest('verified route bounded GET rejection sends no POST body or implicit extra attempt', async () => {
  const t = transport([{ status: 503 }, { status: 503 }, {}]);
  await refusal(() => verifiedRouteExchange({ ...t.options, maxGetAttempts: 2 }));
  assert.equal(t.requests.length, 2); assert.equal(writes(t).length, 0); assert.equal(postRequests(t).length, 0); agentsDestroyed(t);
});
for (const [label, plan] of [
  ['replacement socket', { replaceSocket: true }], ['request actual socket differs from socket event', { actualSocketMismatch: true }], ['reused flag missing', { reusedSocket: false }],
  ['destroyed socket', { beforeSocket: socket => { socket.destroy(); } }],
  ['nonwritable socket', { beforeSocket: socket => { socket.writable = false; } }],
  ['ended socket', { beforeSocket: socket => { socket.writableEnded = true; } }],
  ['connecting socket', { beforeSocket: socket => { socket.connecting = true; } }],
  ['read-ended socket', { beforeSocket: socket => { socket.readableEnded = true; } }],
  ['agent automatic redial', { agentRedial: true }],
]) virtualTest(`verified route refuses ${label} before writing POST bytes`, async () => {
  const t = transport([{}, plan]); await refusal(() => verifiedRouteExchange(t.options));
  assert.equal(postRequests(t).length, 1); assert.equal(writes(t).length, 0); assert.equal(t.requests.length, 2); agentsDestroyed(t);
});
for (const [label, plan] of [
  ['HTTP503 after body sent', { status: 503 }], ['transport error after body sent', { errorAfterEnd: true }],
  ['ambiguous timeout after body sent', { timeoutAfterEnd: true }],
  ['wrong returned POST bytes', { body: Buffer.from('PUBLIC_WRONG_POST') }],
  ['wrong returned POST tag', { headers: { 'x-x10-tls-probe': 'b'.repeat(32) } }],
  ['oversize POST response', { chunks: [Buffer.alloc(2 * 1024 * 1024)] }],
  ['aborted POST response', { responseAborted: true }],
]) virtualTest(`verified route never retries ${label}`, async () => {
  const t = transport([{}, plan]); await refusal(() => verifiedRouteExchange(t.options));
  assert.equal(postRequests(t).length, 1); assert.equal(writes(t).length, 1); assert.deepEqual(writes(t)[0], postBody);
  assert.equal(t.requests.length, 2); agentsDestroyed(t);
});
virtualTest('duplicate POST socket callbacks cannot cause a second body write', async () => {
  const t = transport([{}, { socketEvents: 2 }, {}]);
  try { await verifiedRouteExchange(t.options); } catch (error) { assert.equal(error.code, 'tls_verified_route_refused'); }
  assert.equal(writes(t).length, 1); assert.equal(postRequests(t).length, 1); agentsDestroyed(t);
});
for (const [label, plan] of [
  ['stream replacement socket', { replaceSocket: true }], ['stream not reused', { reusedSocket: false }],
  ['stream wrong tag', { headers: { 'x-x10-tls-probe': 'b'.repeat(32) } }],
  ['stream wrong bytes', { body: Buffer.from('PUBLIC_WRONG_STREAM') }],
  ['stream response bound', { chunks: [Buffer.alloc(2 * 1024 * 1024)] }],
]) virtualTest(`verified route refuses ${label} without replaying POST`, async () => {
  const t = transport([{}, {}, plan]); await refusal(() => verifiedRouteExchange(t.options));
  assert.equal(postRequests(t).length, 1); assert.equal(writes(t).length, 1); assert.equal(t.requests.length, 3); agentsDestroyed(t);
});

virtualTest('verified route keeps acquisition within its injected clock budget without sending a POST', async () => {
  const t = transport([{ status: 503 }, { status: 503 }]); let time = 0;
  await refusal(() => verifiedRouteExchange({ ...t.options, now: () => time += 100, acquireTimeoutMs: 1 }));
  assert(t.requests.length <= 1); assert.equal(writes(t).length, 0); agentsDestroyed(t);
});
virtualTest('verified route bounds GET response bytes before any payload-carrying request', async () => {
  const t = transport([{ chunks: [Buffer.alloc(2 * 1024 * 1024)] }]);
  await refusal(() => verifiedRouteExchange({ ...t.options, maxGetAttempts: 1 }));
  assert.equal(t.requests.length, 1); assert.equal(writes(t).length, 0); agentsDestroyed(t);
});
virtualTest('verified route closes owned agents and removes owned socket listeners after success', async () => {
  const t = transport(); await verifiedRouteExchange(t.options); agentsDestroyed(t);
  for (const socket of t.sockets) for (const event of ['close', 'end', 'error']) assert.equal(socket.listenerCount(event), 0, event);
});
virtualTest('verified route closes owned agents and removes owned socket listeners after terminal POST failure', async () => {
  const t = transport([{}, { timeoutAfterEnd: true }]); await refusal(() => verifiedRouteExchange(t.options)); agentsDestroyed(t);
  for (const socket of t.sockets) for (const event of ['close', 'end', 'error']) assert.equal(socket.listenerCount(event), 0, event);
});

function dispose(permit) { if (typeof permit.dispose === 'function') permit.dispose(); }
test('route permit consumes one live exact reused-socket authority and cannot be consumed twice', () => {
  const socket = new VirtualSocket(), permit = createVerifiedRoutePermit(socket);
  try {
    assert.equal(permit.consume(socket, true), true); assert.equal(permit.consume(socket, true), false);
    assert.equal(permit.status().consumed, true);
  } finally { dispose(permit); }
});
for (const [label, select, reuse] of [
  ['wrong socket', () => new VirtualSocket(), true], ['not reused', socket => socket, false],
  ['missing reused marker', socket => socket, undefined],
]) test(`route permit ${label} refusal permanently prevents later valid consumption`, () => {
  const socket = new VirtualSocket(), permit = createVerifiedRoutePermit(socket);
  try {
    assert.equal(permit.consume(select(socket), reuse), false);
    assert.equal(permit.consume(socket, true), false); assert.equal(permit.status().revoked, true);
  } finally { dispose(permit); }
});
for (const [label, mutate] of [
  ['destroyed', socket => { socket.destroyed = true; }],
  ['nonwritable', socket => { socket.writable = false; }],
  ['write-ended', socket => { socket.writableEnded = true; }],
  ['connecting', socket => { socket.connecting = true; }],
  ['read-ended', socket => { socket.readableEnded = true; }],
]) test(`route permit refuses ${label} socket before an authority can be consumed`, () => {
  const socket = new VirtualSocket(), permit = createVerifiedRoutePermit(socket);
  try { mutate(socket); assert.equal(permit.consume(socket, true), false); assert.equal(permit.status().revoked, true); }
  finally { dispose(permit); }
});
for (const event of ['close', 'end', 'error']) test(`route permit ${event} permanently revokes late callback authority`, () => {
  const socket = new VirtualSocket(), permit = createVerifiedRoutePermit(socket);
  try {
    socket.emit(event, ...(event === 'error' ? [new Error('PUBLIC_SYNTHETIC_ERROR')] : []));
    socket.destroyed = false; socket.writable = true; socket.writableEnded = false; socket.connecting = false;
    assert.equal(permit.consume(socket, true), false); assert.equal(permit.live(socket, true), false);
    assert.equal(permit.status().revoked, true);
  } finally { dispose(permit); }
});
test('route permit explicit timeout revocation cannot be reversed by a late valid socket callback', () => {
  const socket = new VirtualSocket(), permit = createVerifiedRoutePermit(socket);
  try { permit.revoke(); assert.equal(permit.consume(socket, true), false); assert.equal(permit.live(socket, true), false); }
  finally { dispose(permit); }
});
test('route permit disposal revokes authority and removes only its owned socket listeners', () => {
  const socket = new VirtualSocket(), sentinel = () => {}; socket.on('close', sentinel);
  const permit = createVerifiedRoutePermit(socket);
  permit.dispose(); permit.dispose();
  assert.equal(permit.consume(socket, true), false); assert.equal(permit.status().revoked, true);
  assert.deepEqual(socket.listeners('close'), [sentinel]); assert.equal(socket.listenerCount('end'), 0); assert.equal(socket.listenerCount('error'), 0);
  socket.removeListener('close', sentinel);
});

virtualTest('fresh GET socket can still be connecting on assignment and becomes live before the verified response', async () => {
  const t = transport([{ beforeSocket: socket => { socket.connecting = true; }, beforeResponse: socket => { socket.connecting = false; } }, {}, {}]);
  const result = await verifiedRouteExchange({ ...t.options, maxGetAttempts: 1 });
  assert.equal(result.getAttempts, 1); assert.equal(result.postAttempts, 1); assert.equal(writes(t).length, 1); agentsDestroyed(t);
});
virtualTest('verified response captures the actual socket before Node detaches it at end', async () => {
  const plan = { detachSocketBeforeEnd: true }, t = transport([plan, plan, plan]);
  const result = await verifiedRouteExchange({ ...t.options, maxGetAttempts: 1 });
  assert.equal(result.sameSocket, true); assert.equal(writes(t).length, 1); agentsDestroyed(t);
});
virtualTest('late POST socket callback after ambiguous timeout cannot write or retry a second body', async () => {
  const t = transport([{}, { timeoutAfterEnd: true }]); await refusal(() => verifiedRouteExchange(t.options));
  const req = postRequests(t)[0], before = req.ends.length;
  req.reusedSocket = true; req.emit('socket', req.selected); req.emit('socket', new VirtualSocket());
  assert.equal(req.ends.length, before); assert.equal(writes(t).length, 1); assert.equal(postRequests(t).length, 1); agentsDestroyed(t);
});
virtualTest('a POST request-constructor throw terminates the attempt before body transmission and never retries', async () => {
  const t = transport(); let postConstructors = 0;
  const request = (options, callback) => { if (options.method === 'POST') { postConstructors++; throw new Error('SYNTHETIC_PRIVATE constructor failure'); } return t.request(options, callback); };
  await refusal(() => verifiedRouteExchange({ ...t.options, request }));
  assert.equal(postConstructors, 1); assert.equal(writes(t).length, 0); assert.equal(t.requests.length, 1); agentsDestroyed(t);
});
virtualTest('a terminal socket refusal drains late request-destroy error before removing its error guard', async () => {
  const t = transport([{}, { replaceSocket: true, destroyError: true }]); await refusal(() => verifiedRouteExchange(t.options));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(writes(t).length, 0); assert.equal(t.unhandledErrors.length, 0, 'Real ClientRequest destroy can report a later connection-reset error');
  for (const req of t.requests) assert.equal(req.listenerCount('error'), 0, 'Terminal guard is removed after close');
  agentsDestroyed(t);
});

virtualTest('terminal response overflow drains a late response-reset error until response close', async () => {
  const t = transport([{}, { chunks: [Buffer.alloc(2 * 1024 * 1024)], destroyResponseError: true }]);
  await refusal(() => verifiedRouteExchange(t.options)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(writes(t).length, 1); assert.equal(t.unhandledErrors.length, 0);
  for (const res of t.responses) assert.equal(res.listenerCount('error'), 0);
  agentsDestroyed(t);
});
virtualTest('an owned agent destroy exception fails the exchange with a fixed redacted error', async () => {
  const t = transport(), createAgent = () => {
    const agent = t.createAgent(), destroy = agent.destroy.bind(agent);
    agent.destroy = () => { destroy(); throw new Error('SYNTHETIC_PRIVATE agent disposal failed'); }; return agent;
  };
  await refusal(() => verifiedRouteExchange({ ...t.options, createAgent }));
  assert.equal(writes(t).length, 1); assert.equal(postRequests(t).length, 1); agentsDestroyed(t);
});

virtualTest('a response without confirmed complete framing never authorizes a POST', async () => {
  const t = transport([{ missingComplete: true }]);
  await refusal(() => verifiedRouteExchange({ ...t.options, maxGetAttempts: 1 }));
  assert.equal(t.requests.length, 1); assert.equal(writes(t).length, 0); assert.equal(postRequests(t).length, 0); agentsDestroyed(t);
});
