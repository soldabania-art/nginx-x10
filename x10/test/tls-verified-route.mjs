// Test fixture transport only: pin one observed downstream HTTP connection.
// This is not upstream authentication, an all-worker fence or a runtime change.
import http from 'node:http';

const refused = () => Object.assign(new Error('Verified TLS route fixture refused'), { code: 'tls_verified_route_refused' });
const liveSocket = socket => {
  try { return Boolean(socket && socket.destroyed === false && socket.writable === true
    && socket.writableEnded !== true && socket.readableEnded !== true && socket.connecting !== true); } catch { return false; }
};

// A permit is created only after the exchange has verified its actual GET. The
// exported constructor also supports independent virtual lifecycle controls.
export function createVerifiedRoutePermit(selected) {
  let consumed = false, revoked = false, disposed = false;
  const revoke = () => { revoked = true; };
  const attached = [];
  try {
    if (!liveSocket(selected) || typeof selected.on !== 'function' || typeof selected.removeListener !== 'function') throw refused();
    for (const event of ['close', 'end', 'error']) { attached.push(event); selected.on(event, revoke); }
  } catch {
    revoke();
    for (const event of attached) { try { selected.removeListener(event, revoke); } catch { /* Preserve refusal if an injected emitter fails cleanup. */ } }
    throw refused();
  }
  return {
    live(socket, reusedSocket) { return !revoked && !disposed && reusedSocket === true && socket === selected && liveSocket(selected); },
    consume(socket, reusedSocket) {
      if (consumed || revoked || disposed || reusedSocket !== true || socket !== selected || !liveSocket(selected)) { revoke(); return false; }
      consumed = true; return true;
    },
    revoke,
    status() { return { consumed, revoked }; },
    dispose() {
      revoke(); if (disposed) return; disposed = true;
      for (const event of ['close', 'end', 'error']) selected.removeListener(event, revoke);
    },
  };
}

// Factories are injectable for pure/virtual tests; no socket is opened on import.
export async function verifiedRouteExchange({ port, tag, body, origin, postBody, streamBody,
  createAgent = () => new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 }),
  request = http.request, now = () => performance.now(), acquireTimeoutMs = 8000,
  requestTimeoutMs = 2500, maxGetAttempts = 8, retryDelayMs = 25 } = {}) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || typeof tag !== 'string' || tag.length !== 32 || /[^a-f0-9]/.test(tag)
      || typeof origin !== 'string' || origin.length < 1 || origin.length > 256
      || ![body, postBody, streamBody].every(value => Buffer.isBuffer(value) && value.length > 0 && value.length <= 1024 * 1024)
      || !Number.isInteger(acquireTimeoutMs) || acquireTimeoutMs < 1 || acquireTimeoutMs > 8000
      || !Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 2500
      || !Number.isInteger(maxGetAttempts) || maxGetAttempts < 1 || maxGetAttempts > 8
      || !Number.isInteger(retryDelayMs) || retryDelayMs < 0 || retryDelayMs > 1000
      || ![createAgent, request, now].every(value => typeof value === 'function')) throw refused();
  const expectedBody = Buffer.from(body), payload = Buffer.from(postBody), expectedStream = Buffer.from(streamBody);
  const started = now(); if (!Number.isFinite(started)) throw refused();
  const deadline = started + acquireTimeoutMs;
  let agent = null, selected = null, permit = null, getAttempts = 0, postAttempts = 0;
  let agentDestroyed = false, postExact = false, streamExact = false;
  const remaining = () => { const current = now(); if (!Number.isFinite(current)) throw refused(); return deadline - current; };
  const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
  const destroyAgent = () => {
    permit?.revoke();
    if (agent !== null) { const current = agent; agent = null; current.destroy(); agentDestroyed = true; }
  };
  const freeInPool = socket => agent && agent.freeSockets && typeof agent.freeSockets === 'object'
    && Object.values(agent.freeSockets).some(values => Array.isArray(values) && values.includes(socket));
  const waitFree = async (socket, budget) => {
    const end = now() + budget;
    for (;;) {
      if (!liveSocket(socket) || (permit && !permit.live(socket, true))) throw refused();
      if (freeInPool(socket)) return;
      if (!Number.isFinite(now()) || now() >= end) throw refused();
      await sleep(0);
    }
  };
  const exchange = (route, method, data, budget, requireSelected) => new Promise((resolve, reject) => {
    let req = null, response = null, responseSocket = null, socket = null, settled = false, timer = null, ended = false;
    let requestClosed = false, responseClosed = false;
    const drainErrorsUntilClose = (emitter, closed) => {
      if (!emitter || closed || emitter.closed === true || typeof emitter.on !== 'function' || typeof emitter.once !== 'function' || typeof emitter.removeListener !== 'function') return;
      const absorb = () => {};
      const retire = () => { emitter.removeListener('error', absorb); emitter.removeListener('close', retire); };
      emitter.on('error', absorb); emitter.once('close', retire);
    };
    const chunks = []; let bytes = 0;
    const remove = () => {
      if (req && typeof req.removeListener === 'function') { req.removeListener('socket', onSocket); req.removeListener('error', onError); req.removeListener('close', onClose); }
      if (response && typeof response.removeListener === 'function') {
        response.removeListener('data', onData); response.removeListener('error', onError);
        response.removeListener('aborted', onAborted); response.removeListener('end', onEnd); response.removeListener('close', onResponseClose);
      }
    };
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer);
      if (error) permit?.revoke();
      // ClientRequest.destroy() can asynchronously emit socket-hangup errors.
      // Drain terminal errors through owned close, after authority is revoked.
      try { drainErrorsUntilClose(req, requestClosed); drainErrorsUntilClose(response, responseClosed); } catch { error = refused(); }
      try { remove(); } catch { error = refused(); }
      if (error) { try { req?.destroy(); } catch { /* No new transport is attempted. */ } reject(refused()); }
      else resolve(value);
    };
    const onError = () => finish(refused());
    const onAborted = () => finish(refused());
    const onClose = () => { requestClosed = true; if (!ended) finish(refused()); };
    const onResponseClose = () => { responseClosed = true; if (!ended) finish(refused()); };
    const onData = chunk => {
      if (settled) return;
      if (!Buffer.isBuffer(chunk)) return finish(refused());
      bytes += chunk.length; if (bytes > 1024 * 1024) return finish(refused());
      chunks.push(Buffer.from(chunk));
    };
    const onEnd = () => {
      if (settled) return; ended = true;
      try {
        if (!socket || responseSocket !== socket || response.complete !== true) return finish(refused());
        finish(null, { status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks, bytes), socket });
      } catch { finish(refused()); }
    };
    const onSocket = value => {
      if (settled) return;
      socket = value;
      try {
      if (req.socket !== value) return finish(refused());
      if (requireSelected) {
        const allowed = method === 'POST' ? permit?.consume(value, req.reusedSocket) : permit?.live(value, req.reusedSocket);
        if (!allowed) return finish(refused());
        // Do not queue headers/body before exact reuse and liveness validation.
        try { req.end(data); } catch { finish(refused()); }
      } else if (!value || value.destroyed !== false || value.writable !== true) finish(refused());
      } catch { finish(refused()); }
    };
    const onResponse = value => {
      if (settled) {
        permit?.revoke();
        try { drainErrorsUntilClose(value, value?.closed === true); value?.destroy?.(); } catch { /* A late response cannot regain request authority. */ }
        return;
      }
      try {
      response = value; responseSocket = value?.socket;
      if (!req || !socket || req.socket !== socket || !liveSocket(socket) || response?.socket !== socket
          || typeof response.on !== 'function' || typeof response.once !== 'function' || typeof response.removeListener !== 'function') return finish(refused());
      response.on('data', onData); response.once('error', onError); response.once('aborted', onAborted);
      response.once('end', onEnd); response.once('close', onResponseClose);
      } catch { finish(refused()); }
    };
    try {
      req = request({ host: '127.0.0.1', port, path: route, method, agent,
        headers: { 'content-length': data.length } }, onResponse);
      if (settled) {
        try { drainErrorsUntilClose(req, req?.closed === true); req?.destroy?.(); } catch { /* Constructor callbacks already made this exchange terminal. */ }
        return;
      }
      if (!req || typeof req.on !== 'function' || typeof req.once !== 'function' || typeof req.removeListener !== 'function'
          || typeof req.end !== 'function' || typeof req.destroy !== 'function') return finish(refused());
      req.once('socket', onSocket); req.once('error', onError); req.once('close', onClose);
      timer = setTimeout(() => finish(refused()), budget);
      if (!requireSelected) req.end(data);
    } catch { finish(refused()); }
  });
  const matchesRoute = result => result.status === 200 && result.headers?.['x-tls-app'] === origin
    && result.headers?.['x-x10-tls-probe'] === tag;
  try {
    for (; getAttempts < maxGetAttempts;) {
      if (remaining() <= 0) throw refused();
      agent = createAgent(); agentDestroyed = false;
      if (!agent || typeof agent.destroy !== 'function' || typeof agent.createConnection !== 'function') throw refused();
      getAttempts++;
      try {
        const result = await exchange('/', 'GET', Buffer.alloc(0), Math.max(1, Math.min(requestTimeoutMs, remaining())), false);
        if (!matchesRoute(result) || !result.body.equals(expectedBody)) throw refused();
        selected = result.socket;
        await waitFree(selected, Math.max(1, Math.min(requestTimeoutMs, remaining())));
        if (remaining() <= 0) throw refused();
        permit = createVerifiedRoutePermit(selected);
        break;
      } catch {
        destroyAgent(); selected = null;
        if (getAttempts >= maxGetAttempts || remaining() <= 0) throw refused();
        await sleep(Math.max(0, Math.min(retryDelayMs, remaining())));
      }
    }
    if (!permit || !selected || !agent) throw refused();
    // Never let an HTTP Agent silently reconnect after the verified GET.
    agent.createConnection = (_options, callback) => { const error = refused(); if (typeof callback === 'function') callback(error); else throw error; return undefined; };
    postAttempts++;
    const echoed = await exchange('/echo', 'POST', payload, requestTimeoutMs, true);
    if (!matchesRoute(echoed) || !echoed.body.equals(payload) || echoed.socket !== selected) throw refused();
    postExact = true;
    await waitFree(selected, requestTimeoutMs);
    const streamed = await exchange('/stream', 'GET', Buffer.alloc(0), requestTimeoutMs, true);
    if (!matchesRoute(streamed) || !streamed.body.equals(expectedStream) || streamed.socket !== selected) throw refused();
    streamExact = true;
  } catch { throw refused(); }
  finally {
    let cleanupFailed = false;
    try { destroyAgent(); } catch { cleanupFailed = true; }
    try { permit?.dispose(); } catch { cleanupFailed = true; }
    if (cleanupFailed) throw refused();
  }
  return { routeVerified: true, sameSocket: true, getAttempts, postAttempts, postExact, streamExact,
    postBytes: payload.length, streamBytes: expectedStream.length, agentDestroyed,
    postRetried: false, allWorkerFenceAccepted: false };
}
