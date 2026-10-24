#!/usr/bin/env node
// Explicit loopback application example, not the native gateway or a service.
import http from 'node:http';
import { parseArgs } from 'node:util';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const MAX_ECHO_BYTES = 16 * 1024 * 1024;
export const STREAM_BYTES = 8 * 1024 * 1024;

function reply(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

async function stream(res) {
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': STREAM_BYTES });
  const chunk = Buffer.alloc(16 * 1024, 0x78);
  for (let sent = 0; sent < STREAM_BYTES && !res.destroyed; sent += chunk.length) {
    if (res.write(chunk)) continue;
    await new Promise(resolve => {
      const done = () => { res.off('drain', done); res.off('close', done); res.off('error', done); resolve(); };
      res.once('drain', done); res.once('close', done); res.once('error', done);
    });
  }
  if (!res.destroyed) res.end();
}

export function createExampleServer() {
  let activeEcho = 0;
  const server = http.createServer({ requestTimeout: 5000, headersTimeout: 5000,
    keepAliveTimeout: 1000, maxHeaderSize: 16 * 1024 }, (req, res) => {
    req.on('error', () => res.destroy());
    res.on('error', () => req.destroy());
    req.setTimeout(5000, () => req.destroy());
    if (req.method === 'GET' && req.url === '/ready') return reply(res, 200, 'ready\n');
    if (req.method === 'GET' && req.url === '/') return reply(res, 200, 'NGINX X10 upstream example\n');
    if (req.method === 'GET' && req.url === '/stream') { void stream(res); return; }
    if (req.method !== 'POST' || req.url !== '/echo') return reply(res, 404, 'not found\n');
    if (activeEcho >= 4) { res.shouldKeepAlive = false; return reply(res, 503, 'example busy\n'); }
    activeEcho++;
    let released = false;
    const release = () => { if (!released) { released = true; activeEcho--; } };
    res.once('finish', release); res.once('close', release);
    let chunks = [], bytes = 0, refused = false;
    req.on('aborted', () => { chunks = []; });
    req.on('data', chunk => {
      if (refused) return;
      bytes += chunk.length;
      if (bytes > MAX_ECHO_BYTES) {
        refused = true; chunks = []; res.shouldKeepAlive = false;
        reply(res, 413, 'example body limit\n'); return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (refused || res.destroyed) { chunks = []; return; }
      const body = Buffer.concat(chunks, bytes); chunks = [];
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length });
      res.end(body);
    });
  });
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 16;
  server.on('clientError', (_error, socket) => socket.destroy());
  return server;
}

export async function main(args = process.argv.slice(2)) {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({ args, allowPositionals: true,
      options: { port: { type: 'string', default: '9090' }, help: { type: 'boolean', short: 'h' } } }));
    if (positionals.length || !/^[1-9][0-9]{3,4}$/.test(values.port)
        || Number(values.port) < 1024 || Number(values.port) > 65535) throw new Error();
  } catch { process.stdout.write('{"ok":false,"code":"example_arguments"}\n'); process.exitCode = 1; return; }
  if (values.help) {
    process.stdout.write('Loopback application example: --port PORT (default9090). GET /ready, GET /, POST /echo (16MiB,4 active), GET /stream (8MiB). Readiness means this example process responds; not database/business readiness or production service acceptance.\n');
    return;
  }
  const server = createExampleServer(), sockets = new Set();
  let stopping = false, timer;
  const stop = () => {
    if (stopping) return; stopping = true;
    server.close(); server.closeIdleConnections();
    timer = setTimeout(() => { for (const socket of sockets) socket.destroy(); }, 2000);
    timer.unref();
  };
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.once('close', () => {
    clearTimeout(timer); process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
  });
  server.on('error', () => {
    process.stdout.write('{"ok":false,"code":"example_listen"}\n'); process.exitCode = 1;
    process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
  });
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  server.listen(Number(values.port), '127.0.0.1', () => {
    process.stdout.write(JSON.stringify({ ok: true, outcome: 'upstream_example_listening', port: Number(values.port) }) + '\n');
  });
}

let entry = false;
try { entry = Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { /* imported module */ }
if (entry) await main();
