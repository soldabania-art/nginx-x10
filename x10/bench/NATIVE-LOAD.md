# Native loopback load client

This optional Linux C fixture moves the HTTP/1 client out of the Node event loop.
It is a measurement tool, not an NGINX data-plane patch, a benchmark acceptance
result, or evidence of a speedup. The earlier Node driver and all adverse raw
results remain unchanged.

```sh
node x10/bench/native-load.mjs --build
x10/.build/native-load/native-load \
  --port 8088 --path /static --duration-ms 1000 --concurrency 16
```

The build wrapper requires Linux, Node 22+ and `cc`. It compiles with C11, `-O2`,
`-Wall -Wextra -Werror`, verifies the source did not change during compilation,
and records the compiler output, exact argv, source hash and regular executable's
SHA-256, size and mode in `x10/.build/native-load/build.json`. The binary is
`x10/.build/native-load/native-load`; neither build product is committed. Consumers
must check these records and actual file identities before and after measuring.
A build record is local consistency evidence, not signed attestation that a
compiler or same-user process cannot be replaced.

## Supported traffic

The destination is fixed to **127.0.0.1**. There is no hostname or external-address
option. The supplied port must be 1–65535; the path is a bounded ASCII request
target without CR/LF, whitespace, quotes or backslashes. No TLS, DNS or proxy
discovery occurs in the client.

The workload is deliberately narrow: HTTP/1.1 GET, one outstanding request on each
connection, status 200, exactly one decimal Content-Length equal to 1024, and a
byte-exact body with byte `i` equal to `33 + (i % 90)`. Headers are bounded to
16 KiB. Duplicate Content-Length, trailing junk in its value, malformed status
or header lines, folded or NUL-containing names, Transfer-Encoding, any
Content-Encoding, missing/wrong length, body mismatch and truncation fail the
run. Chunked responses are **unsupported and rejected**, including TE+CL; a
valid chunked response is not relabeled malformed HTTP.

Nonblocking sockets and `poll` handle partial reads/writes and connection setup.
Responses buffered with POLLHUP are drained before deciding whether their body
is complete. A verified `Connection: close` response reconnects for subsequent
requests; EOF before completion fails. There is no pipelining or automatic
request replay. Unsolicited extra bytes already read after the framed body are
rejected. Late bytes sent after a final completed response cannot be disproved
by a keepalive client that has ended its run; this is not a generic HTTP security
parser or exhaustive fragmentation proof.

Concurrency is 1–128, admission duration 50–10000 ms, absolute per-request timeout
100–5000 ms, and admitted requests at most 1,000,000 (optionally lowered with
`--max-requests`). A request's timeout includes connect, write and body read;
trickle traffic does not extend it. Completion checks the absolute deadline
again. New admission stops at the duration or request cap, then outstanding
requests drain within their existing deadlines. Any failure stops the run and
counts other outstanding requests as aborted. SIGINT/SIGTERM stop admission,
close every owned socket and report failure. SIGPIPE is suppressed.

`success: true` requires at least one completed response, every admitted request
completed, no failure/abort/interruption, valid histogram/counter invariants,
and clean socket closure. It means valid workload execution, not faster NGINX.
The client uses no shared memory, threads, child processes or management APIs.

## Output and interpretation

One JSON document is written to stdout; success exits zero and a traffic failure
exits one. Invalid options exit two before connecting. `--help` prints usage.

- `counters`: admitted/completed/failed/aborted, connections opened and requests
  reusing a verified connection. After cleanup,
  `admitted = completed + failed + aborted`; histogram count equals completed.
- `timing.elapsedMs` covers first admission through drain and socket closure.
  `admissionMs` stops at the requested duration or earlier cap/error/interruption;
  `drainMs` is the remainder. `throughputRps` uses that complete elapsed window.
  Check `requestCapReached`: a capped run is useful for functional verification,
  but does not measure the requested duration and must be rejected by a
  duration-based performance comparison.
- Latency covers admission through the complete, verified response, including
  connection setup where needed. `meanUs` and `maxUs` are measured directly;
  p50/p95/p99 are **upper bounds of nearest-rank logarithmic histogram buckets**,
  not exact quantiles. Buckets have inclusive upper bounds 1, 2, 4, … microseconds.
  The absolute request limit keeps valid responses well within the 32 buckets.
- `resources.userCpuMs/systemCpuMs` are the client's own getrusage deltas after
  allocation/setup through socket cleanup. They do not include Node fixtures,
  compilation, NGINX or a proxy origin. The monotonic elapsed window covers the
  same traffic/cleanup scope, apart from endpoint clock/syscall overhead.
  `maxRssKiB` is Linux getrusage's process-lifetime high-water mark, potentially
  including fork/exec startup accounting; it is not interval RSS growth,
  live-allocation size or NGINX memory usage.

This remains a closed-loop, single-client-process loopback workload. Native
clients remove one known Node bottleneck but do not remove host scheduling,
shared CPU/cache effects, kernel/network constraints or coordinated omission.
Warmup is a separate client invocation; measured runs start new connections.
A fair driver must retain raw A/A and A/B runs, comparable native build profiles,
separate native/client CPU, balanced order and adverse results. No performance
claim follows from functional verification.

## Functional and sanitizer verification

```sh
node x10/bench/native-load.mjs --verify \
  --output x10/.build/native-load-verification.json
```

The short verifier compiles optimized and separate ASan+UBSan clients, serves
bounded synthetic loopback responses, and tests accepted keepalive/concurrency,
fragmented bodies, explicit close/reconnect, status syntax, framing ambiguities,
wrong bytes, oversized headers, truncation, refused connection, trickle/absolute
timeouts, option bounds and real SIGTERM after a received request. It also runs
four and 64 verified responses against native NGINX at concurrency 1 and 16.
Those request caps and short durations are smoke controls, not performance
samples. Node owns only the test servers and lifecycle; measured client logic
runs entirely in the C process.

Sanitizers are address and undefined-behavior checks with halt-on-error; leak
detection is explicitly disabled for this profile. No LSan or full parser-fuzzing
coverage is claimed. A sanitizer diagnostic cannot satisfy a negative protocol
case: every expected rejection must still return the client's valid JSON,
nonzero status, consistent counters and clean closure.

The wrapper handles parent interruption by signaling each owned process group
and escalating to SIGKILL after 750 ms, even if its group leader has exited. It
bounds compiler, client, readiness and fixture-close waits. Native smoke uses
single-process NGINX and requires SIGQUIT exit zero and readable clean critical
logs before removing its temporary prefix. Parent-interruption verification with
a compiler that ignores SIGTERM is recorded independently in the milestone review.

The committed [verification report](../evidence/native-load-verification.json)
records the exact source/client/native identities and executed controls. It is a
point-in-time result and should not be mixed with sustained benchmark datasets.
