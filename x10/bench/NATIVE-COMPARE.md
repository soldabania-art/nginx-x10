# Native client and native origin comparison

This driver compares the pinned native baseline and X10 binaries using the
[C HTTP/1 client](NATIVE-LOAD.md). Proxy responses come from a separate pristine
native NGINX static origin. Node orchestrates startup, warmup and resource
sampling; it is outside the measured request/response path. The earlier
[Node comparison](README.md) and all its unfavorable results remain unchanged.

```sh
node x10/bench/native-load.mjs --build
node x10/bench/compare-native.mjs > x10/.build/native-comparison.json

# Identical-binary control, both labels refer to exactly the same baseline:
node x10/bench/compare-native.mjs \
  --candidate x10/.build/baseline/nginx \
  --candidate-manifest x10/evidence/build-reference.json \
  --duration-ms 1000 --warmup-ms 250 --repetitions 4 --concurrency 16
```

Run after functional checks, without other project fixtures, builds or load
jobs. The host is not reserved or isolated; a quiet project window does not
control other tenants, kernel scheduling or available CPU. The fixed destination
is loopback, all prefixes are temporary, and the driver installs no service.
The native binaries and archived baseline must already exist.

## Required identities and bounds

The default baseline is `.build/baseline/nginx`, identified by
`evidence/build-reference.json`; the default candidate is `.build/objs/nginx`,
identified by the current `.build/manifest.json` (paths relative to `x10`).
Actual SHA-256, `-V`, compiler/options/dependencies/modules/upstream pin must
match the two recorded builds. Only configure builddir/prefix paths are
normalized; the baseline manifest must record unchanged upstream sources.

The optimized client at `x10/.build/native-load/native-load` needs its matching
`build.json`, source hash and binary hash. `--client`/`--client-manifest` allow an
explicit alternative matching local build record. Client and driver sources,
manifest bytes and all native binary identities are checked before/after.
These are consistency checks on local records, not signed attestations or
independently reproduced compiler inputs.

Duration is 100–10000 ms, warmup 50–5000 ms, repetitions an even 2–10 and
concurrency one to four distinct values from 1–128. Requested admission/warmup
budget is capped at 180 seconds, excluding bounded startup/drain/cleanup.
Clients use a 2-second absolute request deadline. Reaching their request cap
invalidates a timed measurement. SIGINT/SIGTERM stop the client and trigger
bounded cleanup of the client, front and origin. Client output has a size and
runtime limit; failure retains the parsed result or bounded raw diagnostics.

## Workload and counting

One `master_process off` front runs at a time, alongside one fixed pristine
native origin. Static uses sendfile; proxy uses HTTP/1.1 and an upstream
keepalive pool. Both return the exact known 1024-byte pattern. Every accepted
client completion must have HTTP/1.1 status 200, one Content-Length of 1024 and
exact bytes. Chunked/encoded responses are deliberately unsupported and fail
closed. This client is not a generic HTTP conformance implementation.

Each sample uses a separate warmup client, then a fresh measured C process.
Warmup primes native file/cache/pool state; client connections are newly opened
for measurement. The denominator includes connection setup and draining all
requests admitted before cutoff. For each workload/concurrency pair, AB/BA
ordering gives each label equal first/second positions. Raw samples are kept;
summary ratios use arithmetic means and do not pool latency distributions.

The JSON must account for every admitted/completed/failed/aborted request and
every latency histogram entry. `success:true` indicates valid measurement
execution, identity and cleanup, **not** speed improvement or regression
acceptance. No confidence interval or performance threshold is implemented.

| Resource | Meaning and limitation |
| --- | --- |
| Front and origin CPU | Separate Linux `/proc` user/system ticks. Direct children resolved through PPid/NSpid; start ticks checked. Snapshot window includes C-client process creation/exit around traffic. |
| Native RSS | Samples every 25 ms and endpoints; sampled maximum, not an allocation count or true peak. |
| C-client CPU / max RSS | Client self CPU during its defined load/cleanup window; RSS is process-lifetime high water. |
| Node CPU | Orchestration and sampling only, separate from all three native processes. |
| Latency | Full verified response durations. p50/p95/p99 are log2-microsecond histogram **upper bounds**, not exact quantiles. |
| Host/cgroup context | Load average, CPU availability and visible cgroup mount-root snapshots. Boundary context cannot attribute host variation to a particular binary. |

These closed-loop, hot-cache, one-host, single-front workloads do not measure
multiworker scaling, cold storage, TLS/HTTP2/HTTP3, mail or open-loop overload.
The client and origin can still limit the front. Removing the Node traffic loop
does not by itself establish stable measurements. The QUIC parameter patch is
outside these HTTP/1 paths; a ratio cannot establish that it speeds up HTTP/1.

## Driver verification

[Acceptance controls](../evidence/native-comparison-verification.json) separate
an eight-sample 100 ms functional smoke from performance measurements. A changed
compiler profile is rejected before traffic; a manifest change invalidates the
comparison; SIGTERM with the C client, front and origin observed alive leaves
all three stopped. Full failed reports remain alongside the controls. See
[STATUS.md](../STATUS.md) for the subsequent quiet-window observations and their
limits.

## Recorded quiet-window observations

Both final-driver runs used concurrency 16, four samples per label/workload,
1000 ms admission and 250 ms warmup, after all project fixtures stopped.
Each retained 16 successful samples, zero request errors and clean native exits.

| Report | Static mean-throughput ratio | Proxy mean-throughput ratio |
| --- | --- | --- |
| [Identical pristine binary](../evidence/native-benchmark-identical-control.json) | 0.996 | 1.111 |
| [Candidate / pristine](../evidence/native-benchmark-comparison.json) | 1.068 | 1.028 |

The identical-binary spread remains material. These short shared-host
observations establish neither speed improvement nor absence of regression.
They do not explain or supersede the earlier unfavorable Node measurements.
