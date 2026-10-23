# Native NGINX comparison

```sh
node x10/bench/compare.mjs > x10/evidence/benchmark-local.json
```

This driver measures the unchanged upstream binary against the native X10
candidate. Node supplies clients and a local upstream fixture; native NGINX serves
the static file and performs reverse proxying. It does not benchmark the earlier
Node gateway. Run it in a quiet window after functional checks, without concurrent
builds, other benchmark drivers or protocol-test jobs.

The default run has two workloads, an exact 1024-byte static file with `sendfile`
and an exact 1024-byte reverse-proxy response. Each workload uses keepalive HTTP/1.1
with concurrency 1 and 16. Each sample has a 250 ms warmup followed by a one-second
admission window. Two repetitions use the balanced order baseline/candidate,
candidate/baseline for every workload/concurrency pair: 16 measured samples total.
Only one native NGINX process runs at a time. Every response must have status 200,
the expected Content-Length and byte-identical content. A failed request makes the
run fail.

`success: true` means that the measurement completed with valid identities,
responses, counters and cleanup. It does not mean that the candidate is faster or
that a performance regression has been ruled out; this driver has no acceptance
threshold.

Defaults are `x10/.build/baseline/nginx` and `x10/.build/objs/nginx`, checked against
`x10/evidence/build-reference.json` and `x10/evidence/build-fixed.json`. The baseline
manifest records the original build location before its binary was archived; the
driver uses the explicit archived binary path and verifies its content hash.
Both manifests must identify a successful build. Their binary SHA-256 and actual
`nginx -V` outputs must agree. The versions, compiler, compiler flags, TLS
information, configure flags, dependency header versions, generated module list
and pinned upstream revision must agree between builds. Only configure
`--builddir` and `--prefix` path differences are ignored. The baseline manifest
must record unchanged upstream sources. Manifests are recorded build attestations,
not independently reconstructed or signed proof of compiler inputs.

Binaries are hashed again before and after each sample, and both binaries and
manifest bytes are checked at the end. An identity change, incompatible profile,
request failure, resource-counter error or cleanup failure produces a nonzero exit
code and a JSON report with `success: false`. A failed report must not be presented
as a valid performance comparison. SIGINT/SIGTERM stop admission, abort in-flight
client requests and enter the same bounded cleanup path; interrupted runs fail.

The driver creates a private temporary prefix, uses ephemeral loopback ports and
removes its prefix after stopping NGINX. It does not install, start a global
service, change system settings or access public endpoints. `master_process off`
avoids sandbox worker privilege constraints. When the invoking UID is root, its
mapped username is set for configuration validation; this local fixture is not a
production configuration or deployment recommendation.

```sh
node x10/bench/compare.mjs \
  --baseline /path/to/baseline/nginx --candidate /path/to/candidate/nginx \
  --baseline-manifest /path/to/baseline-build.json \
  --candidate-manifest /path/to/candidate-build.json \
  --duration-ms 2000 --warmup-ms 500 --repetitions 4 --concurrency 1,16
```

`--help` lists all options. Duration accepts 100–10000 ms, warmup 50–5000 ms,
repetitions an even integer 2–10, and concurrency one to four unique integers
1–128. Requested measured plus warmup time is capped at 180 seconds. These bounds
exclude bounded startup, request drain and shutdown time. The driver requires Linux,
Node.js 22 or later (verified here with 24.19.0), `getconf`, readable Linux `/proc`, the two
native binaries and their manifests; no npm dependency is used.

## Reading the output

- `runs` retains admission/drain duration, successful and failed requests,
  successful requests per second, keepalive reuse, latency p50/p95/p99/max and
  resource counters for every raw sample. Throughput includes the time needed to
  drain all requests admitted before the deadline. Latency is measured from client
  request creation to the complete verified response. Quantiles use nearest rank
  within each sample; summary throughput means do not pool latency distributions.
- Native user/system CPU comes from Linux `/proc/PID/stat` ticks for the single
  NGINX process, read after warmup and after drain. `CLK_TCK` records its discrete
  resolution. RSS is sampled every 25 ms and at both endpoints; `sampledMax` is not
  a true peak or an allocation count. In sandboxes with a host-view `/proc`, the
  direct child is resolved using PPid plus NSpid. Its starttime is checked to
  reject PID reuse. No unrelated process counters are used.
- `nodeDriverAndUpstream` is this Node process's self CPU delta. It includes the
  clients, HTTP fixture and sampling logic, and is distinct from native CPU. Host
  load, CPU availability and run order are recorded. Setup, configuration tests,
  startup, warmup and cleanup are outside the measured traffic interval.
- `summary` gives each binary's sample rates and their arithmetic mean ratio.
  This is an observation from the recorded samples, not a significance test or
  regression threshold. The raw runs must be examined before drawing conclusions.

These short, closed-loop, hot-cache loopback workloads can be limited by the Node
event loop, which also serves the proxy upstream. They do not measure production
multiworker scaling, network capacity, cold storage, TLS, HTTP/2/3, QUIC, mail or
failure recovery. Other host workloads and scheduler noise remain uncontrolled.
The QUIC parser patch is not exercised by these HTTP/1 tests, so a ratio is not
evidence that the patch accelerates HTTP. No 10× claim follows from this driver.

`benchmark-smoke.json`, when present, records a 100 ms/concurrency-1 functional
check of the driver, not a useful performance estimate. The final
`benchmark-local.json` records its own exact options, identities and environment.

## Recorded local comparison, 23 October 2026

The [recorded default run](../evidence/benchmark-local.json) completed 16 samples
and 102783 verified measured responses with zero request errors. All native
processes stopped with SIGQUIT and exit 0; binary/manifest identities remained
unchanged. The upstream fixture received exactly the expected 56578 proxy
requests, including warmup.

| Workload | Concurrency | Baseline mean requests/s | Candidate mean requests/s | Candidate/baseline |
| --- | --- | --- | --- | --- |
| Static 1 KiB | 1 | 6982.4 | 6907.1 | 0.989 |
| Static 1 KiB | 16 | 9555.2 | 4628.5 | 0.484 |
| Proxy 1 KiB | 1 | 2691.1 | 2952.4 | 1.097 |
| Proxy 1 KiB | 16 | 9174.9 | 8460.5 | 0.922 |

The unfavorable static/concurrency-16 observation is retained. Baseline sample
rates were 7293–11817 requests/s and candidate rates 3776–5481 requests/s. These
two short samples per binary do not establish the cause of the difference or a
general speedup/regression. The additional controls below investigate that
uncertainty. No later result replaces this original observation.

Across all samples, native CPU counters totalled 1660 ms baseline and 1780 ms
candidate, while Node client/upstream CPU totalled 7576 ms and 6923 ms. Native
sampled maximum RSS was 5840896 and 5718016 bytes respectively. These totals mix
the two workloads and concurrency levels and must not be treated as a common
per-request efficiency comparison. The native counters have 10 ms tick
resolution; RSS sampling is not a true peak. The Node process is substantial
workload overhead. The corrected QUIC path is outside these HTTP/1 workloads.

[Driver acceptance](../evidence/benchmark-verification.json) separately records
the short positive smoke, rejection of mismatched compiler profiles, graceful
cleanup after SIGTERM during an active native sample, and invalidation after a
temporary manifest changed during a run. Those are driver-correctness checks,
not additional performance samples.

### Follow-up controls

The [identical-binary control](../evidence/benchmark-identical-control.json) uses
the very same unchanged baseline binary and build manifest for both labels;
their SHA-256 values agree. It uses concurrency 16, two balanced repetitions and
one-second samples. The [longer A/B run](../evidence/benchmark-confirmation.json)
uses the original baseline and patched candidate with concurrency 16, four
balanced repetitions and two-second samples. Both retain raw runs and completed
without request, identity or cleanup errors. They are separate files; the first
result's bytes remain unchanged.

| Control | Workload | Label baseline mean requests/s | Label candidate mean requests/s | Label ratio |
| --- | --- | --- | --- | --- |
| A/A: identical baseline binary | Static 1 KiB | 12240.8 | 8377.4 | 0.684 |
| A/A: identical baseline binary | Proxy 1 KiB | 6676.3 | 10833.6 | 1.623 |
| Longer A/B, four samples per binary | Static 1 KiB | 5595.2 | 4622.4 | 0.826 |
| Longer A/B, four samples per binary | Proxy 1 KiB | 7347.4 | 5907.0 | 0.804 |

These controls demonstrate substantial measurement instability. In the longer
run the unchanged baseline itself ranged from 811.8 to 12607.2 static requests/s,
and its static p99 reached 403 ms. That does not establish why it happened or
exclude a real regression in the patched binary. A stable separate load
generator and controlled execution environment are still required before
accepting a performance claim. Neither a speedup nor absence of regression is
established by these results.

The [observer record](../evidence/benchmark-observer.json) stores visible cgroup
and load counters before and after each follow-up command, its exact argv and
elapsed time. The visible CPU quota was `800000 100000` (eight CPU equivalents).
The A/A command had no new throttle events; the longer A/B command had two,
totalling 43.258 ms of recorded throttled time. CPU pressure was unavailable.
These boundary counters cover the observer's visible cgroup, not individual
samples or a single binary. They do not explain the full variability.
