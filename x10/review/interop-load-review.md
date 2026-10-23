# HTTP/3 and native load-client review

Review date: 23 October 2026. Starting development commit:
`43618ecca59fe802620f810a13f083554952bd7d`.

No unresolved blocker was found in the scoped HTTP/3 fixture, native load client
or comparison driver at the hashes below. Independently executed controls passed
and are recorded in [interop-load-review-controls.json](../evidence/interop-load-review-controls.json).
The aggregate CLI and quiet A/A and A/B measurements remain separate integration
gates owned by the root agent. This review does not certify a production release,
complete QUIC security or a performance advantage.

## Boundary

Implementation owners control the HTTP/3 fixture and the C HTTP/1 load client.
The reviewer owns only this report and a separate review-control JSON. No
production C, implementation or aggregate-runner file is edited by this review.
Sustained benchmarks are reserved for the root agent's quiet measurement window.
All reviewer-owned short fixtures and processes were stopped before handoff.

## Native contracts and acceptance

- `src/event/quic/ngx_event_quic_ssl.c` requires negotiated ALPN during QUIC
  handshake. `src/http/v3/ngx_http_v3_request.c` initializes actual request
  streams; `src/http/v3/ngx_http_v3_module.c` supplies the native `$http3`
  variable. A completed HTTP/2 or TCP exchange cannot stand in for this path.
- H3 positives must use normal CA and hostname verification, actual QUIC/H3
  negotiation and byte-exact responses. Certificate negatives require a
  certificate-specific failure, rather than an arbitrary timeout or socket
  error. Dependency identity and transport/process cleanup must be recorded.
- The load client is intentionally a loopback HTTP/1 fixture client with one
  outstanding request per connection. Unsupported transfer encoding or
  content encoding must fail explicitly. Framing, binary bytes, partial I/O,
  absolute deadlines and all admitted-request outcomes must be checked.
- Latency histograms may provide documented approximate bucket bounds. They
  must not be labeled exact per-request quantiles. A valid measurement run
  does not establish speedup or exclude regression.

The old Node benchmark's unfavorable results and identical-binary controls remain
unaltered historical observations. The new driver uses a pristine native origin
and a separate C client, with Node limited to orchestration. This removes those
Node hot paths but cannot by itself control scheduler noise, host contention or
network representativeness.

## Resolved review findings

1. The draft C fixture accepted `HTTP/1.1 200` without the required space after
   the status code. A reviewer-executed request demonstrated this at source hash
   `49c24f7e046e912d20cd911ab4516b2a65248735edbcfee28ae4e142b83e6201`.
   The owner now requires that space while accepting an empty reason phrase
   when the space exists. Both outcomes were independently retested against the
   final source. This was a fixture-parser issue, not a native NGINX finding.
   A separate draft NUL-name control already rejected its input; the owner had
   fixed that case independently before the reviewed snapshot.
2. Parent interruption of the load-client wrapper initially had no bounded
   escalation for an owned detached compiler that ignored TERM. The owner added
   TERM followed by KILL and group cleanup even after the group leader exits.
   A reviewer-controlled compiler shim ignored TERM; the final wrapper reported
   failure and its compiler group was gone after approximately 761 ms.
3. HTTP/3 cleanup now waits for the UDP transports' `connection_lost` callbacks,
   rather than treating a requested close as completed cleanup. Concurrent-stream
   evidence records six actual unique backend targets before barrier release.
   Cancellation evidence holds an unrelated response in flight, observes the
   cancelled stream's upstream close, then completes the survivor and a fresh
   request on the same QUIC connection. The owner additionally checked that the
   cancelled request was still pending and raised the native read timeout above
   the case deadline so a read timeout cannot masquerade as cancellation.
4. Integration originally checked a top-level H3 client-identity flag and a
   boolean load-client interruption flag that did not match the producers.
   Checks now use `identity.clientUnchangedDuringTest` and exact numeric zero for
   the C client's interruption flag. The comparison driver also checks finite
   nonnegative resources, timing consistency, admitted-request accounting,
   histogram population and throughput/count/time agreement.

These fixes were made by the implementation owners. The reviewer did not edit
their implementation files.

## HTTP/3 conclusions and limits

The reviewed fixture performs real UDP QUIC with TLS certificate-chain and
hostname verification. It requires negotiated ALPN `h3`, native `$http3=h3` and
native `$server_protocol=HTTP/3.0`; TCP or HTTP/2 fallback cannot pass. The owner
reports seven passing cases on both the candidate and pristine binary: a
65,806-byte exact binary GET, exact range GET, fragmented POST with exact backend
receipt, six concurrent streams, observed cancellation with a surviving stream,
unrelated CA rejection and hostname rejection. Certificate negatives require
the TLS certificate-alert code and certificate-specific reason with no completed
handshake; arbitrary connection failures cannot satisfy them.

The inspected final reports record seven created and seven closed UDP clients,
native exit zero, no open sockets, removed temporary roots and no cleanup errors.
The reviewer independently exercised launcher rejection of an unusable interpreter
and SIGTERM cleanup after native startup, including a run with one UDP client
actually created and its close callback observed. Those are separate controls,
not a claim that the reviewer reran the owner's complete seven-case suites.

The client is pinned to aioquic 1.3.0 and a ten-package hashed wheel lock. The
reviewer matched downloaded wheel hashes to both the install report and lock,
matched installed versions to the report and ran `pip check` successfully. The
fixture checks six actual aioquic source-file hashes before and after testing,
as well as the lock digest. This provides local repeatability and identity
checks, not an audit of every dependency's internals. The supplied wheel profile
is CPython 3.12 on Linux x86_64.

HEAD remains explicitly outside the passing scope. The preserved
[HEAD diagnostic](../evidence/http3-client-head-diagnostic.json) records the same
aioquic `H3_MESSAGE_ERROR` 270 rejection on both native binaries. Inspection of
the pinned client's `H3Connection._check_content_length` found an unconditional
comparison between expected content length and received body length. The final
suite uses a range GET, preserves that diagnostic separately and does not bypass
the client parser or label the HEAD result a native defect. Wire correctness for
HEAD is not established by this review.

## Load-client and comparison conclusions

The C client deliberately supports only loopback HTTP/1.1 status 200, a single
Content-Length of 1024, and the exact fixture pattern `33 + i % 90`. It rejects
transfer encoding, content encoding, oversized headers, malformed framing,
truncation, surplus bytes and mismatched bodies. Nonblocking connect/write/read
handle partial I/O, one outstanding request per connection and bounded resources.
The request deadline is absolute across connect, writes, reads and completion;
slow progress does not reset it. Stop-admission and bounded drain preserve the
accounting identity admitted = completed + failed + aborted.

Limits are concurrency 1–128, duration 50–10,000 ms, request timeout 100–5,000 ms
and request cap 1–1,000,000. The measured path has no JavaScript per request.
Latency percentiles are explicitly nearest-rank logarithmic histogram upper
bounds, accompanied by the raw histogram, count, mean and maximum. They are not
exact per-request quantiles. Throughput includes connection setup and drain.
Client CPU deltas and process-lifetime maximum RSS are reported separately.

The new comparison driver uses one native front and a fixed pristine native
origin, separate warmup and measured C-client processes, balanced A/B then B/A
order and exact response verification. It verifies binary/build/source identities,
retains unsuccessful runs and separates front/origin CPU ticks, sampled RSS,
client resources and Node orchestration CPU. The optional visible-cgroup boundary
snapshots explicitly do not attribute cgroup activity to a process. Source identity
is checked again at finish and native configurations are retained in the report.

This remains a short, closed-loop, single-process loopback profile sharing one
host. Scheduler ticks are coarse; RSS sampling can miss peaks; warmup connections
are not reused by measurement. It does not measure production multiworker scaling,
remote networking, TLS, HTTP/2, HTTP/3, QUIC, mail or disk-cold behavior. These
HTTP/1 workloads do not exercise the candidate QUIC parser fix. No observed ratio
can attribute a speed change to that fix or establish a tenfold improvement.

## Evidence provenance

The following controls were executed by the reviewer and retained in the review
JSON. Expected error cases must fail their tested operation to pass the control.

| Reviewer execution | Result | Boundary |
| --- | --- | --- |
| Final C parser CLI controls | 5/5 | Missing status space, valid empty reason, NUL header name, case-insensitive close token list/reconnect, comma Content-Length |
| Wrapper parent SIGTERM with TERM-ignoring compiler | 1/1 | Final wrapper, nonzero failure, owned compiler group gone |
| H3 launcher CLI controls | 2/2 | Unusable interpreter and interruption after an observed native PID |
| H3 interruption with created UDP client | 1/1 | One transport created and one close callback, no leaked fixture |
| Aggregate `jsonChecks` direct controls | 32/32 | Two accepted owner records and 30 mutated records rejected; direct function calls, not aggregate CLI |
| Comparison `runLoad` synthetic controls | 15/15 | One accepted and 14 rejected process-output records through the exact extracted final function; no real subprocess or traffic |
| Dependency inspection | Pass | Ten wheel hashes, installed versions, lock and successful `pip check` |

Owner-executed evidence was inspected separately:

- [http3-fixed.json](../evidence/http3-fixed.json) and
  [http3-reference.json](../evidence/http3-reference.json): 7/7 each, exact final
  fixture/client identity, no skips, native/UDP cleanup recorded.
- [native-load-verification.json](../evidence/native-load-verification.json):
  41/41 short functional, negative, native C1/C16 and ASan/UBSan controls; final
  C/wrapper source identity and no cleanup errors. LeakSanitizer is disabled in
  this environment; this is not an LSan claim.
- [native-comparison-verification.json](../evidence/native-comparison-verification.json):
  4/4 root-executed controls, covering an eight-sample short smoke, profile mismatch
  before traffic, manifest-change invalidation and live-client/front/origin
  SIGTERM cleanup with exit 143 and no leaks. These runtime controls preceded the
  final driver's reporting/identity metadata additions. The reviewer inspected
  those additions and reran the 15 synthetic acceptance controls on the final
  driver; a final full driver CLI run was not independently repeated.

Process-termination controls do not establish power-loss durability or safety
against a hostile same-user process. No sustained measurement or aggregate CLI
was executed by this reviewer.

## Frozen reviewed identities

SHA-256 values refer to the actual final bytes read at handoff.

| File | SHA-256 |
| --- | --- |
| `x10/test/http3-baseline.py` | `2b657e7719bbe68bf294133bf7808d4db39a61b35fb8890a82d2641db9b68655` |
| `x10/test/http3-baseline.mjs` | `bace6eeeb55af6bd412b33d3c5c33902916a48a97af28299e173cf57362b9170` |
| `x10/test/http3-baseline.requirements.txt` | `0577820a7995777c8e0e0723a5c9637be1b2fe9978882d457d6df22a7c47faa1` |
| `x10/bench/native-load.c` | `ea0c28a2a4ec24d67978b442993ca86c86f14a823a6a24e1b7116807f0795828` |
| `x10/bench/native-load.mjs` | `bb3befd34886d278052f209a87220a6ee9b819833c4d1a1fe93ef50663716a71` |
| `x10/bench/compare-native.mjs` | `243a6152f6bd5d25be2180825833cd7e47b943a417c550f27fccf510000b39a2` |
| `x10/test/all.mjs` | `21650f334056618fca4fe770982006c01dca69518286261da419ceb72d70a377` |
| `x10/evidence/interop-load-review-controls.json` | `d1c45088bcefe0276b57a09b42fb06af66061a60961b79f035d93e271e7c8fd5` |

The candidate native binary recorded by H3 evidence is
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`;
the pristine binary is
`adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e`.
Changing reviewed code invalidates the corresponding frozen-source conclusion
until the affected review or controls are refreshed.
