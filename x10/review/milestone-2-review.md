# Milestone 2 — independent review

Review date: 23 October 2026. Working base: c9ed4985f370d0fa444cad974000cadbb9ed7703; pinned native upstream remains 148c75678cd4171338c31d4ed4c02411736d5fe9.

## Scope and method

Read the new native controller and CLI, its real-process fixture, feature fixture, generated QUIC C harness and runner, benchmark driver, pinned official-test runner/selection, unified checker and CI workflow. Follow-up edits addressing findings were reread. Native source still differs from the upstream pin only by the earlier three-line QUIC transport-parameter fix; this milestone does not replace the C data plane.

The reviewer independently reproduced the quoted-directive containment failure using initialize plus native configuration validation in a private temporary prefix; no server was started. After the fix, quoted listen, quoted include and an escaped directive name were independently rejected. A local read also confirmed the host-view /proc versus namespace-PID mismatch. Other complete suite runs and their negative controls were performed by their owners and the root integrator; this review inspected their code and saved results rather than claiming a second independent execution of every suite.

## Findings resolved before the checkpoint

| Area | Finding | Resolution and evidence |
| --- | --- | --- |
| Generated QUIC oracle | A seeded opaque value could have length 64 while its length field used one byte, whose payload capacity is 63. That was an invalid generated input with a false success expectation, not a new NGINX defect. | Promote that length field to two bytes; reject all out-of-range encoder width/value pairs. The default and extended sanitized runs pass with the corrected harness. |
| Controller conflict handling | A conflict detected after candidate validation could enter rollback without another guard, overwriting a manual fragment or signalling a changed operator configuration. | Guards now run before rollback writes, after native validation and after acknowledgement. A gated real-health fixture edits both operator config and fragment during acknowledgement: bytes remain untouched, state becomes pending/ambiguous, and explicit reconciliation/recovery restores the last confirmed content. |
| Controller containment | Native NGINX accepts quoted directive names. Replacing quoted tokens with a placeholder let quoted listen/include bypass the fragment boundary. | Directive names must be plain and unescaped; normal argument quoting remains supported. Independent before/after reproduction and fixture negative cases close this finding. This was a controller boundary defect, not an upstream parser vulnerability. |
| Health-policy inheritance | An inherited proxy cache could return old healthy content; inherited proxy_method POST could change the health request verb. Idle timeouts alone did not bound a trickling response. | The owned location forces bodyless GET, disables inherited cache/store, buffering and ignored aborts, suppresses client headers, and uses fresh revision IDs plus absolute and idle 350 ms deadlines and a 64 KiB cap. Real fixtures cover inherited URI-keyed caching, POST policy and a trickling origin. |
| Benchmark lifecycle and identity | Direct cancellation could orphan the native child; initial hashes alone did not detect changes during measurement. A namespace PID could point at an unrelated process in host-view /proc. | Signal handling enters bounded cleanup, hashes are checked per sample and at completion, and counters identify the direct child by PPid/NSpid with start-time checks. Negative controls reject an incompatible profile and changed manifest and confirm SIGTERM cleanup. |
| Official-test cleanup | Runner cancellation needed to clean its isolated test sessions. Waiting only for the Perl leader after SIGKILL did not prove native descendants had exited. | Signal-aware cleanup waits boundedly for the owned process group to disappear. The retained negative control reports a forced timeout as failure, an interrupted nonzero runner, zero live captured native processes and zero remaining temporary roots. |
| Unified result validation | An output-write exception after success assignment could leave success true in the error JSON. Result identities also needed cross-checks. | Catch always clears success; source, generated-header and reported binary identities are cross-checked. Empty or unpinned official selections are not accepted as compatibility success. The final checker verification has four passing CLI controls, including an output-write failure that returns nonzero JSON with success false; its checker hash matches the frozen reviewed file. |

## Inspected execution results

The [unified candidate evidence](../evidence/native-checks-fixed.json) reports seven successful suites with unchanged source/build identity: HTTP/TLS/HTTP2/reload, stream/mail, native features, the original QUIC regression, generated sanitized properties, native control and the pinned official sample.

Keep their units separate:

- The added feature fixture has 19 behavioural cases on both binaries. It checks exact bodies and status/headers, real limits and cache receipts. The cache-lock case waits for all client writes and native stub_status arrival; turning cache locking off produces the expected failure rather than a false pass.
- The native controller has 16 behavioural subtests; Node TAP also counts its containing parent node. It uses a real master/workers, including rejection, health rollback, conflict refusal, immutable-history checks and a killed CLI followed by explicit recovery.
- Six generated QUIC properties pass 8,923 default cases and 18,667 extended cases under ASan/UBSan. These are related generated inputs, not that many independent protocol features. The unchanged reference produces 940 expected mismatches in the existing defect classes. LeakSanitizer is explicitly disabled after its recorded environment failure; leak checking remains unverified.
- The pinned official sample runs 35 files on both binaries: 32 pass, three whole files skip, 1,083 strict TAP assertions pass, 25 assertions skip, one expected upstream TODO fails, and no strict assertion fails. Missing FCGI, SCGI and the uwsgi daemon account for the whole-file skips. Master semantics are retained for the HTTP/2 reload test; unsafe tests stay disabled.
- Local syntax checks and pinned CI configuration are not proof of a hosted GitHub Actions execution.

## Performance acceptance remains open

The [local benchmark](../evidence/benchmark-local.json) completes 16 balanced samples, verifies every 1 KiB response, records zero failed requests, has graceful cleanup and stable binary/manifest identities. The candidate-to-reference mean throughput ratios are:

| Workload | Concurrency | Observed ratio |
| --- | ---: | ---: |
| Static | 1 | 0.989 |
| Static | 16 | 0.484 |
| Proxy | 1 | 1.097 |
| Proxy | 16 | 0.922 |

The adverse static/concurrency-16 result is retained, not discarded or described as no regression. Its original bytes remain unchanged at SHA-256 33833892362c4d87079a4ed43581a9e5695ab61c8f18d4da61798887489dd723.

The subsequent [A/A control](../evidence/benchmark-identical-control.json) uses the identical unchanged baseline binary and manifest for both labels: both binary hashes are adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e. It retains concurrency 16, two balanced one-second samples per label. The separate [longer A/B confirmation](../evidence/benchmark-confirmation.json) uses the actual baseline and patched candidate at concurrency 16, four balanced two-second samples per binary. The driver code was unchanged. Both commands completed with zero request errors, stable identities and no cleanup failures.

| Follow-up | Static ratio | Proxy ratio |
| --- | ---: | ---: |
| A/A: the same baseline bytes under two labels | 0.684 | 1.623 |
| Longer A/B: original baseline versus patched candidate | 0.826 | 0.804 |

The identical-binary control demonstrates substantial measurement instability. In the longer run, the unchanged baseline's static samples alone ranged from about 812 to 12,607 requests/s, a 15.5-fold spread, with static p99 reaching about 403 ms. These observations do not establish the cause of the original unfavorable result or exclude a real regression in the patched binary. The ratios remain recorded outcomes, not accepted causal measurements of the C change.

The [observer record](../evidence/benchmark-observer.json) covers the visible cgroup and load counters at each follow-up command's boundaries, rather than individual samples or one native binary. The visible quota was eight CPU equivalents; A/A had no new throttle event, while the longer A/B command had two totaling 43.258 ms of recorded throttled time. CPU pressure was unavailable. These limited counters do not explain or rule out causes of the full variability.

The shared Node client/origin event loop and uncontrolled host scheduling limit interpretation. The QUIC fix is not exercised by these HTTP/1 workloads. Neither a speedup nor the absence of regression is established. **Performance acceptance remains OPEN**, with no production approval and no demonstrated 10x improvement. A stable independent load generator/host, additional reproducible workloads and profiling remain necessary before accepting throughput or latency claims.

## Operational limits retained

The controller is a local Linux tool for one explicitly managed loopback HTTP server, under the same trusted UID and PID namespace; it is not a remote administration API or a general configuration editor. Revision probes establish a sampled generation, not an atomic cutover of every connection. The candidate is reloaded before the health gate, so it can serve traffic while being checked. Native handover can temporarily leave old listeners active; rollback does not undo requests or application side effects.

Native configuration testing/reload can have earlier filesystem, shared-zone or listener effects. External includes and application/credential state are outside the main-file/fragment hash guard. A history-append/state-write crash window can require manual inspection; stale locks are never automatically removed. Node uses no pidfd here, leaving a documented identity-check-to-signal race. These boundaries preclude a general ACID, power-loss, all-worker or hostile-same-UID security guarantee.

HTTP/3 end-to-end, the complete official suite, all optional dependencies, 32-bit/platform/TLS matrices, full fuzzing, remote TLS/RBAC management and a public native deployment remain separate work. Source-reading coverage is not a proof of complete runtime compatibility or absence of defects.

## Review conclusion

No unresolved code blocker was found for this constrained development checkpoint after the above fixes. Performance acceptance and the listed compatibility/operational work remain open. This is not approval for a production release, an assertion that every NGINX capability has been improved, or a superiority claim.

## Reviewed code identities

The following hashes identify the reviewed files, independently of the native binary manifests. Documentation-only edits outside this table do not change the code review identity.

| File | SHA-256 |
| --- | --- |
| x10/control/cli.mjs | 2fe6db9e6dab452ce0099b481ca6cafb70a7e18cb90518b9c89eb6fabb96f534 |
| x10/control/manager.mjs | 38794fa7e046fdf3d30f963d852810902179c6ce09fedc289611c234e9ff2e6e |
| x10/test/control.test.mjs | 73cb0f1b1168137593207a18f249364832f146a0c2490d6efcf65fb94234527f |
| x10/test/features-baseline.mjs | c3f13ad98aabf2cbf2517cc3737203361e32f500c9718ad3d416bbd57d26e6f9 |
| x10/test/quic-generated.c | 877a3b230ca886ef5cadb86d41350557e28d507e7a105ec5ae149fb5c5bd5ac5 |
| x10/test/quic-generated.sh | 9f2fee4861ee658ccc3c2d40dcb8fafcab73659326c793f69b236e21e915d062 |
| x10/bench/compare.mjs | 3196eeaf1fc9ff07adff2a0b442a10bb7e12fa61129d094da681b44de64190b3 |
| x10/test/official-tests.sh | 07b58f0708f359745d61db3fa9f7516c8aaf89085e0bce6db9a399190cd55ce5 |
| x10/test/official-tests.json | c17e51f3767696fae639bdb0e9e82e77d660d4ad9573f4e4b96f4b616a23e07e |
| x10/test/all.mjs | b34518b71b3156c27590d2c16c3e6b0e37233547095227d572e62a724552e276 |
| .github/workflows/x10-native.yml | 09436b66594b57e964bce35a3430369b97dcf46cc070856e22114930fc008b01 |
