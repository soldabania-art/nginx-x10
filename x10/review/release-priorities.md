# Product status and release priorities

Review date: 23 October 2026. Reviewed checkpoint:
`8d769208cf79b8a583077ccb75be30f59e9563a1`.

This is a product and release assessment of repository evidence, not a new
runtime, security or performance test. No code, build profile, deployment or
test assertion was changed for this review.

## Intended product

NGINX X10 should remain a native NGINX-based web server, reverse proxy, load
balancer and TCP/UDP/mail proxy, with familiar configuration and module behavior.
The proposed differentiators are clearer operation, reliable configuration
workflows, native observability and individually demonstrated improvements to
specific workloads. A request must not require the console, Node or an LLM.

The name expresses the owner's ambition. It currently does not describe a
measured tenfold speed improvement or tenfold improvement of every function.

## Delivered and verified boundaries

| Layer | Delivered | What the evidence does not establish |
| --- | --- | --- |
| Native foundation | Full upstream source/history/license preserved; pinned Linux build with 105 compiled modules | Every module, platform and configuration combination runtime-verified |
| Native C changes | Two reproduced QUIC transport-parameter defect classes fixed in three changed lines | Rewritten or improved implementations of all protocols; a general QUIC security proof |
| Local operation | Managed fragment revisions, validation, apply/revert, health checks, durable event intent and bounded recovery | Remote administration, all-traffic atomicity, rollback of application effects or power-loss certification |
| Reload diagnostics | Explicit captured-process listener snapshot/inspection, with real held-stream reload evidence | Complete identification of all old generations, unseen respawns or a native listener-close acknowledgment |
| Compatibility evidence | HTTP/TLS/HTTP2, stream/mail, mail TLS, adapters, selected features and two actual HTTP3 clients | New protocol implementations; complete interoperability or fault matrices |
| Measurement tools | Native C load client, native proxy origin and retained A/A plus A/B reports | Stable performance acceptance, speedup or absence of regression |
| Console/deployment | Earlier Vercel console belongs to the experimental Node project | A publicly running native gateway or a console connected to the native control plane |

The final local [milestone-5 aggregate](../evidence/native-checks-milestone-5.json)
contains 15 successful groups. Controller TAP has 68 passes; the observer has
29. The pinned official sample records 1083 strict passes, 25 skips, one expected
upstream TODO and no strict failures across 35 files. These are different units;
they must not be added together or presented as a number of improved functions.
The independent HEAD and handover records each pass on both the candidate and
pristine binary within their documented scope.

Tests have already found real implementation and fixture defects and support
small future native changes. More tests are useful when they answer a concrete
feature, compatibility or failure question. Test-count growth alone is not a
product milestone.

## Three proposed release stages

These are recommended acceptance stages, not completed releases or delivery
date promises. A stage closes only with linked evidence for its stated gates.

| Stage | User-visible result | Exit evidence |
| --- | --- | --- |
| 1. Usable local alpha | An ordinary Linux operator can build/install, start the explicit native service, bind the controller, inspect state and generations, apply/revert a fragment and recover a documented interruption | Repeatable clean-environment setup and removal; a complete operator workflow; optional native generation identity with successful/rejected reload and respawn cases; current regression gate; every unsupported state shown explicitly |
| 2. Measured service beta | Native engine and its operator controls work together as one usable service; protected administration or a connected console is introduced only after local controls are ready | Authentication/authorization/audit and deployment/update/rollback exercises; declared supported platform/protocol profiles; sustained load and failure evidence; dedicated measurement environment with predeclared workloads, metrics and regression tolerance, valid identical-binary controls and retained raw results |
| 3. Production candidate | A versioned, supportable distribution with explicit compatibility, upgrade and recovery boundaries | Repeatable release artifacts and checksums; dependency/upstream update process; supported build matrix; soak, resource exhaustion and broader interruption checks; operational documentation; release notes distinguishing fixes, opt-in additions, measured benefits and remaining limits |

For stage 2, throughput, p95/p99 latency, request errors, CPU and RSS must be
considered together. Numeric acceptance tolerances should be recorded before a
new comparison, rather than selected after seeing favorable samples. Claims
remain specific to the measured workload and environment. A beta can be useful
without a speed claim; it should not be marketed as performance-accepted until
those measurement gates pass.

These stages do not remove the broader [PLAN](../PLAN.md) matrix. Cache, upstream
selection, DNS, event handling, memory, filters and protocol state work remain
separate implementation tracks. Each needs a concrete problem, preserved
baseline, small change and matching evidence.

## Immediate priority

The next feature should add native visibility useful to an operator, not another
unrelated test collection. The smallest candidate is a master-owned successful
configuration-generation identity, with generation membership in the explicitly
enabled native control API. Its contract must cover both reload paths, rejected
configuration, respawn, process-slot reuse and master/binary replacement.

First establish the existing optional control API's behavior with a private
Unix-socket baseline. Then implement the narrow generation contract, expose it
through useful operator status and verify it against that baseline. A generation
number by itself must not be described as worker listener closure, health or a
complete cutover fence. A worker acknowledgment protocol remains a later,
separately designed contract.

Keep the current default activation semantics unchanged while this contract is
being established. Broader protocol fixtures should be added alongside the
feature they protect, and stable performance measurement should remain a
separate workstream. The inherited F5 publisher CLA integration is an unresolved
repository CI-policy issue, not evidence of a native test failure; release
reporting must continue to separate those outcomes.
