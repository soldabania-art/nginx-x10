# C2a: hosted evidence and patch-format policy

Implementation: `99a017e64b33eda537ea0fc19db623984fa2dd9e`.
Date: 2026-10-23. Scope remains read-only observation; full inventory,
semantic export/import, actual TLS-code replacement and NGINX migration
are unimplemented. Local evidence: [continuum-c2a.json](../evidence/continuum-c2a.json).

## Exact hosted research acceptance

| Event | Run | Research job | Result |
| --- | --- | --- | --- |
| Push | [39994034417](https://github.com/soldabania-art/nginx-x10/actions/runs/39994034417) | 120552885020 | completed success |
| Pull request | [39994040940](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040940) | 120552928281 | completed success |

Both decoded logs independently confirm 21/21 core, 7/7 process, 22/22 C1
and 8/8 C2a, zero failures/cancellations/skips/TODO. The C2a aggregate is
`continuum-pinned-openssl-state-probe`, exit0. Native binaries are not linked
to this isolated probe. Runtime strings do not expand the pinned profile.

Native implementation99a017e [push39994034390](https://github.com/soldabania-art/nginx-x10/actions/runs/39994034390)
and [PR39994040738](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040738)
also completed success; jobs120552916731 /120552906412. Both full workflows
include official aggregate, Guard, required Unix transports/generations/operator,
feature-off build and alpha package/checksum. Local native20/20 and official
sample counts remain separate evidence. Previous C1 acceptance is preserved.

## Preserved adverse whitespace result

[Initial Check Whitespace39994040750](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040750),
job120552818898, completed failure. Exactly five diagnostics point to lines
5/7/27/57/80 of `openssl-probe.patch`: each is a single-space unified-diff
context marker for an empty source line. Frozen patch SHA256 remains
`2b61a530504b71c5249ce79e33a58ca51251cf5f245472620da7692a6bfb8dcd`.

Coordinator reproduced the whole PR range from base
`0b622c4a9f4dfe0876209c2a8bf5ce5e25caa812` to implementation99a017e:
exit2 with those five diagnostics and no other warnings. With the exact
`.gitattributes` path policy, the same full-history command returns exit0
with empty stdout/stderr. Attribute lookup remains unspecified for
`openssl-probe.c` and `src/core/nginx.c`.

The exception disables blank-at-EOL checking for the entire named patch
file, not only the five known lines. Patch/C bytes and compile/runtime
logic remain unchanged. Other files retain their rules. Independent private
Git2.51.1 controls confirmed historical-commit behavior, default space-before-tab
and blank-at-EOF detection on the patch, and blank-at-EOL on another C file.
String-valued target attributes need not inherit arbitrary custom
`core.whitespace` flags; current repository workflow sets no such custom flags.
Actual checked-out attributes are required for the tested `git log --check`
behavior; index fallback alone is not asserted.

Hosted policy acceptance is now recorded in the CI receipt below.
Commit-message and version-bump checks on99a017e succeeded. The inherited F5
CLA integration still failed separately; no contract is accepted on the
owner's behalf.

Next: accept the format-policy hosted result, then extend C2a peer/read KeyUpdate,
retry/control/shutdown/limits and runtime cancellation inventory. No new
spending, infrastructure, outreach or commercial scope was introduced.

## CI receipt

Policy implementation: `624f70fa1b5061c5be65759eed5a45a4d56a4af7`.
[Check Whitespace39995212454](https://github.com/soldabania-art/nginx-x10/actions/runs/39995212454),
job120556843347, completed success. Commit-message39995212552 and
version-bump39995212660 also completed success. The initial failure remains
recorded above; this is a format-policy correction, not new TLS behavior.

Successor research push39995200815 completed success with its expensive
research job skipped; this is not a fresh runtime pass. Research PR39995212463
completed success. Original exact runtime acceptance remains implementation
99a017e and its two real research/two full native runs.

Successor native push39995200740 / PR39995212470 were in_progress when this
receipt was written. Those exact SHA/run IDs remain pending in BACKGROUND;
unchanged runtime sources do not permit inventing their outcome. Later
coordination-only descendants do not replace the accepted source hashes.

Receipt modifies only BACKGROUND and this Markdown file, with one parent
being the exact own live lease; no C, patch, workflow or economic change.
Per-file receipt ledger (SHA256):

- BACKGROUND before: `214d18d744b93bf9dc647dd402e5f1c0c7ca932fd2eba854872c9539b278d5c9`; after: `722c244ba9c06fd35358b3c8abf2e43bc956fe5464eab37542097bfbf6b5faab`.
- C2A-CHECKPOINT before: `acbc0ab8c6462214994b736ddcf65d1ebc507825e9a09963f7449a74ac52d2a8`; own after digest omitted to avoid recursion; Git tree/commit identifies it.

Coordinator checked exact source identity and completed workflow/job results;
raw hosted logs, host paths, PIDs and session material are not published.

## Read retry lifecycle checkpoint

The former pending format-successor native runs39995200740 /39995212470
for624f70fa1b5061c5be65759eed5a45a4d56a4af7 completed success, confirmed
before starting this bounded implementation task.

Two new actual TLS cases extend the initial8 to10. Coordinator aggregate
passes10/10 on final runnerc43828e0c90a7b98ad86364b506ad82c3aefc3ee99cb113731f5bfb2161701b3,
with no skips/failures/cancellations/TODO. A real pending READ completes before
echo, while an unrelated successful WRITE leaves the READ obligation recorded
and produces exact RETRY16 refusal. Trusted fixture discipline is not a general
argument-identity or I/O ownership fence.

[Retry evidence](../evidence/continuum-c2a-retry.json) separates four exact-source
held-out TLS cases, one actual-TLS private-mutant sensitivity check, four
no-build diagnostic controls, and two non-TLS unsupported-API baseline checks.
The first build-hook attempt failed before any TLS case; its cause remains
unknown. Subsequent pinned builds and the final runtime aggregate passed.
Only28 fixed build-stage codes can now pass through the runner's dependency
error path; arbitrary codes/messages remain generic.

Native source is unchanged. A fresh identified checkout build passed20/20
aggregate groups; its binary is not claimed identical to the prior checkout.
C0 core21/process7 and C1 tests22 passed separately. Source/build identities,
cleanup boundaries and per-file changes are recorded in the evidence and
[retry ledger](../review/continuum-c2a-retry-ledger.json).

Hosted verification of this new retry implementation is pending its exact
publication SHA; old runtime/metadata CI does not accept it. After that gate,
peer/read KeyUpdate, WRITE retry completion and remaining control/shutdown/
usage-limit/cancellation inventory precede any C2b export/import work.

## Retry implementation hosted CI receipt

Implementation: `356f993ead12a1b827a0351f38143b7b14c8d18f`.
Both research workflows completed success:
[push40006143682](https://github.com/soldabania-art/nginx-x10/actions/runs/40006143682)
and [PR40006152124](https://github.com/soldabania-art/nginx-x10/actions/runs/40006152124).
Jobs120594513518 /120594586195 confirm core21, process7, C1 tests22 and
pinned-probe10, all without failures, skips, cancellations or TODO.

Both full native workflows completed success:
[push40006143712](https://github.com/soldabania-art/nginx-x10/actions/runs/40006143712)
and [PR40006152459](https://github.com/soldabania-art/nginx-x10/actions/runs/40006152459).
Jobs120594514554 /120594562804 include the native/official aggregate,
tenant-cache and Unix gates, feature-off build, alpha package and checksum.
This receipt records workflow/step outcomes; the local20-group evidence and
its fresh-checkout binary identity remain separate from hosted artifacts.
Whitespace40006152181, commit-message40006152137 and version40006152109
completed success. The inherited F5 CLA integration40006147449 failed
separately; no agreement was accepted on the owner's behalf.

Frozen runtime sources and evidence remain identified by356f993; this
metadata receipt is not a new protocol or native acceptance. The first
local build-hook failure remains recorded with unknown underlying cause.
Full TLS inventory, export/import, distinct TLS-code change and native
NGINX continuation remain unimplemented. Next: peer/read KeyUpdate and
remaining WRITE retry/control/shutdown/usage-limit/cancellation inventory.

Only BACKGROUND and this checkpoint change, over the exact live lease;
no runtime, workflow, economic or purchase change. Per-file receipt ledger:

- BACKGROUND SHA256 before `ff80d462b2aaaab0da521953bae1abb4530df13c922b3846e5e85372f342d612`; after `f1afdb5f5ab522657c6cf6c1e0f6db0674ce69fe8d96d9f9fed0615179104ccb`.
- C2A-CHECKPOINT SHA256 before `6ca88fa211b2b744501fbd1dfab06aedb7439ad782d6ee025aeacaa5941dcbd2`; its result is identified by the Git tree/commit to avoid a recursive own digest.

Only allowlisted counts and workflow/job IDs are retained here; raw logs,
host paths, process IDs and session material are excluded.

## Handled TLS runtime interruption checkpoint

[Interruption evidence](../evidence/continuum-c2a-interruption.json) records
13/13 local checks:10 existing ordinary TLS scenarios,2 handled Node runtime
signals and1 no-TLS cached-source control, with no failures/skips/TODO.
Private launchers call unchanged C2a APIs, authenticate TLS and reach a real
successful first READ before echo; the standalone CLI branch is not directly
executed. SIGTERM/SIGINT require fixed failure/143-or130 exit, C-child reaping,
PKI/fixture/pinned-build absence, native endpoint refusal and relay rebind.
These facts precede helper fallback cleanup and do not imply graceful TLS close.

The independent reviewer passed one exact-source held-out SIGINT49319 case,
two separate actual-TLS sensitivity refusals (left PKI and a real occupied
relay listener), three no-TLS options controls and two cached-import controls.
A private late-hash model reaches a stub spawn after disk mutation; final
load-time identity refuses before any build. Local PID/proc mapping now uses
NSpid, namespace and UID; the bounded helper guard is not an atomic PID fence.

Preserved adverse results include the first invalid native-port rebind gate,
two provisional independent process-identity refusals, an unfrozen aggregate
with10PASS/2FAIL, and one temporary reviewer CODE copy removed during final
review cleanup. No original production cleanup defect is established.
Exact final source hashes and identities separate final acceptance from those
provisional runs; missing executed-source identity is not invented.

Native regression passed20/20, official1083 strict PASS/25SKIP/1expectedTODO/
0FAIL, in a fresh checkout with a separately identified binary. C0 core21/
process7 and C1 tests22 passed. Native NGINX and C2a runtime/probe/build sources
are unchanged. Full inventory, peer/read KeyUpdate, WRITE retry, control/
shutdown/limits, export/import and actual TLS-code migration remain pending.
New hosted acceptance must use the exact implementation SHA; prior356f993
acceptance does not accept these tests automatically. No spending introduced.

## Handled interruption implementation hosted CI receipt

Implementation: `85bc255d457087cdce7768755c45b39843f015a5`.
Both research workflows completed success:
[push40010935810](https://github.com/soldabania-art/nginx-x10/actions/runs/40010935810)
and [PR40010942911](https://github.com/soldabania-art/nginx-x10/actions/runs/40010942911).
Jobs120610909369 /120610952419 confirm core21, process7, C1 tests22 and
C2a13, with no failures/skips/cancellations/TODO. C2a13 means10 ordinary
TLS scenarios,2 handled-runtime signal controls and1 no-TLS source control.
Hosted uses the canonical aggregate command; local read-only TAP collection
instrumentation is recorded separately in the original evidence.

Both complete native workflows succeeded:
[push40010935834](https://github.com/soldabania-art/nginx-x10/actions/runs/40010935834)
and [PR40010942898](https://github.com/soldabania-art/nginx-x10/actions/runs/40010942898).
Jobs120610916300 /120610943388 confirm native/official aggregate, tenant-cache
and Unix gates, feature-off build, alpha package and checksum. Hosted outcomes
are distinct from the separately identified local20-group native evidence.
Whitespace40010942943, commit-message40010942723 and version40010942893 also
completed success. Inherited F5 CLA40010937944 failed separately; no agreement
was accepted on the owner's behalf.

Original evidence retains its at-publication pending status and all adverse
results; this receipt records later exact-SHA acceptance. One successful
first-read interruption boundary is not the remaining TLS-state inventory,
standalone CLI coverage, C directSIGINT handling or a cross-version migration.
Next bounded task: real peer-requested KeyUpdate/read generation and response
obligation, then remaining WRITE/control/shutdown/limits before C2b.

This receipt changes only BACKGROUND and this checkpoint over its own exact
live lease, then releases it. Runtime/economic/automation files are unchanged.
Per-file receipt ledger (SHA256):

- BACKGROUND before `e7d3f54c90f99d47bc44141a04cf0b1b9fb843e75872efaaa222a89f4894b3e8`; after `ee2418d248bb1d2921d05c35616d8167b259bd3a3d5b72419506799b5a57a090`.
- C2A-CHECKPOINT before `d2ebddf63b543fc2074a65c380cfda1185e80fb6f3c4779bfa544a2a00d2d919`; its result is identified by Git tree/commit to avoid an own recursive digest.

Only fixed facts, counts and workflow/job IDs are published here; no raw
logs, host paths, process IDs, PKI or session material.

## Peer-requested KeyUpdate local checkpoint

New frozen sources passed canonical15/15, no failure/skip/cancellation/TODO:
12 ordinary actual-TLS scenarios,2 handled-runtime signals,1 no-TLS source
control. Four independently selected actual-TLS heldouts passed. Pending
snapshots1/0 serial3 reasons32832 retain queued response before any WRITE;
completed1/1 serial4 reasons64 follow real echo WRITE, with exact new-key
payload, both close_notify and FIN. Updated generations remain refused.
Two new C endpoints share pinned OpenSSL3.0.13; observer does not independently
validate PKI or Finished MAC. No export/import or code migration is implemented.

C0 core21/process7, C1 tests27=18 synthetic controls+9 runtime checks and
native20/20 passed. Official1083 strictPASS/25SKIP/1expectedTODO/0FAIL.
Exact identities, source-driven plan correction, reporter observation and
remaining gates are preserved in [peer evidence](../evidence/continuum-c2a-peer-key-update.json)
and [native evidence](../evidence/continuum-c2a-peer-key-update-native-regression.json).
The previous85bc255 hosted receipt remains accepted separately. New exact
implementation SHA/run IDs are pending after publication. No new spending.

## Peer-requested KeyUpdate implementation hosted CI receipt

Implementation: `2fac5b5496c702d9fea6ca127128f733b993af67`.
Both research workflows completed success:
[push40014631224](https://github.com/soldabania-art/nginx-x10/actions/runs/40014631224)
and [PR40014641655](https://github.com/soldabania-art/nginx-x10/actions/runs/40014641655).
Jobs120623485610 /120623533299 confirm core21, process7, C1 tests27 and
C2a15 with no failures/skips/cancellations/TODO. C1 is18 synthetic oracle
controls+9 runtime checks. C2a is12 ordinary actual-TLS scenarios,2 handled
runtime-signal controls and1 no-TLS cached-source control. Hosted uses Node22
and the canonical command; local Node24 and heldout identities are separate.

Both full native workflows completed success:
[push40014631185](https://github.com/soldabania-art/nginx-x10/actions/runs/40014631185)
and [PR40014641688](https://github.com/soldabania-art/nginx-x10/actions/runs/40014641688).
Jobs120623498669 /120623548086 completed native/official aggregate, tenant
cache/Unix gates, feature-off build, alpha package and checksum. These hosted
step results are distinct from local20-group counts and native binary identity.
Whitespace40014641780, commit-message40014641627 and version40014641775 also
succeeded. Inherited F5 CLA40014636478 failed separately; no agreement accepted.

Original evidence retains its at-publication pending status; this receipt
records subsequent exact implementation acceptance. Pending1/0 and completed
1/1 observation retain refusals, not transfer grants. Both C endpoints use
one OpenSSL3.0.13 pin. Full state inventory, semantic export/import, actual
TLS-code release change and native NGINX continuation remain unimplemented.

Next bounded task: same-operation actual WRITE retry completion with original
pointer, contents and length, immutable refused/completed snapshots and exact
receipt. A proposed bounded65536-byte attempt may fit the paused relay kernel
window and fail to reach WANT_WRITE: that must remain unsupported/state-not-reached,
not an acceptance or silent increase of observer limits. Both paused readers
must resume before retry. Overlap/control/shutdown/usage limits follow.

This receipt changes only BACKGROUND and this checkpoint over a separate
verified live lease, then releases it. Runtime/workflow/economic/automation
files and spending are unchanged. Per-file receipt ledger (SHA256):

- BACKGROUND before `921a29e16bf8ba241c0a3e067fba57ad8cc114ef7ba7f1e44777e808bed1ba9e`; after `88655a62678eec55c6dc76567515732e9a28f41f53e4c71ba8f5d97ac56ab0dd`.
- C2A-CHECKPOINT before `4335a8222f11c2c9014d4fc0a904c4017daf9823602b2aec2739351c4594145e`; its result is identified by Git tree/commit to avoid recursive own digest.

Only allowlisted counts, hashes and workflow/job IDs are retained; no raw
runtime logs, host paths, process IDs, PKI or session material.

## Same-operation WRITE retry local checkpoint

Canonical16/16 passed with no failures/skips/cancellations/TODO:
13 ordinary actual-TLS scenarios,2 handled runtime signals,1 no-TLS source
control. New case observes real WANT_WRITE, immutable refusal pair, identical
original-buffer/full-length retry success, cleared obligation and immutable
allowed pair. Exact65536-byte echo, sequence and TLS close/FIN are checked.
Original probe and all application/capture limits remain unchanged.

[Write evidence](../evidence/continuum-c2a-write-retry.json) preserves exact
source hashes, independent heldouts/sensitivity, baseline no-TLS unsupported
control and pre-runtime review corrections. Native20/20, official1083 strict
PASS/25SKIP/1expectedTODO/0FAIL, C0 core21/process7 and C1 tests27 passed.
C1 remains18 synthetic oracle controls+9 runtime checks. Distinct local/hosted
build identities must not be conflated. New exact implementation hosted CI
is pending after publication; previous2fac5b5 acceptance remains separate.
Next: overlaps/control/shutdown/usage inventory; no semantic export/import,
actual TLS-code change or native continuation implemented. No new spending.

## Same-operation WRITE retry implementation hosted CI receipt

Implementation: `ea64ec1a1ab8b7601d4fd946ce13563ec1558217`.
Both research workflows completed success:
[push40020048397](https://github.com/soldabania-art/nginx-x10/actions/runs/40020048397)
and [PR40020055569](https://github.com/soldabania-art/nginx-x10/actions/runs/40020055569).
Jobs120642031973 /120642134355 confirm core21, process7, C1 tests27 and
C2a16 without failures/skips/cancellations/TODO. C1 is18 synthetic oracle
controls+9 runtime checks; C2a is13 ordinary actual-TLS scenarios,2 handled
runtime signals and1 no-TLS source control. Hosted Node22 results are separate
from local Node24 source/build identities,2 heldouts and1 mutated control.

Both full native workflows completed success:
[push40020048420](https://github.com/soldabania-art/nginx-x10/actions/runs/40020048420)
and [PR40020055770](https://github.com/soldabania-art/nginx-x10/actions/runs/40020055770).
Jobs120642038792 /120642077361 completed native/official aggregate, tenant
cache/Unix gates, feature-off build, alpha package and checksum. These hosted
step results are distinct from local20-group counts and native binary identity.
Whitespace40020055548, commit-message40020055550 and version40020055547 also
succeeded. Inherited F5 CLA40020051024 failed separately; no agreement accepted.

Original evidence retains its at-publication pending status; this receipt
records subsequent exact implementation acceptance. Original-pointer/content/
full-length WRITE completion and immutable allowed snapshots remain narrow
read-only observation. Full inventory, semantic export/import, actual TLS-code
release change and native continuation remain unimplemented.

Next bounded case must obey the exact pinned SSL_get_error contract: after
WRITE/WANT_WRITE, repeat that WRITE before any other I/O-triggering operation.
A lawful sequence begins READ/WANT_READ, then a separate WRITE/WANT_WRITE,
freezes a refused snapshot pair and finishes WRITE first while retaining READ.
The current first-obligation enum cannot represent both; no acceptance bug is
established. Unrepresented overlap history must remain refused/unsupported;
its eventual clearance needs evidence for every obligation. Primary source:
[SSL_get_error.pod at the pin](https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_get_error.pod).
This is a read-only source handoff, not executed overlap coverage.

This receipt changes only BACKGROUND and this checkpoint over its own live
lease, then releases it. Runtime/workflow/economic/automation files and spending
are unchanged. Per-file receipt ledger (SHA256, exact leased parent):

- BACKGROUND before `b4bf2621a817565ff88513584782fc7d82dd8243cf49ef86f88ff580e1338da5`; after `bd700724f96727f13de4b4400d815f22b4dc1a39edeeb12846b33b07935499ad`.
- C2A-CHECKPOINT before `4702bfddc50d6fe6501b2b56787625665e19e4d1f729dc6cb272232aac247c71`; result identified by Git tree/commit to avoid recursive own digest.

Only allowlisted counts, hashes and workflow/job IDs are retained; no raw
runtime logs, host paths, process IDs, PKI or session material.

## Unsupported overlapping retry local checkpoint

Canonical17/17 passed, separating14 ordinary actual-TLS scenarios,2 handled
runtime signals and1 no-TLS source control. New case obtains real READ/WANT_READ
and distinct WRITE/WANT_WRITE, finishes identical original WRITE first, then
retains READ refusal16 with empty active output. Both refused snapshot pairs
are immutable; exact outbound65536 receipt precedes raw teardown.

[Evidence](../evidence/continuum-c2a-overlap.json) preserves source/build
identities, independent heldouts and baseline no-TLS unsupported control.
C0 core21/process7, C1 tests27=18synthetic+9runtime and fresh native20 passed.
Official1083 strictPASS/25SKIP/1expectedTODO/0FAIL remain separate. Prior
ea64ec1 hosted acceptance is retained; new exact implementation CI is pending.
Probe/ledger and native source remain unchanged. No overlap admission,
full graceful wire verification, semantic export/import or TLS-code migration
is implemented. Next: control/alert/shutdown and sequence/key usage inventory.

## Exact unsupported-overlap hosted acceptance

Implementation `996e997a6db359333d196d8db445580384db02ed` completed success in
research push40027640168/PR40027647320 (jobs120667838222/120667827548)
and native push40027640039/PR40027647366 (jobs120667900969/120667856291).
Both research job logs independently confirm core21/process7/C1-27/C2a-17,
zero failures/skips/cancellations/TODO. Seventeen C2a checks comprise14 ordinary
actual-TLS scenarios,2 handled runtime signals and1 no-TLS source control;
C1 remains18 synthetic oracle controls+9 runtime checks.

Native jobs completed aggregate, tenant-cache/Unix, feature-off build and alpha
package/checksum steps; their hosted success is separate from the local20/20
and official1083 strictPASS/25SKIP/1expectedTODO sample. Format checks
40027647458/40027647281/40027647362 succeeded. F5 CLA40027642566 remains an
inherited failed integration; no agreement was accepted for the owner.

Prior ea64ec1 WRITE-retry acceptance remains separate. This checkpoint accepts
only refusal observation: the original READ remains owed after exact WRITE
success. Raw close, wire=null, no overlap admission, semantic export/import,
actual TLS-code migration or native NGINX continuation. Next control/alert/
shutdown and sequence/key usage gates remain pending. Local evidence retains
at-publication pending status; this exact-SHA receipt records later acceptance.

## Server shutdown local checkpoint

Canonical18/18 passed:15 ordinary actual-TLS cases,2 handled runtime signals,
1 no-TLS source control. New case observes actual SSL_shutdown0/SENT1 then
actual1/SENT|RECEIVED3, with immutable refusal pairs and cleared own retry.
The mapping of0 to fixture WANT_READ is not an OpenSSL error classification.
Exact echo ACK and explicit client end gate call order; full unchanged wire
observer verifies both close_notify, FIN and final sequences including alerts.
[Evidence](../evidence/continuum-c2a-shutdown.json) records independent heldouts,
source/build identities, baseline no-TLS control and cleanup facts.

Core21/process7, C1 27=18synthetic+9runtime and native20/20 passed locally;
official1083 strictPASS/25SKIP/1expectedTODO/0FAIL remain separate. New exact
implementation SHA hosted research/native CI pending;996e997 accepted earlier.
This is normal server-first shutdown refusal only, not complete control/alert/
EOF inventory or admission. Remaining usage gates precede C2b; no semantic
export/import, actual TLS-code migration or native NGINX continuation.

## Exact server-shutdown hosted acceptance

Implementation `1f92d82c42d0c49c82029412fd882036da4e6da8` completed success in
research push40033951784/PR40033956592 (jobs120688803926/120688836523)
and native push40033951855/PR40033955843 (jobs120688801151/120688817731).
Both research logs independently confirm core21/process7/C1-27/C2a-18, zero
failures/skips/cancellations/TODO. Eighteen C2a checks mean15 ordinary actual-TLS
scenarios,2 handled runtime signals and1 no-TLS source control; C1 remains18
synthetic oracle controls+9 runtime checks.

Native jobs completed aggregate, tenant-cache/Unix, feature-off build and alpha
package/checksum steps; hosted success is separate from local20/20 and official
1083 strictPASS/25SKIP/1expectedTODO. Format checks40033955959/40033955950/
40033955902 succeeded. F5 CLA40033954017 remains an inherited failed
integration; no agreement was accepted for the owner.

Prior996e997 overlap acceptance remains separate. This receipt accepts normal
server-first shutdown refusal only: actual0/SENT1 to1/flags3, retrycleared but
closed state remains refused. Completed4356 includes retained processed record
metadata, not a claim of an unprocessed alert. Other control/alert/EOF/shutdown
and usage gates remain pending; no export/import, TLS-code migration or native
NGINX continuation. Local evidence retains at-publication pending status; this
exact-SHA receipt records later hosted acceptance.

## Unexpected EOF local checkpoint

Canonical19/19 passed:16 ordinary actual-TLS cases,2 handled runtime signals,
1 no-TLS source control. New post-echo raw-close case requires actual relay FIN
and actual C READ0/SSL_ERROR_SSL1/first-error reason294. Two immutable refused
snapshots follow; no subsequent TLS I/O/shutdown, no ignore-EOF or quiet option.
wire=null/graceful=false; full stream verification and server FIN not claimed.
[Evidence](../evidence/continuum-c2a-eof.json) records independent heldouts,
source/build identities, baseline no-TLS capability control and cleanup.
Core21/process7, C1 27=18synthetic+9runtime and native20/20 passed locally;
official1083 strictPASS/25SKIP/1expectedTODO/0FAIL remain separate. New exact
implementation research/native CI pending;1f92d82 hosted acceptance retained.
Other alert/EOF/partial/control inventory and usage gates remain before C2b;
no semantic export/import, actual TLS-code migration or native continuation.

## Exact EOF research success and native CI investigation

Implementation `d4bb2bc1c4b73d30b2097426863976fca691d9e8`: research push40040044905
and PR40040050370 (jobs120708789647/120708801705) completed success. Both logs
confirm core21/process7/C1-27/C2a-19, no failures/skips/cancellations/TODO.
Nineteen C2a checks mean16 ordinary actual-TLS cases+2 runtime signals+1 no-TLS
source control. C1 remains18 synthetic oracle controls+9 runtime checks.
Native PR40040050401/job120708803304 completed all stages successfully.

Native push40040045133 attempt1/job120708800093 failed its aggregate:19/20
groups passed, local-alpha-lifecycle failed with runtime_identity during stop
after library-drift control, followed by uninstall failure. TAP6pass/3fail
includes the enclosing parent, not three independent defects. Artifact12538224312
archive SHA256f3f512ad89a2c530c04b943302bd0caf861d1c793cd40ba1b88314e7b2481a44
was inspected privately; only allowlisted facts are retained in BACKGROUND.
A source-based graceful-exit observation-race hypothesis is not proven: no
failure-time per-field process snapshot exists. Alpha sources are unchanged.

One exact failed-job retry: attempt2, statuscompleted, conclusionsuccess, job120711043827.

The original failure remains evidence even if retry succeeds. No race fix was
implemented; native candidate stays under investigation and last fully accepted
native checkpoint1f92d82 remains separate. Next bounded task must reproduce and
resolve this stop-identity failure without weakening foreign/PID protections.
Local native20/20 and official1083 strictPASS/25SKIP/1expectedTODO remain separate.

Format40040050377/40040050390/40040050408 succeeded. F5 CLA40040047294 remains
an inherited failed integration; no agreement accepted. EOF research remains
narrow refusal only: wire=null, no full graceful wire/server FIN claim, state
export/import, TLS-code migration or native NGINX continuation. Local evidence
retains at-publication pending status; this receipt records later observed CI.

## Alpha: исчезновение процесса во время проверки идентичности

Исправлен контролируемый race чтения `/proc`: после `runtime_identity`
в `findMasters` выполняется одна немедленная проверка той же записи. Только
`ENOENT` позволяет пропустить исчезнувшего кандидата; отдельная проверка
записанного PID остаётся. Существующие Z/X, чужие/повторно использованные
PID и ошибки доступа не считаются подтверждённым завершением. CLI stop,
проверки перед сигналом и все 499 native source files не изменены.

Baseline даёт контролируемый `runtime_identity`; candidate проходит 28/28
синтетических тестов, независимые controls — 15/15. Native aggregate: 20/20
групп, включая реальный alpha lifecycle; official: 1083 strict PASS, 25 SKIP,
1 ожидаемый TODO, 0 FAIL. Core21/process7 также прошли. Counts synthetic
и настоящего lifecycle учитываются отдельно; исходники и identities — в
[evidence](../evidence/alpha-stop-identity.json).

Первоначальный сбой CI `d4bb2bc` сохранён: причина его точного interleaving
не доказана, повтор на том же SHA не был исправлением. Новый implementation
ожидает exact-SHA CI. Далее — сначала его результаты и возможные повторные
сбои, затем C2a alert/partial/control и sequence/key usage inventory. Атомарный
снимок `/proc`, pidfd fencing и перенос NGINX/TLS этим изменением не реализованы.
