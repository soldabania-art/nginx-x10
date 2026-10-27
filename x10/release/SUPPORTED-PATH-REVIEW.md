# Supported operator path: reviewed boundaries and open work

Source contract: `60a470a57ec9381b149b8dced0ad7131d9fbec7a`.
This is a source/test/evidence boundary review of the declared trusted nonroot
Linux profile. It is not full G4/G5/G7/V1 acceptance, a hostile same-UID sandbox,
an exhaustive native security audit or an actual incident recovery replay.

| Operator boundary | Reviewed behavior | Remaining condition or result |
| --- | --- | --- |
| Archive before extraction | Exact supplied checksum, finite gzip/tar sizes, allowlisted payload, modes, duplicate/path/link refusals | Checksums are unsigned consistency checks; trusted digest and publisher decision are separate. |
| Archive source identities | Four malformed identity arrays were accepted through regex coercion | Primitive strings are required for every HEX/REV field. Baseline4 accepted; candidate4 refused. Exact26d archive correction and subsequent f0 compatibility are scoped hosted-verified; publisher authentication remains separate. |
| Extracted installation | New canonical private prefix, checked fixed payload, Node/native/library identity and native configuration test | Safe ancestors, compatible ABI and trusted configuration remain prerequisites; native `-t` may open referenced files. |
| Packaged operator documentation | Alpha README linked a source-only sibling service document absent from bundle inventory | Link now points to the exact reviewed public runbook commit; no new payload entry or runtime-package identity is claimed. |
| Runtime ownership | Recorded UID, namespace, executable, command and start identity; guarded stop and retained unknown outcomes | Sampled checks have a verification-to-signal race and do not isolate a malicious same-UID actor. |
| Config change/revert | Explicit readiness/revision observation, retained history and guarded durable transaction recovery | No all-traffic fence or reversal of completed application side effects; controller recovery does not clear alpha faulted state. |
| Controller disk input | Baseline unbound status accepted settings with an ignored extra3MiB string; CLI's2MiB check followed full read | **SCOPED_EXACT_f0_HOSTED_VERIFIED:** both f0 native events completed the installed/service path and owned cleanup with reader76 included. The earlier98b fixture failures remain historical. Exact447 stopped-session alphaCLI compatibility is also scoped accepted; the new apply/revert admission candidate needs new compatibility; other alpha/config/binary/proc reads and full security remain outside the reader correction. |
| Session/inventory capacity | Baseline virtual prepare permits255→256; minimum256-session tree4353entries exceeds inventory4096 | **OPEN, narrow stopped-session component compatibility accepted:** stopped preparation counts the whole tree before creation and again before registry publication; minimum17 structural entries plus one registry temporary are reserved before creation, then one publication entry after creation. A post-creation refusal preserves the old registry and new unregistered tree with explicit STOP/do-not-retry. The new alpha apply/revert candidate separately reserves seven controller entries before spawn; direct controller, native/transient/concurrent growth and full capacity acceptance remain open. No actual256-native-session installation was exercised. |
| Package staging/return | Accepted exact historical/current operator HTTP staging/return/fallback receipts preserve identities and separate counters | Exactf0 scoped compatibility of **LEGACY_CLI_WITH_REVIEWED_CURRENT_PEERS** is hosted-verified for both events: exact acb CLI plus eight shared98b runtime peers. Exact447 stopped-session alphaCLI compatibility is separately accepted; the newer apply/revert alphaCLI candidate remains pending. It is not the complete historical acb package or an old-controller downgrade. Native binary change, TLS-state restore, permanent historical package and broader recovery remain unaccepted. |
| Faulted/orphan incident | Existing commands refuse unsafe restart/uninstall; runbook requires exact observations and STOP_UNRESOLVED | Original prefix stays in place even after a separate fresh restore. No lifecycle-clear/reaper/forced-uninstall path or accepted orphan incident replay. |
| User service and private Node | Local canonical bus/tool prerequisites, bounded observations, source-pinned strict reports and owned cleanup | A clean environment for a control client does not prove a clean environment inherited by the user-manager's service. Trusted manager/Node/loader environment remains an unverified profile prerequisite. |
| Release declaration | Exact60a hosted evidence ZIPs contain119 successful declaration checks; complete ordered36-step contract is verified separately | JSON declaration validation never authenticates external evidence or accepts a release. Permanent versioned publication, independent published-file replay and60-minute soak remain open. |

The first new code correction is intentionally confined to the pre-extraction
[archive verifier](verify-alpha-archive.mjs) and its pure tests. Both schema1
and schema2 valid profiles stay supported; malformed identity/checksum values
refuse without coercing caller objects. No archive is extracted or payload
executed by these tests. A newly computed checksum does not make an invalid
identity type valid, and the correction does not add publisher authentication.

The controller record-reader correction has76 frozen pure/tempfile tests and
29 separate independent heldouts. Exactf0 both-event hosted compatibility is
recorded in the [scoped receipt](../evidence/g5-alpha-inventory-bindings-hosted.json).
Exact447 stopped-session alphaCLI compatibility is separately recorded in
[its scoped receipt](../evidence/g5-stopped-session-capacity-hosted.json). The
new apply/revert admission candidate needs its own new exact compatibility. These are separate changes to runtime
contracts and need their own compatibility/evidence review. Do not turn known
failures into PASS by changing a cap without validating the resulting states.

Portable baseline reproducers are checked in with exact source-hash guards.
Run each from the repository root. They use only virtual/tempfile or mocked
unbound records, never native execution, network, signals or service control:

```sh
node x10/review/controller-input-counterexample.mjs
node x10/review/controller-loader-counterexample.mjs
node x10/review/alpha-session-capacity-counterexample.mjs
```

These scripts intentionally preserve baseline OPEN behavior; a successful
counterexample is not product acceptance. They refuse source drift. The alpha
capacity script remains pinned to its original CLI bytes: run it in a clean
`f0a0bd8fddb4b17943f0131100107d2d9eb4b9a8` checkout. Its refusal against the
new capacity candidate is intentional; do not rewrite its pin or call that a
failed candidate regression. The first
uses owned private temporary records and removes only that created directory;
its returned counts contain no raw paths, configuration or process identities.
The two controller scripts are preserved historical baselines for exact
`26d74c91ca4a3e95a5c3a93eeeae16bc278e2819`: run them in a clean checkout of that
commit. Their hash refusal against the new controller is intentional; do not
rewrite their pins or call them failing candidate regression tests.

Exact60a native push/PR both completed36 successful steps. Their alpha suites
took116097ms and115161ms under the120000ms budget. The older34f PR timed out
at120006ms without complete TAP or cleanup evidence. These later durations
neither explain its cause nor confirm its cleanup; the historical UNKNOWN stays.

Sources and reproducible finite controls are recorded in
[supported-path evidence](../evidence/g5-supported-path-review.json) and the
[exact declaration hosted receipt](../evidence/g7-ci-step-receipts-hosted.json).
Individual baseline, candidate, independent controls and hosted TAP counts
overlap and must not be added into a single security or runtime test total.
Existing c2/6401 failures, local cleanup FAIL_UNKNOWN and CLA failures remain.


## Legacy CLI with explicitly reviewed shared peers — exactf0 accepted

The fixture repair uses the profile
`LEGACY_CLI_WITH_REVIEWED_CURRENT_PEERS`. The legacy alpha CLI remains the exact
reviewed `acb648392e745b5246a5620f2ea6a6286dc06d42` blob,68551 bytes with SHA256
`4560b8b2503f109f210599a6277bdf5497118e3220c1d2fb6a0c041283c3810d`.
Its eight shared runtime peers are pinned separately to
`98bc32d4ee9a6c1d6ed198135df01065ad1a65e7`: all five control modules,
`alpha/runtime.mjs`, `alpha/upstream-example.mjs` and `service/user-unit.mjs`.
Only control `cli.mjs` and `manager.mjs` differ from the acb peer set. Both A
and B use these reviewed current peers; A changes only the alpha CLI bytes.
The actual candidate bundle must match every reviewed peer byte before the
legacy CLI is admitted, and all other copied payload bytes must be preserved.
A matching source checkout alone does not establish the actual bundle bytes.

This is an explicit combination of reviewed sources, not the entire runtime
from historical acb, a test of returning to an old controller, or an independently
published historical package. It may verify only its declared legacy-CLI/current-
controller compatibility through the exactf0 both-event hosted receipt. Prior7b fallback and
26d archive acceptance remain facts about their own exact sources and artifacts.
The exactf0 receipt accepts the declared combination and reader compatibility.
Exact447 separately accepts normal stopped-session alphaCLI compatibility;
neither receipt accepts the newer apply/revert alphaCLI or full G5.

Exact98b native push40533686304/job122293218632 and
PR40533697675/job122293256424 each passed19 of20 native groups. Their managed
controller suite passed162 tests, including76 new pure/tempfile controls and86
prior controls. Each alpha result was614 PASS/3 FAIL/617 total, without timeout:
the old precondition required all eight peers to equal acb despite the reviewed
controller change. Later installed TLS/package/service/private-Node gates were
skipped. Complete cleanup of the failed alpha attempt remains UNKNOWN; source
cleanup attempts do not prove resource absence. The later exactf0 native push/PR
passed the full declared compatibility path and confirmed owned cleanup, as
recorded in [the scoped receipt](../evidence/g5-alpha-inventory-bindings-hosted.json).
That acceptance enabled the stopped-session component, whose exact447 normal
compatibility is separately accepted. The newer apply/revert alphaCLI still
needs exact hosted compatibility. Full G3/G4/G5/G7/V1 remains open.


## Narrow stopped-session registry publication admission — exact447 compatible

The candidate keeps the cumulative entry bound4096 and corrects the walker's
pre-push off-by-one refusal. It samples the actual whole-prefix inventory under
the existing alpha lock, including retained revisions and the lock itself.
Before `createSession`,18 entries of headroom mean17 minimum session entries
plus one atomic registry temporary. After creation, the actual inventory must
still leave one entry before either the registry object or its file changes.
The postcheck is needed because native configuration checking can add more
than the minimum structure.

A postcheck failure is `session_capacity_unresolved`, with STOP/preserve/
do-not-retry guidance. The new unregistered session may remain alongside the
unchanged old registry; no automatic cleanup, registry repair, lifecycle editing
or forced uninstall is added. Thus this is not a clean rollback of creation or
a guarantee that every partial tree remains within the inspection bound.

The gap remains OPEN for cumulative apply/revert/controller revision growth,
native application temporary files, transient native-test high-water usage and
concurrent/direct controller writers. Initial install/restore/stage session
creation is outside this stopped-prepare guard, even though fresh prefixes are
normally small. Recovery, stop and uninstall keep their
existing independent semantics and refusals. Neither a smaller session count
nor raising the inventory limit alone would establish whole-path capacity.
All prior adverse receipts and full G3/G4/G5/G7/V1/release/recovery/Continuum
boundaries remain separate. Exact447 both-event normal installed compatibility is accepted by the
[scoped hosted receipt](../evidence/g5-stopped-session-capacity-hosted.json).
The4096 boundary controls remain pure/virtual; no actual physical exhaustion
fixture or fullcapacity acceptance is implied. Preparation18 overlaps managed
and alpha via an existing import; actual288/603 TAP series are not summed.


## Alpha apply/revert controller-entry admission — candidate

The installed alpha CLI candidate counts the whole prefix under the existing
alpha lock before spawning the controller for `apply` or `revert`. It keeps the
4096-entry inventory limit and requires seven free entries. The count includes
retained sessions/revisions and the existing alpha lock; it is not a session
count cap or a cleanup mechanism. A pre-spawn refusal preserves existing data
and avoids a new controller invocation. Other commands, including stop and
recover, keep their existing independent semantics.

The seven-entry bound covers the pinned controller's declared control-file
operations only. Candidate plus rollback revisions, pending/event state, the
controller lock and retained atomic temporaries must all be accounted for.
Six is insufficient when temporary cleanup itself fails and rollback/ambiguity
handling retain additional temporary names. The source-extracted virtual model
uses explicit atomic/revision outcomes plus representative nonallocating failure
classes. It is not an enumeration of
every possible OS failure; its paths and executions are not independent runtime
tests or physical filesystem high-water observations.

Native/configuration-test files, arbitrary same-UID concurrent writers, direct
controller calls and initial install/restore/stage growth remain outside this
admission. The stopped-preparation post-refusal can still retain an
unregistered or uninspectable tree with STOP; this change does not clean it.
Controller durable writers/schema, old records/revisions, unknown/faulted STOP
and the fixed bundle inventory are preserved. New installed alphaCLI hosted
compatibility is pending, and fullcapacity/G5/V1/recovery/release/Continuum
remain open. See [candidate evidence](../evidence/g5-alpha-revision-capacity.json).

The new [revision baseline producer](../review/alpha-revision-capacity-counterexample.mjs)
is pinned to exact447 alphaCLI and manager bytes. Run it in a clean447 checkout
(or another checkout with exactly those pinned bytes), before the candidate
change. Invoke the checked-in producer by its absolute path with that baseline
checkout as the working directory: it reads the pinned sources relative to the
working directory, so no baseline commit or pin must be rewritten. It reproduces
virtual revision accumulation and unguarded forwarding;
its refusal against changed candidate bytes is intentional. The older three
baseline producers and their source pins remain immutable.
