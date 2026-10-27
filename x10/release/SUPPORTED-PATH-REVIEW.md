# Supported operator path: reviewed boundaries and open work

Source contract: `60a470a57ec9381b149b8dced0ad7131d9fbec7a`.
This is a source/test/evidence boundary review of the declared trusted nonroot
Linux profile. It is not full G4/G5/G7/V1 acceptance, a hostile same-UID sandbox,
an exhaustive native security audit or an actual incident recovery replay.

| Operator boundary | Reviewed behavior | Remaining condition or result |
| --- | --- | --- |
| Archive before extraction | Exact supplied checksum, finite gzip/tar sizes, allowlisted payload, modes, duplicate/path/link refusals | Checksums are unsigned consistency checks; trusted digest and publisher decision are separate. |
| Archive source identities | Four malformed identity arrays were accepted through regex coercion | Current candidate requires primitive strings for every HEX/REV field. Baseline4 accepted; candidate4 refused. Exact new hosted verification pending. |
| Extracted installation | New canonical private prefix, checked fixed payload, Node/native/library identity and native configuration test | Safe ancestors, compatible ABI and trusted configuration remain prerequisites; native `-t` may open referenced files. |
| Packaged operator documentation | Alpha README linked a source-only sibling service document absent from bundle inventory | Link now points to the exact reviewed public runbook commit; no new payload entry or runtime-package identity is claimed. |
| Runtime ownership | Recorded UID, namespace, executable, command and start identity; guarded stop and retained unknown outcomes | Sampled checks have a verification-to-signal race and do not isolate a malicious same-UID actor. |
| Config change/revert | Explicit readiness/revision observation, retained history and guarded durable transaction recovery | No all-traffic fence or reversal of completed application side effects; controller recovery does not clear alpha faulted state. |
| Controller disk input | Baseline unbound status accepted settings with an ignored extra3MiB string; CLI's2MiB check followed full read | **LOCAL_FIX_HOSTED_COMPATIBILITY_PENDING:** bounded acquisition remains locally verified. Exact98b controller tests passed162, including the new76, but both native runs failed the separate legacy-CLI fixture precondition; later installed/service gates were skipped. Other alpha/config/binary/proc reads and full security remain outside this correction. |
| Session/inventory capacity | Source-extracted virtual prepare permits255→256; minimum256-session tree4353entries exceeds inventory4096 | **OPEN:** session capacity and cumulative inventory accounting disagree. No actual256-native-session installation was exercised. Raising one limit alone does not prove safe capacity. |
| Package staging/return | Accepted exact historical/current operator HTTP staging/return/fallback receipts preserve identities and separate counters | The new **LEGACY_CLI_WITH_REVIEWED_CURRENT_PEERS** fixture profile is pending: exact acb CLI plus eight shared98b runtime peers. It is not the complete historical acb package or an old-controller downgrade. Native binary change, TLS-state restore, permanent historical package and broader recovery remain unaccepted. |
| Faulted/orphan incident | Existing commands refuse unsafe restart/uninstall; runbook requires exact observations and STOP_UNRESOLVED | Original prefix stays in place even after a separate fresh restore. No lifecycle-clear/reaper/forced-uninstall path or accepted orphan incident replay. |
| User service and private Node | Local canonical bus/tool prerequisites, bounded observations, source-pinned strict reports and owned cleanup | A clean environment for a control client does not prove a clean environment inherited by the user-manager's service. Trusted manager/Node/loader environment remains an unverified profile prerequisite. |
| Release declaration | Exact60a hosted evidence ZIPs contain119 successful declaration checks; complete ordered36-step contract is verified separately | JSON declaration validation never authenticates external evidence or accepts a release. Permanent versioned publication, independent published-file replay and60-minute soak remain open. |

The first new code correction is intentionally confined to the pre-extraction
[archive verifier](verify-alpha-archive.mjs) and its pure tests. Both schema1
and schema2 valid profiles stay supported; malformed identity/checksum values
refuse without coercing caller objects. No archive is extracted or payload
executed by these tests. A newly computed checksum does not make an invalid
identity type valid, and the correction does not add publisher authentication.

The controller record-reader candidate has76 frozen pure/tempfile tests and
29 separate independent heldouts. Its installed controller bytes change and
need fresh hosted compatibility. After that, align session/inventory capacity
before any broader recovery acceptance. These are separate changes to runtime
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

These scripts intentionally demonstrate current OPEN behavior; a successful
counterexample is not product acceptance. They refuse source drift. The first
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


## Legacy CLI with explicitly reviewed shared peers — candidate

The pending fixture repair uses the profile
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
controller compatibility after new exact hosted execution. Prior7b fallback and
26d archive acceptance remain facts about their own exact sources and artifacts.
No old success accepts the repaired fixture or the new installed controller.

Exact98b native push40533686304/job122293218632 and
PR40533697675/job122293256424 each passed19 of20 native groups. Their managed
controller suite passed162 tests, including76 new pure/tempfile controls and86
prior controls. Each alpha result was614 PASS/3 FAIL/617 total, without timeout:
the old precondition required all eight peers to equal acb despite the reviewed
controller change. Later installed TLS/package/service/private-Node gates were
skipped. Complete cleanup of the failed alpha attempt remains UNKNOWN; source
cleanup attempts do not prove resource absence. The profile repair still needs
new exact hosted compatibility and owned-cleanup receipts before dependent
session/inventory work. Full G3/G4/G5/G7/V1 remains open.
