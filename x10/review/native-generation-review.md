# Independent native generation review

Review date: 23 October 2026. Baseline development checkpoint:
`8d769208cf79b8a583077ccb75be30f59e9563a1`.

No unresolved blocker was found within the optional master-generation
bookkeeping scope at the frozen native hashes below. This is a scoped source
and runtime review, not production certification, a worker acknowledgment
protocol, or an all-generation listener fence. The final aggregate, Unix-domain
transport CI and hosted results remain separate root-owned gates.

[Public review summary](../evidence/native-generation-review-controls.json)
records test names, results and source hashes. The full local record retains
the rendered counter responses, independent burst report, validator mutations
and harness sources; its SHA-256 is recorded in the summary. Host paths, live
process/namespace identities and raw logs are omitted from publication.
Evidence executed by other owners is listed separately; it is not relabeled
as independent execution.

## Source contracts and implementation

The new endpoint is additive: `GET /1/control/generations` in the already
optional native control API. The control discovery list gains its name. Existing
`/1/control/processes` fields are untouched; a private side table avoids changing
`ngx_process_t` or `ngx_cycle_t` layouts. Comparing both headers to the previous
milestone confirms they remain byte-identical. That is a layout preservation
check, not certification of every third-party module ABI.

The review read all changed hunks in the four files below, plus the relevant
initialization, cycle assignment, fork/error/respawn, reap, reload dispatch,
JSON string ownership and rendering contracts:

| File | Reviewed change/contracts |
| --- | --- |
| `src/os/unix/ngx_control.c` | Private side table, counter helpers, new GET dispatch, copied decimal strings/nulls, existing response compatibility and successful PATCH assignment before response rendering |
| `src/os/unix/ngx_control.h` | Internal hook declarations without existing structure changes |
| `src/os/unix/ngx_process.c` | Successful parent-fork publication before the respawn early return; error exits precede the hook; detached classification |
| `src/os/unix/ngx_process_cycle.c` | Master initialization before children; successful HUP commit; rejected HUP, control sweep, reap/respawn and binary/restart paths |

The generation increments at accepted-cycle publication, not when workers are
started or respond. The two successful assignment sites—HUP and control PATCH—
call the commit hook. Rejected `ngx_init_cycle` results do not call it. Existing
PATCH behavior can commit a cycle before response rendering/sending fails; the
new ordering preserves that fact instead of treating response delivery as a
commit boundary.

Every successful non-detached parent fork records the PID, current applicable
cycle generation and a fresh birth before the existing `respawn >= 0` return.
Native fork and earlier setup failures return before that hook. Slot reuse
replaces its private entry. An unexpected cycle or mismatching published PID
leaves the process unclassified rather than guessing. Detached exec children
are omitted and counted separately, because an exec'd master has another
lifetime. The new callbacks do not change worker startup, listener ownership,
reload acceptance or application processing.

Counters are uint64 values rendered through `%uL` into bounded storage, copied
by the production data string handler into the request pool. They reach JSON
as canonical decimal strings. Zero is an unavailable sentinel and renders as
null. Exhaustion latches diagnostic unavailability without wrapping or refusing
native reload/spawn. An unclassified process can leave a known
`current_generation` visible with `available:false`; clients must not use that
partial process set as complete.

The table and endpoint are compiled with the existing control subsystem, and
the new process/master hooks are under `NGX_CONTROL_API`. Without an active
control socket the hooks return without maintaining identities. No management
listener is opened implicitly, no per-HTTP-request operation is introduced, and
there is no new worker protocol or allocation in the spawn/commit callbacks.
Generation and birth identities apply only within one externally verified
master lifetime. PID alone cannot distinguish restarted/reused master instances.

## Independently executed checks

| Execution | Result | Scope |
| --- | --- | --- |
| Production-TU counter and JSON boundaries | 20/20 semantic assertions over 18 rendered records | Actual `ngx_control.c`, production string/data/JSON/pool/buffer/allocation code; only send capture and logging stubbed; ASan/UBSan, no diagnostics |
| Actual queued PATCH burst | 4/4 case groups | Two shared native setup groups and two review behavior groups; actual owned master stop/continue and real loopback API |
| Direct aggregate validator matrix | 137/137 | Three accepted producer records and 134 rejected mutations; exact extracted `jsonChecks`, not 137 runtime suites |

The reusable counter harness is
[generation-boundaries.c](../test/generation-boundaries.c) with
[generation-boundaries.sh](../test/generation-boundaries.sh). Run:

```sh
bash x10/test/generation-boundaries.sh
```

It checks initial identities, two cycle commits before any new child,
respawn/slot overwrite, the same PID receiving a new birth, stale PID mapping,
unknown cycle, detached exclusion, invalid slot bounds, inactive hooks and
master-scope reset. Exact decimal values cross 2^32, JavaScript's 2^53 boundary
and UINT64_MAX. The last valid generation/birth is represented exactly; the
next allocation produces unavailable/null diagnostics and stays latched across
later commits and births. Endpoint rendering does not mutate the side table.
All temporary resources are removed and no network process is started by this
harness. LSan is disabled.

The independent live burst test verified the exact owned master in state `T`,
queued two valid PATCH requests on already connected loopback sockets, and then
sent SIGCONT. Both received HTTP 200. The master reported generation `"3"`,
with new worker births `"3"` and `"4"` in generation three after initial births
one and two. Thus two accepted cycles preceded one new-worker spawn sweep;
allocating generation only at spawn would fail this control. The original
revision still served correctly. Both fixture masters exited normally under
SIGQUIT, all tracked sockets closed, and the prefix was removed.

## Review finding and resolution

The initial aggregate validator accepted mutated generation snapshots with a
missing/wrong scope, wrong master or false availability, although the actual
runtime fixture itself already rejected those values. The root agent added a
strict snapshot helper covering initial, PATCH, HUP and respawn reports. The
final direct matrix rejects those mutations, malformed/non-string/out-of-range
serials, duplicate identities, invalid PID/slot/flags, reference-absence mode,
wrong transport/fallback, interrupted results, changed source flags, incorrect
case counts, sanitizer failures and incomplete cleanup.

This was a result-validation issue, not a native generation defect. The final
matrix records the exact aggregate and extracted-function hashes. Main-runner
filesystem/binary/source identity guards were also read; the direct matrix does
not claim to execute those guards as subprocess tests.

## Separately inspected owner evidence

- [Candidate generation fixture](../evidence/generations-fixed.json): 10/10
  case groups on the rebuilt candidate, including initial generation one,
  accepted/rejected PATCH and HUP, an old response retaining its generation,
  actual worker SIGKILL/respawn with reused slot and fresh birth, read-only 405
  behavior, unchanged legacy JSON keys and exact old response completion.
- [Reference absence](../evidence/generations-reference.json): three explicit
  reference case groups establish expected 404 on pristine NGINX. This is a
  missing diagnostic capability, not a vulnerability or failed protocol fix.
- [Control baseline](../evidence/control-api-fixed.json) and
  [pristine baseline](../evidence/control-api-reference.json): nine groups each
  preserve existing control/reload behavior on explicitly selected loopback TCP.
- [Owner interruption controls](../evidence/control-api-runner-verification.json):
  SIGTERM after a real old response in both shared and generation fixtures
  returns failure before completing every case and cleans the isolated native
  groups, sockets and prefix. These two runtime controls were inspected, not
  independently repeated by this reviewer.
- [Disabled build](../evidence/control-disabled-build.json): build-owner-executed real
  build without `--with-control-api`, absent macro/object, matching remaining
  module/compiler profile and rejected `-l` option. Four groups pass. This is
  one Linux disabled-profile result, not a platform matrix.
- [Local Unix-domain diagnostic](../evidence/control-api-unix-unavailable.json):
  the local kernel refuses AF_UNIX socket creation. TCP is explicit and no
  automatic fallback relabels it as Unix permission proof. Unix transport is a
  separate required hosted gate.

## Remaining boundaries

Live fork/allocation/send failure injection, binary upgrade/old-master restore,
failed worker initialization, 32-bit builds, other Unix platforms and arbitrary
module combinations were not independently executed here. The corresponding
source paths were reviewed and the limitations remain explicit. Counter tests
are not a proof about scheduler interleavings or every possible input.

A classified birth is not successful worker initialization, application health,
listener-close acknowledgment, drain completion or atomic traffic cutover.
Existing master `exiting`/`exited` flags retain their original meaning. No
performance improvement or universal absence of regression follows from this
metadata feature.

## Frozen identities

| File | SHA-256 |
| --- | --- |
| `src/os/unix/ngx_control.c` | `7cfcf5ad2cdf9eb7546281c3ce2dc0254a257b7d009a6c494e913cee4a36f2e0` |
| `src/os/unix/ngx_control.h` | `6273ebce9a188abe9319758cd745c0c1688d24a11db151f9654b675e2dae4541` |
| `src/os/unix/ngx_process.c` | `a354c634854617bed643d8db8b6218aa84cb603a7de1b15d9402427b4a471677` |
| `src/os/unix/ngx_process_cycle.c` | `dd2f45a62724d9a297005f080efa0dcdd34ce7760d7591ec829ff6d3407ce819` |
| `x10/test/generation-boundaries.c` | `b1fc24570be6225147f7b9f190384ed53b6886f31dc42a2b61ed943e0b44a666` |
| `x10/test/generation-boundaries.sh` | `4817699f2a0547862ef9f5d62c6b6fd7e03e9f6a047cef7fa6b0bda6cb2527c0` |
| `x10/test/control-api-baseline.mjs` | `b81d396fb7193120d505c72c668a26e2e1ce3a79af2b8884c3c7bbfa565a1786` |
| `x10/test/generations.mjs` | `39f335e42152dcb3022d153a32ac71fa5a0910fb24acf38975eee2010b894354` |
| `x10/test/all.mjs` | `de06cd2f702b01179dd733f17f39906615b60b48be948f94166f72a5d6f7b6fe` |

The reviewer burst records native binary
`e150b0a6e15c3799384e141ea548c658f1ce126ad2eb996a3965ab6791e0a139`.
All reviewer-owned runtime fixtures have stopped.
