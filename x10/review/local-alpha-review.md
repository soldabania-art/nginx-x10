# Local Linux alpha: independent review

Reviewed on 23 October 2026 at the frozen operator and packaging source hashes
below. No unresolved blocker was found within this local, trusted-operator
scope. This review does not certify production readiness or measured speed.
The complete aggregate and hosted Unix/CI runs remain separately owned gates.
No native C source was changed for this feature.

[Public review summary](../evidence/local-alpha-review-controls.json) retains
test names/results, source and binary hashes, and cleanup facts. It is explicitly
not a raw runner result or validator input. Full local records and the two
independent harnesses are retained privately; the summary records the complete
review record's SHA-256. Host paths, runtime process/namespace/socket identities,
configurations and logs are omitted from the public evidence.

## Reviewed contracts

The controller changes are additive. Default `status` JSON stays compatible;
`status --human` presents the existing revision-header observation, labels
mismatches and pending/error states, and explicitly says that health and
listener drain were not checked. Cross-command flags are rejected before
dispatch. This does not add health probes or alter apply/recover acceptance.

Generation inspection reuses the existing controller lock, bound-master,
pending-transaction and file guards. It requires exactly one explicit private
Unix socket or `127.0.0.1:port`, proves that the selected LISTEN inode belongs
to the bound master, and checks its OS lifetime and namespaces before and after
one GET. Exact schema validation preserves decimal uint64 strings and explicit
unavailable/null states. HTTP deadlines and body/header limits, process/FD/procfs
limits and checked I/O budgets bound supported observations. Procfs budgets
cannot cancel a stalled kernel syscall. Observations are sampled metadata,
not an authentication boundary or readiness acknowledgment.

Packaging checks the native build manifest, bytes, generated inputs, module
inventory and dynamic dependencies. The bundle has an allowlisted payload,
upstream LICENSE/NOTICE and normalized provenance; installation needs neither
the original git checkout nor its build directory. A new owned canonical private
prefix is required. Installation prepares state without starting native NGINX.
The default run opens the two explicitly configured IPv4 loopback HTTP demo
listeners. Native control API activation requires an explicit private socket;
inherited `NGINX_CTRL` is removed and there is no automatic transport fallback.

Each session has its own controller journal and recorded master lifetime.
Start/stop check executable, UID, namespace, start time, command, exact prefix,
configuration and PID file. Signal handlers precede detached spawn; startup
cancellation requests a verified SIGQUIT and performs bounded cleanup.
Normal shutdown requires master and remaining native group absence. Abnormal
exit is `faulted`, preserving data and refusing automatic stop/restart/uninstall;
the alpha does not reap orphan workers. There remains a check-to-signal PID race
because Node has no pidfd signal primitive.

Uninstall verifies installation root identity, immutable bytes, controller
records, stopped sessions and the allowlisted inventory before sibling quarantine
and removal. Changed configuration, pending/unknown data and symlinks are refused.
Known native logs and validated session histories are removed by explicit
uninstall, as documented. Private ownership and unsigned checksums do not protect
against a malicious same-UID actor racing files or processes.

## Independent executions

| Execution | Result | Scope |
| --- | --- | --- |
| Operator TCP flow | 9/9 check groups | Actual native generation/CLI observations and guarded refusal paths |
| Extracted bundle lifecycle | 8/8 check groups | Actual pack/extract/install/native serving/apply/revert/stop/uninstall and deletion/signal guards |

The operator flow initialized and bound a real native master, queried generation
one through the explicit CLI, applied revision B, observed generation two and
received B from the native HTTP listener. Complete controller/config/fragment
hash maps remained unchanged across diagnostic commands. A foreign loopback
server with a valid-looking reply received no HTTP request. Substituted PID-file
bytes and changed main configuration were refused; `apply --human` failed before
journal writes. After SIGQUIT, human status showed an unverified stale runtime
and generation inspection failed closed.

The bundle flow verified exact native bytes and LICENSE after extraction and
installation. Its default master owned exactly the two expected loopback TCP
LISTEN sockets, had no `-l` argument and no installation-root Unix socket. It
served the initial, applied and reverted responses. Live uninstall was refused.
A forged PID file targeting a controlled unrelated sentinel caused stop refusal;
the sentinel stayed alive and native serving continued. Symlink ancestor pack
and install paths failed without creating target directories. After guarded
SIGQUIT, changed config and unknown operator files survived rejected uninstall;
restoring/removing only the fixture's own changes permitted clean uninstall.

Both flows verified unchanged source and native binary hashes. The operator
master exited SIGQUIT zero, its process group disappeared, all tracked sockets
closed, and its temporary root was removed. The bundle supervisor exited zero;
its native group and controlled sentinel were gone, and normal uninstall plus
fixture cleanup left no temporary root. These are execution groups, not counts
of improved NGINX functions.

## Findings and attribution

Root source review identified the startup-signal window and abnormal master exit
being mislabeled stopped. The frozen implementation installs handlers before
spawn, preserves unresolved cleanup, and records `faulted` for abnormal exits.
The owner fixture includes actual early SIGTERM and master SIGKILL/orphan-serving
controls. Their source was inspected; this reviewer did not independently replay
those two destructive fixture paths. The owner's targeted TAP totals were
reported separately: operator 30 (29 subtests plus parent), alpha 9 (8 subtests
plus parent). They are not added to the independent counts above.

Independent source review identified a rejected pack-output path that could
create directories through a symlink ancestor. The owner now validates the
nearest existing canonical ancestor before mkdir. The independent candidate
control confirmed rejection with no target mutation; no old-source runtime
reproduction is claimed.

The earlier substring-prefix observation was a helper/source counterexample,
not a reproduced full-alpha sibling-install defect: normal alpha sessions use
distinct generated session IDs, so illustrative overlapping install names were
insufficient to demonstrate that failure. The frozen helper selects exact
prefix/config arguments while retaining refusal for malformed matching targets.

## Boundaries and frozen identities

The independent generation run used explicit TCP. One actual local/proc PID
mapping arrangement was observed; arbitrary namespace/platform/ABI combinations
are unverified. The package uses Linux procfs, Node 22+ and compatible dynamic
host libraries. Its demo self-check does not establish upstream application
health. Binary debug/configure metadata may contain build paths; private local
bundles were not published. Power loss, every allocation/storage/signal failure,
every crash interleaving and complete worker/drain semantics remain outside this
review. Full regression/hosted results must be attributed to their own run.

| File | SHA-256 |
| --- | --- |
| `x10/control/cli.mjs` | `72972fd1093068d05b788a326962f641fb2871dd7fa4cabb66957fcb3b22775b` |
| `x10/control/manager.mjs` | `f033c4ec66973211bad096cccdbbce63d724c02458711e3ff3a04f5227d9dc53` |
| `x10/control/generations.mjs` | `dba28810084f0cbb84275cc200f5bec93150406306c6bd78b06ac2b585815789` |
| `x10/control/status-format.mjs` | `522d932cbfe9ca8493a5f472207da910eb71476ed47f1148dda589a4171929f8` |
| `x10/alpha/cli.mjs` | `5792054b28d36a1301392dd68c7ea360545de606d58b78df9abbeacf97e256b4` |
| `x10/alpha/runtime.mjs` | `5952dfe5eb577daa3e4e8d0bf2d7b36d5f4ce53ff901814f98a1880e6dea66e2` |
| `x10/test/operator-status.test.mjs` | `0c24bce2518848d14c317b451c261f437a8209387ea9ae8a1abb3e86c560e03d` |
| `x10/test/alpha.test.mjs` | `f6cbbe5ecc597170b68650d2c02146b46d738fef4ad9a25590da215c655f6f11` |
| `x10/alpha/README.md` | `4779fba1f6bee0b5bd111784553f37d06f592239b179ab4ba77a9b9f13c372bf` |
| `x10/alpha/NOTICE.txt` | `27f28e07cead124c76c2cd290077117278c2dd61ac336d04ef3f08a48de685bc` |

Both independent flows used native binary
`e150b0a6e15c3799384e141ea548c658f1ce126ad2eb996a3965ab6791e0a139`.
All reviewer-owned processes and temporary resources have stopped or been removed.
