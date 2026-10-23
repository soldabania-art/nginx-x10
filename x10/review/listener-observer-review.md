# Captured-process listener observer: independent review

Reviewed on 23 October 2026, starting from development commit
`4024ef43d1e10e4079d54651036ee2daec424e29`. No unresolved blocker was found
in the frozen observer, controller diagnostic wrappers or handover fixture
within the scope below. This is a scoped review and a set of short controls,
not certification of a generation fence, production release or complete native
reload compatibility.

The reviewer owns this report and
[review-control evidence](../evidence/listener-observer-review-controls.json).
Implementation changes were made by their owners; the reviewer did not change
production or controller implementation. The evidence includes the exact review
harness source and separates reviewer executions from inspected owner results.
All reviewer fixtures are stopped.

## Boundary and contracts

The new commands are explicit diagnostics. `snapshot-listeners` records a
supported single `127.0.0.1` IPv4 TCP LISTEN inode and the specifically captured
native child identities. `inspect-listeners` checks those identities and their
own descriptor inventories later. `ok:true` means inspection completed; the
separate `observation.state` is `pending` or `closed`. An unavailable observation
fails, rather than becoming an empty descriptor list or successful closure.

The manager wrappers use the ordinary lock, refuse unbound or pending state,
validate the current revision and bound master, and recheck file/master guards
after observation. They do not change apply/revert/recover acceptance, advance
history, issue a reload, expose a management socket or send process signals.
The CLI requires the complete saved snapshot-command output. Native C is
unchanged by this diagnostic.

Process identity checks include procfs PID, local `NSpid`, parent procfs PID,
start ticks, UID, executable and PID/network namespaces. The observer matches
the captured listener inode against each child's `/proc/<pid>/fd` links;
`/proc/<pid>/net/tcp` supplies a network-namespace table, not descriptor ownership.
Identities are checked around descriptor inspection. Permission denial,
malformed input, changed identity, changed listener or exceeded bounds remains
unresolved. Process exit is accepted only after two specifically absent process
directory lookups; an individual missing FD link triggers bounded inventory
retry instead.

Primary Linux sources were checked for the child-list interpretation:
[procfs documentation](https://www.kernel.org/doc/html/v6.14/filesystems/proc.html#proc-pid-task-tid-children-information-about-task-children)
and [kernel `fs/proc/array.c`](https://github.com/torvalds/linux/blob/master/fs/proc/array.c).
The kernel renders child IDs in the procfs mount's PID namespace. Its fast child
list can skip entries during concurrent exits. Repeated matching lists therefore
remain a churn diagnostic, not proof of a complete generation. The bounded PPid
fallback has the same sampling limitation.

## Findings resolved before freeze

1. **Missing kernel child-list interface.** The first independent actual native
   capture failed at observer hash `f17fa20e…` because
   `/proc/<master>/task/<master>/children` did not exist while the master was
   alive. The current environment exposes no such entry even for the reviewer
   process. The owner added a bounded numeric `/proc` scan with PPid filtering
   and full identity validation when that interface is absent. Unreadable scan
   state fails; disappearing processes require confirmed absence. The original
   draft failure and final passing native run are retained in the review JSON.
   This was an observer portability issue, not a native NGINX defect.
2. **Resource acquisition after deadline.** Root review found that a deadline
   check after `open`/`opendir` could throw before the caller acquired the handle
   for its `finally` block. The owner added acquisition cleanup. The reviewer
   independently delayed real status-file and FD-directory acquisitions beyond
   the three-second budget and confirmed that both acquired resources were
   closed by the observer before the expected failure returned.
3. **Aggregate schema gaps.** Read-through found that deleting the capture hash
   and both observation hash links could satisfy `undefined === undefined`.
   Inspection scopes also lacked explicit checks. Root added a required hash
   format and both scopes, plus native-log checks. Direct mutations against the
   final extracted validator reject these records. These controls are direct
   function executions, not claims that the aggregate CLI was rerun by review.

## Reviewer-executed controls

| Execution | Result | Actual boundary |
| --- | --- | --- |
| Short native observer controls | 15/15 | Real native master/worker, namespace PID mapping, pending owner, reload release, stopped-master refusal, context/snapshot/start-time negatives, FD I/O faults and deadline acquisition cleanup |
| Handover interruption after an observed stopped worker | 1/1 | Independently read worker state `T`, SIGTERM to fixture, nonzero failed result, resume requested, native/fixture cleanup and observed stopped worker gone |
| Direct handover aggregate validator | 36/36 | One accepted frozen owner record and 35 mutated records rejected; exact extracted `jsonChecks` function, no aggregate CLI or mocked child execution |

The real native run recorded distinct local and procfs master PIDs, so it
exercised the ancestor-mounted `/proc` mapping used in this environment. The
initial live owner was `pending`; after HUP the captured worker was observed
exited and the result became `closed`. This short reviewer run does not claim
to exercise the held-old-stream case itself.

I/O controls monkeypatch Node builtins only inside the review process while
reading the real child's procfs entries. EACCES on its FD directory remains
unresolved. One FD-link ENOENT retries the inventory and stays pending; three
persistent attempts remain unresolved. A rehashed start-tick mismatch is refused.
Delayed real acquisitions verify resource closure. These are controlled error
injections, not kernel faults or hostile same-user tests.

The independent interruption control targeted the frozen handover fixture after
its stop marker and separately confirmed the old worker's `T` state in procfs.
The fixture returned exit 1, `success:false`, `interrupted:true` and SIGTERM after
approximately 122 ms. It reported resumed/stopped native processes, zero open
sockets, removed temporary root and no cleanup errors; the reviewer separately
confirmed the stopped worker's procfs directory was gone. No native process or
review prefix remains.

## Owner evidence inspected separately

The paired [candidate](../evidence/handover-fixed.json) and
[pristine](../evidence/handover-reference.json) reports each contain seven passing
cases at the frozen observer/fixture hashes. They exercise two workers, a real
held old response, an exactly identified SIGSTOP'd old worker retaining the
listener while a fresh new revision responds, SIGCONT followed by listener
absence while that worker and response remain alive, a second reload, exact old
response completion and native rejection of an invalid reload. The observer
reports pending then closed against the same snapshot hash. Both report native
SIGQUIT exit 0 and complete fixture cleanup.

The owner also reports 29 TAP passes for the isolated observer test file
(28 scenarios and one parent), including synthetic namespace/identity/refusal
cases and resource cleanup. Review read those test cases, but does not relabel
them as independently executed. The owner's
[handover interruption control](../evidence/handover-runner-verification.json)
is separate from the reviewer interruption above. Root owns the full aggregate
CLI and hosted CI gates; neither is supplied by this review.

## Frozen identities and limits

| File | SHA-256 |
| --- | --- |
| `x10/control/listeners.mjs` | `12bed6ad9137bb4d1209c737731f907403bfa1631d7738a521b6cf2b0efce2bb` |
| `x10/control/manager.mjs` | `65ce6e5f3ccd6099786abf0a6253309febef5bdefcfeba1849f86f2b394c83b9` |
| `x10/control/cli.mjs` | `7c6227f1f48ddc68bdfdf07e5a0b26b4387f34be1bfd9e9acacadcda8b8dad76` |
| `x10/test/handover-baseline.mjs` | `65b08954966cf53b23c3e1ee160030f38534a93342786ae2b5a12174d0f84612` |
| `x10/test/all.mjs` | `dab3514773962ece7c14550718a81e5b35956650533edc7ca61ae25656b371fd` |

The JSON records all inspected evidence/test hashes and the extracted validator
hash. Changing reviewed implementation or validator bytes requires rechecking
the affected conclusions. The native binary remained
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`.

Supported observations require one exact IPv4 listener inode. Wildcard, same-port
IPv6 or multiple matching listener inodes are refused; a single inode cannot
prove SO_REUSEPORT is disabled. Limits include 512 captured children, 10,000
fallback procfs entries, 4096 descriptors per process, 32,768 total inspected
descriptors, one-MiB TCP tables, a two-MiB snapshot and a shared three-second
elapsed-I/O budget. Filesystem syscalls themselves cannot generally be cancelled,
so this is not a hard wall-clock promise under a hung kernel/filesystem.

`closed` remains an observation about the captured process set at that time.
Unobserved respawns, later generations, later FD changes and sampling races are
outside that set. It establishes neither application health nor completion of
already accepted traffic, HTTP/2/QUIC drain, all-worker generation completeness,
linearizable cutover or rollback of application side effects. Snapshot hashes
detect accidental change and do not authenticate a hostile same-UID caller.
