# Captured TCP listener observation: design and limits

Reviewed on 23 October 2026 at development commit
`4024ef43d1e10e4079d54651036ee2daec424e29`. This document proposes a bounded
manual diagnostic. It does not change native C, apply/rollback policy or the
meaning of existing health acknowledgment. No new runtime experiment was
performed by this design review; runtime proof belongs to the separate fixture.

## Chosen next step

Provide explicit capture and later inspect/wait operations for one managed
loopback IPv4 TCP listener and the specifically identified processes captured
before a reload. An operator can capture, perform the normal apply, then inspect
whether those captured processes still own that listener. The observer never
starts a daemon, exposes a management listener or sends a process signal.

The result must carry `scope: "captured-processes-only"`. A successful released
observation means only that the exact captured identities were observed exited
or without the exact captured listener inode. It is not a complete generation
fence, a claim about every newly accepted request, or a guarantee that no worker
was missed by process-set churn. Already accepted connections can remain alive.

Default apply/revert/recover acknowledgment remains sampled revision and health.
Observation failure is diagnostic failure; it must not trigger a reload,
rollback, TERM/KILL, forced stream closure or a durable "applied" event.

## Native contracts read

| Contract | Source | Consequence |
| --- | --- | --- |
| The master reaps children before processing HUP; a successful reload spawns the new cycle, sleeps 100 ms, then sends old children QUIT. | `src/os/unix/ngx_process_cycle.c`: `ngx_master_process_cycle`, `ngx_reap_children` | A pre-HUP process list can miss an old-cycle respawn. New readiness can precede old-worker listener closure. |
| `exiting` is set in the master after channel delivery or successful signal delivery. | `src/os/unix/ngx_process_cycle.c`: `ngx_signal_worker_processes` | `exiting:true` acknowledges a request to quit, not execution of the close path. |
| A worker marks itself exiting, sets the optional shutdown timer, closes listeners, closes idle connections and continues active work. | `src/os/unix/ngx_process_cycle.c`: `ngx_worker_process_cycle` | Waiting for process exit would unnecessarily wait for active streams. |
| TCP close removes accept events, closes worker descriptors and sets their cycle-local fd to -1. Some QUIC descriptors are intentionally retained. | `src/core/ngx_connection.c`: `ngx_close_listening_sockets` | FD ownership is a useful TCP observation; do not generalize it to UDP/QUIC. |
| The master reuses matching listener descriptors across cycles. | `src/core/ngx_cycle.c`: `ngx_init_cycle` | A listener still visible in a network namespace or the master is expected. Only each child's descriptor inventory answers child ownership. |
| Optional native control JSON exposes process name, PID and the master's `exiting` flag; its reload builds a cycle before later worker startup/shutdown processing. | `src/os/unix/ngx_control.c`: `ngx_control_show_processes`, `ngx_control_reload_config`; master control branch | Neither existing endpoint supplies a generation ID or a listener-close ACK. Do not open the control API implicitly. |
| Native process slots are reused, and respawn returns before resetting all slot flags. | `src/os/unix/ngx_process.c`: `ngx_spawn_process` | A slot or PID alone is not a durable process identity. |

The master channel endpoints already use `FIOASYNC`/`F_SETOWN`, but the present
master loop does not drain worker-side close-ACK messages. A new channel command
alone would not implement reliable native acknowledgment. Generation stamping,
both reload paths, respawns, binary upgrades, short/error writes, retries,
master reception and stale slot/PID handling need an explicit native contract.
That broader change is deferred from this diagnostic milestone.

## Snapshot and guards

The manager wrapper should use the ordinary controller lock, canonical state
and private-directory guards, immutable revision/config validation and existing
bound-master verification. It can return a snapshot to the caller; inspection
must validate all snapshot fields and bounded lengths before touching `/proc`.
No state/history/pending records are advanced by this diagnostic. A caller-held
JSON snapshot is not an authenticated attestation; a hash, if supplied, detects
accidental changes only.

Capture a supported single matching TCP LISTEN inode for exact `127.0.0.1:port`
in the bound master's network namespace. Resolve the endpoint using that
namespace's TCP table, then intersect it with `/proc/<pid>/fd` socket symlinks.
`/proc/<pid>/net/tcp` is a network-namespace view, not a process FD inventory.
Use string inode values rather than potentially lossy JavaScript numbers.

Multiple matching listener inodes, relevant wildcard/IPv6 ambiguity or an
unresolvable endpoint are unsupported/unresolved. A `/proc` observation cannot
prove that SO_REUSEPORT is disabled when only one matching inode exists. State
the supported single-inode condition instead of claiming exhaustive reuseport
detection. Do not silently widen this operation to arbitrary ports or UDP.

Record the exact master identity and every captured direct-child identity with:

- `/proc` directory PID, local PID resolved through `NSpid`, parent `/proc` PID;
- start ticks, UID, executable, PID-namespace inode and network-namespace inode;
- which captured children own the managed socket inode and their FD numbers;
- observation timestamps and explicit process-set-churn limitations.

Use the bound master `/proc` PID for PPid comparisons, not the PID-file number.
This environment can mount `/proc` from an ancestor PID namespace. Require
verified controller/master/child namespace relationships and the supported UID
policy. Wrong/unreadable namespaces, another UID or executable, and malformed
identity records are unresolved. Human-readable process titles can be useful
diagnostics, but they cannot identify a configuration generation or prove close.

Inspect identities before and after descriptor enumeration. Check child lists
around capture to expose observed churn; two matching scans still do not prove
that no short-lived child existed between scans. Preserve that limitation even
when all captured owners later release the socket.

## Races and outcomes

| Observation | Required behavior |
| --- | --- |
| Same captured identity still owns the captured inode | `pending`; continue only within the absolute observation deadline. |
| Same identity has a fully readable FD inventory without that inode | `released` for this captured process, even when accepted streams remain active. |
| Captured process authoritatively exited | Record `exited` separately; it satisfies only this captured identity's release. |
| PID exists with different start ticks/namespace/executable/UID | `identity_changed`/unresolved; never inspect or signal the new occupant as the captured process. |
| A single FD symlink vanishes during enumeration | Descriptor churn, not proof of process exit; retry the inventory within a small bounded retry budget. Exhaustion is unresolved. |
| FD directory/process identity disappears | Recheck process identity/existence. Count exited only when disappearance is established, not from an arbitrary ENOENT inside `/fd`. |
| EACCES/EPERM, malformed/truncated data or other I/O error | Unresolved failure, never an empty inventory or exited result. |
| Master binding, namespace or managed endpoint/inode changes | Unresolved failure; do not reinterpret a different listener as the captured listener. |
| New child appears after capture | Report it as outside the captured set; do not silently classify it as old or new generation. |
| Deadline or resource bound reached | Explicit timeout/limit result, non-success; no signals or automatic recovery. |

Zombie processes may have no descriptors, but state and identity still need an
explicit check. Keep "exited", "released while alive", "pending" and
"unresolved" distinct. A master disappearance is not successful handover.

Apply independent caps to snapshot bytes/entries, `/proc` entries inspected,
captured children, TCP-table bytes/rows and FDs per process. Concrete initial
limits can be conservative (for example 10,000 `/proc` entries and a few thousand
FDs per captured process), provided they are documented and exceeded limits fail
explicitly. Check a monotonic absolute deadline throughout scans and retries;
one fresh deadline per process would accidentally multiply the total budget.
Node filesystem syscalls themselves have no general cancellation guarantee, so
avoid describing the deadline as a hard wall-clock bound under a hung kernel or
filesystem. Do not leave unbounded parallel enumeration running after timeout.

## Required evidence

1. Capture a real old worker with an active response; delay that worker's quit
   handling. Show fresh new-revision responses while inspection remains pending.
   Resume normally, observe its listener FD gone while the old response remains
   open, then finish the exact old response body. No production C modification
   is needed for this fixture; narrowly scoped SIGSTOP/SIGCONT belong only to
   owned test workers and require unconditional resume/cleanup.
2. Exercise multiple workers, process exit and repeated capture/inspect. Keep
   the result explicitly restricted to captured identities.
3. Countercheck a snapshot of a live listener owner as pending, so an observer
   that always returns released cannot pass the fixture.
4. Reject malformed snapshots, reused PID/start ticks, different master/network
   namespace, unreadable FD state, ambiguous listener inodes, size/count limits
   and exhausted descriptor-race retries before claiming success. Synthetic
   filesystem controls must be labeled separately from real process evidence.
5. Verify CLI failure/interruption does not alter managed config, state/history
   or process liveness, and leaves no fixture children/sockets/prefixes.

The old-worker SIGSTOP experiment demonstrates the specific readiness/listener
gap. It does not prove arbitrary scheduler behavior, all accepted HTTP/1
pipelining/keepalive traffic, HTTP/2 GOAWAY, QUIC drain or a full cutover fence.

## Reviewed native source identity

These hashes cover the files containing the contracts read above; they do not
mean every line or platform branch in each file was re-reviewed in this pass.

| File | SHA-256 |
| --- | --- |
| `src/os/unix/ngx_process_cycle.c` | `b8811ead5647f9cfc76f3085f4f57e622e434f403de2ca7aa131d33442fdbda6` |
| `src/os/unix/ngx_process.c` | `5097cec7f4a3e95c766b31692eb4e9b16fb00ffa11e5c750d7f6bc93bd9d01f5` |
| `src/os/unix/ngx_process.h` | `7098dfaa875fd04aff122c344f0dfa72bad5fb5f572b7177d30766303b3f27f6` |
| `src/os/unix/ngx_control.c` | `69fd6f589cabc38ccc4131d102078c4c2ac2697259985e329dcd09d757d9c094` |
| `src/os/unix/ngx_channel.c` | `6827d833cb07eabe9e43995d40f52eba8f1b8b74e968798a98083ceaa0fac2ee` |
| `src/os/unix/ngx_channel.h` | `31a3065d083fb98177451ed0bba4f19c7a7c763d48f0be88234101376d2823c6` |
| `src/core/ngx_connection.c` | `56896a9af65da2f4246a47ff27c4772ad6b0e3137752c65c997ffa6675d61c11` |
| `src/core/ngx_cycle.c` | `9f4474071bc95db1e0b51e4db39c12bad09be0ac126760b3643f95abe95f9ad6` |
