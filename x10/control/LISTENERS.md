# Captured-process TCP listener observation

`listeners.mjs` is an optional Linux diagnostic. It records a specific native
master's currently observable direct children and later checks whether those
captured processes still own one managed TCP LISTEN socket. It reads `/proc`
only: no process is signalled, no configuration changes, and no background
watcher or management endpoint is installed.

The scope is always `captured-processes-only`. Native reload may start a new
worker before an old worker processes its quit command. A fresh response from
the new configuration therefore cannot certify old listener closure. This
diagnostic observes that narrower boundary while an accepted old response may
continue. Neither capture nor inspection identifies a complete configuration
generation, proves all-traffic cutover, or validates application health.

## API and result

```js
const snapshot = await captureTcpListeners({ master, binary, port });
const observation = await inspectTcpListeners(snapshot, { master, binary, port });
```

`master` is the already verified controller binding: local `pid`, mount-view
`procPid`, `pidNamespace`, `startTicks`, `uid`, canonical `executable`, and the
SHA-256 of the master command title in `commandSha256`. All seven fields are
required. The module rechecks the actual master and the calling process's PID
and network namespaces. Its public API has no alternate proc root or fault
injection option.

The snapshot records its time, exact master binding, network namespace, port,
listener inode, and captured process identities plus their owning descriptor
numbers. A SHA-256 envelope detects accidental edits; it is not a signature
against a hostile process with the same UID. An empty process set or a set
without a captured listener owner is refused.

Inspection returns `state:"pending", closed:false` while any captured process
owns the socket, or `state:"closed", closed:true` when every captured process
is observed without it or has exited. Each process reports `owns-listener`,
`listener-absent`, or `exited`. These are sampled observations at the recorded
time, not guarantees about later descriptor acquisition or future traffic.

`listener_snapshot_invalid` rejects a malformed, changed or incompatible
snapshot. `listener_observation_unavailable` leaves an observation unresolved:
permission errors, unsupported namespaces/endpoints, changed identities,
ambiguous inodes, exhausted resource bounds, or persistent descriptor races
cannot become a successful closure report.

## Supported endpoint and identity

The endpoint is exactly IPv4 `127.0.0.1:port` with one distinct LISTEN inode in
the master's network namespace. A wildcard listener, any same-port TCP6
listener, or multiple matching IPv4 inodes is refused. A single inode does not
prove that every possible reuseport configuration has been detected; reuseport
and QUIC/UDP closure are outside the supported claim. The bound master must
retain that same inode during capture and inspection.

`/proc/<pid>/net/tcp*` identifies namespace socket state, not process ownership.
Ownership comes from the process's own `/proc/<pid>/fd` links. Captured children
must match parent, local/mount-view PID mapping through `NSpid`, UID, executable,
start ticks, PID namespace and network namespace. Identity is rechecked around
descriptor inspection. A changed/reused PID remains unresolved. Exit requires
two directory lookups reporting specifically ENOENT; other errors are not exit.
A closing descriptor's ENOENT causes up to three complete inventory attempts.

Capture first uses `/proc/<master>/task/<master>/children`. Kernels omitting
that file use a bounded numeric `/proc` scan and `PPid` classification instead.
Unreadable surviving entries make the fallback unresolved. Repeating the child
list catches observed churn but cannot prove that unobserved exits/respawns did
not occur between samples. Capture consequently never labels its set a complete
old generation. Check-to-use races remain without pidfds or native cooperation.

## Bounds and verification

Each call has a 3-second elapsed budget checked around procfs operations,
10,000 numeric proc entries, 512 captured children, 4096 descriptors per process,
32,768 total descriptor entries, 1 MiB per TCP table, and a 2 MiB snapshot limit.
Reads use bounded buffers and directory iteration stops at its entry limit.
Resources acquired just as the budget expires are closed. Node cannot forcibly
cancel every kernel filesystem syscall: a stalled kernel/procfs operation can
exceed wall-clock budget before returning. The module refuses an overdue result;
it does not claim a hard cancellation deadline for a hung kernel.

```sh
node --test --test-reporter=tap x10/test/listeners.test.mjs
```

The owner fixture has 28 synthetic procfs/fault scenarios plus one parent TAP
check. It redirects filesystem calls only inside the isolated test worker and
checks every acquired file/directory closes, including actual delayed acquisition
across the elapsed budget. These controls are separate from the actual native
reload and independent reviewer evidence linked from [STATUS](../STATUS.md).
