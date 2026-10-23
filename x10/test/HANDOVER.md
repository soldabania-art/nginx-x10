# Native TCP listener observation during reload

This Linux loopback fixture distinguishes a fresh response from a new
configuration, closure of a captured old worker's TCP listening descriptor,
and completion of that worker's already accepted response. Those are separate
events. No production C code or default reload behavior is changed.

```sh
node x10/test/handover-baseline.mjs
node x10/test/handover-baseline.mjs \
  --binary x10/.build/baseline/nginx --output x10/.build/handover-reference.json
```

`--binary` or `X10_NGINX_BINARY` selects the native executable. Node hosts only
the local upstream fixture, assertions and `/proc` observations. The native
profile must already be built. Missing Linux `/proc` support, inaccessible or
ambiguous identities, failed assertions and incomplete cleanup cause a nonzero
exit and `success:false`, rather than a passing skip.

## Seven case groups

| Case | Required observation |
| --- | --- |
| Native validation | Actual `nginx -t` for the isolated two-worker configuration |
| Old stream and listener | Exact first response bytes, native `$pid` and revision A, uniquely resolved worker identity and actual ownership of the managed TCP LISTEN inode |
| New response while old listener remains | Only that identified old worker receives SIGSTOP; fresh revision B is served by another native worker while the stopped worker still owns the original listener. The optional observer reports `pending`. |
| Listener closure before response completion | SIGCONT resumes the old worker; it remains alive with the accepted response held open, but its managed listening descriptor is absent. The observer reports the captured process set `closed`. |
| Second reload during old drain | Fresh revision C is served after a second actual HUP while the original response remains held open |
| Exact old completion | Releasing the upstream yields exactly `first:old\nlast:old\n`, after listener closure and both reloads |
| Rejected reload | An actual syntax-invalid HUP is logged as rejected; four fresh requests retain the last valid revision C |

The listener observer captures exactly the two native workers before the first
reload. That snapshot is checked while the held-stream worker is stopped,
after it resumes and closes its listener, and after the second reload. The
fixture also performs its own independent fd/inode observation of the exact
held-stream worker, rather than inferring descriptor closure from the observer's
summary or a process title. Process start ticks, UID, executable, parent and
PID/network namespace are checked around descriptor reads. Local signal PIDs
are mapped through `NSpid`; they are not assumed to be `/proc` directory names.

## Scope and cleanup

The real native source contracts are reviewed in
[handover-boundaries.md](../review/handover-boundaries.md): successful HUP starts
new workers before requesting old shutdown, and a quitting TCP worker closes
listening descriptors while continuing active work. The optional external
[observer](../control/listeners.mjs) reports only its captured processes. It
does not label later or previously unseen processes with a native generation ID.
Its `closed` result is not an all-worker generation fence or all-traffic atomic
cutover. This fixture deliberately does not induce respawn or process-set churn.

Only private IPv4 loopback TCP is covered. QUIC/UDP, reuseport, HTTP/2, keepalive
or pipelined accepted requests, production traffic, platform matrices and late
module initialization failures require their own checks. Worker shutdown and
proxy-read policies are bounded to 20 seconds; the fixture has a 30-second
overall deadline. These limits do not establish preservation of arbitrarily
long application streams.

Every exit path requests SIGCONT for the isolated native process group before
bounded SIGQUIT/TERM/KILL cleanup. No unrelated process is signaled. All client
and upstream sockets are tracked, destroyed and required to close; the private
prefix is removed. A passing run requires a normal native exit code zero under
SIGQUIT. Interruption is always a failed suite. Diagnostic progress on stderr
identifies the point at which the owned old worker is observed stopped, allowing
an independent interruption control to test that cleanup path.

The native log is checked for unexpected error/critical/alert/emergency entries.
The deliberate invalid directive is recorded separately. In restricted
root-in-user-namespace fixtures the native `initgroups(..., 0)` call can log
`Operation not permitted` while retaining the invoking UID; that precise known
environment diagnostic is retained separately and is not a production fix.

JSON records the selected binary bytes and `-V`, harness/observer and relevant
native-source hashes before/after, exact process and listener identities,
all observer reports, native diagnostics and cleanup. These are local
consistency records, not signed source-to-binary attestations or a performance
claim.

## Recorded evidence

On 23 October 2026, the frozen harness and observer passed all seven groups on
both the [candidate](../evidence/handover-fixed.json) and
[pristine baseline](../evidence/handover-reference.json). Both record two
captured workers, `pending` while the old stream worker is stopped, `closed`
after resumption while its accepted response remains live, normal SIGQUIT exit
zero, zero tracked sockets and a removed temporary prefix. The binaries retain
their separately recorded SHA-256 identities; the same behavior on both builds
does not constitute a new native C improvement.

The [runner interruption control](../evidence/handover-runner-verification.json)
sent SIGTERM only after stderr confirmed that the owned old worker was stopped.
The fixture returned exit 1 and `success:false`, requested SIGCONT, cleaned up
the native group, sockets and prefix, and left the native process group absent.
That expected failure is a separate control, not another passing handover case.
