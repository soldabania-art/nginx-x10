# Local native configuration controller

This development tool coordinates **one explicitly managed HTTP server fragment**
in an existing NGINX configuration. NGINX remains the C data plane. The tool uses
Node 22 builtins, Linux `/proc`, native `-t`, SIGHUP and local HTTP probes. It
does not start NGINX, expose an administration API, install anything globally or
edit the operator's `nginx.conf`.

It is intentionally constrained: one loopback HTTP listener, one private prefix,
one self-contained `serverBody`, and one explicitly selected loopback health
backend. Arbitrary native configuration elsewhere remains available to the
operator, outside this fragment boundary. This is not yet a remote control
plane or a general configuration editor.

## Setup

Run as the same ordinary Linux user that owns the native master and the private
prefix. The prefix must already exist with mode `0700`, without symlink
ancestors. Config, fragment and PID file are distinct direct children of that
prefix. Paths use letters, digits, `/`, `.`, `_`, `+`, `-`; spaces are unsupported.
Initialize before starting NGINX: the managed fragment and PID file must not
already exist.

For example, the operator creates `/home/alex/x10-run/nginx.conf`:

```nginx
daemon off;
master_process on;
worker_processes 1;
pid /home/alex/x10-run/nginx.pid;
error_log /home/alex/x10-run/error.log notice;
events { worker_connections 1024; }
http {
    access_log off;
    include /home/alex/x10-run/managed.conf;
}
```

The include must appear exactly once as its own unquoted absolute-path line.
The tool verifies this boundary and native syntax; it does not parse every
operator directive or recursively freeze external includes. Avoid overlapping
listeners and reserved routes in the surrounding operator configuration.

Create `settings.json`:

```json
{
  "prefix": "/home/alex/x10-run",
  "binary": "/home/alex/nginx-x10/x10/.build/objs/nginx",
  "config": "nginx.conf",
  "fragment": "managed.conf",
  "pidFile": "nginx.pid",
  "port": 8088,
  "gateTimeoutMs": 3000
}
```

Create `candidate.json`, selecting a real readiness endpoint for the application:

```json
{
  "serverBody": "location / { proxy_pass http://127.0.0.1:9000; }",
  "healthURL": "http://127.0.0.1:9000/health"
}
```

The backend must already be running. Its health response must finish with HTTP
200. `healthURL` accepts only explicit `http://127.0.0.1:port/path`, on a
different port from the managed server, without credentials, query or fragment.
The tool does not follow redirects. This health endpoint is chosen by the
operator; it does not automatically prove every application route or peer is
healthy.

`serverBody` is trusted operator input, limited to 1 MiB. Balanced containment is
checked and directive names must be unquoted/unescaped. `listen` and `include`
are rejected. The controller owns its enclosing `server`, loopback listener,
`/__x10_revision` and `/__x10_health` locations; duplicate reserved locations
fail native validation. Quotes in normal directive arguments are supported.
This limited checker is not an NGINX parser or a sandbox for hostile config.

```sh
node x10/control/cli.mjs init --spec settings.json --file candidate.json
```

Start the native master explicitly in another terminal, using the exact
canonical binary and separate absolute `-p`/`-c` arguments:

```sh
/home/alex/nginx-x10/x10/.build/objs/nginx \
  -p /home/alex/x10-run/ -c /home/alex/x10-run/nginx.conf
```

Then bind and manage it:

```sh
node x10/control/cli.mjs bind --state /home/alex/x10-run/.x10-control
node x10/control/cli.mjs apply --state /home/alex/x10-run/.x10-control --file candidate.json
node x10/control/cli.mjs status --state /home/alex/x10-run/.x10-control
node x10/control/cli.mjs history --state /home/alex/x10-run/.x10-control
node x10/control/cli.mjs revert --state /home/alex/x10-run/.x10-control --revision REVISION_ID
```

Every activation, including a revert or rollback, receives a new unpredictable
revision ID. Revert reuses a stored revision's input, not its old runtime ID.
`init` leaves an unbound desired revision; `bind` confirms the explicitly
started native master and its readiness before enabling changes.

## What apply confirms

1. Acquire an exclusive file lock. Verify private ownership, unchanged main
   config, pinned binary bytes, managed fragment and revision/history hashes.
2. Persist an immutable revision and a pending transaction; replace only the
   managed fragment through a synced temporary file and rename.
3. Run the exact registered native binary with `-p`, `-c`, `-t`. A rejected
   candidate restores the previous fragment before any HUP, provided the files
   and runtime still match the journal. An external conflict is left untouched.
4. Recheck native master identity immediately before SIGHUP. Success from a
   signal command is not treated as a reload acknowledgement.
5. Require two consecutive fresh HTTP connections with the new revision body
   and header, plus HTTP 200 from a health response carrying that same new ID.
   The health location bypasses inherited proxy cache/store, forces bodyless GET
   and disables buffering and ignored client aborts. It does not forward probe
   client headers or follow redirects. Probes have an absolute 350 ms deadline
   as well as an idle timeout and 64 KiB response cap.
6. Recheck files/master again before committing the confirmed revision. On a
   failed health gate, attempt a fresh activation of the last confirmed input,
   validate it and verify its new probe/health ID. A conflict or failed restore
   remains pending/ambiguous and blocks further changes.

Private state contains mode `0400` revision files, a SHA-256 history chain and
synced state/pending records. Each new history event also has a durable
`event-commit.json` intent containing its before/after state, exact next record
and envelope hash. The write order is intent, append/sync history, replace/sync
state, then remove/sync intent. These detect accidental changes and incomplete
operations; they are not signatures against a malicious process with the same
UID. Atomic writes sync the file and directory. Normal commands refuse an
unfinished event commit with `commit_pending`; reconciliation is explicit.

An I/O error in event persistence or terminal pending cleanup is reported as
`event_commit_incomplete`. The caller does not overwrite a matching pending
stage with `ambiguous` or start another rollback merely because a durable write
reported failure. Explicit recovery still validates the actual files; this error
code does not claim that the original apply succeeded or that the failure left
a recoverable intent.

Existing schema-1 state, revision and history files remain supported without a
rewrite or migration. New in-flight events gain the additional intent. An old
history/state mismatch without such an intent remains refused; the tool does
not invent a missing before/after snapshot for a historical crash.

The PID file is resolved through `NSpid` and the exact PID namespace inode, then
checked against UID, canonical `/proc/.../exe`, start ticks and native master
command line. Both local and `/proc` IDs are recorded. This matters when `/proc`
is mounted from an ancestor PID namespace. Run future commands in the same PID
namespace. Node has no `pidfd_send_signal` here: a residual race remains between
the last identity check and `kill`. Restarting or replacing the bound master or
binary deliberately requires operator intervention; automatic rebinding is not
implemented.

## Explicit listener diagnostics

The separate [Linux listener observer](LISTENERS.md) records the specifically
identified current native children and their ownership of the managed TCP
listener. Capture before an apply and inspect the saved output afterward:

```sh
node x10/control/cli.mjs snapshot-listeners --state /home/alex/x10-run/.x10-control > before.json
node x10/control/cli.mjs apply --state /home/alex/x10-run/.x10-control --file candidate.json
node x10/control/cli.mjs inspect-listeners --state /home/alex/x10-run/.x10-control --file before.json
```

Both commands use the existing lock, bound-master identity and file guards.
They refuse an unbound master or unresolved transaction. A successful inspection
returns `ok:true` with `observation.state` equal to `pending` or `closed`;
`ok:true` alone does not mean closure. Unavailable or changed identities produce
an error. The commands send no signals and do not alter apply, rollback or
recovery acceptance. A snapshot covers captured processes only: it cannot
identify every old configuration generation, rule out intervening respawns,
certify health or establish an atomic all-traffic cutover. See the observer's
supported endpoint, namespace, resource and elapsed-budget limits.

## Recovery and boundaries

All output is JSON. An applied/bound operation has `ok:true`. An apply that is
rejected, rolled back or ambiguous has nonzero CLI status; inspect `outcome`.
A successful durable reconciliation has `ok:true,outcome:"reconciled"` and exits
zero: this means recovery succeeded. Its `recordedOutcome` preserves whether the
original operation was `applied`, `bound`, `rejected` or `rolled_back`; recovery
success does not turn a rejected apply into a successful apply. `status`
distinguishes the last confirmed revision from a pending transaction and an
observed runtime revision.

A killed controller can leave both a lock and pending journal. **No stale lock
is automatically deleted.** First inspect `lock` and confirm the specific
operation is no longer running. An operator may then remove that lock. If
manually changed files conflict with the journal, inspect and reconcile them
to known revision bytes before recovery:

```sh
node x10/control/cli.mjs recover --state /home/alex/x10-run/.x10-control
```

Recovery first handles an exact interrupted event commit, if present. It
requires a valid envelope, event-specific state/revision/pending relationships,
and history at exactly the before or appended-record boundary. Before advancing
or merely deleting the intent, it rechecks config/binary/fragment bytes, the
bound native master identity, and fresh revision/health probes. A candidate that
was once healthy but is unhealthy now stays unresolved. A valid unbound initial
event can be completed after native syntax validation; it remains unbound.
Recovery appends or replaces only the missing durable stages. A complete
history line is re-synced before state advancement even if it is already
visible: the earlier append may have succeeded while its fsync failed. If the
after-state is already visible, recovery syncs that file and its directory
before removing the intent. A failure in these existing-file sync retries
leaves history/state/intent bytes unchanged; the intent remains for inspection
and retry. Recovery never truncates history. If a terminal event already
completed but pending removal was interrupted, exact terminal record/revision relationships and fresh runtime
checks permit clearing that pending record without another activation.
Repeating recovery after completion returns `nothing_pending`.

For a consistent nonterminal pending transaction, recovery validates and freshly
activates the last confirmed input. Its result is `rolled_back`, with nonzero
CLI status recording the failed original transaction; a subsequent `status`
shows the confirmed recovery. Unknown bytes, partial/noncanonical history
records, contradictory snapshots, changed operator config/binary or stale
master identity are refused. Do not erase pending/history/intent to make an
unknown state appear successful. An unbound bad initial configuration has no
automatic runtime recovery; inspect it before starting or binding the master.

Native configuration testing and reload can create files, affect shared zones,
listeners or other resources before final success. This controller **does not
provide general ACID semantics**, power-loss-proof distributed state, or proof
that every old worker has exited. Sampled fresh revision probes establish the
observed generation; inherited module policies and external includes still
need operator review. Only the main config's bytes and the managed fragment
are guarded; external include files, referenced credentials and application
state are outside that hash guard. Concurrent edits by the same trusted user
remain subject to filesystem check-to-use races.

The candidate is reloaded before its health gate, so it can serve requests while
being checked. A failed candidate may have handled traffic before rollback;
rollback does not undo requests or application side effects. Two fresh generation
probes do not provide a linearizable all-traffic cutover: fresh connections can
temporarily reach the prior generation during native handover.

Recovery covers the recorded event intent/history/state boundaries and a
completed terminal event whose pending removal was interrupted. It does not
claim every crash or power-loss point. Partial history writes, missing or
malformed intents, and an old mismatch without an intent require operator
inspection. Reported failures in the event persistence block retain its matching pending
transaction for inspection/retry. An already contradictory intent from an older
controller remains refused; recovery does not infer or rewrite its old stage.
An immutable revision created before a killed operation recorded its intent can
remain orphaned and is never adopted merely because it exists.

## Verification

```sh
node --test x10/test/control.test.mjs
X10_NGINX_BINARY=/absolute/path/to/nginx node --test x10/test/control.test.mjs
```

The real native fixture covers bind and namespace identity, valid apply,
syntax rejection, URI-keyed inherited cache plus cacheable healthy origin,
inherited POST override, bounded trickle response, verified rollback/revert,
concurrent operator conflict, lock refusal, path/config/revision/history
integrity and a real killed CLI followed by explicit recovery. It uses native
master/workers and local synthetic HTTP endpoints; it is not a load test.
Fixture cancellation relays termination to its own native process group.

The durable event fixture additionally reproduces the previous controller's
history/state mismatch after a real SIGKILL, then exercises intent, history,
state and intent-removal boundaries for `applied`; the history boundary for
`bound`, `apply_started`, `rejected` and `rolled_back`; and a second SIGKILL
inside recovery. It checks idempotence, conflicting config, stale identity,
health regression, partial history, hash-valid invalid transitions/record shapes,
and present falsy/array journals that must never be treated as absent. These
are process-interruption tests after actual filesystem sync calls, not simulated
power loss or a full storage-failure matrix. Frozen milestone-2 evidence stays
unchanged; the additional run is recorded separately.


The storage-failure fixture adds real initialization SIGKILL cases at synced
intent, history, state and intent-removal boundaries. Reconciliation keeps the
initial revision unbound; the tests then explicitly start and bind a real native
master and apply another revision. Ordinary initialization I/O failure retains
its cleanup behavior for the controller state and fragment. Native `-t` may
leave an empty PID file without starting a daemon. Inspect that side effect and
confirm no master is running before manually removing it for a new `init`;
the controller does not automatically delete an existing PID file.

[Storage evidence](../evidence/control-storage-fixed.json) adds 32 scenarios,
including two explicitly expected prior-controller failure observations. The
milestone-4 controller file had 66 TAP checks: 63 scenarios and three parents.
The new evidence records two
counterexamples against the previous controller: a rejected event's reported
I/O failure poisoned an otherwise matching pending stage, and recovery could
skip a failed history fsync merely because the line was visible. New terminal
fault cases inject a single EIO before a write/sync/rename/unlink or after a real
sync, while partial-append cases actually write and sync a strict record prefix.
Failed history/state sync retries preserve the files and intent; successful
retry is idempotent. These are subprocess filesystem fault injections, not
kernel/hardware faults, complete storage-failure coverage or power-loss proof.

The current file adds two explicit listener CLI cases: capture and pending
inspection with tamper rejection, then captured-process closure after apply.
The [listener controller record](../evidence/control-listeners-fixed.json)
contains the first parent's 18 successful behavior scenarios, exact source
hashes and pre/post source consistency; the complete controller now has 68 TAP
checks including three parents. The separate observer file has its own 29 TAP
checks. Neither count represents a number of improved native protocol features.
