# Local native configuration controller

This development tool coordinates **one explicitly managed HTTP server fragment**
in an existing NGINX configuration. NGINX remains the C data plane. The tool uses
Node 22 builtins, Linux `/proc`, native `-t`, SIGHUP and local HTTP probes. It
does not start NGINX, expose an administration API, install anything globally or
edit the operator's `nginx.conf`.

It is intentionally constrained: one loopback HTTP listener, an optional explicit
loopback HTTPS listener on the same managed server, one private prefix,
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
  "healthURL": "http://127.0.0.1:9000/health",
  "healthExpectedStatus": 200,
  "healthExpectedBody": "ready\n"
}
```

The backend must already be running. With this explicit contract, its health
response must finish with the declared status and exact UTF-8 body bytes.
`healthExpectedStatus` is an integer from 200 through 299;
`healthExpectedBody` is a well-formed string of at most 4096 UTF-8 bytes,
including the empty string. Both fields must be supplied together. Explicit
health responses exceeding 4096 bytes refuse the gate; bodies are not included
in mismatch diagnostics. Revision and health probes still require two
consecutive fresh observations of the same revision.

For compatibility, candidates with neither field keep their previous HTTP 200
requirement, unchecked response body and 64 KiB response bound. Their canonical
revision records and hashes do not acquire new defaults. Declaring an explicit
pair is recommended for application readiness; existing stored revisions do
not silently become stricter.

`healthURL` accepts only explicit `http://127.0.0.1:port/path`, on a
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

## Optional frontend HTTPS

A candidate can explicitly add a second, IPv4 loopback TLS listener while
keeping the existing HTTP listener and HTTP revision/readiness probes:

```json
{
  "serverBody": "location / { proxy_pass http://127.0.0.1:9000; proxy_next_upstream off; }",
  "healthURL": "http://127.0.0.1:9000/ready",
  "healthExpectedStatus": 200,
  "healthExpectedBody": "ready\n",
  "https": {
    "port": 8443,
    "certificate": "/home/alex/x10-certs/v1/server.crt",
    "certificateKey": "/home/alex/x10-certs/v1/server.key"
  }
}
```

`https` is optional and accepts exactly these three fields. The controller
renders `listen 127.0.0.1:8443 ssl`, the certificate references and TLSv1.2/
TLSv1.3. The existing `listen`/`include` containment guard still applies to
`serverBody`. Absent `https` preserves legacy revision inputs and fragments.
The TLS port must be an integer from 1024 through 65535, distinct from the
managed HTTP port and health backend port. The operator must also choose a port
distinct from every other configured listener, including the alpha demo health
server. This controller does not inventory arbitrary surrounding server blocks.

Use versioned certificate files in a separate operator-owned private directory,
outside the alpha installation. Each immediate containing directory must be
owned by the current UID with mode exactly 0700. Every ancestor must be a
directory owned by root or the current UID; group/other writes require the
sticky bit. The walk is bounded to 128 levels. Files must be owned regular
files of 1..256 KiB; the private key must have mode 0400 or 0600. Certificate
files must have mode 0400, 0600 or 0644 and use a distinct path from the key.
Paths must be simple, canonical, absolute ASCII paths of at most 4096 characters
without symlink aliases; spaces and escaped path syntax are
unsupported. Native `-t` validates the actual certificate/key pair. Node does
not copy the private key into revision records or the installation inventory.
Never put private keys or raw TLS diagnostics in Git or public evidence.

Apply a new candidate with new versioned certificate paths for rotation. Keep
the previous files available for revert, recovery and restart. Removing
`https` requests a new HTTP-only revision; old connections can drain under the
previous native generation. This is no immediate revocation or all-worker drain
guarantee. A revert creates a fresh revision using the old input and files.
The installation neither issues nor renews certificates and does not edit,
delete or restore their external files. In-place replacement is outside the
versioned-file operating procedure; path records do not freeze file contents
or protect against a malicious same-UID operator or check-to-use races.

After every apply, rotation, revert or restart, separately authenticate the
HTTPS endpoint with an explicit trusted CA and expected DNS name. For example:

```sh
curl --fail --cacert /home/alex/x10-certs/ca.crt \
  --resolve localhost:8443:127.0.0.1 https://localhost:8443/
```

The built-in HTTP health gate does not perform this TLS handshake, check client
trust, expiry or hostname, or continuously certify the HTTPS listener. Status
and successful apply alone are not TLS acceptance. Loopback binding remains;
this feature does not expose public administration, configure firewall/DNS,
activate a supervisor or accept the Production V1 service profile.

The installed/extracted lifecycle and client refusal checks run separately:

```sh
node --test --test-reporter=tap x10/test/frontend-tls.test.mjs
```

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
   and header, plus the declared health status/body contract carrying that same
   new ID (legacy candidates require HTTP 200 without body equality).
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

## Human status and native generation inspection

The existing JSON status remains the default. For operator-readable output:

```sh
node x10/control/cli.mjs status --state /home/alex/x10-run/.x10-control --human
```

The text separates an unbound or changed master, the observed revision header,
config/fragment differences, pending work and history. It suggests the next
inspection or recovery command. Presentation does not change the existing JSON
status exit semantics: an observation is not an application health or drain test.

To inspect native generations, explicitly start the native master with its
optional control endpoint (for example `-l unix:/home/alex/x10-run/control.sock`),
then select that endpoint:

```sh
node x10/control/cli.mjs inspect-generations \
  --state /home/alex/x10-run/.x10-control \
  --control-socket /home/alex/x10-run/control.sock
```

The command opens no listener. It sends a bounded GET and verifies the bound
master and registered files before and after observing its owned control socket.
The response must have the expected master scope, process identities and exact
decimal-string uint64 counters. A deliberately selected IPv4 loopback TCP API
can be inspected with `--control-address 127.0.0.1:PORT`; there is no automatic
transport fallback. Unix socket creation may be disallowed by the host kernel.
Native `available:false` is a diagnostic state. Even `available:true` does not
certify worker initialization, health, listener closure or accepted-stream drain.

## Recovery and boundaries

Output is JSON unless `status --human` was requested. An applied/bound operation has `ok:true`. An apply that is
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

### Sampled observation contract regression

The later fixture repair preserves the controller's existing acceptance gate.
An ordinary request immediately after `apply` or recovery is not required to
be the candidate: old and new native workers can temporarily share a listener.
The fixture now checks durable outcome, revision and pending state immediately,
then waits for an HTTP 200 with the expected application body and separately
for the exact reserved revision body/header. Those are separate fresh samples,
not a same-worker observation or an all-traffic cutover guarantee.

An explicitly synthetic loopback control scripts two successful candidate
revision/health rounds followed by an old application response. The original
one-shot assertion fails deterministically; bounded observation accepts only
the later expected response. Persistent old content, non-200 content, transport
failure, trickling responses and incorrect revision body/header/status remain
failures. Every fixture request has an absolute one-second deadline in addition
to its idle timeout. The observation loop has a six-second default budget;
an in-flight request can add roughly one request deadline, plus scheduling
and cleanup time. This is bounded fixture behavior, not a hard wall-clock SLA.

The original expected-B/actual-A native result remains recorded unchanged in
`continuum-source-capture.json`; its precise scheduling is not reconstructed.
This repairs a fixture overclaim, not the controller or native reload behavior.

The complete current file has 77 passing TAP checks: the prior 68 native
checks plus eight synthetic scenarios and their parent. Full local official
aggregate: 20/20 groups. Exact implementation hosted CI remains separate.

## Bounded controller record acquisition candidate

Controller disk records and control CLI JSON inputs now use the existing
installed `manager.mjs` module's `readBoundedText` helper. This changes record
acquisition before decoding/parsing; it does not change the durable event
format, revision integrity hashes, transaction/recovery rules or readiness
contract. The new code still needs exact hosted native compatibility evidence.

| Input | Maximum encoded file bytes | Oversize refusal |
| --- | --- | --- |
| Controller metadata: settings, state, pending transaction, event intent | 2 MiB (2097152) | `record_limit` |
| Immutable revision record | 8 MiB (8388608) | `record_limit` |
| Controller history JSONL | 16 MiB (16777216), retaining its existing cap | `history_limit` |
| Control CLI JSON file arguments, including settings/candidate/listener inputs | 2 MiB (2097152) | `input_limit` |

The revision budget leaves room for JSON escaping and metadata around the
existing bounded candidate body. These are encoded-byte limits, not character
counts. No runtime option silently raises them. A file already over its budget
is refused from metadata before allocating its content buffer or reading its
contents. Accepted descriptor size determines a finite buffer with one extra
byte to detect growth; there is no unbounded `readFile` fallback for these
records. Decode requires well-formed UTF-8 before JSON/JSONL parsing.

Acquisition requires an owned regular file with no group/other write permission.
The descriptor opens read-only with `O_NOFOLLOW | O_NONBLOCK`; a final-component
symlink or nonregular file is refused, not followed or accepted as an empty
record. This helper does not independently certify every ancestor directory;
the controller's existing canonical/private-prefix guards remain separate.
Existing accepted read-only modes remain valid. Stable hardlinks remain
supported: a positive link count is required and rechecked, rather than imposing
a new single-link restriction on historical records.

The helper compares device, inode, UID, mode, link count, size, mtime and ctime
between the selected path, opened descriptor, post-read descriptor and repeated
path observation. It also requires the number of bytes read to match the
original descriptor size. Identity/read inconsistencies refuse with
`record_changed`; a newly observed oversize or permissions violation keeps its
own refusal code. Malformed UTF-8 refuses with `record_encoding`.
Ownership/permissions retain their existing `unsafe_path`/`unsafe_permissions`
refusals. These are sampled
consistency checks under the trusted same-UID operator model, not an OS fence
against another same-UID process racing the files. Kernel/filesystem stalls
still have no hard wall-clock termination guarantee.

The helper does not repair, rename, chmod or rewrite a rejected record. Existing
controller lock, durable save and explicit recovery behavior still apply; a
record refusal does not authorize deleting locks, clearing faulted alpha state
or replaying an operation. Other binary, native configuration, certificate or
`/proc` reads are separate contracts: this change does not claim every read in
the controller or installed package is covered by this helper.

The focused pure/tempfile checks are:

```sh
node --test --test-reporter=tap x10/control/record-input.test.mjs
```

This test file also runs in the existing `managed-native-control` aggregate
suite. Its local pure/tempfile results do not establish physical durable
recovery, native process compatibility or full G4/G5/V1 acceptance; those
require the applicable supported hosted checks. No new bundle helper file,
native process or background service is introduced by the reader.

The checked-in source-pinned baseline reproducers under `x10/review/` remain
unchanged historical evidence. Their controller input/loader guards now
intentionally refuse the changed runtime source. To reproduce the accepted
oversized-settings and read-before-size-check observations, run them from a
separate clean checkout of `26d74c91ca4a3e95a5c3a93eeeae16bc278e2819`;
do not remove their pins or run them against a live installation. The separate
session/inventory capacity finding remains open.
