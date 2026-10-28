# Faulted or orphan native process: preserve first

This is an operator incident procedure for the declared Ubuntu24.04/x86_64,
Node22, trusted nonroot, local `systemd --user` profile. It uses existing X10
commands. **There is currently no supported command that repairs or clears a
faulted alpha lifecycle, reaps orphan workers, or makes that installation
uninstallable.** An orphan may still serve requests after its master exits.

A correct outcome can be **STOP_UNRESOLVED**: retain the original installation
in place, keep the private incident record, and leave the service unavailable
for a separately reviewed host-specific resolution. Do not turn an unknown
cleanup result into success. A conditional fresh HTTP restore below creates a
separate installation; it never repairs or releases the faulted one.

These are instructions, not a report that an incident or recovery was executed.
The source contract reviewed here is commit
`fbbcdff430a26542bdf650896cb19abe7fa97d36`. The
[release contract](../release/RELEASE-CONTRACT.md),
[current checkpoint](../continuum/BACKGROUND.json) and
[gates](../continuation-2026-10-24/GATES.json) retain the wider acceptance limits.

## 1. Stop changes and establish the incident scope

Keep the potentially live prefix at its original canonical absolute path.
Do not rename, move, replace, chmod, edit or remove it, its native executable,
Node, libraries, session records, PID file, sockets, locks, logs or unit files.
Renaming a live prefix breaks the executable/path identities used by the guards;
a sibling quarantine is an implementation detail of a successful guarded
uninstall, not an incident command.

Do not issue `run`, `prepare-run`, `bind`, `wait-bind`, `apply`, `revert`,
`recover`, `backup`, `stop` or `uninstall` against a faulted source. Do not start,
restart, reset-failed, remove or rewrite its unit during initial capture. No
`killall`, process-name matching followed by a signal, negative-PID/group signal,
manual lifecycle edit, stale-lock deletion, force uninstall or automatic reaper
is part of this procedure. `Restart=no` and `SendSIGKILL=no` are not proof that
all workers have exited.

Use the same UID, PID namespace and network namespace as the original supported
installation. Do not use sudo, change accounts, enter another namespace, change
journal ACLs/groups, enable linger, or alter credentials to make a check pass.
The current local development environment is unsuitable for physical native,
signal, process-group, systemd or network incident testing; execute an approved
physical procedure only on the supported authorized host.

Before any observation, have the following **preincident** private records:

- Exact canonical prefix, its device/inode/UID, installation ID, the complete
  session registry, immutable package hashes/modes and recorded Node identity.
- Exact owned unit name, original fragment/link paths and bytes, expected user
  manager/cgroup, last known invocation, launcher PID/start ticks/command and
  native master identity including proc PID, namespace PID, PID/network namespace,
  UID, executable, start ticks, command hash and session prefix/config.
- Known controller revisions/binding, declared proxy/health ports, Unix control
  socket, external application/readiness resources and their separate owner.
- A preexisting confirmed declarative HTTP backup and its independently retained
  byte count/hash, protected location and source revision. The backup is required
  only for the restore branch; absence does not prevent preservation/diagnosis.

Do not reconstruct ownership from a PID file, current process name, stale
lifecycle JSON, journal marker, successful HTTP response or a newly calculated
checksum alone. If any required identity was not retained, cannot be reconciled
with current source/host facts, or conflicts with another operator, record
**STOP_UNRESOLVED**. Do not guess a unit name, session or process group.

Create no files inside the old prefix. Keep incident material outside it in a
new, disjoint, canonical, owned mode0700 directory with safe ancestors. Files
must be private0600. Raw paths, PIDs, namespace IDs, command lines, configuration,
backups and journal messages can be sensitive: keep them private, never paste
raw captures into Git, an issue, a public artifact or a chat report. Diagnostic
copies of changing records are not a consistent backup.

## 2. Make bounded, read-only observations

Use trusted installed OS tools and a trusted Node with reviewed identities.
Start from a trusted clean shell; unsetting variables after untrusted code was
loaded cannot undo its effects. Before these examples, exclude unreviewed Node,
dynamic-loader, locale/pager and remote D-Bus overrides for **all** tools,
including timeout, ps and ss. The capture wrapper starts its diagnostic process
with an empty environment and fixed PATH/locale. For later Node commands, use
the same trusted environment; at minimum remove these explicit inherited names:

```sh
unset NODE_OPTIONS NODE_PATH NGINX_CTRL LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
unset LD_DEBUG LD_DEBUG_OUTPUT GLIBC_TUNABLES GCONV_PATH LOCPATH
unset SYSTEMD_PAGER SYSTEMD_PAGERSECURE PAGER DBUS_SESSION_BUS_ADDRESS
unset DBUS_SYSTEM_BUS_ADDRESS XDG_RUNTIME_DIR
```

Do not run executable content obtained from the faulted prefix merely because
its name looks familiar. Stop if tools, permissions or complete observations
are unavailable; a denied read is not absence.

The examples below are Bash command specifications on the authorized host.
Replace the placeholders from already verified private records, not through
`eval`, shell parsing of logs or command substitution of untrusted JSON:

```sh
x10_old_prefix=/absolute/private/original-install
x10_incident=/absolute/private/new-incident-directory
x10_node=/absolute/verified/node22
x10_unit=x10-lifecycle-REPLACE_WITH_RECORDED_TOKEN.service
x10_uid=REPLACE_WITH_VERIFIED_NONROOT_DECIMAL_UID
x10_proc_pid=REPLACE_WITH_RECORDED_PROC_PID
x10_front_port=REPLACE_WITH_CONFIRMED_PROXY_PORT
x10_health_port=REPLACE_WITH_CONFIRMED_HEALTH_PORT
```

Require canonical paths, the current real/effective UID equal to `x10_uid`, a
recorded proc PID greater than1, validated distinct high ports, and the exact
recorded unit. An unset/example value is **STOP_UNRESOLVED**. The fixture-style
unit name shown is an example, not permission to select another matching unit.

For a concrete bounded capture, the following convenience function writes only
new private diagnostic files outside the old installation. It is not an X10 CLI
or an identity validator. It must be used only with the explicit read-only
commands below. Bash `ulimit -f` uses1024-byte units in this supported shell.
The file cap applies separately to stdout and stderr; it does not authenticate
or parse either stream. Before calling it, independently verify that the incident
directory and ancestors remain canonical and safely owned, and exclusively
controlled by the trusted operator. Require **every** intended stdout/stderr/exit
path to be absent, including a dangling symlink or special file. Noclobber is
not O_NOFOLLOW and does not exclude every nonregular-file/race case. If another
same-UID actor can race the paths, STOP_UNRESOLVED; this shell convenience does
not provide an OS-level fence.

```sh
x10_capture_readonly() (
  umask 077
  set -C
  x10_label=$1
  shift
  case "$x10_label" in
    unit|recipe|namespace|proc|listeners|unix|journal) ;;
    *) exit 1 ;;
  esac
  for x10_suffix in stdout stderr exit; do
    x10_output="$x10_incident/$x10_label.$x10_suffix"
    if [ -e "$x10_output" ] || [ -L "$x10_output" ]; then exit 1; fi
  done
  ulimit -f 256 || exit 1
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=1s 3s "$@" \
    > "$x10_incident/$x10_label.stdout" \
    2> "$x10_incident/$x10_label.stderr"
  x10_query_rc=$?
  printf '%s\n' "$x10_query_rc" > "$x10_incident/$x10_label.exit" || exit 1
  exit "$x10_query_rc"
)
```

Use a new capture directory for a repeated complete observation; noclobber
refuses reuse. After every call, check the directory identity again and use
read-only no-dereference file metadata to require all three outputs to be owned
regular files, singly linked, mode0600, with stable device/inode/UID/mode/size
identities around reading. A symlink, special file, unexpected owner/link/mode
or changed identity is STOP_UNRESOLVED. Do not repair or remove it. Check every
invocation's exit status, the saved status, file sizes and completeness before
using it. A nonzero/timeout/signal, missing status, nonempty stderr, stdout or stderr reaching262144bytes, partial last
record, missing/duplicate property or unparseable value is **UNKNOWN**, hence
**STOP_UNRESOLVED**. Do not pipe through `head`, discard stderr, ignore a status,
or accept a truncated inventory. A file-size limit is a recording bound;
kernel/filesystem stalls have no guaranteed hard termination deadline.
The timeout affects only its diagnostic command/process group, never the X10
unit or a native process selected from the capture. Never use this wrapper with
a mutating command such as systemctl stop/start/restart or an installed lifecycle
command.

Before querying, apply the existing [preflight prerequisites](preflight.mjs):
`/usr/bin/systemctl` must be canonical, a safe root-owned regular executable;
`/`, `/usr`, `/usr/bin`, `/run` and `/run/user` must be canonical safe root-owned
directories without group/other write or special modes. `/run/user/UID` must be
canonical, owned by that UID and mode0700; its canonical `bus` must be a socket
owned by the same UID. A clean environment alone does not validate an endpoint.
Do not redirect to a remote/inherited bus or create/replace a missing one.

Then query the current UID's local manager with a clean environment and the
exact retained unit, using a finite property set. `--all` preserves intentional
empty property values; an absent key is never interpreted as an empty value:

```sh
x10_capture_readonly unit /usr/bin/env -i \
  PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  XDG_RUNTIME_DIR="/run/user/$x10_uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$x10_uid/bus" \
  /usr/bin/systemctl --user --no-pager --no-ask-password show --all "$x10_unit" \
  --property=Id --property=LoadState --property=ActiveState \
  --property=SubState --property=Result --property=MainPID \
  --property=ControlPID --property=InvocationID --property=ControlGroup \
  --property=FragmentPath --property=UnitFileState --property=Job

x10_capture_readonly recipe /usr/bin/env -i \
  PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  XDG_RUNTIME_DIR="/run/user/$x10_uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$x10_uid/bus" \
  /usr/bin/systemctl --user --no-pager --no-ask-password show --all "$x10_unit" \
  --property=ExecStartPre --property=ExecStart --property=ExecStartPost \
  --property=ExecStop --property=Restart --property=KillMode \
  --property=KillSignal --property=SendSIGKILL

x10_capture_readonly namespace /usr/bin/readlink \
  /proc/self/ns/pid /proc/self/ns/net

x10_capture_readonly proc /usr/bin/ps -eo \
  pid,ppid,pgid,sid,uid,lstart,comm,args

x10_capture_readonly listeners /usr/bin/ss -ltnp \
  "( sport = :$x10_front_port or sport = :$x10_health_port )"

x10_capture_readonly unix /usr/bin/ss -lxnp
```

The first manager query must return each requested key exactly once and no
unexpected keys. Reconcile `Id`, fragment/link file identity and bytes, local
user-manager cgroup, Node/launcher commands, invocation, MainPID and ControlPID
with the preincident inventory. Inspect the exact fragment/link with read-only
file tools; never follow an unexpected link. Recipe properties must match the
retained accepted recipe. On this systemd255 profile, `show --all` represents
no job as the present empty property **`Job=`**, not `Job=0`. The
[version255 systemctl show implementation](https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c)
formats a positive job ID as a decimal value and a zero ID as empty; the
[version255 manual](https://www.freedesktop.org/software/systemd/man/255/systemctl.html)
explains why `--all` is needed to retain empty properties. Any nonempty `Job`
is STOP_UNRESOLVED. A missing property, unfamiliar serialization or another
unreviewed manager/tool version is UNKNOWN; do not infer no queued activation
from MainPID0. Record the property again immediately
before the restore/activation gates; no single snapshot excludes a future race.
Unknown overrides, active restart policy, enabled or queued activation, a foreign
cgroup or a substituted fragment are unresolved.
A unit with `MainPID=0`, `inactive` or `failed` is **not** proof of worker absence.
An empty invocation after exit does not identify an earlier invocation; use the
retained one for historical journal correlation, and record that distinction.

Treat the process/socket listings as discovery aids, never signal authority.
For every retained launcher/master and any candidate worker, read the exact
`/proc/PROC_PID/{status,stat,cmdline,cgroup}`, `exe`, `ns/pid` and `ns/net`
without changing them. Compare UID, proc PID versus namespace PID (`NSpid`),
start ticks, executable, command/prefix/config, group/cgroup and namespaces to
the original identity. Do not treat `ps`'s human start time as start ticks.
Repeat the file/namespace/process observation around the manager observation;
changed, unreadable, ambiguous or reused identities remain UNKNOWN. Inspect
all recorded sessions, not just the registry's current session.

In the existing [runtime helpers](../alpha/runtime.mjs), `inspectMaster`
refuses ambiguous/reused identities and namespace mismatch;
`remainingNativeGroup` checks the recorded group and refuses unresolved members.
They do not signal processes and are not a public faulted-recovery command.
A process outside the sampled group, a hidden process or a permission-denied
inventory cannot be declared absent from an empty list. `ps`, a cgroup path,
a PID file and the helpers do not provide an OS fence against a same-UID race.

Read the old `.alpha-install.json`, `.alpha-registry.json`, **every** registered
`runs/SESSION/lifecycle.json`, controller settings/state/history/revisions,
PID/control-socket metadata and both alpha/controller lock paths without
modifying them. Bound each record to its source contract, validate its exact
shape, ownership, mode, identity and applicable consistency hash, and compare
repeat reads. Alpha manifest/registry/lifecycle and revision records have
checksums; controller `state.json` is not universally checksummed. A valid hash
is neither evidence that the record is fresh nor authentication of its author.
A pending transaction/event intent, changed input/history, unknown file, partial
record, live lock owner or unexplained stale lock is **STOP_UNRESOLVED**. Do not
remove a lock even if its recorded PID appears gone.

Compare recorded Node and host-library paths, bytes, hashes and modes with the
retained inventory. Read the exact native executable's current identity and
its mapped libraries where observable. A replaced/deleted executable, changed
library, missing map or inaccessible identity prevents using the old installed
code as diagnostic authority. Never repair the old hash record to match drift.

Installed `info`, `status` and `history` are **not passive capture commands**:
they acquire the alpha lock; `status` can also send a revision HTTP request.
Do not call them while any old startup/operator/lock owner may exist. The
no-alpha-lock `package-info` and `service-unit` paths verify their own limited
contracts, may refuse dependency drift, and do not establish lifecycle health,
full inventory freshness, worker exit or resource absence. No such result clears
a faulted lifecycle. Do not run `recover` as a diagnostic: controller recovery
can write state and request reload/rollback; it does not repair alpha lifecycle.

A journal is optional diagnostic context, not an absence or health proof. If
readable without extra permissions, query only the exact retained UID, unit and
invocation. Request a129th sentinel entry and reject a result with more than128
entries; do not hide an oversized observation by truncating it. Do not use a glob
or another invocation:

```sh
x10_invocation=REPLACE_WITH_RETAINED_32_LOWERCASE_HEX_INVOCATION
x10_capture_readonly journal /usr/bin/env -i \
  PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  XDG_RUNTIME_DIR="/run/user/$x10_uid" \
  /usr/bin/journalctl --no-pager --quiet --output=json \
  --output-fields=MESSAGE,_UID,_SYSTEMD_USER_UNIT,_SYSTEMD_INVOCATION_ID \
  --lines=129 "_UID=$x10_uid" "_SYSTEMD_USER_UNIT=$x10_unit" \
  "_SYSTEMD_INVOCATION_ID=$x10_invocation"
```

Check every returned record's correlation fields and complete JSON framing.
No records, denied reads or missing invocation mean **journal UNKNOWN**, not
that no process ran. A prior `running` marker does not prove current readiness.
The source [journal observer](journal-check.mjs) brackets its bounded queries
with fresh ownership checks; its private fixture-only unit-name contract must
not be silently expanded to confer authority on an arbitrary incident unit.

## 3. Choose an honest outcome

| Observation | Required outcome |
| --- | --- |
| Live orphan/native worker, live launcher/hook, live socket, held lock, active or queued unit operation | STOP_UNRESOLVED; preserve original path and records. This runbook does not reap it. |
| Any unknown/conflicting/reused identity, namespace, dependency, record, port or owner | STOP_UNRESOLVED; do not signal, restart, remap ports or delete data. |
| `stop_pending`, unknown exit or failed/unconfirmed cleanup | STOP_UNRESOLVED; a stop timeout is not a confirmed stop. |
| Faulted record but current processes/resources appear gone | Keep the faulted installation in place. Absence does not clear lifecycle; only consider the separate restore branch after every prerequisite below. |
| No preincident confirmed compatible HTTP backup | Preservation/diagnosis only; STOP_UNRESOLVED for restore. Do not try to create a backup from the faulted source. |
| Complete trusted input/backup and independently established old-resource absence | A fresh prepared restore may be created conditionally; the old installation remains retained and faulted. |

A master PID's disappearance is insufficient: the existing alpha test explicitly
observes an orphan worker still serving after master SIGKILL. Its test-owned
process-group cleanup is fixture code, **not an operator recovery recipe**.
Do not copy its signal into this runbook. Restoring configuration does not undo
requests, uploads, external database changes, messages or any other side effect.

## 4. Conditional fresh HTTP restore

This branch is available only when all of the following are independently
confirmed in the same trusted nonroot host context:

1. The faulted installation remains unmodified in place. No old launcher,
   hook, native master/worker/group or owned cgroup member remains, and no
   original owned Unix socket, alpha/controller lock or pending manager job
   can act on the old installation. No automatic/queued activation can race
   the operation. Missing preincident inventory, inaccessible process/socket
   views or a possible same-UID concurrent writer makes this UNKNOWN.
2. The backup is the preexisting, previously confirmed HTTP configuration for
   the intended source revision, not a new file synthesized from the incident.
   Its original byte count/hash and trusted provenance agree. Its parent is
   canonical owned0700; the file is canonical, singly linked, owned0600, at
   most2MiB and in the supported exact declarative-backup format. Hashes are
   consistency checks, not signatures, encryption or authentication.
3. Review the exact backed-up `serverBody`, `healthURL`, expected readiness
   status/body, proxy port and health port. Both original **X10-owned listeners**
   are free and no old socket/group can reacquire them. All other referenced
   listener paths/ports and external files are understood and safe. The
   external upstream/readiness application has its own confirmed owner and
   expected compatibility; it may need to remain running. Do not stop or
   remap an upstream merely to make a blanket 'all ports absent' claim.
4. The exact checked schema2 extracted package, trusted Node22 and compatible
   current dynamic host libraries are available and reviewed for this host.
   An expiring Actions artifact is not a permanent versioned release. The
   archive digest must come from an independently trusted record, not solely
   a sidecar fetched with untrusted bytes. The package's payload checksums do
   not establish publisher authenticity, security or ABI compatibility.
5. Choose a disjoint new canonical absolute prefix that does not exist, under
   an existing safely owned private parent. It must neither contain nor sit
   inside the faulted prefix, backup, extracted bundle or incident directory.
   Do not reuse the original prefix, session, controller state, binding or unit.

If any prerequisite is unknown, stop. There is no fallback port override. A
fresh prefix does not authorize concurrent service while orphan ownership or
original resources are unresolved.

Before extraction, use the existing trusted archive verifier; it is a checkout
verification tool, not an installed-bundle command:

```sh
"$x10_node" /absolute/trusted/checkout/x10/release/verify-alpha-archive.mjs \
  --archive /absolute/private/nginx-x10-linux-alpha.tar.gz \
  --sha256 VERIFIED_ARCHIVE_SHA256
```

Require exit0, `valid:true`, `code:archive_consistent`, `schemaVersion:2` and
the intended archive/bundle/native/payload identities from the actual verifier
result. Extract only those verified
unchanged bytes into a separate new private location with the checked payload
modes preserved. If extraction or any identity is ambiguous, retain the result
and stop; never overwrite another tree or adjust unexpected payload modes.
The extracted installer revalidates its own fixed inventory.

Restore through the checked extracted install command, using no overrides:

```sh
x10_bundle=/absolute/private/checked-extraction/nginx-x10-alpha
x10_new_prefix=/absolute/private/new-restored-install
x10_backup=/absolute/private/confirmed-backups/preincident-http.json
"$x10_node" "$x10_bundle/install.mjs" install \
  --prefix "$x10_new_prefix" --restore "$x10_backup"
```

Do not add `--port`, `--health-port` or `--upstream-port`: restore refuses them
and preserves the declared ports and exact input. Extracted-bundle installation
also refuses `--binary` and `--manifest`; source-checkout overrides are not a
substitute for this checked-package procedure. Repeated/malformed options are
refused. Do not edit the backup to evade the guard or remap external paths.

The installer executes native `-t`, which may open referenced external files.
Only trusted reviewed configuration and safe referenced resources may reach
this step. It does not start the daemon, but it is not arbitrary-data-only
parsing. TLS backup/key/PKI restore is unsupported. Application data, external
files/services, runtime processes, locks, pending operations and old history
are not included or replayed.

Record the command's actual exit status and full private finite result. If it
fails or its result is uncertain, preserve any newly created prefix; do not
blindly retry or recursively erase it. A successful result must identify
the selected new `prefix`, new `session`/`sessionPrefix` and `revision`, with
`declarativeRestored:true`, `nativeStarted:false`, `readinessChecked:false`, `serviceAccepted:false` and
`productionAccepted:false`. The install result has **no installationId field**:
separately read the checked new `.alpha-install.json` installationId, reconcile
it with the new registry/lifecycle, and compare it to the retained old manifest.
Confirm fresh prepared lifecycle, null runtime and control socket, null controller binding/pending, exact restored input/ports,
one initialized-unbound history entry and the intended checked package/Node/
library identities. New identities must differ from those of the original.

Only against the **new**, known unstarted, unlocked installation may the
existing inspection commands be used for this prepared-state check:

```sh
"$x10_node" "$x10_new_prefix/bin/x10" package-info
"$x10_node" "$x10_new_prefix/bin/x10" info
"$x10_node" "$x10_new_prefix/bin/x10" status
"$x10_node" "$x10_new_prefix/bin/x10" history
```

These commands do not turn configuration restore into accepted service. A
prepared installation with null binding does not prove application readiness.

## 5. Separate activation and retention

Recheck every old identity/resource/lock and the exact original ports immediately
before any activation. Require the same trusted operator to prevent concurrent
changes; this is procedural coordination, not a kernel fence. Unknown facts or
any newly live resource mean STOP_UNRESOLVED. Do not start a second server to
probe whether an unresolved orphan still owns the ports.

On a separately authorized supported service host, obtain the new installation's
own recipe with its recorded Node:

```sh
"$x10_node" "$x10_new_prefix/bin/x10" service-unit --auto-readiness
```

This prints JSON containing a proposed unit; it does not activate a service.
Validate `ok:true`, `outcome:service_unit_generated`, `activationPerformed:false`
and the complete expected recipe. Do not redirect the JSON itself into a
`.service` file or substitute a checkout-generated recipe for a refused installed
one. The [service instructions](README.md) and
[user-unit source](user-unit.mjs) define the supported guarded path. A separate
operator activation must use only a fresh exact owned unit/link and the checked
Node, with `prepare-run`, `run`, bounded `wait-bind`, `Restart=no`,
`KillMode=process` and `SendSIGKILL=no`; do not enable persistent autostart or
change the host to bypass unavailable prerequisites.

After activation, require fresh unit/invocation, launcher/native/session/binding
identities, successful bounded installed readiness with the exact expected
status/body, and the intended revision. Independently verify the approved
idempotent application path and complete fresh traffic bytes. Do not replay
recorded incident POSTs or use retrying mutating probes. Manager 'active', native
`-t`, a journal marker or a demo self-check is insufficient. A health or identity
refusal is a failed/unaccepted restored service, not permission to rebind or
relax readiness. Use only its separately accepted guarded stop procedure when
its current identities are known; otherwise STOP_UNRESOLVED and retain both
installations. This document has not exercised that entire incident path.

The original installation remains faulted and retained even after a successful
separate restore. Do not edit its stage to `stopped`, remove its registry entry,
use another launcher to uninstall it, or delete it manually. An external host
intervention that stops an orphan does not make the old alpha lifecycle eligible
for uninstall. Record old-prefix retention as **retained/unresolved**, never as
'all owned cleanup confirmed'. Do not remove backup, known-good package or
private incident evidence until a separate reviewed retention/disposal decision.

## Source and acceptance map

| Contract or observed control | What it establishes here | What it does not establish |
| --- | --- | --- |
| [alpha CLI](../alpha/cli.mjs): `installed`, `lifecycle`, `stopped`, `prepareRun`, `stop`, `uninstall`, main dispatch | Exact identity/inventory gates, faulted refusals, lock behavior and no lifecycle-clear command | A way to clear faulted state, reap workers or force removal |
| [runtime](../alpha/runtime.mjs): `inspectMaster`, `remainingNativeGroup` | Read-only strict process/namespace/group checks and conservative unknown handling | A signal capability, exhaustive portable orphan reaper or same-UID OS fence |
| [alpha CLI](../alpha/cli.mjs): `backup`, `readBackup`, `install`, restore argument guards | Prepared/stopped-only export, bounded private HTTP backup, fresh unbound restore and override refusals | Backup of faulted runtime, TLS/application data or automatic port remapping |
| [controller](../control/manager.mjs): `recover`, `status` | Pending/intent recovery is distinct; status may inspect runtime and request a revision | Repair of alpha lifecycle or passive no-I/O diagnostics |
| [alpha test](../test/alpha.test.mjs): actual master SIGKILL/orphan case | Scoped fixture observes worker still serving and run/stop/uninstall refusing `abnormal_exit` | Production orphan cleanup; its test-owned signals are not this runbook |
| [restored service receipt](../evidence/g4-restored-service-hosted.json) | Separately accepted same-package HTTP restored-service fixture | Faulted-source/orphan incident recovery, TLS backup or fullG4/V1 |
| [kept-A fallback receipt](../evidence/g4-kept-a-fallback-hosted.json) | Separately accepted controlled unhealthy distinct B → explicit kept-A HTTP fallback with known owned cleanup | Arbitrary crash/orphan recovery, complete failure containment or automatic production fallback |

Independent review of this procedure and source-backed stop cases is a document
and boundary result. Full faulted/orphan recovery, full G4/G5 security acceptance,
fullG3/V1, native-binary upgrade, TLS restore, permanent publication, independent
published replay, the60-minute soak and semantic Continuum remain open. Existing
c2/6401 failures, local cleanup FAIL_UNKNOWN and CLA failures remain historical
adverse evidence; later success or this runbook does not erase or explain them.
