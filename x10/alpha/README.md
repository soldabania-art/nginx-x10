# Local Linux alpha

This installs the checked native NGINX build and a local operator CLI into a
new private directory. Node 22+, Linux `/proc`, compatible dynamic libraries,
`ldd`, and the chosen free IPv4 loopback ports are required. NGINX serves all
HTTP traffic; Node only runs installation and operator commands. No sudo,
system service or global files are used. This is an experimental local alpha,
not a production package or a measured 10× performance improvement.

From the repository after its existing build:

```sh
node x10/alpha/cli.mjs install --prefix "$HOME/nginx-x10-alpha" --port 8088 --health-port 8089
```

The prefix must be new, absolute, canonical and contain only simple path
characters (no spaces). Its existing parent must be safely owned or a sticky
temporary directory. Symlinks, including ancestor aliases, are rejected.
`--manifest FILE` selects a full build manifest; optional `--binary FILE` must
match its exact binary. Source installation verifies native source/build inputs,
`-V`, binary hash, generated files, module list and host dynamic dependencies.
The installed binary, helper modules, licenses and build record are checked on
subsequent commands. Hashes are consistency checks, not signatures.

In terminal one:

```sh
"$HOME/nginx-x10-alpha/bin/x10" run
```

`run` keeps native `daemon off` in the foreground, with explicit private `-p`
and `-c`. It first prints `native_starting` with an explicitly unverified
candidate PID, then `outcome: running` after identifying its own master. In a
second terminal, replace `X10` below with the absolute installed launcher:

```sh
X10="$HOME/nginx-x10-alpha/bin/x10"
"$X10" bind
"$X10" status --human
curl http://127.0.0.1:8088/
"$X10" apply --file "$HOME/nginx-x10-alpha/examples/candidate-b.json"
"$X10" history
"$X10" revert --revision ID_FROM_HISTORY
"$X10" recover
"$X10" info
"$X10" stop
```

The first response is `NGINX X10 local alpha` plus newline. The bundled example
changes it to `NGINX X10 updated local alpha`. Its JSON has `serverBody` (a
managed server's body, without `listen`/`include`/other server blocks) and
`healthURL`. The generated second native server answers
`http://127.0.0.1:8089/__x10_demo_self_check`. This is a demo self-check only;
it does not establish health of an upstream application. `status` uses JSON by
default; `--human` labels its revision-header observations and unperformed
health/drain checks. See the controller documentation for gate/recovery limits.

## Optional loopback application upstream

A new installation can explicitly select an HTTP application instead of the
native demo response:
Stop any earlier installation using the same ports before starting this one.

```sh
x10_app_prefix="$HOME/nginx-x10-app"
node x10/alpha/cli.mjs install --prefix "$x10_app_prefix" --port 8088 --health-port 8089 --upstream-port 9090
```

The three ports must be distinct decimal unprivileged ports, 1024..65535.
`--upstream-port` always means `127.0.0.1`; it does not accept a hostname,
URL, credentials or a remote administration endpoint. Omit it to preserve the
existing demo mode. Installation prepares configuration and records its inputs;
`installed` does not mean that an application exists or has passed a health gate.

For an operator-owned application listening on that port, provide an idempotent
`GET /ready` endpoint. The managed `/` location proxies HTTP/1.1 to it with
`proxy_next_upstream off`; this example does not automatically retry requests.
New application-mode installations require `/ready` to finish with HTTP 200
and exactly `ready` followed by one newline. Both the initial input and bundled
candidate set `healthExpectedStatus: 200` and `healthExpectedBody: "ready\n"`.
Application readiness is sampled through the managed native listener at
`http://127.0.0.1:8088/__x10_health`. Bind/apply gates require HTTP 200 and the
current revision header and the exact configured response bytes, bounded to
4096 bytes. This checks the declared endpoint contract; it does not prove
database/business readiness. An operator-owned candidate can declare another
successful status/body pair; both fields are required together. Legacy candidates
with neither field retain their previous HTTP 200/body-unchecked behavior and
64 KiB response bound. The separate native demo self-check on port
8089 remains available and can return 200 while the application is unavailable.
`status` observes runtime/revision state; it does not continuously recheck
application readiness. Use an explicit current request when needed.

An optional example application is included in the verified immutable helper
inventory. In one terminal, after installation:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
node "$x10_app_prefix/lib/alpha/upstream-example.mjs" --port 9090
```

Wait for `outcome: upstream_example_listening`. The example listens only on
IPv4 loopback. `GET /ready` returns `ready` plus newline; `GET /` returns
`NGINX X10 upstream example` plus newline. `POST /echo` echoes at most 16 MiB
with at most four active echo requests; `GET /stream` produces 8 MiB with
backpressure. These are bounded example routes, not an authenticated application,
a supervisor or an accepted Production V1 service.

In a second terminal, keep the native foreground launcher running:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
"$x10_app_prefix/bin/x10" run
```

After its verified `running` event, use a third terminal:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
"$x10_app_prefix/bin/x10" bind
curl --fail --show-error http://127.0.0.1:8088/__x10_health
curl --fail --show-error http://127.0.0.1:8088/
printf 'payload\n' | curl --fail --show-error --data-binary @- http://127.0.0.1:8088/echo
"$x10_app_prefix/bin/x10" apply --file "$x10_app_prefix/examples/candidate-b.json"
"$x10_app_prefix/bin/x10" history
```

In application mode, `candidate-b.json` keeps the same upstream and readiness
URL and adds `X-X10-Example: application-b`; it does not replace the proxy with
a demo response. Revert using a real recorded revision ID. Restart preserves
only the checked last-confirmed input and still needs an explicit new bind;
it does not transfer a live connection or guarantee continued app readiness.

Stop native through `bin/x10 stop`, wait for its foreground launcher to exit,
and stop the example in its own terminal with Ctrl-C before uninstalling.
The example handles its own sockets with bounded shutdown; it never reaps
unrelated processes. The existing same-UID, ABI, state, unknown-file and
uninstall restrictions below still apply.

A verified stop permits another `run`. Each run uses a new `runs/<session-id>`
private directory and controller state. Only a hash-verified last-confirmed
input is transferred. Bind explicitly to the new master. Old configurations,
revision journals and histories stay in their old session directories; `history`
shows the current session, and `info` identifies it. Pending, conflicting or
modified state blocks restart until inspected/recovered. No automatic rebind
or process-lifetime continuation is claimed. The registry has a 256-session
schema ceiling, but cumulative inventory headroom can refuse preparation earlier;
256 is not a verified operational capacity guarantee.

The native control API stays closed by default. For explicit private Unix
inspection only, start with an absent socket directly inside the installation:

```sh
"$X10" run --control-socket "$HOME/nginx-x10-alpha/control.sock"
# another terminal, after bind:
"$X10" inspect-generations --control-socket "$HOME/nginx-x10-alpha/control.sock"
```

Unix socket denial fails startup; there is no TCP fallback. Generation metadata
is native bookkeeping, not worker readiness or complete listener-drain proof.

`stop` checks the recorded PID namespace, network namespace, UID, executable,
start ticks, command hash, explicit prefix/config and pidfile before SIGQUIT.
It waits at most five seconds and reports remaining drain without forced kill.
Ctrl-C/termination of the foreground launcher requests the same checked graceful
stop. Run operator commands in the same PID/network namespaces. A stale alpha
lock is preserved for manual inspection. Node has no pidfd signal primitive,
so an unavoidable verification-to-signal race remains; a trusted same-UID
operator must not race changes to the private directory or processes. Ownership
and checksums do not isolate a malicious same-UID actor.

Changed host libraries block new starts and mutating controller operations.
Inspection, guarded stop and uninstall remain available and report drift;
prepare a fresh installation for the updated host ABI. Libraries are never
modified by these commands.

Once all sessions are stopped, `"$X10" uninstall` validates the full known
inventory and removes that installation through an owned sibling quarantine.
It refuses unknown files, symlinks, changed immutable/configuration/revision
records, pending transactions or nonempty native temporary directories. It
never follows a symlink out of the prefix. Known native logs and retained
validated session histories are intentionally removed by explicit uninstall;
copy them first if needed. Abnormal native exit (including master SIGKILL) is
recorded as `faulted` and blocks automatic stop/restart/uninstall: orphan
workers may still serve requests. Inspect these processes and retained records
manually; this alpha is not an orphan reaper. Startup cancellation after native
spawn requests the same verified SIGQUIT and waits a bounded five seconds.
Unresolved startup cleanup is preserved and reported.

Use the [faulted/orphan incident runbook](https://github.com/soldabania-art/nginx-x10/blob/34f713c411b73fdf1e10337c4539f35b64a31235/x10/service/INCIDENT-RUNBOOK.md)
before acting on an abnormal exit. Preserve the original prefix in place.
This pinned source document is available from an extracted bundle as well:
the bundle does not include the runbook itself. The link does not establish
a permanent accepted package release or physical incident recovery acceptance.
Installed `info`, `status` and `history` acquire locks; `status` may also make
an HTTP revision observation. They are not passive initial diagnostics.
There is no supported command to clear `faulted` or force uninstall it.
Fresh HTTP restore needs a preexisting confirmed backup and independently
safe original listener/resources; unknown facts require `STOP_UNRESOLVED`.

A failed/incomplete installation is preserved for
operator inspection rather than recursively erased.

## Local bundle

```sh
node x10/alpha/cli.mjs pack --output x10/.build/dist/nginx-x10-linux-alpha.tar.gz
# On a compatible Linux host, in an existing private directory:
tar -xzf nginx-x10-linux-alpha.tar.gz
node nginx-x10-alpha/install.mjs install --prefix "$HOME/nginx-x10-alpha" --port 8088 --health-port 8089
# Or choose an absent application-mode prefix and a separate app port:
node nginx-x10-alpha/install.mjs install --prefix "$HOME/nginx-x10-app" --port 8088 --health-port 8089 --upstream-port 9090
```

An extracted bundle verifies its own allowlisted payload and needs no original
git checkout or build tree. An application-mode install can run the shipped
`lib/alpha/upstream-example.mjs` exactly as above; the original checkout is not
needed. It contains native binary, exact CLI helpers,
LICENSE/NOTICE and an allowlisted provenance record, without live configuration,
state, PID, namespace or logs. It still requires Node and compatible host dynamic
libraries; it is not a universal portable/static package. Checksums are unsigned
consistency records. Binary debug/configure metadata can contain build paths.
Local bundles stay ignored; published CI artifacts must come from the public
hosted runner checkout, not this private workspace.

There is no accepted permanent versioned alpha download in these instructions
yet. A locally packed archive or expiring CI artifact is not a permanent release.
Use the exact checked candidate that contains `--upstream-port` and the new
example; earlier bundles must not be assumed to contain them. G2 distribution
and independent replay from a published archive remain separate acceptance gates.

Run `node --test --test-reporter=tap x10/test/alpha.test.mjs` for actual native
installation/lifecycle/restart, tamper, refusal and bundle extraction checks.


## Exact hosted application-upstream checks

Implementation `eb4e2de3` passed the expanded alpha40/extracted-bundle path and
required native/Unix checks in exact hosted CI. [Receipt](../evidence/g2-upstream-hosted.json)
records actual artifacts, source/build identities, skips and limitations.
Local AF_UNIX creation was refused with EPERM; hosted success does not resolve
or bypass that local environment restriction.

This is implementation compatibility, not an accepted permanent alpha release.
A versioned permanent archive and independent nonroot Node22 replay from the
published files remain pending. The operated service, TLS, package upgrade/
rollback/recovery, security, frozen soak and Production V1 gates stay open.


## Installed startup wait-bind (G3 partial)

After launching an installed alpha, the operator may use:

```sh
/absolute/recorded/node /absolute/private/alpha/bin/x10 wait-bind --timeout-ms 10000
```

This installed command waits for the existing run command to finish startup.
It releases the alpha lock between startup observations so native identity can
be recorded, then attempts the existing controller bind once. It is not a
retry loop for unhealthy applications, integrity failures, changed identity,
stopped/faulted sessions or unexpected session replacement. Existing `bind`
behavior and old installations are preserved; an old installed CLI without
this command requires a newly verified installation.

The startup budget is monotonic and bounded; it reserves time for the existing
readiness gate before starting bind; with less than four seconds remaining it
refuses before the attempt. Filesystem/kernel stalls are not a hard
real-time guarantee. A deadline or cancellation arriving during bind cannot
undo a durable controller commit: an explicit ambiguous result requires status
and identity inspection, not a blind retry. No process is signalled by wait-bind.
Do not interpret missing success as proof that the controller stayed unbound.

The generated systemd recipe does not automatically invoke this command yet.
Actual user-manager startup/stop/restart, readiness cancellation and failed-start
cleanup, slow drain, TLS and published-file target acceptance remain gates.
G3 and Production V1 are not completed by this helper.


## Exact hosted wait-bind compatibility

Implementation `3b293c57` passed exact hosted native checks, including the
expanded installed alpha cases. [Receipt](../evidence/g3-wait-bind-hosted.json)
keeps actual artifacts and build identities distinct from source events.
This verifies the helper's narrow compatibility, not automatic systemd readiness
or service/TLS acceptance. The local first native19/20 observer ESRCH remains
unresolved; later CI success is neither a local repair nor a historical fix.
Which captured-process observation failed remains unknown. Late/cancelled bind
may have committed, and the inspection/runbook restrictions above still apply.


### Verified HTTPS upstream: bounded test profile

The managed listener remains loopback HTTP. An operator-owned candidate can
proxy to an HTTPS application using the existing native configuration body.
It must explicitly enable `proxy_ssl_verify on`, set an operator-provided CA
with `proxy_ssl_trusted_certificate`, enable `proxy_ssl_server_name on`, and
set `proxy_ssl_name` to the expected certificate DNS name. Connecting to
`127.0.0.1` does not remove the certificate-name check. Keep
`proxy_next_upstream off` to avoid implicit request replay.

The CA file is operator-controlled trust material outside the immutable
installation inventory; it is not shipped in the bundle or authenticated by
its checksum. Keep it in a protected operator directory outside the installed
prefix. The HTTPS application owns its certificate and private key. Never put
private keys in release evidence or Git. Certificate/trust rotation requires
its own verified reload and operational procedure.

The reproducible acceptance command, after the documented native build, is:

```sh
node --test --test-reporter=tap x10/test/alpha-tls.test.mjs
```

This test packs and extracts the alpha, installs it separately, and uses only
owned loopback endpoints and temporary CA/key material. Its HTTP readiness
relay probes the managed `/ready` route through the HTTPS upstream. It does
not probe `__x10_health` recursively. A plain application health endpoint that
bypasses HTTPS cannot establish TLS readiness. The relay is a test fixture,
not an installed production health service.

This profile verifies upstream TLS only. It does not enable incoming HTTPS,
change the managed `listen` guard, operate a user service, authenticate a
permanent published release, or accept Production V1. Exact CI and supported
nonroot service/deployment acceptance are recorded separately.

### Optional managed incoming HTTPS

A newly verified bundle containing the frontend TLS extension can add
`https: { "port": 8443, "certificate": "/absolute/private/certs/v1/server.crt",
"certificateKey": "/absolute/private/certs/v1/server.key" }` to an operator
candidate. Apply it through the installed `bin/x10 apply --file` command after
startup and bind. This adds an IPv4 loopback HTTPS listener to the managed
server and retains its existing HTTP listener. It does not change arbitrary
`listen` permission in `serverBody`, enable a public listener, or make an old
installed bundle gain new code. See the [controller contract](../control/README.md#optional-frontend-https)
for the exact file/port guards and certificate lifecycle.

Keep operator-owned versioned certificate/key files outside the installation;
their immediate directory must have mode 0700 and their key mode 0400 or 0600.
Choose the TLS port distinct from every configured listener, including the
demo health server and application. Retain earlier certificate versions for
revert/restart/recovery; uninstall never owns these external files. Rotation
uses a new candidate with new versioned paths, followed by an authenticated
HTTPS client check with an explicit CA and expected DNS name. There is no
automatic certificate issuance, renewal, external-file rollback or expiry
monitoring. Same-UID concurrent changes remain outside the protected boundary.

The HTTP health gate checks its declared readiness endpoint; it does not
authenticate the frontend HTTPS endpoint. Separately test HTTPS after apply,
rotation, revert and restart. Restart transfers the confirmed candidate into
a new session and still requires explicit bind. Old native connections can
drain after a change; successful apply does not mean instantaneous TLS listener
revocation or completed old-worker exit. Status is not a continuous TLS check.

`node --test --test-reporter=tap x10/test/frontend-tls.test.mjs` exercises the
installed/extracted loopback path. A local source-present test remains distinct
from independent nonroot Node22 acceptance from a permanent published package.
The actual user service, permanent release and Production V1 gates remain open.


## Declarative backup and fresh restore foundation — 26 October 2026

The installed `backup --output ABSOLUTE_FILE` command exports only the current
last-confirmed controller input and the two declared installation ports. Every
registered source session must be prepared or cleanly stopped, with unchanged
installed/controller records, no pending operation and no live owned native
process. An unknown or faulted source is refused. The source stays unchanged.

Choose an absent absolute output outside the installation, directly inside an
owned mode0700 directory with safe canonical ancestors. Publication creates a
mode0600 regular file without overwriting an existing path. Treat its contents
as sensitive configuration. The finite command result contains a byte count and
file hash; consistency hashes are not an authentication signature or encryption.
A late publication/directory-sync error can leave a completed private output;
inspect it rather than deleting or retrying blindly after an unknown result.

Restore uses the source checkout or checked extracted bundle:
`node install.mjs install --prefix NEW_ABSOLUTE --restore ABSOLUTE_FILE`.
For a source checkout, use `node x10/alpha/cli.mjs install` with the same options
and the normal checked build inputs. The target prefix must not exist. Do not
supply `--port`, `--health-port` or `--upstream-port`: restore retains the declared
ports and exact candidate input without automatic path/port remapping.

The input file must be owned0600, singly linked, bounded to2MiB, canonical JSON
with the declared schema and valid consistency records. Unknown/duplicate keys,
unsupported versions, bad hashes, links, unsafe modes and changed read identities
are refused. The optional controller `https` object is unsupported by this
foundation; certificates and private keys are not exported or restored. Restore
only configuration trusted by the local operator: native `-t` parses supplied
directives and may open referenced external files. A consistency checksum does
not make arbitrary configuration safe.

A successful restore creates new installation/session/controller identities,
records the target's checked package, Node and host-library identities, and runs
native `-t`. It leaves a fresh prepared installation with null binding. It does
not start a daemon, bind health, test readiness or activate the service. It does
not transfer old process IDs, namespace identities, history, pending state,
locks, binary packages, Node binaries or dependency files. External files or
paths referenced by `serverBody` are not copied or rewritten; native `-t`
validates the target's available inputs but does not prove application health.

Use the ordinary explicit run/bind or supported service path only after target
validation. This foundation is not package upgrade/downgrade, a full backup of
application data, portable TLS recovery, authenticated disaster recovery or V1.
Exact resulting native and restored-service CI remains pending in the checkpoint.


## Restored foreground HTTP application acceptance fixture — 26 October 2026

The preceding backup implementation `1c257bd85c27e905ddc8d7d2725a7ebc579b81d7`
passed both exact native CI contexts:20 native groups and160/160 full-alpha
TAP tests per job. That extracted-bundle path exported stopped confirmed input,
ran native `-t` in a new installation, verified fresh identities/null binding and
removed the still-unbound target. It did not start a restored daemon or check
application readiness. The existing normal managed-service path also passed its
separate TLS/restart/journal and owned-cleanup observations. Neither result
accepts full recovery, package rollback or Production V1.

The new acceptance fixture exercises the next narrower question: restore a
stopped last-confirmed HTTP application configuration, explicitly start its fresh
native session, refuse incorrect application readiness before binding, then
accept the exact ready response and observe the restored revision and application
traffic. It checks a POST counter to distinguish successful delivery from replay,
graceful stop and owned target removal, with the source records and backup bytes
preserved. The installed runtime, backup parser, controller, package inventory,
service recipe and existing fixture budgets are unchanged.

This authored path needs actual exact resulting hosted native CI. Local pure or
source-extracted controls do not execute its physical native lifecycle. Its scope
is foreground loopback HTTP application acceptance: it does not establish a
restored managed service, HTTPS/PKI backup, application-data/database recovery or
an upgrade between distinct runtime packages. Preserve the original installation
and known-good package until a new target is independently accepted.


## Checked installed package identity — 27 October 2026

A newly verified installation containing this command can report its checked
runtime payload without starting native code or changing operator state:

```sh
"$X10" package-info
```

Use the installed launcher with no additional arguments or options. An older
installed CLI does not gain the command when a checkout is updated. Before
reporting, the installed command performs the existing canonical installation,
immutable-file and strict recorded dynamic-dependency checks. It does not
acquire the alpha lock, write a lifecycle record, bind health, activate a
service or run a native executable. A refused inspection returns the fixed
`package_info_refused` code and a generic message without installation paths.

The JSON result has `outcome: package_identified` and code-relative
`runtimeFiles`, sorted by path, containing the file byte counts, modes and
SHA256 values. `runtimePayloadSha256` identifies the selected installed native
binary, launcher, alpha/controller modules and, for schema2, the service recipe.
`operatorPayloadSha256` uses the same records except `bin/nginx`, while
`nativeBinarySha256` identifies that binary separately. A changed operator
package must not be described as a changed native NGINX binary.

The two payload fingerprints hash the canonical JSON
`{schemaVersion: 1, files: [...]}` for their respective sorted file lists.
Build records, source/provenance labels, archive timestamps, documentation,
`examples/candidate-b.json`, licenses, installation IDs, prefixes, sessions,
configuration and host-library paths are excluded from these payload identities.
The installed `lib/alpha/upstream-example.mjs` helper remains a runtime file. Updating only
those metadata therefore does not establish a different runtime package.
The original complete installation inventory is still verified; exclusion
from a fingerprint does not permit an installed file to be changed or omitted.

These are consistency observations under the existing trusted-operator
boundary, not signatures, a new concurrent same-UID filesystem fence or an
atomic snapshot of live application state. `consistencyOnly` is true;
`compatibilityAccepted`, `upgradePerformed`, `rollbackAccepted`,
`serviceAccepted` and `productionAccepted` remain false. Identical identities
do not establish ABI or state compatibility; differing identities do not prove
that an upgrade is safe. Keep the old known-good package, installation and
state until separately verified target acceptance.

This command supplies a bounded identity prerequisite for the still-open
side-by-side package A-to-B-to-A contract. It does not stage, switch, migrate,
start, restore or roll back a package. Its new extracted-bundle assertions
require exact resulting hosted CI; local pure and virtual controls do not
establish physical package transition or service acceptance.

The older dated pending paragraphs above retain their historical scope.
The earlier restored HTTP managed-service path on implementation
`831360a9a9770815c660f5bc06d002b92154a1b0` is separately accepted only within
the same checked package and temporary nonroot systemd-user profile; see its
[hosted receipt](../evidence/g4-restored-service-hosted.json). That success
does not close distinct-package rollback, TLS backup, the full G4/V1,
permanent distribution, independent published replay or the60-minute soak.


## Exact installed package identity acceptance — 27 October 2026

Implementationacb648392e745b5246a5620f2ea6a6286dc06d42 passed native
push40455973705/job122029316296 and PR40455978706/job122029337388:
34 actual successful steps,20 native groups and284 alpha tests each.
Both artifacts contain the15-field package identity diagnostic,11 runtime
files and identical runtime/operator/native fingerprints across contexts.
Actual installed-byte, fresh restored identity, prepared-record/owned-lock
preservation and argument-refusal observations passed. The passing fixtures
also retain excluded immutable-file and dependency-drift refusals, plus
unchanged application request/POST counters before first startup.

Existing restored-service regressions also passed on this new CLI:18 proofs,
5 sessions,2 restarts,6 bounded journal checks,TLS3 and all13 cleanup facts,
with unit/private Node/bootstrap removal. Service contract617PASS/1root-only
SKIP remains explicit; normal operation did not exercise failure containment.
Research PR actually ran21/7/27/48; push runtime skipped and CLA failed.

This accepts read-only package identity, not package staging, compatibility,
activation, native binary upgrade or A-to-B-to-A. Next: implement bounded
side-by-side staging with no implicit activation and preserved known-good
files, then verify actual reviewed payload transitions and rollback.
Hashes are consistency records, not signatures. FullG3/G4/V1, TLS restore,
permanent release, independent published replay and60-minute soak stay open.
Evidence: x10/evidence/g4-package-identity-hosted.json.


## Explicit side-by-side package staging — 27 October 2026

A candidate containing `stage` can prepare a different checked operator package
in a new private prefix while retaining the old installation. Invoke the
**explicitly trusted, extracted candidate bundle**, not the old installed
launcher and not a source checkout:

```sh
node nginx-x10-alpha/install.mjs stage \
  --source-prefix /absolute/private/old-install \
  --prefix /absolute/private/new-install \
  --expected-source-payload SOURCE_RUNTIME_PAYLOAD_SHA256 \
  --expected-bundle-manifest CANDIDATE_BUNDLE_MANIFEST_SHA256
```

Replace both SHA256 placeholders with independently checked lowercase hashes.
The source pin names the original installed runtime payload; the candidate pin
hashes the exact raw `bundle.json` bytes. Neither a hash nor a manifest obtained
from the same untrusted download establishes publisher authenticity. The
operator must trust the candidate and configuration before executing its
installer. The new inspector reads the source's checked installed records; an
old installation need not contain `stage` or `package-info`, and its code is
not silently updated to gain those commands.

This bounded path requires schema2 source and candidate installations, a new
absent target, safe canonical private paths and disjoint source, bundle and
target roots. All registered source sessions must be prepared or cleanly
stopped; unknown files, pending or changed controller state, faulted/live
sessions, unsupported HTTP input or recorded dependency drift cause refusal.
The current confirmed declarative HTTP input and ports are transferred through
an owned private temporary backup under the source alpha lock. Source files,
records and histories are retained and rechecked. The lock is cooperative
same-UID coordination, not a security or supervisor fence.

The staged target receives fresh installation, session and revision identities
and remains prepared and unbound. Native version and configuration syntax
checks (`-V`, `ldd` and `-t`) may execute during verification/installation;
`stage` does not start a serving daemon, check application readiness, install
or activate a user unit, change listeners or switch traffic. It does not copy
old bindings, process identities, histories, live TLS state or application data.
A differing operator payload can still contain the identical native NGINX
binary; runtime, operator and native identities must be assessed separately.
Metadata or provenance labels alone do not make a different runtime package.

A failed command returns a redacted refusal. If a target was already created,
keep it for inspection rather than retrying or recursively deleting unknown
files. Only the command's own temporary backup is cleaned automatically. The
source package is not uninstalled, renamed or replaced. Retain the known-good
package and state until independently accepted target validation and a separately
reviewed switch/return procedure are available.

The new pure/tempfile/virtual controls exercise the declared boundary; their
counts and frozen bytes belong to [candidate evidence](../evidence/g4-package-stage.json).
The authored hosted fixture uses actual earlier operator CLI bytes and the
same compiled native binary to distinguish real operator-payload staging from
a metadata-only edit. Until exact resulting CI is checked, it is not a physical
staging acceptance. Even a passing staging fixture does not accept A-to-B-to-A,
reversible application-state migration, a native binary upgrade, package
rollback or a permanent published release. TLS restore, independent published
replay, the60-minute soak, fullG3/G4/V1 and semantic Continuum remain open.
Windows remains a separately assigned, deferred and unverified plan after an
accepted Linux V1; this command adds no Windows support.


## Exact side-by-side package staging acceptance — 27 October 2026

Implementationad012446592488fe4bc33ff28a2f4189bb8c865a passed native
push40468943667/job122071147148 and PR40468947907/job122071164947:
34 actual successful steps,20 native groups and410 alpha tests each.
Both exact artifacts contain one36-field staging diagnostic and four refusals
without overwrite. The25-field stage result is asserted against actual bytes.
Historical acb operator code differs from the candidate; native binary is the
same. Source files and backup stayed unchanged, the fresh target remained
prepared/unbound, listeners stayed closed and owned installations were removed.
The historical bundle is an explicit checked reassembly, not a published archive.

Existing service regressions passed on this new CLI:18 restored proofs,
5 sessions,2 restarts,6 bounded journal checks,3 downstream and3 upstream TLS
sessions, all13 cleanup facts and unit/private-Node/bootstrap removal.
Service contract617PASS/1root-onlySKIP is explicit. Normal successful operation
did not exercise failure containment. Research PR actually ran21/7/27/48;
research push runtime skipped and inherited CLA failed.

This accepts staging without activation. The source A is prepared/unbound
in this proof, so no A-to-B-to-A traffic, reverse state compatibility or native
binary upgrade is accepted. Next: A serves P, B serves and confirms Q, then
the exact old A installer restores B-produced Q into fresh A2 and A2 serves Q.
Keep known-good A and application effects intact; verify every owned stop.
Foreground return and managed-service transition remain separate gates.
FullG3/G4/V1, TLS restore, permanent release, independent published replay,
60-minute soak and semantic Continuum stay open. Runtime is unchanged by
this receipt. Evidence: x10/evidence/g4-package-stage-hosted.json.


## Foreground operator-package return fixture — 27 October 2026

The next authored acceptance fixture exercises a narrower return path than
managed-service package rollback. It uses an explicitly checked reassembly of
the earlier operator package A and the current operator package B. Their actual
operator payloads differ; the compiled native NGINX binary is identical. The
historical reassembly is not a previously published archive, and hashes are
consistency records rather than package signatures.

The declared sequence is A(P) → B(Q) → A2(Q). First, A serves a checked HTTP
input P and application traffic, then stops with owned process/listener absence
confirmed. B is staged into its own new private prefix, explicitly started,
and must refuse wrong readiness before establishing a fresh binding. It then
serves HTTP traffic and confirms a different supported HTTP input Q. After B
is cleanly stopped, its checked backup is restored by the **exact trusted old
A installer** into a new A2 prefix. A2 must have the original A payload identity,
fresh installation/session/revision identities and no initial binding; after
an explicit start/bind it must actually serve Q. An old A installer is not
assumed to contain the newer `stage` command.

The fresh reinstall is the return mechanism. Old source records are not edited
to look like the new target, and B's runtime binding, session history, PIDs,
pending state and journal are not copied into A2. The declared compatibility
question concerns only the supported declarative HTTP backup/input format.
Native syntax acceptance or matching hashes alone do not demonstrate that A2
can serve the B-produced input; actual hosted readiness and traffic are required.
The original known-good A installation and package are retained unchanged while
B and A2 operate. Each owned serving process must stop before the next uses
the same listeners; no seamless or all-traffic atomic cutover is claimed.

The application observes distinct POST effects in the A, B and A2 phases. A
package return must not replay these requests, reset their counters or undo
already accepted application effects. GET and streamed response observations
remain separate from readiness, and all traffic and cleanup assertions must
come from the exact resulting hosted fixture, not a virtual receipt alone.
This is a test extension using the existing installation/operator commands;
it introduces no new general-purpose rollback command or runtime CLI behavior.

Local pure controls validate the finite proof/receipt contract only. Local
native/process-group/signal/systemd fixtures are not run in the current nested
execution environment. Exact resulting hosted native CI and artifact review
are pending for this authored scenario; see
[candidate evidence](../evidence/g4-operator-return.json) for frozen identities
and the actual verification state. Earlier staging-only or service receipts
do not accept this newly authored traffic path.

Even a passing foreground A(P) → B(Q) → A2(Q) fixture does not accept the
separate managed-service package-transition gate, a different native binary
upgrade/downgrade, arbitrary state/database/journal migration, TLS-state restore,
permanent distribution, independent published replay, the60-minute soak or full
G3/G4/V1. Semantic Continuum and the deferred Windows plan remain unverified;
the central G9 portfolio handoff is unchanged.


## Verified-route connection contract for the HTTPS fixture — 27 October 2026

The HTTPS-upstream fixture now makes its connection assumption explicit.
Before sending its one application POST, it selects a downstream HTTP
connection on which a GET has actually returned the expected good body,
authenticated-origin marker and exact candidate route tag. The POST and stream
must use that same selected connection. Automatic agent redial is disabled;
the request must have the exact live, writable socket and the expected reuse
state before the fixture sends the payload. A missing, changed or closed socket
causes refusal, without retrying the application POST on another connection.

This connection is between the test client and the managed native HTTP
listener. It is not the HTTPS origin socket, a TLS-library state transfer or a
proof about every worker. Native upstream CA/hostname verification and the
existing negative TLS controls remain separate obligations. Matching a public
fixture route marker alone is not authentication. The initial GET also checks
actual response content and origin identity before the connection is selected.
This is a fixture-only correction: installed CLI, native C, controller and
service behavior are unchanged.

The earlier exact implementation `6401c8f0fe4690a4daea0abac43d2e0efd91c0ad`
had different native workflow outcomes. Push `40475357966` completed all34
steps successfully. PR `40475365565` failed step21 in the HTTPS-upstream
fixture: its application POST received503 instead of200, and the origin had
received zero application POSTs. The preceding good CA/hostname GET passed;
later negative TLS controls and the PR service step did not execute. The
failed fixture's owned native/launcher/socket/temp-root cleanup was confirmed.
Both events had already passed the20-group native aggregate and617 alpha tests,
including the new foreground operator-return proof. Push success does not
erase the PR failure or supply its skipped service observations.

An old-worker/route interleaving is a hypothesis, not an established cause of
that503. Reusing a verified downstream connection narrows the fixture to its
declared route; a future passing test must not be described as fixing a native
runtime defect or guaranteeing all-traffic readiness. The adverse result and
exact artifact identities remain in [candidate evidence](../evidence/g3-tls-verified-route.json).
The new source and pure controls require a frozen local result and exact
resulting hosted TLS/native/service verification. Until then, the changed
fixture is not accepted by the earlier successful push.

No zero-downtime, all-worker drain, request replay, live connection migration,
Continuum, package rollback, permanent release or Production V1 claim follows
from the pin. The operator-return/managed-service transition and the remaining
G3–G8 gates retain their separately declared acceptance requirements.


## Exact foreground return and HTTPS fixture receipt — 27 October 2026

Implementation `ac2ae992d47907d82817cbd2dfb23480972c056a` completed both
native push40480203383/job122108410221 and PR40480208863/job122108417175
successfully:34 actual steps,20 native groups and617 alpha tests each.
The separate HTTPS-upstream fixture passed76 TAP tests per event, including
58 virtual controls. Its14-field diagnostic confirms the selected actual verified GET,
one65551-byte POST and one65537-byte stream on the same checked downstream
HTTP connection, exactly one origin POST and no POST retry. All existing
CA/hostname/plaintext refusal controls and owned cleanup passed.

Both events also verify foreground A(P) → B(Q) → old-A2(Q):13 phases,
3 real traffic legs and19 diagnostic fields. The old A installer restores
B-produced HTTP Q into a fresh unbound A2, then A2 explicitly starts/binds
and serves Q. Its checked operator/runtime payload equals A and differs from
B; the native NGINX binary remains identical. Original known-good A files
stay unchanged, with confirmed owned stop/listener absence between starts.
Three unique65551-byte POST receipts remain in the synthetic origin's memory
without replay/reset, and three256KiB streams match exactly. This does not
establish database/disk durability or the release upload/stream/load budgets.
Input hashes contain run-specific ports: P!=Q=A2 holds within each run;
complete proofs need not be identical between push and PR. The old operator
bundle is a checked historical reassembly, not a published historical archive.

The same implementation passed existing restored managed-service regressions:
18 restored proofs,5 sessions,2 restarts,6 bounded journal checks, the existing
three-session service TLS profile and complete unit/private-Node/bootstrap
cleanup. This accepts those regressions, not a managed-service package switch.
The full failure-containment matrix was not exercised by normal cleanup.

The accepted new scope is foreground operator-package return, backward
compatibility of the supported HTTP declarative input and the corrected
verified-route TLS fixture. The historical6401 PR step21 POST503 failure
with zero origin POSTs is retained, and its cause remains unknown. A later
passing connection-pinned fixture is not evidence of a native runtime fix,
an all-worker fence or seamless connection migration. Earlier dated pending
paragraphs preserve their historical candidate scope; this receipt records
the newly checked implementation.

The separate managed-service package-transition/recovery gate is next. Native
binary upgrade/downgrade, TLS restore, permanent release, independent published
replay, the60-minute soak, fullG3/G4/V1 and semantic Continuum remain open.
The deferred Windows plan and central G9 transition are unchanged. See the
[exact hosted receipt](../evidence/g4-operator-return-hosted.json).


## Managed operator-package return candidate — 27 October 2026

A separate nonroot systemd-user checker now exercises three private units:
A serves HTTP P, stops and retires; B stages from A, first serves P, applies Q,
serves Q and completes an actual manager restart; the exact old A installer
then restores B-produced Q into a fresh A2 that serves Q. Each unit retains
its own immutable prefix/binary/launcher context. Actual hosted acceptance
of this new scenario is pending; the accepted foreground receipt remains
separate at `ee2daa0385f654e96fd5b75c09da4e0179bb90a1`.

The expected new proof has 12 sections,16 phases,3 units,4 successful native
invocations,1 manager restart and5 bounded journal checks. These are separate
from the unchanged legacy18 restored proofs/5 sessions/2 restarts/6 journal
checks/3 downstream plus3 upstream TLS sessions. Journal checks are not exact
query counts. Four successful traffic-leg GET checks can each use up to8
idempotent route-acquisition attempts; the initial B/P GET is one separate
check. Each leg sends one unique65551-byte POST and one exact65537-byte stream
on its already verified downstream HTTP connection, without POST retry.
Synthetic POST effects remain in origin memory, not durable business storage.

The checker requires observed prepared null bindings for A/B/A2. B manager restart can bind before
external observation; its intermediate initial binding is explicitly null
meaning unobserved, while new actual session/revision/binding/invocation and
old process retirement are mandatory. Eleven stop/link/not-found facts gate
activation of the next unit. Known-good A files and backups remain preserved.

Checkout-owned system Node supplies exact reviewed historical CLI bytes as
a private0400 input outside the candidate bundle. Private Node never runs Git
or changes security configuration. Both source-pinned collectors and strict
success reports are now mandatory before private Node cleanup. The new report
is bounded12KiB and the combined envelope32KiB. Closed adverse reports remain
`ok:false`; unknown logs/proofs are not published and dependency cleanup refuses.

Frozen local Node24 pure/tempfile/virtual checks passed631/631, including529
new controls once. Separate review has3 historical-reader controls,8 workflow
tempfile controls and8 virtual report controls. YAML/inline Node syntax passed.
No physical native/process-group/signal/systemd/network fixtures ran locally.
The actual new managed package path therefore remains unaccepted pending exact
hosted push/PR jobs and `service-package-return.json`.

B remains the operator runtime introduced by `ad012…`; fixtures/docs do not
create another runtime version. A/A2 use reviewed historical CLI reassembly
with the same compiled NGINX binary. Native/library upgrade, TLS restore,
full recovery/security matrix, permanent release, independent published replay,
60-minute soak, fullG3/G4/V1 and semantic Continuum remain open. Historical
6401 POST503/origin0 failure with unknown cause, local cleanup FAIL_UNKNOWN,
CLA failure, owner window and deferred Windows plan remain unchanged.

See the [candidate evidence](../evidence/g4-managed-package-return.json) and [per-file ledger](../review/g4-managed-package-return-ledger.json).


## Immutable revision reader and failure-reason candidate — 27 October 2026

The first managed-service package-return implementation
`c2adbea6c8d1e8b864291383445d35a0b27e875a` failed both native push40486053822
and PR40486064789 at step30. Both reports show phase `install_a`, terminal
`cleanup_unconfirmed` and no managed proof. Cleanup overwrote the original
primary refusal, so its exact historical code is unavailable. The private Node,
historical CLI input and bootstrap root were retained; no dependency-cleanup
artifact confirms their removal. Do not describe that failed path as accepted.

Both events had passed the20-group native aggregate,617 alpha tests,76 TLS
TAP tests and the separate existing service's18 restored proofs/5 sessions/
2 restarts/6 bounded journal checks/3 downstream and3 upstream TLS sessions.
Those earlier checks and legacy cleanup do not prove successful cleanup of the
new managed-package collector. The foreground operator-return acceptance remains
separately scoped, with no managed package return inferred from it.

The reproduced fixture defect is specific: the manager writes an immutable
revision with mode0400, while the new collector's exact reader required0600.
A safe baseline control refused the actual0400 record and accepted identical
0600 bytes. The candidate instead requires0400 and retains exact regular-file,
ownership/link/size and consistency checks; it does not relax the manager's
record permissions or modify the installed CLI/native/controller/service recipe.
That known contract mismatch is not claimed as the exclusive historical cause.

The new report schema2 has13 fields and preserves a bounded `primaryFailure`
code/phase before cleanup can overwrite the terminal outcome. Successful reports
require `primaryFailure:null`; closed failure reports remain `ok:false` and
cannot authorize private Node removal. Proof shape/counts remain unchanged.
The workflow/consumer source pins change together, with no new job budget,
permissions, credentials or schedules.

Frozen local Node24 pure/tempfile/virtual controls passed662/662 with no
fail/cancel/skip/TODO. The31 additional fix controls are included once:
18 proof,9 actual-reader and4 consumer controls. The separate3-control exact-c2
baseline is not added. An intermediate mixed-schema consumer run had11 failures
among118 controls; that adverse result stays separate from final verification.
YAML and inline Node syntax passed. No physical native/process-group/signal/
systemd/network fixture ran locally.

Actual resulting CI remains pending; no local pure check is evidence of
physical managed-service return acceptance.
The prior failed results and earlier6401 POST503/cause-unknown observation stay
in history. Recovery/security, native binary upgrade, TLS restore, permanent
release, independent published replay, the60-minute soak and fullG3/G4/V1/
Continuum gates remain open. See [candidate evidence](../evidence/g4-managed-package-return.json).


## Exact managed HTTP operator return receipt — 27 October 2026

Implementation `0ebded94ea331c1b28c52e71fa725dc35bb2f08a` completed native
push40490525329/job122143117385 and PR40490532178/job122143157669 with
all35 actual steps successful. Both actual `service-package-return.json`
artifacts have the13-field schema2 success report with `primaryFailure:null`;
its schema1 proof has12 sections and16 ordered phases. The observed sequence
uses3 distinct owned units and4 invocations: A/P, B/Q, a real B manager restart
preserving Q, then the old A installer restoring B-produced Q into fresh A2/Q.

Each run confirms5 bounded journal CHECKS,4 successful traffic-leg GET checks
and1 separate initial B/P GET check. An individual route acquisition may make
up to8 idempotent attempts; these are not exact raw GET or journal-query counts.
The4 successful legs each deliver one unique unretried65551-byte POST and one
exact65537-byte stream over the verified route. POST receipts persist in the
synthetic origin's memory without replay/reset, not a database or durable disk.
The fixture sizes do not establish the release upload/stream/soak budgets.

Actual checked payloads satisfy A=A2!=B for operator/runtime code, while the
native NGINX binary stays identical. P!=Q=A2 is verified within each event;
run-specific ports mean complete input digests can differ between events.
The historical A bundle is an explicit checked reassembly, not a published
historical archive. Eleven stop/link/not-found facts gate target activation;
12 restart facts verify old-process retirement and actual fresh identities.
The intermediate prepared null binding during B's automatic restart was not
observed: its proof value is null/unknown, not a claimed observation. The final
fresh binding/invocation is verified. Known-good A files and backups remain
unchanged until owned cleanup. All3 units/installations and the authenticated
private Node, historical input/history and bootstrap root were removed only
after both source-pinned service reports succeeded.

The same jobs passed20 native groups,617 alpha tests and76 TLS TAP tests;
the separate legacy service retained its18 restored proofs/5 sessions/2 restarts/
6 bounded journal checks/3 downstream and3 upstream TLS sessions and owned cleanup.
Research PR40490532200 actually ran21/7/27/48; research push runtime skipped and CLA failed.
Normal cleanup success is separate from the still-open full failure-containment matrix.

This accepts only scoped managed HTTP operator-package return and backward
compatibility of the declared HTTP input. The prior c2 failures, unavailable
historical primary reason,0400/0600 reader baseline and earlier6401 POST503
with unknown cause are preserved. The receipt does not accept native binary
upgrade/downgrade, TLS restore, arbitrary state/database/journal migration,
permanent distribution, independent published replay, the60-minute soak,
full recovery/security/package-failure gates, fullG3/G4/V1 or Continuum.

The next gate is a distinct unhealthy B after A retirement: verify readiness
failure and zero B POSTs, confirm failed B is quiescent, then explicitly reactivate
the preserved known-good A. This extends already tested legacy refusal primitives
to the separate cross-package fallback. Windows and the G9 portfolio handoff
remain deferred/unchanged. See the [exact hosted receipt](../evidence/g4-managed-package-return-hosted.json).


## Stopped-session capacity admission — exact447 compatibility accepted

Before a stopped session can create and register its successor, the guard
counts the whole existing private installation tree under the alpha lock. This
includes retained sessions and revision files, not just the session count. The
entry bound remains4096; the walker now refuses a4097th entry instead of
allowing one extra entry at the traversal boundary. No old session or history is
pruned to make room. A prepared current session remains an idempotent path.

A pre-creation capacity refusal leaves the registry and existing session tree
unchanged. Creation can add more files than its minimum structure because native
configuration checking may create logs or other files. The candidate therefore
counts the actual tree again before changing the registry, reserving one entry
for atomic registry publication. If that second check fails, the command returns
`session_capacity_unresolved`: **STOP, preserve the installation for inspection
and do not retry preparation.** The old registry stays unchanged, but the newly
created, unregistered session is retained. That is a partial unresolved outcome,
not a clean refusal or a session that may safely be deleted automatically.

This admission applies only to stopped-session registry publication through
`prepare-run` or the corresponding `run` path. It does not bound transient
`nginx -t` files, later application temporary files, cumulative `apply`/`revert`
revision growth, direct controller use or same-UID concurrent writers. Those
capacity boundaries remain open. Initial install, restore and side-by-side
staging call `createSession` outside this stopped-session guard; a fresh prefix
is normally small, but custom native configuration checks are not a universal
growth guarantee there either. Existing stop/recover/uninstall commands are
not given this new admission check; their own state, ownership, unknown-file and
faulted/orphan refusals still apply. An already over-limit or unknown tree must
be preserved for manual inspection, without history editing or forced removal.

The fixed counters and reserves are consistency checks for the declared
cooperative profile, not a filesystem resource quota or an OS fencing mechanism.
Exact447 normal installed operator/service compatibility is accepted for both
events in the [scoped receipt](../evidence/g5-stopped-session-capacity-hosted.json).
Its4096-entry exhaustion controls remain pure/virtual; this does not accept
physical capacity exhaustion, the separate apply/revert component below or full G5/V1.


## Apply/revert control-entry admission — exactcd8 compatibility accepted

Before the installed alpha CLI forwards `apply` or `revert` to the controller,
it counts the actual whole installation tree while holding the existing alpha
lock. That tree includes retained sessions, revisions and the alpha lock itself.
The command requires seven free entries under the unchanged4096-entry bound;
4089 existing entries can pass this check, while4090 cannot. A refusal happens
before the controller process is started, so this admission adds no revision,
pending record, native signal or controller write on its refusal path. Existing
records and revisions are preserved rather than pruned to make room.

The seven-entry reserve describes only the declared controller's own writes
for one apply/revert operation. It includes the controller lock, candidate and
possible rollback revisions, pending/event records and atomic temporaries.
Counting only one candidate revision or assuming successful temporary cleanup
is insufficient: an error path can retain three atomic temporaries while
rollback and ambiguity handling proceed. A source-extracted virtual fault model uses explicit atomic/revision failure
outcomes plus representative nonallocating failure classes, and checks that path along with normal apply, native rejection and
rollback; it is not an enumeration of every possible OS failure. This
is a model of the pinned controller control flow, not physical filesystem
high-water measurement or a guarantee about arbitrary native configuration.

The controller's durable writers, record schemas and recovery behavior are
unchanged. `stop` and `recover` do not receive a new admission gate. Other
forwarded commands do not receive this seven-entry apply/revert gate; the
separate bind admission below uses its own reviewed reserve. Direct controller
CLI/API use bypasses these alpha guards.
Native application files, configuration-test temporary writes, same-UID
concurrent writers, initial install/restore/stage growth and prepared-session
reuse remain outside this new reserve. It does not repair an existing
unregistered session or replace the stopped-preparation STOP/manual-inspection
contract above. Capacity, full security/recovery and V1 remain open.

Exactcd8 normal installed compatibility is accepted for both events in the
[scoped hosted receipt](../evidence/g5-alpha-revision-capacity-hosted.json).
Local pure/tempfile boundary tests and virtual fault paths do not establish
physical4096-entry exhaustion or an allOS-failure guarantee.
See [candidate evidence](../evidence/g5-alpha-revision-capacity.json).


## Bind control-entry admission — exactb1d compatibility accepted

The installed alpha CLI counts the whole installation tree before
forwarding `bind` to the controller. It also checks the running, locked branch
of `wait-bind` before its first controller status observation and subsequent
direct bind. Checking only the CLI proxy would leave this service startup path
unguarded. The existing alpha lock is already included in the inventory. The
unchanged4096-entry limit requires three free entries:4093 existing entries
may pass admission, while4094 are refused before controller activity.

The three-entry reserve covers only the pinned controller's declared control
files for status followed by bind. A status observation releases its controller
lock before binding; a failure during its cleanup propagates rather than starting
bind. Binding can hold its controller lock together with an event intent and
a state-file atomic temporary. Bind creates no revision, rollback or retry.
The source-extracted virtual model evaluates the actual lock, atomic and durable
event flow with declared filesystem failure classes, including retained
temporaries and failures before or after a filesystem effect. This is not a
physical filesystem high-water measurement or an enumeration of every OS failure.

The prepared-session wait path is unchanged and does not repeatedly take the
startup lock. Exact runtime identity validation, readiness checks, cancellation,
deadline decisions and `bindingMayHaveCommitted` semantics remain in their
existing order. A capacity refusal occurs before bind is attempted; it does not
claim that a durable binding happened. A bind already attempted is still awaited
once and reported as potentially committed on a late/cancelled/error outcome.
`stop` and `recover` remain available under their existing state and ownership
checks, without this new capacity gate. No controller durable writer or schema
is changed, and old records and revisions are preserved rather than deleted.

This cooperative admission does not fence direct controller calls, native or
configuration-test files, arbitrary concurrent same-UID writers or kernel timing.
Initial install/restore/stage registry publication and ordinary first-inspection
lock headroom have the narrow candidate admission described below; native growth
and broader future operations remain outside that contract. Prepared reuse, recovery-created revisions and the
stopped-preparation partial unregistered tree/STOP outcome are not repaired by
this change. Full capacity, security/recovery and V1 remain open.

Exactb1d normal installed, startup and service compatibility is scoped accepted
for both native events in the
[hosted receipt](../evidence/g5-alpha-bind-capacity-hosted.json) and
[per-file ledger](../review/g5-alpha-bind-capacity-hosted-ledger.json).
Push40603217925/job122536307484 and PR40603226496/job122536335129 completed
36 successful steps and20/20 native groups each, with actual complete zero-skip
managed376 and alpha603 TAP. All three strict reports, source pins and owned/
private Node/history/bootstrap cleanup are confirmed. This receipt changes no
runtime; this README changes packaged documentation bytes, while the fixed
bundle inventory remains unchanged.

The actual eight-file managed commands include new bind51 and the retained,
translated revision37 series once per managed suite. Their individual labels,
and capacity46/preparation18, lie outside the retained32768-character tails;
inclusion uses the exact command, source VM registrations, strict manager pins
before model evaluation and complete376 summaries. All45 decomposition and17
recipe labels appear once in each retained tail. Preparation18 also runs through
alpha's existing import, so these counts overlap and are not unique totals.

The accepted exactcd8 receipt above remains separate. Pure/tempfile and modeled
fault controls do not establish physical4096-entry exhaustion, every OS-failure
case or full capacity/G5/V1 acceptance. See
[candidate evidence](../evidence/g5-alpha-bind-capacity.json).

Initial registry publication now has the separate candidate boundary below.
Accepted bind compatibility remains attached to exactb1d, not to the newly
changed installed CLI.


## Initial registry publication and first inspection — candidate

After `createSession` completes, installation counts the actual whole prefix
before publishing its first registry. The same installation path is used for
fresh install, HTTP restore and package stage. Admission reserves three entries
under the unchanged4096-entry inventory bound:4093 existing entries may pass;
4094 are refused before the registry write. This is the newly created private
prefix, before its initial registry publication; no existing alpha lock is
added to this install path. Exclusive operator use remains a precondition,
and this cooperative admission is not an OS fence.

The three-entry contract covers exactly one registry publication followed by
one ordinary unbound `info`, `status` or `history` inspection. Registry atomic
publication holds one temporary or final registry name; an ordinary inspection
can add an alpha lock and a controller lock. Directory handles do not add names.
The reviewed source model includes before/after-effect open, write, sync, close,
rename and cleanup failures, including retained locks and registry visibility
after rename. It is finite virtual accounting, not every possible OS failure or
a physical4096-entry high-water measurement. The baseline crossing4094→4097 is
an occupancy observation; status/history themselves do not inventory-refuse.

A refusal before registry publication preserves the incomplete private prefix
and prepared session through the existing install catch; no automatic cleanup,
retry, registry repair or rollback is introduced. Native creation may already
have produced an overbound partial tree before this postcreate check. Preserve
it for manual inspection/STOP; this change cannot promise that every failed
installation remains inspectable by the bounded walker. Existing old records
and revisions are not compacted or deleted.

Ordinary inspectability does not promise activation near capacity. Bind and
apply/revert retain their separate3 and7 reserves; stopped preparation retains
its18/1 checks. `stop` and `recover` receive no new capacity gate. Controller
durable writers, schemas, native code and workflow budgets remain unchanged.
Direct controller, recovery, native/configuration-test, transient, concurrent
and prepared-reuse growth remain outside this narrow contract.

The new immutable [baseline producer](../review/alpha-initial-capacity-counterexample.mjs)
is pinned to exactb1d CLI/manager bytes, also present at16b. Run its checked-in
absolute path with a clean matching checkout as the working directory. Candidate
source-pin refusal is intentional; the older five producers remain immutable.
[Candidate evidence](../evidence/g5-alpha-initial-capacity.json) separates pure/
tempfile controls and modeled failure paths from installed acceptance. The
changed installed CLI requires its own exact push/PR hosted compatibility;
priorb1d success does not transfer. Fullcapacity/G3/G4/G5/G7/V1, recovery/release
and semantic Continuum remain OPEN; Windows remains DEFERRED_UNVERIFIED.
