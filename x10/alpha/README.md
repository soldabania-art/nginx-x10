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

A verified stop permits another `run`. Each run uses a new `runs/<session-id>`
private directory and controller state. Only a hash-verified last-confirmed
input is transferred. Bind explicitly to the new master. Old configurations,
revision journals and histories stay in their old session directories; `history`
shows the current session, and `info` identifies it. Pending, conflicting or
modified state blocks restart until inspected/recovered. No automatic rebind
or process-lifetime continuation is claimed. Up to 256 sessions are supported.

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

A failed/incomplete installation is preserved for
operator inspection rather than recursively erased.

## Local bundle

```sh
node x10/alpha/cli.mjs pack --output x10/.build/dist/nginx-x10-linux-alpha.tar.gz
# On a compatible Linux host, in an existing private directory:
tar -xzf nginx-x10-linux-alpha.tar.gz
node nginx-x10-alpha/install.mjs install --prefix "$HOME/nginx-x10-alpha" --port 8088 --health-port 8089
```

An extracted bundle verifies its own allowlisted payload and needs no original
git checkout or build tree. It contains native binary, exact CLI helpers,
LICENSE/NOTICE and an allowlisted provenance record, without live configuration,
state, PID, namespace or logs. It still requires Node and compatible host dynamic
libraries; it is not a universal portable/static package. Checksums are unsigned
consistency records. Binary debug/configure metadata can contain build paths.
Local bundles stay ignored; published CI artifacts must come from the public
hosted runner checkout, not this private workspace.

Run `node --test --test-reporter=tap x10/test/alpha.test.mjs` for actual native
installation/lifecycle/restart, tamper, refusal and bundle extraction checks.
