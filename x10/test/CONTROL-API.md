# Native control API compatibility fixture

This fixture exercises the existing optional native API in the pinned NGINX
source. It does not install a control service or change the local controller's
activation contract. The native build must include `--with-control-api`.
The actual opt-in CLI is **`-l address`**, not `-C`.

```sh
node x10/test/control-api-baseline.mjs
node x10/test/control-api-baseline.mjs --transport unix
node x10/test/control-api-baseline.mjs \
  --binary x10/.build/baseline/nginx \
  --source /absolute/path/to/pristine/nginx
```

The default transport is explicit `tcp`: one temporary `127.0.0.1:ephemeral`
control listener, alongside a separate loopback HTTP fixture. `--transport unix`
instead requires a socket inside a mode-0700 temporary prefix and checks its
mode 0600 and invoking UID. There is no automatic fallback or passing skip.
Only synthetic configuration is exposed, for the bounded test lifetime. This
is not an authenticated remote administration interface.

## Nine case groups

| Case | Required observation |
| --- | --- |
| Native profile/config | Actual `-V`, control-API build flag and native `-t` |
| Default disabled | An actual master without `-l` has no owned Unix LISTEN socket or managed control TCP listener; inherited `NGINX_CTRL` is removed for the fixture |
| Explicit listener/discovery | Actual master-owned loopback LISTEN inode, or owned private Unix socket; exact root/versioned discovery paths |
| Version/process/config | Native version matches `-V`; two worker PIDs map through NSpid/parent/UID/executable/start ticks/namespaces; active config dump is byte-exact |
| Rejections | Known unsupported methods return 405, unknown path 404 |
| Accepted response | A real old-worker proxied response remains open after its exact first chunk |
| Valid PATCH reload | `/1/control/config` returns 200, fresh HTTP response carries revision B from a new worker, old response remains live; API reports old worker `exiting` |
| Invalid PATCH reload | Syntax-invalid configuration returns 422 with the specific native diagnostic; fresh requests and active config dump retain B despite invalid bytes on disk |
| Old completion | Accepted old response completes exactly after both reload attempts |

The normal endpoints are `GET /1/nginx`, `GET /1/control/processes`,
`GET /1/control/config`, and `PATCH /1/control/config`. The compatibility test
accepts the additive `generations` discovery entry while preserving the known
process/config entries. The old process JSON fields are otherwise unchanged.

A PATCH response is not worker readiness or listener-close acknowledgment. The
fixture waits for fresh native HTTP revision probes and independently resolves
reported process IDs. The API's `exiting` field is master bookkeeping, not proof
that a worker executed its listener-close path. Configuration dump APIs may
disclose secrets in real operator configurations; this fixture contains none.

## Identity and cleanup

`--binary` / `X10_NGINX_BINARY` select the native executable. `--source` selects
the native source tree whose hashes are recorded; pristine evidence uses the
pristine checkout, not the changed candidate tree. Harness hashes always refer
to this repository's fixture. Source and binary identities are recorded
separately; they are local consistency checks, not signed build attestations.

Requests have a 1200 ms absolute deadline and 256 KiB body cap. The complete
fixture has a 30-second deadline, private prefixes, tracked client/upstream
sockets and bounded SIGQUIT/TERM/KILL cleanup of its own native process groups.
Both default-disabled and explicit-API native masters must exit normally under
SIGQUIT for a passing full run. Interruption is failure and stops subsequent
fixture operations. The exact intentionally rejected configuration diagnostic,
restricted-container initgroups diagnostic when applicable, and the generation
fixture's specifically identified deliberate worker kill are separated from
unexpected native errors.

Some local execution environments deny AF_UNIX socket creation with EPERM.
[The retained local diagnostic](../evidence/control-api-unix-unavailable.json)
is a failed Unix run, not a Unix PASS or a native defect. Required local groups
select TCP explicitly by default; Unix mode remains a separate required hosted
CI check on its supporting Linux environment. No automatic transport fallback
changes a failed Unix run into success.

Recorded normal runs: [candidate](../evidence/control-api-fixed.json),
[pristine](../evidence/control-api-reference.json).
[Actual interruption controls](../evidence/control-api-runner-verification.json)
terminate after an observed old response is live and verify native groups,
sockets and prefix are gone. These tests do not cover all methods, malformed
requests, connection limits, slow clients, platform cases or production auth.
