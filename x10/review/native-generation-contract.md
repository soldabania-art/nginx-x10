# Native master generation diagnostics: contract

Reviewed on 23 October 2026 at development checkpoint
`8d769208cf79b8a583077ccb75be30f59e9563a1`. This document defines the narrow
contract implemented in the working tree. At the time of this source review,
its native build, paired runtime evidence and independent counter controls are
still integration gates, not completed claims. [STATUS](../STATUS.md) remains
the authority for subsequently verified results.

## Scope and endpoint

The next native feature is an additive, read-only
`GET /1/control/generations` endpoint in the already optional Unix control API.
It reports which accepted master configuration cycle was used for each recorded
native child birth. It does not add a worker-to-master acknowledgment channel,
modify listener closure, change reload acceptance, or close client connections.
The existing `/1/control/processes` fields and both native structure layouts
(`ngx_cycle_t`, `ngx_process_t`) remain unchanged. Control discovery gains the
`generations` name; non-GET methods return 405.

The API is still opened only by an explicit existing native control-socket
choice. Compiling the feature does not expose a management address. The local
Node controller does not silently adopt this endpoint or change its apply,
rollback, recovery or health semantics. A native master is required; existing
single-process-mode API unavailability is retained.

Proposed/implemented JSON shape for an ordinary initialized master:

```json
{
  "scope": "master-process",
  "master_pid": 1234,
  "current_generation": "2",
  "available": true,
  "reason": "",
  "excluded_detached": 0,
  "processes": [
    {
      "name": "worker process",
      "pid": 1236,
      "slot": 1,
      "generation": "2",
      "birth": "3",
      "exiting": false,
      "exited": false
    }
  ]
}
```

`available:true` means the included records are classified in this master's
bookkeeping snapshot. It is not worker initialization, application health,
listener closure, readiness or a live-process guarantee. `exiting` and `exited`
are existing master-side flags; successful QUIT delivery is not execution of the
worker's close path. Process records include workers and native cache helpers.
Detached exec children are excluded and counted separately, because an exec'd
new master has its own configuration lifetime.

## Generation and birth rules

- Initial `ngx_master_process_cycle` starts generation `"1"` before workers and
  cache helpers are forked. An identical-content reload still has a new cycle
  identity; this is not a configuration-content hash or controller revision ID.
- Increment generation at every successful assignment of a newly accepted
  `ngx_cycle`, in both the HUP branch and `ngx_control_reload_config`. A rejected
  `ngx_init_cycle` leaves generation and the installed cycle unchanged.
- Increment occurs before response rendering and before new workers are started.
  The existing PATCH path can install a new cycle even if response rendering or
  sending later fails. A lost response therefore does not imply rejection.
- A single `ngx_control_handle_events` sweep can accept multiple PATCH reloads,
  then trigger only one worker-start sweep after it returns. Generation numbers
  may consequently have no corresponding child births. They must not be
  allocated only when workers start, nor advertised as successful-ready counts.
- Every successful parent fork receives a fresh birth serial before the
  `respawn >= 0` early return. A failed fork does not consume a birth. Slot reuse
  overwrites the side-table entry and binds it to the newly published PID.
- The recorded generation is from the actual cycle passed to spawn, checked
  against the registered installed-cycle pointer. It is not copied blindly
  from the former slot: respawn calls use the master's then-current cycle.
  An unexpected cycle pointer leaves generation null and the snapshot visibly
  unavailable rather than guessing. A normal same-cycle respawn gets the same
  generation and a fresh birth.
- HUP while `ngx_new_binary` exists and `ngx_restart` can restart workers without
  accepting a new configuration cycle. Such births retain the current old
  master's generation and receive fresh serials. Noaccept/QUIT/reopen do not
  allocate a new generation.

The master owns one fixed side table indexed by `NGX_MAX_PROCESSES` slots.
Entries record PID, generation and birth; output is accepted only when the
entry PID matches the current native slot PID. Freed slots are not emitted.
A mismatched/unclassified included slot yields null ID(s), `available:false`
and `reason:"unclassified_process"`. In that case `current_generation` can
remain non-null: the installed master cycle is known, but included process
membership is incomplete. Consumers must not use the partially classified list
as complete. Exhaustion/uninitialized states instead suppress current and
process IDs. An internal uninitialized view reports `reason:"uninitialized"`.
Master-loop serialization prevents a control request
from observing the middle of the parent-side slot publication; signal handlers
continue only their existing flag/status work.

## Width, exhaustion and master lifetime

Counters use `uint64_t` and are serialized as canonical decimal **JSON strings**,
without leading zeroes. Zero is an unavailable sentinel, serialized as null.
This avoids JavaScript's 2^53-1 integer precision boundary, signed int64 limits,
and truncation through a 32-bit `uintptr_t` number-handler argument. The helper
formats `%uL` into local bounded storage and the existing string handler copies
it into the request pool.

At UINT64_MAX, the next generation or birth allocation latches diagnostic
unavailability: `available:false`, `reason:"counter_exhausted"`, and null IDs.
Counters never wrap or reuse an identity. Native reload, fork and traffic
behavior continue unchanged; a diagnostic counter cannot reject an otherwise
valid configuration. Restart/exec starts a fresh master's counters at one.

Identity is scoped to a particular externally verified master process, not a
machine, boot, cluster or installation. Callers must bind master PID plus OS
lifetime/PID-namespace identity (the local controller already has start ticks,
namespace and executable checks). PID alone is not a global master-instance ID.
The inherited control socket does not carry counters across binary exec. New
and old masters can both have generation `"1"`; their counters must never be
merged. If a failed new binary causes the old master to reown its control socket,
the old master's own counters persist. Detached new-binary entries are not
mislabeled as workers of their parent's generation.

## Compatibility and implementation boundary

State and callbacks live in `ngx_control.c`; only small declarations and guarded
hooks are added to `ngx_control.h`, Unix process spawn and master-cycle code.
When `NGX_CONTROL_API` is disabled there is no new table, endpoint or callback
reference. When compiled but no control socket is active, hooks return without
maintaining identities. Windows already rejects `--with-control-api`; no Win32
source or unsupported platform substitute is introduced. Dynamic module ABI
structures are not enlarged, though actual off-profile and module/build checks
remain necessary before claiming platform compatibility.

No per-HTTP-request data-path operation, shared-memory zone, worker protocol,
external dependency, background thread or persistent counter file is added.
This does not itself establish a measurable performance improvement or zero
cost in every compiled configuration.

## Required evidence before accepting the feature

| Control | Required result |
| --- | --- |
| Pristine binary | New endpoint 404; existing discovery/processes/config remain their documented behavior. |
| Initial native master | Generation one; all included worker/helper births unique, positive decimal strings; master PID exact. |
| GET-only/discovery | New discovery name, GET success; mutation method 405 with no reload, PID or generation change. |
| Valid HUP | New accepted generation and new births; held old worker retains its prior generation while draining. |
| Valid control PATCH | Generation allocated for actual accepted cycle; fresh native response eventually uses the new configuration. |
| Rejected HUP and PATCH | Actual rejection; generation and prior serving configuration retained. |
| Respawn and slot reuse | Kill only an owned fixture worker; replacement has a fresh birth, correct current cycle, valid PID and no inherited stale slot identity. |
| Burst/multiple PATCH | Every installed cycle is counted; skipped worker generations are allowed. No ready/listener claim from a 200 response. |
| Detached/binary lifetime | Detached entries excluded; exec/new master resets its scope; old-master restore retains its original scope. Any unexecuted actual upgrade scenario must remain explicitly unverified. |
| Integer boundaries | Production-TU counter/formatter harness covers >2^32, >2^53, UINT64_MAX, exhaustion without wrap and null/unclassified behavior under ASan/UBSan where available. |
| Error controls | Allocation/send failure does not misclassify an already committed cycle as rejected; failed fork does not allocate a new birth. |
| Disabled profile | Real build without control API and no new endpoint/listener; existing protocol/CLI checks retained. |
| Cleanup | Every test uses an explicit isolated fixture socket, bounded operations and verified native/client/socket/prefix cleanup; interruption remains failure. |

Unix-domain control transport and explicit isolated loopback TCP transport
exercise the same endpoint semantics but different socket/platform behavior.
If the local kernel refuses AF_UNIX, preserve that failure separately and keep
Unix transport as a required CI gate. Do not silently fallback and label a TCP
run proof of Unix socket permissions.

Generation diagnostics are the first narrow native metadata step toward better
reload observation. A reliable all-generation listener-close protocol would
still need worker execution acknowledgments, stale-message handling and failure
states. Accepted/pipelined traffic, HTTP/2/3 drain, module side effects and
health-after-activation mean that even such metadata is not an atomic
all-traffic transaction.

## Reviewed current native source identities

These hashes refer to the in-progress implementation bytes frozen for the first
native build/review. They are consistency anchors, not proof that all paths have
already been executed.

| File | SHA-256 |
| --- | --- |
| `src/os/unix/ngx_process.c` | `a354c634854617bed643d8db8b6218aa84cb603a7de1b15d9402427b4a471677` |
| `src/os/unix/ngx_process_cycle.c` | `dd2f45a62724d9a297005f080efa0dcdd34ce7760d7591ec829ff6d3407ce819` |
| `src/os/unix/ngx_control.c` | `7cfcf5ad2cdf9eb7546281c3ce2dc0254a257b7d009a6c494e913cee4a36f2e0` |
| `src/os/unix/ngx_control.h` | `6273ebce9a188abe9319758cd745c0c1688d24a11db151f9654b675e2dae4541` |
| `src/core/ngx_data.c` | `f17cc16776d3eef02ae2a7bf3d796a0c7ef742b014efaa5188e7094481dd5443` |
| `src/core/ngx_json.c` | `d26b5e939a4d248edb7e1cc455048b6ee6eb885807272d7dc4329d48c584a21d` |
| `src/core/nginx.c` | `e10938c9cec230d0e1f3eab17bddd69f7abf4904c760149d54005f2776c3ce17` |
| `auto/modules` | `27a48262e8677ee1291710a45030af5bdd6035c17faf05f53a925e82736ee9c2` |
