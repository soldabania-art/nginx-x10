# NGINX cycle and connection lifecycle review

Pinned source: NGINX 1.31.9, commit `148c75678cd4171338c31d4ed4c02411736d5fe9`. Fully read `src/core/ngx_connection.c` (1,663 lines), its header (239), `src/core/ngx_cycle.c` (1,484), and its header (149): **four files, 3,535 physical lines**. Exact ranges and SHA-256 are in `core-lifecycle-coverage.json`. No source edits were made. This is complete textual reading of the assigned slice, not full branch execution or a proof of safety. Master/worker process orchestration, event backends and protocol-specific close handlers are covered separately.

## Candidate configuration and resource ownership

`ngx_init_cycle` (`ngx_cycle.c:39`) allocates a new cycle pool, copies persistent prefix/configuration identity, builds independent arrays/lists, loads the module set, creates core configurations and parses inline/file configuration. Parser or core `init_conf` failure destroys candidate pools and restores environment state. A signaller returns after configuration initialization; it does not open the full server resources.

The candidate subsequently checks pid/lock files, creates paths, opens new log files with close-on-exec, and prepares shared-memory zones. Listening sockets are matched against the old cycle by socket type and complete address. A match transfers the descriptor and records `previous`; `remain` identifies old listeners that must survive. Backlog/deferred-accept/reuseport/protocol changes have separate flags. Unmatched listeners are opened nonblocking. Only after these steps does the code enter the marked commit section, redirect logs and invoke module initialization. Old files, unmatched sockets and unused zone mappings are then retired.

The failure path closes candidate files, frees newly allocated zone mappings while excluding old reused mappings, closes sockets marked newly opened and destroys candidate pools. It does **not** close every descriptor copied from the old cycle. That distinction is essential: indiscriminate cleanup would destroy the still-running configuration.

### Reload is not a universal ACID transaction

Syntax/core-configuration failures can leave the old running route intact, and a native regression should assert that exact case. The broader statement that any failed reload undoes every possible side effect is unsupported:

- A reused zone's `init(zone, old_data)` runs before commit and may change shared module state. Its module owns compatibility and failure semantics.
- A pidfile name change can create the new file and delete the old pidfile before later initialization completes.
- Transitioning to reuseport or another socket protocol can set SO_REUSEPORT on the old listener. Socket configuration may act on a descriptor shared with the old cycle.
- `ngx_init_modules` failure after the commit marker is explicitly fatal (`exit(1)`), rather than returning through ordinary candidate rollback.
- Path creation and filesystem effects are not a general transactional filesystem protocol.

A management layer should run native `-t`, retain a known-good configuration, observe actual worker/route transition and record the exact failed stage. It must not report a successful application merely because a reload signal was delivered, or claim arbitrary module failures are automatically reversible.

## Shared zones and old/new cycles

`ngx_shared_memory_add` (`ngx_cycle.c:1306`) keys declarations by name and rejects conflicting module tags or sizes in one candidate configuration. During reload, matching name/tag/size normally reuses the old address and passes old module data to `init`. `noreuse` changes this path: old data may seed a newly allocated mapping. New mappings require nonzero size, shared mutex/slab initialization and module initialization; reused mappings must preserve module-specific compatibility.

`ngx_init_zone_pool` (`:966`) checks an existing slab mapping's expected address and remaps on supported Windows paths. A new slab starts with `min_shift=3`, end/address fields, shared mutex creation and `ngx_slab_init`. Pointer-bearing shared data therefore cannot be treated as an arbitrary copyable JSON object. Combined with upstream zones, peer references, zombies and configuration-generation guards are required while membership changes.

After successful initialization, the master/init-cycle path can destroy its old pool because old worker processes retain their own process/mapping lifetime. The non-master path stores old cycles and schedules `ngx_clean_old_cycles` (`:1380`) every 30 seconds. It destroys an old pool only after all its connection descriptors are invalid, keeping resources alive for existing connections. This is a lifetime rule, not a periodic forced connection kill.

## Listeners and socket reuse

`ngx_create_listening` (`ngx_connection.c:20`) allocates listener/address metadata with fd −1 and default stream/backlog/buffer settings. `ngx_clone_listening` (`:99`) creates a listener entry per worker when reuseport is enabled. `ngx_set_inherited_sockets` (`:135`) reconstructs address, type, buffer settings, reuseport, socket protocol, fast-open and deferred-accept state from inherited descriptors; unsupported addresses are ignored explicitly.

`ngx_open_listening_sockets` (`:426`) skips ignored/existing/inherited descriptors as appropriate, enables required reuse options, makes new sockets nonblocking and performs bind/listen. EADDRINUSE gets up to five attempts separated by 500ms outside config-test mode; other errors fail promptly. `-t` has special binding behavior, so its success is valuable but not a promise that a future production start can acquire every resource. Unix sockets also have pathname permission/deletion behavior.

`ngx_configure_listening_sockets` (`:742`) applies buffer sizes, TCP keepalive tuning, routing table, fast-open, backlog and deferred acceptance. UDP wildcard destination-info and QUIC no-fragment settings are platform guarded. Some unsupported socket-option failures are logged and ignored; evidence should preserve logs instead of inferring all requested kernel settings became active.

`ngx_close_listening_sockets` (`:1126`) removes active events/timers, returns listener connection slots, closes owned descriptors and conditionally deletes Unix socket names. QUIC listeners have a deliberate exception depending on reuseport/BPF; a new global listener-close loop must not erase it. Shared/inherited descriptors and Unix pathname ownership across binary upgrades require the existing guards.

## Connections, pressure and drain

`ngx_get_connection` (`ngx_connection.c:1207`) validates fd-table capacity, attempts bounded idle-resource draining, obtains a free connection slot, preserves event objects, clears prior state and toggles event instance bits. This guards recycled descriptor/event identity. `ngx_free_connection` (`:1273`) returns the slot and clears its fd-table association only if it still points at that slot.

`ngx_close_connection` (`:1286`) cancels read/write timers, removes registered and posted events, marks events closed, removes reusable-queue membership, frees the slot, invalidates fd and closes the socket unless it is shared. A second close is logged instead of silently closing a potentially recycled descriptor. TLS/protocol/pool teardown belongs to callers; this function is not a substitute for those layers.

`ngx_reusable_connection` (`:1374`) maintains queue membership and waiting statistics symmetrically. `ngx_drain_connections` (`:1405`) activates when free slots fall to at most 1/16 and reusable connections exist. It requests closure of the oldest bounded batch (between one and 32), invokes each connection's read handler and can retry a lingering-close candidate when no free slot emerged. It does not randomly evict arbitrary active requests. `ngx_close_idle_connections` (`:1462`) likewise marks idle entries closed through their protocol handler.

`ngx_set_shutdown_timer` / `ngx_shutdown_timer_handler` (`ngx_cycle.c:1437` / `:1455`) implement the configured worker shutdown deadline. At expiry, non-invalid, non-accept, non-channel, non-resolver connections receive `close=1,error=1` and their read handler runs. An unset/zero timeout does not create this deadline. The protocol handler must release its state correctly; direct fd closure would bypass protocol ownership and shared-socket rules.

## Changes to evaluate and regression criteria

The native code already implements listener inheritance, graceful old/new worker lifetimes, shared-zone reuse, idle pressure relief and bounded shutdown. These should be exposed and verified before proposing replacements. Useful optional work includes reload-stage diagnostics, worker-generation visibility and resource-budget observability. Such work must distinguish configuration validation, signal delivery, candidate initialization and proven serving state.

| Experiment or test | Non-regression acceptance |
| --- | --- |
| Valid reload during a streamed response | New requests eventually use the new configuration; the accepted old response finishes with complete ordered bytes. Retired workers stop accepting but retain needed old resources. |
| Invalid syntax reload | Native `-t` rejects it; a directly signalled failed reload is observed in logs; existing route and active stream remain usable. State the tested failure stage explicitly. |
| Resource/module failure injection | Separate parser, log-open, bind, zone-init and post-commit module-init cases; document exact old/new side effects. Do not group them under a universal rollback guarantee. |
| Repeated same-address reload and reuseport/protocol transition | No leaked fd or accidental close of reused listeners, correct worker distribution, configured/actual option differences visible. |
| Zone reuse/name/tag/size/noreuse combinations | Correct old-data handoff, no incompatible pointer reuse, duplicate declaration rejection, stable shared counters and no dangling peer references. |
| Idle pressure and connection-slot reuse | Close only eligible idle/reusable entries through handlers; no stale posted event reaching a recycled slot; free list, fd table, queue and counters return to baseline. |
| Graceful shutdown and deadline | Short responses complete; active long responses survive until configured deadline; hung streams and TLS handshakes eventually release resources; channels/resolver/listener/QUIC exceptions remain correct. |
| Log reopen and binary inheritance | New file opened/configured before replacing old fd, errors retain prior usable file, inherited listener identity preserved, unrelated processes and socket paths untouched. |

The next native harness is a deliberately smaller executable subset: HTTP/1 pool/POST/stream, TLS/HTTP2 and concrete successful/syntax-invalid reload cases, all on loopback under a private temporary prefix. It does not certify platform-specific transitions, QUIC, every shared-zone module or all failure-injection stages above.
