# Native reload: listener closure and drain boundaries

Source review on 23 October 2026, based on upstream
`148c75678cd4171338c31d4ed4c02411736d5fe9` and X10 development checkpoint
`29746068bfca299b85062e981df250aa3e12abb8`. No production C or controller change
is proposed by this report. The conclusions below distinguish source inference
from existing runtime evidence. They do not certify a listener fence.

## Native ordering

| Contract | Source | Consequence |
| --- | --- | --- |
| A successful HUP builds a new cycle, starts its workers/cache helpers, sleeps 100 ms, then tells older children to quit. A failed cycle retains the old one. | `src/os/unix/ngx_process_cycle.c`: `ngx_master_process_cycle` | A fast response from a new worker can arrive before older workers have received their quit command. The sleep is an ordering delay, not an upper bound on old-worker shutdown. |
| Newly spawned children have `just_spawn` set; the shutdown sweep clears that flag and skips them. Quit normally travels through the process channel, with a signal fallback. | `src/os/unix/ngx_process_cycle.c`: `ngx_signal_worker_processes`; `src/os/unix/ngx_process.c`: `ngx_spawn_process` | Successful delivery does not acknowledge execution of the worker's shutdown branch. |
| A quitting worker marks itself exiting, installs an optional shutdown timer, closes listening sockets, closes idle connections, and continues processing active work. | `src/os/unix/ngx_process_cycle.c`: `ngx_worker_process_cycle` | Listener closure and worker exit are different milestones. Waiting for every old worker to exit would delay confirmation until active streams finish. |
| TCP listener events are removed and the worker's listener descriptors are closed. Some QUIC listener descriptors are deliberately retained. | `src/core/ngx_connection.c`: `ngx_close_listening_sockets` | TCP descriptor absence cannot be generalized to QUIC/HTTP3 or UDP session drain. |
| A matching new-cycle listener reuses the old descriptor; the master retains descriptors needed by the new cycle. | `src/core/ngx_cycle.c`: `ngx_init_cycle` | A listener remaining visible in the network namespace or master is expected and says nothing about old-worker ownership. |
| Child reaping can respawn a worker before the master processes `ngx_reconfigure`. | `src/os/unix/ngx_process_cycle.c`: `ngx_master_process_cycle`, `ngx_reap_children` | A single pre-HUP child snapshot can miss an old-cycle replacement born between that snapshot and cycle replacement. New process start time alone does not identify its configuration generation. |

`worker_shutdown_timeout` is an optional native policy. Its timer marks remaining
connections as closing/error and invokes their handlers; it is not a promise to
preserve arbitrarily long streams. With no such timer, active work can delay
worker exit. The ordinary HTTP keepalive path checks `!ngx_exiting` in
`src/http/ngx_http_request.c`, while `keepalive_min_timeout` has a separate path;
already accepted or pipelined traffic needs its own acceptance tests. HTTP/2 and
HTTP/3 have their own GOAWAY/session state. None of those protocols acquires
all-traffic atomic cutover semantics
from a local HTTP readiness probe.

## Existing runtime evidence

[The HTTP fixture](../test/http-baseline.mjs) and its committed
[candidate evidence](../evidence/http-fixed.json) exercise a held response from
the old upstream across a successful reload and a later rejected reload. The
response completes with exactly `first:a\nlast:a\n`, while fresh route requests
observe the new configuration. That supports preservation of that accepted
stream. It does not inspect old-worker listening descriptors or prove that every
fresh connection after the first new response uses the new generation.

The controller's `acknowledged` function requires two fresh revision/health
observations, separated by a retry delay. Those observations are useful sampled
readiness evidence. Its request deadlines and retry count do not establish that
the master has completed the later old-worker shutdown sweep.

No additional runtime fence experiment was performed for this report. Native
process-cycle source SHA-256 at review:
`b8811ead5647f9cfc76f3085f4f57e622e434f403de2ca7aa131d33442fdbda6`.

## Feasible bounded observation

A Linux-only observer can check a narrower statement without changing NGINX:
**the specifically identified pre-reload processes no longer own the managed TCP
listener**. This can coexist with old active streams. A future opt-in observer
would need all of the following:

1. Verify the bound master by UID, canonical executable, PID namespace, start
   ticks and command identity. Map local and host-view `/proc` PIDs through
   `NSpid`; never treat a PID-file number as an unconditional `/proc` directory.
2. Record each relevant child's stable identity and parent relationship, including
   namespace/start ticks. Recheck identity around descriptor inspection. A process
   disappearing can count as gone only after distinguishing exit from access
   failure or PID reuse. Unreadable or ambiguous process state must fail the gate.
3. Resolve the managed address/port to TCP LISTEN socket inode(s) in the correct
   network namespace, then intersect those inodes with each child's own
   `/proc/<pid>/fd` symlinks. `/proc/<pid>/net/tcp` describes a network namespace;
   it is not that process's descriptor inventory. Account for inherited/shared
   sockets, TCP6 when enabled, and any reuseport listener set explicitly supported.
4. Bound elapsed time and the number of process/descriptor entries inspected.
   Keep a timed-out or inaccessible observation visibly unresolved. Do not send
   TERM/KILL merely to make a confirmation deadline pass.
5. Continue to verify fresh revision/health and file/master identity. Closing old
   listeners does not validate application health or undo requests already served
   by a failed candidate.

This observation must not be labeled a complete old-generation fence. Pre-HUP
process-set churn remains unclassified without a generation identity supplied by
the native master, a reliably delimited native event stream, or stronger process
coordination. Parsing human-readable worker-start logs is a possible diagnostic,
not a supported durable generation API. A process title containing “shutting
down” is set before listener closure and is insufficient on its own.

The pinned source also contains an optional native control API
(`src/os/unix/ngx_control.c`), compiled in this build profile but not opened by
the local controller. Its process list exposes name, PID and the master's
`exiting` flag, not a configuration-generation ID or worker-side listener-close
acknowledgment. That flag is set after sending the quit command. The API's reload
response likewise does not certify that old workers have run their close path.
Opening this API is a separate explicit operator choice; its presence in the
binary must not silently expose a management listener.

For a complete guarantee, first design a narrow native generation/listener-close
acknowledgment contract and its failure states; compare that with the cost and
compatibility of external process observation. It must distinguish listener
closure from completion of already accepted connections. Keep the existing
sampled-generation claim until the stronger contract is tested.

## Required acceptance cases before enabling a stronger gate

- Keep one real old-generation response open; confirm its worker can remain
  alive after its TCP listener descriptors are gone and finish the exact body.
- Delay an old worker's shutdown handling and show that new-generation probes
  alone can pass while the old listener observation remains pending.
- Exercise multiple workers, an old-worker exit/respawn around HUP, a new-worker
  init failure, rejected reload, and a second reload while old streams drain.
- Exercise host-view `/proc` PID translation, PID reuse/start-time mismatch,
  unavailable fd/status entries, wrong network namespace, and resource/deadline
  bounds. Unsupported QUIC/reuseport paths must be explicit, not false passes.
- Preserve already accepted old traffic and application side effects in the
  documented model. A stronger listening-socket observation still cannot make a
  health-after-activation controller transactional for all requests.
