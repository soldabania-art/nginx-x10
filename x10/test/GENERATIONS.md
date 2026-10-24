# Native master generation and process birth fixture

The new read-only `GET /1/control/generations` endpoint exposes master-owned
configuration and process-incarnation identities. This fixture uses the shared
[bounded control API runner](CONTROL-API.md); it does not add a daemon or open
any implicit management endpoint.

```sh
node x10/test/generations.mjs
node x10/test/generations.mjs --transport unix
node x10/test/generations.mjs --reference \
  --binary x10/.build/baseline/nginx \
  --source /absolute/path/to/pristine/nginx
```

Transport is explicitly `tcp` (default, exact temporary IPv4 loopback) or `unix`
(private prefix, mode 0600). There is no downgrade, automatic fallback or
passing dependency/platform skip. The local AF_UNIX EPERM limitation is retained
as a failed diagnostic; Unix validation belongs to the separate required hosted
CI steps where supported.

## Ten candidate case groups

Two shared setup groups require the actual build/config validation and an actual
default-disabled master before the explicit API master starts. Eight additional
groups check:

1. Initial generation `"1"`, two actual workers, distinct birth IDs, PID/slot
   uniqueness and native process identity mapping.
2. Successful control PATCH advances to `"2"`; a held old response keeps its
   original PID/birth/generation `"1"`, while two new workers have generation `"2"`.
3. Rejected control reload leaves generation `"2"` and serving revision unchanged.
4. Successful SIGHUP advances to `"3"`, retaining the original old response.
5. An actually logged rejected SIGHUP leaves generation `"3"` unchanged.
6. SIGKILL of an exactly identified current worker causes actual respawn in the
   same slot and generation, with a different PID and larger distinct birth ID.
7. The generation endpoint rejects PATCH/POST with 405 and legacy process JSON
   remains exactly `name`, `pid`, `exiting`.
8. The original accepted response completes byte-exactly after both successful
   and rejected reload paths and current-worker respawn.

The deliberate SIGKILL targets only an isolated, verified fixture worker. Its
exact PID-specific native signal-9 diagnostic is recorded separately; other
alerts remain unexpected. No production or unrelated process is targeted.

## What the identities mean

Generation and birth IDs are canonical decimal **strings**. The scope is one
master lifetime (`scope:"master-process"`), anchored by the independently
verified master PID/start ticks/UID/executable and PID/network namespaces.
Counters are not globally unique across master restart or binary upgrade.
`current_generation` describes accepted master configuration-cycle bookkeeping;
it does not certify that every worker started, became ready, or closed a prior
listener. Birth distinguishes successful process incarnations even when slots
are reused. The fixture verifies these statements on actual wire responses and
processes; overflow/unclassified/fork-failure boundaries require their separate
native focused controls and review.

The API may report `available:false`, null IDs and an explanatory reason when
identity cannot safely be represented/classified. This must remain unresolved,
not be interpreted as readiness or complete generation fencing. Detached binary
children are counted separately by `excluded_detached`; the ordinary fixture
does not perform a binary upgrade.

## Reference and evidence

`--reference` is an explicit different mode. After the two shared setup checks,
it requires exactly HTTP 404 for the new endpoint and records the missing
capability as expected reference absence. It does not turn an arbitrary error
or missing candidate endpoint into PASS. No request parsing defect or security
vulnerability is inferred from pristine NGINX lacking this added feature.

[Candidate JSON](../evidence/generations-fixed.json) contains ten passing case
groups. [Pristine JSON](../evidence/generations-reference.json) contains the
three explicit reference checks. Native source hashes come from the selected
`--source` checkout; both the generation harness and shared runner hashes are
recorded before/after. The selected binary and native sources must remain
unchanged. Every normal master exits SIGQUIT zero; all tracked sockets close
and the prefix is removed. Actual cancellation controls are linked from
[CONTROL-API.md](CONTROL-API.md).

These are Linux loopback observations. They do not establish a worker-side
listener-close ACK, all-worker readiness, atomic traffic cutover, QUIC/UDP drain,
every platform/configuration matrix or performance superiority.
