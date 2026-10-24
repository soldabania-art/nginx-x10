# C2b readiness: metadata preflight is not an exporter

Snapshot: project base `4e75ae7b153ff0991624dcf1fdedc2d4a394425c`;
OpenSSL source `85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c`, with the
existing metadata-only key-install monitor patch. This is a bounded source
review for the initial TLS1.3/AES128GCM server profile, not a complete audit.

**Readiness decision: semantic export/import remains blocked.** The new
preflight can reject malformed metadata, mismatched declared identities and an
insufficient directional future-record budget. Eligibility for inventory review
does not authorize secret extraction, transfer, ownership, target I/O or reuse
of a captured snapshot. No secret material belongs in this report or its JSON.

| Obligation | Concrete source state and current evidence | Missing adapter contract |
| --- | --- | --- |
| Current record material | `ssl_st.client_app_traffic_secret`, `server_app_traffic_secret`, `read_iv`, `write_iv`, `enc_read_ctx`, `enc_write_ctx`; the probe exports none of their bytes. | Bounded protected-RAM capsule, exact directional secret length/profile and reviewed cleansing. Do not serialize EVP objects or use session master key as a substitute. |
| Direction and KeyUpdate | `tls13_update_key` selects server secret when `s->server == sending`, otherwise client secret. For this server, READ uses client application secret and WRITE uses server application secret. | Preserve secrets needed for later peer KeyUpdate and response; derived key/IV alone does not establish that behavior. Initial generation at capture does not make future KeyUpdate impossible. |
| Sequence and key install | `RECORD_LAYER.read_sequence/write_sequence` are next counters. Both `tls13_change_cipher_state` and `tls13_update_key` reset the corresponding sequence during installation. | Fresh target construction must install the intended current key and restore the exact next sequence without replaying handshake derivation, advancing an epoch or reusing a nonce. No importer exists. |
| Provider and cipher objects | `SSL_CTX.libctx/propq` select fetched algorithms in `tls13_hkdf_expand`; cipher contexts are separately allocated/reset in `tls13_change_cipher_state`. C2a pins its build and default provider. | Reconstruct fresh target algorithm objects under explicit target identity/configuration, with checked failures; no pointer/layout copying or assumption that an opaque EVP context is portable. |
| Authentication/session semantics | `ssl_st.session`, `verify_result`, `verified_chain`, negotiated extensions/ALPN and role remain outside the record-counter preflight. | Specify supported authenticated application semantics and preserved/explicitly unsupported public APIs. `i2d_SSL_SESSION`, resumption or a new handshake cannot resume this live stream. |
| Future APIs/control | `exporter_master_secret`, finished/resumption material and `session_ctx` have separate purposes. C2a refuses tickets, PHA, pending update/alert/shutdown and other unsupported states. | Decide which established-state APIs the first fixture supports. Do not silently claim preservation of exporter/session APIs merely because application records decrypt. Unknown transitions must still refuse. |
| Buffers and operation obligations | Probe checks `rlayer.rbuf/wbuf/rrec`, packet/fragment lengths, `wnum/wpend_*`, caller ledger and control flags. A zero buffer observation does not serialize application queues or callbacks. | A live single-owner freeze point must cover callbacks, pending arguments, events and later mutations until commit/abort. The enum ledger is not a concurrency fence. |
| Same transport and retirement | C1/C2a use a two-leg recording relay. `BIO_s_socket` and descriptor identity are only observed; socket ownership is not transferred. | Verified same endpoint transfer, exclusive reader/writer grant, no target I/O before commit, source exit before continuation and distinct TLS code identity. No native NGINX migration exists. |
| Future record budget | Metadata preflight performs exact arithmetic on independent current sequences and explicit application/handover/closure counts. | A trusted runtime must debit every protected record, handle refusal/exhaustion and preserve budget across export/import. A proposed allowance is not a reservation or enforcement mechanism. |

The existing `runProbeScenario` returns historical probe observations after its
exchange and closure. Applying metadata preflight to these genuine observations
tests representation compatibility and rejection arithmetic; it is **not** a
live safepoint test. Matching caller-supplied source hashes is not attestation,
snapshot freshness, target compatibility or a transport-binding proof.

## Exact next live-hold insertion point

In `openssl-probe-fixture.c`, the ordinary `exchange` branch emits probe1 and
probe2, compares the complete result structs, then immediately enters
`complete(READ, &trailer, 1, deadline)` to consume peer closure. There is **no**
STEP/ACK barrier between this pair and the next TLS READ. The existing
`step(deadline)` helper reads exactly `STEP\n` with bounded stdin readiness;
other lifecycle branches use it, but the quiescent exchange does not.

The runner consumes and checks the pair in `runProbeScenario`, around
`firstSample`, `checkedImmutablePair` and `immutableRepeatedProbe`. Adding only
a JavaScript callback there would not freeze C: it could already be inside
the next READ. A first live-hold experiment must insert a separate bounded C
barrier immediately after the pair comparison and before any further TLS call,
then bind the runner's decision to the current run identity/challenge and
re-observe metadata before release. Timeout, cancellation, stale/mismatched
decision and closure while held must remain explicit failures with cleanup.
None of that barrier, freshness protocol or secret capture is implemented by
the metadata preflight in this run.

## Independent checks for this bounded preflight

Two genuine authenticated TLS quiescent observations were obtained with
payload5519 and39017 bytes, observed directional sequences1/1 and3/3.
Exact echo, repeated immutable probes, wire records, both close_notify and
closure passed. Metadata preflight then accepted explicit read14/write21
proposed records including closure, and10 mutated metadata requests refused.
These checks deliberately apply preflight to a historical observation after
the exchange, not a live held SSL. Four observed owned temporary roots were
absent and all39 observed children had closed;16 runtime/review source hashes
were unchanged. The C2a test-registration file and the new preflight test file
were not included in this runtime hash set.

Separately6144 synthetic budget vectors passed an independent arbitrary-precision
sum/remainder oracle:3802 eligible and2342 refused, with exact exhaustion and
one-record differences in each direction. One revoked-Proxy input also refused
without invoking traps. These controls reuse the author's inert valid-field
fixture constructor only for unrelated metadata; arithmetic inputs and oracle
were independently chosen. They emit no TLS records and prove no freshness,
secret export or runtime budget enforcement. Sanitized receipts are embedded
by the coordinator in the run's evidence, with private observer-script hashes.

The next smallest code experiment is a reviewed, explicitly paused source-side
in-memory capsule under the above restricted API contract. Before it can be
accepted, define secret lifetime/cleanup and an adapter identity, then test
read-only capture against the genuine source without target traffic. Import,
cross-release code change and old-code retirement need separate gates. Other
partial/alert/EOF variants remain unsupported rather than being added merely
to postpone the library-state unknown.

Primary pinned sources reviewed: [ssl_local.h][ssl], [tls13_enc.c][enc],
[record.h][record], [ssl3_record_tls13.c][record-enc]. Existing local contracts:
[C2a profile](C2A-PROFILE.md), [public/private boundary](OPENSSL-STATE.md),
[operations](OPERATIONS.md). Tests and exact hashes are recorded separately
in this run's sanitized evidence; source review alone is not runtime acceptance.

[ssl]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/ssl_local.h
[enc]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/tls13_enc.c
[record]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/record.h
[record-enc]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/ssl3_record_tls13.c

### Exact CI: metadata capsule preflight

Implementation `deecc35825a706ac8b58d728f8f8a6e35b9d0986`: research push
`40062408179` и PR `40062412144`, native push `40062408165` и PR
`40062412125` завершены success. Оба research logs подтверждают21/7/27/23;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](../evidence/continuum-capsule-preflight-hosted.json) сохраняет artifact
digests и отдельные event-head/checkout/build identities. Hosted official:
1105 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL; local1083 отдельно.

Это приёмка metadata/budget arithmetic, не живого safepoint или exporter.
Возвращённые snapshots являются post-cleanup историей. Далее — bounded C
STEP после immutable pair до любого TLS READ/control/shutdown и runner
decision/nonce/reobservation barrier, с abort/cleanup перед экспортом.

## Opt-in source-side live hold

The new `quiescent-live-hold` fixture path adds an explicit C decision barrier
immediately after its first immutable allowed probe pair, before the next TLS
READ/control/shutdown. The existing ordinary `quiescent` scenario is unchanged.
The single-threaded C source generates a fresh public 128-bit nonce, records
the current call serial and waits on its control pipe and raw socket with an
independent monotonic deadline of at most three seconds. Only an exact bounded
CONTINUE line matching nonce and serial can reach reobservation and release.
ABORT, stale/malformed/queued duplicate decisions, timeout or observed transport
activity take the refusal/cleanup path without SSL_shutdown or later TLS I/O.

The runner calls `onLiveHold` only after the C hold-ready event and first probe
pair. Its deeply frozen context exposes allowlisted metadata and verified-build
identity, not an SSL object or secret bytes. During this callback, `sourceHeld`
is true and `historical` false. The cooperative callback deadline is at most
two seconds, reduced against the advertised C remainder; the C deadline remains
independent and authoritative. After callback completion the runner verifies its
harness again, and C requires fresh probes3/4 to match the initial complete
result and ledger serial before hold-released. Only then is normal client
closure permitted. A returned final result is historical evidence:
`historical:true`, `sourceHeld:false`, `heldDuringCallback:true`.

Independent checks used two genuine authenticated TLS exchanges with delayed
continue decisions (payload3701 and52009), observing the owned C child alive
before and after each callback delay, exactly two initial probes before the
decision, unchanged ledger serial and fresh probes before release. Exact echo,
wire verification, both close_notify and normal closure passed after release.
Seven separate actual-TLS refusal controls covered ABORT, stale nonce, stale
ledger serial, callback throw, the actual C three-second timeout, an already
queued duplicate decision and peer raw transport closure while held. The C
timeout control deliberately withheld the real CONTINUE control-pipe line;
the duplicate control wrote two real decision lines in one pipe write. Neither
control changed TLS counters, SSL return values, native clock or library state.
All negative controls required no probes3/4, release, TLS shutdown or successful
done event, and actual source child closure. Sanitized counts, source identities,
cleanup facts and the private observer-script hash are recorded in the evidence.

This closes only the explicit single-threaded fixture hold gap. Raw socket and
control-pipe idleness checks are samples; arrivals after the last check remain
possible. They are not atomic transport ownership fences or proof of absent
concurrent use in arbitrary applications. The public nonce binds this control
exchange and is not a credential or attestation. Caller-provided blocking code
cannot be forcibly preempted by a JavaScript timer; callbacks are trusted and
cooperative. Held standalone OS-signal/CLI behavior was not independently
validated by these controls; canonical programmatic cancellation is separate
from the pre-existing OS-signal boundaries.

The metadata preflight still accepts only its original `quiescent` scenario;
new live-hold probes retain the genuine `quiescent-live-hold` label and are not
silently relabeled to bypass that contract. Live preflight compatibility,
read-only secret capture, protected-RAM lifetime and cleansing, importer/target
construction, exclusive I/O ownership, distinct TLS-code versions and source
retirement before continuation remain separate unaccepted gates. There is no
semantic export/import, automatic adapter compiler or native NGINX migration.

### Exact CI: bounded source-side C hold

Implementation `2debcc30101a72b1e5b08b22dd2ac9b0d040c401`: research push
`40065524807` и PR `40065527979`, native push `40065524846` и PR
`40065528012` завершены success. Оба research logs подтверждают21/7/27/30;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](../evidence/continuum-live-hold-hosted.json) сохраняет artifact
digests и отдельные event-head/checkout/build identities. Hosted official:
1105 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL; local1083 отдельно.

Принят узкий opt-in source fixture hold: только bounded callback видит
удерживаемый source; returned result после cleanup является историей.
Это не exporter/importer, transport/ownership fence или migration.
Далее — combined reviewed live preflight binding и первый protected-RAM
read-only source capture после inventory/secret lifetime contract gate.
Held scenario не переименовывается в quiescent ради старого checker.

## Transient protected source sample

The new [source capture contract](SOURCE-CAPTURE.md) defines a restricted
record-material-only copy under the genuine C hold. A separate held-profile
preflight binds the original samples1/2, current nonce/ledger and build identity;
the old checker remains quiescent-only. C independently binds CAPTURE, reobserves
and creates a locked, guarded, dump/fork-excluded read-only copy, then clears and
unmaps it before release. Public evidence contains no keys or key fingerprints.

This closes only the transient source-copy experiment, subject to recorded test
results. The subset deliberately excludes session/authentication/exporter and
future API semantics. It is not the complete reusable semantic capsule required
for an importer. Mapping protections do not cover the original SSL heap or Node
oracle. SourceUnchanged is a subset/probe/ledger observation, not an all-object
immutability proof. Full inventory, reusable lifetime, target construction,
future record enforcement, exclusive transport ownership, distinct code and
source retirement remain unaccepted; no native NGINX migration is implemented.

Локально35/35 C2a:28 ordinaryTLS,2 OS signals,1 programmatic cancel,
1 noTLS source control и3 synthetic groups. Прежние30 tests сохранены.
Независимо4 actualTLS:2 captures, actual mlock-limit refusal и stale CAPTURE;
ещё4096 synthetic controls:342 eligible/3754 refused плюс revoked Proxy.
Первый C capture отказал из-за очищенного handshake scratch; исправлен
переходом к digest negotiated cipher с прежними SHA256/cipher guards.
Исходные отказы и недоступный ptrace сохранены, syscall tracing не заявлен.
Core21/process7/C1 27 прошли. Native сначала17/20:2 отсутствующих HTTP3
clients и controller expectedB/actualA; после11 pinned wheels/2 venv —20/20.
Последний PASS не исправляет и не объясняет controller timing observation.
Official1083 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL.
[Очищенный evidence](../evidence/continuum-source-capture.json) содержит source hashes, обе попытки и cleanup.
Exact implementation CI pending. Далее сначала controller counterexample/
contract review, затем reusable capsule inventory/lifetime; importer/migration
не реализованы. Это защищённая дополнительная копия, не whole-process защита.
