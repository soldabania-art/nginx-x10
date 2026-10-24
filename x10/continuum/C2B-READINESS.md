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
