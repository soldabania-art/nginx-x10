# Event / TLS / QUIC source review

Source: NGINX 1.31.9, commit `148c75678cd4171338c31d4ed4c02411736d5fe9`. Scope: 59 manifest files, 39,098 lines. Exact source ranges and hashes are recorded in `event-tls-quic-coverage.json`. Final source coverage: **59/59 files,39,098/39,098 lines, all full_read;0 partial/structural/unread**. Source hashes, line counts, manifest membership and uninterrupted inclusive ranges were validated against the fixed commit. This is a source review, not an execution/performance result. Conditional platform/TLS-library branches were read but were not compiled or run. Checkpoints below preserve the sequence of reading, so their intermediate counts are historical.

## Read checkpoint 1: event contracts, posted queues, timers

- `src/event/ngx_event.h:19–100`: event state carries readiness/registration separately (`ready`, `active`, `disabled`), closure/timer/posted flags, direction and accept role. The instance bit detects stale reused events; callbacks must not equate fd identity with lifetime identity.
- `src/event/ngx_event.h:149–166`: backend action table separates add/delete/enable/disable, connection registration, notification, process-events and init/done. Preserve these contracts when adding a backend; replacing a syscall alone is insufficient.
- `src/event/ngx_event.h:175–241`: level, clear/edge, greedy-until-EAGAIN, kqueue metadata, timer support and eventport auto-removal are distinct capabilities. Backend-independent code branches on capability semantics, not a blanket claim that all backends are edge-triggered.
- `src/event/ngx_event_posted.h:17–37`: enqueue is guarded by `posted`; dequeue clears the flag and removes the intrusive queue entry. `ngx_event_process_posted` removes before invoking the handler (`ngx_event_posted.c:24–34`), so a callback can repost itself. One event cannot simultaneously occupy two intrusive posted queues.
- `src/event/ngx_event_posted.c:40–59`: next-iteration events are marked ready with unknown availability (`-1`) and moved as a queue; this is an intentional scheduling stage, not merely an alias of immediate posting.
- Timer tree permits equal keys (`ngx_event_timer.c:16–20`); find-min uses signed subtraction to calculate expired deadlines (`:45–49`). Expiry removes the node and clears `timer_set` before marking `timedout` and calling the handler (`:68–94`). Do not free an event still linked in timers/posted queues.
- `ngx_event_timer.h:51–86`: an existing timer is retained if the new key differs by less than 300 ms, reducing tree churn for fast connections. This is an existing performance/precision tradeoff; changing the lazy-delay globally needs timeout-accuracy and throughput evidence.
- `ngx_event_timer.c:99–125`: shutdown eligibility distinguishes cancelable timers; pending timers are not interchangeable with required work.

Candidate measurements: posted-queue wait and handler duration; timer operations/request and actual timeout deviation; no event-loop redesign or timer-data-structure replacement without baseline tail-latency, CPU, timer-cardinality and close/reuse correctness tests.

## Historical checkpoint boundary

The next sections record findings only after complete source chunks were read. The final coverage statement above supersedes intermediate progress counts.

## Read checkpoint 2: event loop, all eight backends, accept/connect, UDP and pipe

All non-OpenSSL, non-QUIC event files are now fully read (21 files, 9,819 lines). No runtime execution is claimed.

### Loop and connection lifecycle

`ngx_process_events_and_timers` (`ngx_event.c:195`) chooses the minimum timer, adjusts accept-mutex wait, forces zero wait for posted-next work, polls the backend, runs posted accept callbacks, unlocks accept mutex, expires timers, then runs ordinary posted callbacks. This order limits how long the accept mutex covers non-accept work. Changing ordering affects scheduling, timer latency and fairness.

`ngx_event_process_init` (`ngx_event.c:632`) initializes posted/timer structures, selected backend, preallocated connection/read/write arrays and free list. It detaches old-cycle listener event registrations on reload. TCP accept, generic UDP and QUIC receive have different handlers. Reuseport worker sockets bypass the shared accept-mutex path; epoll exclusive accept is selected only where applicable.

`ngx_event_accept.c:21–323`: accept4/nonblocking fallback, multi_accept versus kqueue available counts, and EMFILE/ENFILE handling are explicit state paths. Descriptor exhaustion disables acceptance and either drops the mutex or arms a delay timer; free connection pressure is `connection_n/8 - free_connection_n` (`:139`). Successful accept initializes pool, socket functions, addresses, read/write readiness and connection number before invoking `ls->handler(c)`. Failure paths release socket/connection/pool in the corresponding ownership order. `ngx_reorder_accept_events` (`:432`) periodically re-adds an EPOLLEXCLUSIVE listener (normally each 16 requests) to avoid concentrating accepts on the first worker; do not remove it as redundant registration.

`ngx_event_connect_peer` (`ngx_event_connect.c:21`) calls peer selection before allocating an outgoing socket, applies bind/transparent/socket policies, installs protocol I/O functions, registers backend interest and treats EINPROGRESS as NGX_AGAIN. Refusal/unreachable errors return NGX_DECLINED after closing and clearing `pc->connection`; internal setup failures return NGX_ERROR. Keep these return categories and peer lifecycle hooks distinct.

### Backend differences that a fork must preserve

- epoll: registration combines read/write interests and embeds the connection instance bit in pointer low bit. Error/hangup wakes active read/write paths; RDHUP becomes pending EOF. Dispatch checks stale lifetime before read and again before write because the read callback can close/reuse the connection. AIO completion via eventfd marks `complete`, clears `active`, sets `ready` and posts a callback; eventfd notify is a separate callback path. See `modules/ngx_epoll_module.c:578–1006`.
- kqueue: batched change list supports cancellation before syscall, disable versus delete, explicit flush, NOTE_LOWAT and EOF errno/available metadata. The event pointer also carries an instance bit; one-shot clears active when received. User/timer/vnode/AIO filters have their own state transitions. See `modules/ngx_kqueue_module.c:303–656`.
- poll/select (including Windows): level readiness is staged in posted queues. Compact arrays repair moved event indices; select maintains fd sets and validates FD_SETSIZE. Invalid descriptors trigger repair/disable paths to avoid CPU spinning. Windows select also watches write exceptions and sleeps when no sockets exist; WSAPoll requires platform availability. Do not infer POSIX fd-index semantics on Windows handles.
- /dev/poll: POLLREMOVE is flushed before close; removing one direction can require restoring the active paired direction. Returned descriptors are resolved through `cycle->files`; phantom descriptors are investigated/repaired. Read callbacks require a lifetime check before writing.
- event ports: delivery removes all fd interests, so both directions become inactive; one-shot and re-association, especially accept sockets under the mutex, are essential. Timer/user sources are handled separately. It is not epoll with renamed calls.

### Buffered upstream pipe and ownership

`ngx_event_pipe` alternates downstream write and upstream read until no work/blockage remains, then reconciles backend registration and read/send timers. Input is not read without available buffers: it reuses raw buffers, allocates only up to configured `bufs.num`, favors writing a ready downstream, optionally spills to bounded temp storage, or stops reading. Rate delay is represented by the upstream read event's delayed flag and timer. See `ngx_event_pipe.c:23–345`.

The pipe has separate raw/input/output/busy/free/writing chains (`ngx_event_pipe.h:25–96`). Shadow buffer aliases prevent copying but mean raw storage cannot be reused until the last shadow is consumed. Busy limits count underlying recycled storage, not repeated aliases. Cacheable data and AIO temp-file writes have different retention/completion rules. The output filter updates free/busy chains; only a last shadow returns raw storage to the free list. Error drain also unlinks shadow ownership. See `ngx_event_pipe.c:498–1129`.

Preserve preread bytes, partial buffer positions, temp-file offsets, buffer tags and last-shadow boundaries. Do not collapse EOF/error/upstream_done/downstream_done: they drive final flushing and cache handling. The copy input filter clips data exceeding declared Content-Length and warns; arbitrary retries after partial forwarding would violate these ownership/protocol boundaries.

### Generic UDP

`ngx_event_udp.c:25–379` uses a shared listener socket and a static receive buffer; an existing logical UDP connection borrows a stack buffer only during its immediate callback. New logical connections copy initial bytes into connection-owned storage. Lookup keys include the peer and wildcard local address; CRC selects tree position but full address comparison resolves collisions. Cleanup removes the logical entry without closing the shared listener (`:390–590`). Retaining pointers to the transient datagram buffer beyond the callback would be invalid.

### Candidate changes and tests

Start with sampled counters for accept saturation, EMFILE backoff, posted wait, pipe memory/temp-file spill and downstream stall duration. Benchmark overhead with sampling disabled/enabled. For any accept/batch/timer tuning run short/long mixed connections, unequal worker pressure, exhausted fd pools, half-closes, fd reuse within a dispatch batch and reload under load. For pipe changes test slow clients, cache on/off, chunked/declared-length mismatch, aborted clients, AIO completion and small buffer caps before measuring throughput, p99, allocations and disk bytes.

## Read checkpoint 3: OpenSSL core and object cache

The complete 6,872-line OpenSSL core, 419-line header and 1,267-line object cache are now read. Total full coverage: 24 files / 18,377 lines. Stapling/OCSP and QUIC remain unread at this checkpoint.

### Nonblocking TLS callback chain

`ngx_ssl_create_connection` allocates per-connection SSL state, sets fd and client/server role and installs ex_data back-reference. `ngx_ssl_handshake` drives `SSL_do_handshake`; WANT_READ/WANT_WRITE clears the corresponding readiness, replaces both event callbacks with `ngx_ssl_handshake_handler`, reconciles event registration and returns NGX_AGAIN. A later readiness callback resumes the state machine, then invokes the saved protocol-level completion handler. Success installs TLS recv/send functions and still passes through OCSP validation before setting handshaked. These are nonblocking socket state transitions, not evidence of arbitrary asynchronous HSM/crypto-job support.

`ngx_ssl_recv` drains SSL_read until no data or destination capacity, because TLS-buffered records do not map one-to-one to kernel socket readability. When kernel availability is exhausted but TLS may buffer bytes, it reposts read to the next event-loop iteration. SSL_read can WANT_WRITE and SSL_write can WANT_READ: saved opposite-direction handlers are temporarily replaced and later restored/reposted. A fork must preserve this cross-direction dependency and the existing timeout owner; adding a new timer on both directions can create conflicting deadlines.

`ngx_ssl_send_chain` coalesces buffers into a configurable TLS buffer (default16KiB) because OpenSSL has no SSL_writev, honors flush/last-buffer markers and tracks pending TLS-buffered bytes. KTLS sendfile is selected only when the negotiated BIO reports capability; file truncation, partial send, EBUSY/NODISKIO and WANT_READ/WRITE have explicit paths. Do not globally remove copies or force sendfile based solely on OS support.

Shutdown skips SSL_shutdown during incomplete handshake, distinguishes quiet/no-wait/no-send policy, may require two close_notify calls, and resumes via read/write handlers with a 3000ms read timer when blocked. QUIC streams share SSL ownership and bypass ordinary SSL object free. Completion resets connection recv and frees SSL only under the right ownership flags.

### Authentication, secrets and compatibility boundaries

The verification callback records errors but returns1; certificate acceptance policy is consumed above this shared wrapper via SSL_get_verify_result and host/OCSP checks. Do not label this alone a verification bypass or change it without checking HTTP/stream/mail callers (outside this manifest). Host verification explicitly distinguishes IP SAN from DNS, and old-library fallback uses SAN before CN, with constrained wildcard matching.

TLS1.3 session resumption adjusts lifetime to configured remaining timeout to avoid endlessly extending resumed sessions past certificate expiry/revocation. Session IDs are scoped by context, certificates and client CA names. Shared session caching serializes ASN.1 outside the shared slab mutex, bounds session/id size, resolves hash collisions by full IDs, expires a small bounded number per operation and explicitly zeros session bytes on eviction. Ticket rotation keeps current/previous/next keys, synchronizes shared state under lock, retains decryptability for issued-session lifetime and zeros temporary/key storage.

Certificate chains and keys have distinct OpenSSL reference ownership. A cache pair mismatch invalidates and retries once, addressing uneven cert/key refresh. Configuration-cycle object cache may inherit references only when type/key and file uniq+mtime match; runtime object cache uses valid/inactive/max rules with an LRU-like expiry queue. `data:`, file, engine and OpenSSL store sources are distinct; encrypted keys disable object caching where required. Password buffers are copied only for runtime use and explicitly zeroed at cleanup; empty-password arrays avoid worker stdin prompts. Do not replace ref/free pairs with memcpy or turn key-source strings into unrestricted remote management inputs.

Version/provider branches cover OpenSSL, LibreSSL, BoringSSL/AWS-LC, ECH, certificate compression and newer/deprecated API variants. Source-level #ifdef coverage is not proof each variant has been built/tested. Preserve alert mapping and legacy library workarounds until support policy and an interop matrix justify deletion.

Candidate measurements: handshake wall/CPU by full/resumed session and chain size, WANT_READ/WRITE resumptions, SSL buffer copies/request, KTLS fallback rate, session cache lock hold time/miss/eviction, cert-cache hit/reload time. Do not change TLS crypto, replay semantics, session lifetime, trust policy or ticket-key rotation as a speed optimization. TLS1.3 early data requires application-level replay/idempotency policy; enabling it globally is not a safe latency shortcut.

## Read checkpoint 4: complete stapling and client OCSP

All 25 non-QUIC event files are fully read: 21,207 lines. `ngx_event_openssl_stapling.c` was read in explicit ranges1–700,701–1400,1401–2100,2101–2830.

Stapling and client-certificate OCSP are separate policies. Stapling callback serves a copied valid cached response immediately (OpenSSL takes response ownership), then triggers background refresh only if host exists, not loading and refresh deadline passed. Refresh validates response/status, replaces stable storage outside the temporary context and uses bounded refresh/backoff times. Client OCSP validates the verified chain (depth policy), consults shared status cache, asynchronously queries each required certificate, and resumes the TLS protocol completion handler. Caller must still consume verification/OCSP status; shared TLS wrapper does not decide all application authentication policy.

The outbound chain is request creation → asynchronous resolver → nonblocking connect-peer → write/read callbacks → incremental HTTP status/header/body parser → OCSP signature/id/time validity verification → result/cache/completion. It retries configured resolved addresses on connection/timeout/parse failure, resets parser/request cursors, removes resolver/connection state and finally destroys the dedicated context pool. Response storage is16KiB; body completion is EOF-driven (`TODO honor Content-Length` remains in source). Responder prefix is explicitly HTTP, not an assumed general HTTPS client. Do not replace this with blocking DNS or synchronous network I/O inside the handshake.

Shared OCSP cache keys issuer identity/public key/serial rather than request URL; entries store certificate status plus validity, compare full keys, expire on lookup and evict boundedly under allocation pressure. No-nextUpdate results are capped to an hour for cache storage, distinct from the stapling in-memory validity handling. Signature validation flags depend on configured staple verify policy; preserving safe policy semantics matters more than reducing handshake work by skipping verification.

Fault-injection follow-up candidate (not a confirmed deployed bug): in `ngx_ssl_stapling_update`, loading is set before allocating the OCSP context; allocation failure returns without the usual completion resetting loading. Verify behavior with forced allocation failure and determine whether a bounded retry/reset is warranted. Also test fragmented response parsing, oversized status/header/body, multiple addresses, resolver cancellation and connection-close during client OCSP before changing this state machine.

## Read checkpoint 5: QUIC state/header contracts, tokens, logical sockets and BPF source/generation

All QUIC headers plus tokens/socket implementation and BPF helper/build/generated instruction table were fully read. Reading the generated table is not a verifier execution or proof its compiled bytes match a locally rebuilt toolchain.

QUIC separates four encryption levels from three packet-number spaces:0-RTT/1-RTT share application space. Each send context has generated/sending/sent queues, crypto buffer, ACK ranges and packet numbers. Connection-level events separately drive push/PTO/close/path-validation/key-update. Stream send/receive state enums, stream/connection offsets and flow-control maxima are independent from UDP datagram readiness. Keep these units and ownership distinct (`ngx_event_quic.h`, `ngx_event_quic_connection.h`, `ngx_event_quic_transport.h`).

Native OpenSSL QUIC API, quictls API, BoringSSL/AWS-LC/LibreSSL API and an OpenSSL compatibility adapter are compile-time branches. Header selection does not imply identical features/performance or that all variants were executed.

Token creation uses authenticated AES256-GCM with random IV, bounded token size, expiry and address hash; retry tokens bind port while NEW_TOKEN can tolerate port change. Validation distinguishes garbage/auth failure (ABORT) from authenticated-but-invalid/expired/address mismatch (DECLINED); only success marks validated and restores original DCID. Stateless-reset token derivation includes host secret, worker and CID. Preserve authenticated fields and error distinctions; do not substitute CRC/hash routing for token authentication.

QUIC sockets in this layer are logical CID registrations sharing a UDP listener, not a fresh OS socket per stream. Initial socket setup registers newly generated server CID plus temporary initial DCID, records client CID and path, and keeps registration queues/free lists aligned with listener rbtree entries. Close removes logical registrations without treating the shared UDP fd as per-stream ownership.

BPF helper first routes matching DCID key to a reuseport worker socket; a new/unknown CID uses hash distribution across current/previous worker-count generations with fallback during reload. Packet bounds are checked through direct data bounds or bpf_skb_load_bytes; failure returns SK_DROP. The first8 DCID bytes have a routing-key contract; reserved0xFF keys designate listener sockets. Generated program relocates sockmap and worker-count maps. Preserve source-generator-relocations coherence and test worker-count changes, reload and DCID rebinding before tuning this path. No BPF program was loaded here.


## Read checkpoint 6: QUIC connection lifecycle and frame dispatch

`ngx_event_quic.c` was read completely in ranges1–750,751–1523. Full coverage now47/59 files,25,180/39,098 lines.

The input callback parses every coalesced packet in a datagram; a declined undecryptable packet does not prevent attempting later packets. Undecryptable packets are not queued here: recovery relies on retransmission. Initial connection creation sets three packet-number contexts, crypto keys, RTT/PTO state, congestion window and separately posted push/path/key-update/close callbacks. New connections accept Initial packets subject to CID/token/address-validation/retry constraints; version negotiation and stateless reset have separate paths. Tokens are authenticated separately from address hashes.

Packet handling checks keys/encryption level, decrypts, associates path, initializes TLS, discards obsolete key spaces and dispatches each frame. Stack frame/buffer structs and a static plaintext buffer are temporary; handlers must copy retained bytes. ACK-eliciting/probing distinctions affect acknowledgment and migration; padding/ACK alone do not elicit ACK. Initial/Handshake/Application packet numbers and encryption key lifetimes cannot be merged. Application key-phase switch installs the new keys before posting next-key generation. Transport parameter checks include source-CID match, UDP payload bounds, CID limit, ACK exponent and negotiated idle timeout.

Closing is a state machine: discard queued retransmission work, optionally send CONNECTION_CLOSE at available levels and wait3*PTO, drain/close streams, cancel posted events/timers, remove logical sockets and clean keys, detach UDP state before SSL shutdown, close the fd and destroy the pool. Silent timeout/reset draining differs from immediate fatal failure. Shutdown reason can wait until no active streams. Calling close twice or freeing the connection while posted callbacks remain would break ownership. Flood heuristic compares transport bytes with application stream progress plus a fixed allowance; it is not a per-IP rate limiter. Preserve close/key-discard/frame accounting until loss, reordering, migration and draining tests demonstrate a change.


## Read checkpoint 7: ACK/loss/CUBIC, buffers, CIDs, migration and QUIC receive

Full coverage52/59 files,29,476/39,098 lines. ACK, connid, frames, migration and UDP implementations were read fully; exact ranges are in the JSON ledger.

`ngx_event_quic_ack.c` validates ACK arithmetic and rejects acknowledging never-sent packet numbers, updates RTT only for a newly acknowledged largest packet with eligible tracked data, accounts ACK delay against minRTT/handshake policy and walks sent frames in packet-number order. Packet accounting lives on frame.plen (one accounted frame per packet); retransmission removes/requeues frames with semantics-specific updates: fresh MAX_* values, discard obsolete stream frames/ACK/PING/path probes, regenerate ACK when needed. Preserve accounting across ACK/loss/key-space discard/migration reset to avoid double decrement or congestion-window inflation.

This source uses CUBIC with Reno-friendly estimation, application-idle time compensation, recovery epoch gating, beta0.7, min2*MTU window and persistent-congestion handling. Loss time threshold is max(latestRTT,smoothedRTT)*9/8 with1ms floor; packet threshold is at least3 and can grow with outstanding packet-number span. A single timer selects earliest loss deadline before PTO; PTO grows exponentially and sends two congestion-exempt PING probes per expired eligible space. Delayed application ACKs are posted/timed with gap2 and max_ack_delay; out-of-order arrivals force ACK, finite range slots coalesce/split/drop oldest with immediate fallback ACK. Do not assume the recovery code is a simple fixed Reno implementation or lower all timers to speed it up.

`ngx_event_quic_frames.c` separates reusable frame metadata,4096-byte backing buffers and cloned shadow descriptors. The backing shadow's reference count determines reuse; splitting preserves payload ownership and FIN stays on the last fragment. Ordered receive buffers represent holes with sync descriptors, skip duplicates and only expose a contiguous prefix; consumed offsets and last-chain optimization remain coherent. Frame count is bounded by configured stream-derived maximum; free lists reuse memory until connection pool teardown. Avoid replacing holes/refcounts with eager contiguous copies without measuring sparse/out-of-order memory and copy cost.

`ngx_event_quic_connid.c` enforces sequence-number consistency, monotonically increasing retire-prior-to, advertised client CID limits, forbidden retirement of the packet's own DCID and reissues server CIDs up to min(peer limit,8). CID-in-use retirement must replace the active path CID or free the old path; BPF routing prefix is attached to random server CIDs only for applicable listeners.

`ngx_event_quic_migration.c` accepts migration only from the highest-numbered non-probing packet; a single probe path and spare CID avoid unbounded unknown-path growth. PATH_RESPONSE must match one of the random challenges and response goes on the challenged path. Anti-amplification bounds constrain1200-byte padding. Address change resets RTT/congestion and excludes old packet numbers; port-only change can preserve path estimates. Failed active validation restores last validated backup or returns no-viable-path. PMTU discovery waits100ms, probes/bisects toward peer payload limit with16-byte precision, ignores probe loss for congestion, tracks ACKed packet numbers and treats EMSGSIZE distinctly. Changing MTU/probe retry policy needs black-hole, NAT rebinding and loss tests.

`ngx_event_quic_udp.c` demultiplexes by full DCID plus local address for wildcard listeners (CRC is only index). Existing connections borrow a static datagram buffer only during the immediate callback; a new connection copies it. Shared listener/worker fd ownership is explicit; the logical connection does not close that shared UDP fd. BPF worker-only listeners drop unknown connections rather than accidentally accepting them. Preserve borrowed-buffer lifetime and kqueue byte-availability accounting when evaluating batched recvmsg/recvmmsg.


## Read checkpoint 8: BPF lifetime, QUIC TLS APIs and packet protection

Full coverage56/59 files,33,654/39,098 lines. Complete BPF manager, OpenSSL adapter, QUIC SSL and protection implementations are now read.

BPF manager scopes sockhash/worker-count maps by listener address, duplicates old map fds on reload, exports inheritable descriptors through NGINX_BPF_MAPS for binary upgrade and flips master generations. Worker sockets use random non-reserved routing keys and lazy event connection registration. quic_bpf cannot change on reload; disabling during binary upgrade with inherited maps is rejected. Initialization failure at initial start fails; failure during reload is logged and tolerated because immediately exiting the master would orphan workers, and the source explicitly warns of potentially inconsistent state after partial kernel attachment. This needs operational fault-injection/reload tests, not a promise of transactional BPF reconfiguration. Map sizing is worker_processes*32; retain capacity/reload assumptions until measured.

`ngx_event_quic_ssl.c` couples ordered CRYPTO buffering to TLS callbacks. Native OpenSSL QUIC-TLS dispatch supplies/releases records and secrets; BoringSSL/quictls-style callbacks copy outbound handshake bytes into CRYPTO frames, map encryption levels, and validate ALPN plus required client transport parameters. Errors raised inside callbacks are also recorded on qc->error and checked after SSL_do_handshake; return values alone do not express all failure policy. The CRYPTO offset window is65535 bytes and out-of-order holes must stay bounded. Handshake completion sets handshaked, emits HANDSHAKE_DONE, schedules next keys, discards handshake space, starts PMTU/CID issuance/streams. Early streams require early keys and parsed client parameters; replay policy still belongs above this transport.

OpenSSL compatibility is materially different: it derives secrets from a keylog callback, synthesizes TLS records into a memory BIO and extracts outbound handshake/alerts with message callbacks; early data is explicitly disabled. The keylog callback name does not mean ordinary builds persist secrets to a keylog file. This extra record construction/copying is a measurable compatibility cost, not evidence to delete it for all supported libraries. Test each supported build/API independently.

`ngx_event_quic_protection.c` derives Initial secrets from version-specific salt/DCID; TLS-selected ciphers determine AEAD/header protection/hash. Each packet XORs the packet number into an IV-derived nonce, authenticates the unprotected header, then applies header protection. Decrypt reconstructs packet number into a local candidate, verifies AEAD first, rejects zero-frame payload/reserved bits and only then advances the largest received packet number. Preserve this commit-after-authentication invariant. Key update uses precomputed next keys to reduce timing leakage, retains header-protection context across application key updates, frees replaced AEAD contexts, and explicitly zeros temporary/stored secrets where coded. Crypto debug macros can expose secrets/plaintext; do not enable them in production telemetry. Do not optimize by weakening authentication, reusing nonces, advancing state before tag verification or changing key-discard timing.


## Read checkpoint 9: QUIC output transaction and streams

Full coverage58/59 files,36,883/39,098 lines; transport parser is partial1–600 at this checkpoint.

`ngx_event_quic_output.c` already supports UDP GSO (compile/config gated), at most64 segments and65487-byte batch buffer. It requires validated paths, no Initial/Handshake queued frames and sufficient queued application data/congestion headroom before batching. It coalesces encryption levels into datagrams, preserves minimum Initial/header-protection sample padding and applies per-path3x received-byte anti-amplification budget. Do not propose GSO as an absent feature or force it on unvalidated paths.

Output has generated→sending→sent transaction queues. Packet numbers and queued frames are tentatively advanced while encrypting, but bytes-in-flight/sent queues commit only after send succeeds. EAGAIN reverts sending frames and packet numbers then schedules10ms push retry; a frame's plen charges packet bytes once. The immediate frame-send path has its own accounting/free rules. Stateless reset length is smaller than triggering packet and filtered through a fixed64KiB probabilistic per-worker bitmap refreshed each second; it is bounded-memory suppression, not exact per-IP admission. Close retransmission is interval-limited; Retry stops coalesced-datagram processing after one response. Candidate observability: send EAGAIN/retry delay, GSO eligibility/batch size, padding, anti-amplification blocked duration and ack-only sends; measure overhead and p99 before changing heuristics.

`ngx_event_quic_streams.c` exposes each logical stream as a shared-fd ngx_connection_t with its own pool/events and parent-owned TLS/transport. Stream IDs encode initiator/direction and opening a higher ID implicitly opens lower same-type IDs within negotiated limits. Initialization posts application read handlers and postpones push to coalesce application output; it also waits for asynchronous client OCSP where configured. Stream construction failure may reject with configured RESET/STOP policy rather than break ownership.

Three pressures stay separate: application unacknowledged send-buffer cap, peer per-stream/connection MAX_DATA, and congestion/path send budget. send_chain copies only up to acked+stream_buffer_size-sent; ACK frees room and posts write readiness, while MAX_* flushes blocked stream frames. Receive accounting advances by highest observed offsets (including gaps/reset final size), checks both flow limits, preserves final-size consistency and only posts readable contiguous bytes/EOF. MAX_DATA/STREAM_DATA are replenished from consumed offsets at half-window, not receipt alone. Aggressively increasing windows trades bandwidth-delay-product utilization for retained memory; measure both.

Stream cleanup can remove the application connection while transport state remains awaiting final size/send acknowledgment. Final close waits for terminal states, then frees chains/removes tree node/recycles metadata and replenishes client stream count; connection closing posts continuation until streams drain. Cancelable streams determine reusable/shutdown eligibility. Never close the shared UDP fd or free parent SSL from a logical stream. Benchmark many streams with unequal flow-blocking; current connection MAX_DATA wakeup walks stream tree in ID order, so fairness changes are a hypothesis requiring per-stream completion-time and starvation evidence.


## Read checkpoint 10: transport parsing/serialization complete

`ngx_event_quic_transport.c` was fully read in1–600,601–1200,1201–1800,1801–2215. All59 manifest files/39,098 lines are now full_read. No platform, TLS API variant, BPF verifier or live network test was executed in this review.

The parser bounds each fixed/variable-length read, separates long/short header layout and only advertises QUICv1 in this snapshot. Long headers enforce CID length, Initial datagram minimum, token length and contained packet length; a short header consumes its configured fixed server CID length. Frame permission masks vary by packet encryption type; receiving server-only NEW_TOKEN/HANDSHAKE_DONE is disallowed. STREAM variants normalize flags while preserving optional offset/length/FIN semantics, and lengthless STREAM consumes the rest of the packet. ACK ranges are syntactically bounded here and arithmetically checked in ack.c. Serializer supports a sizing pass (NULL destination), then writes exact frame/header bytes; caller supplies sized storage. Preserve the two-pass agreement, varint62-bit limits, endian/alignment portability and authenticated packet boundaries.

Transport parameters have syntactic parsing here, semantic limits in ngx_quic_apply_transport_params and source-CID comparison elsewhere. Unknown/reserved IDs should remain extensible; values are borrowed from stable TLS callback data where appropriate. Local receive windows derive from stream concurrency*buffer sizes; 0-RTT context serializes the compatibility-relevant prefix before ACK/CID/token parameters.

### Targeted reproduction candidates, not confirmed runtime defects

1. `transport.c:1619–1720,1725–1790`: public parse loop holds64-bit varint parameter IDs, while helper accepts uint16_t. Source-level narrowing can alias a high unknown ID to a recognized low ID. A differential corpus should include IDs separated by65536 and assert unknown-ID behavior; test through every TLS API path before drawing a deployment/security conclusion.
2. Same parser has no visible duplicate-ID set; scalar helper reads a varint without requiring its returned cursor to equal that parameter's declared end. Build malformed/duplicate/trailing-byte parameter cases against the intended protocol policy. Confirm results with a small C harness or real client and compare upstream tests/spec before choosing a fix. Bounds-checking of the enclosing field alone does not establish all semantic validation.
3. `ngx_event_openssl_stapling.c:656–679`: loading is set before ngx_ssl_ocsp_start; failed context allocation returns before completion resets it. Force exactly that allocation failure and check whether refresh can recover. This is a source-path observation, not an observed outage.
4. `streams.c:1320–1360`: when connection MAX_DATA reopens, flushing walks streams in ID order until connection budget is spent. Instrument per-stream service/wait time under mixed stream demand to determine whether fairness work is warranted; no starvation measurement has been made.

## Вывод для NGINX fork

В рассмотренном слое уже есть зрелая событийная модель, backpressure, nonblocking TLS, кэширование сессий и сертификатов, QUIC CUBIC, loss/PTO, миграция, PMTU, GSO и BPF-маршрутизация. Их повторная реализация не является доказанным улучшением. Практичная первая работа — воспроизводимый baseline, наблюдаемость причин задержек и небольшие изменения с измеримым эффектом. Этот обзор не доказывает ускорение в10раз и не покрывает HTTP/stream/mail-конфигурацию вне указанного manifest.

### Карта callback/state chains

| Цепочка | Состояние, которое нельзя терять | Опорный исходник |
|---|---|---|
| backend poll → posted accept → unlock → timers → posted ordinary | ready/active/instance и порядок планирования | event.c:195; event.h; posted.c |
| accept/connect → listener/protocol callback | владелец fd/pool, AGAIN/DECLINED/ERROR, pressure backoff | accept.c:21; connect.c:21 |
| upstream read → raw/input/shadow → downstream/temp write → recycle | last_shadow, busy byte cap, partial positions, AIO ownership | pipe.c:23–1129 |
| TLS handshake → WANT_READ/WRITE → event callback → saved protocol continuation | cross-direction handler/timeout ownership, OCSP completion | openssl.c; openssl_stapling.c |
| UDP DCID lookup → datagram/packet decrypt → frame dispatch | borrowed bytes, three packet spaces, authenticated state advance | quic_udp.c; quic.c; protection.c:1129 |
| CRYPTO reassembly → TLS API callback → queued CRYPTO → handshake done → stream initialization | crypto hole/window bounds, ALPN/TP, key discard | ssl.c:627–996 |
| STREAM recv/send → consumed offsets / peer MAX_* / ACK → posted readiness | receive final size, stream+connection flow and unacked buffer cap | streams.c:952–1824 |
| frame queue → packet encrypt → socket send → commit or revert → ACK/loss/PTO | single packet-byte charge, retransmission semantics, timer ownership | output.c:115–276; ack.c |
| new path → challenge → response/timeout → active or validated backup | anti-amplification, CID ownership, RTT/congestion reset | migration.c |

Here and below, short source names refer to their complete ngx_event_* names under src/event or src/event/quic, as recorded in the ledger.

### Измеримые предложения и критерии решения

| Приоритет / изменение | Что измерять | Обязательная проверка перед принятием |
|---|---|---|
| P0: regression corpus для TP parser и OOM stapling | воспроизводимый вход, точный код/alert и восстановление; security/performance эффект пока не установлен | реальный C/TLS path, разные TLS API, санитайзеры и подтверждение ожидаемой протокольной политики |
| P1: опциональные bounded counters/histograms, sampled trace | время posted wait/handler, accept pressure, TLS WANT-resume, pipe stall/spill, QUIC ACK/PTO/retry/GSO; CPU и p99 при telemetry off/on | отсутствие secret/plaintext logging, блокирующего I/O и выделения памяти на каждое событие; лимит кардинальности |
| P2: эксперимент с UDP receive batching | syscalls/datagram, CPU/Гбит, socket drops, event-loop pause, p99, память | IPv4/IPv6 wildcard cmsg, truncation, CID demux, borrowed-buffer lifetime, fallback без batching; GSO уже существует |
| P2: QUIC write EAGAIN retry tuning и stream wake fairness | доля EAGAIN, фактические10ms задержки, полезная скорость, per-stream wait/completion и Jain fairness | никакого busy-loop; сохранение send commit/revert, cap/ACK accounting; смешанные размеры и потоки с blocked MAX_DATA |
| P2: TLS native API/compat/KTLS/cache tuning по workload | full/resumed handshake CPU+p50/p99, копии, cache miss/lock time, KTLS fallback | одинаковые crypto/trust/session политики, библиотека/ядро/CPU pinned, матрица interop и аварийные ветки |
| P3: pipe buffer/spill/rate policy для BDP workload | RSS/соединение, disk bytes, throughput и p99 для slow consumers | buffer cap, cache/AIO, разрывы, Content-Length mismatch, shadow refs и финальный flush |

Это гипотезы для экспериментов. Ни для одной в этом задании не получены runtime-метрики или подтверждённый выигрыш. Порог принятия следует объявить до теста (например, требуемое снижение CPU при допустимом p99), затем проверить на повторных запусках и соседних нагрузках.

### Что не менять без baseline и regression matrix

- Edge/level/one-shot registration, instance stale-event checks, posted/timer unlink-before-callback, accept mutex ordering и EMFILE backoff.
- TLS trust checks, replay/early-data policy, nonce/key derivation, session/ticket lifetime, key discard/zeroing и cross-direction WANT_READ/WANT_WRITE.
- QUIC congestion/RTT/loss/PTO/ACK арифметику, anti-amplification, migration validation, packet-number spaces или buffer/refcount caps ради рекламного ускорения.
- Shared UDP/stream fd и SSL ownership, shadow last-owner recycling, send commit/revert, logical CID lifecycle и BPF generation/reload mapping.
- Platform/library compatibility branches без явной политики поддержки и выполненных build/interop тестов.

Первый reproducible benchmark должен фиксировать commit/build flags, TLS library/kernel/CPU/NIC, worker count/affinity, FD/memory limits, одинаковые cert/cipher/cache/GSO/BPF настройки, внешнюю машину генератора, concurrency, mix sizes, warmup и длительность. Отдельно измерять TCP/TLS/QUIC, full/resumed handshake, slow clients и NETEM loss/RTT/reordering/migration; собирать goodput, ошибки, p50/p95/p99, CPU, RSS, drops и disk I/O. Сравнивать fork с неизменённым тем же NGINX commit повторными чередующимися запусками, сохраняя raw results и доверительные интервалы. Нельзя переносить loopback microbenchmark или throughput одного сценария на утверждение о всех функциях/10x.

## Evidence boundary

Completed: full source reading of the exact59-file manifest, incremental notes, range/hash/line-count/commit validation. Not performed: NGINX compilation, live traffic, platform backend tests, OpenSSL/provider matrix, BPF load/verifier test, protocol conformance/fuzzing, fault injection, performance comparison. The candidate observations above remain unconfirmed until those checks. No NGINX source or product code was modified by this review.
