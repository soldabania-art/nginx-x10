# Source record-material sample: protected copy, then destruction

This opt-in research contract extends the pinned `quiescent-live-hold` fixture.
It is a synchronous, transient, read-only source sample. It is not a complete
semantic capsule, exporter, importer, ownership transfer or connection upgrade.
The ordinary `quiescent` path and native NGINX remain unchanged.

## Supported source and exact inventory

The source is the previously identified patched OpenSSL commit
`85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c`, server TLS1.3, initial
AES128GCM/SHA256 application keys only. All existing probe refusals still apply:
partial/control/alert/shutdown/retry state, unknown monitor or changed generation
is unsupported. The caller is the trusted, single-threaded C fixture, holding
the same SSL and ledger without any intervening TLS/BIO I/O call or application callback.

The private pointer-free representation contains schema1, generations0/0,
mutation serial2, current call serial and the current public C challenge, plus:

| Server direction | Bytes copied directly from the live source | Size |
| --- | --- | --- |
| READ | `client_app_traffic_secret`, `read_iv`, next `read_sequence` | 32+12+8 |
| WRITE | `server_app_traffic_secret`, `write_iv`, next `write_sequence` | 32+12+8 |

The actual active EVP contexts must identify AES128GCM with key length16,
IV length12 and the correct decrypt/encrypt directions. The negotiated cipher's public handshake-digest descriptor must identify
SHA256 with length32; a temporary handshake-only SSL field is not required
to survive establishment. No EVP object, pointer, session master
key, callback or opaque provider state is copied. This is a record-material
subset, not evidence that the entire established TLS state has been inventoried.

## Admission and lifecycle

The legacy `checkCapsulePreflight` stays `quiescent`-only. A separate
`checkHeldCapturePreflight` validates inert exact-field metadata: genuine held
scenario, immutable samples1/2, verified-build identity equality, current public
nonce/call serial and explicit directional application/handover/closure counts.
Both closure allowances must be positive; arithmetic stays exact under the
existing conservative `2^24` record cap. Matching public arguments is not
attestation or a freshness proof. The trusted runner obtains its expected
identity and challenge separately from the current harness and C-ready event.
No snapshot is relabeled to bypass the legacy checker.

The callback must explicitly return action `capture` with nonce, call serial
and budget. The runner checks the held metadata before sending exact bounded
`CAPTURE <nonce> <serial>\n`. A proposed record plan is review arithmetic only:
this experiment does not reserve/debit records or enable target I/O. C checks
its own decision binding, deadline, idle transport sample and fresh probes3/4
before calling the read-only sampler; no JavaScript result authorizes C state
without these independent native checks.

The sampler checks the current probe and ledger against the initial observation
and then allocates three anonymous private pages. The middle page becomes RW;
mlock, MADV_DONTDUMP and MADV_DONTFORK must succeed before any secret copy. The
outer pages remain inaccessible. The material is written directly into the
locked page, without a second secret-bearing stack struct, then the middle
page becomes read-only. Secret/IV equality uses constant-time comparisons;
public metadata/sequence and complete initialized probe/ledger samples must
still match the live source. The source is never changed by an importer.

Cleanup restores RW, cleanses the **entire accessible page**, inspects every
byte through volatile reads for zero, unlocks and unmaps all three pages.
Success requires every protection, equality and cleanup step. Only after this
returns successfully, the hold deadline/interruption/transport are checked
again and the public `capture-cleared` receipt is emitted before release.
The receipt contains fixed booleans and byte counts; it exposes no secret,
secret fingerprint, pointer or address. No capsule handle survives the call.
Normal source TLS closure resumes only after release.

Any capture/allocation/protection/source-mismatch/cleanup failure becomes
`hold_capture`: no success receipt, release or later TLS I/O. If restoring RW
fails, the sampler does not write a read-only page or claim a wipe; it attempts
unmap and refuses, and the owned source exits. Handled interruption follows the
normal cleanup path. SIGKILL, a crash or kernel failure cannot promise explicit
cleansing. Time limits are checked around synchronous native work; they are
not a scheduler-level preemption guarantee for an arbitrary blocked syscall.

## Explicit boundary

The protected mapping covers only this additional copy. Original SSL/EVP heap
allocations, compiler temporaries and the Node wire oracle are not protected by
it. Privileged debuggers and compromise of the trusted process are outside this
memory-hardening experiment. `sourceUnchanged` means the copied subset equals
live bytes at comparison and the probe/ledger observations match; it is not a
bytewise proof for every SSL/EVP allocation or a concurrency fence. Raw socket
peek/poll are transport samples, not an atomic no-arrival or ownership fence.

No authentication/session chain, exporter/Finished/resumption secrets, ALPN
API state, provider objects or future API obligations are preserved by this
subset. No claim is made for SSL export-keying-material/session APIs, later
KeyUpdate, target reconstruction or fresh AEAD object construction. Those need
an explicit complete first-profile semantic contract before a reusable capsule
or importer can be accepted. A successful sample merely returns to the same
source TLS implementation; old code does not retire before continuation.

The next gate is a reviewed fuller semantic inventory and a source-only,
protected lifetime/abort contract for a reusable capsule. Target import,
exclusive I/O ownership, a distinct TLS code version, source exit before target
continuation and opt-in native NGINX integration remain separate milestones.
