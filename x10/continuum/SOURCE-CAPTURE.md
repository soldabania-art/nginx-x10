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

## Opt-in retained source-copy lifetime

The additional `capture-held` action extends the same genuine live-hold
scenario. It retains only the already documented record-material subset, not
full semantic TLS state. The original transient `capture` action remains a
create/compare/destroy operation; no target object or importer is introduced.

A private C-owned opaque slot keeps mapping ownership and public bindings, not
another secret copy. A by-value nonzero generation is scoped to this native
process/hold and is bound to the original SSL pointer, ledger identity and
snapshot, nonce, call serial and the original monotonic hold deadline. The
process-local generation counter refuses exhaustion without wrapping. A closed
slot cannot reopen; its tombstone lives until hold exit so stale generation
values do not cause a free-then-dereference API. No pointer crosses into JS.

The slot becomes READY only after protected allocation, actual copy, read-only
protection and fresh source equality. `CAPTURE_HOLD nonce serial` emits one
`capsule-ready` while that protected mapping is still live. The trusted runner
can then provide a bounded `onCapsuleHold` callback with frozen public metadata.
Its exact inert decision is `DISCARD nonce serial generation` or the matching
ABORT. Neither callback nor capsule creation restarts the original three-second
native hold deadline; the cooperative JS budget is reduced against its remainder.
A timed-out callback result has no later command or reacquisition authority.

DISCARD checks the live generation/source/ledger/nonce/expiry, then always
revokes and destroys the copy. Internal abort cleanup is independent of expiry
and interruption and remains available after authorization has failed. Cleanup
revokes READY before system calls, restores writable protection, cleanses the
whole accessible page, verifies zero through volatile reads, unlocks and unmaps.
The single `capsule-cleared` receipt precedes any hold release. Cleanup alone
never grants source resume; a valid decision, successful cleanup and post-clear
deadline/interruption/transport checks are all required for release.

ABORT, stale/malformed/duplicate decisions, observed transport activity, native
expiry or handled SIGTERM after READY require destruction and refusal without
later TLS READ/WRITE/control/shutdown. A failed restore/unmap cannot claim an
explicit wipe; the source must refuse continuation and exit. The runner gives
owned children a bounded SIGTERM cleanup grace before SIGKILL escalation,
independent of the already aborted operation signal. A failure may carry a
checked public cleanup receipt only after actual native close, exactly one
ordered READY/CLEARED pair, matching bindings, a valid output channel, no release
and no forced termination. That receipt does not turn the original failure
into a successful operation. SIGKILL/crash remains explicit-wipe-unknown.

### Source API allowlist during READY

The retained-copy profile allows only the slot generation/check/discard/internal
cleanup operations and the existing read-only profile/probe helpers. It forbids
source TLS/BIO I/O, key updates, shutdown, session setters, arbitrary application
callbacks or other state-mutating calls while READY. This trusted single-thread
fixture discipline is not a concurrent-application fence. Socket peek/poll remain
samples, not transport ownership. Returned JS results are historical after the
copy and source are cleaned up; retained metadata is not live authority.

The slot does not preserve or implement target authentication/session/exporter,
Finished/resumption/ALPN APIs, fresh provider/cipher reconstruction, future record
budget enforcement or later KeyUpdate semantics. Those full semantic/API gates,
exclusive target I/O ownership, distinct TLS code, source retirement and native
NGINX integration remain unaccepted. Protections still cover only this extra
mapping, not the original SSL/EVP heap, compiler temporaries or Node oracle.

## Failed destruction and bounded retry

An unmap failure no longer makes the owned mapping unreachable to a later
cleanup call. A FAILED slot with a remaining mapping may retry destruction,
including the existing terminal free call. Its failure stays latched: later
zeroing/unmapping cannot grant READY, a successful discard or source resume.
There is no retry loop and no retry beyond the trusted caller's bounded calls.

If restoring write access fails after a copy, cleanup keeps that nonzero page
locked while attempting unmap. It does not call munlock before a verified
whole-page cleanse. Successful unmap itself removes the mapping and its lock;
that does not prove explicit wiping. A successful munlock clears the internal
ownership flag so an unmap retry does not repeat an already completed unlock.

The unchanged implementation was shown to skip a second unmap after one
injected failure and to unlock uncleaned bytes after a combined restore/unmap
failure. These are synthetic production-translation-unit fault controls, not
live TLS admission or migration tests. The bounded fix preserves permanent
failure and mandatory terminal source exit. Persistent OS failure, crash or
SIGKILL still cannot promise explicit erasure; free is best-effort, not a
general recoverable allocator. Exact cases and identities belong in the
[protection evidence](../evidence/continuum-capture-protection.json).


## Separate pre-capture API metadata observation

`inspect-api` is a mutually exclusive opt-in decision on the existing live
hold, not an operation on a READY retained slot. C binds `API_INVENTORY` to
current nonce/call serial and the original three-second deadline, reobserves
probe/ledger, compares two fully initialized API metadata structs and a final
probe, then emits one receipt before ordinary source release. Existing hold
ready/released schemas and continue/capture/capture-held paths are preserved.
The READY source API allowlist above is not expanded by this separate action.

The observer reports exact existing ALPN profile/length, local/peer Finished
lengths queried with nonnull dummy/count0, server-only/no-client-auth status
and non-reused session presence. It copies no Finished/certificate/secret
values and calls no exporter, session serializer, refcounting getter or TLS I/O.
Original library API capabilities are not disabled: false `*Preserved` flags
state only that this experiment does not preserve them. Returned JS metadata
is frozen historical data without source-held or export authority.

Equal metadata does not preserve Finished values or complete authentication,
exporter/session/resumption/PHA/KeyUpdate/provider state. Control-channel
schema/order failure remains a strict failure, not an erasure proof: generic
invalid-channel policy can SIGKILL after a real source release. Tests and
[API evidence](../evidence/continuum-api-inventory.json) keep this separate from
native binding refusal before release. No importer or ownership transfer is added.
