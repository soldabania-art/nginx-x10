#ifndef X10_CONTINUUM_OPENSSL_CAPTURE_H
#define X10_CONTINUUM_OPENSSL_CAPTURE_H

#include <signal.h>
#include "openssl-probe.h"

/* Public receipt only: never a secret-bearing capsule or pointer. */
typedef struct {
    unsigned int captured, locked, dont_dump, dont_fork, read_only;
    unsigned int source_unchanged, cleansed, unmapped;
    unsigned int secret_bytes, iv_bytes, sequence_bytes;
} X10_CAPTURE_RESULT;

/* One trusted C owner retains this opaque slot until the current hold exits.
 * A generation is a by-value token, never an address or secret. Destruction
 * revokes it but keeps the slot tombstone alive, so stale tokens cannot reopen
 * or inspect freed storage. This is a source-copy lifetime, not TLS import. */
typedef struct x10_capture_slot_st X10_CAPTURE_SLOT;

X10_CAPTURE_SLOT *x10_capture_slot_new(void);
int x10_capture_slot_open(X10_CAPTURE_SLOT *slot, const SSL *ssl,
    const X10_PROBE_LEDGER *ledger, const X10_PROBE_RESULT *initial,
    const char nonce[33], int64_t deadline_ms,
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *result);
uint64_t x10_capture_slot_generation(const X10_CAPTURE_SLOT *slot);
int x10_capture_slot_check(const X10_CAPTURE_SLOT *slot, uint64_t generation,
    const SSL *ssl, const X10_PROBE_LEDGER *ledger, const char nonce[33],
    const volatile sig_atomic_t *interrupted);
/* Discard validates the live binding, then destroys even on a stale/expired/
 * interrupted request. It returns 1 only when both validation and cleanup
 * succeed. Cleanup alone proves no right to resume the source. */
int x10_capture_slot_discard(X10_CAPTURE_SLOT *slot, uint64_t generation,
    const SSL *ssl, const X10_PROBE_LEDGER *ledger, const char nonce[33],
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *result);
/* Internal abort cleanup is allowed after expiry/interruption. It is
 * idempotent, revokes before touching the mapping, and latches any failure. */
int x10_capture_slot_cleanup(X10_CAPTURE_SLOT *slot,
    X10_CAPTURE_RESULT *result);
/* Free only when the hold has ended and no caller can use the slot again.
 * It performs best-effort cleanup, but never converts failure into success. */
void x10_capture_slot_free(X10_CAPTURE_SLOT *slot);

/* Research-only, synchronous, single-owner source sample. Copies a restricted
 * initial TLS1.3/AES128GCM server record-material subset into a guarded Linux
 * mapping, locks/excludes that copy from dumps/fork, marks it read-only,
 * compares it with the still-held source, then clears and unmaps it before
 * returning. No SSL/BIO I/O, secret output, ownership grant or importer.
 * Original SSL/EVP allocations and any compiler temporaries are NOT protected
 * by the capsule mapping. SIGKILL/process crash cannot promise explicit wipe.
 * Return 1 ONLY after all steps including cleanup succeed, otherwise 0. The
 * caller must refuse all later TLS I/O and exit on failure. */
int x10_capture_source(const SSL *ssl, const X10_PROBE_LEDGER *ledger,
    const X10_PROBE_RESULT *initial, const char nonce[33],
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *result);

#endif
