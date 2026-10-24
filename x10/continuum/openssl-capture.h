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
