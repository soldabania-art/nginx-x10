#ifndef X10_CONTINUUM_OPENSSL_USAGE_H
#define X10_CONTINUUM_OPENSSL_USAGE_H

/* Research-only admission policy for the initial TLS_AES_128_GCM_SHA256
 * application-key epoch. RFC 8446 section 5.5 discusses approximately
 * 2^24.5 full-size AES-GCM records. This deliberately lower, fixed cap is
 * 2^24 protected records per direction/key, counting all protected record
 * types in that epoch rather than only application payload records.
 *
 * next is the eight-byte, big-endian NEXT record sequence. Require next
 * strictly below 2^24: at least one record then remains below the cap.
 * Rejecting a high counter also rejects imminent uint64 sequence wrap.
 * Compare bytes directly; do not add headroom to a possibly maximal integer,
 * narrow to a native word, round through floating point or reset the counter.
 *
 * This helper neither validates epoch history nor enforces later I/O usage.
 * The probe's independent known/initial-generation and terminal-state guards
 * remain mandatory. An allowed observation is not a traffic grant, a runtime
 * key-update scheduler or proof of AEAD safety for a continued connection.
 */
static inline int x10_sequence_usage_allowed(const unsigned char next[8])
{
    if (next == 0)
        return 0;
    return next[0] == 0 && next[1] == 0 && next[2] == 0
        && next[3] == 0 && next[4] == 0;
}

#endif
