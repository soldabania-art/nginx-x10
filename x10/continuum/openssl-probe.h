#ifndef X10_CONTINUUM_OPENSSL_PROBE_H
#define X10_CONTINUUM_OPENSSL_PROBE_H

/* Research-only metadata observer for the pinned, patched OpenSSL build.
 * No exporter/importer, I/O, ownership transfer or complete-state proof. */
#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

enum x10_probe_call {
    X10_CALL_NONE = 0, X10_CALL_ACCEPT = 1, X10_CALL_READ = 2,
    X10_CALL_WRITE = 3, X10_CALL_HANDSHAKE = 4,
    X10_CALL_SHUTDOWN = 5, X10_CALL_CONTROL = 6
};
enum x10_probe_outcome {
    X10_OUTCOME_UNKNOWN = 0, X10_OUTCOME_SUCCESS = 1,
    X10_OUTCOME_WANT_READ = 2, X10_OUTCOME_WANT_WRITE = 3,
    X10_OUTCOME_ERROR = 4
};

/* Fixture-maintained typed ledger. Only completion of the SAME outstanding
 * operation may clear retry_call. A successful unrelated call cannot clear it.
 * bound_ssl is compared, never published. One thread/owner is a caller contract;
 * this struct is not a concurrent-call detector, lock or security fence. */
typedef struct {
    uint32_t schema_version;             /* exactly 1 */
    const SSL *bound_ssl;
    uint64_t call_serial;                /* nonzero; no caller-side wrap */
    enum x10_probe_call active_call;
    enum x10_probe_call retry_call;
    enum x10_probe_call last_call;
    enum x10_probe_outcome last_outcome;
} X10_PROBE_LEDGER;

#define X10_REASON_INPUT          (UINT64_C(1) << 0)
#define X10_REASON_PROFILE        (UINT64_C(1) << 1)
#define X10_REASON_LEDGER         (UINT64_C(1) << 2)
#define X10_REASON_ACTIVE_CALL    (UINT64_C(1) << 3)
#define X10_REASON_RETRY          (UINT64_C(1) << 4)
#define X10_REASON_MONITOR        (UINT64_C(1) << 5)
#define X10_REASON_GENERATION     (UINT64_C(1) << 6)
#define X10_REASON_READ_BUFFER    (UINT64_C(1) << 7)
#define X10_REASON_READ_RECORD    (UINT64_C(1) << 8)
#define X10_REASON_WRITE_BUFFER   (UINT64_C(1) << 9)
#define X10_REASON_WRITE_CALL     (UINT64_C(1) << 10)
#define X10_REASON_HANDSHAKE      (UINT64_C(1) << 11)
#define X10_REASON_CONTROL        (UINT64_C(1) << 12)
#define X10_REASON_TRANSPORT      (UINT64_C(1) << 13)
#define X10_REASON_BOUNDS         (UINT64_C(1) << 14)
#define X10_REASON_KEY_UPDATE     (UINT64_C(1) << 15)

/* Allowlisted lengths/enums/counters only. No secret bytes, addresses or key
 * fingerprints. seq strings are empty when an input/ledger/active-call guard
 * refuses before observing SSL; otherwise sixteen lower-case hex digits + NUL.
 * stale wpend_tot/wpend_ret and nonzero wbuf_offset are observations, not by
 * themselves reasons to reject a completed successful write. */
typedef struct {
    uint32_t schema_version;
    unsigned int allowed;
    uint64_t reasons;
    unsigned int monitor_known;
    /* mutation_serial counts successful KEY INSTALL events only. It is not
     * an all-SSL-state mutation counter or a concurrent-use/change fence. */
    uint64_t read_generation, write_generation, mutation_serial;
    char read_next_sequence[17], write_next_sequence[17];
    size_t packet_length, rbuf_left, rbuf_offset, rbuf_length;
    size_t unread_record_bytes, unread_control_bytes;
    size_t wbuf_left, wbuf_offset, wbuf_length, wnum;
    size_t stale_wpend_tot, stale_wpend_ret;
    unsigned int read_record_slots, write_buffer_slots;
    int rstate, rwstate, flow_state, handshake_state, in_init, in_handshake;
    int enc_read_state, enc_write_state, key_update, alert_dispatch, shutdown;
    unsigned int handshake_fragment_length;
    size_t init_num;
    enum x10_probe_call ledger_last_call, ledger_retry_call;
    enum x10_probe_outcome ledger_last_outcome;
    uint64_t ledger_call_serial;
} X10_PROBE_RESULT;

/* Returns 1 when observation was produced (including a refused safepoint), 0
 * only for NULL output. All fields are initialized. Does not mutate SSL/ledger,
 * read/flush a BIO, perform SSL I/O, print, hash or copy secret material. */
int x10_openssl_probe(const SSL *ssl, const X10_PROBE_LEDGER *ledger,
                      X10_PROBE_RESULT *result);

#endif
