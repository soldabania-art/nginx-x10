#ifndef X10_CONTINUUM_OPENSSL_API_INVENTORY_H
#define X10_CONTINUUM_OPENSSL_API_INVENTORY_H

#include "openssl-probe.h"

#define X10_API_REASON_INPUT       (UINT64_C(1) << 0)
#define X10_API_REASON_PROBE       (UINT64_C(1) << 1)
#define X10_API_REASON_PROFILE     (UINT64_C(1) << 2)
#define X10_API_REASON_ALPN        (UINT64_C(1) << 3)
#define X10_API_REASON_FINISHED    (UINT64_C(1) << 4)
#define X10_API_REASON_AUTH        (UINT64_C(1) << 5)
#define X10_API_REASON_SESSION     (UINT64_C(1) << 6)
#define X10_API_REASON_GETTERS     (UINT64_C(1) << 7)
#define X10_API_REASON_CHANGED     (UINT64_C(1) << 8)

/* Read-only, nonsecret metadata for the exact pinned initial server fixture.
 * Finished fields are lengths only, not values or a preservation proof.
 * No peer certificate with verify_result OK means NO client authentication;
 * it does not establish that the server authenticated its peer.
 * The five *_preserved fields are zero by contract: this inventory does not
 * preserve those APIs. They do not claim the original SSL lacks the APIs. */
typedef struct {
    uint32_t schema_version;
    unsigned int allowed;
    uint64_t reasons, probe_reasons, ledger_call_serial;
    int server, protocol_version, init_finished;
    size_t alpn_length;
    unsigned int alpn_matches_profile;
    size_t finished_length, peer_finished_length;
    unsigned int finished_lengths_match_private;
    int verify_mode;
    unsigned int verify_result_ok;
    unsigned int peer_certificate_present, peer_chain_present;
    unsigned int verified_chain_present, session_present, session_reused;
    unsigned int server_only_no_client_auth, getters_match_private;
    unsigned int exporter_preserved, session_api_preserved;
    unsigned int resumption_preserved, post_handshake_auth_preserved;
    unsigned int future_key_update_preserved;
} X10_API_INVENTORY;

/* Returns 1 for a produced observation, including refusal; 0 only for NULL
 * output. Requires the existing trusted single-owner quiescent probe contract.
 * Calls only reviewed read-only getters and the probe; no SSL/BIO I/O, state
 * mutation, allocations, secret copy/hash/output, session serialization or
 * exporter call. Does not authorize capture, target I/O or source resume. */
int x10_openssl_api_inventory(const SSL *ssl, const X10_PROBE_LEDGER *ledger,
                              X10_API_INVENTORY *result);

#endif
