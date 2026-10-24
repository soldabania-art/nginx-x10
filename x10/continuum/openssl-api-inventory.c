/* Bounded source-only metadata inventory for the exact patched C2a build.
 * Reviewed pinned getters: ssl/ssl_lib.c, ssl/ssl_sess.c, statem/statem.c.
 * This is not a complete SSL inventory, exporter, importer or API-preserving
 * capsule. In particular, lengths do not preserve Finished verify_data. */
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif
#include "crypto/bio/bio_local.h"
#include "ssl/ssl_local.h"
#include "openssl-api-inventory.h"
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 0 \
    || OPENSSL_VERSION_PATCH != 13
# error API_inventory_requires_exact_OpenSSL_3_0_13_pinned_headers
#endif

int x10_openssl_api_inventory(const SSL *s, const X10_PROBE_LEDGER *ledger,
                              X10_API_INVENTORY *out)
{
    static const unsigned char expected_alpn[] = "continuum-c1";
    X10_PROBE_LEDGER before;
    X10_PROBE_RESULT first, last;
    const unsigned char *selected = NULL;
    const SSL_SESSION *session;
    const X509 *peer;
    const STACK_OF(X509) *peer_chain, *verified_chain;
    unsigned int selected_length = 0;
    unsigned char dummy = 0;
    size_t finished_length, peer_finished_length;
    long verify_result;
    int reused, matches;

    if (out == NULL) return 0;
    memset(out, 0, sizeof(*out));
    out->schema_version = 1;
    if (s == NULL || ledger == NULL) {
        out->reasons = X10_API_REASON_INPUT;
        return 1;
    }
    before = *ledger;
    out->ledger_call_serial = before.call_serial;
    if (!x10_openssl_probe(s, ledger, &first)) {
        out->reasons = X10_API_REASON_PROBE;
        return 1;
    }
    out->probe_reasons = first.reasons;
    if (!first.allowed || first.schema_version != 1 || first.reasons != 0) {
        out->reasons = X10_API_REASON_PROBE;
        return 1;
    }

    /* All getters below are direct field reads on this pinned revision. */
    out->server = SSL_is_server(s);
    out->protocol_version = SSL_version(s);
    out->init_finished = SSL_is_init_finished(s);
    matches = out->server == s->server
        && out->protocol_version == s->version
        && out->init_finished == (!s->statem.in_init
                                  && s->statem.hand_state == TLS_ST_OK);
    if (out->server != 1 || out->protocol_version != TLS1_3_VERSION
        || out->init_finished != 1)
        out->reasons |= X10_API_REASON_PROFILE;

    SSL_get0_alpn_selected(s, &selected, &selected_length);
    matches = matches && selected == s->s3.alpn_selected
        && selected_length == s->s3.alpn_selected_len;
    if (selected_length <= 255) out->alpn_length = selected_length;
    if (selected != NULL && selected_length == sizeof(expected_alpn) - 1
        && s->s3.alpn_selected_len == sizeof(expected_alpn) - 1
        && memcmp(selected, expected_alpn, sizeof(expected_alpn) - 1) == 0)
        out->alpn_matches_profile = 1;
    if (!out->alpn_matches_profile)
        out->reasons |= X10_API_REASON_ALPN;

    /* A non-NULL dummy and count zero query lengths without copying any
     * Finished bytes. The source arrays remain entirely inside the SSL. */
    finished_length = SSL_get_finished(s, &dummy, 0);
    peer_finished_length = SSL_get_peer_finished(s, &dummy, 0);
    if (finished_length <= sizeof(s->s3.tmp.finish_md))
        out->finished_length = finished_length;
    if (peer_finished_length <= sizeof(s->s3.tmp.peer_finish_md))
        out->peer_finished_length = peer_finished_length;
    out->finished_lengths_match_private =
        finished_length == s->s3.tmp.finish_md_len
        && peer_finished_length == s->s3.tmp.peer_finish_md_len;
    if (finished_length != 32 || peer_finished_length != 32
        || !out->finished_lengths_match_private || dummy != 0)
        out->reasons |= X10_API_REASON_FINISHED;

    session = SSL_get_session(s);
    reused = SSL_session_reused(s);
    out->session_present = session != NULL;
    out->session_reused = reused != 0;
    matches = matches && session == s->session && reused == s->hit;
    if (session == NULL || out->session_reused)
        out->reasons |= X10_API_REASON_SESSION;

    out->verify_mode = SSL_get_verify_mode(s);
    verify_result = SSL_get_verify_result(s);
    out->verify_result_ok = verify_result == X509_V_OK;
    peer = SSL_get0_peer_certificate(s);
    peer_chain = SSL_get_peer_cert_chain(s);
    verified_chain = SSL_get0_verified_chain(s);
    out->peer_certificate_present = peer != NULL;
    out->peer_chain_present = peer_chain != NULL;
    out->verified_chain_present = verified_chain != NULL;
    matches = matches && out->verify_mode >= 0
        && (uint32_t) out->verify_mode == s->verify_mode
        && verify_result == s->verify_result
        && peer == (s->session != NULL ? s->session->peer : NULL)
        && peer_chain == (s->session != NULL ? s->session->peer_chain : NULL)
        && verified_chain == s->verified_chain;
    out->server_only_no_client_auth = out->server == 1
        && out->verify_mode == SSL_VERIFY_NONE && out->verify_result_ok
        && !out->peer_certificate_present && !out->peer_chain_present
        && !out->verified_chain_present;
    if (!out->server_only_no_client_auth)
        out->reasons |= X10_API_REASON_AUTH;
    out->getters_match_private = matches != 0;
    if (!matches) out->reasons |= X10_API_REASON_GETTERS;

    /* Zero-initialized unsupported *_preserved flags classify this inventory,
     * not the original SSL's capabilities. Do not exercise those APIs here. */
    if (memcmp(&before, ledger, sizeof(before)) != 0
        || !x10_openssl_probe(s, ledger, &last)
        || memcmp(&first, &last, sizeof(first)) != 0
        || memcmp(&before, ledger, sizeof(before)) != 0)
        out->reasons |= X10_API_REASON_CHANGED;
    out->allowed = out->reasons == 0;
    return 1;
}
