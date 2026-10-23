/* C2a read-only observer. Compile ONLY against the exact patched OpenSSL tree
 * and generated headers identified by openssl-build.mjs. Private layouts are
 * neither an installed-library ABI nor a complete TLS-state inventory.
 * bio_local.h must precede any public BIO header on this pinned revision. */
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif
#include "crypto/bio/bio_local.h"
#include "ssl/ssl_local.h"
#include "openssl-probe.h"
#include <limits.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 0 \
    || OPENSSL_VERSION_PATCH != 13
# error C2a_requires_exact_OpenSSL_3_0_13_headers_and_pinned_source
#endif
#if !defined(OPENSSL_NO_KTLS) || !defined(OPENSSL_NO_ASYNC) \
    || !defined(OPENSSL_NO_ENGINE) || !defined(OPENSSL_NO_COMP)
# error C2a_requires_no_ktls_no_async_no_engine_no_comp_build
#endif

static int x10_call_valid(enum x10_probe_call call)
{
    return call >= X10_CALL_NONE && call <= X10_CALL_CONTROL;
}

static int x10_outcome_valid(enum x10_probe_outcome outcome)
{
    return outcome >= X10_OUTCOME_UNKNOWN && outcome <= X10_OUTCOME_ERROR;
}

static void x10_sequence(char output[17], const unsigned char sequence[8])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < 8; ++i) {
        output[i * 2] = digits[sequence[i] >> 4];
        output[i * 2 + 1] = digits[sequence[i] & 15];
    }
    output[16] = '\0';
}

static int x10_buffer_bounds(const SSL3_BUFFER *buffer)
{
    return buffer->offset <= buffer->len
        && buffer->left <= buffer->len - buffer->offset
        && (buffer->len == 0 || buffer->buf != NULL)
        && buffer->app_buffer == 0;
}

int x10_openssl_probe(const SSL *s, const X10_PROBE_LEDGER *ledger,
                      X10_PROBE_RESULT *out)
{
    const RECORD_LAYER *rl;
    size_t i, reads, writes;

    if (out == NULL)
        return 0;
    memset(out, 0, sizeof(*out));
    out->schema_version = 1;
    if (s == NULL || ledger == NULL) {
        out->reasons = X10_REASON_INPUT;
        return 1;
    }
    if (ledger->schema_version != 1 || ledger->bound_ssl != s
            || ledger->call_serial == 0
            || !x10_call_valid(ledger->active_call)
            || !x10_call_valid(ledger->retry_call)
            || !x10_call_valid(ledger->last_call)
            || !x10_outcome_valid(ledger->last_outcome)) {
        out->reasons |= X10_REASON_LEDGER;
    }
    out->ledger_last_call = x10_call_valid(ledger->last_call)
        ? ledger->last_call : X10_CALL_NONE;
    out->ledger_retry_call = x10_call_valid(ledger->retry_call)
        ? ledger->retry_call : X10_CALL_NONE;
    out->ledger_last_outcome = x10_outcome_valid(ledger->last_outcome)
        ? ledger->last_outcome : X10_OUTCOME_UNKNOWN;
    out->ledger_call_serial = ledger->call_serial;
    if ((out->reasons & X10_REASON_LEDGER) != 0)
        return 1;
    /* Refuse before dereferencing any concurrently mutated SSL internals.
     * This trusts the single-owner fixture ledger; it is not a thread fence. */
    if (ledger->active_call != X10_CALL_NONE) {
        out->reasons |= X10_REASON_ACTIVE_CALL;
        return 1;
    }
    if (ledger->retry_call != X10_CALL_NONE)
        out->reasons |= X10_REASON_RETRY;
    if ((ledger->last_call != X10_CALL_READ
            && ledger->last_call != X10_CALL_WRITE)
            || ledger->last_outcome != X10_OUTCOME_SUCCESS)
        out->reasons |= X10_REASON_LEDGER;

    rl = &s->rlayer;
    if (s->version != TLS1_3_VERSION || s->server != 1
            || s->method == NULL || !SSL_IS_TLS13(s)
            || s->session == NULL || s->session->cipher == NULL
            || s->session->cipher->id != TLS1_3_CK_AES_128_GCM_SHA256
            || s->hit != 0 || s->rlayer.d != NULL
            || s->early_data_state != SSL_EARLY_DATA_NONE
            || s->ext.early_data != SSL_EARLY_DATA_NOT_SENT
            || s->max_early_data != 0 || s->post_handshake_auth != SSL_PHA_NONE
            || s->pha_enabled != 0 || s->renegotiate != 0
            || s->max_pipelines > 1 || rl->read_ahead != 0
            || (s->mode & (SSL_MODE_ENABLE_PARTIAL_WRITE
                           | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                           | SSL_MODE_ASYNC)) != 0
            || (s->options & SSL_OP_ENABLE_KTLS) != 0
            || s->job != NULL || s->asyncrw != 0
            || s->record_padding_cb != NULL || s->block_padding != 0) {
        out->reasons |= X10_REASON_PROFILE;
    }
    /* Exact built-in socket method, one shared direct BIO, no custom methods,
     * chain/filter, callback, buffering BIO or async transport. These field
     * reads and BIO_s_socket's static-method getter perform no BIO I/O. */
    if (s->rbio == NULL || s->rbio != s->wbio || s->bbio != NULL) {
        out->reasons |= X10_REASON_TRANSPORT;
    } else if (s->rbio->method != BIO_s_socket()
            || s->rbio->next_bio != NULL || s->rbio->prev_bio != NULL
            || s->rbio->init != 1 || s->rbio->num < 0
            || s->rbio->callback_ex != NULL
#ifndef OPENSSL_NO_DEPRECATED_3_0
            || s->rbio->callback != NULL
#endif
            ) {
        out->reasons |= X10_REASON_TRANSPORT;
    }

    out->monitor_known = s->x10_probe_known == 3U;
    out->read_generation = s->x10_probe_read_generation;
    out->write_generation = s->x10_probe_write_generation;
    out->mutation_serial = s->x10_probe_mutation_serial;
    if (!out->monitor_known || out->mutation_serial < 2
            || (out->read_generation == 0 && out->write_generation == 0
                && out->mutation_serial != 2))
        out->reasons |= X10_REASON_MONITOR;
    if (out->read_generation != 0 || out->write_generation != 0)
        out->reasons |= X10_REASON_GENERATION;
    x10_sequence(out->read_next_sequence, rl->read_sequence);
    x10_sequence(out->write_next_sequence, rl->write_sequence);

    out->rstate = rl->rstate;
    out->rwstate = s->rwstate;
    out->packet_length = rl->packet_length;
    out->rbuf_left = rl->rbuf.left;
    out->rbuf_offset = rl->rbuf.offset;
    out->rbuf_length = rl->rbuf.len;
    if (!x10_buffer_bounds(&rl->rbuf)
            || rl->packet_length > rl->rbuf.len)
        out->reasons |= X10_REASON_BOUNDS;
    if (rl->rstate != SSL_ST_READ_HEADER
            || rl->packet_length != 0 || rl->rbuf.left != 0)
        out->reasons |= X10_REASON_READ_BUFFER;
    reads = rl->numrpipes;
    writes = rl->numwpipes;
    if (reads > SSL_MAX_PIPELINES || writes > SSL_MAX_PIPELINES) {
        out->reasons |= X10_REASON_BOUNDS;
        reads = writes = 0;
    }
    out->read_record_slots = (unsigned int) reads;
    out->write_buffer_slots = (unsigned int) writes;
    if (reads > 1 || writes > 1)
        out->reasons |= X10_REASON_PROFILE;
    for (i = 0; i < reads; ++i) {
        const SSL3_RECORD *rr = &rl->rrec[i];
        if (rr->read > 1 || rr->off > SSL3_RT_MAX_PLAIN_LENGTH
                || rr->length > SSL3_RT_MAX_PLAIN_LENGTH - rr->off) {
            out->reasons |= X10_REASON_BOUNDS;
            continue;
        }
        /* Unread empty/control records are obligations too. Consumed slots
         * may remain allocated with numrpipes==1 and are not pending. */
        if (!rr->read || rr->length != 0) {
            out->reasons |= X10_REASON_READ_RECORD;
            out->unread_record_bytes += rr->length;
            if (rr->type != SSL3_RT_APPLICATION_DATA)
                out->unread_control_bytes += rr->length;
        }
    }
    for (i = 0; i < writes; ++i) {
        const SSL3_BUFFER *wb = &rl->wbuf[i];
        if (!x10_buffer_bounds(wb))
            out->reasons |= X10_REASON_BOUNDS;
        if (SIZE_MAX - out->wbuf_left < wb->left)
            out->reasons |= X10_REASON_BOUNDS;
        else
            out->wbuf_left += wb->left;
        if (wb->offset > out->wbuf_offset)
            out->wbuf_offset = wb->offset;
        if (wb->len > out->wbuf_length)
            out->wbuf_length = wb->len;
        if (wb->left != 0)
            out->reasons |= X10_REASON_WRITE_BUFFER;
    }
    out->wnum = rl->wnum;
    out->stale_wpend_tot = rl->wpend_tot;
    out->stale_wpend_ret = rl->wpend_ret;
    if (rl->wnum != 0 || s->rwstate != SSL_NOTHING)
        out->reasons |= X10_REASON_WRITE_CALL;

    out->flow_state = s->statem.state;
    out->handshake_state = s->statem.hand_state;
    out->in_init = s->statem.in_init;
    out->in_handshake = s->statem.in_handshake;
    out->enc_read_state = s->statem.enc_read_state;
    out->enc_write_state = s->statem.enc_write_state;
    out->handshake_fragment_length = (unsigned int) rl->handshake_fragment_len;
    out->init_num = s->init_num;
    if (s->statem.state != MSG_FLOW_FINISHED
            || s->statem.hand_state != TLS_ST_OK
            || s->statem.in_init != 0 || s->statem.in_handshake != 0
            || s->statem.cleanuphand != 0
            || s->statem.enc_read_state != ENC_READ_STATE_VALID
            || s->statem.enc_write_state != ENC_WRITE_STATE_VALID
            || s->enc_read_ctx == NULL || s->enc_write_ctx == NULL
            || rl->handshake_fragment_len != 0
            || s->init_num != 0 || s->init_buf != NULL)
        out->reasons |= X10_REASON_HANDSHAKE;
    out->key_update = s->key_update;
    out->alert_dispatch = s->s3.alert_dispatch;
    out->shutdown = s->shutdown;
    if (s->key_update != SSL_KEY_UPDATE_NONE)
        out->reasons |= X10_REASON_KEY_UPDATE;
    if (s->s3.alert_dispatch != 0 || s->shutdown != 0
            || s->quiet_shutdown != 0 || s->num_tickets != 0
            || s->sent_tickets != 0 || s->ext.extra_tickets_expected != 0
            || s->ext.ticket_expected != 0)
        out->reasons |= X10_REASON_CONTROL;
    out->allowed = out->reasons == 0;
    return 1;
}
