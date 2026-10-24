/*
 * Isolated C2a read-only probe fixture with actual nonblocking TLS calls.  No state export, keylog, adapter, FD
 * handover or native NGINX integration is implemented here.
 * Public OpenSSL 3.0 API contracts reviewed: SSL_read, SSL_write,
 * SSL_shutdown, SSL_key_update and SSL_CTX_set_alpn_select_cb.
 * https://docs.openssl.org/3.0/man3/SSL_read/
 * https://docs.openssl.org/3.0/man3/SSL_write/
 * https://docs.openssl.org/3.0/man3/SSL_shutdown/
 * https://docs.openssl.org/3.0/man3/SSL_key_update/
 * Exact research pin: 85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c.
 * Its doc/man3/SSL_write.pod requires the same arguments for WANT retries
 * unless moving-write-buffer mode is enabled; contents must still match.
 * ssl/record/rec_layer_s3.c retains pending write progress across that retry.
 * Its doc/man3/SSL_get_error.pod also forbids other I/O-triggering operations
 * after WRITE/WANT_WRITE until the original WRITE is repeated.
 * Its SSL_shutdown.pod distinguishes first-send return 0 from an error;
 * SSL_get_error must not classify that 0. Repeating shutdown may finish it.
 * No SSL_write is permitted after starting shutdown.
 * Its SSL_get_error.pod classifies unexpected EOF as SSL_ERROR_SSL with
 * SSL_R_UNEXPECTED_EOF_WHILE_READING; fatal errors forbid later TLS I/O.
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "openssl-probe.h"

#define MAX_APPLICATION_BYTES 65536U
#define DEADLINE_MS 24000
#define PRESSURE_LIMIT (4U * 1024U * 1024U)
static volatile sig_atomic_t interrupted;
static const unsigned char alpn[] = "continuum-c1";

static void stop_signal(int sig) { (void) sig; interrupted = 1; }

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int ready(int fd, short events, int64_t deadline)
{
    struct pollfd pfd;
    int rc;
    int64_t remaining, now;
    pfd.fd = fd; pfd.events = events; pfd.revents = 0;
    while (!interrupted) {
        now = now_ms();
        if (now < 0 || (remaining = deadline - now) <= 0) return 0;
        rc = poll(&pfd, 1, (int) remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0 || (pfd.revents & (POLLERR | POLLNVAL))) return 0;
        /* Retry SSL on HUP so close_notify is distinguished from raw EOF. */
        return (pfd.revents & (events | POLLHUP)) != 0;
    }
    return 0;
}

static int nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return 0;
    flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static int choose_alpn(SSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int at = 0, length;
    (void) ssl; (void) arg;
    while (at < inlen) {
        length = in[at++];
        if (length == 0 || length > inlen - at) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (length == sizeof(alpn) - 1 && memcmp(in + at, alpn, length) == 0) {
            *out = alpn; *outlen = (unsigned char) length;
            return SSL_TLSEXT_ERR_OK;
        }
        at += length;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int reject_password(char *buffer, int size, int writing, void *argument)
{
    (void) buffer; (void) size; (void) writing; (void) argument;
    return 0; /* Fixture keys must not trigger interactive password prompts. */
}

static int public_version(const char *version)
{
    size_t i, length = strnlen(version, 128);
    if (!length || length == 128) return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char) version[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || strchr(" .+-_()", c))) return 0;
    }
    return 1;
}

/* This typed ledger describes calls actually made by this single-threaded
 * fixture. It is not a lock, proof of ownership or imported state. */
typedef struct {
    SSL *ssl;
    int fd;
    int error;
    int last_result;
    size_t amount;
    X10_PROBE_LEDGER ledger;
} PEER;

static int invoke(PEER *peer, enum x10_probe_call call, void *buffer, size_t size)
{
    int result;
    X10_PROBE_LEDGER *ledger = &peer->ledger;
    if (interrupted || ledger->active_call != X10_CALL_NONE
        || ledger->call_serial == UINT64_MAX) return 0;
    ledger->call_serial++;
    ledger->active_call = call;
    peer->amount = 0;
    ERR_clear_error(); errno = 0;
    switch (call) {
    case X10_CALL_ACCEPT: result = SSL_accept(peer->ssl); break;
    case X10_CALL_READ:
        result = SSL_read_ex(peer->ssl, buffer, size, &peer->amount); break;
    case X10_CALL_WRITE:
        result = SSL_write_ex(peer->ssl, buffer, size, &peer->amount); break;
    case X10_CALL_HANDSHAKE: result = SSL_do_handshake(peer->ssl); break;
    case X10_CALL_SHUTDOWN: result = SSL_shutdown(peer->ssl); break;
    case X10_CALL_CONTROL:
        result = SSL_key_update(peer->ssl, SSL_KEY_UPDATE_NOT_REQUESTED); break;
    default: ledger->active_call = X10_CALL_NONE; return 0;
    }
    peer->last_result = result; /* Allowlisted return observation, not state. */
    /* No intervening OpenSSL call before SSL_get_error classification. */
    if (result > 0) peer->error = SSL_ERROR_NONE;
    else if (call == X10_CALL_SHUTDOWN && result == 0)
        peer->error = SSL_ERROR_WANT_READ; /* incomplete, not SSL_get_error(0) */
    else peer->error = SSL_get_error(peer->ssl, result);
    ledger->active_call = X10_CALL_NONE;
    ledger->last_call = call;
    if (peer->error == SSL_ERROR_NONE) {
        ledger->last_outcome = X10_OUTCOME_SUCCESS;
        if (ledger->retry_call == call) ledger->retry_call = X10_CALL_NONE;
        return 1;
    }
    if (peer->error == SSL_ERROR_WANT_READ
        || peer->error == SSL_ERROR_WANT_WRITE) {
        ledger->last_outcome = peer->error == SSL_ERROR_WANT_READ
            ? X10_OUTCOME_WANT_READ : X10_OUTCOME_WANT_WRITE;
        if (ledger->retry_call == X10_CALL_NONE || ledger->retry_call == call)
            ledger->retry_call = call;
    } else {
        ledger->last_outcome = X10_OUTCOME_ERROR;
        /* A terminal error/close does not turn a prior retry into success. */
    }
    return 0;
}

static int complete(PEER *peer, enum x10_probe_call call, void *buffer,
    size_t size, int64_t deadline)
{
    while (!interrupted && now_ms() < deadline) {
        if (invoke(peer, call, buffer, size)) return 1;
        if (peer->error == SSL_ERROR_WANT_READ) {
            if (!ready(peer->fd, POLLIN, deadline)) return 0;
        } else if (peer->error == SSL_ERROR_WANT_WRITE) {
            if (!ready(peer->fd, POLLOUT, deadline)) return 0;
        } else return 0;
        /* The SAME operation/arguments are retried until it completes. */
    }
    return 0;
}

static int step(int64_t deadline)
{
    char line[5];
    size_t at = 0;
    ssize_t got;
    while (at < sizeof(line)) {
        if (!ready(STDIN_FILENO, POLLIN, deadline)) return 0;
        got = read(STDIN_FILENO, line + at, sizeof(line) - at);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got <= 0) return 0;
        at += (size_t) got;
    }
    return memcmp(line, "STEP\n", sizeof(line)) == 0;
}

static void emit_probe(const char *scenario, unsigned int sample, PEER *peer,
    const X10_PROBE_RESULT *r)
{
    printf("{\"event\":\"probe\",\"scenario\":\"%s\",\"sample\":%u,"
        "\"allowed\":%s,\"reasons\":\"%" PRIu64 "\",\"monitorKnown\":%s,"
        "\"readGeneration\":\"%" PRIu64 "\",\"writeGeneration\":\"%" PRIu64 "\","
        "\"mutationSerial\":\"%" PRIu64 "\",\"readNextSequence\":\"%s\",\"writeNextSequence\":\"%s\","
        "\"sslPending\":%d,\"sslHasPending\":%s,"
        "\"packetLength\":%zu,\"rbufLeft\":%zu,\"rbufOffset\":%zu,\"rbufLength\":%zu,"
        "\"unreadRecordBytes\":%zu,\"unreadControlBytes\":%zu,"
        "\"wbufLeft\":%zu,\"wbufOffset\":%zu,\"wbufLength\":%zu,\"wnum\":%zu,"
        "\"staleWpendTot\":%zu,\"staleWpendRet\":%zu,\"readRecordSlots\":%u,\"writeBufferSlots\":%u,"
        "\"rstate\":%d,\"rwstate\":%d,\"flowState\":%d,\"handshakeState\":%d,"
        "\"inInit\":%d,\"inHandshake\":%d,\"encReadState\":%d,\"encWriteState\":%d,"
        "\"keyUpdate\":%d,\"alertDispatch\":%d,\"shutdown\":%d,"
        "\"handshakeFragmentLength\":%u,\"initNum\":%zu,"
        "\"ledgerLastCall\":%d,\"ledgerRetryCall\":%d,\"ledgerLastOutcome\":%d,"
        "\"ledgerCallSerial\":\"%" PRIu64 "\"}\n",
        scenario, sample, r->allowed ? "true" : "false", r->reasons,
        r->monitor_known ? "true" : "false", r->read_generation,
        r->write_generation, r->mutation_serial, r->read_next_sequence,
        r->write_next_sequence, SSL_pending(peer->ssl),
        SSL_has_pending(peer->ssl) ? "true" : "false", r->packet_length,
        r->rbuf_left, r->rbuf_offset, r->rbuf_length, r->unread_record_bytes,
        r->unread_control_bytes, r->wbuf_left, r->wbuf_offset, r->wbuf_length,
        r->wnum, r->stale_wpend_tot, r->stale_wpend_ret, r->read_record_slots,
        r->write_buffer_slots, r->rstate, r->rwstate, r->flow_state,
        r->handshake_state, r->in_init, r->in_handshake, r->enc_read_state,
        r->enc_write_state, r->key_update, r->alert_dispatch, r->shutdown,
        r->handshake_fragment_length, r->init_num, (int) r->ledger_last_call,
        (int) r->ledger_retry_call, (int) r->ledger_last_outcome,
        r->ledger_call_serial);
}

static int observe(PEER *peer, X10_PROBE_RESULT *result)
{
    X10_PROBE_LEDGER before = peer->ledger;
    if (peer->ledger.active_call != X10_CALL_NONE
        || !x10_openssl_probe(peer->ssl, &peer->ledger, result)) return 0;
    return memcmp(&before, &peer->ledger, sizeof(before)) == 0;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *count = NULL, *nonce = NULL;
    const char *scenario = NULL, *failure = "arguments";
    const char *runtime_version = OpenSSL_version(OPENSSL_VERSION);
    const char *scenarios[] = {"quiescent", "partial-header", "partial-body",
        "unread-plaintext", "empty-read-retry", "write-backpressure", "queued-key-update",
        "completed-key-update", "completed-read-retry", "unrelated-write-read-retry",
        "peer-key-update-pending", "peer-key-update-completed", "completed-write-retry",
        "overlapping-read-write-retry", "server-shutdown-lifecycle",
        "unexpected-transport-eof", "peer-first-shutdown-lifecycle"};
    SSL_CTX *ctx = NULL;
    PEER peer;
    X10_PROBE_RESULT first, second;
    struct sockaddr_in address;
    struct sigaction action;
    socklen_t address_len = sizeof(address);
    unsigned char challenge[16] = {0}, *payload = NULL, *outbound = NULL, trailer = 0;
    void *retry_buffer = NULL;
    unsigned char pressure[16384];
    const unsigned char *selected = NULL;
    unsigned int selected_len = 0;
    unsigned long parsed = 0;
    size_t i, wanted = 0, total = 0, pressure_total = 0, retry_size = 0;
    int listener = -1, status = 1, known = 0, size = 4096;
    int quiescent, unread, partial, pressure_case, ku, empty, completed_ku, exchange;
    int completed_read, unrelated_write, completed_write, overlap, allowed_case;
    int peer_ku, peer_ku_pending, peer_ku_completed, shutdown_lifecycle, unexpected_eof;
    int peer_shutdown;
    unsigned long eof_error = 0;
    int64_t deadline;

    memset(&peer, 0, sizeof(peer)); peer.fd = -1;
    memset(pressure, 0, sizeof(pressure));
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&action, 0, sizeof(action)); action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)
        || sigaction(SIGALRM, &action, NULL)) goto done;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL)) goto done;
    alarm(25);
    for (i = 1; i < (size_t) argc; i++) {
        const char **destination = NULL;
        if (!strcmp(argv[i], "--cert")) destination = &cert;
        else if (!strcmp(argv[i], "--key")) destination = &key;
        else if (!strcmp(argv[i], "--bytes")) destination = &count;
        else if (!strcmp(argv[i], "--challenge")) destination = &nonce;
        else if (!strcmp(argv[i], "--scenario")) destination = &scenario;
        if (!destination || *destination || ++i >= (size_t) argc
            || !argv[i][0] || strlen(argv[i]) > 4096) goto done;
        *destination = argv[i];
    }
    if (!cert || !key || !count || !nonce || !scenario || strlen(nonce) != 32)
        goto done;
    for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++)
        if (!strcmp(scenario, scenarios[i])) known = 1;
    if (!known) goto done;
    for (i = 0; count[i]; i++) {
        if (count[i] < '0' || count[i] > '9' || i > 5) goto done;
        parsed = parsed * 10 + (unsigned long) (count[i] - '0');
        if (parsed > MAX_APPLICATION_BYTES) goto done;
    }
    if (!parsed || (count[0] == '0' && count[1])) goto done;
    wanted = (size_t) parsed;
    for (i = 0; i < sizeof(challenge); i++) {
        int a = hex_nibble(nonce[i * 2]), b = hex_nibble(nonce[i * 2 + 1]);
        if (a < 0 || b < 0) goto done;
        challenge[i] = (unsigned char) (a * 16 + b);
    }
    quiescent = !strcmp(scenario, "quiescent");
    unread = !strcmp(scenario, "unread-plaintext");
    partial = !strcmp(scenario, "partial-header") || !strcmp(scenario, "partial-body");
    pressure_case = !strcmp(scenario, "write-backpressure");
    ku = !strcmp(scenario, "queued-key-update");
    empty = !strcmp(scenario, "empty-read-retry");
    completed_ku = !strcmp(scenario, "completed-key-update");
    completed_read = !strcmp(scenario, "completed-read-retry");
    unrelated_write = !strcmp(scenario, "unrelated-write-read-retry");
    completed_write = !strcmp(scenario, "completed-write-retry");
    overlap = !strcmp(scenario, "overlapping-read-write-retry");
    peer_ku_pending = !strcmp(scenario, "peer-key-update-pending");
    peer_ku_completed = !strcmp(scenario, "peer-key-update-completed");
    peer_ku = peer_ku_pending || peer_ku_completed;
    shutdown_lifecycle = !strcmp(scenario, "server-shutdown-lifecycle");
    unexpected_eof = !strcmp(scenario, "unexpected-transport-eof");
    peer_shutdown = !strcmp(scenario, "peer-first-shutdown-lifecycle");
    allowed_case = quiescent || completed_read || completed_write;
    exchange = allowed_case || completed_ku || peer_ku_completed
        || shutdown_lifecycle || unexpected_eof || peer_shutdown;
    if (unread && wanted < 2) goto done;
    if ((completed_write || overlap) && wanted != MAX_APPLICATION_BYTES) goto done;

    failure = "configuration";
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1
        || SSL_CTX_set_num_tickets(ctx, 0) != 1
        || SSL_CTX_set_max_early_data(ctx, 0) != 1) goto done;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_KTLS | SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_post_handshake_auth(ctx, 0);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_quiet_shutdown(ctx, 0); SSL_CTX_set_read_ahead(ctx, 0);
    SSL_CTX_set_max_pipelines(ctx, 1);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_clear_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        | SSL_MODE_ASYNC | SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_alpn_select_cb(ctx, choose_alpn, NULL);
    SSL_CTX_set_default_passwd_cb(ctx, reject_password);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) goto done;
    deadline = now_ms(); if (deadline < 0) goto done; deadline += DEADLINE_MS;
    failure = "listen";
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || !nonblocking(listener)) goto done;
    memset(&address, 0, sizeof(address)); address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address))
        || listen(listener, 1)
        || getsockname(listener, (struct sockaddr *) &address, &address_len)) goto done;
    printf("{\"event\":\"listening\",\"port\":%u}\n", (unsigned int) ntohs(address.sin_port));
    failure = "accept";
    while (!interrupted) {
        if (!ready(listener, POLLIN, deadline)) goto done;
        peer.fd = accept(listener, NULL, NULL);
        if (peer.fd >= 0) break;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) goto done;
    }
    if (peer.fd < 0 || !nonblocking(peer.fd)) goto done;
    close(listener); listener = -1;
    if ((pressure_case || completed_write || overlap)
        && setsockopt(peer.fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) goto done;
    peer.ssl = SSL_new(ctx);
    if (!peer.ssl || SSL_set_fd(peer.ssl, peer.fd) != 1) goto done;
    peer.ledger.schema_version = 1; peer.ledger.bound_ssl = peer.ssl;
    failure = "handshake";
    if (!complete(&peer, X10_CALL_ACCEPT, NULL, 0, deadline)) goto done;
    SSL_get0_alpn_selected(peer.ssl, &selected, &selected_len);
    if (SSL_version(peer.ssl) != TLS1_3_VERSION || SSL_session_reused(peer.ssl)
        || strcmp(SSL_get_cipher_name(peer.ssl), "TLS_AES_128_GCM_SHA256")
        || selected_len != sizeof(alpn) - 1 || memcmp(selected, alpn, sizeof(alpn) - 1)
        || SSL_get_early_data_status(peer.ssl) != SSL_EARLY_DATA_NOT_SENT
        || !public_version(runtime_version) || !public_version(OPENSSL_VERSION_TEXT)) goto done;
    printf("{\"event\":\"handshake\",\"version\":\"TLSv1.3\",\"cipher\":\"TLS_AES_128_GCM_SHA256\","
        "\"alpn\":\"continuum-c1\",\"resumed\":false,\"opensslVersion\":\"%s\","
        "\"opensslHeadersVersion\":\"%s\"}\n", runtime_version, OPENSSL_VERSION_TEXT);
    printf("{\"event\":\"ready\",\"scenario\":\"%s\"}\n", scenario);
    failure = "step";
    if (!step(deadline)) goto done;
    payload = OPENSSL_malloc(wanted);
    if (!payload) goto done;

    failure = "scenario_unreached";
    if (completed_read || unrelated_write || overlap) {
        /* The orchestrator withholds all application bytes until this real
         * empty read reports WANT_READ. Keep the original read arguments;
         * enum equality in the fixture ledger is not an argument fence. */
        retry_buffer = payload; retry_size = wanted;
        if (overlap) memset(payload, 0xa5, wanted);
        if (invoke(&peer, X10_CALL_READ, retry_buffer, retry_size)
            || peer.error != SSL_ERROR_WANT_READ || peer.amount != 0
            || peer.ledger.last_call != X10_CALL_READ
            || peer.ledger.last_outcome != X10_OUTCOME_WANT_READ
            || peer.ledger.retry_call != X10_CALL_READ
            || SSL_pending(peer.ssl) != 0) goto done;
        printf("{\"event\":\"retry-ready\",\"scenario\":\"%s\",\"call\":%d,"
            "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":%zu,"
            "\"sslPending\":%d}\n", scenario, (int) peer.ledger.last_call,
            (int) peer.ledger.last_outcome, (int) peer.ledger.retry_call,
            peer.amount, SSL_pending(peer.ssl));
        if (completed_read) {
            if (retry_buffer != payload || retry_size != wanted
                || !complete(&peer, X10_CALL_READ, payload, wanted, deadline)
                || !peer.amount || peer.amount > wanted
                || peer.ledger.last_call != X10_CALL_READ
                || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
                || peer.ledger.retry_call != X10_CALL_NONE) goto done;
            total = peer.amount;
            /* Record this immediately: an echo write cannot be mistaken for
             * the successful operation that cleared the original read retry. */
            printf("{\"event\":\"retry-completed\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":%zu,"
                "\"sslPending\":%d,\"sameReadArguments\":%s}\n", scenario,
                (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
                (int) peer.ledger.retry_call, peer.amount, SSL_pending(peer.ssl),
                retry_buffer == payload && retry_size == wanted ? "true" : "false");
            /* A separate bounded control ACK prevents stdout/TCP delivery
             * ordering from weakening the before-echo observation. */
            failure = "retry_completion_step";
            if (!step(deadline)) goto done;
            failure = "scenario_unreached";
        } else if (unrelated_write) {
            /* Keep the pending read buffer separate and untouched. Successful
             * unrelated output must leave the original READ retry outstanding. */
            outbound = OPENSSL_malloc(wanted);
            if (!outbound) goto done;
            for (i = 0; i < wanted; i++)
                outbound[i] = (unsigned char) (((i * 29 + 7) & 255) ^ challenge[i % 16]);
            if (!complete(&peer, X10_CALL_WRITE, outbound, wanted, deadline)
                || peer.amount != wanted || peer.ledger.last_call != X10_CALL_WRITE
                || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
                || peer.ledger.retry_call != X10_CALL_READ) goto done;
        } else {
            void *write_buffer;
            size_t write_size;

            /* The first-obligation ledger cannot represent both retries.
             * This scoped overlap is unsupported: every snapshot must refuse,
             * including after WRITE completion. Never retry the original READ
             * or claim that its obligation or this history has been cleared. */
            if (retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != 0xa5) goto done;
            outbound = OPENSSL_malloc(wanted);
            if (!outbound || outbound == payload) goto done;
            for (i = 0; i < wanted; i++)
                outbound[i] = (unsigned char) (((i * 29 + 7) & 255) ^ challenge[i % 16]);
            write_buffer = outbound; write_size = wanted;
            /* Client and relay readers are paused. No larger fallback payload
             * or synthetic retry substitutes for actual bounded WANT_WRITE. */
            failure = "state_not_reached";
            if (invoke(&peer, X10_CALL_WRITE, write_buffer, write_size)
                || peer.error != SSL_ERROR_WANT_WRITE
                || peer.ledger.last_call != X10_CALL_WRITE
                || peer.ledger.last_outcome != X10_OUTCOME_WANT_WRITE
                || peer.ledger.retry_call != X10_CALL_READ
                || !observe(&peer, &first) || first.allowed
                || !(first.reasons & X10_REASON_RETRY)
                || !(first.reasons & X10_REASON_LEDGER)
                || !(first.reasons & (X10_REASON_WRITE_BUFFER | X10_REASON_WRITE_CALL))
                || !(first.wbuf_left || first.wnum)) goto done;
            if (retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != 0xa5) goto done;
            printf("{\"event\":\"overlap-retry-ready\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":0,"
                "\"writeLength\":%zu,\"sameWriteArguments\":true,\"originalReadUnchanged\":true}\n",
                scenario, (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
                (int) peer.ledger.retry_call, write_size);
            emit_probe(scenario, 1, &peer, &first);
            failure = "overlap_retry_probe";
            if (!observe(&peer, &second)) goto done;
            emit_probe(scenario, 2, &peer, &second);
            if (memcmp(&first, &second, sizeof(first))) goto done;
            failure = "overlap_retry_resume_step";
            if (!step(deadline)) goto done;
            failure = "overlap_write_completion";
            /* The pinned SSL_get_error contract permits only this original
             * WRITE until completion. Polls, probes and getters do no TLS I/O.
             * Do not advance by a failed call's reported written count. */
            if (write_buffer != outbound || write_size != wanted
                || retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != 0xa5
                    || outbound[i] != (unsigned char) (((i * 29 + 7) & 255)
                        ^ challenge[i % 16])) goto done;
            if (!complete(&peer, X10_CALL_WRITE, write_buffer, write_size, deadline)
                || peer.amount != wanted || peer.ledger.last_call != X10_CALL_WRITE
                || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
                || peer.ledger.retry_call != X10_CALL_READ) goto done;
            if (write_buffer != outbound || write_size != wanted
                || retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != 0xa5
                    || outbound[i] != (unsigned char) (((i * 29 + 7) & 255)
                        ^ challenge[i % 16])) goto done;
            /* Immediately record WRITE completion with the READ still owed. */
            printf("{\"event\":\"overlap-write-completed\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":0,"
                "\"writeLength\":%zu,\"sameWriteArguments\":true,\"originalReadUnchanged\":true,"
                "\"applicationBytesWritten\":%zu}\n", scenario,
                (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
                (int) peer.ledger.retry_call, write_size, peer.amount);
        }
    }
    if (exchange || peer_ku) {
        while (total < wanted) {
            if (!complete(&peer, X10_CALL_READ, payload + total, wanted - total, deadline)
                || !peer.amount || peer.amount > wanted - total) goto done;
            total += peer.amount;
        }
        for (i = 0; i < wanted; i++)
            if (payload[i] != (unsigned char) (((i * 29 + 7) & 255) ^ challenge[i % 16])) goto done;
        if (peer_ku) {
            /* The peer requested this update on the wire. No server control,
             * handshake or write call precedes this successful READ snapshot.
             * The pinned tls_process_key_update installs read keys and queues
             * a NOT_REQUESTED response; it does not send that response here. */
            if (!observe(&peer, &first) || first.allowed
                || first.reasons != (X10_REASON_GENERATION | X10_REASON_KEY_UPDATE)
                || !first.monitor_known || first.read_generation != 1
                || first.write_generation != 0 || first.mutation_serial != 3
                || first.key_update != SSL_KEY_UPDATE_NOT_REQUESTED
                || first.ledger_last_call != X10_CALL_READ
                || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
                || first.ledger_retry_call != X10_CALL_NONE
                || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)) goto done;
            printf("{\"event\":\"peer-update-received\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":%zu,"
                "\"sslPending\":%d,\"keyUpdate\":%d,\"readGeneration\":\"%" PRIu64 "\","
                "\"writeGeneration\":\"%" PRIu64 "\",\"mutationSerial\":\"%" PRIu64 "\"}\n",
                scenario, (int) first.ledger_last_call,
                (int) first.ledger_last_outcome, (int) first.ledger_retry_call,
                total, SSL_pending(peer.ssl), first.key_update,
                first.read_generation, first.write_generation, first.mutation_serial);
            /* In this pin SSL_do_handshake alone does not re-enter init for
             * an automatically queued peer response. The actual echo WRITE
             * below takes ssl3_write_bytes' queued-control path, flushes the
             * response, installs write keys, then sends application data. */
        }
        if (completed_ku && (!invoke(&peer, X10_CALL_CONTROL, NULL, 0)
            || !complete(&peer, X10_CALL_HANDSHAKE, NULL, 0, deadline)
            || SSL_get_key_update_type(peer.ssl) != SSL_KEY_UPDATE_NONE)) goto done;
        if (completed_write) {
            /* The full authenticated request is the original echo buffer.
             * Both downstream readers are paused before the initial STEP.
             * One bounded 65536-byte call must create actual backpressure;
             * a kernel that absorbs it has not reached this test state. */
            retry_buffer = payload; retry_size = wanted;
            failure = "state_not_reached";
            if (invoke(&peer, X10_CALL_WRITE, retry_buffer, retry_size)
                || peer.error != SSL_ERROR_WANT_WRITE
                || peer.ledger.last_call != X10_CALL_WRITE
                || peer.ledger.last_outcome != X10_OUTCOME_WANT_WRITE
                || peer.ledger.retry_call != X10_CALL_WRITE
                || !observe(&peer, &first) || first.allowed
                || !(first.reasons & X10_REASON_RETRY)
                || !(first.reasons & (X10_REASON_WRITE_BUFFER | X10_REASON_WRITE_CALL))
                || !(first.wbuf_left || first.wnum)) goto done;
            printf("{\"event\":\"write-retry-ready\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":%zu,"
                "\"writeLength\":%zu,\"sameWriteArguments\":%s}\n",
                scenario, (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
                (int) peer.ledger.retry_call, total, retry_size,
                retry_buffer == payload && retry_size == wanted ? "true" : "false");
            emit_probe(scenario, 1, &peer, &first);
            failure = "write_retry_probe";
            if (!observe(&peer, &second)) goto done;
            emit_probe(scenario, 2, &peer, &second);
            if (memcmp(&first, &second, sizeof(first))) goto done;
            failure = "write_retry_resume_step";
            if (!step(deadline)) goto done;
            failure = "write_retry_completion";
            /* No intervening SSL operation and no buffer mutation: retry the
             * SAME pointer, contents and FULL original length, never a tail.
             * complete() repeats exactly these arguments on further WANTs. */
            if (retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != (unsigned char) (((i * 29 + 7) & 255)
                    ^ challenge[i % 16])) goto done;
            if (!complete(&peer, X10_CALL_WRITE, retry_buffer, retry_size, deadline)
                || peer.amount != wanted || peer.ledger.last_call != X10_CALL_WRITE
                || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
                || peer.ledger.retry_call != X10_CALL_NONE) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != (unsigned char) (((i * 29 + 7) & 255)
                    ^ challenge[i % 16])) goto done;
            /* Capture completion before any subsequent SSL call or shutdown. */
            printf("{\"event\":\"write-retry-completed\",\"scenario\":\"%s\",\"call\":%d,"
                "\"outcome\":%d,\"retryCall\":%d,\"applicationBytesRead\":%zu,"
                "\"applicationBytesWritten\":%zu,\"writeLength\":%zu,\"sameWriteArguments\":%s}\n",
                scenario, (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
                (int) peer.ledger.retry_call, total, peer.amount, retry_size,
                retry_buffer == payload && retry_size == wanted ? "true" : "false");
        }
        if (exchange && !completed_write
            && (!complete(&peer, X10_CALL_WRITE, payload, wanted, deadline)
            || peer.amount != wanted)) goto done;
        if (peer_ku_completed
            && SSL_get_key_update_type(peer.ssl) != SSL_KEY_UPDATE_NONE) goto done;
    } else if (unread) {
        if (!ready(peer.fd, POLLIN, deadline)
            || !complete(&peer, X10_CALL_READ, payload, 1, deadline)
            || peer.amount != 1 || SSL_pending(peer.ssl) <= 0) goto done;
    } else if (partial || empty) {
        if (partial && !ready(peer.fd, POLLIN, deadline)) goto done;
        if (invoke(&peer, X10_CALL_READ, payload, wanted)
            || peer.error != SSL_ERROR_WANT_READ || SSL_pending(peer.ssl) != 0) goto done;
    } else if (ku) {
        if (!invoke(&peer, X10_CALL_CONTROL, NULL, 0)
            || SSL_get_key_update_type(peer.ssl) != SSL_KEY_UPDATE_NOT_REQUESTED) goto done;
    } else if (pressure_case) {
        for (i = 0; i < sizeof(pressure); i++)
            pressure[i] = (unsigned char) (((i * 29 + 7) & 255) ^ challenge[i % 16]);
        while (pressure_total < PRESSURE_LIMIT && !interrupted && now_ms() < deadline) {
            if (invoke(&peer, X10_CALL_WRITE, pressure, sizeof(pressure))) {
                if (peer.amount != sizeof(pressure)) goto done;
                pressure_total += peer.amount;
            } else break;
        }
        if (peer.error != SSL_ERROR_WANT_WRITE || peer.ledger.retry_call != X10_CALL_WRITE) goto done;
    }

    if (unexpected_eof) {
        /* The client acknowledges the exact echoed payload, then closes the
         * transport without TLS close_notify. A real FIN must cause the pin's
         * fatal EOF classification; a retry/RST/clean close is not a PASS. */
        failure = "eof_ready";
        if (!observe(&peer, &first) || !first.allowed
            || peer.ledger.retry_call != X10_CALL_NONE
            || (SSL_get_options(peer.ssl) & SSL_OP_IGNORE_UNEXPECTED_EOF)
            || SSL_get_quiet_shutdown(peer.ssl)
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)) goto done;
        printf("{\"event\":\"eof-ready\",\"scenario\":\"%s\","
            "\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu}\n",
            scenario, total, wanted);
        if (!step(deadline) || !ready(peer.fd, POLLIN, deadline)) goto done;
        failure = "unexpected_eof_state_not_reached";
        if (invoke(&peer, X10_CALL_READ, &trailer, 1)) goto done;
        /* invoke classified the actual raw return with SSL_get_error first.
         * Match SSL_get_error's first queue entry: fatal alert dispatch may
         * append a secondary BIO error. Never print or drain the error queue. */
        eof_error = ERR_peek_error();
        if (peer.last_result != 0 || peer.error != SSL_ERROR_SSL
            || ERR_GET_LIB(eof_error) != ERR_LIB_SSL
            || ERR_GET_REASON(eof_error) != SSL_R_UNEXPECTED_EOF_WHILE_READING
            || peer.amount != 0 || peer.ledger.last_call != X10_CALL_READ
            || peer.ledger.last_outcome != X10_OUTCOME_ERROR
            || peer.ledger.retry_call != X10_CALL_NONE) goto done;
        printf("{\"event\":\"eof-observed\",\"scenario\":\"%s\","
            "\"call\":%d,\"outcome\":%d,\"retryCall\":%d,\"rawResult\":%d,"
            "\"sslError\":%d,\"errorReason\":%d,\"applicationBytesRead\":%zu}\n",
            scenario, (int) peer.ledger.last_call,
            (int) peer.ledger.last_outcome, (int) peer.ledger.retry_call,
            peer.last_result, peer.error, ERR_GET_REASON(eof_error), peer.amount);
        /* After SSL_ERROR_SSL, only metadata probes and resource cleanup may
         * follow. No read/write/control/handshake/shutdown operation is legal. */
    }

    if (peer_shutdown) {
        /* An exact echo receipt precedes the peer's explicit TLS end. The
         * orchestrator waits for forwarded close bytes before STEP. Only a
         * real ZERO_RETURN, not a retry/fatal EOF, reaches these snapshots. */
        failure = "peer_shutdown_ready";
        if (!observe(&peer, &first) || !first.allowed
            || peer.ledger.retry_call != X10_CALL_NONE
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)
            || SSL_get_shutdown(peer.ssl) != 0
            || (SSL_get_options(peer.ssl) & SSL_OP_IGNORE_UNEXPECTED_EOF)
            || SSL_get_quiet_shutdown(peer.ssl)) goto done;
        printf("{\"event\":\"peer-shutdown-ready\",\"scenario\":\"%s\","
            "\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu}\n",
            scenario, total, wanted);
        if (!step(deadline) || !ready(peer.fd, POLLIN, deadline)) goto done;
        failure = "peer_shutdown_received_state_not_reached";
        if (invoke(&peer, X10_CALL_READ, &trailer, 1)
            || peer.last_result != 0 || peer.error != SSL_ERROR_ZERO_RETURN
            || peer.amount != 0 || SSL_get_shutdown(peer.ssl) != SSL_RECEIVED_SHUTDOWN
            || peer.ledger.last_call != X10_CALL_READ
            || peer.ledger.last_outcome != X10_OUTCOME_ERROR
            || peer.ledger.retry_call != X10_CALL_NONE
            || !observe(&peer, &first) || first.allowed
            || !(first.reasons & X10_REASON_CONTROL)
            || !(first.reasons & X10_REASON_LEDGER)
            || (first.reasons & X10_REASON_RETRY)
            || first.shutdown != SSL_RECEIVED_SHUTDOWN
            || first.alert_dispatch != 0 || first.wbuf_left || first.wnum
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)) goto done;
        /* ZERO_RETURN is a clean received close, not fatal SSL_ERROR_SSL.
         * The existing ledger records both as ERROR; no new CLOSED enum or
         * artificial retry completion is introduced by this fixture case. */
        printf("{\"event\":\"peer-shutdown-received\",\"scenario\":\"%s\","
            "\"call\":%d,\"outcome\":%d,\"retryCall\":%d,"
            "\"shutdownBits\":%d,\"rawResult\":%d,\"sslError\":%d,"
            "\"applicationBytesRead\":%zu}\n", scenario,
            (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
            (int) peer.ledger.retry_call, first.shutdown, peer.last_result,
            peer.error, peer.amount);
        emit_probe(scenario, 1, &peer, &first);
        failure = "peer_shutdown_received_probe";
        if (!observe(&peer, &second)) goto done;
        emit_probe(scenario, 2, &peer, &second);
        if (memcmp(&first, &second, sizeof(first))) goto done;
        failure = "peer_shutdown_response_step";
        if (!step(deadline)) goto done;
        failure = "peer_shutdown_completion";
        /* Respond only after the received-only observations. No application
         * read/write/control call follows the peer close_notify. */
        if (!complete(&peer, X10_CALL_SHUTDOWN, NULL, 0, deadline)
            || peer.last_result != 1 || peer.error != SSL_ERROR_NONE
            || SSL_get_shutdown(peer.ssl) != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)
            || peer.ledger.last_call != X10_CALL_SHUTDOWN
            || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
            || peer.ledger.retry_call != X10_CALL_NONE) goto done;
        printf("{\"event\":\"peer-shutdown-completed\",\"scenario\":\"%s\","
            "\"call\":%d,\"outcome\":%d,\"retryCall\":%d,"
            "\"shutdownBits\":%d,\"rawResult\":%d,\"sslError\":%d}\n", scenario,
            (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
            (int) peer.ledger.retry_call, SSL_get_shutdown(peer.ssl),
            peer.last_result, peer.error);
    }

    if (shutdown_lifecycle) {
        /* The client withholds close_notify until both sent-only snapshots.
         * This exact-echo ACK excludes unread application data for this narrow
         * profile; it is not a general truncation or concurrent-writer fence. */
        failure = "shutdown_ready";
        if (!observe(&peer, &first) || !first.allowed
            || peer.ledger.retry_call != X10_CALL_NONE
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)) goto done;
        printf("{\"event\":\"shutdown-ready\",\"scenario\":\"%s\","
            "\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu}\n",
            scenario, total, wanted);
        if (!step(deadline)) goto done;
        failure = "shutdown_sent_state_not_reached";
        /* Return 0 is successful one-way shutdown, not SSL_ERROR_WANT_READ.
         * invoke's existing ledger convention records it as incomplete; it
         * deliberately does not call SSL_get_error for this special return. */
        if (invoke(&peer, X10_CALL_SHUTDOWN, NULL, 0)
            || peer.last_result != 0 || peer.error != SSL_ERROR_WANT_READ
            || SSL_get_shutdown(peer.ssl) != SSL_SENT_SHUTDOWN
            || peer.ledger.last_call != X10_CALL_SHUTDOWN
            || peer.ledger.last_outcome != X10_OUTCOME_WANT_READ
            || peer.ledger.retry_call != X10_CALL_SHUTDOWN
            || !observe(&peer, &first) || first.allowed
            || !(first.reasons & X10_REASON_CONTROL)
            || !(first.reasons & X10_REASON_RETRY)
            || first.shutdown != SSL_SENT_SHUTDOWN || first.alert_dispatch != 0
            || first.wbuf_left || first.wnum) goto done;
        printf("{\"event\":\"shutdown-started\",\"scenario\":\"%s\","
            "\"call\":%d,\"outcome\":%d,\"retryCall\":%d,"
            "\"shutdownBits\":%d,\"rawResult\":%d}\n", scenario,
            (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
            (int) peer.ledger.retry_call, first.shutdown, peer.last_result);
        emit_probe(scenario, 1, &peer, &first);
        failure = "shutdown_sent_probe";
        if (!observe(&peer, &second)) goto done;
        emit_probe(scenario, 2, &peer, &second);
        if (memcmp(&first, &second, sizeof(first))) goto done;
        failure = "shutdown_peer_close_step";
        if (!step(deadline)) goto done;
        failure = "shutdown_completion";
        /* The pin permits repeated SSL_shutdown after return 0. Only that
         * operation follows; no application read/write or control I/O occurs. */
        if (!complete(&peer, X10_CALL_SHUTDOWN, NULL, 0, deadline)
            || peer.last_result != 1
            || SSL_get_shutdown(peer.ssl) != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)
            || peer.ledger.last_call != X10_CALL_SHUTDOWN
            || peer.ledger.last_outcome != X10_OUTCOME_SUCCESS
            || peer.ledger.retry_call != X10_CALL_NONE) goto done;
        printf("{\"event\":\"shutdown-completed\",\"scenario\":\"%s\","
            "\"call\":%d,\"outcome\":%d,\"retryCall\":%d,"
            "\"shutdownBits\":%d,\"rawResult\":%d}\n", scenario,
            (int) peer.ledger.last_call, (int) peer.ledger.last_outcome,
            (int) peer.ledger.retry_call, SSL_get_shutdown(peer.ssl), peer.last_result);
    }

    failure = "probe";
    if (interrupted || now_ms() >= deadline) goto done;
    if (!observe(&peer, &first)) goto done;
    emit_probe(scenario, completed_write || overlap || shutdown_lifecycle || peer_shutdown ? 3 : 1, &peer, &first);
    if (unexpected_eof) {
        if (first.allowed || !(first.reasons & X10_REASON_LEDGER)
            || first.ledger_last_call != X10_CALL_READ
            || first.ledger_last_outcome != X10_OUTCOME_ERROR
            || first.ledger_retry_call != X10_CALL_NONE) goto done;
        if (!observe(&peer, &second)) goto done;
        emit_probe(scenario, 2, &peer, &second);
        if (memcmp(&first, &second, sizeof(first))) goto done;
    } else if (shutdown_lifecycle || peer_shutdown) {
        /* A fully closed session remains outside the live continuation
         * safepoint, even after its shutdown retry is actually complete. */
        if (first.allowed || !(first.reasons & X10_REASON_CONTROL)
            || (first.reasons & X10_REASON_RETRY)
            || first.shutdown != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)
            || first.ledger_last_call != X10_CALL_SHUTDOWN
            || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
            || first.ledger_retry_call != X10_CALL_NONE
            || first.alert_dispatch != 0 || first.wbuf_left || first.wnum
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)) goto done;
        if (!observe(&peer, &second)) goto done;
        emit_probe(scenario, 4, &peer, &second);
        if (memcmp(&first, &second, sizeof(first))) goto done;
        printf("{\"event\":\"shutdown\",\"clean\":true,\"shutdownBits\":%d}\n", SSL_get_shutdown(peer.ssl));
    } else if (exchange) {
        if (allowed_case && (!first.allowed || first.reasons != 0)) goto done;
        if (completed_ku && (first.allowed || !(first.reasons & X10_REASON_GENERATION)
            || first.read_generation != 0 || first.write_generation != 1
            || first.mutation_serial != 3 || first.key_update != SSL_KEY_UPDATE_NONE
            || first.ledger_last_call != X10_CALL_WRITE
            || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
            || first.ledger_retry_call != X10_CALL_NONE)) goto done;
        if (peer_ku_completed && (first.allowed || first.reasons != X10_REASON_GENERATION
            || !first.monitor_known || first.read_generation != 1
            || first.write_generation != 1 || first.mutation_serial != 4
            || first.key_update != SSL_KEY_UPDATE_NONE
            || first.ledger_last_call != X10_CALL_WRITE
            || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
            || first.ledger_retry_call != X10_CALL_NONE)) goto done;
        if (!observe(&peer, &second)) goto done;
        emit_probe(scenario, completed_write ? 4 : 2, &peer, &second);
        if (memcmp(&first, &second, sizeof(first))) goto done;
        failure = "peer_close_notify";
        while (1) {
            if (complete(&peer, X10_CALL_READ, &trailer, 1, deadline)) {
                failure = "application_trailer"; goto done;
            }
            if (peer.error != SSL_ERROR_ZERO_RETURN) goto done;
            break;
        }
        failure = "shutdown";
        if (!complete(&peer, X10_CALL_SHUTDOWN, NULL, 0, deadline)
            || (SSL_get_shutdown(peer.ssl) & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
                != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) goto done;
        printf("{\"event\":\"shutdown\",\"clean\":true,\"shutdownBits\":%d}\n", SSL_get_shutdown(peer.ssl));
    } else {
        if (first.allowed || !first.reasons) goto done;
        if (partial && (!(first.reasons & X10_REASON_READ_BUFFER)
            || !(first.packet_length || first.rbuf_left))) goto done;
        if (unread && (!(first.reasons & X10_REASON_READ_RECORD) || !first.unread_record_bytes)) goto done;
        if (empty && !(first.reasons & X10_REASON_RETRY)) goto done;
        if (unrelated_write && (first.reasons != X10_REASON_RETRY
            || first.ledger_last_call != X10_CALL_WRITE
            || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
            || first.ledger_retry_call != X10_CALL_READ
            || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl))) goto done;
        if (overlap) {
            if (first.reasons != X10_REASON_RETRY
                || first.ledger_last_call != X10_CALL_WRITE
                || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
                || first.ledger_retry_call != X10_CALL_READ
                || first.wbuf_left || first.wnum || first.rwstate != SSL_NOTHING
                || SSL_pending(peer.ssl) != 0 || SSL_has_pending(peer.ssl)
                || retry_buffer != payload || retry_size != wanted) goto done;
            for (i = 0; i < wanted; i++)
                if (payload[i] != 0xa5) goto done;
            if (!observe(&peer, &second)) goto done;
            emit_probe(scenario, 4, &peer, &second);
            if (memcmp(&first, &second, sizeof(first))) goto done;
            /* Exact plaintext receipt must be acknowledged before raw close.
             * No READ retry, close_notify, handover or admission follows. */
            failure = "overlap_write_receipt_step";
            if (!step(deadline)) goto done;
            failure = "probe";
        }
        if (ku && !(first.reasons & X10_REASON_KEY_UPDATE)) goto done;
        if (peer_ku_pending) {
            if (first.reasons != (X10_REASON_GENERATION | X10_REASON_KEY_UPDATE)
                || !first.monitor_known || first.read_generation != 1
                || first.write_generation != 0 || first.mutation_serial != 3
                || first.key_update != SSL_KEY_UPDATE_NOT_REQUESTED
                || first.ledger_last_call != X10_CALL_READ
                || first.ledger_last_outcome != X10_OUTCOME_SUCCESS
                || first.ledger_retry_call != X10_CALL_NONE) goto done;
            if (!observe(&peer, &second)) goto done;
            emit_probe(scenario, 2, &peer, &second);
            if (memcmp(&first, &second, sizeof(first))) goto done;
            /* Both snapshots precede any outgoing TLS operation. Wait for
             * the bounded receipt ACK before intentionally raw teardown. */
            failure = "peer_key_update_pending_step";
            if (!step(deadline)) goto done;
            failure = "probe";
        }
        if (pressure_case && (!(first.reasons & X10_REASON_RETRY)
            || !(first.reasons & (X10_REASON_WRITE_BUFFER | X10_REASON_WRITE_CALL))
            || !(first.wbuf_left || first.wnum))) goto done;
        if (unrelated_write) {
            /* Wait for the peer's exact plaintext receipt before raw teardown;
             * stdout/TCP/EOF scheduling must not decide the negative result. */
            failure = "unrelated_write_receipt_step";
            if (!step(deadline)) goto done;
            failure = "probe";
        }
    }
    if (interrupted || now_ms() >= deadline) goto done;
    printf("{\"event\":\"done\",\"scenario\":\"%s\",\"observed\":true,\"allowed\":%s,"
        "\"graceful\":%s,\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu,"
        "\"pressureBytesCompleted\":%zu}\n", scenario, allowed_case ? "true" : "false",
        exchange && !unexpected_eof ? "true" : "false", exchange || peer_ku ? total : (unread ? (size_t) 1 : (size_t) 0),
        exchange || unrelated_write || overlap ? wanted : (size_t) 0, pressure_total);
    status = 0;
done:
    alarm(0);
    if (payload) OPENSSL_clear_free(payload, wanted);
    if (outbound) OPENSSL_clear_free(outbound, wanted);
    OPENSSL_cleanse(challenge, sizeof(challenge)); OPENSSL_cleanse(pressure, sizeof(pressure));
    OPENSSL_cleanse(&trailer, sizeof(trailer));
    SSL_free(peer.ssl); SSL_CTX_free(ctx);
    if (peer.fd >= 0) close(peer.fd);
    if (listener >= 0) close(listener);
    ERR_clear_error();
    if (status) printf("{\"event\":\"error\",\"code\":\"%s\"}\n", interrupted ? "cancelled" : failure);
    return status;
}
