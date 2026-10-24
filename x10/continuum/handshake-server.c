/*
 * Isolated C1 TLS handshake fixture.  No state export, keylog, adapter, FD
 * handover or native NGINX integration is implemented here.
 * Public OpenSSL 3.0 API contracts reviewed: SSL_read, SSL_write,
 * SSL_shutdown, SSL_key_update and SSL_CTX_set_alpn_select_cb.
 * https://docs.openssl.org/3.0/man3/SSL_read/
 * https://docs.openssl.org/3.0/man3/SSL_write/
 * https://docs.openssl.org/3.0/man3/SSL_shutdown/
 * https://docs.openssl.org/3.0/man3/SSL_key_update/
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

#define MAX_APPLICATION_BYTES 65536U
#define DEADLINE_MS 20000
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

/* Call immediately after the failing SSL operation, in the same thread. */
static int retry_ssl(SSL *ssl, int result, int fd, int64_t deadline,
    int *peer_closed)
{
    int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_ZERO_RETURN) { *peer_closed = 1; return 0; }
    if (error == SSL_ERROR_WANT_READ) return ready(fd, POLLIN, deadline);
    if (error == SSL_ERROR_WANT_WRITE) return ready(fd, POLLOUT, deadline);
    return 0;
}

static int handshake(SSL *ssl, int fd, int64_t deadline, int initial)
{
    int result, closed = 0;
    do {
        if (interrupted || now_ms() >= deadline) return 0;
        ERR_clear_error(); errno = 0;
        result = initial ? SSL_accept(ssl) : SSL_do_handshake(ssl);
        if (result == 1) return 1;
    } while (retry_ssl(ssl, result, fd, deadline, &closed));
    return 0;
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

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *count = NULL, *nonce = NULL;
    const char *runtime_version = OpenSSL_version(OPENSSL_VERSION);
    const char *failure = "arguments";
    unsigned char challenge[16] = {0}, trailer = 0, *payload = NULL;
    const unsigned char *selected = NULL;
    unsigned int selected_len = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    struct sockaddr_in address;
    struct sigaction action;
    socklen_t address_len = sizeof(address);
    size_t wanted = 0, received = 0, written = 0, amount, i;
    unsigned long parsed = 0;
    int listener = -1, client = -1, status = 1, result, closed = 0;
    int key_update = 0, update_before = SSL_KEY_UPDATE_NONE, shutdown_bits;
    int64_t deadline;

    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0
        || sigaction(SIGTERM, &action, NULL) != 0
        || sigaction(SIGALRM, &action, NULL) != 0) goto done;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) goto done;
    alarm(22);

    for (i = 1; i < (size_t) argc; i++) {
        const char **destination = NULL;
        if (strcmp(argv[i], "--key-update") == 0) {
            if (key_update) goto done;
            key_update = 1; continue;
        }
        if (strcmp(argv[i], "--cert") == 0) destination = &cert;
        else if (strcmp(argv[i], "--key") == 0) destination = &key;
        else if (strcmp(argv[i], "--bytes") == 0) destination = &count;
        else if (strcmp(argv[i], "--challenge") == 0) destination = &nonce;
        if (!destination || *destination || ++i >= (size_t) argc
            || !argv[i][0] || strlen(argv[i]) > 4096) goto done;
        *destination = argv[i];
    }
    if (!cert || !key || !count || !nonce || strlen(nonce) != 32) goto done;
    for (i = 0; count[i]; i++) {
        if (count[i] < '0' || count[i] > '9' || i > 5) goto done;
        parsed = parsed * 10 + (unsigned long) (count[i] - '0');
        if (parsed > MAX_APPLICATION_BYTES) goto done;
    }
    if (!parsed || (count[0] == '0' && count[1])) goto done;
    wanted = (size_t) parsed;
    for (i = 0; i < sizeof(challenge); i++) {
        int high = hex_nibble(nonce[i * 2]), low = hex_nibble(nonce[i * 2 + 1]);
        if (high < 0 || low < 0) goto done;
        challenge[i] = (unsigned char) (high * 16 + low);
    }

    failure = "configuration";
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1
        || SSL_CTX_set_num_tickets(ctx, 0) != 1
        || SSL_CTX_set_max_early_data(ctx, 0) != 1) goto done;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION
        | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_post_handshake_auth(ctx, 0);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_quiet_shutdown(ctx, 0);
    SSL_CTX_set_read_ahead(ctx, 0);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_clear_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE
        | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_alpn_select_cb(ctx, choose_alpn, NULL);
    SSL_CTX_set_default_passwd_cb(ctx, reject_password);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) goto done;

    failure = "listen";
    deadline = now_ms();
    if (deadline < 0) goto done;
    deadline += DEADLINE_MS;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || !nonblocking(listener)) goto done;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) != 0
        || listen(listener, 1) != 0
        || getsockname(listener, (struct sockaddr *) &address, &address_len) != 0) goto done;
    printf("{\"event\":\"listening\",\"port\":%u}\n", (unsigned int) ntohs(address.sin_port));
    failure = "accept";
    while (!interrupted) {
        if (!ready(listener, POLLIN, deadline)) goto done;
        client = accept(listener, NULL, NULL);
        if (client >= 0) break;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) goto done;
    }
    if (client < 0 || !nonblocking(client)) goto done;
    close(listener); listener = -1;
    ssl = SSL_new(ctx);
    failure = "handshake";
    if (!ssl || SSL_set_fd(ssl, client) != 1 || !handshake(ssl, client, deadline, 1)) goto done;
    SSL_get0_alpn_selected(ssl, &selected, &selected_len);
    if (SSL_version(ssl) != TLS1_3_VERSION || SSL_session_reused(ssl)
        || strcmp(SSL_get_cipher_name(ssl), "TLS_AES_128_GCM_SHA256") != 0
        || selected_len != sizeof(alpn) - 1
        || memcmp(selected, alpn, sizeof(alpn) - 1) != 0
        || SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_NOT_SENT) goto done;
    if (!public_version(runtime_version) || !public_version(OPENSSL_VERSION_TEXT)) {
        failure = "backend_version"; goto done;
    }
    printf("{\"event\":\"handshake\",\"version\":\"TLSv1.3\","
           "\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"alpn\":\"continuum-c1\",\"resumed\":false,"
           "\"opensslVersion\":\"%s\",\"opensslVersionNumber\":%lu,"
           "\"opensslHeadersVersion\":\"%s\"}\n",
           runtime_version, OpenSSL_version_num(), OPENSSL_VERSION_TEXT);

    if (key_update) {
        failure = "key_update";
        if (SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED) != 1) goto done;
        update_before = SSL_get_key_update_type(ssl);
        if (update_before != SSL_KEY_UPDATE_NOT_REQUESTED
            || !handshake(ssl, client, deadline, 0)
            || SSL_get_key_update_type(ssl) != SSL_KEY_UPDATE_NONE) goto done;
    }

    failure = "application_read";
    payload = OPENSSL_malloc(wanted);
    if (!payload) goto done;
    while (received < wanted) {
        if (interrupted || now_ms() >= deadline) goto done;
        amount = 0; ERR_clear_error(); errno = 0;
        result = SSL_read_ex(ssl, payload + received, wanted - received, &amount);
        if (result == 1) {
            if (!amount || amount > wanted - received) goto done;
            for (i = 0; i < amount; i++) {
                if (payload[received + i] != (unsigned char)
                    ((((received + i) * 29 + 7) & 255) ^ challenge[(received + i) % 16])) {
                    failure = "application_mismatch"; goto done;
                }
            }
            received += amount; continue;
        }
        if (!retry_ssl(ssl, result, client, deadline, &closed)) goto done;
    }
    if (SSL_pending(ssl) != 0) { failure = "application_trailer"; goto done; }
    failure = "application_write";
    do {
        if (interrupted || now_ms() >= deadline) goto done;
        amount = 0; ERR_clear_error(); errno = 0;
        result = SSL_write_ex(ssl, payload, wanted, &amount);
        if (result == 1) { if (amount != wanted) goto done; written = amount; break; }
    } while (retry_ssl(ssl, result, client, deadline, &closed));
    if (written != wanted) goto done;
    printf("{\"event\":\"quiesce\",\"point\":\"after_application_echo_before_close\","
           "\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu,"
           "\"sslPending\":%d,\"sslHasPending\":%d,\"keyUpdateRequested\":%s,"
           "\"keyUpdateTypeBeforeFlush\":%d,\"keyUpdateType\":%d,\"shutdownBits\":%d}\n",
           received, written, SSL_pending(ssl), SSL_has_pending(ssl),
           key_update ? "true" : "false", update_before,
           SSL_get_key_update_type(ssl), SSL_get_shutdown(ssl));

    /* The matching client ends after the echo. Consume through authenticated
     * peer close_notify and reject every extra application byte, even late. */
    failure = "peer_close_notify";
    closed = 0;
    while (!closed) {
        if (interrupted || now_ms() >= deadline) goto done;
        amount = 0; ERR_clear_error(); errno = 0;
        result = SSL_read_ex(ssl, &trailer, 1, &amount);
        if (result == 1) { failure = "application_trailer"; goto done; }
        if (!retry_ssl(ssl, result, client, deadline, &closed) && !closed) goto done;
    }
    failure = "shutdown";
    do {
        if (interrupted || now_ms() >= deadline) goto done;
        ERR_clear_error(); errno = 0;
        result = SSL_shutdown(ssl);
        if (result == 1) break;
        if (result == 0) continue; /* Not an SSL_get_error error condition. */
        if (!retry_ssl(ssl, result, client, deadline, &closed)) goto done;
    } while (1);
    shutdown_bits = SSL_get_shutdown(ssl);
    if ((shutdown_bits & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
        != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) goto done;
    printf("{\"event\":\"shutdown\",\"clean\":true,\"shutdownBits\":%d,"
           "\"sentCloseNotify\":true,\"receivedCloseNotify\":true}\n", shutdown_bits);
    status = 0;
done:
    alarm(0);
    if (payload) OPENSSL_clear_free(payload, wanted);
    OPENSSL_cleanse(challenge, sizeof(challenge)); OPENSSL_cleanse(&trailer, sizeof(trailer));
    SSL_free(ssl); SSL_CTX_free(ctx);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    ERR_clear_error();
    if (status) printf("{\"event\":\"error\",\"code\":\"%s\"}\n", interrupted ? "cancelled" : failure);
    return status;
}
