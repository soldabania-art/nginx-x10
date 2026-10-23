/*
 * Isolated authenticated TLS 1.3 peer-requested KeyUpdate fixture. No state
 * export/import, reconnect, TLS-code migration or native NGINX integration.
 * Keylog output is confined to an inherited private IPC descriptor (3).
 * Public contracts: SSL_connect, SSL_read, SSL_write, SSL_key_update,
 * SSL_shutdown and SSL_CTX_set_keylog_callback (OpenSSL 3.0).
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_APPLICATION_BYTES 65536U
#define DEADLINE_MS 24000
#define KEYLOG_FD 3
#define KEYLOG_LINE_MAX 256U
#define KEYLOG_LINES_MAX 16U
static volatile sig_atomic_t interrupted;
static int keylog_failed;
static unsigned int keylog_lines;
static unsigned int initial_secrets;
static unsigned int unique_labels;
static unsigned char keylog_random[64];
static int64_t deadline;
static const unsigned char alpn[] = "continuum-c1";

static void stop_signal(int sig) { (void) sig; interrupted = 1; }

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int ready(int fd, short events)
{
    struct pollfd pfd;
    int rc;
    int64_t now, remaining;
    pfd.fd = fd; pfd.events = events; pfd.revents = 0;
    while (!interrupted) {
        now = now_ms();
        if (now < 0 || (remaining = deadline - now) <= 0) return 0;
        rc = poll(&pfd, 1, (int) remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0 || (pfd.revents & (POLLERR | POLLNVAL))) return 0;
        /* Let SSL distinguish authenticated close_notify from raw EOF. */
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

static int private_keylog_channel(void)
{
    struct stat channel, output;
    struct sockaddr_un address;
    socklen_t length = sizeof(address), type_length;
    int flags, type, fd;
    if (fstat(KEYLOG_FD, &channel) != 0
        || channel.st_uid != geteuid()
        || (!S_ISFIFO(channel.st_mode) && !S_ISSOCK(channel.st_mode))) return 0;
    for (fd = STDOUT_FILENO; fd <= STDERR_FILENO; fd++) {
        if (fstat(fd, &output) == 0 && channel.st_dev == output.st_dev
            && channel.st_ino == output.st_ino) return 0;
    }
    flags = fcntl(KEYLOG_FD, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) == O_RDONLY) return 0;
    if (S_ISSOCK(channel.st_mode)) {
        type_length = sizeof(type);
        memset(&address, 0, sizeof(address));
        if (getsockopt(KEYLOG_FD, SOL_SOCKET, SO_TYPE, &type, &type_length)
            || type != SOCK_STREAM
            || getsockname(KEYLOG_FD, (struct sockaddr *) &address, &length)
            || address.sun_family != AF_UNIX) return 0;
    }
    return nonblocking(KEYLOG_FD);
}

static int lower_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static void keylog(const SSL *ssl, const char *line)
{
    static const char *labels[] = {"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET",
        "CLIENT_TRAFFIC_SECRET_N", "SERVER_TRAFFIC_SECRET_N"};
    char framed[KEYLOG_LINE_MAX + 1];
    size_t length, prefix = 0, i, at = 0;
    ssize_t written;
    unsigned int label = 0;
    int saved_errno = errno;
    (void) ssl;
    if (keylog_failed || interrupted) { keylog_failed = 1; return; }
    length = strnlen(line, KEYLOG_LINE_MAX);
    if (length == KEYLOG_LINE_MAX || keylog_lines >= KEYLOG_LINES_MAX)
        goto failed;
    for (i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        size_t n = strlen(labels[i]);
        if (length > n && memcmp(line, labels[i], n) == 0 && line[n] == ' ') {
            label = (unsigned int) i; prefix = n + 1; break;
        }
    }
    /* AES-128-GCM/SHA256: client_random and each traffic secret are 32 bytes. */
    if (!prefix || length != prefix + 64 + 1 + 64 || line[prefix + 64] != ' ')
        goto failed;
    for (i = prefix; i < length; i++)
        if (i != prefix + 64 && !lower_hex(line[i])
            && !(line[i] >= 'A' && line[i] <= 'F')) goto failed;
    if (!keylog_lines) memcpy(keylog_random, line + prefix, sizeof(keylog_random));
    else if (memcmp(keylog_random, line + prefix, sizeof(keylog_random))) goto failed;
    if (label < 5 && (unique_labels & (1U << label))) goto failed;
    memcpy(framed, line, length); framed[length++] = '\n';
    while (at < length && !interrupted) {
        written = write(KEYLOG_FD, framed + at, length - at);
        if (written > 0) { at += (size_t) written; continue; }
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)
            && ready(KEYLOG_FD, POLLOUT)) continue;
        break;
    }
    OPENSSL_cleanse(framed, sizeof(framed));
    if (at != length) goto failed;
    keylog_lines++;
    if (label < 5) unique_labels |= 1U << label;
    if (label < 4) initial_secrets |= 1U << label;
    errno = saved_errno;
    return;
failed:
    OPENSSL_cleanse(framed, sizeof(framed));
    keylog_failed = 1;
    errno = saved_errno;
}

enum operation { CONNECT, READ, WRITE, HANDSHAKE, SHUTDOWN };
typedef struct { SSL *ssl; int fd; int error; size_t amount; } PEER;

static int complete(PEER *peer, enum operation call, void *buffer, size_t size)
{
    int result;
    int64_t now;
    while (!interrupted && !keylog_failed) {
        now = now_ms();
        if (now < 0 || now >= deadline) return 0;
        peer->amount = 0; ERR_clear_error(); errno = 0;
        switch (call) {
        case CONNECT: result = SSL_connect(peer->ssl); break;
        case READ: result = SSL_read_ex(peer->ssl, buffer, size, &peer->amount); break;
        case WRITE: result = SSL_write_ex(peer->ssl, buffer, size, &peer->amount); break;
        case HANDSHAKE: result = SSL_do_handshake(peer->ssl); break;
        case SHUTDOWN: result = SSL_shutdown(peer->ssl); break;
        default: return 0;
        }
        /* No intervening OpenSSL call before classification. */
        if (result > 0) peer->error = SSL_ERROR_NONE;
        else if (call == SHUTDOWN && result == 0)
            peer->error = SSL_ERROR_WANT_READ;
        else peer->error = SSL_get_error(peer->ssl, result);
        if (keylog_failed || interrupted) return 0;
        if (peer->error == SSL_ERROR_NONE) return 1;
        if (peer->error == SSL_ERROR_WANT_READ) {
            if (!ready(peer->fd, POLLIN)) return 0;
        } else if (peer->error == SSL_ERROR_WANT_WRITE) {
            if (!ready(peer->fd, POLLOUT)) return 0;
        } else return 0;
        /* Preserve the SAME operation, buffer and length across every retry. */
    }
    return 0;
}

static int step(void)
{
    char line[5];
    size_t at = 0;
    ssize_t got;
    while (at < sizeof(line)) {
        if (!ready(STDIN_FILENO, POLLIN)) return 0;
        got = read(STDIN_FILENO, line + at, sizeof(line) - at);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got <= 0) return 0;
        at += (size_t) got;
    }
    return memcmp(line, "STEP\n", sizeof(line)) == 0;
}

static int decimal(const char *text, unsigned int maximum, unsigned int *value)
{
    size_t i;
    unsigned int n = 0;
    if (!text || !text[0] || (text[0] == '0' && text[1])) return 0;
    for (i = 0; text[i]; i++) {
        if (i > 5 || text[i] < '0' || text[i] > '9') return 0;
        n = n * 10 + (unsigned int) (text[i] - '0');
        if (n > maximum) return 0;
    }
    *value = n; return n != 0;
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
    const char *ca = NULL, *port = NULL, *count = NULL, *nonce = NULL;
    const char *scenario = NULL, *failure = "arguments";
    const char *runtime_version = OpenSSL_version(OPENSSL_VERSION);
    SSL_CTX *ctx = NULL;
    PEER peer;
    struct sockaddr_in address;
    struct sigaction action;
    const unsigned char *selected = NULL;
    unsigned int selected_len = 0, parsed = 0, port_number = 0;
    unsigned char challenge[16] = {0}, protocol[sizeof(alpn)];
    unsigned char *payload = NULL, *echo = NULL;
    size_t i, wanted = 0, total = 0;
    int completed = 0, status = 1, result, socket_error;
    socklen_t error_length = sizeof(socket_error);

    memset(&peer, 0, sizeof(peer)); peer.fd = -1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&action, 0, sizeof(action)); action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)
        || sigaction(SIGALRM, &action, NULL)) goto done;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL)) goto done;
    alarm(25);
    deadline = now_ms(); if (deadline < 0) goto done; deadline += DEADLINE_MS;
    for (i = 1; i < (size_t) argc; i++) {
        const char **destination = NULL;
        if (!strcmp(argv[i], "--ca")) destination = &ca;
        else if (!strcmp(argv[i], "--port")) destination = &port;
        else if (!strcmp(argv[i], "--bytes")) destination = &count;
        else if (!strcmp(argv[i], "--challenge")) destination = &nonce;
        else if (!strcmp(argv[i], "--scenario")) destination = &scenario;
        if (!destination || *destination || ++i >= (size_t) argc
            || !argv[i][0] || strlen(argv[i]) > 4096) goto done;
        *destination = argv[i];
    }
    if (!ca || !nonce || !scenario || strlen(nonce) != 32
        || !decimal(port, 65535, &port_number)
        || !decimal(count, MAX_APPLICATION_BYTES, &parsed) || parsed < 2) goto done;
    if (!strcmp(scenario, "peer-key-update-completed")) completed = 1;
    else if (strcmp(scenario, "peer-key-update-pending")) goto done;
    wanted = (size_t) parsed;
    for (i = 0; i < sizeof(challenge); i++) {
        unsigned int a, b;
        if (!lower_hex(nonce[i * 2]) || !lower_hex(nonce[i * 2 + 1])) goto done;
        a = nonce[i * 2] <= '9' ? (unsigned int) (nonce[i * 2] - '0')
            : (unsigned int) (nonce[i * 2] - 'a' + 10);
        b = nonce[i * 2 + 1] <= '9' ? (unsigned int) (nonce[i * 2 + 1] - '0')
            : (unsigned int) (nonce[i * 2 + 1] - 'a' + 10);
        challenge[i] = (unsigned char) (a * 16 + b);
    }
    failure = "keylog_channel";
    if (!private_keylog_channel()) goto done;
    failure = "configuration";
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1
        || SSL_CTX_set_max_early_data(ctx, 0) != 1
        || SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) goto done;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_KTLS | SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_post_handshake_auth(ctx, 0);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_quiet_shutdown(ctx, 0); SSL_CTX_set_read_ahead(ctx, 0);
    SSL_CTX_set_max_pipelines(ctx, 1);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_clear_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        | SSL_MODE_ASYNC | SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_keylog_callback(ctx, keylog);
    protocol[0] = sizeof(alpn) - 1;
    memcpy(protocol + 1, alpn, sizeof(alpn) - 1);
    if (SSL_CTX_set_alpn_protos(ctx, protocol, sizeof(protocol)) != 0) goto done;
    peer.ssl = SSL_new(ctx);
    if (!peer.ssl || SSL_set_tlsext_host_name(peer.ssl, "continuum.test") != 1
        || SSL_set1_host(peer.ssl, "continuum.test") != 1) goto done;
    SSL_set_hostflags(peer.ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    failure = "connect";
    peer.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer.fd < 0 || !nonblocking(peer.fd)) goto done;
    memset(&address, 0, sizeof(address)); address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t) port_number);
    result = connect(peer.fd, (struct sockaddr *) &address, sizeof(address));
    if (result != 0 && (errno != EINPROGRESS || !ready(peer.fd, POLLOUT))) goto done;
    if (getsockopt(peer.fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length)
        || socket_error || SSL_set_fd(peer.ssl, peer.fd) != 1) goto done;
    failure = "handshake";
    if (!complete(&peer, CONNECT, NULL, 0)) goto done;
    SSL_get0_alpn_selected(peer.ssl, &selected, &selected_len);
    if (SSL_get_verify_result(peer.ssl) != X509_V_OK
        || SSL_version(peer.ssl) != TLS1_3_VERSION || SSL_session_reused(peer.ssl)
        || strcmp(SSL_get_cipher_name(peer.ssl), "TLS_AES_128_GCM_SHA256")
        || selected_len != sizeof(alpn) - 1 || memcmp(selected, alpn, sizeof(alpn) - 1)
        || SSL_get_early_data_status(peer.ssl) != SSL_EARLY_DATA_NOT_SENT
        || keylog_failed || initial_secrets != 15U
        || !public_version(runtime_version) || !public_version(OPENSSL_VERSION_TEXT)) goto done;
    printf("{\"event\":\"handshake\",\"version\":\"TLSv1.3\",\"cipher\":\"TLS_AES_128_GCM_SHA256\","
        "\"alpn\":\"continuum-c1\",\"resumed\":false,\"authorized\":true,\"opensslVersion\":\"%s\","
        "\"opensslHeadersVersion\":\"%s\"}\n", runtime_version, OPENSSL_VERSION_TEXT);
    printf("{\"event\":\"ready\",\"scenario\":\"%s\"}\n", scenario);
    failure = "step";
    if (!step()) goto done;
    payload = OPENSSL_malloc(wanted); echo = OPENSSL_malloc(wanted);
    if (!payload || !echo) goto done;
    for (i = 0; i < wanted; i++)
        payload[i] = (unsigned char) (((i * 29 + 7) & 255) ^ challenge[i % 16]);
    failure = "key_update";
    ERR_clear_error();
    if (SSL_key_update(peer.ssl, SSL_KEY_UPDATE_REQUESTED) != 1
        || !complete(&peer, HANDSHAKE, NULL, 0)
        || SSL_get_key_update_type(peer.ssl) != SSL_KEY_UPDATE_NONE) goto done;
    failure = "write";
    if (!complete(&peer, WRITE, payload, wanted) || peer.amount != wanted) goto done;
    printf("{\"event\":\"sent\",\"scenario\":\"%s\",\"applicationBytesWritten\":%zu,"
        "\"keyUpdateRequested\":true}\n", scenario, wanted);
    if (completed) {
        failure = "echo";
        while (total < wanted) {
            if (!complete(&peer, READ, echo + total, wanted - total)
                || !peer.amount || peer.amount > wanted - total) goto done;
            total += peer.amount;
        }
        if (memcmp(payload, echo, wanted) != 0) goto done;
        failure = "shutdown";
        if (!complete(&peer, SHUTDOWN, NULL, 0)
            || (SSL_get_shutdown(peer.ssl) & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
                != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) goto done;
        printf("{\"event\":\"shutdown\",\"clean\":true,\"shutdownBits\":%d}\n", SSL_get_shutdown(peer.ssl));
    } else {
        /* No read or automatic response flush: wait for the server probe and
         * orchestrator receipt before the intentionally ungraceful teardown. */
        failure = "receipt_step";
        if (!step()) goto done;
    }
    if (interrupted || keylog_failed || now_ms() < 0 || now_ms() >= deadline) goto done;
    printf("{\"event\":\"done\",\"scenario\":\"%s\",\"graceful\":%s,"
        "\"applicationBytesRead\":%zu,\"applicationBytesWritten\":%zu}\n",
        scenario, completed ? "true" : "false", total, wanted);
    status = 0;
done:
    alarm(0);
    if (payload) OPENSSL_clear_free(payload, wanted);
    if (echo) OPENSSL_clear_free(echo, wanted);
    OPENSSL_cleanse(challenge, sizeof(challenge));
    OPENSSL_cleanse(keylog_random, sizeof(keylog_random));
    SSL_free(peer.ssl); SSL_CTX_free(ctx);
    if (peer.fd >= 0) close(peer.fd);
    /* Descriptor 3 is inherited exclusively for this process's private log. */
    close(KEYLOG_FD);
    ERR_clear_error();
    if (status) printf("{\"event\":\"error\",\"code\":\"%s\"}\n",
        interrupted ? "cancelled" : (keylog_failed ? "keylog_channel" : failure));
    return status;
}
