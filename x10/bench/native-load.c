#define _GNU_SOURCE
/* Bounded loopback HTTP/1.1 load fixture. Not part of the NGINX data plane. */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 128
#define HEADER_LIMIT 16384
#define BODY_SIZE 1024
#define RESPONSE_LIMIT (HEADER_LIMIT + BODY_SIZE)
#define LATENCY_BUCKETS 32

enum phase { IDLE, CONNECTING, WRITING, READING };
struct client {
    int fd;
    enum phase phase;
    size_t sent, received, header_size;
    int close_after, used_before;
    uint64_t started_ns, expires_ns;
    unsigned char response[RESPONSE_LIMIT];
};
struct options {
    int port, concurrency, duration_ms, timeout_ms;
    uint64_t max_requests;
    const char *target;
};
struct totals {
    uint64_t admitted, completed, failed, aborted, connections, reused;
    uint64_t latency_sum, latency_max, histogram[LATENCY_BUCKETS];
    int cleanup_errors, error_number;
    const char *error;
};
static volatile sig_atomic_t interrupted;

static void on_signal(int signal_number) { interrupted = signal_number; }
static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) { perror("clock_gettime"); exit(2); }
    return (uint64_t) value.tv_sec * UINT64_C(1000000000) + (uint64_t) value.tv_nsec;
}
static double cpu_ms(struct timeval value) { return value.tv_sec * 1000.0 + value.tv_usec / 1000.0; }
static int number(const char *text, uint64_t low, uint64_t high, uint64_t *value) {
    uint64_t parsed = 0;
    if (!*text) return 0;
    for (; *text; text++) {
        if (*text < '0' || *text > '9' || parsed > (high - (unsigned) (*text - '0')) / 10) return 0;
        parsed = parsed * 10 + (unsigned) (*text - '0');
    }
    if (parsed < low || parsed > high) return 0;
    *value = parsed; return 1;
}
static int options(int argc, char **argv, struct options *out) {
    *out = (struct options) { 0, 1, 1000, 2000, UINT64_C(1000000), "/static" };
    for (int i = 1; i < argc; i++) {
        const char *key = argv[i];
        if (!strcmp(key, "--help")) return 2;
        if (++i == argc) return 0;
        uint64_t n;
        if (!strcmp(key, "--port")) { if (!number(argv[i], 1, 65535, &n)) return 0; out->port = (int) n; }
        else if (!strcmp(key, "--concurrency")) { if (!number(argv[i], 1, MAX_CLIENTS, &n)) return 0; out->concurrency = (int) n; }
        else if (!strcmp(key, "--duration-ms")) { if (!number(argv[i], 50, 10000, &n)) return 0; out->duration_ms = (int) n; }
        else if (!strcmp(key, "--timeout-ms")) { if (!number(argv[i], 100, 5000, &n)) return 0; out->timeout_ms = (int) n; }
        else if (!strcmp(key, "--max-requests")) { if (!number(argv[i], 1, 1000000, &n)) return 0; out->max_requests = n; }
        else if (!strcmp(key, "--path")) {
            const unsigned char *p = (unsigned char *) argv[i];
            if (*p != '/' || strlen((char *) p) > 1024) return 0;
            for (; *p; p++) if (!isalnum(*p) && !strchr("/_.~%?=&+-", *p)) return 0;
            out->target = argv[i];
        } else return 0;
    }
    return out->port != 0;
}
static void quote(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *) text; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static void close_client(struct client *client, struct totals *totals) {
    if (client->fd >= 0) {
        if (close(client->fd) != 0 && errno != EINTR) totals->cleanup_errors++;
        client->fd = -1;
    }
    client->phase = IDLE;
    client->used_before = 0;
}
static void failure(struct client *client, struct totals *totals, const char *reason, int error_number) {
    if (!totals->error) { totals->error = reason; totals->error_number = error_number; }
    if (client->phase != IDLE) totals->failed++;
    close_client(client, totals);
}
static int header_token(unsigned char c) {
    return c != 0 && (isalnum(c) || strchr("!#$%&'*+-.^_`|~", c) != NULL);
}
static int name_equal(const unsigned char *name, size_t length, const char *expected) {
    return strlen(expected) == length && !strncasecmp((const char *) name, expected, length);
}
static int close_token(const unsigned char *value, size_t length) {
    size_t at = 0;
    while (at < length) {
        while (at < length && (value[at] == ' ' || value[at] == '\t' || value[at] == ',')) at++;
        size_t start = at;
        while (at < length && value[at] != ',') at++;
        size_t end = at;
        while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) end--;
        if (end - start == 5 && !strncasecmp((const char *) value + start, "close", 5)) return 1;
    }
    return 0;
}
static const char *parse_headers(struct client *client) {
    unsigned char *bytes = client->response;
    const unsigned char *end = bytes + client->header_size;
    unsigned char *line_end = memmem(bytes, client->header_size, "\r\n", 2);
    if (!line_end) return "invalid_status_line";
    size_t first_length = (size_t) (line_end - bytes);
    if (first_length < 13 || memcmp(bytes, "HTTP/1.1 200", 12)
        || bytes[12] != ' ') return "unexpected_http_status";
    for (size_t i = 0; i < first_length; i++) if (bytes[i] < 32 || bytes[i] > 126) return "invalid_status_line";
    int found_length = 0;
    const unsigned char *line = line_end + 2;
    while (line + 2 <= end && !(line[0] == '\r' && line[1] == '\n')) {
        const unsigned char *next = memmem(line, (size_t) (end - line), "\r\n", 2);
        if (!next) return "invalid_header_line";
        const unsigned char *colon = memchr(line, ':', (size_t) (next - line));
        if (!colon || colon == line) return "invalid_header_name";
        for (const unsigned char *p = line; p < colon; p++) if (!header_token(*p)) return "invalid_header_name";
        const unsigned char *value = colon + 1, *tail = next;
        for (const unsigned char *p = value; p < tail; p++) if ((*p < 32 && *p != '\t') || *p > 126) return "invalid_header_value";
        while (value < tail && (*value == ' ' || *value == '\t')) value++;
        while (tail > value && (tail[-1] == ' ' || tail[-1] == '\t')) tail--;
        size_t name_size = (size_t) (colon - line), value_size = (size_t) (tail - value);
        if (name_equal(line, name_size, "content-length")) {
            if (found_length++) return "duplicate_content_length";
            uint64_t n = 0;
            if (!value_size) return "invalid_content_length";
            for (const unsigned char *p = value; p < tail; p++) {
                if (*p < '0' || *p > '9' || n > BODY_SIZE) return "invalid_content_length";
                n = n * 10 + (unsigned) (*p - '0');
            }
            if (n != BODY_SIZE) return "unexpected_content_length";
        } else if (name_equal(line, name_size, "transfer-encoding")) return "unsupported_transfer_encoding";
        else if (name_equal(line, name_size, "content-encoding")) return "unsupported_content_encoding";
        else if (name_equal(line, name_size, "connection")) client->close_after |= close_token(value, value_size);
        line = next + 2;
    }
    if (line + 2 != end || !found_length) return "missing_content_length";
    return NULL;
}
static int response_state(struct client *client, const char **error) {
    if (!client->header_size) {
        unsigned char *separator = memmem(client->response, client->received, "\r\n\r\n", 4);
        if (!separator) {
            if (client->received >= HEADER_LIMIT) *error = "response_headers_too_large";
            return *error ? -1 : 0;
        }
        client->header_size = (size_t) (separator - client->response) + 4;
        if (client->header_size > HEADER_LIMIT) { *error = "response_headers_too_large"; return -1; }
        *error = parse_headers(client);
        if (*error) return -1;
    }
    size_t total = client->header_size + BODY_SIZE;
    if (client->received > total) { *error = "unexpected_bytes_after_body"; return -1; }
    size_t available = client->received - client->header_size;
    for (size_t i = 0; i < available; i++) {
        if (client->response[client->header_size + i] != (unsigned char) (33 + i % 90)) {
            *error = "response_body_mismatch"; return -1;
        }
    }
    return client->received == total;
}
static void complete(struct client *client, struct totals *totals, uint64_t now, int hangup) {
    if (now >= client->expires_ns) { failure(client, totals, "request_absolute_timeout", 0); return; }
    uint64_t latency = now - client->started_ns;
    totals->completed++; totals->latency_sum += latency;
    if (latency > totals->latency_max) totals->latency_max = latency;
    uint64_t microseconds = latency / 1000 + (latency % 1000 != 0);
    unsigned bucket = 0;
    while (bucket + 1 < LATENCY_BUCKETS && microseconds > (UINT64_C(1) << bucket)) bucket++;
    totals->histogram[bucket]++;
    client->phase = IDLE; client->used_before = 1;
    if (client->close_after || hangup) close_client(client, totals);
}
static void read_response(struct client *client, struct totals *totals, short events) {
    while (!totals->error) {
        if (client->received == RESPONSE_LIMIT) { failure(client, totals, "response_limit_exceeded", 0); return; }
        ssize_t count = recv(client->fd, client->response + client->received, RESPONSE_LIMIT - client->received, 0);
        if (count > 0) {
            client->received += (size_t) count;
            const char *error = NULL;
            int ready = response_state(client, &error);
            if (ready < 0) { failure(client, totals, error, 0); return; }
            if (ready) { complete(client, totals, now_ns(), events & (POLLHUP | POLLERR)); return; }
        } else if (count == 0) { failure(client, totals, "response_truncated", 0); return; }
        else if (errno == EINTR) { if (interrupted) return; }
        else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (events & POLLERR) {
                int error_number = 0; socklen_t length = sizeof(error_number);
                if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &error_number, &length) != 0) error_number = errno;
                failure(client, totals, "socket_read_error", error_number);
            }
            return;
        } else { failure(client, totals, "socket_read_error", errno); return; }
    }
}
static void write_request(struct client *client, struct totals *totals, const char *request, size_t size) {
    while (client->sent < size) {
        ssize_t count = send(client->fd, request + client->sent, size - client->sent, MSG_NOSIGNAL);
        if (count > 0) client->sent += (size_t) count;
        else if (count < 0 && errno == EINTR) { if (interrupted) return; }
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        else { failure(client, totals, "socket_write_error", count < 0 ? errno : 0); return; }
    }
    client->phase = READING;
}
static void admit(struct client *client, struct totals *totals, struct options *opts, uint64_t now) {
    totals->admitted++;
    client->started_ns = now;
    client->expires_ns = now + (uint64_t) opts->timeout_ms * 1000000;
    client->sent = client->received = client->header_size = 0;
    client->close_after = 0;
    client->phase = WRITING;
    if (client->fd >= 0) { totals->reused += client->used_before != 0; return; }
    client->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (client->fd < 0) { failure(client, totals, "socket_create_error", errno); return; }
    totals->connections++;
    int enabled = 1;
    if (setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) { failure(client, totals, "socket_option_error", errno); return; }
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((uint16_t) opts->port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(client->fd, (struct sockaddr *) &address, sizeof(address)) == 0) return;
    if (errno != EINPROGRESS) { failure(client, totals, "socket_connect_error", errno); return; }
    client->phase = CONNECTING;
}
static uint64_t quantile(const struct totals *totals, unsigned percent) {
    if (!totals->completed) return 0;
    uint64_t rank = (totals->completed * percent + 99) / 100, count = 0;
    for (unsigned i = 0; i < LATENCY_BUCKETS; i++) {
        count += totals->histogram[i];
        if (count >= rank) return UINT64_C(1) << i;
    }
    return 0;
}
int main(int argc, char **argv) {
    struct options opts;
    int parsed = options(argc, argv, &opts);
    if (parsed != 1) {
        if (parsed == 2) { puts("Usage: native-load --port N [--path /static] [--duration-ms 50..10000] [--concurrency 1..128] [--timeout-ms 100..5000] [--max-requests 1..1000000]\nFixed target127.0.0.1; strict fixed1024-byte HTTP/1.1 responses; no TLS/chunked/encoding."); return 0; }
        fputs("Invalid or incomplete options. Use --help.\n", stderr);
        puts("{\"schemaVersion\":1,\"suite\":\"native-http1-load\",\"success\":false,\"error\":{\"reason\":\"invalid_options\",\"errno\":0}}"); return 2;
    }
    struct client *clients = calloc((size_t) opts.concurrency, sizeof(*clients));
    if (!clients) { perror("calloc"); return 2; }
    for (int i = 0; i < opts.concurrency; i++) clients[i].fd = -1;
    struct pollfd descriptors[MAX_CLIENTS];
    struct totals totals = {0};
    char request[1300];
    int written = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n", opts.target);
    if (written < 0 || (size_t) written >= sizeof(request)) { free(clients); return 2; }
    signal(SIGPIPE, SIG_IGN); signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before) != 0) { perror("getrusage"); free(clients); return 2; }
    uint64_t started = now_ns(), deadline = started + (uint64_t) opts.duration_ms * 1000000;
    uint64_t timeout = (uint64_t) opts.timeout_ms * 1000000, admission_end = deadline;
    while (!interrupted && !totals.error) {
        uint64_t now = now_ns();
        int active = 0;
        for (int i = 0; i < opts.concurrency && !totals.error; i++) {
            struct client *client = &clients[i];
            now = now_ns();
            if (client->phase == IDLE && now < deadline && totals.admitted < opts.max_requests) admit(client, &totals, &opts, now);
            if (totals.admitted == opts.max_requests && admission_end == deadline) admission_end = now;
            if (client->phase != IDLE) {
                active++;
                if (now - client->started_ns >= timeout) failure(client, &totals, "request_absolute_timeout", 0);
            }
        }
        if (!active || totals.error) break;
        uint64_t next = now + timeout;
        if (now < deadline && totals.admitted < opts.max_requests) next = deadline;
        for (int i = 0; i < opts.concurrency; i++) {
            struct client *client = &clients[i];
            descriptors[i].fd = client->phase == IDLE ? -1 : client->fd;
            descriptors[i].events = client->phase == READING ? POLLIN : POLLOUT;
            descriptors[i].revents = 0;
            if (client->phase != IDLE && client->started_ns + timeout < next) next = client->started_ns + timeout;
        }
        int wait_ms = next <= now ? 0 : (int) ((next - now + 999999) / 1000000);
        int ready = poll(descriptors, (nfds_t) opts.concurrency, wait_ms);
        if (ready < 0) { if (errno == EINTR) continue; totals.error = "poll_error"; totals.error_number = errno; break; }
        now = now_ns();
        for (int i = 0; i < opts.concurrency && !totals.error && !interrupted; i++) {
            struct client *client = &clients[i];
            short events = descriptors[i].revents;
            if (client->phase == IDLE) continue;
            if (now - client->started_ns >= timeout) { failure(client, &totals, "request_absolute_timeout", 0); break; }
            if (!events) continue;
            if (events & POLLNVAL) { failure(client, &totals, "invalid_poll_descriptor", 0); break; }
            if (client->phase == CONNECTING) {
                int error_number = 0; socklen_t length = sizeof(error_number);
                if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &error_number, &length) != 0) error_number = errno;
                if (error_number) { failure(client, &totals, "socket_connect_error", error_number); break; }
                client->phase = WRITING;
            }
            if (client->phase == WRITING && events & (POLLOUT | POLLERR | POLLHUP)) write_request(client, &totals, request, (size_t) written);
            if (client->phase == READING && events & (POLLIN | POLLERR | POLLHUP)) read_response(client, &totals, events);
        }
    }
    uint64_t finished;
    int open_sockets = 0;
    for (int i = 0; i < opts.concurrency; i++) {
        if (clients[i].phase != IDLE) totals.aborted++;
        close_client(&clients[i], &totals);
        open_sockets += clients[i].fd >= 0;
    }
    finished = now_ns();
    if (finished < admission_end) admission_end = finished;
    if (getrusage(RUSAGE_SELF, &after) != 0) { totals.error = "getrusage_error"; totals.error_number = errno; memset(&after, 0, sizeof(after)); }
    uint64_t histogram_count = 0;
    for (unsigned i = 0; i < LATENCY_BUCKETS; i++) histogram_count += totals.histogram[i];
    int consistent = totals.admitted == totals.completed + totals.failed + totals.aborted && histogram_count == totals.completed;
    int success = !interrupted && !totals.error && !totals.cleanup_errors && !open_sockets && totals.completed && consistent && totals.admitted == totals.completed;
    printf("{\"schemaVersion\":1,\"suite\":\"native-http1-load\",\"success\":%s,\"interrupted\":%d,\"endpoint\":{\"host\":\"127.0.0.1\",\"port\":%d,\"path\":", success ? "true" : "false", (int) interrupted, opts.port);
    quote(opts.target);
    printf("},\"options\":{\"durationMs\":%d,\"concurrency\":%d,\"timeoutMs\":%d,\"maxRequests\":%" PRIu64 "},", opts.duration_ms, opts.concurrency, opts.timeout_ms, opts.max_requests);
    printf("\"counters\":{\"admitted\":%" PRIu64 ",\"completed\":%" PRIu64 ",\"failed\":%" PRIu64 ",\"aborted\":%" PRIu64 ",\"connectionsOpened\":%" PRIu64 ",\"reusedRequests\":%" PRIu64 "},", totals.admitted, totals.completed, totals.failed, totals.aborted, totals.connections, totals.reused);
    printf("\"timing\":{\"elapsedMs\":%.6f,\"admissionMs\":%.6f,\"drainMs\":%.6f},\"throughputRps\":%.6f,", (finished - started) / 1e6, (admission_end - started) / 1e6, (finished - admission_end) / 1e6, finished > started ? totals.completed * 1e9 / (finished - started) : 0.0);
    printf("\"latency\":{\"count\":%" PRIu64 ",\"meanUs\":%.6f,\"maxUs\":%.6f,\"p50UpperUs\":%" PRIu64 ",\"p95UpperUs\":%" PRIu64 ",\"p99UpperUs\":%" PRIu64 ",\"quantileMethod\":\"nearest-rank logarithmic histogram upper bound\",\"histogram\":[", totals.completed, totals.completed ? totals.latency_sum / 1000.0 / totals.completed : 0.0, totals.latency_max / 1000.0, quantile(&totals, 50), quantile(&totals, 95), quantile(&totals, 99));
    for (unsigned i = 0; i < LATENCY_BUCKETS; i++) printf("%s{\"upperUs\":%" PRIu64 ",\"count\":%" PRIu64 "}", i ? "," : "", UINT64_C(1) << i, totals.histogram[i]);
    printf("]},\"resources\":{\"userCpuMs\":%.6f,\"systemCpuMs\":%.6f,\"maxRssKiB\":%ld},\"cleanup\":{\"openSockets\":%d,\"errors\":%d},\"counterInvariant\":%s,\"requestCapReached\":%s,\"error\":", cpu_ms(after.ru_utime) - cpu_ms(before.ru_utime), cpu_ms(after.ru_stime) - cpu_ms(before.ru_stime), after.ru_maxrss, open_sockets, totals.cleanup_errors, consistent ? "true" : "false", totals.admitted == opts.max_requests ? "true" : "false");
    if (totals.error) { printf("{\"reason\":"); quote(totals.error); printf(",\"errno\":%d}", totals.error_number); }
    else if (interrupted) printf("{\"reason\":\"interrupted\",\"errno\":0}");
    else if (!consistent) printf("{\"reason\":\"counter_invariant\",\"errno\":0}");
    else printf("null");
    puts("}");
    free(clients);
    return success ? 0 : 1;
}
