/*
 * Bounded tests of the actual receive-side QUIC frame parser.
 * Packet eligibility is from RFC 9000 sections 12.4/19. Byte parsing is not
 * apply-time ACK arithmetic, stream flow control or handshake validation.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>

#ifndef NGX_QUIC_TRANSPORT_SOURCE
#error "quic-frames.sh must select the production translation unit"
#endif
#include NGX_QUIC_TRANSPORT_SOURCE

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

typedef struct { const char *name; unsigned cases, failed; } property_t;
enum { FIELDS, TRUNCATION, LENGTHS, PERMISSIONS, LIMITS, SEEDED, NPROPERTIES };
static property_t properties[] = {
    { "complete_fields_consumption_and_nonminimal_values", 0, 0 },
    { "structured_frame_prefixes_are_rejected", 0, 0 },
    { "declared_payload_lengths_and_borrowed_bounds", 0, 0 },
    { "client_frame_packet_eligibility", 0, 0 },
    { "unknown_type_cid_and_stream_limit_boundaries", 0, 0 },
    { "seeded_inputs_return_only_bounded_consumption", 0, 0 }
};
static unsigned examples;
static uint64_t input_digest = UINT64_C(14695981039346656037);

static size_t
integer(u_char *p, uint64_t value, unsigned width)
{
    unsigned i, tag = width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3;
    if ((width != 1 && width != 2 && width != 4 && width != 8)
        || value >= (UINT64_C(1) << (8 * width - 2)))
    {
        fprintf(stderr, "Invalid fixture varint\n"); exit(2);
    }
    for (i = width; i; i--) { p[i - 1] = (u_char) value; value >>= 8; }
    p[0] |= (u_char) (tag << 6);
    return width;
}

static unsigned
width(uint64_t value)
{
    return value < 64 ? 1 : value < 16384 ? 2
           : value < UINT64_C(1073741824) ? 4 : 8;
}

static void
record(unsigned property, const char *label, unsigned type, int passed,
    const u_char *bytes, size_t n)
{
    size_t i;
    properties[property].cases++;
    for (i = 0; i < n; i++) {
        input_digest ^= bytes[i]; input_digest *= UINT64_C(1099511628211);
    }
    input_digest ^= n; input_digest *= UINT64_C(1099511628211);
    if (!passed) {
        properties[property].failed++;
        if (examples++ < 12) {
            fprintf(stderr, "property=%s label=%s type=%u bytes=%zu\n",
                    properties[property].name, label, type, n);
        }
    }
}

static int
allowed(unsigned type, unsigned packet)
{
    /* packet: Initial, Handshake, 0-RTT, 1-RTT; client->server. */
    if (type == 0 || type == 1 || type == 28) return 1;
    if (type == 2 || type == 3 || type == 6) return packet != 2;
    if (type == 7 || type == 30) return 0; /* server-only */
    if (type == 27) return packet == 3;
    return packet >= 2;
}

static size_t
frame(u_char *p, unsigned type, uint64_t value, unsigned w, size_t payload)
{
    size_t n = 1, i;
    p[0] = (u_char) type;
#define V(v) (n += integer(p + n, (v), w))
    switch (type) {
    case 0: case 1: case 30: break;
    case 2: case 3:
        V(value); V(value); V(1); V(value); V(0); V(0);
        if (type == 3) { V(value); V(value); V(value); }
        break;
    case 4: V(value); V(value); V(value); break;
    case 5: V(value); V(value); break;
    case 6: V(value); V(payload); break;
    case 7: V(payload); break;
    case 8: case 9: case 10: case 11:
    case 12: case 13: case 14: case 15:
        V(value);
        if (type & 4) V(value);
        if (type & 2) V(payload);
        break;
    case 16: case 18: case 19: case 20: case 22: case 23: case 25:
        V(value); break;
    case 17: case 21: V(value); V(value); break;
    case 24:
        V(value); V(value); p[n++] = 20;
        for (i = 0; i < 36; i++) p[n++] = (u_char) (i + 3);
        break;
    case 26: case 27:
        for (i = 0; i < 8; i++) p[n++] = (u_char) (i + 3);
        break;
    case 28: case 29:
        V(value); if (type == 28) V(value); V(payload); break;
    }
    if (type == 6 || type == 7 || (type >= 8 && type <= 15)
        || type == 28 || type == 29)
    {
        for (i = 0; i < payload; i++) p[n++] = (u_char) (i + 33);
    }
#undef V
    return n;
}

static ssize_t
parse(u_char *p, size_t n, unsigned packet, ngx_quic_frame_t *f,
    ngx_buf_t *b, ngx_quic_header_t *pkt)
{
    static const unsigned flags[] = { 0xc0, 0xe0, 0xd0, 0x40 };
    static const unsigned levels[] = { 0, 2, 1, 3 };
    static ngx_log_t log;
    static ngx_chain_t chain;
    memset(f, 0, sizeof(*f)); memset(b, 0, sizeof(*b));
    memset(pkt, 0, sizeof(*pkt));
    chain.buf = b; chain.next = NULL; f->data = &chain;
    pkt->log = &log; pkt->flags = flags[packet]; pkt->level = levels[packet];
    return ngx_quic_parse_frame(pkt, p, p + n, f);
}

static int
borrowed(ngx_buf_t *b, u_char *p, size_t n, size_t expected)
{
    uintptr_t first = (uintptr_t) p, last = first + n;
    return (uintptr_t) b->pos >= first && (uintptr_t) b->last <= last
           && (uintptr_t) b->last >= (uintptr_t) b->pos
           && (uintptr_t) b->last - (uintptr_t) b->pos == expected;
}

static int
fields(ngx_quic_frame_t *f, ngx_buf_t *b, u_char *p, size_t n,
    unsigned type, uint64_t v, unsigned w, size_t payload)
{
    unsigned i;
    if (f->type != (type >= 8 && type <= 15 ? 8 : type)
        || f->level != NGX_QUIC_ENCRYPTION_APPLICATION) return 0;
    switch (type) {
    case 0: case 1: return 1;
    case 2: case 3:
        return f->u.ack.largest == v && f->u.ack.delay == v
               && f->u.ack.range_count == 1 && f->u.ack.first_range == v
               && f->u.ack.ranges_length == 2 * w
               && borrowed(b, p, n, 2 * w) && b->pos == p + 1 + 4 * w
               && b->last == p + 1 + 6 * w
               && (type == 2 || (f->u.ack.ect0 == v
                   && f->u.ack.ect1 == v && f->u.ack.ce == v));
    case 4: return f->u.reset_stream.id == v
                   && f->u.reset_stream.error_code == v
                   && f->u.reset_stream.final_size == v;
    case 5: return f->u.stop_sending.id == v && f->u.stop_sending.error_code == v;
    case 6: return f->u.crypto.offset == v && f->u.crypto.length == payload
                   && borrowed(b, p, n, payload) && b->last == p + n;
    case 8: case 9: case 10: case 11:
    case 12: case 13: case 14: case 15:
        return f->u.stream.stream_id == v && f->u.stream.offset == ((type & 4) ? v : 0)
               && f->u.stream.off == !!(type & 4) && f->u.stream.len == !!(type & 2)
               && f->u.stream.fin == !!(type & 1)
               && f->u.stream.length == payload && borrowed(b, p, n, payload)
               && b->last == p + n;
    case 16: return f->u.max_data.max_data == v;
    case 17: return f->u.max_stream_data.id == v && f->u.max_stream_data.limit == v;
    case 18: case 19: return f->u.max_streams.limit == v && f->u.max_streams.bidi == (type == 18);
    case 20: return f->u.data_blocked.limit == v;
    case 21: return f->u.stream_data_blocked.id == v && f->u.stream_data_blocked.limit == v;
    case 22: case 23: return f->u.streams_blocked.limit == v && f->u.streams_blocked.bidi == (type == 22);
    case 24:
        if (f->u.ncid.seqnum != v || f->u.ncid.retire != v || f->u.ncid.len != 20) return 0;
        for (i = 0; i < 20; i++) if (f->u.ncid.cid[i] != i + 3) return 0;
        for (i = 0; i < 16; i++) if (f->u.ncid.srt[i] != i + 23) return 0;
        return 1;
    case 25: return f->u.retire_cid.sequence_number == v;
    case 26: case 27:
        for (i = 0; i < 8; i++) if (f->u.path_challenge.data[i] != i + 3) return 0;
        return 1;
    case 28: case 29:
        return f->u.close.error_code == v && f->u.close.reason.len == payload
               && (uintptr_t) f->u.close.reason.data >= (uintptr_t) p
               && (uintptr_t) f->u.close.reason.data + payload <= (uintptr_t) p + n
               && f->u.close.reason.data == p + n - payload
               && (type == 29 || f->u.close.frame_type == v);
    }

    return 0;
}

static void
expect(unsigned property, const char *label, const u_char *bytes, size_t n,
    unsigned packet, ssize_t expected, ngx_uint_t error)
{
    u_char *p = malloc(n ? n : 1);
    ngx_quic_frame_t f; ngx_buf_t b; ngx_quic_header_t pkt;
    ssize_t rc;
    if (!p) exit(2);
    memcpy(p, bytes, n); rc = parse(p, n, packet, &f, &b, &pkt);
    record(property, label, n ? bytes[0] : 255,
           rc == expected && (rc != NGX_ERROR || pkt.error == error), p, n);
    free(p);
}

int
main(void)
{
    static const uint64_t values[] = { 0, 1, 63, 64, 16383, 16384,
        UINT64_C(1073741823), UINT64_C(1073741824),
        UINT64_C(1152921504606846976), UINT64_C(4611686018427387903) };
    static const unsigned widths[] = { 1, 2, 4, 8 };
    u_char bytes[512], *p;
    size_t n, cut, i, j; unsigned type, packet, w, k, total = 0, failed = 0;
    ngx_quic_frame_t f; ngx_buf_t b; ngx_quic_header_t pkt;
    ssize_t rc;
    uint64_t random = UINT64_C(9000);

    for (type = 0; type <= 30; type++) {
        n = frame(bytes, type, 1, 1, 5);
        for (packet = 0; packet < 4; packet++) {
            expect(PERMISSIONS, "packet-level", bytes, n, packet,
                   allowed(type, packet) ? (ssize_t) n : NGX_ERROR,
                   NGX_QUIC_ERR_PROTOCOL_VIOLATION);
        }
        if (!allowed(type, 3) || (type >= 8 && type <= 15 && !(type & 2))) continue;
        for (cut = 0; cut < n; cut++) {
            expect(TRUNCATION, "every-structured-prefix", bytes, cut, 3,
                   NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        }
    }

    for (type = 0; type < 30; type++) {
        if (!allowed(type, 3)) continue;
        for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
            if ((type == 18 || type == 19 || type == 22 || type == 23)
                && values[i] > UINT64_C(1152921504606846976)) continue;
            for (j = 0; j < 4; j++) {
                w = widths[j];
                if (values[i] >= (UINT64_C(1) << (8 * w - 2))) continue;
                n = frame(bytes, type, values[i], w, 5);
                p = malloc(n); if (!p) return 2; memcpy(p, bytes, n);
                rc = parse(p, n, 3, &f, &b, &pkt);
                record(FIELDS, "decoded-fields", type,
                       rc == (ssize_t) n && fields(&f, &b, p, n, type, values[i], w, 5), p, n);
                free(p);
            }
        }
    }

    for (type = 6; type <= 29; type++) {
        if (type != 6 && type != 10 && type != 14 && type != 28 && type != 29) continue;
        n = frame(bytes, type, 1, 8, 5);
        for (cut = 0; cut < n; cut++) {
            expect(TRUNCATION, "wide-field-prefix", bytes, cut, 3,
                   NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        }
        bytes[n] = 1;
        expect(LENGTHS, "delimited-frame-stops-before-next-ping", bytes, n + 1,
               3, (ssize_t) n, 0);
    }
    for (type = 2; type <= 16; type++) {
        if (type != 2 && type != 3 && type != 16) continue;
        n = frame(bytes, type, 1, 8, 0); bytes[n] = 1;
        expect(LENGTHS, "scalar-or-ack-stops-before-next-ping", bytes, n + 1,
               3, (ssize_t) n, 0);
    }
    for (type = 8; type <= 15; type++) {
        if (type & 2) continue;
        n = frame(bytes, type, 1, 1, 5); bytes[n++] = 1;
        p = malloc(n); if (!p) return 2; memcpy(p, bytes, n);
        rc = parse(p, n, 3, &f, &b, &pkt);
        record(LENGTHS, "no-len-stream-consumes-packet-remainder", type,
               rc == (ssize_t) n && fields(&f, &b, p, n, type, 1, 1, 6), p, n);
        free(p);
    }
    bytes[0] = 0; bytes[1] = 0; bytes[2] = 0; bytes[3] = 1;
    expect(LENGTHS, "padding-run-stops-before-ping", bytes, 4, 3, 3, 0);

    /* Payload length 2^62-1 must not narrow to a short available buffer. */
    for (type = 6; type <= 29; type++) {
        if (type != 6 && type != 10 && type != 14 && type != 28 && type != 29) continue;
        n = 1; bytes[0] = (u_char) type;
        n += integer(bytes + n, 0, 1);
        if (type == 14 || type == 28) n += integer(bytes + n, 0, 1);
        n += integer(bytes + n, UINT64_C(4611686018427387903), 8);
        expect(LENGTHS, "huge-declared-payload", bytes, n, 3, NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        for (k = 0; k <= 128; k++) {
            n = frame(bytes, type, 1, width(k), k);
            expect(LENGTHS, "exact-declared-payload", bytes, n, 3, (ssize_t) n, 0);
            if (k) expect(LENGTHS, "one-byte-short-payload", bytes, n - 1, 3,
                          NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        }
    }

    bytes[0] = 2; bytes[1] = 0; bytes[2] = 0;
    n = 3 + integer(bytes + 3, UINT64_C(4611686018427387903), 8);
    bytes[n++] = 0;
    expect(LENGTHS, "huge-range-count-short-input", bytes, n, 3,
           NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);

    /* Scalar limit is inclusive 2^60, as required by RFC 9000 section 19.11. */
    for (type = 18; type <= 23; type++) {
        if (type == 20 || type == 21) continue;
        n = frame(bytes, type, UINT64_C(1152921504606846975), 8, 0);
        expect(LIMITS, "stream-count-below-limit", bytes, n, 3, (ssize_t) n, 0);
        n = frame(bytes, type, UINT64_C(1152921504606846976), 8, 0);
        expect(LIMITS, "stream-count-at-limit", bytes, n, 3, (ssize_t) n, 0);
        n = frame(bytes, type, UINT64_C(1152921504606846977), 8, 0);
        expect(LIMITS, "stream-count-above-limit", bytes, n, 3, NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
    }
    for (k = 0; k <= 21; k++) {
        bytes[0] = 24; bytes[1] = 1; bytes[2] = 1; bytes[3] = (u_char) k;
        memset(bytes + 4, 3, k + 16); n = 4 + k + 16;
        expect(LIMITS, "cid-length", bytes, n, 3,
               k >= 1 && k <= 20 ? (ssize_t) n : NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
    }
    bytes[0] = 24; bytes[1] = 0; bytes[2] = 1; bytes[3] = 1;
    memset(bytes + 4, 3, 17);
    expect(LIMITS, "retire-exceeds-sequence", bytes, 21, 3, NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
    for (k = 31; k <= 32; k++) {
        bytes[0] = (u_char) k;
        expect(LIMITS, "first-unknown-frame-types", bytes, 1, 3,
               NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
    }
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (values[i] <= 30) continue;
        n = integer(bytes, values[i], width(values[i]));
        expect(LIMITS, "unknown-frame-type", bytes, n, 3, NGX_ERROR, NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
    }

    /* Deterministic bounded mutation corpus; sanitizer finding always fails. */
    for (i = 0; i < 4096; i++) {
        random ^= random >> 12; random ^= random << 25; random ^= random >> 27;
        n = random % 129;
        for (j = 0; j < n; j++) {
            random ^= random >> 12; random ^= random << 25; random ^= random >> 27;
            bytes[j] = (u_char) random;
        }
        if (n && i % 2 == 0) bytes[0] = (u_char) (i % 31);
        p = malloc(n ? n : 1); if (!p) return 2; memcpy(p, bytes, n);
        rc = parse(p, n, 3, &f, &b, &pkt);
        record(SEEDED, "bounded-return", n ? bytes[0] : 255,
               rc == NGX_ERROR || (rc > 0 && (size_t) rc <= n), p, n);
        free(p);
    }

    printf("{\"properties\":[");
    for (i = 0; i < NPROPERTIES; i++) {
        printf("%s{\"name\":\"%s\",\"cases\":%u,\"failed\":%u}", i ? "," : "",
               properties[i].name, properties[i].cases, properties[i].failed);
        total += properties[i].cases; failed += properties[i].failed;
    }
    printf("],\"strict\":{\"cases\":%u,\"passed\":%u,\"failed\":%u},"
           "\"inputDigestFnv1a64\":\"%016llx\",\"policyObservations\":[",
           total, total - failed, failed, (unsigned long long) input_digest);
    for (i = 1; i < 4; i++) {
        n = integer(bytes, 1, widths[i]);
        rc = parse(bytes, n, 3, &f, &b, &pkt);
        printf("%s{\"name\":\"nonminimal_ping_type_%ubytes\",\"returnCode\":%ld,"
               "\"accepted\":%s}", i == 1 ? "" : ",", widths[i], (long) rc,
               rc == (ssize_t) n ? "true" : "false");
    }
    printf("]}\n");
    return failed ? 1 : 0;
}
