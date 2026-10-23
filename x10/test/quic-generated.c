/*
 * Bounded, deterministic properties for the production QUIC TP parser.
 * RFC 9000 sections 7.4.2, 16, 18, 18.1 and 18.2 define the wire contracts.
 * Only logging is replaced; no sockets, TLS handshake or apply-time semantic
 * validation is modeled. Duplicate receiver policy is intentionally excluded.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>

#ifndef NGX_QUIC_TRANSPORT_SOURCE
#error "quic-generated.sh must select the production translation unit"
#endif
#include NGX_QUIC_TRANSPORT_SOURCE

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level;
    (void) log;
    (void) err;
    (void) fmt;
}

typedef struct {
    const char *name;
    unsigned    cases;
    unsigned    failed;
} property_t;

enum {
    NUMERIC_ENCODINGS,
    UNKNOWN_IDS,
    OPAQUE_VALUES,
    TRUNCATION,
    NUMERIC_SHAPE,
    ROLE_AND_FLAG,
    PROPERTY_COUNT
};

static property_t properties[] = {
    { "known_numeric_widths_and_nonminimal_encodings", 0, 0 },
    { "unknown_full_width_ids_preserve_destination", 0, 0 },
    { "unknown_opaque_values_are_not_interpreted", 0, 0 },
    { "truncated_id_length_or_value_is_rejected", 0, 0 },
    { "numeric_value_consumes_declared_field", 0, 0 },
    { "server_only_ids_and_zero_length_option", 0, 0 }
};

static const uint64_t numeric_ids[] = { 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14 };
static const unsigned widths[] = { 1, 2, 4, 8 };
static const uint64_t value_boundaries[] = {
    0, 1, 30, 63, 64, 16383, 16384,
    UINT64_C(1073741823), UINT64_C(1073741824),
    UINT64_C(4611686018427387903)
};

static uint64_t random_state;
static uint64_t input_digest = UINT64_C(14695981039346656037);
static unsigned printed_failures;
static unsigned property_examples[PROPERTY_COUNT];

static uint64_t
next_random(void)
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * UINT64_C(2685821657736338717);
}

static uint64_t
width_max(unsigned width)
{
    return (UINT64_C(1) << (8 * width - 2)) - 1;
}

/* Independent encoder follows RFC 9000 section 16, including nonminimal forms. */
static size_t
encode_integer(u_char *out, uint64_t value, unsigned width)
{
    unsigned i, tag;

    if ((width != 1 && width != 2 && width != 4 && width != 8)
        || value > width_max(width))
    {
        fprintf(stderr, "Fixture attempted an invalid varint width/value\n");
        exit(2);
    }
    tag = width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3;
    for (i = width; i > 0; i--) {
        out[i - 1] = (u_char) value;
        value >>= 8;
    }
    out[0] |= (u_char) (tag << 6);
    return width;
}

static size_t
parameter(u_char *out, uint64_t id, unsigned id_width,
    const u_char *value, size_t length, unsigned length_width)
{
    size_t n;

    n = encode_integer(out, id, id_width);
    n += encode_integer(out + n, length, length_width);
    if (length != 0) {
        memcpy(out + n, value, length);
    }
    return n + length;
}

static void
set_numeric(ngx_quic_tp_t *tp, uint64_t id, uint64_t value)
{
    switch (id) {
    case 1: tp->max_idle_timeout = value; break;
    case 3: tp->max_udp_payload_size = value; break;
    case 4: tp->initial_max_data = value; break;
    case 5: tp->initial_max_stream_data_bidi_local = value; break;
    case 6: tp->initial_max_stream_data_bidi_remote = value; break;
    case 7: tp->initial_max_stream_data_uni = value; break;
    case 8: tp->initial_max_streams_bidi = value; break;
    case 9: tp->initial_max_streams_uni = value; break;
    case 10: tp->ack_delay_exponent = value; break;
    case 11: tp->max_ack_delay = value; break;
    case 14: tp->active_connection_id_limit = value; break;
    }
}

static ngx_quic_tp_t
sentinel(void)
{
    size_t i;
    ngx_quic_tp_t tp;

    memset(&tp, 0, sizeof(tp));
    for (i = 0; i < sizeof(numeric_ids) / sizeof(numeric_ids[0]); i++) {
        set_numeric(&tp, numeric_ids[i], UINT64_C(700) + numeric_ids[i]);
    }
    return tp;
}

/* Compare named fields, never struct padding or borrowed string contents. */
static int
same_destination(const ngx_quic_tp_t *a, const ngx_quic_tp_t *b)
{
    return a->max_idle_timeout == b->max_idle_timeout
           && a->max_ack_delay == b->max_ack_delay
           && a->max_udp_payload_size == b->max_udp_payload_size
           && a->initial_max_data == b->initial_max_data
           && a->initial_max_stream_data_bidi_local == b->initial_max_stream_data_bidi_local
           && a->initial_max_stream_data_bidi_remote == b->initial_max_stream_data_bidi_remote
           && a->initial_max_stream_data_uni == b->initial_max_stream_data_uni
           && a->initial_max_streams_bidi == b->initial_max_streams_bidi
           && a->initial_max_streams_uni == b->initial_max_streams_uni
           && a->ack_delay_exponent == b->ack_delay_exponent
           && a->active_connection_id_limit == b->active_connection_id_limit
           && a->disable_active_migration == b->disable_active_migration
           && a->original_dcid.len == b->original_dcid.len
           && a->original_dcid.data == b->original_dcid.data
           && a->initial_scid.len == b->initial_scid.len
           && a->initial_scid.data == b->initial_scid.data
           && a->retry_scid.len == b->retry_scid.len
           && a->retry_scid.data == b->retry_scid.data
           && memcmp(a->sr_token, b->sr_token, sizeof(a->sr_token)) == 0
           && a->preferred_address == b->preferred_address;
}

static void
check(unsigned property, const char *label, const u_char *bytes, size_t length,
    ngx_int_t expected_rc, const ngx_quic_tp_t *expected_tp)
{
    size_t i;
    int match, same;
    ngx_int_t rc;
    ngx_log_t log;
    ngx_quic_tp_t tp;
    u_char *exact;

    /* Exact allocation lets ASan detect reads beyond the supplied input. */
    exact = malloc(length != 0 ? length : 1);
    if (exact == NULL) {
        fprintf(stderr, "Cannot allocate bounded parser input\n");
        exit(2);
    }
    if (length != 0) {
        memcpy(exact, bytes, length);
    }
    memset(&log, 0, sizeof(log));
    tp = sentinel();
    rc = ngx_quic_parse_transport_params(exact, exact + length, &tp, &log);
    same = expected_tp == NULL || same_destination(&tp, expected_tp);
    match = rc == expected_rc && (expected_rc != NGX_OK || same);
    properties[property].cases++;
    for (i = 0; i < length; i++) {
        input_digest ^= bytes[i];
        input_digest *= UINT64_C(1099511628211);
    }
    input_digest ^= property;
    input_digest *= UINT64_C(1099511628211);
    input_digest ^= length;
    input_digest *= UINT64_C(1099511628211);

    if (!match) {
        properties[property].failed++;
        if (printed_failures < 16 && property_examples[property] < 2) {
            property_examples[property]++;
            if (printed_failures++ != 0) {
                printf(",");
            }
            printf("{\"property\":\"%s\",\"label\":\"%s\","
                   "\"caseInProperty\":%u,\"actualReturnCode\":%ld,"
                   "\"expectedReturnCode\":%ld,\"destinationMatches\":%s,"
                   "\"inputLength\":%zu,\"bytesHex\":\"",
                   properties[property].name, label, properties[property].cases,
                   (long) rc, (long) expected_rc,
                   expected_tp == NULL ? "null" : same ? "true" : "false", length);
            for (i = 0; i < length; i++) {
                printf("%02x", bytes[i]);
            }
            printf("\"}");
        }
    }
    free(exact);
}

static void
numeric_properties(void)
{
    size_t i, j, w, iw, lw, n, length, cut;
    u_char value[16], bytes[96];
    ngx_quic_tp_t expected;

    for (i = 0; i < sizeof(numeric_ids) / sizeof(numeric_ids[0]); i++) {
        for (j = 0; j < sizeof(value_boundaries) / sizeof(value_boundaries[0]); j++) {
            for (w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
                if (value_boundaries[j] > width_max(widths[w])) {
                    continue;
                }
                length = encode_integer(value, value_boundaries[j], widths[w]);
                expected = sentinel();
                set_numeric(&expected, numeric_ids[i], value_boundaries[j]);
                for (iw = 0; iw < 4; iw++) {
                    for (lw = 0; lw < 4; lw++) {
                        n = parameter(bytes, numeric_ids[i], widths[iw], value,
                                      length, widths[lw]);
                        check(NUMERIC_ENCODINGS, "boundary_and_width", bytes, n,
                              NGX_OK, &expected);
                    }
                }
                value[length] = 0;
                value[length + 1] = 0xff;
                n = parameter(bytes, numeric_ids[i], 1, value, length + 1, 1);
                check(NUMERIC_SHAPE, "one_trailing_byte", bytes, n,
                      NGX_ERROR, NULL);
                n = parameter(bytes, numeric_ids[i], 1, value, length + 2, 2);
                check(NUMERIC_SHAPE, "two_trailing_bytes", bytes, n,
                      NGX_ERROR, NULL);
            }
        }
        n = parameter(bytes, numeric_ids[i], 1, value, 0, 1);
        check(NUMERIC_SHAPE, "empty_numeric_value", bytes, n, NGX_ERROR, NULL);
        for (w = 0; w < 4; w++) {
            length = encode_integer(value, 30, widths[w]);
            for (iw = 0; iw < 4; iw++) {
                n = parameter(bytes, numeric_ids[i], widths[iw], value, length, 8);
                /* Every nonempty proper prefix is inside a required field. */
                for (cut = 1; cut < n; cut++) {
                    check(TRUNCATION, "every_nonempty_prefix", bytes, cut,
                          NGX_ERROR, NULL);
                }
            }
        }
    }
}

static void
unknown_properties(void)
{
    static const uint64_t high_parts[] = {
        UINT64_C(65536), UINT64_C(1073741824), UINT64_C(281474976710656),
        UINT64_C(4611686018427322368)
    };
    static const uint64_t low_parts[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 27, 65535
    };
    size_t h, l, w, v, n, length;
    uint64_t id;
    u_char value[64], bytes[96];
    ngx_quic_tp_t expected = sentinel();

    for (h = 0; h < sizeof(high_parts) / sizeof(high_parts[0]); h++) {
        for (l = 0; l < sizeof(low_parts) / sizeof(low_parts[0]); l++) {
            id = high_parts[h] + low_parts[l];
            for (w = 0; w < 4; w++) {
                if (id > width_max(widths[w])) {
                    continue;
                }
                for (v = 0; v < 4; v++) {
                    /* Empty, numeric-looking, truncated-varint, arbitrary. */
                    length = v == 0 ? 0 : v == 3 ? sizeof(value) : 1;
                    memset(value, v == 1 ? 30 : v == 2 ? 0x40 : 0xff,
                           sizeof(value));
                    n = parameter(bytes, id, widths[w], value, length, 2);
                    check(UNKNOWN_IDS, "high_id_low_bits_alias", bytes, n,
                          NGX_OK, &expected);
                }
            }
        }
    }
    for (length = 0; length <= sizeof(value); length++) {
        for (v = 0; v < length; v++) {
            value[v] = (u_char) ((v * 73 + length * 29) & 255);
        }
        /* 27 is a reserved grease ID; it has no value semantics. */
        n = parameter(bytes, 27, 8, value, length, 8);
        check(OPAQUE_VALUES, "reserved_id_opaque_value", bytes, n,
              NGX_OK, &expected);
        n = encode_integer(bytes, 27, 8);
        n += encode_integer(bytes + n, length + 1, 8);
        if (length != 0) {
            memcpy(bytes + n, value, length);
        }
        check(TRUNCATION, "opaque_declared_length_beyond_input", bytes,
              n + length, NGX_ERROR, NULL);
    }
    n = encode_integer(bytes, 27, 1);
    n += encode_integer(bytes + n, width_max(8), 8);
    check(TRUNCATION, "maximum_declared_length_beyond_input", bytes, n,
          NGX_ERROR, NULL);
}

static void
role_properties(void)
{
    static const uint64_t forbidden[] = { 0, 2, 13, 16 };
    size_t i, w, n;
    u_char bytes[64], value[8] = { 0 };
    ngx_quic_tp_t expected;

    for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        for (w = 0; w < 4; w++) {
            n = parameter(bytes, forbidden[i], widths[w], value, 0, 1);
            check(ROLE_AND_FLAG, "server_only_parameter", bytes, n,
                  NGX_ERROR, NULL);
        }
    }
    for (i = 0; i < 4; i++) {
        for (w = 0; w < 4; w++) {
            n = parameter(bytes, 12, widths[i], value, 0, widths[w]);
            expected = sentinel();
            expected.disable_active_migration = 1;
            check(ROLE_AND_FLAG, "zero_length_disable_migration", bytes, n,
                  NGX_OK, &expected);
            n = parameter(bytes, 12, widths[i], value, 1, widths[w]);
            check(ROLE_AND_FLAG, "nonempty_disable_migration", bytes, n,
                  NGX_ERROR, NULL);
        }
    }
    expected = sentinel();
    check(ROLE_AND_FLAG, "empty_parameter_list", bytes, 0, NGX_OK, &expected);
}

static void
generated_properties(unsigned count)
{
    unsigned i, width, id_width, length_width;
    size_t j, length, n, cut;
    uint64_t id, value_number;
    u_char value[80], bytes[112];
    ngx_quic_tp_t expected;

    for (i = 0; i < count; i++) {
        width = widths[next_random() % 4];
        id_width = widths[next_random() % 4];
        length_width = widths[next_random() % 4];
        expected = sentinel();
        if (i % 4 == 1) {
            id = (next_random() & width_max(8)) | UINT64_C(65536);
            length = next_random() % 65;
            if (length > width_max(length_width)) {
                length_width = 2;
            }
            for (j = 0; j < length; j++) {
                value[j] = (u_char) next_random();
            }
            n = parameter(bytes, id, 8, value, length, length_width);
            check(UNKNOWN_IDS, "seeded_unknown_id_and_opaque_value", bytes, n,
                  NGX_OK, &expected);
            continue;
        }
        id = numeric_ids[next_random()
                         % (sizeof(numeric_ids) / sizeof(numeric_ids[0]))];
        value_number = next_random() & width_max(width);
        length = encode_integer(value, value_number, width);
        if (i % 4 == 0) {
            set_numeric(&expected, id, value_number);
            n = parameter(bytes, id, id_width, value, length, length_width);
            check(NUMERIC_ENCODINGS, "seeded_numeric_width", bytes, n,
                  NGX_OK, &expected);
        } else if (i % 4 == 2) {
            value[length] = (u_char) next_random();
            n = parameter(bytes, id, id_width, value, length + 1, length_width);
            check(NUMERIC_SHAPE, "seeded_numeric_trailing_byte", bytes, n,
                  NGX_ERROR, NULL);
        } else {
            n = parameter(bytes, id, id_width, value, length, length_width);
            cut = 1 + next_random() % (n - 1);
            check(TRUNCATION, "seeded_numeric_prefix", bytes, cut,
                  NGX_ERROR, NULL);
        }
    }
}

int
main(int argc, char **argv)
{
    unsigned long seed, random_cases;
    unsigned i, count = 0, failures = 0;
    char *end;

    if (argc != 3) {
        return 2;
    }
    seed = strtoul(argv[1], &end, 10);
    if (*end != '\0' || seed > UINT32_MAX) {
        return 2;
    }
    random_cases = strtoul(argv[2], &end, 10);
    if (*end != '\0' || random_cases > 10000) {
        return 2;
    }
    random_state = ((uint64_t) seed << 1) | 1;
    printf("{\"schemaVersion\":1,\"suite\":\"quic-generated-properties\","
           "\"seed\":%lu,\"randomCasesRequested\":%lu,\"failureExamples\":[",
           seed, random_cases);
    numeric_properties();
    unknown_properties();
    role_properties();
    generated_properties((unsigned) random_cases);
    printf("],\"properties\":[");
    for (i = 0; i < PROPERTY_COUNT; i++) {
        if (i != 0) {
            printf(",");
        }
        printf("{\"name\":\"%s\",\"cases\":%u,\"passed\":%u,\"failed\":%u}",
               properties[i].name, properties[i].cases,
               properties[i].cases - properties[i].failed, properties[i].failed);
        count += properties[i].cases;
        failures += properties[i].failed;
    }
    printf("],\"strict\":{\"cases\":%u,\"passed\":%u,\"failed\":%u},"
           "\"failureExamplesLimit\":16,\"failureExamplesPerPropertyLimit\":2,"
           "\"inputDigestFnv1a64\":\"%016llx\","
           "\"duplicatePolicy\":\"excluded_unchanged\",\"networkUsed\":false}"
           "\n", count, count - failures, failures,
           (unsigned long long) input_digest);
    return failures != 0;
}
