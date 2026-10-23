/*
 * Local regression harness for the actual NGINX QUIC transport parser.
 * Includes the selected checkout's translation unit; unused production
 * functions are removed by --gc-sections. No sockets or TLS peers are used.
 *
 * RFC 9000: sections 7.4, 7.4.2, 16, 18.1 and 18.2.
 * Unknown IDs MUST be ignored. Duplicate rejection is a SHOULD and is
 * deliberately observed separately; policy rejection is deferred. These two
 * observations do not change strict pass/fail. The other eleven cases do.
 * Integer values occupy the declared field; legal nonminimal varints remain
 * accepted. These tests establish parser results, not exploitability.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>

#ifndef NGX_QUIC_TRANSPORT_SOURCE
#error "runner.sh must select the production transport source"
#endif
#include NGX_QUIC_TRANSPORT_SOURCE

/* Production logging is irrelevant to parser output and is not linked here. */
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
    const char  *name;
    const char  *contract;
    u_char       bytes[32];
    size_t       length;
    ngx_int_t    expected_rc;
    uint64_t     expected_idle;
    ngx_flag_t   expected_disabled;
    unsigned     classification; /* 0: regression, 1: control, 2: policy */
} parser_case_t;

static const parser_case_t cases[] = {
    { "valid_idle", "valid control",
      { 0x01, 0x01, 0x1e }, 3, NGX_OK, 30, 0, 1 },
    { "valid_nonminimal_2byte_varint", "RFC16 legal nonminimal encoding",
      { 0x01, 0x02, 0x40, 0x1e }, 4, NGX_OK, 30, 0, 1 },
    { "valid_nonminimal_4byte_varint", "RFC16 legal nonminimal encoding",
      { 0x01, 0x04, 0x80, 0x00, 0x00, 0x1e }, 6,
      NGX_OK, 30, 0, 1 },
    { "valid_disable_migration", "valid zero-length control",
      { 0x0c, 0x00 }, 2, NGX_OK, 777, 1, 1 },
    { "unknown_small_id", "RFC7.4.2 MUST ignore unknown parameter",
      { 0x1b, 0x02, 0xff, 0xff }, 4, NGX_OK, 777, 0, 1 },
    { "unknown_id_65537_alias_idle", "RFC7.4.2 MUST ignore unknown parameter",
      { 0x80, 0x01, 0x00, 0x01, 0x01, 0x1e }, 6,
      NGX_OK, 777, 0, 0 },
    { "unknown_id_65548_alias_disable", "RFC7.4.2 MUST ignore unknown parameter",
      { 0x80, 0x01, 0x00, 0x0c, 0x01, 0x00 }, 6,
      NGX_OK, 777, 0, 0 },
    { "duplicate_known_idle", "RFC7.4 SHOULD reject duplicate; policy deferred",
      { 0x01, 0x01, 0x1e, 0x01, 0x01, 0x1f }, 6,
      NGX_ERROR, 0, 0, 2 },
    { "duplicate_identical_idle", "RFC7.4 SHOULD reject duplicate; policy deferred",
      { 0x01, 0x01, 0x1e, 0x01, 0x01, 0x1e }, 6,
      NGX_ERROR, 0, 0, 2 },
    { "integer_declared_length_has_trailing_byte", "RFC18.1/18.2 integer field",
      { 0x01, 0x02, 0x1e, 0x00 }, 4, NGX_ERROR, 0, 0, 0 },
    { "truncated_varint", "invalid control",
      { 0x01, 0x01, 0x40 }, 3, NGX_ERROR, 0, 0, 1 },
    { "length_beyond_input", "invalid control",
      { 0x01, 0x02, 0x1e }, 3, NGX_ERROR, 0, 0, 1 },
    { "forbidden_server_only_parameter", "invalid client parameter control",
      { 0x00, 0x00 }, 2, NGX_ERROR, 0, 0, 1 },
};

static int
print_case(const parser_case_t *test)
{
    size_t         j;
    int            match;
    ngx_int_t      rc;
    ngx_log_t      log;
    ngx_quic_tp_t  tp;

    memset(&log, 0, sizeof(log));
    memset(&tp, 0, sizeof(tp));
    tp.max_idle_timeout = 777;

    rc = ngx_quic_parse_transport_params((u_char *) test->bytes,
                (u_char *) test->bytes + test->length, &tp, &log);

    match = rc == test->expected_rc
            && (rc != NGX_OK
                || (tp.max_idle_timeout == test->expected_idle
                    && tp.disable_active_migration == test->expected_disabled));

    printf("{\"name\":\"%s\",\"contract\":\"%s\","
           "\"classification\":\"%s\",\"actual\":{\"returnCode\":%ld,"
           "\"idleTimeout\":%llu,\"disableActiveMigration\":%ld},"
           "\"expected\":{\"returnCode\":%ld,\"idleTimeout\":",
           test->name, test->contract,
           test->classification == 2 ? "policyObservation"
              : test->classification == 1 ? "control" : "regression",
           (long) rc, (unsigned long long) tp.max_idle_timeout,
           (long) tp.disable_active_migration, (long) test->expected_rc);

    if (test->expected_rc == NGX_OK) {
        printf("%llu,\"disableActiveMigration\":%ld}",
               (unsigned long long) test->expected_idle,
               (long) test->expected_disabled);
    } else {
        /* Output fields after rejection are not part of the assertion. */
        printf("null,\"disableActiveMigration\":null}");
    }

    printf(",\"matchesExpected\":%s,\"bytesHex\":\"",
           match ? "true" : "false");

    for (j = 0; j < test->length; j++) {
        printf("%02x", test->bytes[j]);
    }

    printf("\"}");
    return match;
}

int
main(void)
{
    size_t    i;
    unsigned  count = 0, failures = 0, control_failures = 0;

    printf("{\"schemaVersion\":1,\"caseCount\":%zu,\"strictResults\":[",
           sizeof(cases) / sizeof(cases[0]));

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].classification == 2) {
            continue;
        }

        if (count++) {
            printf(",");
        }

        if (!print_case(&cases[i])) {
            failures++;
            if (cases[i].classification == 1) {
                control_failures++;
            }
        }
    }

    printf("],\"strict\":{\"caseCount\":%u,\"passed\":%u,\"failed\":%u,"
           "\"controlFailures\":%u},\"policyObservations\":[",
           count, count - failures, failures, control_failures);

    count = 0;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].classification != 2) {
            continue;
        }

        if (count++) {
            printf(",");
        }

        (void) print_case(&cases[i]);
    }

    printf("],\"policyStatus\":\"Duplicate rejection is RFC9000 section7.4"
           " SHOULD; enforcement deferred, observations do not fail strict.\"}\n");

    return failures != 0;
}
