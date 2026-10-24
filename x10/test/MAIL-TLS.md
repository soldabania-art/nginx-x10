# Native mail TLS compatibility fixture

Run with the current Linux profile (Node built-ins and the `openssl` CLI):

```sh
node x10/test/mail-tls-baseline.mjs
node x10/test/mail-tls-baseline.mjs --binary x10/.build/baseline/nginx
```

`X10_NGINX_BINARY` selects a binary when `--binary` is absent. The harness emits
one JSON result and exits nonzero on any failed assertion, interruption, missing
required mail/TLS module, source/binary change, unexpected native error or cleanup
failure. It creates synthetic certificates and fixtures on loopback, retains the
invoking UID, runs one native process with `master_process off`, and removes the
private temporary prefix. No private keys are retained in evidence.

## Exercised behavior

There are 15 grouped checks, rather than 15 independently improved features:

| Cases | What is observed |
| --- | --- |
| Native config validation | Seven loopback mail listeners, required modules and actual `nginx -t` |
| SMTP/IMAP/POP3 mandatory upgrade | STARTTLS/STLS advertised; plaintext authentication refused without contacting `auth_http`; trusted TLS upgrade; pre-TLS pipelined command discarded; post-upgrade capability/auth changes; second upgrade refused; authenticated native backend tunnel |
| SMTP/IMAP/POP3 implicit TLS | Trusted CA and matching hostname, capabilities and authenticated native backend tunnel |
| SMTP/IMAP/POP3 upgrade trust rejection | An unrelated CA causes an explicit certificate-chain verification error, rather than accepting any connection failure as success |
| SMTP/IMAP/POP3 implicit hostname rejection | Correct CA plus wrong DNS hostname causes `ERR_TLS_CERT_ALTNAME_INVALID` |
| SMTP state reset | Pre-upgrade EHLO and MAIL; post-upgrade RCPT before a fresh MAIL receives 503; fresh MAIL/RCPT reaches `auth_http` with an explicitly present, empty `Auth-SMTP-Helo` and fresh sender/recipient headers |
| Fixture accounting | Exactly seven encrypted auth requests and matching native backend handshakes; no unexpected fixture failures |

The SMTP reset check uses a separate `starttls on; smtp_auth none` listener.
`AUTH PLAIN` does not emit `Auth-SMTP-Helo`, so an absent header under that method
would not prove that native STARTTLS cleared HELO state. The auth-NONE fixture
checks that the header is actually present. The reset fixture does not deliver
mail, use real accounts, or expose a public relay.

Clients always set `rejectUnauthorized: true` for the positive and negative TLS
checks. NGINX terminates TLS and reports `Auth-SSL: on`, the negotiated protocol
and cipher to the synthetic HTTP authenticator. The trusted sessions in the
recorded environment negotiated TLS 1.3. Configuration permits TLS 1.2 and TLS
1.3; this fixture does not claim a complete version/library/client matrix.

## Evidence and limits

The candidate and pristine baseline each passed 15/15 on 23 October 2026:
[candidate](../evidence/mail-tls-fixed.json) and
[baseline](../evidence/mail-tls-reference.json). Both exited normally with code 0,
and cleanup reports zero open sockets, stopped native/fixture listeners, no
command children and a removed temporary prefix. The JSON records selected
binary bytes and `-V`, harness and relevant mail-source hashes before/after,
certificate fingerprints, exact expected certificate error classes and
per-case results. These passing compatibility cases do not constitute new
production C changes or prove a performance advantage.

A separate [SIGTERM negative control](../evidence/mail-tls-runner-verification.json)
interrupted the harness after observing the actual native PID file. It exited
1 with `passed: false`; cleanup stopped the
native process and fixture listeners, left zero sockets and command children,
and removed the prefix. An interruption is never counted as a passing suite.

Pipelining coverage sends the upgrade and one extra plaintext command in a
single write. It does not cover every TCP fragmentation or malicious-client
schedule. Client certificates, TLS resumption, upstream TLS, multiple TLS
libraries, delivery, full protocol grammar, multiworker operation and load are
outside this fixture. Expected certificate-verification abort/close messages at
native info level are counted separately from unexpected error/critical logs.
