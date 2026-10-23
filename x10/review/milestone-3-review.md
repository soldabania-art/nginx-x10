# Milestone 3 independent review

Review date: 23 October 2026. This report records independent inspection and
targeted checks for the new native protocol fixtures and their aggregate-runner
integration. It is not a production approval, a full protocol-security audit, or
evidence of a performance advantage.

## Review boundary

The reviewer owns only this report. Implementation files and evidence remain
owned by their respective authors. Review begins from development commit
`29746068bfca299b85062e981df250aa3e12abb8`.

Native contracts read before reviewing the fixtures:

- `src/mail/ngx_mail_handler.c`: TLS initialization and post-STARTTLS protocol
  reentry.
- `src/mail/ngx_mail_smtp_handler.c`: clearing SMTP HELO/envelope and pending
  plaintext bytes on STARTTLS.
- `src/mail/ngx_mail_imap_handler.c` and `src/mail/ngx_mail_pop3_handler.c`:
  upgrade eligibility and pending plaintext buffer reset.
- `src/http/modules/ngx_http_fastcgi_module.c`: request parameter-length
  encoding, record types, request ID, content length and padding.
- `src/http/modules/ngx_http_scgi_module.c`: request netstring framing and first
  `CONTENT_LENGTH` entry.
- `src/http/modules/ngx_http_uwsgi_module.c`: modifiers, little-endian packet
  length and key/value lengths.

## Review gates

The pending fixture review checks actual native binary/source identities,
nonempty passing case sets, exact bytes and framing, intended failure classes,
bounded socket/child lifetime, and truthful separation of skips from passes.
TLS positive cases must use normal CA/hostname verification. Negative cases
must observe certificate-validation errors rather than accept arbitrary I/O
failure as proof. Adapter malformed-response cases must show that the backend
actually received and parsed the intended request before the expected failure.

The aggregate runner must require the new suites' identity and cleanup fields,
and retain its pre/post build/source checks. An exit-zero process or an empty
case array is insufficient evidence.

## Findings resolved before freeze

1. The draft mail fixture reported its selected binary path and unchanged flag
   only at top level, while the aggregate validator required those fields in
   `identity`. The final fixture supplies both required identity fields.
2. A stopped native process alone could hide a crash during mail-fixture
   cleanup. Positive mail success now requires native exit code zero and no
   terminating signal, in addition to empty error/socket/child accounting.
3. The initial SMTP reset proof inferred an empty HELO from a missing
   `Auth-SMTP-Helo` header under AUTH PLAIN. The mail author caught this false
   inference. The final case uses a separate auth-NONE listener, requires the
   actual header to be present and empty, rejects a stale post-upgrade RCPT
   before fresh MAIL, and verifies the fresh envelope reaching the backend.
4. The adapter fixture previously swallowed failure to read the native error
   log, allowing unavailable diagnostics to look clean. A successfully spawned
   native run now requires the log to have been read; failure records a cleanup
   error. Prefix removal is checked by `stat(prefix)`, not by the absence of one
   file within it.

These were fixture/reporting issues. They are not newly discovered NGINX
production defects. No production C change was made for these new fixtures.

## Inspected protocol assertions

The mail fixture verifies SMTP STARTTLS, IMAP STARTTLS and POP3 STLS with
`starttls only`, refusal of plaintext authentication without contacting
`auth_http`, capability changes, refusal of a second upgrade, and authenticated
backend tunnels. Each upgrade case sends a second command in the same
plaintext write and confirms that it does not authenticate after the upgrade.
Implicit TLS is also tested for each protocol. Positive TLS connections use
`rejectUnauthorized: true`, a generated trusted CA and the certificate's
hostname. Wrong-CA and wrong-hostname cases require certificate-specific error
codes; arbitrary connection failure cannot satisfy them. The separate SMTP
reset case observes the actual auth-NONE metadata described above.

The adapter fixture parses the native wire request before responding and
requires exactly one recorded receipt for every success and failure case.
FastCGI checks role, request ID, record order, zero request padding, terminal
PARAMS/STDIN and long parameter encoding. SCGI checks netstring boundaries and
the first `CONTENT_LENGTH` parameter. uWSGI checks modifiers and little-endian
packet/key/value lengths. All three verify query/header metadata, exact binary
POST bytes across a 70 KiB body, decoded chunked input, fragmented responses,
invalid/truncated headers, incomplete bodies and a bounded pre-header timeout.
The malformed-response cases cannot pass merely because the synthetic request
parser raised an exception: a fully validated receipt and empty fixture-error
accounting are required.

The final owner-executed evidence was independently read and its code/source
hashes checked against the files:

| Fixture | Candidate | Pristine baseline | Cleanup |
| --- | --- | --- | --- |
| Mail TLS | 15/15, no skips | 15/15, no skips | Exit 0, zero sockets/command children/errors, prefix removed |
| Protocol adapters | 21/21, no skips | 21/21, no skips | SIGQUIT, exit 0, zero sockets/errors, prefix removed |

The candidate fixture runs identify binary SHA-256
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`;
the pristine baseline runs identify
`adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e`.
These are the binaries used by the recorded runs, before the subsequent
canonical rebuild. Local module-source hashes are recorded separately from
binary identity; they do not attest which files compiled an executable.

## Independent executed controls

[Protocol runner verification](../evidence/protocol-runner-verification.json)
contains two different kinds of checks, explicitly separated:

- Twenty direct negative controls evaluate the real `jsonChecks` function from
  the final aggregate source. For each new suite they reject the wrong suite,
  empty or failed cases, a skip, missing binary hash, changed binary/source,
  a live native process/socket and a cleanup error. Two valid synthetic records
  are accepted. These are direct validator checks, not end-to-end aggregate CLI
  runs, and do not exercise its separate binary-path comparison.
- Two actual adapter CLI controls reject `/bin/true` as an unusable native
  executable and handle SIGTERM after an actual native PID file appears. Both
  exit one with `success: false`. The interruption leaves no native PID, open
  socket or temporary prefix. Its approximately 4.16 second completion is
  within the aggregate runner's 6.5 second child-cleanup grace. The readiness
  retry loop remains bounded to four seconds even after interruption.

The separate owner-executed
[mail interruption control](../evidence/mail-tls-runner-verification.json)
was inspected: native startup was observed, SIGTERM produced exit one and
`passed: false`, all fixture/native resources stopped, and no sockets,
command children, temporary root or cleanup errors remained.

## Aggregate and build identity review

The aggregate adds both new suites to its functional run and requires exact
suite names, nonempty all-pass case sets, no skips, the selected binary path
and hash, unchanged binary/source flags and complete cleanup. It retains
pre/post native source, manifest and binary checks. The direct controls above
were rerun after the generated-input enforcement was added.

The generated-input writer and checker changes were also read. The writer
records verified regular-file SHA-256, size and mode for
`ngx_auto_config.h`, `ngx_auto_headers.h` and `ngx_modules.c`, parses the module
catalog from those bytes, and checks file identity again before publishing.
The checker requires those records before suites and compares the complete
observed map afterward. Its permission mask includes special bits (`07777`),
matching Python `stat.S_IMODE`; a same-byte `4644` change is rejected. A
historical manifest without those records is
rejected and requires a real rebuild.

[Build identity verification](../evidence/build-identity-verification.json)
records the reproduced old-checker acceptance gap separately from sixteen
actual new CLI/writer controls. Those owner-executed controls were inspected;
the reviewer did not rerun or relabel them as independent executions. They
used isolated copies and started no native fixture processes. This is local
build-record consistency, not a signed or reproducible-build attestation or
protection from a malicious same-user process able to rewrite both files and
manifest.

## Frozen code identities

| File | SHA-256 |
| --- | --- |
| `x10/test/all.mjs` | `69a00ef5b24c04454a11e7ec038401adcbb9d276672a1ba20f4135ac02403714` |
| `x10/test/mail-tls-baseline.mjs` | `c5662a3941090d75ca371c45c157236c53757d90708ab2de13add25cf58550fd` |
| `x10/test/adapters-baseline.mjs` | `4e4f9599788c98ec1a4eb112b56363822539fc91a6990d5ded0efca1bb856f63` |
| `x10/build.sh` | `8f4bcb4c91224a07fe2f15376d4f9a4b772dc7e81a9c97c72a7d67c17712b51f` |

## Remaining boundaries

No unresolved blocker was found in the reviewed protocol fixtures or aggregate
integration at these hashes. A full aggregate pass after the real canonical
rebuild is a separate acceptance gate; this report does not manufacture such a
result from owner evidence or direct validator checks.

The fixtures cover one local Linux/OpenSSL build with synthetic clients,
authentication and application backends. They do not prove real mailbox or
application-runtime interoperability, TLS resumption/client certificates, all
TCP fragmentation patterns, unbuffered request backpressure, adapter caching,
keepalive pools, retries or multiplexing. Matching baseline and candidate
results establish preservation for these cases, not a new adapter/TLS fix or
speed improvement. Controller reconciliation and native handover are outside
this review; see [handover boundaries](handover-boundaries.md) and the separate
controller evidence.
