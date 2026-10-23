# Native compatibility checks

`x10/test/official-tests.sh` runs a pinned sample of the official
[nginx-tests](https://github.com/nginx/nginx-tests) alongside the X10 regression
fixtures. The upstream tests are not rewritten, vendored or made easier to pass.
The exact revision, license hash, 35 selected files and their families are in
[official-tests.json](test/official-tests.json). The default checkout is
`x10/.build/nginx-tests`, outside committed code. Its upstream BSD-2-Clause
LICENSE remains present. A changed revision, dirty checkout or changed license
fails before testing.

```sh
bash x10/build.sh
bash x10/test/official-tests.sh --output x10/.build/official.json
bash x10/test/official-tests.sh \
  --binary x10/.build/baseline/nginx \
  --output x10/.build/official-reference.json
```

The second command assumes an archived upstream binary exists; the runner does
not build or manufacture that baseline. A different checkout of the exact
pinned test revision can be selected with `--tests-dir`. First use needs Git
network access; later runs reuse the verified clean checkout.

## Unified native regression profile

The required local profile uses Linux x86_64, Node.js 22+, a C compiler with
ASan/UBSan support, OpenSSL CLI and CPython 3.12 with `venv` support. Build-library
requirements remain in [BUILD.md](BUILD.md). Install the separately pinned HTTP/3
test client before invoking the aggregate; on Ubuntu 24.04 this also requires
`python3-venv`:

```sh
python3 -m venv x10/.build/http3-venv
x10/.build/http3-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-baseline.requirements.txt
x10/.build/http3-venv/bin/python -m pip check
bash x10/build.sh
node x10/test/all.mjs --official
```

The complete ten-package wheel lock targets Linux x86_64 and CPython 3.12; it
is not a universal platform lock. Installation needs package-download access,
but no test installs dependencies at runtime. `X10_HTTP3_PYTHON` can select an
absolute interpreter path in an already prepared pinned environment. A missing
client or mismatched installed version fails the required HTTP/3 group rather
than recording a passing skip. See [HTTP3.md](test/HTTP3.md) for exact client
identity, cleanup and coverage boundaries.

The default aggregate runs eleven groups; `--official` adds the twelfth.
Build/source provenance is checked before and after the groups and is not
counted as another protocol test. `--provenance-only` performs no functional
checks.

| Group | Scope |
| --- | --- |
| `http-tls-http2-reload` | Native HTTP/TLS/HTTP2 and selected reload behavior |
| `stream-mail` | Loopback TCP/UDP stream and SMTP/IMAP/POP3 |
| `mail-tls-starttls` | Implicit TLS and upgrades with trust/hostname controls |
| `protocol-adapters` | Real FastCGI/SCGI/uWSGI backend receipts |
| `http3-interop` | Seven actual UDP QUIC/TLS 1.3/H3 cases; ALPN `h3`, native protocol headers and exact responses |
| `native-features` | Selected cache, limits, files and routing behavior |
| `quic-regression` | Transport-parameter regression counterexamples |
| `quic-generated-sanitized` | Generated transport-parameter properties under ASan/UBSan |
| `quic-frame-boundaries` | 6579 generated frame-parser inputs under ASan/UBSan |
| `native-load-client-verification` | 41 short C-client functional/sanitizer controls, including native C1/C16 smoke; no performance gate |
| `managed-native-control` | 66 controller TAP passes, including bounded journal/storage interruption and recovery cases |
| `official-nginx-tests` | The pinned upstream sample; skips and TODO remain separately counted |

The saved [milestone-4 aggregate](evidence/native-checks-milestone-4.json)
reports 12/12 successful groups and controller TAP pass 66/fail 0. Group counts,
TAP assertions and generated parser inputs are different units and are not
summed into a test or feature count. The [reference parser record](evidence/quic-frames-reference.json)
and [candidate parser record](evidence/quic-frames-fixed.json) each report 6579
passing inputs. The corpus checks parsing, not ACK state arithmetic, stream flow/final-size
handlers, packet protection or a network matrix. LeakSanitizer is disabled.

HTTP/3 requires normal CA/hostname verification and certificate-specific negative
results, with observed UDP transport closure. HEAD remains explicitly unverified
because the pinned client rejected it on both binaries; the diagnostic is
retained separately. The seven cases do not cover loss/reordering, migration,
0-RTT, browser interoperability or the full QPACK/QUIC input space. The C-client
verification checks framing, exact bodies, bounds, deadlines, accounting and
cleanup; its short capped traffic is not evidence of throughput or latency
improvement. Performance comparisons run separately in a quiet measurement
window, preserving A/A controls, raw adverse results and the old Node evidence.

## What is run and counted

The sample covers HTTP location/URI/header/body parsing, ranges, gzip and
rewrite; proxy framing, retry policy, keepalive, cache and HTTP/2 upstream;
FastCGI/SCGI/uWSGI/gRPC; downstream HTTP/2 and trailers; TCP/UDP stream proxying,
half-close and balancing; mail; limits, balancing and real IP handling. A family
being selected does not mean every test in it executed. For example, FastCGI
requires the Perl FCGI module and uWSGI requires its external daemon. Missing
optional dependencies retain the official TAP skip and its reason.

JSON is written to stdout and optionally `--output`; progress goes to stderr.
Each file records its source SHA-256, runtime, exit status, timeout, TAP parse
errors, skip reasons, assertion counts and failures. Strict passes, failures,
skips, expected TODO failures and unexpected TODO passes have separate counters.
An exit error, incomplete TAP, bailout, assertion failure or timeout fails the
run. A skipped file or assertion is never counted as passed. The report also
records binary SHA-256, `nginx -V`, process mode, exact injected test globals and
whether the official checkout and binary stayed unchanged.

The default is 20 seconds per file, with an explicit 45-second allowance for
`upstream_least_time.t`: its controlled latency and decay scenario takes about
24 seconds on the inspected host. Use `--timeout N` (5..180) to override all file
limits when deliberately testing under a slower instrumented build. Tests run sequentially under a local
fixture lock. Each gets a private temporary root and process group. The runner
terminates that group's remaining children and deletes fixtures on completion;
on timeout it records a failure. SIGINT/SIGTERM interrupt the active test through
the same bounded cleanup and return nonzero JSON. The selected upstream configs
explicitly use `daemon off;`, keeping their native processes in that session.
It does not enable `TEST_NGINX_UNSAFE`, preserve
generated private keys or install optional software.

## Process mode and environment

The suite uses the native master/worker default, also selectable explicitly as
`--process-mode master`. When run as root, the current uid/gid names are selected
with a native `user` directive. This
avoids trying to chown files to an unmapped `nobody` uid in a user namespace. It
does not bypass a failed assertion. Every report exposes this configuration.

Single-process replacement is not supported: `h2.t` deliberately checks reload
and GOAWAY semantics that depend on the master process. A restricted root user
namespace may still prohibit worker group initialization; such failures must
remain failures. Selecting the current user in fixtures does not validate
privilege dropping to a different production account. The separate native HTTP
regression harness adds selected master/worker reload cases.

Only the selected upstream tests are run by this official sample. The complete
official suite, broader HTTP/3/QUIC interoperability, TLS-library/platform matrix,
fuzzing and throughput remain separate work beyond the bounded X10 groups above.
Unsafe tests are disabled. The Perl TLS helpers used by
some upstream tests have their own verification policies; these checks do not
replace the X10 harness's trusted-CA/hostname negative controls.

## Self-contained protocol fixtures

The X10 aggregate also runs [mail TLS/STARTTLS](test/MAIL-TLS.md),
[FastCGI/SCGI/uWSGI adapters](test/ADAPTERS.md) and
[actual HTTP/3](test/HTTP3.md) against the selected native
binary. These are separate local fixtures, not replacements or edits to the
pinned upstream sample. Mail and adapter servers use Node builtins; HTTP/3 uses
the pinned Python client and local asyncio backends. These fixtures do not
need the optional Perl adapter clients. An upstream dependency skip remains a
skip even when an X10 fixture checks part of that protocol.

The required profile must pass all cases in these three suites without skips.
Aggregate acceptance requires the exact suite and binary identity, unchanged
source/binary, normal case success and zero leaked sockets/processes or cleanup
errors. Mail certificate negatives must identify trust or hostname rejection.
Adapter failures must show a real parsed backend receipt before asserting the
expected 502/504 or incomplete response.

Generated config headers and module source are now checked against identities
recorded during the real build, before any suite starts and again afterward.
The controller's 66 TAP passes include real process interruption at known durable
journal boundaries, injected sync/partial-append errors and bounded recovery.
Those tests do not simulate power loss, every filesystem interleaving or failing
hardware, and do not make an all-traffic cutover guarantee. See [BUILD.md](BUILD.md), [controller boundaries](control/README.md)
and [native handover review](review/handover-boundaries.md).

## GitHub Actions

[x10-native.yml](../.github/workflows/x10-native.yml) builds the Linux profile and
runs `node x10/test/all.mjs --official`: the unified native regression entry point
plus this pinned official sample in master mode. It installs `python3-venv`, the
hashed HTTP/3 wheel lock and the optional Perl FCGI, SCGI and TLS clients, uses
read-only repository permissions and pinned action revisions, and
uploads only JSON evidence. It neither deploys a gateway nor changes billing,
secrets or native test assertions.

The workflow is configured for relevant changes on `x10-development` and
`x10-main`, relevant pull requests into those branches or `master`, and manual
dispatch. A local pass or a committed workflow is not proof that GitHub Actions
actually ran; runner access and optional daemon availability can still affect a
specific hosted run. See [STATUS.md](STATUS.md) for observed commit/run results.

## Integration and upstream mirror policy

`master` is the unmodified upstream reference. Fork-owned changes, including CI
adaptation, belong on `x10-main` and development branches. `x10-main` is the
independent integration base; `x10-development` targets it for review. Keeping
the original upstream reference does not require applying F5 publisher checks
to this independent project's pull requests.

The inherited F5 CLA workflow has a job-level repository guard on the
integration base and development head: `github.repository == 'nginx/nginx'`.
That workflow version is intended to run the F5 job only in its original
publisher's repository. Native build, compatibility, whitespace and
commit-message checks remain enabled.

The guard is not effective for the current default branch. Both
`pull_request_target` and `issue_comment` obtain their workflow from the base
repository's **default branch**, currently the pristine upstream `master`.
Retargeting a pull request to `x10-main` does not change this. See the current
[GitHub reference](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
The observed CLA run [39896918773](https://github.com/soldabania-art/nginx-x10/actions/runs/39896918773)
on development head `ebb693ea8ae0b2833550991d7e59a4ec26973da6` failed because
the inherited publisher assistant expected its remote-signature token. It is
an unresolved publisher integration, separate from native test results.

Making `x10-main` the default branch would activate the repository guard while
preserving `master` as an upstream mirror. The connected repository tools do
not expose that setting, so it has not been changed. No agreement was accepted,
CLA phrase posted, signature storage edited or publisher secret provisioned.

## Local validation on 23 October 2026

The pinned sample was run against both the archived upstream binary and the X10
candidate with native master/workers and `user root root;` in private loopback
fixtures. Both reported the same result:

| Result | Upstream | X10 |
| --- | ---: | ---: |
| Files passed | 32 | 32 |
| Entire files skipped by upstream | 3 | 3 |
| Files failed | 0 | 0 |
| Strict assertions passed | 1083 | 1083 |
| Assertions skipped | 25 | 25 |
| Expected upstream TODO failures | 1 | 1 |
| Strict assertions failed | 0 | 0 |

Each run consumed 1109 TAP assertion results; skipped files do not contribute
assertion counts. Whole-file skip reasons were missing Perl FCGI, missing Perl
SCGI and missing `uwsgi`. Unsafe/long upstream cases remained disabled. The
single expected TODO was cache `Vary` normalization of equivalent
`Accept-Encoding` token order; it was not promoted to a strict pass.

An initial exploration with single-process mode and a uniform 20-second cap
failed two files: HTTP/2 reload requires real master semantics, and the
least-time fixture's deliberate delays exceed 20 seconds. These were retained
as failed exploration results. The final native-master run and explicit
least-time allowance execute the original assertions unchanged.

A negative control forced a proxy test past a five-second cap, then sent
SIGTERM to the runner during another active proxy fixture. The timed-out test
remained failed, the runner returned nonzero interrupted JSON, all four
captured native processes belonged to their Perl test sessions, no captured
native process remained live and no temporary test root remained. This check
exposed and fixed an asynchronous-exit race: waiting for the Perl leader alone
did not prove its native children had finished after SIGKILL.

Shell/embedded-Python syntax and YAML structure were checked locally. The three
action pins were verified against official Git refs (`checkout` v6.0.2,
`setup-node` v6, `upload-artifact` v6). These local results do not certify a hosted
run or establish a performance advantage; hosted results belong to the exact
commit identified in [STATUS.md](STATUS.md) and GitHub Actions.
