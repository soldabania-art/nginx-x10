# Native compatibility checks

The Guard experiment has a separate required hosted TAP step after the normal
20-group aggregate. Its eight tests cover only generated native tenant/cache
scenarios, ineffective fixes and interruption cleanup; they are not AI results.
The local milestone-8 aggregate is [summarized here](evidence/native-checks-milestone-8.json).
The prior milestone-7 hosted run failed one negative alpha fixture; it did not
reach the Unix or package gates. The corrected fixture uses an owned native
copy at a different path and requires the manifest-identity rejection.

Milestone-6 and later files committed under `x10/evidence` are explicit public summaries,
not raw runner records. They retain result names/counts and source/binary
hashes; host paths, runtime process/namespace identities, raw configurations,
certificate metadata and logs are omitted. Each summary records the hash of
the complete local record. Validators operate on fresh, complete suite output;
the publication summaries are not validator inputs.

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
requirements remain in [BUILD.md](BUILD.md). Install both separately pinned HTTP/3
test clients before invoking the aggregate; on Ubuntu 24.04 this also requires
`python3-venv`:

```sh
python3 -m venv x10/.build/http3-venv
x10/.build/http3-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-baseline.requirements.txt
x10/.build/http3-venv/bin/python -m pip check
python3 -m venv x10/.build/http3-head-venv
x10/.build/http3-head-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-head.requirements.txt
x10/.build/http3-head-venv/bin/python -m pip check
bash x10/build.sh
node x10/test/all.mjs --official
```

The ten-package aioquic lock and separate four-package curl_cffi 0.16.3 lock
target Linux x86_64 and CPython 3.12; neither is a universal platform lock.
Installation needs package-download access, but no test installs dependencies at
runtime. `X10_HTTP3_PYTHON` can select an
absolute interpreter path for the aioquic environment; `X10_HTTP3_HEAD_PYTHON`
selects the separate prepared curl_cffi environment. A missing client or
mismatched installed version fails its required group rather than recording a
passing skip. See [HTTP3.md](test/HTTP3.md) and [http3-head.md](test/http3-head.md)
for exact identities, cleanup and coverage boundaries.

The current default aggregate runs nineteen groups; `--official` adds the twentieth.
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
| `http3-head-independent-client` | Four independent libcurl client cases: verified GET/HEAD and certificate-specific CA/hostname rejection; mandatory HTTP/3 |
| `native-features` | Selected cache, limits, files and routing behavior |
| `quic-regression` | Transport-parameter regression counterexamples |
| `quic-generated-sanitized` | Generated transport-parameter properties under ASan/UBSan |
| `quic-frame-boundaries` | 6579 generated frame-parser inputs under ASan/UBSan |
| `native-load-client-verification` | 41 short C-client functional/sanitizer controls, including native C1/C16 smoke; no performance gate |
| `managed-native-control` | Controller transactions, bounded journal/storage interruption and recovery, plus explicit listener snapshot/inspection CLI cases |
| `operator-status` | Human status, explicit generation queries tied to the bound native master and refusal of unverified endpoints |
| `local-alpha-lifecycle` | Private installation, native run/bind/apply/revert/stop, restart with retained session history and guarded removal |
| `listener-observer-boundaries` | Separate observer identity, namespace, snapshot-integrity, descriptor-race, I/O and resource-bound checks |
| `reload-listener-observation` | Seven live native case groups separating new responses, captured old-listener closure and accepted-stream completion |
| `native-control-api` | Nine existing optional control-API compatibility groups on explicit ephemeral IPv4 loopback |
| `native-process-generations` | Ten candidate groups for accepted/rejected HUP/PATCH, old drain and real worker respawn |
| `native-generation-boundaries` | Twenty production-TU assertions with ASan/UBSan, including uint64 formatting and exhaustion |
| `official-nginx-tests` | The pinned upstream sample; skips and TODO remain separately counted |

The saved [milestone-4 aggregate](evidence/native-checks-milestone-4.json)
reports the earlier twelve-group profile: 12/12 successful groups and controller
TAP pass 66/fail 0. The preceding [milestone-5 aggregate](evidence/native-checks-milestone-5.json)
passed 15/15 groups, with controller TAP 68/68 and separate observer TAP 29/29,
after the independent HEAD cancellation fix. The new [milestone-6 aggregate](evidence/native-checks-milestone-6.json)
passed 18/18 groups on the rebuilt native generation implementation. The current
milestone-7 profile adds operator-status and local-alpha-lifecycle; its final
[local aggregate](evidence/native-checks-milestone-7.json) passed 20/20, exit 0:
operator-status 30/30 TAP, alpha lifecycle 9/9, controller 68/68 and observer
29/29. Official results remain 1083 strict passes, 25 skips, one expected TODO
and no strict failures. Native C and the binary SHA are unchanged from
milestone 6. Hosted results belong to their
exact commit and are checked separately. See [STATUS.md](STATUS.md). Group counts,
TAP assertions and generated parser inputs are different units and are not
summed into a test or feature count. The [reference parser record](evidence/quic-frames-reference.json)
and [candidate parser record](evidence/quic-frames-fixed.json) each report 6579
passing inputs. The corpus checks parsing, not ACK state arithmetic, stream flow/final-size
handlers, packet protection or a network matrix. LeakSanitizer is disabled.

HTTP/3 requires normal CA/hostname verification and certificate-specific negative
results, with observed UDP transport closure. The original aioquic HEAD
diagnostic remains unchanged: that pinned client rejected HEAD on both native
binaries. The separate curl_cffi/libcurl fixture requires `V3ONLY`, reports
actual HTTP version 30 and native H3/protocol/method headers, and checks a
byte-exact GET representation, HEAD status/headers with an empty API-visible
body, plus CA/hostname-specific failures. The saved
[candidate](evidence/http3-head-fixed.json) and
[reference](evidence/http3-head-reference.json) reports contain four passing cases
each; these standalone runs are separate from the current full aggregate. The
fixture does not claim packet-level absence of HEAD DATA frames. The seven aioquic cases do not cover loss/reordering,
migration,
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
[actual HTTP/3](test/HTTP3.md), plus an
[independent HTTP/3 HEAD client](test/http3-head.md), against the selected native
binary. These are separate local fixtures, not replacements or edits to the
pinned upstream sample. Mail and adapter servers use Node builtins; HTTP/3 uses
the pinned aioquic Python client and local asyncio backends. The independent
HEAD fixture uses separately pinned curl_cffi/libcurl, not an aioquic parser
patch. These fixtures do not need the optional Perl adapter clients. An upstream dependency skip remains a
skip even when an X10 fixture checks part of that protocol.

The required profile must pass all cases in these protocol suites without skips.
Aggregate acceptance requires the exact suite and binary identity, unchanged
source/binary, normal case success and zero leaked sockets/processes or cleanup
errors. Mail certificate negatives must identify trust or hostname rejection.
Adapter failures must show a real parsed backend receipt before asserting the
expected 502/504 or incomplete response.

Generated config headers and module source are now checked against identities
recorded during the real build, before any suite starts and again afterward.
The controller fixture includes real process interruption at known durable
journal boundaries, injected sync/partial-append errors and bounded recovery.
Milestone 4 recorded 66 TAP passes; the current file records 68, including the
explicit listener diagnostics through the CLI.
Those tests do not simulate power loss, every filesystem interleaving or failing
hardware, and do not make an all-traffic cutover guarantee. See [BUILD.md](BUILD.md), [controller boundaries](control/README.md)
and [native handover review](review/handover-boundaries.md).

## Reload and captured listener diagnostics

The [live reload fixture](test/HANDOVER.md) holds an actual old-generation
response open, stops only its identified native worker, and observes a fresh
new-revision response while that worker still owns the TCP LISTEN descriptor.
After SIGCONT, it requires listener absence while the worker and accepted
response remain live, a second reload, exact stream completion and rejection of
an invalid reload. Both the fixture's own fd/inode checks and the observer's
captured-process report are recorded. Every cleanup path resumes stopped owned
processes before bounded native shutdown; interruption remains failure.

The optional [manual observer](control/LISTENERS.md) is exposed by
`snapshot-listeners` and `inspect-listeners`. It uses the controller lock,
bound-master identity and file guards, but changes no apply/recover acceptance
and sends no signal. Inspection returns `ok:true` for a completed observation;
`observation.state` separately indicates `pending` or `closed`. Unavailable or
changed identity is unresolved, never a closed result. This observes only the
captured process set; it is not a native generation API, proof about unseen
respawns or later children, application health, complete accepted-connection
drain, or an all-traffic atomic cutover.

The observer supports a single matching IPv4 loopback TCP listener inode and
explicit PID/network namespace checks. It refuses ambiguous endpoints,
inaccessible procfs data, invalid snapshots and exceeded resource/elapsed
budgets. A single inode cannot prove that every possible reuseport configuration
is absent. Node filesystem calls cannot cancel a stalled kernel/procfs operation;
the elapsed budget must not be described as a hard wall-clock guarantee under
such a stall. The separate boundary tests and live fixture do not cover the full
platform, QUIC/UDP or process-churn matrix.

## Operator status and isolated Linux alpha

`operator-status` runs the existing JSON status and the new human presentation,
then queries native generations through an explicitly selected endpoint. The
inspector requires the bound master's OS lifetime, PID/network namespaces and
LISTEN inode ownership before and after its fixed GET. Native `master_pid` is
compared with the local PID from `NSpid`; procfs paths use the distinct proc PID.
HTTP has an absolute request deadline, header/body caps and strict schema and
uint64-string checks. Foreign endpoints, changed ownership, contradictory
metadata and incomplete responses fail closed. Successfully received
`native.available:false` retains its reason and null identities; `ok:true` is a
completed diagnostic, not readiness. Human status preserves the old JSON/exit
semantics, including observed unbound or stale runtime, and explicitly says
health and listener drain were not checked.

`local-alpha-lifecycle` exercises installation into a new private prefix and
the installed foreground launcher, bind, change/revert, stop, session restart,
preserved prior history and guarded removal. Packaging uses a verified build
manifest and copies the native binary, controllers, examples and licenses. A
new run creates a fresh controller session seeded from verified confirmed
content; it never silently rebinds the old controller. The default launch omits
the native control API and clears inherited `NGINX_CTRL`. Optional API launch
accepts only an explicit Unix socket directly inside the private installation.
The native demo self-check is not application health. A faulted lifecycle,
unverified process, changed files or unknown installation content requires
operator inspection rather than automatic deletion or restart.

The package still requires Linux, Node.js 22+ and compatible dynamic libraries.
It is not a universal static binary, service manager or full upgrade/crash
matrix. The local aggregate and package lifecycle passed. The
[independent review](review/local-alpha-review.md) records nine operator and
eight package controls on the frozen files. A new hosted run, including the
required Unix gates, is pending. See [QUICKSTART.md](QUICKSTART.md) and
[alpha/README.md](alpha/README.md).

## Native generation feature gates

The native [generation endpoint](test/GENERATIONS.md) adds master-scoped
configuration/birth identities to the explicitly enabled control API. It
preserves the existing process/cycle layouts and legacy process fields. Numbers
are decimal strings; readiness, listener closure and global uniqueness across
master lifetimes are outside this contract.

The required local aggregate uses explicit ephemeral `127.0.0.1` TCP fixtures.
The test transport never falls back automatically. Local AF_UNIX creation is
refused by the execution kernel; that unsuccessful observation is retained in
[control-api-unix-unavailable.json](evidence/control-api-unix-unavailable.json).
It is not counted as a Unix PASS. The hosted workflow separately requires:

```sh
node x10/test/control-api-baseline.mjs --transport unix
node x10/test/generations.mjs --transport unix
X10_STATUS_TRANSPORT=unix node --test --test-reporter=tap x10/test/operator-status.test.mjs
bash x10/test/control-disabled.sh --output x10/.build/control-disabled.json
```

The last check serially rebuilds the same Linux module profile without control
API support in a separate object directory. It verifies the macro/object are
absent and `-l` is rejected, and preserves the default build inputs/binary and
root Makefile. No configure jobs may overlap. Its result is separate from the
aggregate. The Unix operator gate is required separately; there is no automatic
TCP fallback or passing skip. This is a Linux feature-off build, not a full OS or dynamic
module ABI certification. See [build evidence](evidence/control-disabled-build.json).

## GitHub Actions

[x10-native.yml](../.github/workflows/x10-native.yml) builds the Linux profile and
runs `node x10/test/all.mjs --official`: the unified native regression entry point
plus this pinned official sample in master mode. It installs `python3-venv`, the
hashed aioquic and independent curl_cffi HTTP/3 wheel locks in separate venvs,
and the optional Perl FCGI, SCGI and TLS clients, uses
read-only repository permissions and pinned action revisions, and
uploads JSON/TAP evidence. After the required checks, it packages a local Linux
alpha with:

```sh
node x10/alpha/cli.mjs pack --output x10/.build/dist/nginx-x10-linux-alpha.tar.gz
```

The successful `nginx-x10-linux-alpha` artifact contains the `.tar.gz` and a
SHA-256 checksum sidecar. Packaging metadata is retained as JSON in the separate
`x10-native-evidence` artifact. The extracted `nginx-x10-alpha/` bundle installs
with `node install.mjs install --prefix NEW_ABSOLUTE --port 8088 --health-port 8089`
without the source checkout or a compiler; its dynamic runtime requirements
remain. Artifacts are development snapshots, not signed releases or claims of
cross-machine ABI compatibility. The workflow neither deploys a gateway nor
changes billing, secrets or native test assertions.

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
