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

Only the selected upstream tests are run. The complete official test suite,
HTTP/3/QUIC interoperability, TLS-library/platform matrix, fuzzing and throughput
remain separate work. Unsafe tests are disabled. The Perl TLS helpers used by
some upstream tests have their own verification policies; these checks do not
replace the X10 harness's trusted-CA/hostname negative controls.

## GitHub Actions

[x10-native.yml](../.github/workflows/x10-native.yml) builds the Linux profile and
runs `node x10/test/all.mjs --official`: the unified native regression entry point
plus this pinned official sample in master mode. It installs the optional Perl
FCGI, SCGI and TLS clients, uses read-only repository permissions and pinned action revisions, and
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
