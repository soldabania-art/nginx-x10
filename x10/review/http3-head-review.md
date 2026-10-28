# Independent HTTP/3 HEAD fixture review

Reviewed on 23 October 2026 against the frozen identities below. No unresolved
blocker remains in this scoped fixture after the fixes and independent controls
described here. This review covers a separate libcurl/ngtcp2 client; the existing
aioquic fixture and its unsuccessful HEAD diagnostic remain unchanged.

## What this establishes

The new fixture uses a fresh Curl handle in a separate short-lived process for
each request, `HTTP_VERSION=V3ONLY`, explicit loopback hostname resolution and
disabled proxies. It requires actual `CurlInfo.HTTP_VERSION=30`, native
`$http3=h3`, `$server_protocol=HTTP/3.0` and the actual native request method.
Certificate-chain verification, hostname verification and the generated custom
CA remain enabled. The native listener uses UDP/QUIC and TLS 1.3 only.

The four cases are a 65,810-byte binary GET, HEAD for the same representation,
wrong CA and wrong hostname. Both positive cases require status 200, the expected
nonzero Content-Length and their respective native GET/HEAD method. GET checks
length and SHA-256 of the full expected body. HEAD checks the zero bytes exposed
by libcurl's normal NOBODY mode. This is independent-client interoperability,
**not a raw packet-level proof that no DATA frame was sent**.

Certificate negatives require libcurl error 60 with issuer- or hostname-specific
reason, no HTTP status and no response body; arbitrary connection failure does
not pass. Fresh handles avoid the documented possibility of reusing a connection
with a different requested protocol version. Actual version and native headers
are checked in addition to the requested mode.

The owner retained four passing cases on each native binary. The reviewer
independently reran all four candidate cases successfully. The pristine result
was inspected, not independently rerun by this review. The native source checkout
observed by the fixture is recorded separately from the selected executable;
these local hashes do not attest which source built an arbitrary binary.

## Findings resolved during review

1. `nginx -t` creates an empty PID file. The draft existence-only readiness test
   could accept that file before the real process became ready. The final code
   requires its nonempty content to equal the owned subprocess PID, live native
   identity and ownership of the expected UDP listener inode.
2. The first readiness fix addressed `/proc/<local-pid>` directly. This workspace
   mounts `/proc` from an ancestor PID namespace, so those numbers differ. The
   owner now resolves exact NSpid, parent `/proc` PID, UID, executable and PID
   namespace, records start ticks and rechecks identity around UDP ownership.
   The independent final run records different local and `/proc` PIDs and passes
   with the resolved identity; it does not assume those numbers coincide.
3. Draft `communicate()` buffered subprocess output before checking its cap.
   Final capture uses selector-driven incremental reads with a 2 MiB cap and a
   monotonic deadline, killing and reaping the owned child on failure. Independent
   controls exceed the output cap and a short deadline, then verify child exit
   and the cleared active-child reference.
4. The draft SIGTERM handler raised `InterruptedError`. Python's selector catches
   that exception as its own interrupted-system-call condition. The initial
   reviewer control observed non-success and clean exit, but its raw trace showed
   all four requests continued. That earlier trace is preserved as
   `priorInterruptionDiagnostic` in the review JSON, explicitly outside final
   prompt-cancellation acceptance. The owner replaced it with
   `FixtureInterrupted(RuntimeError)` and explicit interruption checks at command
   start, selector-loop and case boundaries. The final independent SIGTERM run
   stops in the first GET case: one failed case, zero passed cases, zero completed
   client results, `FixtureInterrupted` and nonzero launcher exit. Native exits
   through SIGQUIT with code zero, the owned group is gone and the prefix removed.

The interrupted request process is killed/reaped; its Curl handle cannot report
normal close completion. Accordingly that failed report has
`clientSocketsClosed:false`, while actual remaining owned sockets are zero and
the owned process group is gone. This failed operation is not accepted by the
positive aggregate schema. Completed positive requests each report zero owned
sockets after Curl close.

The implementation owner made these fixes. The reviewer edited only review
artifacts and isolated review scripts, not the fixture or native source.

## Independently executed controls

[Raw review controls](../evidence/http3-head-review-controls.json) distinguish
actual CLI executions, direct subprocess-helper calls and direct validator calls.
They do not claim that direct calls ran the full aggregate CLI.

| Control | Result | Scope |
| --- | --- | --- |
| Missing interpreter and executable non-interpreter | 2/2 | Real Node launcher, nonzero exit and failed JSON |
| Unusable native binary | 1/1 | Real launcher rejects before native fixture startup |
| Candidate protocol CLI | 4/4 protocol cases in one control | Actual verified H3 GET, HEAD and both certificate negatives |
| SIGTERM after real native UDP startup | 1/1 | Workflow stops in first case; native/group/prefix cleaned |
| Child output cap and deadline | 2/2 | Exact `command()` helper with real owned subprocesses; killed/reaped |
| Aggregate `jsonChecks` | 35/35 | Two owner records accepted and 33 mutated schema records rejected |
| Aggregate H3 HEAD identity guard | 4/4 | Exact extracted block, actual filesystem hashes; matching identity accepted, wrong lock/harness/launcher hashes rejected |
| Dependency inspection | Pass | Four downloaded wheel hashes, installed versions and independent `pip check` |

The first five rows are seven top-level review controls; the candidate control
contains four protocol cases. Those units are not summed as interchangeable
tests. Direct schema mutations cover fallback-capable mode, actual protocol,
client identity, source changes, interrupted results, incomplete cases, skips,
native/fixture errors and cleanup failures. The final all.mjs source/function
hashes and raw mutations are recorded in JSON.

All four downloaded wheel byte hashes match the separate lock and dependency
report; installed versions match and `pip check` succeeds. The original aioquic
HEAD diagnostic remains byte-for-byte equal to Git HEAD, SHA-256
`0816788574ff44ca357b877da549d558e2ee429a744c7ce19b973dd79a7b445a`.
It remains unsuccessful. The new result neither patches aioquic nor establishes
that its HEAD behavior changed or that its diagnostic was a native NGINX defect.

## Limits and identity

This is a Linux x86_64/CPython 3.12 loopback fixture. It does not cover packet-level
HEAD conformance, browsers, loss/reordering, migration, QPACK robustness, 0-RTT,
resumption, multiworker reload or a platform/TLS matrix. No throughput advantage
or production certification follows. Process interruption and cleanup do not
simulate kernel hangs or power loss. Standard descriptors 0–2 are excluded from
owned-socket accounting because Node may supply socket-backed standard streams.

Harness, launcher, native source/binary, lock, selected client files and dependency
versions are checked before and after a run. The four-wheel hash profile and
local installed-file checks are consistency evidence, not a signed dependency
audit. All reviewer fixtures are stopped; this review runs no sustained load.

| Frozen file | SHA-256 |
| --- | --- |
| `x10/test/http3-head.py` | `e9e7316b016d095ae7fc44fa61348e9927a82f3d7ff1d71eef11e91cc6486b6a` |
| `x10/test/http3-head.mjs` | `e0cc8c4441e2bd7ff0b7b3fc6ff085baa3b72ee479712019a2fd4da81dcac409` |
| `x10/test/http3-head.requirements.txt` | `3ccf1913a2c5cca06e8d1af2660c08d7447943f10839777d038bd4df63ad5b0f` |
| `x10/test/all.mjs` | `dab3514773962ece7c14550718a81e5b35956650533edc7ca61ae25656b371fd` |
| `x10/evidence/http3-head-review-controls.json` | `616964276c22fe373e811ca11ce5d021d2bed81b652fe8df3b23fc77d236c9fa` |

The candidate binary recorded by the independent CLI is
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`.
The inspected pristine evidence records
`adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e`.
Changed reviewed implementation bytes require an affected review update.

## Primary references consulted

- [libcurl version selection, 3ONLY and connection reuse](https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html)
- [Actual transfer HTTP version](https://curl.se/libcurl/c/CURLINFO_HTTP_VERSION.html)
- [NOBODY and HEAD API behavior](https://curl.se/libcurl/c/CURLOPT_NOBODY.html)
- [Peer verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)
- [Hostname verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)
- [curl_cffi low-level implementation](https://curl-cffi.readthedocs.io/en/latest/_modules/curl_cffi/curl.html)

The selector cancellation finding was checked in the installed Python standard
library's `selectors.EpollSelector.select` and against the retained runtime trace.
