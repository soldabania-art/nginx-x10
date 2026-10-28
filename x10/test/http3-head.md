# Independent HTTP/3 HEAD interoperability

This separate fixture uses pinned **curl_cffi 0.16.3**, whose bundled libcurl
8.21.0-IMPERSONATE uses BoringSSL, ngtcp2 1.20.0 and nghttp3 1.15.0 in the
recorded wheel. It provides an independent HTTP/3 client implementation from
the aioquic client in [HTTP3.md](HTTP3.md). No browser impersonation profile,
proxy, external endpoint or dynamic fingerprint update is used.

The preserved [aioquic HEAD diagnostic](../evidence/http3-client-head-diagnostic.json)
remains unchanged and unsuccessful. This fixture does not patch aioquic or
bypass its response parser. Successful independent-client interoperability does
not establish that aioquic's HEAD behavior has changed.

## Install and run

The four-distribution hashed wheel lock targets Linux x86_64 and CPython 3.12.
It is separate from the existing aioquic environment. No test installs packages.
The Ubuntu profile also requires `python3-venv` and the OpenSSL CLI.

```sh
python3 -m venv x10/.build/http3-head-venv
x10/.build/http3-head-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-head.requirements.txt
x10/.build/http3-head-venv/bin/python -m pip check
node x10/test/http3-head.mjs
node x10/test/http3-head.mjs \
  --binary x10/.build/baseline/nginx --output x10/.build/http3-head-reference.json
```

An existing prepared interpreter can be selected with
`X10_HTTP3_HEAD_PYTHON=/absolute/venv/bin/python`. `--binary` and
`X10_NGINX_BINARY` select the native binary. It must already be built with
`--with-http_v3_module`; missing dependencies/module, mismatched versions or a
failed case return nonzero failure rather than a passing skip. Direct Python
invocation is supported using that pinned environment.

## Four checks

| Case | Acceptance |
| --- | --- |
| Verified H3 GET control | HTTP 200, 65,810 exact binary bytes represented by their length and SHA-256, Content-Length 65,810 and native GET method |
| Verified H3 HEAD | HTTP 200, the same representation Content-Length, native HEAD method and zero body bytes exposed by libcurl |
| Wrong CA | libcurl error 60, issuer-verification reason, no HTTP response/body |
| Wrong hostname | libcurl error 60, certificate-name mismatch reason, no HTTP response/body |

Each request uses a fresh Curl handle in a separately owned, bounded worker
process. `HTTP_VERSION=V3ONLY` forbids downgrade, proxies are disabled and
hostnames resolve explicitly to loopback. Success additionally requires actual
`CurlInfo.HTTP_VERSION=V3` (numeric 30), the intended loopback peer and native
`$http3=h3` / `$server_protocol=HTTP/3.0` / `$request_method` headers.
`SSL_VERIFYPEER=1`, `SSL_VERIFYHOST=2` and the generated trusted CA remain enabled;
no insecure verification mode is used. The native fixture listens only on UDP
and permits TLS 1.3. A fresh handle also avoids libcurl's documented possibility
of reusing an existing connection with a different requested protocol version.

HEAD's empty body is an **API-level observation** from libcurl's normal NOBODY
mode. It is not a raw packet-level proof that no DATA frame was sent. The GET
control checks that the nonzero Content-Length really identifies the available
representation. This scope does not establish complete HEAD or HTTP/3 wire
conformance, browser interoperability, loss/migration handling, 0-RTT, resumption,
QPACK robustness or production multiworker/reload behavior.

## Identity, bounds and cleanup

The native process runs in a private temporary prefix under the invoking UID.
Certificates and private keys are generated with OpenSSL only in that prefix
and removed at cleanup. Native readiness requires a nonempty PID file matching
the owned child and its actual UDP listener. `/proc` identities resolve the
child through NSpid, parent, UID, executable and exact PID namespace; an
ancestor-mounted `/proc` is supported. Start ticks are rechecked before the
readiness observation is accepted. This is a bounded fixture process check,
not an authentication scheme against hostile same-user processes.

Each client has a 1.5-second connection deadline, 3-second transfer deadline and
5-second process deadline. Response body/header callbacks cap accumulation at
128 KiB / 64 KiB; parent child-output capture stops at 2 MiB while streaming.
The Node launcher caps combined output and total runtime, forwards termination
to Python for cleanup and bounds escalation of its owned process group.
Python kills/reaps an interrupted request worker and gracefully quits native
NGINX, with kill fallback on cleanup failure. Progress stderr identifies actual
native startup for interruption controls without introducing a test sleep.

Each Curl handle must close all owned socket descriptors before its worker exits;
the parent reaps every request child and requires no owned sockets after native
shutdown. Standard descriptors are excluded: Node can back stdout/stderr with
Unix sockets. Source files, native binary, dependency versions/lock/client files,
harness and launcher are checked before and after. These local consistency
checks are not signed or reproducible-build attestations. The observed source
checkout is recorded separately from the selected native binary; it is not a
claim that the chosen executable was compiled from those observed bytes.

## Primary references

- [Pinned curl_cffi 0.16.3 and wheel hashes](https://pypi.org/project/curl-cffi/0.16.3/)
- [curl_cffi low-level Curl API](https://curl-cffi.readthedocs.io/en/stable/api.html)
- [curl_cffi HTTP version selection](https://curl-cffi.readthedocs.io/en/stable/advanced.html)
- [libcurl HTTP version / 3ONLY and reuse semantics](https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html)
- [libcurl actual HTTP version](https://curl.se/libcurl/c/CURLINFO_HTTP_VERSION.html)
- [libcurl NOBODY / HEAD](https://curl.se/libcurl/c/CURLOPT_NOBODY.html)
- [libcurl peer verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)
- [libcurl hostname verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)
