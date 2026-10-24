# Native HTTP/3 interoperability fixture

This fixture uses a real aioquic client over loopback UDP, QUIC, TLS 1.3 and
HTTP/3. There is no TCP, HTTP/2 or plaintext fallback. It checks the negotiated
`h3` ALPN together with the native `$http3` and `$server_protocol` response
headers (`h3`, `HTTP/3.0`) before accepting exact response bytes.

The client is a test dependency, separate from the C data plane. The native
binary must already exist and include `--with-http_v3_module`. The current
Linux build profile uses the upstream OpenSSL compatibility path. This is a
bounded interoperability check for that build, not a full QUIC implementation
audit or a speed comparison.

## Install the test client

The complete lock targets **Linux x86_64, CPython 3.12**, as used by Ubuntu
24.04. It pins ten distributions, including aioquic 1.3.0, with wheel SHA-256.
It is not a universal platform lock. No dependency installation happens during
a test run.

```sh
python3 -m venv x10/.build/http3-venv
x10/.build/http3-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-baseline.requirements.txt
x10/.build/http3-venv/bin/python -m pip check
```

Ubuntu may require `python3-venv`. An existing pinned environment can be selected
with `X10_HTTP3_PYTHON=/absolute/venv/bin/python`. The runner verifies all ten
installed versions against the lock and records actual client-module hashes.
The lock identifies accepted download artifacts; it is not a signed attestation
of a running environment or protection from a malicious same-user process.

Primary client references: [aioquic 1.3.0](https://pypi.org/project/aioquic/1.3.0/),
[asyncio API](https://aioquic.readthedocs.io/en/latest/asyncio.html) and the
[upstream HTTP/3 example](https://github.com/aiortc/aioquic/blob/main/examples/http3_client.py).
The fixture is its own implementation using the installed pinned API; the
examples and dependency source are not vendored into this repository.

## Run

```sh
node x10/test/http3-baseline.mjs
node x10/test/http3-baseline.mjs \
  --binary x10/.build/baseline/nginx --output x10/.build/http3-reference.json
```

`--binary` and `X10_NGINX_BINARY` select the real native executable. The Python
core also supports direct invocation from the pinned venv. Missing client
dependencies, a wrong installed version, unsupported module, invalid result or
failed case cause nonzero exit and `success:false`; they are not passing skips.
The Node launcher owns a Python/native child process group, relays cancellation,
bounds output/runtime and clears residual children if the interpreter exits
unexpectedly. Certificates and private keys are generated only in the private
temporary fixture directory and removed afterward.

## Seven case groups

| Case | Acceptance proof |
| --- | --- |
| Verified binary GET | Trusted synthetic CA, hostname `localhost`, negotiated ALPN `h3`, native protocol headers, exact 65,806-byte payload and SHA-256 |
| Byte range | Native 206, exact 4,096 bytes and `Content-Range` |
| Binary POST | DATA submitted in 4,093-byte pieces; exact echoed bytes and one real backend receipt with method, query, token, body length and SHA-256 |
| Concurrent streams | Six distinct H3 stream IDs; six exact unique backend targets observed before any response is released; all six responses match |
| Cancellation | Slow response has delivered data and a real backend receipt; an unrelated stream remains held in flight while cancellation closes the slow upstream; it then completes, and a fresh stream succeeds on the same QUIC connection |
| Wrong CA | Actual QUIC/TLS termination `0x12a` (`bad_certificate`) with issuer-verification reason and no completed handshake |
| Wrong hostname | Actual QUIC/TLS termination `0x12a` with hostname-mismatch reason and no completed handshake |

These are seven groups, not seven improved NGINX functions or seven independent
security proofs. Request/response timeouts, body/header caps and private fixture
ownership bound the run. Success requires graceful native exit zero, no fixture
or native critical errors, no live TCP writers/backend tasks, no remaining UDP
transports, unchanged source/binary/client and removal of the temporary root.
UDP closure is confirmed through each transport's `connection_lost` callback,
not merely a call to `close()`.

## HEAD diagnostic and remaining scope

The initial fixture attempted HEAD. aioquic 1.3.0's H3 response parser applies a
body-size/content-length equality check to the empty HEAD response and closes
with H3 message error. The same diagnostic occurred against both native
binaries and is preserved in
[http3-client-head-diagnostic.json](../evidence/http3-client-head-diagnostic.json).
It is not a passing test, a new NGINX defect or a fix. The final fixture tests
GET ranges and explicitly leaves HEAD interoperability unverified; it does not
patch or weaken the client parser to make the result pass.

The fixture uses one native process, synthetic HTTP/1.1 backends and QUIC retry.
It does not cover a browser, 0-RTT, resumption, client certificates, key updates,
loss/reordering/migration/NAT rebinding, QUIC version matrix, load, worker reload
or all HTTP/3/QPACK malformed inputs. Client source and local NGINX source hashes
are separate from binary identity and do not attest what compiled an executable.
