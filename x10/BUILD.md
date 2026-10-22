# Native Linux build

Run from any directory:

```sh
./x10/build.sh
./x10/build.sh --jobs 4
./x10/build.sh --configure-only
```

Requirements: Linux, Bash, a C compiler available as `cc`, GNU make, Python 3,
Git, and the usual upstream configure utilities. Install the development headers
and libraries for PCRE2, OpenSSL, zlib and libcrypt using your system's package
manager. The script does not install dependencies or require root. For example,
Ubuntu 24.04 packages are `build-essential python3 git libpcre2-dev libssl-dev
zlib1g-dev libcrypt-dev`; `pkg-config` is optional for dependency metadata.

This profile reproduces the 21 feature flags of the inspected NGINX 1.31.9 build:
HTTP TLS, HTTP/2, HTTP/3, stream and mail with TLS, stream TLS preread, threads,
file AIO, HTTP real IP, stub status, auth request, addition, sub, DAV, slice,
gunzip, gzip static, module compatibility, and the native control API. All other
upstream module defaults still apply. The manifest records the actual generated
module list rather than treating these flags as the complete list.

Build products and logs are under `x10/.build/`; objects and the executable are
under `x10/.build/objs/`. The configured prefix is `x10/.build/runtime/`. **No
installation is performed**, so that runtime directory is not populated with
configuration or assets. The script runs the generated Makefile directly and
does not start a server. Upstream configure also creates its standard ignored
root `Makefile`; tracked upstream sources are not edited.

The default parallelism is two jobs; `--jobs` accepts integers from 1 through 64.
`--configure-only` writes a `configured` manifest with no binary hash, even if an
older executable exists. A failed compile writes `build_failed`; configure
failure leaves its log and no success manifest. Concurrent builds in the same
checkout are not supported. Use separate checkouts for independent builds.

`x10/.build/manifest.json` records the fixed upstream revision, checkout revision,
tracked changes, platform, exact configure/make argv, compiler flags, NGINX
version, generated modules, compiler-preprocessed dependency header versions,
optional pkg-config package versions and, after a
successful build, `nginx -V` output and binary SHA-256. pkg-config reports package
metadata; it is labelled separately from the binary's version output. This is a
reproducible build **profile**, not a promise of identical binary bytes across
compiler, dependency, environment or checkout-path changes. Upstream configure
does not escape arbitrary paths; use letters, digits, `/`, `.`, `_`, `+`, `-` in
the checkout path.

The manifest also records changed `src/`, `auto/` and `conf/` paths relative to
the pinned upstream revision, plus SHA-256 of that Git binary diff. This keeps
source-change provenance after a patch is committed as well as before commit.

The `built` status requires a regular executable file, execute permission for the
current user, a successful `nginx -V`, and unchanged file identity, size, mode and
timestamps during verification. The manifest records its executable mode. A
binary verification failure returns a nonzero exit status and writes
`verification_failed`, an error message and `binary: null`. The manifest is a
snapshot; consumers must check the current binary before executing it.

HTTP/3 compilation may use the upstream OpenSSL compatibility path. Successful
compilation does not demonstrate HTTP/3 interoperability or performance. This
profile currently supports Linux only; other operating systems are unverified.

## Validation

On 2026-10-22 the unmodified upstream baseline built successfully on Linux x86_64
with GCC 13.3.0, PCRE2 headers 10.42, OpenSSL headers 3.0.13 and zlib headers 1.3.
The binary reported NGINX 1.31.9 and OpenSSL 3.0.13 via `-V`. The manifest contained
105 registered modules, all 23 configure arguments and no tracked source changes.
Its SHA-256 was
`adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e`.
The local baseline binary and manifest were archived under `.build/baseline/`.

The native fork also rebuilt successfully after the three-line QUIC transport
parameter fix in `src/event/quic/ngx_event_quic_transport.c` (full-width parameter
ID and complete numeric-value consumption). Its binary SHA-256 was
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`,
with the same compiler, dependency header versions and 105 registered modules.
The manifest identified that source file and source-diff SHA-256
`e39c9727a66feae3390301c0718438dc00182a28b607e6156a2b6d059f65ba64`.
Compilation and `-V` were verified here; protocol regression checks are maintained
separately from this build profile.

A later check found the fixed binary at mode `0644` with the same content hash.
Its ctime was four seconds after the successful build manifest, while mtime was
unchanged; the action that changed the mode was not identified. Only that binary
was restored to `0755`, and `-V` succeeded again. The actual manifest writer was
checked against the non-executable file: it returned failure and recorded
`verification_failed`; after the targeted mode repair it recorded `built`, mode
`0755` and the unchanged SHA-256. No C source or baseline archive was changed by
this repair.

Shell syntax, help output, rejection of `--jobs 65`, and configure-only mode with
an existing binary were checked. Configure-only correctly omitted the previous
binary hash. The full build produced a manifest whose SHA-256 matched the
executable; the runtime prefix was not created and tracked upstream files had no
diff. No throughput or latency improvement is established by compilation.
