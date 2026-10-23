# Native FastCGI, SCGI and uWSGI fixtures

```sh
node x10/test/adapters-baseline.mjs --binary x10/.build/objs/nginx
node x10/test/adapters-baseline.mjs --binary x10/.build/baseline/nginx
```

`X10_NGINX_BINARY` selects the binary when `--binary` is absent. `--output FILE`
writes the same JSON report emitted on stdout. Any failing assertion, fixture
parser exception, unexpected critical native error, interruption, changed source
or binary, incomplete native shutdown or failed resource cleanup makes the run
fail. No optional application runtime or Perl client is required. The default
native build profile includes all three modules; missing modules fail `nginx -t`
instead of producing a silent skip.

The Node TCP servers parse actual requests emitted by native NGINX. They are
synthetic application backends, not replacement adapters. Only loopback ports
and private temporary prefixes are used. Native NGINX runs in single-process
mode, retaining the invoking UID; master/reload behavior belongs to other suites.

Each adapter has seven behavior cases, 21 in total:

| Case | Observable assertions |
| --- | --- |
| GET metadata and fragmented response | Method, full URI, query string, host, joined duplicate header and a 196-byte header value; exact 201 status, response header, Content-Length and binary response. FastCGI headers span STDOUT records; every protocol response also spans TCP writes. SCGI/uWSGI use an HTTP status line here. |
| Buffered binary POST | Exact 71,687 request bytes, byte digest, content type/length and binary echo. Body exceeds the 1 KiB client body buffer. FastCGI requires at least three nonempty STDIN records and a terminal empty STDIN. Response uses CGI `Status` headers. |
| Chunked client POST | Client omits Content-Length and writes multiple chunks; NGINX buffers/decodes them, emits a correct adapter Content-Length and forwards 4,099 exact binary bytes. |
| Invalid upstream header | A deliberate NUL inside a header name produces a complete native 502 response. |
| Truncated upstream header | A partial SCGI/uWSGI header or incomplete declared FastCGI record produces a complete native 502 response. |
| Truncated declared body | A 200 response advertising 20 bytes but sending `short` is observed as incomplete by the HTTP client, with exactly those five bytes. A truncated response is not counted as complete success. |
| Upstream timeout | An origin that parsed the request but sends no response produces a complete native 504 within the fixture deadline. |

Every failure case first requires exactly one strictly parsed backend request,
with the same metadata assertions as valid requests. A synthetic parser exception
is a separate `fixtureErrors` failure, never an expected native rejection. All
locations set `*_next_upstream off`; these cases do not exercise retries.

The wire parsers check FastCGI v1, responder role, request ID 1, record lengths,
native zero padding, PARAMS termination, STDIN termination and one/four-byte
parameter lengths. The long header requires the four-byte form. Response records
include nonzero padding and header splits. SCGI checks the decimal netstring,
comma, NUL pairs, first `CONTENT_LENGTH` and `SCGI=1`. uWSGI checks modifier bytes,
little-endian packet length and bounded little-endian name/value lengths. Request
bodies must match the declared size with no trailing bytes.

These contracts were read in the local source functions
`ngx_http_fastcgi_create_request`, `ngx_http_fastcgi_process_record`,
`ngx_http_fastcgi_process_header`, `ngx_http_scgi_create_request`,
`ngx_http_scgi_process_status_line`, `ngx_http_scgi_process_header`,
`ngx_http_uwsgi_create_request` and `ngx_http_uwsgi_process_header`.

Evidence records the actual binary path, SHA-256, `-V`, checkout revision and
hashes of the three local adapter translation units plus the harness. Before/after
hash equality detects changes during the run. These local hashes do not attest
that a selected executable was built from those files; the unified checker adds
build provenance for the candidate. The pristine executable and candidate should
agree on all 21 cases. This suite adds compatibility evidence and fixes no
production adapter code.

Request buffering is explicitly enabled and response buffering disabled. Real
PHP/Python application runtimes, unbuffered request backpressure, upstream TLS,
cache, keepalive pools, retries, multiplexing, load and other operating systems
remain outside this fixture matrix.
