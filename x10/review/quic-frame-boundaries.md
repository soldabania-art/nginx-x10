# QUIC receive-frame boundaries

Source and fixture review on 23 October 2026, starting from X10 development
`43618ecca59fe802620f810a13f083554952bd7d` and pristine upstream
`148c75678cd4171338c31d4ed4c02411736d5fe9`.

**No new production defect was confirmed in this bounded 64-bit pass. No C
patch is proposed.** The result expands regression coverage; it does not mean
all QUIC frames, connection states or platforms have been proven correct.

## Executed parser fixture

```sh
bash x10/test/quic-frames.sh
bash x10/test/quic-frames.sh --source /path/to/pristine/nginx --objs /path/to/configured/objs
```

The shell runner compiles [quic-frames.c](../test/quic-frames.c), which includes
the selected production transport translation unit. Unused production functions
are removed by linker section collection; only logging is stubbed. No socket,
native server or TLS peer is created. The caller-owned frame/chain/buffer
structures are initialized as required by `ngx_quic_parse_frame`. Input is
copied into an exactly sized allocation before parsing, so ASan can see a read
past a truncated allocation, not just a logical end inside a large scratch
buffer. Borrowed payload/range pointers and frame consumption are checked
before the allocation is freed.

The independent wire builder encodes varints from their bit layout. The
packet-eligibility oracle follows [RFC 9000 section 12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)
for client-to-server Initial, Handshake, 0-RTT and 1-RTT packets. It does not call
the production serializer to manufacture expected bytes. Frame types 0..30 are
covered by the eligibility matrix; unknown-type controls include the immediate
31/32 boundary and larger varints.

The same **6579 inputs pass on both production translation units**
under ASan+UBSan, with no execution diagnostics. Fixed seed: 9000. Input digest
FNV-1a64: `60272381a5a42680` on both. These are related generated
inputs across six properties, not thousands of independent protocol features.

| Property | Inputs | Failed on either source |
| --- | --- | --- |
| complete_fields_consumption_and_nonminimal_values | 721 | 0 |
| structured_frame_prefixes_are_rejected | 289 | 0 |
| declared_payload_lengths_and_borrowed_bounds | 1304 | 0 |
| client_frame_packet_eligibility | 124 | 0 |
| unknown_type_cid_and_stream_limit_boundaries | 45 | 0 |
| seeded_inputs_return_only_bounded_consumption | 4096 | 0 |

Results: [candidate](../evidence/quic-frames-fixed.json),
[pristine reference](../evidence/quic-frames-reference.json).

The scalar matrix crosses 1/2/4/8-byte encodings and varint boundaries through
`2^62-1`, including legal nonminimal **field values**. Structured prefixes cover
ordinary and wide fields. Payload checks include exact/one-byte-short declared
lengths, a huge declared length with short input, frame boundaries before a
following PING, no-LEN STREAM consuming the packet remainder, and a padding run
stopping before the next frame. Limits include CID lengths 0..21,
retire-prior-to greater than sequence, and below/at/above `2^60` stream counts.
A declared ACK range count of `2^62-1` with insufficient bytes must fail rather
than run an unbounded loop. The 4096 deterministic mutation inputs assert only
bounded return/consumption and sanitizer cleanliness; they are not an oracle
that every syntactically accepted random frame is semantically valid.

## Assertion negative control

[The mutation control](../evidence/quic-frames-negative-control.json) copies
source into an ignored temporary directory and deliberately disables only the
`ngx_quic_read_bytes` declared-length check. The final harness returns exit 1
with **1092 strict mismatches**, including truncated and oversized payload
cases. The control is marked as an expected failure of the mutated parser;
it is a successful check of fixture sensitivity, not an NGINX bug or a passing
functional run. Canonical source and generated files stay unchanged, and the
temporary source copy is removed.

## Source contracts and excluded semantics

The relevant source paths were read before implementing these assertions:

- `ngx_event_quic_transport.c`: `ngx_quic_parse_int`, byte helpers,
  `ngx_quic_parse_frame`, packet permission masks and `ngx_quic_parse_ack_range`.
  Length checks precede borrowing/copying bytes. The parser normalizes STREAM
  flag variants to the common frame type and returns only the consumed frame
  length, except no-LEN STREAM whose payload is the remaining packet.
- `ngx_event_quic_transport.h` and `ngx_event_quic_connection.h`: frame layout,
  union flags, CID/token capacity and encryption-level values.
- `ngx_event_quic_ack.c`: `ngx_quic_handle_ack_frame` validates the first ACK
  range against the largest packet number and validates gap/range subtraction.
  Those connection/send-context effects are not executed here. Structurally
  complete ACK boundary vectors can intentionally violate those later rules.
- `ngx_event_quic_streams.c`: `ngx_quic_handle_stream_frame` applies direction,
  final-size and flow-control rules before buffering. `ngx_event_quic_ssl.c`
  applies CRYPTO buffering/handshake rules. Parsing an offset/length is not a
  claim that a live connection would accept that frame.

### Frame-type encoding policy

Three separate observations show current acceptance of PING type 1 encoded in
2, 4 or 8 bytes. RFC 9000 section 12.4 requires senders to use the shortest
frame-type encoding, but permits receivers to reject a longer encoding. Receiver
rejection is **MAY**, so acceptance is not classified here as a confirmed defect
or strict failure. These observations do not add to strict PASS counts. This is
distinct from ordinary field varints, for which nonminimal encodings remain
valid. No receiver-policy change is made.

### Platform and lifetime limits

This profile has 64-bit `size_t`. Passing a decoded uint64 length to the
size_t byte helper needs a real 32-bit build to establish behavior on that ABI;
this fixture does not simulate one by changing typedefs. The local `cc -m32`
probe cannot find 32-bit libc headers (`bits/libc-header-start.h`), so no 32-bit
result or defect is claimed. A matching generated-header/dependency profile is
required before adding that platform to acceptance.

Borrowed-buffer lifetime after this synchronous call, queued-frame ownership,
packet protection, ACK/congestion state, flow control, loss/reordering,
handshake, HTTP/3 and network interoperability remain outside this fixture.
LeakSanitizer is explicitly disabled; leak behavior is unverified. Normal runner
completion checks temporary build-root removal. No interruption experiment was
performed for this compilation-only runner.

## Code identities

| File/source | SHA-256 |
| --- | --- |
| Harness | `9a2b4e9fa60881891b4e77e09a92540702559f792f5e0fad2b9310cd2415d289` |
| Runner | `8ea4dde51ebf8ab152ab67d79310a02b2e4caa1b438d2bed7c0d9af2c9d2ddd8` |
| Candidate transport source | `3a5a4a5279af489c62937f55d175d0ac82c5cf3e2bf1fead9e9ebc8d8c4f0a6a` |
| Pristine transport source | `a0b47a7045659a52787d1a3f539cb5d63074c0ad5c7ccb9c33219755ff1dfe81` |

Each result also records compiler flags/version, generated config digest,
selected source/header digests, sanitizer options, no-network scope and
before/after identity checks. Baseline uses its own configured
`nginx-native-build/objs-x10` profile; candidate uses `x10/.build/objs`.

## Root review boundary

The root reviewer read the complete C fixture and runner, checked their
recorded hashes and the candidate/reference 6579-case summaries, and verified
the stream-count/frame-type policy against the primary RFC sections linked
above. The same canonical-source fixture is included in the aggregate gate;
that gate records its own execution rather than relying on an agent handoff.
The isolated modified-source negative-control artifact is retained as its
owner-executed sensitivity check and is not relabeled as a root execution or
a newly identified NGINX defect. No additional production patch or modified
parser experiment was added during this root review.
