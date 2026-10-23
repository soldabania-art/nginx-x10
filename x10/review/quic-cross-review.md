# QUIC transport parameter cross-review

Reviewed independently against NGINX 1.31.9, commit `148c75678cd4171338c31d4ed4c02411736d5fe9`. This is an additional focused review outside the completed 42-file HTTP manifest. No C source was changed, no network peer was contacted, and no vulnerability or exploitability claim is made.

## Result

The wide-ID observation is a real parser defect: an unsupported 62-bit transport parameter identifier can be narrowed to a supported 16-bit identifier and change a parameter or cause rejection. This contradicts ignoring unsupported transport parameters. It is not the intentional unknown-parameter skip path.

The integer-length observation is also reproducible: a numeric parameter accepts one valid integer followed by unconsumed bytes inside its declared value. This is a field-consumption/conformance issue, distinct from legal nonminimal integer encoding. It does not demonstrate out-of-bounds access or parsing the leftover bytes as the next parameter: the outer parser skips the full declared length.

Duplicate known parameters are accepted with last-value-wins behavior. Receiver-side duplicate rejection is a SHOULD in RFC 9000, so this is a strict-policy/robustness decision to document and test. It must not be presented as an unconditional MUST violation or combined with the ID-narrowing defect into a single security claim.

## Source and normative basis

`ngx_quic_parse_transport_params` stores the decoded identifier in `uint64_t id`, handles forbidden client parameters using that full value, and then passes it to `ngx_quic_parse_transport_param`. Both that helper's prototype and definition accept `uint16_t id`. C conversion discards the high bits before the helper's known-ID switch.

For known numeric parameters the helper calls `ngx_quic_parse_int(p, end, &varint)` and rejects only a NULL result. It does not require the returned pointer to equal the end of that parameter's value. The public loop subsequently advances its original pointer by `len`, so any remainder is ignored. The public loop also has no seen-ID tracking; assigning the same known parameter again overwrites its destination.

Primary contract: [RFC 9000 §7.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4) describes duplicate handling, [§7.4.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.2) requires ignoring unsupported transport parameters, [§18.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1) defines ID/length/value encoding, and [§18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2) defines the individual numeric values as variable-length integers. [§16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16) permits encodings longer than the minimum needed for a value. The official sections and relevant excerpts were retrieved and checked by `release_docs` and shared in this task; this reader did not retrieve external network content or read the entire RFC.

Full consumption should therefore mean `decoded_end == value_end`; comparing the declared length to the *minimal* encoding size would incorrectly reject valid nonminimal encodings. The normative strength of receiver duplicate rejection remains separate from malformed field shape and unknown-ID handling.

## Independent local execution

Read the entire `nginx-x10/x10/test/quic-transport.c` and `runner.sh`, then ran:

```sh
bash x10/test/runner.sh \
  --source /workspace/scratch/d8c3d94bb512/nginx-reference \
  --objs /workspace/scratch/d8c3d94bb512/nginx-native-build/objs-x10
```

The runner includes the selected production translation unit directly and uses configured NGINX headers; linker section garbage collection removes unrelated production functions. It replaces only logging for the exercised path. No parser is reimplemented and no sockets or TLS clients are used. Temporary compiler output is removed by an EXIT trap. The run selected the exact reference source, whose SHA-256 was printed as `a0b47a7045659a52787d1a3f539cb5d63074c0ad5c7ccb9c33219755ff1dfe81`.

Result: 13 cases, eight baseline controls passed, five mismatches, zero control failures, strict exit status 1. The five mismatches comprise two manifestations of the wide-ID defect, two duplicate-policy cases and one trailing-value case; they are not five independently established vulnerabilities.

| Case / exact bytes | Expected parser behavior | Observed result | Assessment |
| --- | --- | --- | --- |
| `80010001011e`: ID 65537, length 1, value 30 | Ignore unknown ID; idle sentinel stays 777 | `NGX_OK`; idle becomes 30 | Wide ID aliases `max_idle_timeout` (ID 1). |
| `8001000c0100`: ID 65548, length 1, opaque byte 0 | Ignore unknown ID | `NGX_ERROR` | Wide ID aliases the zero-length `disable_active_migration` parameter (ID 12). |
| `01011e01011f`: duplicate idle 30 then 31 | Strict duplicate policy rejects | `NGX_OK`; idle becomes 31 | Last value wins; receiver SHOULD/policy question. |
| `01011e01011e`: identical duplicate idle | Strict duplicate policy rejects | `NGX_OK`; idle remains 30 | Same policy issue even when values agree. |
| `01021e00`: idle value length 2, one-byte integer 30 then extra 0 | Reject malformed numeric value shape | `NGX_OK`; idle becomes 30 | Numeric helper leaves one byte unconsumed. |
| `0102401e` and `01048000001e` | Accept legal 2/4-byte representations of 30 | Both accepted as 30 | Confirms nonminimal encoding must remain allowed. |
| `1b02ffff` | Ignore unknown/reserved small ID with opaque value | Accepted; sentinel unchanged | Intentional skip works when ID does not alias a known helper case. |
| `010140`, `01021e`, `0000` | Reject truncated integer, declared length beyond input, forbidden client parameter | All rejected | Relevant input-boundary and role checks remain active. |

These isolated parameter lists are parser-level controls, not complete valid handshakes: for example, a full handshake additionally needs a matching initial source connection ID. The selected generated headers are from the local configured build and the source is the pinned reference. This establishes actual C parser results on that configuration, not all build architectures.

## Downstream validation and limits

The relevant TLS callbacks copy defaults into a temporary parameter structure, invoke this parser and then call `ngx_quic_apply_transport_params`. Apply checks the initial source connection ID, UDP payload size, active connection-ID minimum, ACK delay exponent and maximum ACK delay, then adopts negotiated limits. Those checks are valuable, but receive already-converted fields without the original parameter ID, duplicate history or consumed-byte count. They cannot restore correct handling of an unknown wide identifier or detect that an integer's trailing byte was ignored.

This review did not construct a full QUIC handshake, demonstrate client-visible impact, prove a denial of service, measure exposure on deployed systems, or evaluate a patch. The source path and actual parser tests support treating the narrowing and field-consumption behavior as concrete correctness issues requiring deliberate native-fork decisions. They do not support a public security advisory by themselves.

## Follow-up recommendations

- Keep the full decoded ID width through helper dispatch; unknown IDs must not mutate supported fields. Cover both 4-byte and 8-byte identifiers, a maximum unknown ID, and a wide unknown zero-length value whose low bits resemble ID 12.
- Require exactly one numeric integer to consume its declared value while retaining legal 2/4/8-byte nonminimal forms. Cover empty, truncated and trailing-data values independently from whole-input length checks.
- Choose and document duplicate receiver policy explicitly. If adding rejection, compare full IDs and account for resource bounds rather than a truncating small-ID map; keep the RFC SHOULD distinction in test descriptions.
- Before accepting any C change, run the same production-source harness against baseline and candidate, add complete-handshake integration with matching connection IDs, and ensure unknown extension parameters continue to work. Keep this experiment separate from performance claims and unrelated fork features.

## Additional reading ledger

All ranges below are inclusive source lines actually displayed and read. Searches were used only for navigation. The original HTTP manifest and its completed JSON ledger are unchanged by these additional ranges.

| File in pinned reference | File lines | Status | Actual read ranges | SHA-256 |
| --- | ---: | --- | --- | --- |
| `src/event/quic/ngx_event_quic_transport.c` | 2215 | partial | 1–240; 1590–2030 | `a0b47a7045659a52787d1a3f539cb5d63074c0ad5c7ccb9c33219755ff1dfe81` |
| `src/event/quic/ngx_event_quic_transport.h` | 398 | full_read | 1–398 | `bfdd117254953492a1482bf52d4a8db3af6bbff0795dfb2cfd2d38552fb374dc` |
| `src/event/quic/ngx_event_quic.c` | 1523 | partial | 110–225 | `6065edc85bf610c2b38b39ee39b2cb0195aac19ac48fb8dbd9fe525e2d0f5452` |
| `src/event/quic/ngx_event_quic_ssl.c` | 996 | partial | 230–315; 490–565 | `ffd8ef9dac1580503f41b351ee68c4438fa02909a2a7ca161613aaae7002459a` |

Harness snapshot read in full: `x10/test/quic-transport.c` 1–140, SHA-256 `05cb149ca6188a9e6bdf1d15e6fed18dcb3c0f7113a50630bc32a7a3de216ebd`; `x10/test/runner.sh` 1–70, SHA-256 `773b186ae471fee44d98e5104e70e0c7f12a36c6ee02a0d4187293b3c9b40f10`. These harness paths belong to the native-fork checkout, not the source-coverage manifest. Later changes require a new snapshot/run before claiming the same evidence.

## Candidate patch review, 2026-10-22 UTC

The root author subsequently made a three-line native change in `nginx-x10/src/event/quic/ngx_event_quic_transport.c`: the helper declaration and definition now use `uint64_t id`, and the numeric decode check rejects `p == NULL || p != end`. Independently inspected the complete diff. These changes directly address the two demonstrated causes, keep unknown values opaque and do not introduce a minimal-encoding requirement. Duplicate receiver policy is unchanged. The patched source SHA-256 is `3a5a4a5279af489c62937f55d175d0ac82c5cf3e2bf1fead9e9ebc8d8c4f0a6a`.

The harness author also separated the two duplicate cases from strict pass/fail. This reader reread both updated harness files in full and independently ran the same updated harness against the reference and patched source with the same generated headers:

Updated harness snapshot: `x10/test/quic-transport.c` 1–177, SHA-256 `6e7d9a49d2be858361f03d932037b842940ad6ddb8fb52fefba97047f0b1c6f7`; `x10/test/runner.sh` 1–91, SHA-256 `fc759f6ae3da74727dab1d2363e1da3b404cf2a0624a36f1602c940b028e6a13`.

| Selected production source | Strict assertions | Duplicate observations | Process exit |
| --- | --- | --- | ---: |
| Pinned reference, SHA-256 `a0b47a70…1fe81` | 8 passed, 3 failed, 0 control failures | Both accepted, reported separately | 1 |
| Three-line candidate, SHA-256 `3a5a4a52…f0a6a` | 11 passed, 0 failed | Both accepted, reported separately | 0 |

Both runs report `sourceUnchangedDuringTest: true` and `networkUsed: false`. The legal 2-byte and 4-byte nonminimal encodings pass in both versions; wide unknown IDs stop mutating/rejecting as known parameters in the candidate, and the trailing-value case is rejected. Thus the comparison demonstrates the intended parser behavior change without laundering the duplicate SHOULD observations into unconditional failures.

This addendum reviews the source patch and local parser execution only. Full native build and HTTP/TLS/HTTP2/reload regression evidence belongs to the separate integration harness. Full QUIC handshake integration, 8-byte/max-ID coverage and 32-bit builds remain additional evidence, not implied by these eleven strict assertions.
