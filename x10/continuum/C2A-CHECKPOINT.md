# C2a: hosted evidence and patch-format policy

Implementation: `99a017e64b33eda537ea0fc19db623984fa2dd9e`.
Date: 2026-10-23. Scope remains read-only observation; full inventory,
semantic export/import, actual TLS-code replacement and NGINX migration
are unimplemented. Local evidence: [continuum-c2a.json](../evidence/continuum-c2a.json).

## Exact hosted research acceptance

| Event | Run | Research job | Result |
| --- | --- | --- | --- |
| Push | [39994034417](https://github.com/soldabania-art/nginx-x10/actions/runs/39994034417) | 120552885020 | completed success |
| Pull request | [39994040940](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040940) | 120552928281 | completed success |

Both decoded logs independently confirm 21/21 core, 7/7 process, 22/22 C1
and 8/8 C2a, zero failures/cancellations/skips/TODO. The C2a aggregate is
`continuum-pinned-openssl-state-probe`, exit0. Native binaries are not linked
to this isolated probe. Runtime strings do not expand the pinned profile.

Native implementation99a017e [push39994034390](https://github.com/soldabania-art/nginx-x10/actions/runs/39994034390)
and [PR39994040738](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040738)
also completed success; jobs120552916731 /120552906412. Both full workflows
include official aggregate, Guard, required Unix transports/generations/operator,
feature-off build and alpha package/checksum. Local native20/20 and official
sample counts remain separate evidence. Previous C1 acceptance is preserved.

## Preserved adverse whitespace result

[Initial Check Whitespace39994040750](https://github.com/soldabania-art/nginx-x10/actions/runs/39994040750),
job120552818898, completed failure. Exactly five diagnostics point to lines
5/7/27/57/80 of `openssl-probe.patch`: each is a single-space unified-diff
context marker for an empty source line. Frozen patch SHA256 remains
`2b61a530504b71c5249ce79e33a58ca51251cf5f245472620da7692a6bfb8dcd`.

Coordinator reproduced the whole PR range from base
`0b622c4a9f4dfe0876209c2a8bf5ce5e25caa812` to implementation99a017e:
exit2 with those five diagnostics and no other warnings. With the exact
`.gitattributes` path policy, the same full-history command returns exit0
with empty stdout/stderr. Attribute lookup remains unspecified for
`openssl-probe.c` and `src/core/nginx.c`.

The exception disables blank-at-EOL checking for the entire named patch
file, not only the five known lines. Patch/C bytes and compile/runtime
logic remain unchanged. Other files retain their rules. Independent private
Git2.51.1 controls confirmed historical-commit behavior, default space-before-tab
and blank-at-EOF detection on the patch, and blank-at-EOL on another C file.
String-valued target attributes need not inherit arbitrary custom
`core.whitespace` flags; current repository workflow sets no such custom flags.
Actual checked-out attributes are required for the tested `git log --check`
behavior; index fallback alone is not asserted.

Hosted policy acceptance is now recorded in the CI receipt below.
Commit-message and version-bump checks on99a017e succeeded. The inherited F5
CLA integration still failed separately; no contract is accepted on the
owner's behalf.

Next: accept the format-policy hosted result, then extend C2a peer/read KeyUpdate,
retry/control/shutdown/limits and runtime cancellation inventory. No new
spending, infrastructure, outreach or commercial scope was introduced.

## CI receipt

Policy implementation: `624f70fa1b5061c5be65759eed5a45a4d56a4af7`.
[Check Whitespace39995212454](https://github.com/soldabania-art/nginx-x10/actions/runs/39995212454),
job120556843347, completed success. Commit-message39995212552 and
version-bump39995212660 also completed success. The initial failure remains
recorded above; this is a format-policy correction, not new TLS behavior.

Successor research push39995200815 completed success with its expensive
research job skipped; this is not a fresh runtime pass. Research PR39995212463
completed success. Original exact runtime acceptance remains implementation
99a017e and its two real research/two full native runs.

Successor native push39995200740 / PR39995212470 were in_progress when this
receipt was written. Those exact SHA/run IDs remain pending in BACKGROUND;
unchanged runtime sources do not permit inventing their outcome. Later
coordination-only descendants do not replace the accepted source hashes.

Receipt modifies only BACKGROUND and this Markdown file, with one parent
being the exact own live lease; no C, patch, workflow or economic change.
Per-file receipt ledger (SHA256):

- BACKGROUND before: `214d18d744b93bf9dc647dd402e5f1c0c7ca932fd2eba854872c9539b278d5c9`; after: `722c244ba9c06fd35358b3c8abf2e43bc956fe5464eab37542097bfbf6b5faab`.
- C2A-CHECKPOINT before: `acbc0ab8c6462214994b736ddcf65d1ebc507825e9a09963f7449a74ac52d2a8`; own after digest omitted to avoid recursion; Git tree/commit identifies it.

Coordinator checked exact source identity and completed workflow/job results;
raw hosted logs, host paths, PIDs and session material are not published.
