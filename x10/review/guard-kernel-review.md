# Guard deterministic kernel: independent review

Reviewed on 23 October 2026. No unresolved blocker was found in the frozen
generated tenant/cache kernel. This is a finite deterministic experiment on
the existing native binary, not AI discovery, AI repair, authentication,
production certification or a new NGINX vulnerability. No native rebuild or
full regression suite was run by this reviewer.

[Public review summary](../evidence/guard-kernel-review-controls.json) contains
names/results, hashes, cleanup facts and limitations. It is not raw runner
output or aggregate-validator input. The full private record retains the
independent commands/results and harness; its SHA-256 is recorded in the
summary. Host paths, runtime identities, logs and embedded raw records are
omitted from publication. Frozen milestone-7 review files were not changed.

## RFC and prior art

[The RFC](guard-research.md) separates a future AI search/repair hypothesis from
this implemented verification kernel. Its comparative study and novelty remain
unproven. The following primary sources were opened and checked directly:

| Source | Supported prior approach |
| --- | --- |
| [ACtests](https://arxiv.org/html/2505.12770v1) | Runtime access-control change testing, replay and request synthesis |
| [CornerCase](https://www.microsoft.com/en-us/research/publication/cornercase-automated-extremal-testing-of-protocol-implementations-using-llms/) | LLM constraint extraction, boundary tests and differential execution |
| [Gixy](https://github.com/yandex/gixy), [Gixy-Next](https://github.com/MegaManSec/Gixy-Next) | Static NGINX configuration/security analysis |
| [Speedscale replay](https://docs.speedscale.com/concepts/replay/) | Captured-traffic replay and dependency response mocks |
| [Cornetto](https://nsg.ethz.ch/publications/2026-05-05-benchmarking-llm-driven-network-configuration-repair-20-500-11850-799709/) | LLM repair evaluated through independent formal verification and regression checks |

These support the RFC's narrow comparisons. They do not establish exhaustive
prior-art coverage, an unoccupied market, or absence of other stateful/cache
tools. Runtime observations are not formal verification. No model API,
AI-generated patch, arbitrary customer configuration importer or general
customer binary adapter was implemented or tested here.

## Source and execution contract

The CLI validates every declarative input and baseline/candidate compatibility
before build probing. The exact schema allows two distinct bounded synthetic
labels, one constrained resource and two cache-key choices. Unknown fields,
configuration text, destinations, headers and shell commands are not accepted.
The current build verifier is tied to this checkout's recorded native source,
upstream pin, generated files and binary identity. A selected executable remains
trusted local code; consistency hashes are not signatures or sandboxing.

Each contract runs two fresh private-cache orders: A→B→A→B and B→A→B→A.
The generated one-process native HTTP profile uses controlled loopback origin
data. Tenant bodies and independent origin traces check isolation; native
MISS/MISS/HIT/HIT plus one origin request per tenant check useful caching.
Disabling cache cannot weaken this declared contract into a passing repair.
It could be a separate mitigation policy outside this experiment.

Request/body/readiness/output/process limits and owned shutdown paths were read.
Public errors omit raw OS/config/log output. Normal native completion must be
SIGQUIT zero; incomplete cleanup fails verification. These are supported-operation
bounds, not cancellation guarantees for every stalled kernel/filesystem call.

## Independent controls

Seven check groups passed, with the units kept separate:

- Five actual native CLI scenario groups: correct isolated key; bad-key paired
  witness; correct candidate; cache-off refusal; unchanged bad pair.
- One controlled preflight positive control: an executable with a matching local
  manifest demonstrably wrote its marker when build probing was requested.
- One rejection group containing six invalid/unsupported/incomparable inputs:
  no executable marker and no fixture directory was created, including the
  repeated-slash resource case.

Both fresh bad-key orders produced a correct priming response followed by a
different tenant receiving that same known tenant body with HTTP 200. The
correct key retained both isolation and cache hits. Cache-off retained isolated
bodies but failed cache effectiveness, without a leak witness. The unchanged
bad pair failed as `baseline_violates_contract`; the old version was not trusted
merely because it was called baseline.

All normal native orders reported zero exit, no forced cleanup, closed origin,
zero sockets and removed prefix. Every CLI child was reaped. The final accessible
private-executable procfs inventory was empty before emergency cleanup and after;
no fixture directories remained. Source and original native bytes were unchanged.

The first independent harness cleanup inventory encountered permission denial
on an unrelated protected proc entry. This was a reviewer-harness error, not a
kernel result. Inventory was restricted to accessible private fixture executables
and the short controls reran successfully; no first-attempt PASS is claimed.

## Findings, attribution and limits

Independent source review found that a repeated-slash resource could enter a
generated exact location while native URI normalization chose another route.
It also found that generic non-200/unknown-body failures could be labeled as
tenant mismatches. The owner now rejects repeated slashes before effects and
classifies malformed responses/cold priming state as infrastructure errors.
Only recognized foreign-tenant bodies after a valid prime form leakage evidence.
The candidate input rejection was independently executed. The HTTP-shape branch
was reviewed in source; no independent HTTP fault injection is claimed.

The RFC request order was aligned with actual alternating execution. The owner
targeted TAP output was separately inspected: 8 tests, including its parent,
zero skips/failures. Its test-only preload injects SIGTERM during a real tenant
request after unique readiness and checks its own child's reaping/removal.
This interruption control was not independently repeated or added to the seven
groups above.

The corpus is one trusted generated Linux HTTP/cache profile, two synthetic
labels and one resource. Labels are not authenticated identities. Arbitrary
configurations, authorization applications, TLS, HTTP/2/3, distributed cache,
reload races, platform/ABI matrices, production isolation and AI quality remain
unverified. Same-UID malicious code and check-to-use races are not isolated.
Full regression, publication and hosted CI results belong to separate runs.

| File | SHA-256 |
| --- | --- |
| `x10/proof/runner.mjs` | `23ce6ec1e7f0429e08ad0c71fe836d75bd5934ff6c748c6d189b4748f0e8f33d` |
| `x10/proof/cli.mjs` | `a204ef1958dbb8a538fd20680340402609eb9e16499b598bded4d57d4aaf560e` |
| `x10/test/proof.test.mjs` | `c0964090631e7fd7776a97772fe7de91784b0a8c4920426ca266e4922597b050` |

Independent executions used unchanged native binary
`e150b0a6e15c3799384e141ea548c658f1ce126ad2eb996a3965ab6791e0a139`.
Per-file source contracts and the remaining hashes are in the public summary.
All reviewer-owned processes and temporary fixtures have stopped or been removed.
