# Native contract verification experiment

This is the deterministic verification kernel for a research direction. No LLM,
AI-generated repair, general config importer or production deployment is implemented.
It executes a small declared scenario on the real manifest-checked NGINX binary.

```sh
node x10/proof/cli.mjs check --contract x10/proof/examples/isolated.json
node x10/proof/cli.mjs compare --baseline x10/proof/examples/isolated.json --candidate x10/proof/examples/leaking.json
```

The first command exits 0. The second exits 1 with a concrete two-request cache
counterexample. Replacing the candidate with `isolated.json` passes; replacing it
with `cache-disabled.json` fails the cache-effectiveness requirement. `--binary`
and `--manifest` explicitly select the locally recorded build; the normal X10
build is the default. Linux and Node 22+ are required. Run the targeted checks with
`node --test x10/test/proof.test.mjs`.

Every generated config uses private temporary files, fresh native cache, loopback
origin and frontend, synthetic tenant labels, fresh HTTP connections and one native
process. Each fresh-cache order (A→B and B→A) then repeats A/B to observe native
MISS/HIT behavior. The independent origin trace must contain exactly one request
per tenant. A leak yields the priming request and the mismatching response.

Only the exact bounded JSON schema is accepted. Configuration text, arbitrary
headers, paths outside a short resource grammar, live destinations and shell
commands cannot be supplied. Exit 2 means input/infrastructure verification did
not complete; exit 3 means an unsupported contract/host. Local OS errors and raw
native logs are not copied into the JSON result.

These are finite synthetic checks, not an exhaustive proof of tenant isolation.
Tenant labels are not authentication. Build hashes check local consistency and
do not attest a signed build or stable host libraries. No production traffic is
captured, replayed or modified. This experiment does not establish a new NGINX
vulnerability, performance improvement, worldwide novelty or production readiness.
