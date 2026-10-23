# ENGINE X10 native development

- Develop the original NGINX Open Source codebase. Keep existing modules, protocols, configuration semantics and platform branches unless the owner explicitly approves a change of scope.
- Preserve upstream history, copyright and LICENSE. Record the upstream revision and keep security updates easy to merge.
- The Node gateway in soldabania-art/engine-x10 is an experimental fixture and console project; it is not this native data plane.
- Read the affected native lifetime, buffer, event, error and module-order contracts before editing C. Keep patches small and follow the surrounding NGINX style.
- Each fix needs a counterexample on the unchanged baseline, a passing candidate case and relevant regression checks. Reading source or compiling a module does not prove its runtime compatibility.
- Keep unknown QUIC parameters and valid nonminimal varints interoperable. Treat duplicate-parameter policy separately from the first parser fixes.
- Keep new optional behavior off by default when it changes existing semantics. Do not replay requests or expose management endpoints implicitly.
- Record configure flags, dependencies, compiled modules, source changes and binary identity with test evidence. Do not claim performance improvement without comparable measurements.
- Do not commit private keys, credentials, build products or transient test prefixes. Run local fixtures on loopback with bounded child cleanup.
- Maintain x10/PLAN.md, x10/STATUS.md and the per-file review ledger. Unverified observations are hypotheses, not vulnerability announcements or completed features.
- Run `node x10/test/all.mjs --official` for the current native development profile. Keep build/source identity checks and explicit upstream skips/TODOs intact.
- The local controller confirms sampled generation/health after reload. Do not describe it as blue-green isolation, an all-traffic atomic cutover, or recovery from every crash point.
- Retain unfavorable benchmark data and identical-binary controls. The current Node loopback measurements have substantial unexplained variance and do not establish performance acceptance.

## Continuum research and scheduled development

- The owner authorized the Continuum concept, economic assumptions, bounded implementation work and periodic cloud development to be recorded in this repository. Preserve the full native NGINX project; the isolated research directory does not replace its data plane.
- Read `x10/continuum/README.md`, `PLAN.md`, `OPERATIONS.md` and current `BACKGROUND.json` before a Continuum task. A scheduled coordinator must acquire and reread the documented Git branch lease before publishing; only the coordinator integrates or updates the branch. Never force-push.
- Treat record primitives, a state-machine model, socket passing, manual layout adapters, independent handshake interoperability, an OpenSSL state adapter and native NGINX integration as separate milestones. Do not call a synthetic established-record fixture a completed live NGINX/TLS-library upgrade, an automatic adapter compiler, a proof of completeness or a technological breakthrough.
- Do not introduce experimental record cryptography into production paths. Only public RFC vectors and clearly synthetic fixture secrets belong in tests; never publish real session keys, traffic or raw host evidence.
- Run `node x10/continuum/check.mjs` and `node --test x10/continuum/process-handover.test.mjs` for the research profile, preserving counterexamples and cleanup checks. Native changes also require their own baseline/candidate evidence and the official native aggregate.
- Recreate a useful temporary assistant team when tools support it. A schedule is periodic resumption, not permanently running assistants; record unavailable execution, pending CI and unresolved failures honestly. Do not create additional schedules from a scheduled task.
