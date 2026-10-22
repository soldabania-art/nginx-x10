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
