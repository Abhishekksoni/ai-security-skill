# Contributing

1. Add or modify a security control under `controls/**/*.yaml` or a security requirement under `knowledge/frameworks/**/*.yaml`.
2. Register any new control file paths in the `SecurityControlRegistry` initialization logic ([registry.ts](file:///Users/abhisheksoni/Downloads/ai-security-skill/src/controls/registry.ts#L29-L59)).
3. Add a vulnerable fixture and, when appropriate, a secure fixture under `fixtures/`.
4. Add or update a unit/integration test.
5. Run `npm run check`.
6. Keep findings deterministic where possible. LLM reasoning should never be the only source of evidence for a blocking finding.

Prefer small, composable changes over large control bundles.

