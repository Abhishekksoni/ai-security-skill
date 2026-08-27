# Contributing

1. Add or modify a rule under `rules/`.
2. Add a vulnerable fixture and, when appropriate, a secure fixture.
3. Add or update a unit/integration test.
4. Run `npm run check`.
5. Keep findings deterministic where possible. LLM reasoning should never be the only source of evidence for a blocking finding.

Prefer small, composable changes over large rule bundles.
