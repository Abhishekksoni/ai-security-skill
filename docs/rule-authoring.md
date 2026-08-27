# Rule authoring

Rules in v0.1 live in `rules/*.json`.

A rule has:

- `id`: stable identifier, e.g. `AUTHZ-001`.
- `category`: broad class of risk.
- `severity`: `info`, `low`, `medium`, `high`, or `critical`.
- `blocking`: whether the rule can block by default.

Keep detection and remediation evidence-based. A rule should avoid claiming proof when it only has a heuristic signal. Use `candidate` findings for uncertain semantic checks in future versions.
