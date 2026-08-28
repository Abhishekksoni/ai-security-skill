# Rule and Control Authoring

## 1. Security Controls

Controls live in `controls/**/*.yaml` (e.g. [agent_security.yaml](file:///Users/abhisheksoni/Downloads/ai-security-skill/controls/ai/agent_security.yaml)).

A security control has:
- `id`: stable identifier, e.g. `CTRL-AI-002`.
- `name`: friendly name of the control.
- `category`: broad class of risk.
- `mapped_requirements`: list of standard requirement IDs from the knowledge base (e.g. `LLM-EXCESSIVE-AGENCY-001`).
- `applicability`: rules defining when this control is checked based on the project context (e.g. `project.ai.detected == true`).
- `severity_if_failed`: `info`, `low`, `medium`, `high`, or `critical`.
- `default_policy`:
  - `block`: boolean whether the control blocks deployment/commits by default.

### Registering Controls
New control files must be registered inside the initialization logic of `SecurityControlRegistry` in [registry.ts](file:///Users/abhisheksoni/Downloads/ai-security-skill/src/controls/registry.ts#L29-L59).

---

## 2. Security Requirements (Knowledge Base)

Requirements are stored in `knowledge/frameworks/<framework-id>/requirements.yaml`.

A framework requirement file has:
- `id`: framework identifier (e.g. `owasp-asvs`).
- `name`: full name of the standard.
- `version`: version of the standard.
- `requirements`: list of standard requirements, each containing `id` (e.g. `LLM-TOOL-AUTH-001`), `title`, `description`, and `category`.

---

## 3. Legacy Rules (Backward Compatibility)

Legacy rules live in `rules/**/*.json` and are still loaded for compatibility:
- `id`: stable identifier, e.g. `AUTHZ-001`.
- `category`: broad class of risk.
- `severity`: `info`, `low`, `medium`, `high`, or `critical`.
- `blocking`: boolean whether the rule can block by default.

Keep detection and remediation evidence-based. A rule should avoid claiming proof when it only has a heuristic signal. Use `candidate` findings for uncertain semantic checks.

