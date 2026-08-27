# Architecture

## Security lifecycle

`INIT -> DISCOVER -> THREAT_MODEL -> REQUIREMENTS -> REVIEW_CHANGE -> SCAN -> GATE -> DEPLOY`

The engine is designed around two classes of checks:

- Deterministic checks: file scanning, source inspection, configuration inspection and external scanner adapters.
- Reasoning checks: future semantic/LLM-assisted analysis. These should create candidate findings that still need independently verifiable evidence before becoming blocking.

## Project state

The `.security/` directory is the durable security memory of the application. It is intentionally human-readable so a developer can review and edit policy.
