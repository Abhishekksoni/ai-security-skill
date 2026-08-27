# Agent Security Skill

## Mission

Treat security as a control loop around AI-assisted software development.

**Do not self-certify.** The coding agent may propose an implementation and fix findings, but the security engine owns findings and gate decisions.

## Required lifecycle

1. `security_initialize` before substantial implementation.
2. `security_requirements` before implementing security-sensitive features.
3. `security_review_change` before adding or changing authentication, authorization, API endpoints, database access, file uploads, webhooks, AI tools, payments, secrets, or infrastructure.
4. `security_scan` after risky changes and before commits/deployment.
5. `security_gate` before deployment.

## Agent behavior

When a security tool returns `blocked`, stop the relevant development step and remediate the finding. Do not silence, delete, or reinterpret a blocking finding without an explicit policy change.

When a finding is marked heuristic or candidate, treat it as a review requirement rather than proof of exploitability.

Never expose secrets in tool arguments, logs, or generated reports.
