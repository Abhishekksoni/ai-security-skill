# Agent Security Control Layer (security-skill)

> **Security infrastructure for AI-generated software. Establish requirements, review risky changes, scan implementations, and block insecure deployments—all inside the AI loop.**

---

## 1. What Problem This Solves

AI coding agents (such as Claude Code, Codex, Cursor, and others) are incredibly productive at writing code, but they lack human-like security intuition. They are prone to introducing critical vulnerabilities like IDOR/BOLA, SQL injection, hardcoded secrets, and unsafe execution configurations. 

Furthermore, **an AI coding agent should never define its own security requirements or certify its own work as secure**. 

`security-skill` solves this by introducing a local-first, deterministic security control plane that runs as an independent guardrail around AI agent workflows. It enforces safety constraints, runs AST and dependency scanners, logs findings, and dynamically blocks deployment gates.

---

## 2. Why AI Coding Agents Need This

AI coding loops move too fast for traditional manual review. Integrating `security-skill` into the loop ensures:
- **Traceability**: Threats map directly to security requirements, rules, scanners, and findings.
- **Risk-Based Context**: Agents are given immediate implementation guidance before writing code (via `review-change`).
- **Independent Verification**: Gate results are deterministic and based on scanner output; agents cannot self-resolve findings without correcting the code.
- **Local Enforcement**: Run entirely offline on the developer's local machine, protecting sensitive intellectual property.

---

## 3. Architecture

```text
            AI AGENT
               │
               ▼
        SECURITY CONTROL
             LAYER (MCP/CLI)
               │
     ┌─────────┼─────────┐
     ▼         ▼         ▼
 Threat      Rules     Scanners
 Model       Engine    & AST Analysis
     │         │         │
     └─────────┼─────────┘
               ▼
          FINDINGS
               │
               ▼
        SECURITY GATE
          │          │
        BLOCK       PASS
          │          │
          ▼          ▼
       REMEDIATE   DEPLOY
```

- **Deterministic Layer**: Performs robust AST analysis using the TypeScript Compiler API, secret scanning, environment parsing, and handles integrations with external tools.
- **Reasoning Layer**: Handles threat modeling, authorization pattern definitions, and agent permissions.
- **State memory**: Entirely contained in `.security/` under the target repository root.

---

## 4. Installation

Ensure Node.js >= 20 is installed, then run:

```bash
# Clone the repository
git clone https://github.com/open-security/agent-security-skill.git
cd agent-security-skill

# Install dependencies
npm install

# Build the project
npm run build
```

Link the CLI executable to run it globally (optional):
```bash
npm link
```

---

## 5. Quick Start

Run the following commands in any target codebase directory:

```bash
# 1. Initialize the security directory (.security/)
security-skill init

# 2. Discover the project stack and sensitive signals
security-skill discover

# 3. Generate the baseline threat model
security-skill threat-model

# 4. Generate security requirements mapped to rules
security-skill requirements

# 5. Scan the workspace for vulnerabilities (builtin AST + external tools)
security-skill scan

# 6. Evaluate findings against the security policy gate
security-skill gate
```

---

## 6. CLI Usage

The `security-skill` binary supports the following subcommands:

- `init`: Creates `.security/` state layout.
- `discover`: Scans files and prints JSON representation of the stack.
- `requirements`: Returns applicable security requirement lists in YAML.
- `threat-model`: Outputs a custom threat model in YAML.
- `review-change --type=<type> --path=<path> --description=<desc>`: Assesses a proposed change and returns controls.
- `scan [--changed]`: Runs local analyzers. `--changed` targets only files modified in git status/diff.
- `findings`: Lists all open security findings.
- `explain [finding-id]`: Prints analysis, attack scenarios, and required fixes for a finding.
- `gate`: Evaluates findings against policy. Exits `0` on PASS, `1` on BLOCK, `2` on warning, `3` on error.
- `report`: Compiles a detailed markdown audit report to `.security/report.md`.
- `status`: Show local security state.

---

## 7. Model Context Protocol (MCP) Integration

Expose all capabilities of the control plane directly to your AI editor (Cursor, Windsurf, Claude Code) by adding the following configuration to your MCP settings (`mcp_config.json`):

```json
{
  "mcpServers": {
    "agent-security-skill": {
      "command": "node",
      "args": ["/absolute/path/to/agent-security-skill/dist/mcp/server.js"],
      "env": {}
    }
  }
}
```

### Exposed MCP Tools
- `security_initialize`: Prepares control structure.
- `security_context`: Inspects project details.
- `security_requirements`: Lists active policies.
- `security_review_change`: Runs predictive controls check on planned features.
- `security_threat_model`: Retransmits threat maps.
- `security_scan`: Runs security checks.
- `security_findings`: Returns all open findings.
- `security_explain_finding`: Detailed remediation steps for a finding.
- `security_gate`: Runs gates check.

---

## 8. Example Security Gate Policy

The gate policy is stored in `.security/policy.yaml`:

```yaml
blockOn:
  - critical
  - high
maxFindings:
  medium: 5
  low: 20
requiredRules:
  - SECRET-001
  - AUTHZ-001
```

If any critical/high findings are open, or if `SECRET-001` or `AUTHZ-001` are triggered, `security-skill gate` will block the commit/deployment.

---

## 9. Supported Scanners

1. **Built-in AST Engine (TypeScript Compiler API)**: Performs syntactical data-flow analysis on JavaScript/TypeScript to check for:
   - IDOR / BOLA (database lookups without session checks)
   - Prompt Injection paths (interpolation in system prompts)
   - SQL Injection (template literals in raw queries)
   - OS Command Injection (shell interpolation in exec/spawn)
   - Weak JWT signature verify settings
   - Tool Excessive Agency & Tool Authorization flaws
2. **External Adapters (Optional, Auto-detected)**:
   - **Gitleaks**: Secrets detection.
   - **Semgrep**: Advanced SAST scanning.
   - **npm audit**: Dependency scanning.
   - **osv-scanner**: Open Source Vulnerability checks.
   - **trivy**: Container and dependency scan.

---

## 10. Rule Development

Rules are declared in JSON files under the `rules/` directory (categorized by universal, typescript, python, ai, etc.).

Example rule structure:
```json
{
  "id": "AUTHZ-001",
  "name": "Missing server-side resource authorization",
  "category": "authorization",
  "severity": "critical",
  "blocking": true,
  "description": "Resource mutations or lookups must verify ownership or explicit authorization roles."
}
```

To contribute a new rule:
1. Define the rule JSON under `rules/<category>/rules.json`.
2. Add a vulnerable fixture under `fixtures/vulnerable/` and a secure fixture under `fixtures/secure/`.
3. Update tests under `tests/rules.test.ts` to assert detection.

---

## 11. Security Model & Decisions (Exceptions)

Exceptions are managed via Markdown ADR files under `.security/decisions/ADR-001.md`:

```markdown
# ADR-001: Exclude SQLi in local tests

finding_id: SQLI-73716c69
rule_id: INJ-003
expires: 2026-12-31
approved: true
reviewer: SecurityLead
reason: SQL query is executed against a hardcoded sqlite memory db.
```

The engine parses these files, checks the expiration date and approval status, and automatically suppresses findings with active decisions.

---

## 12. Privacy & Data Handling

- **100% Offline**: All AST analysis, secret scans, and dependency parsing run locally.
- **No Telemetry**: No tracking identifiers, usage metrics, or source code are sent to external backends.

---

## 13. Limitations

- `security-skill` is designed as a developer-assistant guardrail; it does **not** replace professional penetration testing, runtime WAF filters, or comprehensive security reviews.

---

## 14. Contribution Guidelines

We welcome community rules! Please check [CONTRIBUTING.md](file:///Users/abhisheksoni/Downloads/ai-security-skill/CONTRIBUTING.md) for rule authoring requirements.
