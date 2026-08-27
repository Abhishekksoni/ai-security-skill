# Agent Security Control Layer (ai-security-skill)

> **Standards-based security control plane for AI coding agents. Establish requirements, trace threats, scan implementations with taint analysis, and block insecure deployments—all inside the local development loop.**

---

## 1. How It Works: The Context-Aware Pipeline

Unlike generic scanners that run blind checks and flood developers with noisy alerts, `ai-security-skill` follows a **Context-First** verification methodology:

1. **Context Discovery**: The engine dynamically profiles your project (detecting language, frameworks, auth, database stacks, payments, and AI capabilities) to construct a localized `.security/context.yaml` profile.
2. **Framework Alignment**: The project context is evaluated against our **Standards Database** (OWASP ASVS V5, OWASP API Security, OWASP GenAI, NIST SSDF, and CIS Controls) to automatically map only the security requirements that apply to your code.
3. **Control Applicability**: Dynamic applicability rules evaluate which controls must be checked. For instance, if Stripe or PayPal imports are detected, it triggers the payment amount integrity checks; if LLM or agent tool configurations are detected, it activates agent validation checks.
4. **AST & Taint-Flow Verification**: Executes structural parsing (AST compiler nodes) and dataflow taint propagation trackers to inspect inputs. It checks if client-tampered pricing reaches payment intents, or if unvalidated tool selections reach agent boundaries.
5. **Deterministic Policy Gate**: Blocks or allows builds based on compliance policy limits, treating unverified or `UNKNOWN` control states with conservative default gates.

---

## 2. Key Features

- **Contextual Security Mapping**: Automatically extracts requirements from standard security frameworks based on your specific application stack context.
- **Advanced Taint Analysis Engine**: Traces how variables propagate from untrusted requests (`req.body`, `req.json()`) to sensitive payment API sinks (e.g. Stripe checkout) to protect e-commerce transactional integrity (`BL-001`).
- **AI Agent Security Boundaries**: Validates LLM tool catalog boundaries to verify that agent integrations enforce user session checks and lack excessive execution privileges.
- **Independent Verification**: Gate decisions are deterministic and run local-first, preventing AI coding assistants from certifying their own work or bypassing security policies.
- **100% Local and Private**: Runs completely offline under `.security/` inside your repository without cloud telemetry.

---

## 3. Architecture

```text
                       AI AGENT / DEVELOPER
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   ai-security-skill   │
                     │    (MCP Server/CLI)   │
                     └───────────┬───────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
     [ KNOWLEDGE ]         [ REASONING ]        [ DETERMINISTIC ]
      Frameworks &         Project Profile       Static Scanners &
       Standards            Threat Model        Taint-Flow Engine
    (OWASP/NIST/CIS)             │                    │
            │                    │                    │
            └───────────┬────────┘                    │
                        ▼                             ▼
                  Requirements                     Findings
                        │                             │
                        └─────────────┬───────────────┘
                                      ▼
                               ┌─────────────┐
                               │ POLICY GATE │
                               └──────┬──────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
                 [ PASS ]                      [ BLOCK / WARN ]
              Gate Exits 0                      Gate Exits 1
           (Deploy/Integrate)                (Remediate/ADR Exception)
```

- **Knowledge Layer**: Framework specifications (OWASP ASVS, API, GenAI, NIST, CIS) are loaded dynamically from machine-readable YAML configs.
- **Control Layer**: Map framework requirements to actual verification controls (Authentication, Tenancy, Injection, Secrets, Business Logic, AI agent validation).
- **Verification Engine**: Executes AST analysis, taint propagation trackers, and optional external adapters to determine control status (`PASS` | `FAIL` | `UNKNOWN`).

---

## 4. Installation

Ensure Node.js >= 20 is installed, then run:

```bash
# Clone the repository
git clone https://github.com/Abhishekksoni/ai-security-skill.git
cd ai-security-skill

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
npx ai-security-skill init

# 2. Scan workspace (runs profiling, threat modeling, AST scanners, and updates report.md)
npx ai-security-skill scan

# 3. Check status of all security controls checklist
npx ai-security-skill status

# 4. Evaluate findings against the security policy gate
npx ai-security-skill gate
```

---

## 6. CLI Usage

The `ai-security-skill` binary supports the following subcommands:

- `init`: Creates `.security/` state layout.
- `discover`: Scans files and prints JSON representation of the stack.
- `requirements`: Returns applicable security requirement lists in YAML.
- `threat-model`: Outputs a custom threat model in YAML.
- `review-change --description=<desc>`: Assesses a proposed change (e.g. adding payment checkouts) and returns required controls, threats, and test recommendations.
- `scan [--changed]`: Runs local analyzers and automatically updates `.security/report.md` (and threat model).
- `findings`: Lists all open security findings.
- `explain [finding-id]`: Prints analysis, attack scenarios, and required fixes for a finding.
- `gate`: Evaluates findings against policy. Exits `0` on PASS, `1` on BLOCK.
- `report`: Compiles a detailed markdown audit report to `.security/report.md`.
- `status`: Show security state checklist including evaluated controls.

---

## 7. Model Context Protocol (MCP) Integration

Expose all capabilities of the control plane directly to your AI editor (Cursor, Windsurf, Claude Code) by adding the following configuration to your MCP settings (`mcp_config.json`):

```json
{
  "mcpServers": {
    "ai-security-skill": {
      "command": "node",
      "args": ["/absolute/path/to/ai-security-skill/dist/mcp/server.js"],
      "env": {}
    }
  }
}
```

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
unknown:
  critical: block
  high: block
  medium: warn
  low: allow
```

If any critical/high findings are open, or if an applicable control remains in an `UNKNOWN` state (for critical/high categories), `ai-security-skill gate` will block the commit/deployment.

---

## 9. Supported Scanners

1. **Taint Analysis Engine**: Syntactically traces untrusted user request inputs (e.g., body parameters, API query strings) to sensitive execution sinks. Specifically evaluates e-commerce checkout routes to verify that payments are constructed using database-derived product pricing rather than client-supplied amounts (`BL-001`).
2. **Built-in AST Engine**: Evaluates:
   - IDOR / BOLA (database queries without session filters)
   - Prompt Injection paths (interpolation in LLM instruction blocks)
   - SQL Injection (string templates in raw client statements)
   - OS Command Injection (shell interpolation in child_process.exec)
   - Weak JWT signature verify settings (allowing "none" algorithm)
   - AI agent tool catalog definitions (ensuring direct validation checks)
3. **External Adapters (Optional, Auto-detected)**:
   - **Gitleaks**: Secrets detection.
   - **Semgrep**: Advanced SAST scanning.
   - **npm audit**: Dependency scanning.
   - **osv-scanner**: Open Source Vulnerability checks.
   - **trivy**: Container and dependency scan.

---

## 10. Privacy & Data Handling

- **100% Offline**: All AST analysis, secret scans, dataflow tracing, and dependency parsing run locally.
- **No Telemetry**: No tracking identifiers, usage metrics, or source code are sent to external backends.

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
