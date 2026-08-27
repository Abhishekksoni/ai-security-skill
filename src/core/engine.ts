import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import YAML from 'yaml';
import { ensureDir, exists, readJson, writeJson, readYaml, writeYaml, writeText, readText } from './fs.js';
import { discoverProject } from './discovery.js';
import { loadRules, requirementsFor } from './rules.js';
import { runBuiltinScans } from '../scanners/builtin.js';
import { runOptionalExternalScans } from '../scanners/external.js';
import type { Finding, ProjectContext, SecurityPolicy, SecurityRequirement, SecurityState, Severity } from './types.js';

export const SECURITY_DIR = '.security';

export function securityPaths(root: string) {
  const base = path.join(root, SECURITY_DIR);
  return {
    base,
    context: path.join(base, 'context.yaml'),
    requirements: path.join(base, 'requirements.yaml'),
    threatModel: path.join(base, 'threat-model.yaml'),
    policy: path.join(base, 'policy.yaml'),
    findings: path.join(base, 'findings.json'),
    state: path.join(base, 'state.json'),
    scans: path.join(base, 'scans'),
    decisions: path.join(base, 'decisions')
  };
}

const defaultPolicy: SecurityPolicy = {
  blockOn: ['critical', 'high'],
  maxFindings: { medium: 5, low: 20 },
  requiredRules: ['SECRET-001', 'AUTHZ-001']
};

export async function init(root: string) {
  const p = securityPaths(root);
  await ensureDir(p.scans);
  await ensureDir(p.decisions);
  if (!(await exists(p.policy))) await writeYaml(p.policy, defaultPolicy);
  if (!(await exists(p.state))) {
    await writeJson(p.state, {
      version: '0.1',
      initializedAt: new Date().toISOString()
    } satisfies SecurityState);
  }
  if (!(await exists(p.findings))) await writeJson(p.findings, []);
}

export async function getContext(root: string): Promise<ProjectContext> {
  const p = securityPaths(root);
  const context = await discoverProject(root);
  await writeYaml(p.context, context);
  return context;
}

export async function getRequirements(root: string): Promise<SecurityRequirement[]> {
  const p = securityPaths(root);
  const context = await getContext(root);
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const rules = await loadRules(path.join(packageRoot, 'rules'));
  const requirements = requirementsFor(context, rules);
  await writeYaml(p.requirements, requirements);
  return requirements;
}

export async function generateThreatModel(root: string): Promise<string> {
  const p = securityPaths(root);
  const c = await getContext(root);
  
  // Build assets
  const assets = [
    { id: 'A001', name: 'User accounts & session profiles', sensitivity: 'high' },
    { id: 'A002', name: 'Application system configurations & secrets', sensitivity: 'critical' }
  ];
  if (c.database.detected) {
    assets.push({ id: 'A003', name: 'Database records', sensitivity: 'high' });
  }
  if (c.sensitiveSignals.includes('payments')) {
    assets.push({ id: 'A004', name: 'Payment transactions & gate tokens', sensitivity: 'critical' });
  }
  if (c.ai.detected) {
    assets.push({ id: 'A005', name: 'AI prompt instructions & system parameters', sensitivity: 'high' });
  }

  // Build actors
  const actors = [
    { id: 'U001', name: 'Anonymous internet user', trust_level: 'untrusted' }
  ];
  if (c.authentication.detected) {
    actors.push({ id: 'U002', name: 'Authenticated user', trust_level: 'trusted' });
  }

  // Build entry points
  const entryPoints = c.entryPoints.map((ep, i) => ({
    id: `E${String(i + 1).padStart(3, '0')}`,
    type: ep.kind,
    path: ep.path
  }));
  if (entryPoints.length === 0) {
    entryPoints.push({ id: 'E001', type: 'web_route', path: '/' });
  }

  // Build trust boundaries
  const trustBoundaries = [
    { id: 'TB001', from: 'Anonymous internet user', to: 'Application endpoints' }
  ];

  // Build threats
  const threats: any[] = [];
  let threatIdx = 1;
  const addThreat = (category: string, severity: string, asset: string, entry: string, note: string) => {
    threats.push({
      id: `T${String(threatIdx++).padStart(3, '0')}`,
      category,
      severity,
      asset,
      entry_point: entry,
      note
    });
  };

  if (c.database.detected) {
    addThreat('sql_injection', 'critical', 'A003', entryPoints[0].id, 'Verify inputs to database query methods parameterize arguments securely.');
  }
  if (c.authentication.detected) {
    addThreat('broken_access_control', 'critical', 'A001', entryPoints[0].id, 'Enforce strict resource ownership or role permissions on every route (prevent IDOR/BOLA).');
  }
  if (c.ai.detected) {
    addThreat('prompt_injection', 'high', 'A005', entryPoints[0].id, 'Isolate model system prompts from user controlled content and validate tool boundaries.');
    addThreat('excessive_agency', 'critical', 'A005', entryPoints[0].id, 'Ensure destructive model tools require explicit human confirmation.');
  }
  if (c.sensitiveSignals.includes('payments')) {
    addThreat('privilege_escalation', 'critical', 'A004', entryPoints[0].id, 'Validate payment-related operations with independent backend checks and signed webhooks.');
  }
  addThreat('credential_leakage', 'critical', 'A002', 'E001', 'Use environment secrets and prevent hardcoded access credentials in source code repositories.');

  const threatModelObj = {
    version: '1.0',
    application: {
      name: c.name,
      type: c.type
    },
    assets,
    actors,
    entry_points: entryPoints,
    trust_boundaries: trustBoundaries,
    threats
  };

  const yamlText = YAML.stringify(threatModelObj);
  await writeText(p.threatModel, yamlText);
  return yamlText;
}

export function reviewChange(change: { type?: string; path?: string; description?: string }) {
  const text = `${change.type ?? ''} ${change.path ?? ''} ${change.description ?? ''}`.toLowerCase();
  const requirements = new Set<string>(['SECRET-001']);
  const threats: string[] = [];
  const guidance: string[] = [];

  if (/auth|login|session|password|oauth|token/.test(text)) {
    requirements.add('AUTH-001');
    requirements.add('AUTH-002');
    requirements.add('AUTHZ-001');
    threats.push('credential abuse', 'session hijack', 'signature bypass');
    guidance.push('Authenticate server-side, validate JWT signatures strictly, and enforce authorization independently of client claims.');
  }
  if (/api|route|endpoint|webhook/.test(text)) {
    requirements.add('API-001');
    requirements.add('API-003');
    threats.push('unauthorized API access', 'rate-limit abuse', 'cross-origin attack');
    guidance.push('Validate request inputs, authenticate sensitive endpoints, apply rate-limits, and avoid overly broad CORS configurations.');
  }
  if (/db|database|sql|prisma|query|mongo|drizzle/.test(text)) {
    requirements.add('AUTHZ-001');
    requirements.add('AUTHZ-002');
    requirements.add('INJ-003');
    threats.push('sql injection', 'broken object-level authorization', 'cross-tenant data leakage');
    guidance.push('Use parameterized queries/ORM APIs, filter by tenant ID, and enforce resource ownership server-side.');
  }
  if (/upload|file|storage|image|document/.test(text)) {
    threats.push('malicious file upload', 'path traversal');
    guidance.push('Constrain file size/type, generate safe server-side names, isolate storage, and never trust client MIME or extensions.');
  }
  if (/ai|llm|agent|tool|rag|prompt/.test(text)) {
    requirements.add('AI-001');
    requirements.add('AI-002');
    requirements.add('AI-003');
    requirements.add('AI-004');
    requirements.add('AI-005');
    threats.push('prompt injection', 'excessive agency', 'indirect instruction injection', 'improper output handling', 'unauthorized tool calling');
    guidance.push('Validate tool arguments, authorize the acting user independently of the model, minimize tool permissions, protect prompts from leaking internals, and validate model outputs before execution.');
  }
  if (/payment|refund|transfer|delete|admin|role/.test(text)) {
    requirements.add('AUTHZ-001');
    requirements.add('API-001');
    threats.push('privilege escalation', 'unauthorized destructive action');
    guidance.push('Require explicit authorization and audit sensitive mutations; do not let user-controlled IDs or model output decide privileges.');
  }

  const isHigh = threats.some(t => /privilege|unauthorized|credential|injection|agency|bypass|leakage/.test(t));
  return {
    risk: isHigh ? ('high' as const) : threats.length ? ('medium' as const) : ('low' as const),
    requiredControls: [...requirements],
    threats,
    guidance
  };
}

export async function scan(root: string, options?: { changedOnly?: boolean }): Promise<Finding[]> {
  await init(root);
  const context = await getContext(root);
  await getRequirements(root);

  let fileFilter: string[] | undefined = undefined;
  if (options?.changedOnly) {
    try {
      const { execSync } = await import('node:child_process');
      const gitDiff = execSync('git diff --name-only', { cwd: root }).toString().trim().split('\n').filter(Boolean);
      const gitStatus = execSync('git status --porcelain', { cwd: root }).toString().trim().split('\n').filter(Boolean).map(line => line.slice(3).trim());
      fileFilter = [...new Set([...gitDiff, ...gitStatus])].map(f => path.resolve(root, f));
    } catch {
      // Graceful fallback to all files if not a git repo or git fails
    }
  }

  const builtin = await runBuiltinScans(context, fileFilter);
  const external = await runOptionalExternalScans(context.root);
  const findings = [...builtin, ...external];
  const p = securityPaths(root);
  const scanId = crypto.randomUUID();
  await writeJson(p.findings, findings);
  await writeJson(path.join(p.scans, `${scanId}.json`), { scanId, createdAt: new Date().toISOString(), findings });
  const state = await readJson<SecurityState>(p.state, { version: '0.1', initializedAt: new Date().toISOString() });
  state.lastScanAt = new Date().toISOString();
  state.scanId = scanId;
  await writeJson(p.state, state);
  return findings;
}

interface Decision {
  findingId?: string;
  ruleId?: string;
  expires?: string;
  approved: boolean;
}

async function loadDecisions(decisionsDir: string): Promise<Decision[]> {
  const decisions: Decision[] = [];
  if (!(await exists(decisionsDir))) return [];
  try {
    const files = await fs.readdir(decisionsDir);
    const mdFiles = files.filter(f => f.endsWith('.md'));
    for (const f of mdFiles) {
      const text = await readText(path.join(decisionsDir, f));
      if (!text) continue;
      
      const findingMatch = /finding[-_]id:\s*([^\s\n]+)/i.exec(text) || /finding:\s*([^\s\n]+)/i.exec(text);
      const ruleMatch = /rule[-_]id:\s*([^\s\n]+)/i.exec(text) || /rule:\s*([^\s\n]+)/i.exec(text);
      const expiresMatch = /expires?:\s*([^\s\n]+)/i.exec(text) || /expiration:\s*([^\s\n]+)/i.exec(text);
      const approved = /approved:\s*true/i.test(text) || /status:\s*approved/i.test(text) || /approval:\s*([^\n]+)/i.test(text);
      
      decisions.push({
        findingId: findingMatch?.[1]?.trim(),
        ruleId: ruleMatch?.[1]?.trim(),
        expires: expiresMatch?.[1]?.trim(),
        approved
      });
    }
  } catch {}
  return decisions;
}

function severityRank(s: Severity) {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const)[s];
}

export async function gate(root: string) {
  await init(root);
  const p = securityPaths(root);
  const policy = await readYaml<SecurityPolicy>(p.policy, defaultPolicy);
  let findings = await readJson<Finding[]>(p.findings, []);
  if (!findings.length) findings = await scan(root);
  
  // Apply decisions/exceptions
  const decisions = await loadDecisions(p.decisions);
  const now = new Date();
  
  findings = findings.map(f => {
    const matchingDecision = decisions.find(d => {
      if (!d.approved) return false;
      if (d.expires) {
        const exp = new Date(d.expires);
        if (isNaN(exp.getTime()) || exp < now) return false;
      }
      return (d.findingId && f.id === d.findingId) || (d.ruleId && f.rule_id === d.ruleId);
    });
    if (matchingDecision) {
      return { ...f, status: 'ignored' as const };
    }
    return f;
  });
  
  // Update stored findings to reflect ignored status
  await writeJson(p.findings, findings);
  
  const openFindings = findings.filter(f => f.status === 'open');
  const blocking = openFindings.filter(f => f.blocks || policy.blockOn.some(s => severityRank(f.severity) >= severityRank(s)));
  const counts = openFindings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  
  const overLimit = Object.entries(policy.maxFindings).some(([sev, max]) => (counts[sev] ?? 0) > (max ?? 0));
  const status: 'pass' | 'warn' | 'block' = blocking.length || overLimit ? 'block' : openFindings.length ? 'warn' : 'pass';
  
  const result = {
    status,
    counts,
    blockingFindings: blocking,
    requiredRules: policy.requiredRules ?? [],
    policy
  };
  
  const state = await readJson<SecurityState>(p.state, { version: '0.1', initializedAt: new Date().toISOString() });
  state.lastGateAt = new Date().toISOString();
  state.status = status;
  await writeJson(p.state, state);
  return result;
}

export async function generateReport(root: string): Promise<string> {
  const p = securityPaths(root);
  const context = await readYaml<ProjectContext>(p.context, {} as any);
  const reqs = await readYaml<SecurityRequirement[]>(p.requirements, []);
  const policy = await readYaml<SecurityPolicy>(p.policy, {} as any);
  const findings = await readJson<Finding[]>(p.findings, []);
  const state = await readJson<SecurityState>(p.state, {} as any);

  const openFindings = findings.filter(f => f.status === 'open');
  const ignoredFindings = findings.filter(f => f.status === 'ignored');

  const report = `# Security Audit Report - ${context.name ?? 'Project'}
Generated: ${new Date().toISOString()}
Security State Status: **${state.status?.toUpperCase() ?? 'UNKNOWN'}**

## 1. Project Context
- **Name**: ${context.name}
- **Project Type**: ${context.type}
- **Frontend Stack**: ${context.stack?.frontend?.join(', ') || 'none'}
- **Backend Stack**: ${context.stack?.backend?.join(', ') || 'none'}
- **Database Stack**: ${context.stack?.database?.join(', ') || 'none'}
- **Authentication**: ${context.authentication?.detected ? `Yes (via ${context.authentication.providers.join(', ')})` : 'No'}
- **AI Stack**: ${context.ai?.detected ? `Yes (providers: ${context.ai.providers.join(', ')}, frameworks: ${context.ai.frameworks.join(', ')})` : 'No'}

## 2. Security Gate Settings
- **Block on Severities**: ${policy.blockOn?.join(', ') || 'none'}
- **Maximum Warning Thresholds**: ${Object.entries(policy.maxFindings ?? {}).map(([k, v]) => `${k}=${v}`).join(', ') || 'none'}
- **Required Controls**: ${policy.requiredRules?.join(', ') || 'none'}

## 3. Active Security Requirements (${reqs.length})
${reqs.map(r => `- **${r.id}** [${r.severity.toUpperCase()}]: ${r.description}`).join('\n')}

## 4. Findings Summary
- **Open Findings**: ${openFindings.length}
- **Ignored Exceptions**: ${ignoredFindings.length}

### Open Findings (${openFindings.length})
${openFindings.length === 0 ? '_No open findings detected._' : openFindings.map(f => `
#### [${f.severity.toUpperCase()}] ${f.id}: ${f.title}
- **Rule ID**: ${f.rule_id}
- **Confidence**: ${f.confidence}
- **Source**: ${f.source}
- **Location**: \`${f.location?.file}${f.location?.line ? `:${f.location.line}` : ''}\`
- **Description**: ${f.description}
${f.attack_scenario ? `- **Attack Scenario**: ${f.attack_scenario}` : ''}
- **Evidence**:
  \`\`\`
  ${f.evidence.join('\n')}
  \`\`\`
- **Remediation**: ${f.required_fix || 'Review finding details.'}
`).join('\n')}

### Ignored Exceptions (${ignoredFindings.length})
${ignoredFindings.length === 0 ? '_No exceptions/ignored findings._' : ignoredFindings.map(f => `
- **${f.id}** (${f.rule_id}) at \`${f.location?.file}\` - Approved exception active.
`).join('\n')}
`;

  await writeText(path.join(p.base, 'report.md'), report);
  return report;
}
