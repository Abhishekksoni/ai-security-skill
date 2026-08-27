import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import path from 'node:path';
import { getContext, getRequirements, generateThreatModel, init, scan, gate, reviewChange, securityPaths } from '../core/engine.js';
import { readJson } from '../core/fs.js';
import type { Finding } from '../core/types.js';

const server = new McpServer({ name: 'agent-security-skill', version: '0.1.0' });

const rootSchema = { root: z.string().optional() };
const resolveRoot = (root?: string) => path.resolve(root ?? process.cwd());

server.registerTool('security_initialize', {
  description: 'Initialize the project security control plane.',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  await init(r);
  return { content: [{ type: 'text', text: `✓ Initialized .security/ at ${r}` }] };
});

server.registerTool('security_context', {
  description: 'Return the discovered security context (stack, databases, auth providers, etc.).',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  const context = await getContext(r);
  return { content: [{ type: 'text', text: JSON.stringify(context, null, 2) }] };
});

server.registerTool('security_requirements', {
  description: 'Return the active security requirements derived from the project context.',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  const requirements = await getRequirements(r);
  return { content: [{ type: 'text', text: JSON.stringify(requirements, null, 2) }] };
});

server.registerTool('security_review_change', {
  description: 'Assess proposed changes or feature additions before implementation and return required security controls.',
  inputSchema: {
    root: z.string().optional(),
    type: z.string().optional(),
    path: z.string().optional(),
    description: z.string().optional()
  }
}, async ({ root, type, path: targetPath, description }) => {
  const result = reviewChange({ type, path: targetPath, description });
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

server.registerTool('security_threat_model', {
  description: 'Generate or return the baseline threat model in YAML format.',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  const threatModelYaml = await generateThreatModel(r);
  return { content: [{ type: 'text', text: threatModelYaml }] };
});

server.registerTool('security_scan', {
  description: 'Run all local security scans (built-in AST checks and external adapters).',
  inputSchema: {
    root: z.string().optional(),
    changed: z.boolean().optional()
  }
}, async ({ root, changed }) => {
  const r = resolveRoot(root);
  const findings = await scan(r, { changedOnly: changed });
  return { content: [{ type: 'text', text: JSON.stringify(findings, null, 2) }] };
});

server.registerTool('security_findings', {
  description: 'List all open/active security findings.',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  const p = securityPaths(r);
  const findings = await readJson<Finding[]>(p.findings, []);
  const openFindings = findings.filter(f => f.status === 'open');
  return { content: [{ type: 'text', text: JSON.stringify(openFindings, null, 2) }] };
});

server.registerTool('security_explain_finding', {
  description: 'Provide detailed reasoning, attack scenarios, and remediation guides for a specific finding.',
  inputSchema: {
    root: z.string().optional(),
    findingId: z.string()
  }
}, async ({ root, findingId }) => {
  const r = resolveRoot(root);
  const p = securityPaths(r);
  const findings = await readJson<Finding[]>(p.findings, []);
  const finding = findings.find(f => f.id === findingId);
  if (!finding) {
    return { content: [{ type: 'text', text: `Error: Finding ${findingId} not found.` }] };
  }
  const explanation = `
Finding: ${finding.id} [${finding.severity.toUpperCase()}]
Title: ${finding.title}
Rule ID: ${finding.rule_id}
Location: ${finding.location?.file ?? 'unknown'}${finding.location?.line ? `:${finding.location.line}` : ''}
Status: ${finding.status}

Description:
${finding.description}

Attack Scenario:
${finding.attack_scenario ?? 'No explicit attack scenario provided.'}

Evidence:
${finding.evidence.join('\n')}

Remediation / Required Fix:
${finding.required_fix ?? 'Review finding details and check rule.'}
`;
  return { content: [{ type: 'text', text: explanation }] };
});

server.registerTool('security_gate', {
  description: 'Run the security policy gate check. Returns PASS/WARN/BLOCK status.',
  inputSchema: rootSchema
}, async ({ root }) => {
  const r = resolveRoot(root);
  const result = await gate(r);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

await serveStdio(() => server);
