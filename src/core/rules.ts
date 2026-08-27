import { readText } from './fs.js';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { SecurityRequirement, Severity, ProjectContext } from './types.js';

export interface RuleDefinition {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  blocking: boolean;
  description?: string;
}

async function getJsonFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...await getJsonFiles(full));
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        files.push(full);
      }
    }
  } catch {}
  return files;
}

export async function loadRules(rulesDir: string): Promise<RuleDefinition[]> {
  const allRules: RuleDefinition[] = [];
  const files = await getJsonFiles(rulesDir);
  
  // Also check if rulesDir itself is a JSON file (for backward compatibility / direct file tests)
  if (rulesDir.endsWith('.json')) {
    const raw = await readText(rulesDir);
    if (raw) {
      const parsed = JSON.parse(raw) as { rules: RuleDefinition[] };
      return parsed.rules ?? [];
    }
  }

  for (const f of files) {
    try {
      const raw = await readText(f);
      if (raw) {
        const parsed = JSON.parse(raw) as { rules: RuleDefinition[] };
        if (parsed.rules) {
          allRules.push(...parsed.rules);
        }
      }
    } catch {}
  }
  return allRules;
}

export function requirementsFor(context: ProjectContext, rules: RuleDefinition[]): SecurityRequirement[] {
  return rules
    .filter(rule => {
      // AI rules only apply if AI stack is detected
      if (rule.id.startsWith('AI-')) return context.ai.detected;
      
      // Auth rules only apply to non-trivial projects or if authentication is explicitly detected
      if (rule.id === 'AUTH-001' || rule.id === 'AUTH-002') {
        return context.authentication.detected || context.type !== 'software_project';
      }
      if (rule.id === 'AUTHZ-001' || rule.id === 'AUTHZ-002') {
        return context.authentication.detected || context.type !== 'software_project';
      }
      
      // Database specific rules only apply if database stack is detected
      if (rule.id === 'INJ-003' || rule.id === 'AUTHZ-002') {
        return context.database.detected;
      }
      
      return true;
    })
    .map(rule => ({
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      blocking: rule.blocking,
      description: rule.description ?? rule.name
    }));
}
