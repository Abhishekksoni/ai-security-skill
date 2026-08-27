import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readYaml } from '../core/fs.js';
import type { ProjectContext } from '../core/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageRoot = path.resolve(__dirname, '../..');

export interface SecurityControl {
  id: string;
  name: string;
  category: string;
  mappedRequirements: string[];
  applicability: {
    any?: any[];
  };
  severityIfFailed: 'info' | 'low' | 'medium' | 'high' | 'critical';
  defaultPolicy: {
    block: boolean;
  };
}

export class SecurityControlRegistry {
  private controls: SecurityControl[] = [];

  constructor() {}

  async initialize(customRoot?: string) {
    const root = customRoot || packageRoot;
    const controlFiles = [
      'authentication/jwt.yaml',
      'authorization/idor.yaml',
      'authorization/tenancy.yaml',
      'injection/eval.yaml',
      'injection/cmd.yaml',
      'injection/sql.yaml',
      'secrets/hardcoded.yaml',
      'secrets/template.yaml',
      'business-logic/bl_001.yaml',
      'ai/agent_security.yaml'
    ];

    for (const cf of controlFiles) {
      const yamlPath = path.join(root, 'controls', cf);
      const data = await readYaml<any>(yamlPath, null);
      if (data) {
        this.controls.push({
          id: data.id,
          name: data.name,
          category: data.category,
          mappedRequirements: data.mapped_requirements ?? [],
          applicability: data.applicability ?? {},
          severityIfFailed: data.severity_if_failed ?? 'high',
          defaultPolicy: data.default_policy ?? { block: false }
        });
      }
    }
  }

  getControls(): SecurityControl[] {
    return this.controls;
  }

  evaluateApplicability(context: ProjectContext, threatModel?: any): SecurityControl[] {
    return this.controls.filter(control => {
      const anyExprs = control.applicability.any;
      if (!anyExprs || anyExprs.length === 0) return true;

      // Evaluate any-expressions
      return anyExprs.some(expr => {
        if (expr === 'true' || expr === true) return true;
        if (expr === 'false' || expr === false) return false;
        if (typeof expr !== 'string') return false;

        // Custom evaluation logic matching simple properties:
        if (expr === 'project.payments.enabled == true') {
          // If project context indicates stripe/payments or has payments enabled
          const hasPayments = context.stack.backend.includes('stripe') || 
                              context.sensitiveSignals.includes('payments') ||
                              (context as any).payments?.enabled;
          return !!hasPayments;
        }

        if (expr === 'project.ai.detected == true') {
          return context.ai.detected;
        }

        if (expr === 'project.authentication.detected == true') {
          return context.authentication.detected;
        }

        if (expr === "project.type == 'web_application'") {
          return context.type === 'web_application';
        }

        if (expr === 'project.stack.database.length > 0') {
          return context.database.detected || context.stack.database.length > 0;
        }

        if (expr === 'project.database.detected == true') {
          return context.database.detected;
        }

        if (expr.startsWith("project.stack.backend.includes")) {
          const match = /'([^']+)'/.exec(expr);
          if (match) {
            const pkg = match[1];
            return context.stack.backend.includes(pkg);
          }
        }

        if (expr.startsWith("project.authentication.providers.includes")) {
          const match = /'([^']+)'/.exec(expr);
          if (match) {
            const provider = match[1];
            return context.authentication.providers.includes(provider);
          }
        }

        return false;
      });
    });
  }
}
