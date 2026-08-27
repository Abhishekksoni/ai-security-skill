import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readYaml } from '../core/fs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageRoot = path.resolve(__dirname, '../..');

export interface SecurityFramework {
  id: string;
  name: string;
  version: string;
  sourceUrl: string;
  license: string;
}

export interface SecurityRequirement {
  id: string;
  frameworkId: string;
  title: string;
  description: string;
  category: string;
}

export class SecurityKnowledgeRegistry {
  private frameworks = new Map<string, SecurityFramework>();
  private requirements: SecurityRequirement[] = [];

  constructor() {}

  async initialize(customRoot?: string) {
    const root = customRoot || packageRoot;
    const frameworkIds = ['owasp-asvs', 'owasp-api', 'owasp-genai', 'nist-ssdf', 'cis'];
    
    for (const fid of frameworkIds) {
      const yamlPath = path.join(root, 'knowledge/frameworks', fid, 'requirements.yaml');
      const data = await readYaml<any>(yamlPath, null);
      if (data) {
        const framework: SecurityFramework = {
          id: data.id,
          name: data.name,
          version: data.version,
          sourceUrl: data.sourceUrl,
          license: data.license
        };
        this.frameworks.set(data.id, framework);
        
        if (Array.isArray(data.requirements)) {
          for (const req of data.requirements) {
            this.requirements.push({
              id: req.id,
              frameworkId: data.id,
              title: req.title,
              description: req.description,
              category: req.category
            });
          }
        }
      }
    }
  }

  getFramework(id: string): SecurityFramework | undefined {
    return this.frameworks.get(id);
  }

  getRequirements(): SecurityRequirement[] {
    return this.requirements;
  }

  findByCategory(category: string): SecurityRequirement[] {
    return this.requirements.filter(r => r.category === category);
  }
}
