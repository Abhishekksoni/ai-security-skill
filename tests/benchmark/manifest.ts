import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const casesRoot = path.join(__dirname, 'cases');

export interface BenchmarkCase {
  id: string;
  ruleId: string;
  expected: 'vuln' | 'secure';
  filePath: string;
  contextOverrides?: any;
}

export const benchmarkCases: BenchmarkCase[] = [
  // AUTH-001: Missing app authentication for AI-enabled project
  {
    id: 'auth_001_vuln',
    ruleId: 'AUTH-001',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'auth/auth_001_vuln.ts'),
    contextOverrides: {
      ai: { detected: true, providers: ['openai'], frameworks: ['vercel-ai-sdk'] },
      authentication: { detected: false, providers: [] }
    }
  },
  {
    id: 'auth_001_secure',
    ruleId: 'AUTH-001',
    expected: 'secure',
    filePath: path.join(casesRoot, 'auth/auth_001_secure.ts'),
    contextOverrides: {
      ai: { detected: true, providers: ['openai'], frameworks: ['vercel-ai-sdk'] },
      authentication: { detected: true, providers: ['custom'] }
    }
  },

  // AUTH-002: Weak JWT signature validation
  {
    id: 'auth_002_vuln',
    ruleId: 'AUTH-002',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'auth/auth_002_vuln.ts')
  },
  {
    id: 'auth_002_secure',
    ruleId: 'AUTH-002',
    expected: 'secure',
    filePath: path.join(casesRoot, 'auth/auth_002_secure.ts')
  },

  // AUTHZ-001: Missing server-side resource authorization (IDOR/BOLA)
  {
    id: 'authz_001_idor_vuln',
    ruleId: 'AUTHZ-001',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'authz/api/idor_vuln.ts')
  },
  {
    id: 'authz_001_idor_secure',
    ruleId: 'AUTHZ-001',
    expected: 'secure',
    filePath: path.join(casesRoot, 'authz/api/idor_secure.ts')
  },

  // AUTHZ-002: Missing tenant isolation
  {
    id: 'authz_002_tenant_vuln',
    ruleId: 'AUTHZ-002',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'authz/api/tenant_vuln.ts'),
    contextOverrides: {
      type: 'web_application'
    }
  },
  {
    id: 'authz_002_tenant_secure',
    ruleId: 'AUTHZ-002',
    expected: 'secure',
    filePath: path.join(casesRoot, 'authz/api/tenant_secure.ts'),
    contextOverrides: {
      type: 'web_application'
    }
  },

  // INJ-001: Dynamic JavaScript code execution (eval)
  {
    id: 'inj_001_eval_vuln',
    ruleId: 'INJ-001',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'injection/inj_001_vuln.ts')
  },
  {
    id: 'inj_001_eval_secure',
    ruleId: 'INJ-001',
    expected: 'secure',
    filePath: path.join(casesRoot, 'injection/inj_001_secure.ts')
  },

  // INJ-002: OS command injection
  {
    id: 'inj_002_os_vuln',
    ruleId: 'INJ-002',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'injection/inj_002_vuln.ts')
  },
  {
    id: 'inj_002_os_secure',
    ruleId: 'INJ-002',
    expected: 'secure',
    filePath: path.join(casesRoot, 'injection/inj_002_secure.ts')
  },

  // INJ-003: SQL Injection
  {
    id: 'inj_003_sql_vuln',
    ruleId: 'INJ-003',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'injection/inj_003_vuln.ts')
  },
  {
    id: 'inj_003_sql_secure',
    ruleId: 'INJ-003',
    expected: 'secure',
    filePath: path.join(casesRoot, 'injection/inj_003_secure.ts')
  },

  // SECRET-001: Hardcoded secret detection
  {
    id: 'secret_001_key_vuln',
    ruleId: 'SECRET-001',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'secrets/secret_001_vuln.ts')
  },
  {
    id: 'secret_001_key_secure',
    ruleId: 'SECRET-001',
    expected: 'secure',
    filePath: path.join(casesRoot, 'secrets/secret_001_secure.ts')
  },

  // SECRET-002: Literal credentials in config templates
  {
    id: 'secret_002_env_vuln',
    ruleId: 'SECRET-002',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'secrets/vuln_env/.env.example')
  },
  {
    id: 'secret_002_env_secure',
    ruleId: 'SECRET-002',
    expected: 'secure',
    filePath: path.join(casesRoot, 'secrets/secure_env/.env.example')
  },

  // AI-001: Prompt injection vulnerability
  {
    id: 'ai_001_prompt_vuln',
    ruleId: 'AI-001',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'ai/ai_001_vuln.ts')
  },
  {
    id: 'ai_001_prompt_secure',
    ruleId: 'AI-001',
    expected: 'secure',
    filePath: path.join(casesRoot, 'ai/ai_001_secure.ts')
  },

  // AI-002: Excessive agency in tools configuration & AI-005: Tool authorization bypass
  {
    id: 'ai_002_tool_vuln',
    ruleId: 'AI-002',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'ai/ai_002_vuln.ts')
  },
  {
    id: 'ai_002_tool_secure',
    ruleId: 'AI-002',
    expected: 'secure',
    filePath: path.join(casesRoot, 'ai/ai_002_secure.ts')
  },
  {
    id: 'ai_005_tool_vuln',
    ruleId: 'AI-005',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'ai/ai_002_vuln.ts')
  },
  {
    id: 'ai_005_tool_secure',
    ruleId: 'AI-005',
    expected: 'secure',
    filePath: path.join(casesRoot, 'ai/ai_002_secure.ts')
  },

  // AI-004: Improper output handling
  {
    id: 'ai_004_output_vuln',
    ruleId: 'AI-004',
    expected: 'vuln',
    filePath: path.join(casesRoot, 'ai/ai_004_vuln.ts')
  },
  {
    id: 'ai_004_output_secure',
    ruleId: 'AI-004',
    expected: 'secure',
    filePath: path.join(casesRoot, 'ai/ai_004_secure.ts')
  }
];
