import path from 'node:path';
import ts from 'typescript';
import { listFiles, readText } from '../core/fs.js';
import type { Finding, ProjectContext } from '../core/types.js';

function makeFinding(partial: Omit<Finding, 'createdAt'>): Finding {
  return { ...partial, createdAt: new Date().toISOString() };
}

export async function runBuiltinScans(context: ProjectContext, fileFilter?: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  let files: string[] = [];
  try {
    files = await listFiles(context.root);
    if (fileFilter) {
      const filterSet = new Set(fileFilter.map(f => path.resolve(context.root, f)));
      files = files.filter(f => filterSet.has(path.resolve(f)));
    }
  } catch {
    return [];
  }
  
  const textFiles = files.filter(f => /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|java|json|yaml|yml|env|toml|sql|md)$/i.test(f));
  const codeFiles = files.filter(f => /\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(f));

  // 1. Secrets Regex Scans
  const secretPatterns: Array<[RegExp, string]> = [
    [/AKIA[0-9A-Z]{16}/g, 'AWS access key format detected'],
    [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, 'Private key material detected'],
    [/(?:api[_-]?key|secret|token|password|session[_-]?secret)\s*[:=]\s*["'][^"'\n]{16,}["']/gi, 'Potential hardcoded credential detected']
  ];

  for (const file of textFiles) {
    try {
      const raw = await readText(file);
      if (!raw) continue;
      const rel = path.relative(context.root, file);
      
      // Don't scan lockfiles or built packages for secrets
      if (/package-lock\.json|yarn\.lock|pnpm-lock\.yaml|dist\/|build\//.test(rel)) continue;

      for (const [pattern, evidence] of secretPatterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(raw);
        if (match) {
          const line = raw.slice(0, match.index).split('\n').length;
          findings.push(makeFinding({
            id: `SECRET-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
            rule_id: 'SECRET-001',
            severity: 'critical',
            confidence: 0.85,
            status: 'open',
            title: 'Potential hardcoded secret',
            description: 'A credential-like value, API key, or private key appears in source code.',
            location: { file: rel, line },
            evidence: [evidence],
            required_fix: 'Move the secret to a secure environment variables configuration (.env file) or runtime secret manager.',
            source: 'builtin-secret-scan',
            blocks: true
          }));
          break;
        }
      }
    } catch {}
  }

  // 2. AST Code Analysis (using TypeScript Compiler API)
  for (const file of codeFiles) {
    try {
      const raw = await readText(file);
      if (!raw) continue;
      const rel = path.relative(context.root, file);

      const sourceFile = ts.createSourceFile(file, raw, ts.ScriptTarget.Latest, true);

      let hasDatabaseCall = false;
      let hasUserControlInput = false;
      let hasAuthCheck = false;
      let hasRateLimiting = false;
      let hasTenantFilter = false;

      function visit(node: ts.Node) {
        // Look for imports of rate-limiters
        if (ts.isImportDeclaration(node) || ts.isCallExpression(node)) {
          const text = node.getText(sourceFile);
          if (/rateLimit|limiter|rate-limit|express-rate-limit/i.test(text)) {
            hasRateLimiting = true;
          }
        }

        // Look for CORS config
        if (ts.isCallExpression(node)) {
          const text = node.getText(sourceFile);
          if (/cors\(/i.test(text) && (text.includes("origin: '*'") || text.includes("origin:\"*\""))) {
            const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
            findings.push(makeFinding({
              id: `CORS-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
              rule_id: 'API-003',
              severity: 'medium',
              confidence: 0.9,
              status: 'open',
              title: 'Insecure CORS configuration',
              description: 'CORS configuration allows wildcard origin ("*") which permits arbitrary external domains to interact with resources.',
              location: { file: rel, line },
              evidence: ['cors config with wildcard origin'],
              required_fix: 'Explicitly allow trusted origin domains, or avoid wildcard CORS when authorization credentials are used.',
              source: 'ast-sast',
              blocks: false
            }));
          }
        }

        // Look for property assignments checking tenant or user ID (e.g. where: { tenantId } or tenantId: session.tenantId)
        if (ts.isPropertyAssignment(node)) {
          const name = node.name.getText(sourceFile);
          if (/^(tenantId|orgId|organizationId|accountId)$/i.test(name)) {
            hasTenantFilter = true;
          }
        }

        // Detect Database Calls
        if (ts.isCallExpression(node)) {
          const expr = node.expression;
          let methodName = '';
          let objectName = '';
          
          if (ts.isPropertyAccessExpression(expr)) {
            methodName = expr.name.text;
            if (ts.isIdentifier(expr.expression)) {
              objectName = expr.expression.text;
            } else if (ts.isPropertyAccessExpression(expr.expression)) {
              objectName = expr.expression.name.text;
            }
          }

          if (/^(db|prisma|conn|query|client|mongoose|repo|schema)/i.test(objectName) || /^(query|\$queryRawUnsafe|find|update|delete|create|insert)/i.test(methodName)) {
            hasDatabaseCall = true;
          }

          // Check for SQL Injection (INJ-003)
          if (
            (objectName === 'db' && methodName === 'query') ||
            (objectName === 'prisma' && methodName === '$queryRawUnsafe') ||
            (objectName === 'conn' && (methodName === 'query' || methodName === 'execute')) ||
            (ts.isIdentifier(expr) && expr.text === 'queryRaw')
          ) {
            const firstArg = node.arguments[0];
            if (firstArg && ts.isTemplateExpression(firstArg)) {
              const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              findings.push(makeFinding({
                id: `SQLI-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                rule_id: 'INJ-003',
                severity: 'critical',
                confidence: 0.88,
                status: 'open',
                title: 'Potential SQL Injection',
                description: 'A raw SQL execution method is invoked using variable interpolation in a template string.',
                location: { file: rel, line },
                evidence: [firstArg.getText(sourceFile)],
                required_fix: 'Use parameterized queries (placeholders like ?, $1) or standard Prisma/ORM builder methods instead of dynamic string building.',
                source: 'ast-sast',
                blocks: true
              }));
            }
          }

          // Check for OS Command Injection (INJ-002)
          if (
            (objectName === 'child_process' || objectName === 'process') ||
            (ts.isIdentifier(expr) && (expr.text === 'exec' || expr.text === 'spawn' || expr.text === 'execSync'))
          ) {
            const firstArg = node.arguments[0];
            if (firstArg && (ts.isTemplateExpression(firstArg) || ts.isBinaryExpression(firstArg))) {
              const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              findings.push(makeFinding({
                id: `OSCMD-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                rule_id: 'INJ-002',
                severity: 'critical',
                confidence: 0.9,
                status: 'open',
                title: 'Potential OS Command Injection',
                description: 'Process execution command string is constructed dynamically with variables, which allows shell parameter injection.',
                location: { file: rel, line },
                evidence: [firstArg.getText(sourceFile)],
                required_fix: 'Execute command binaries directly without shell interpreters (shell: false) and pass dynamic parameters as arguments arrays.',
                source: 'ast-sast',
                blocks: true
              }));
            }
          }

          // Check for Weak JWT config (AUTH-002)
          if (methodName === 'verify' && (objectName === 'jwt' || objectName === 'jsonwebtoken')) {
            const optionsArg = node.arguments[2];
            if (optionsArg && ts.isObjectLiteralExpression(optionsArg)) {
              for (const prop of optionsArg.properties) {
                if (ts.isPropertyAssignment(prop) && prop.name.getText(sourceFile) === 'algorithms') {
                  const val = prop.initializer;
                  if (ts.isArrayLiteralExpression(val)) {
                    for (const el of val.elements) {
                      if (ts.isStringLiteral(el) && el.text.toLowerCase() === 'none') {
                        const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
                        findings.push(makeFinding({
                          id: `JWT-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                          rule_id: 'AUTH-002',
                          severity: 'critical',
                          confidence: 0.95,
                          status: 'open',
                          title: 'Weak JWT signature verification',
                          description: 'JWT verification options allow accepting the "none" algorithm, allowing attackers to bypass authentication.',
                          location: { file: rel, line },
                          evidence: ['algorithms: ["none"] configuration detected'],
                          required_fix: 'Enforce strong signature verification algorithms like RS256/HS256 and remove "none" option.',
                          source: 'ast-sast',
                          blocks: true
                        }));
                      }
                    }
                  }
                }
              }
            }
          }

          // Check for Prisma/ORM Mass Assignment (API-002)
          if (/^(update|create)$/.test(methodName)) {
            const arg = node.arguments[0];
            if (arg && ts.isObjectLiteralExpression(arg)) {
              for (const prop of arg.properties) {
                if (ts.isPropertyAssignment(prop) && prop.name.getText(sourceFile) === 'data') {
                  const dataVal = prop.initializer;
                  const text = dataVal.getText(sourceFile);
                  if (/^(req\.(body|params|query)|body)$/.test(text)) {
                    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
                    findings.push(makeFinding({
                      id: `MASS-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                      rule_id: 'API-002',
                      severity: 'high',
                      confidence: 0.8,
                      status: 'open',
                      title: 'Potential Mass Assignment Vulnerability',
                      description: 'Passing unfiltered user requests directly to database update or create calls can allow modification of protected system fields.',
                      location: { file: rel, line },
                      evidence: [node.getText(sourceFile)],
                      required_fix: 'Map input parameters explicitly or validate request bodies against schema validators (e.g. Zod) to restrict input values.',
                      source: 'ast-sast',
                      blocks: true
                    }));
                  }
                }
              }
            }
          }

          // Check for Improper LLM Output Handling (AI-004)
          if (/^(exec|eval|db\.query|prisma\.\$queryRawUnsafe)/.test(objectName + '.' + methodName) || (ts.isIdentifier(expr) && expr.text === 'eval')) {
            const firstArg = node.arguments[0];
            if (firstArg) {
              const argText = firstArg.getText(sourceFile);
              if (/llmResponse|aiOutput|modelText|completionText|response\.choices|message\.content/i.test(argText)) {
                const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
                findings.push(makeFinding({
                  id: `AIOUT-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                  rule_id: 'AI-004',
                  severity: 'critical',
                  confidence: 0.85,
                  status: 'open',
                  title: 'Improper LLM output execution',
                  description: 'Unstructured text output returned from AI model completion is directly fed into executable API contexts.',
                  location: { file: rel, line },
                  evidence: [node.getText(sourceFile)],
                  required_fix: 'Structure model responses using JSON mode or Tool schemas, and enforce rigid parameter validations before execution.',
                  source: 'ast-ai-security',
                  blocks: true
                }));
              }
            }
          }
        }

        // Detect User Inputs
        if (ts.isPropertyAccessExpression(node)) {
          const name = node.name.text;
          let objName = '';
          if (ts.isIdentifier(node.expression)) {
            objName = node.expression.text;
          }
          if (objName === 'params' || objName === 'query' || objName === 'body' || name === 'searchParams' || name === 'params' || name === 'query' || name === 'body') {
            hasUserControlInput = true;
          }
        }

        // Detect Auth Validation Check
        if (ts.isIdentifier(node)) {
          const name = node.text;
          if (/^(session|auth|user|role|token|userId|currentUser)$/i.test(name) || /^(authorize|checkPermission|ensureOwner|assertRole|hasRole)$/.test(name)) {
            hasAuthCheck = true;
          }
        }

        // Check for dynamic prompt building that could be Prompt Injection (AI-001)
        let isPromptVarOrFunc = false;
        if (ts.isVariableDeclaration(node)) {
          const name = node.name.getText(sourceFile);
          if (/prompt|instruction|system/i.test(name)) {
            isPromptVarOrFunc = true;
          }
        } else if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
          const name = node.name?.getText(sourceFile) ?? '';
          if (/prompt|instruction|system/i.test(name)) {
            isPromptVarOrFunc = true;
          }
        } else if (ts.isPropertyAssignment(node)) {
          const name = node.name.getText(sourceFile);
          if (/content|prompt|instruction/i.test(name)) {
            isPromptVarOrFunc = true;
          }
        }

        if (isPromptVarOrFunc) {
          const text = node.getText(sourceFile);
          if (/input|query|userInput|userMessage/i.test(text) && (text.includes('`') || text.includes('+'))) {
            const hasXMLTags = /<\w+>[^<]*\${[^}]+}[^<]*<\/\w+>/.test(text) || text.includes('user_request') || text.includes('user_input') || text.includes('<user_request>');
            const hasSanitization = /\.replace|sanitize/i.test(text);
            if (!hasXMLTags && !hasSanitization) {
              const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              findings.push(makeFinding({
                id: `AIINJ-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                rule_id: 'AI-001',
                severity: 'high',
                confidence: 0.75,
                status: 'open',
                title: 'Potential Prompt Injection Vulnerability',
                description: 'Model instructions are combined with unvalidated user message variables, creating injection paths.',
                location: { file: rel, line },
                evidence: [text.slice(0, 200)],
                required_fix: 'Delineate user content strictly in system prompts (e.g. delimiters like XML tags) or configure model variables securely.',
                source: 'ast-ai-security',
                blocks: true
              }));
            }
          }
        }

        // Check for AI Tool Excessive Agency & Tool Auth (AI-002 & AI-005)
        if (ts.isObjectLiteralExpression(node)) {
          const text = node.getText(sourceFile);
          if (/(delete|remove|refund|transfer|send_email|sendEmail)/i.test(text) && /(tool|function|agent|assistant|description)/i.test(text)) {
            // Clean comments to avoid false passes
            const cleanText = text.replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');
            if (!cleanText.includes('auth') && !cleanText.includes('session') && !cleanText.includes('checkPermission') && !cleanText.includes('userId') && !cleanText.includes('role')) {
              const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              findings.push(makeFinding({
                id: `AIAUT-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                rule_id: 'AI-005',
                severity: 'critical',
                confidence: 0.8,
                status: 'open',
                title: 'Potential AI Tool Authorization Flaw',
                description: 'Exposing powerful or destructive tool actions to AI model selection without direct authorization checks.',
                location: { file: rel, line },
                evidence: [text.slice(0, 150) + '...'],
                required_fix: 'Ensure the tool implementation independently validates the user session authorization context before applying mutations.',
                source: 'ast-ai-security',
                blocks: true
              }));
              
              findings.push(makeFinding({
                id: `AIAGC-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
                rule_id: 'AI-002',
                severity: 'critical',
                confidence: 0.8,
                status: 'open',
                title: 'AI Excessive Agency',
                description: 'AI tool catalog grants direct destructive mutation privileges without intermediate human confirmation checks.',
                location: { file: rel, line },
                evidence: [text.slice(0, 150) + '...'],
                required_fix: 'Introduce human approval confirmation prompts on high-impact tools.',
                source: 'ast-ai-security',
                blocks: true
              }));
            }
          }
        }

        ts.forEachChild(node, visit);
      }

      visit(sourceFile);

      // Flag IDOR/BOLA (AUTHZ-001)
      const isApiOrRoute = /\b(api|routes|handlers|idor|tenant|bola)\b/i.test(rel) || rel.includes('route.ts') || rel.includes('route.js');
      if (isApiOrRoute && hasDatabaseCall && hasUserControlInput && !hasAuthCheck) {
        findings.push(makeFinding({
          id: `IDOR-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
          rule_id: 'AUTHZ-001',
          severity: 'critical',
          confidence: 0.85,
          status: 'open',
          title: 'Missing server-side resource authorization (BOLA/IDOR)',
          description: 'API endpoint updates or queries the database using user-controlled parameters without session authorization checks.',
          location: { file: rel },
          evidence: ['Database query + request inputs with no active user session validation'],
          required_fix: 'Obtain authenticated user session context (e.g. auth().userId or req.user.id) and verify the ownership of target objects.',
          source: 'ast-semantic',
          blocks: true
        }));
      }

      // Flag Missing Tenant Isolation (AUTHZ-002)
      if (isApiOrRoute && hasDatabaseCall && hasUserControlInput && context.type === 'web_application' && !hasTenantFilter && hasAuthCheck) {
        findings.push(makeFinding({
          id: `TENANT-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
          rule_id: 'AUTHZ-002',
          severity: 'critical',
          confidence: 0.75,
          status: 'open',
          title: 'Potential missing tenant isolation',
          description: 'Multi-tenant database queries in API endpoints appear to lack active filtering by tenant/org identifier.',
          location: { file: rel },
          evidence: ['Database operation + session auth without tenant filter'],
          required_fix: 'Strictly include tenantId/orgId query limits in all select, update, and delete database transactions.',
          source: 'ast-semantic',
          blocks: true
        }));
      }

      // Flag Missing Rate Limiting on login/signup/auth (API-001)
      if (isApiOrRoute && /login|signup|auth|register|password/i.test(rel) && !hasRateLimiting) {
        findings.push(makeFinding({
          id: `RATE-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
          rule_id: 'API-001',
          severity: 'high',
          confidence: 0.8,
          status: 'open',
          title: 'Missing rate limiting middleware',
          description: 'Authentication or sensitive mutations endpoints lack rate-limiting middleware, exposing them to brute force or DoS attacks.',
          location: { file: rel },
          evidence: ['Auth/sensitive endpoint file with no rate-limiting configuration'],
          required_fix: 'Apply rate limiter middleware (e.g. express-rate-limit) on login and authentication mutation routes.',
          source: 'ast-semantic',
          blocks: false
        }));
      }

      // Flag eval() usage (INJ-001)
      if (/\b(eval|new Function)\s*\(/.test(raw)) {
        const idx = raw.search(/\b(eval|new Function)\s*\(/);
        const line = raw.slice(0, idx).split('\n').length;
        findings.push(makeFinding({
          id: `EVAL-${Buffer.from(rel).toString('hex').slice(0, 8)}`,
          rule_id: 'INJ-001',
          severity: 'high',
          confidence: 0.95,
          status: 'open',
          title: 'Dynamic code execution (eval)',
          description: 'Dynamic JS evaluation allows execution of arbitrary commands if inputs are control-influenced.',
          location: { file: rel, line },
          evidence: ['eval() or Function constructor detected'],
          required_fix: 'Avoid dynamic execution; parse strict formats (JSON) or use restricted safe parsing models.',
          source: 'ast-sast',
          blocks: true
        }));
      }

    } catch (e) {
      // Graceful parsing exception skip
    }
  }

  // 3. Environment Example literal password/keys (SECRET-002)
  try {
    const envExample = await readText(path.join(context.root, '.env.example'));
    if (envExample && /(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*(?!["']?\s*CHANGE_ME\s*["']?|["']?\s*["']?)(["']?[a-zA-Z0-9_\-]{8,40}["']?)/i.test(envExample)) {
      findings.push(makeFinding({
        id: 'CONFIG-ENV-001',
        rule_id: 'SECRET-002',
        severity: 'medium',
        confidence: 0.85,
        status: 'open',
        title: 'Example env template contains literal secrets',
        description: '.env.example templates should avoid exposing realistic credentials or configuration tokens.',
        location: { file: '.env.example' },
        evidence: ['Literal secret assignment detected in template config'],
        required_fix: 'Replace realistic credentials in env templates with CHANGE_ME placeholders or empty string targets.',
        source: 'builtin-config',
        blocks: false
      }));
    }
  } catch {}

  // 5. Missing App Authentication for AI-enabled project (AUTH-001)
  if (context.ai.detected && !context.authentication.detected) {
    findings.push(makeFinding({
      id: 'AI-AUTH-001',
      rule_id: 'AUTH-001',
      severity: 'high',
      confidence: 0.9,
      status: 'open',
      title: 'AI project missing authentication provider',
      description: 'The codebase exposes AI generative APIs or frameworks but lacks any detected auth provider configuration.',
      evidence: ['AI stack detected', 'No auth libraries or custom password/session codes found'],
      required_fix: 'Secure the application by implementing user authentication (e.g. NextAuth, Clerk, Google OAuth) and restricting AI routes.',
      source: 'builtin-architecture',
      blocks: true
    }));
  }

  return findings;
}
