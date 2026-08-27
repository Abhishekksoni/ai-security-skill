import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBuiltinScans } from '../src/scanners/builtin.js';
import type { ProjectContext } from '../src/core/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const mockContext = (subDir: string): ProjectContext => ({
  name: 'fixture-test',
  root: path.join(projectRoot, 'fixtures', subDir),
  type: 'web_application',
  stack: { frontend: ['nextjs'], backend: ['next'], database: ['postgresql'], detectedFiles: [] },
  authentication: { detected: true, providers: ['custom'] },
  ai: { detected: true, providers: ['openai'], frameworks: ['vercel-ai-sdk'] },
  database: { detected: true, systems: ['postgresql'] },
  entryPoints: [],
  sensitiveSignals: [],
  discoveredAt: new Date().toISOString()
});

test('vulnerable fixtures are detected correctly', async () => {
  const context = mockContext('vulnerable');
  const findings = await runBuiltinScans(context);
  console.log('VULNERABLE FINDINGS:', findings);

  const ruleIds = findings.map(f => f.rule_id);
  
  // Verify BOLA/IDOR detected
  assert.ok(ruleIds.includes('AUTHZ-001'), 'Should detect AUTHZ-001 IDOR');
  
  // Verify SQLi detected
  assert.ok(ruleIds.includes('INJ-003'), 'Should detect INJ-003 SQL injection');
  
  // Verify OS Command Injection detected
  assert.ok(ruleIds.includes('INJ-002'), 'Should detect INJ-002 OS command injection');
  
  // Verify Weak JWT validation detected
  assert.ok(ruleIds.includes('AUTH-002'), 'Should detect AUTH-002 weak JWT configuration');
  
  // Verify AI excessive agency or tool auth bypass detected
  assert.ok(ruleIds.includes('AI-005'), 'Should detect AI-005 tool authorization bypass');
  assert.ok(ruleIds.includes('AI-002'), 'Should detect AI-002 excessive tool agency');
  
  // Verify improper output handling detected
  assert.ok(ruleIds.includes('AI-004'), 'Should detect AI-004 improper output handling');
  
  // Verify prompt injection detected
  assert.ok(ruleIds.includes('AI-001'), 'Should detect AI-001 prompt injection');
});

test('secure fixtures are not falsely detected', async () => {
  const context = mockContext('secure');
  const findings = await runBuiltinScans(context);

  const ruleIds = findings.map(f => f.rule_id);
  
  // Secure versions should not trigger critical findings
  assert.ok(!ruleIds.includes('AUTHZ-001'), 'Should not flag secure IDOR code');
  assert.ok(!ruleIds.includes('INJ-003'), 'Should not flag secure SQL code');
  assert.ok(!ruleIds.includes('INJ-002'), 'Should not flag secure command spawn code');
  assert.ok(!ruleIds.includes('AUTH-002'), 'Should not flag secure JWT validation code');
  assert.ok(!ruleIds.includes('AI-005'), 'Should not flag secure AI tool code');
  assert.ok(!ruleIds.includes('AI-004'), 'Should not flag secure output parsing code');
  assert.ok(!ruleIds.includes('AI-001'), 'Should not flag secure prompt formatting code');
});
