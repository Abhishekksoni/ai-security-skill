import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { init, scan, gate, generateThreatModel } from './engine.js';

test('scan detects a dynamic execution primitive and hardcoded credential', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'agent-security-'));
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: {} }));
  await fs.writeFile(path.join(root, 'app.ts'), 'eval(input); const API_KEY = "secret-abcdefghijklm";');
  await init(root);
  const findings = await scan(root);
  assert.ok(findings.some(f => f.rule_id === 'INJ-001'));
  assert.ok(findings.some(f => f.rule_id === 'SECRET-001'));
});

test('gate blocks critical findings', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'agent-security-gate-'));
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: {} }));
  await fs.writeFile(path.join(root, 'app.ts'), 'eval(input); const API_KEY = "secret-abcdefghijklm";');
  await init(root);
  const result = await gate(root);
  assert.equal(result.status, 'block');
  assert.ok(result.blockingFindings.length >= 1);
});

test('findings sanitize sensitive environment variable values and secrets', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'agent-security-sanitize-'));
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: {} }));
  
  // Write a .env file with actual secret
  await fs.writeFile(path.join(root, '.env'), 'STRIPE_API_KEY="sk_live_12345678901234567890"\nDATABASE_URL=postgresql://user:pass@localhost:5432/db');
  
  // Write a code file with hardcoded secret
  await fs.writeFile(path.join(root, 'app.ts'), 'const myKey = "AKIA1234567890123456"; const pass = "super-secret-password-1234";');
  
  await init(root);
  const findings = await scan(root);
  
  // Ensure that no finding contains the actual secret/password values
  for (const f of findings) {
    for (const ev of f.evidence) {
      assert.ok(!ev.includes('sk_live_12345678901234567890'), 'Should not contain Stripe live key');
      assert.ok(!ev.includes('super-secret-password-1234'), 'Should not contain hardcoded secret');
      assert.ok(!ev.includes('AKIA1234567890123456'), 'Should not contain AWS access key');
      assert.ok(!ev.includes('user:pass'), 'Should not contain DB credentials');
    }
    assert.ok(!f.description.includes('sk_live_12345678901234567890'));
    assert.ok(!f.description.includes('super-secret-password-1234'));
  }
});

test('generateThreatModel includes detected file names but not raw secret values', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'agent-security-tm-'));
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: {} }));
  await fs.writeFile(path.join(root, '.env'), 'STRIPE_API_KEY="sk_live_12345678901234567890"');
  await init(root);
  await scan(root);
  
  const tmYaml = await generateThreatModel(root);
  assert.ok(tmYaml.includes('Detected in: .env'), 'Threat note should name the file (.env)');
  assert.ok(!tmYaml.includes('sk_live_12345678901234567890'), 'Threat note/model should not contain actual secret value');
});
