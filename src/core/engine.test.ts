import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { init, scan, gate } from './engine.js';

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
