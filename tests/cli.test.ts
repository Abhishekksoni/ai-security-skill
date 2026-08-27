import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const cliPath = path.join(projectRoot, 'dist/cli/index.js');
const tempRoot = path.join(projectRoot, 'tests/temp-projects');

describe('CLI Integration Tests', () => {
  before(async () => {
    // Compile project to ensure dist/cli/index.js is present and updated
    execSync('npm run build', { cwd: projectRoot });
    await fs.mkdir(tempRoot, { recursive: true });
  });

  after(async () => {
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  test('CLI prints help menu on unknown or help command', () => {
    const stdout = execSync(`node ${cliPath} help`, { encoding: 'utf8' });
    assert.match(stdout, /Agent Security Skill/i);
    assert.match(stdout, /Commands:/i);
  });

  test('init command bootstraps .security directory in fresh project', async () => {
    const testDir = path.join(tempRoot, 'fresh-project');
    await fs.mkdir(testDir, { recursive: true });

    const stdout = execSync(`node ${cliPath} init --root=${testDir}`, { encoding: 'utf8' });
    assert.match(stdout, /Initialized/);

    const securityDir = path.join(testDir, '.security');
    const policyFile = path.join(securityDir, 'policy.yaml');
    const stateFile = path.join(securityDir, 'state.json');

    assert.ok(await fs.stat(securityDir).then(s => s.isDirectory()));
    assert.ok(await fs.stat(policyFile).then(s => s.isFile()));
    assert.ok(await fs.stat(stateFile).then(s => s.isFile()));
  });

  test('init on existing .security project preserves configuration', async () => {
    const testDir = path.join(tempRoot, 'existing-security-project');
    await fs.mkdir(testDir, { recursive: true });

    // Run init first
    execSync(`node ${cliPath} init --root=${testDir}`);
    const policyPath = path.join(testDir, '.security/policy.yaml');
    
    // Write custom rule to policy
    const customPolicy = 'blockOn:\n  - critical\nrequiredRules:\n  - SECRET-001\n';
    await fs.writeFile(policyPath, customPolicy, 'utf8');

    // Run init again
    execSync(`node ${cliPath} init --root=${testDir}`);

    // Verify it was not overwritten
    const currentPolicy = await fs.readFile(policyPath, 'utf8');
    assert.strictEqual(currentPolicy, customPolicy);
  });

  test('scan command executes successfully on clean project and reports 0 findings', async () => {
    const testDir = path.join(tempRoot, 'clean-project');
    await fs.mkdir(testDir, { recursive: true });
    
    // Write safe code
    await fs.writeFile(path.join(testDir, 'package.json'), '{}', 'utf8');
    await fs.writeFile(path.join(testDir, 'index.ts'), 'console.log("hello world");', 'utf8');

    const stdout = execSync(`node ${cliPath} scan --root=${testDir}`, { encoding: 'utf8' });
    assert.match(stdout, /Findings: 0/);
  });

  test('scan command finds vulnerabilities on vulnerable project', async () => {
    const testDir = path.join(tempRoot, 'vulnerable-project');
    await fs.mkdir(testDir, { recursive: true });

    // Write package.json referencing OpenAI to trigger AI checks, but missing auth configuration
    await fs.writeFile(
      path.join(testDir, 'package.json'),
      JSON.stringify({ dependencies: { 'openai': '^4.0.0' } }),
      'utf8'
    );
    // Write code containing eval usage
    await fs.writeFile(
      path.join(testDir, 'index.ts'),
      'eval(process.argv[2]);',
      'utf8'
    );

    const stdout = execSync(`node ${cliPath} scan --root=${testDir}`, { encoding: 'utf8' });
    
    // Should flag missing authentication (AUTH-001) due to AI context and missing auth provider
    assert.match(stdout, /AUTH-001/);
    // Should flag eval code execution (INJ-001)
    assert.match(stdout, /INJ-001/);
  });

  test('gate command returns 0 on clean project and 1 on blocked/vulnerable project', async () => {
    const cleanDir = path.join(tempRoot, 'clean-gate-project');
    await fs.mkdir(cleanDir, { recursive: true });
    await fs.writeFile(path.join(cleanDir, 'package.json'), '{}', 'utf8');
    await fs.writeFile(path.join(cleanDir, 'index.ts'), 'console.log("clean");', 'utf8');

    // Run scan to generate findings.json first
    execSync(`node ${cliPath} scan --root=${cleanDir}`);
    
    // Gate should pass (exit code 0)
    let cleanExitCode = 0;
    try {
      execSync(`node ${cliPath} gate --root=${cleanDir}`);
    } catch (err: any) {
      cleanExitCode = err.status;
    }
    assert.strictEqual(cleanExitCode, 0);

    const vulnDir = path.join(tempRoot, 'vulnerable-gate-project');
    await fs.mkdir(vulnDir, { recursive: true });
    await fs.writeFile(path.join(vulnDir, 'package.json'), '{}', 'utf8');
    await fs.writeFile(path.join(vulnDir, 'index.ts'), 'eval(x);', 'utf8');

    // Run scan to populate findings
    execSync(`node ${cliPath} scan --root=${vulnDir}`);

    // Gate should block (exit code 1)
    let vulnExitCode = 0;
    try {
      execSync(`node ${cliPath} gate --root=${vulnDir}`);
    } catch (err: any) {
      vulnExitCode = err.status;
    }
    assert.strictEqual(vulnExitCode, 1);
  });

  test('explain command returns code 2 on missing or wrong finding ID', async () => {
    let exitCodeNoId = 0;
    try {
      execSync(`node ${cliPath} explain`, { stdio: 'pipe' });
    } catch (err: any) {
      exitCodeNoId = err.status;
    }
    assert.strictEqual(exitCodeNoId, 2);

    let exitCodeInvalidId = 0;
    try {
      execSync(`node ${cliPath} explain NON-EXISTENT-ID`, { stdio: 'pipe' });
    } catch (err: any) {
      exitCodeInvalidId = err.status;
    }
    assert.strictEqual(exitCodeInvalidId, 2);
  });
});
