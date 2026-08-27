#!/usr/bin/env node
import path from 'node:path';
import { exists, readJson } from '../core/fs.js';
import { getContext, getRequirements, generateThreatModel, init, scan, gate, reviewChange, generateReport, getVerificationStates } from '../core/engine.js';
import type { Finding } from '../core/types.js';

const args = process.argv.slice(2);
const command = args[0] ?? 'help';

// Find root options
const rootArg = args.find((a: string) => a.startsWith('--root='))?.slice(7);
const root = path.resolve(rootArg ?? process.cwd());

const print = (v: unknown) => console.log(typeof v === 'string' ? v : JSON.stringify(v, null, 2));

async function main() {
  switch (command) {
    case 'init':
      await init(root);
      console.log(`✓ Initialized ${path.join(root, '.security')}`);
      break;

    case 'discover':
      print(await getContext(root));
      break;

    case 'requirements':
      print(await getRequirements(root));
      break;

    case 'review-change': {
      // Support flags: --type=x --path=y --description=z
      const typeOpt = args.find((a: string) => a.startsWith('--type='))?.slice(7);
      const pathOpt = args.find((a: string) => a.startsWith('--path='))?.slice(7);
      const descOpt = args.find((a: string) => a.startsWith('--description='))?.slice(14);
      
      let description = descOpt;
      if (!description) {
        // Fallback to positional parameters that don't start with --
        description = args.slice(1).filter((a: string) => !a.startsWith('--')).join(' ');
      }

      print(reviewChange({
        type: typeOpt,
        path: pathOpt,
        description
      }));
      break;
    }

    case 'threat-model':
      console.log(await generateThreatModel(root));
      break;

    case 'scan': {
      const changedOnly = args.includes('--changed');
      const findings = await scan(root, { changedOnly });
      const counts = findings.reduce<Record<string, number>>((a, f) => (a[f.severity] = (a[f.severity] ?? 0) + 1, a), {});
      
      console.log(`Scanned ${root}`);
      console.log(`Findings: ${findings.length}  ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(' ')}`);
      for (const f of findings) {
        const fileLoc = f.location?.file ? ` (${f.location.file}${f.location.line ? `:${f.location.line}` : ''})` : '';
        console.log(`${f.severity.toUpperCase()} ${f.rule_id} ${f.title}${fileLoc}`);
      }
      console.log(`\n✓ Generated threat-model and detailed report at ${path.join(root, '.security', 'report.md')}`);
      break;
    }

    case 'findings': {
      const p = path.join(root, '.security', 'findings.json');
      const findings = await readJson<Finding[]>(p, []);
      const openFindings = findings.filter(f => f.status === 'open');
      console.log(`Open findings: ${openFindings.length}`);
      for (const f of openFindings) {
        const fileLoc = f.location?.file ? ` (${f.location.file}${f.location.line ? `:${f.location.line}` : ''})` : '';
        console.log(`- [${f.severity.toUpperCase()}] ${f.id} (${f.rule_id}): ${f.title}${fileLoc}`);
      }
      break;
    }

    case 'explain': {
      const findingId = args[1];
      if (!findingId) {
        console.error('Error: Please specify a finding ID (e.g. explain FIND-001)');
        process.exitCode = 2;
        break;
      }
      const p = path.join(root, '.security', 'findings.json');
      const findings = await readJson<Finding[]>(p, []);
      const finding = findings.find(f => f.id === findingId);
      if (!finding) {
        console.error(`Error: Finding ${findingId} not found.`);
        process.exitCode = 2;
        break;
      }
      console.log(`\n==================================================`);
      console.log(`EXPLANATION: ${finding.id} [${finding.severity.toUpperCase()}]`);
      console.log(`==================================================`);
      console.log(`Title:       ${finding.title}`);
      console.log(`Rule ID:     ${finding.rule_id}`);
      console.log(`Source:      ${finding.source}`);
      console.log(`Confidence:  ${finding.confidence}`);
      console.log(`Status:      ${finding.status}`);
      if (finding.location) {
        console.log(`Location:    ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`);
      }
      console.log(`\nDescription:\n${finding.description}`);
      if (finding.attack_scenario) {
        console.log(`\nAttack Scenario:\n${finding.attack_scenario}`);
      }
      console.log(`\nEvidence:\n${finding.evidence.join('\n')}`);
      if (finding.required_fix) {
        console.log(`\nRequired Fix / Remediation:\n${finding.required_fix}`);
      }
      console.log(`==================================================\n`);
      break;
    }

    case 'gate': {
      try {
        const result = await gate(root);
        console.log(`SECURITY GATE: ${result.status.toUpperCase()}`);
        console.log(JSON.stringify({ counts: result.counts, requiredRules: result.requiredRules }, null, 2));
        if (result.blockingFindings.length) {
          console.log('\nBlocking findings:');
          for (const f of result.blockingFindings) {
            const fileLoc = f.location?.file ? ` (${f.location.file}:${f.location.line ?? ''})` : '';
            console.log(`- ${f.rule_id}: ${f.title}${fileLoc}`);
          }
          process.exitCode = 1;
        } else {
          process.exitCode = 0;
        }
      } catch (err) {
        console.error('Unexpected error in security gate:', err);
        process.exitCode = 3;
      }
      break;
    }

    case 'report': {
      const reportMarkdown = await generateReport(root);
      console.log(`✓ Generated security report at ${path.join(root, '.security', 'report.md')}`);
      break;
    }

    case 'status': {
      const p = path.join(root, '.security', 'state.json');
      const state = await readJson<any>(p, { status: 'uninitialized' });
      
      console.log('=== Project Security State ===');
      console.log(`Last Scan: ${state.lastScanAt ?? 'never'}`);
      console.log(`Last Gate Evaluation: ${state.lastGateAt ?? 'never'}`);
      console.log(`Overall Gate Status: ${state.status?.toUpperCase() ?? 'UNKNOWN'}`);
      console.log('');
      
      try {
        const verifications = await getVerificationStates(root);
        console.log('Checked Security Controls:');
        console.log('─────────────────────────────────────────────────────────────────');
        console.log('Control ID         Status      Name');
        console.log('─────────────────────────────────────────────────────────────────');
        for (const v of verifications) {
          const statusStr = v.status === 'PASS' ? '✔ PASS' : v.status === 'FAIL' ? '✘ FAIL' : '⚠ UNKNOWN';
          console.log(`${v.controlId.padEnd(18)} ${statusStr.padEnd(11)} ${v.name}`);
        }
        console.log('─────────────────────────────────────────────────────────────────');
      } catch (err) {
        console.error('Error fetching controls status:', err);
      }
      break;
    }

    case 'help':
    default:
      console.log(`Agent Security Skill v0.1.0

Commands:
  init              Initialize .security/
  discover          Detect stack and project signals
  requirements      Generate security requirements
  threat-model      Generate baseline threat model
  review-change     Assess risk levels of potential modifications
  scan              Run local security checks (--changed for modified files only)
  findings          List active findings
  explain [id]      Detailed analysis and remediation for finding ID
  gate              Evaluate security policy (exit 1 on block)
  report            Generate detailed Markdown audit report
  status            Show security state
  mcp               Run MCP server

Options:
  --root=/path/to/project`);
  }
}

main().catch(err => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 3;
});
