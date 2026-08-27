import { spawn } from 'node:child_process';
import type { Finding } from '../core/types.js';

interface Adapter {
  name: string;
  command: string;
  args: string[];
  parse: (stdout: string) => Finding[];
}

function run(adapter: Adapter, cwd: string): Promise<Finding[]> {
  return new Promise(resolve => {
    const child = spawn(adapter.command, adapter.args, { cwd, shell: false, stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.on('data', (d: any) => { out += d.toString(); });
    child.on('error', () => {
      // Graceful ignore of missing commands
      resolve([]);
    });
    child.on('close', () => {
      resolve(adapter.parse(out));
    });
  });
}

export async function runOptionalExternalScans(root: string): Promise<Finding[]> {
  const adapters: Adapter[] = [
    {
      name: 'semgrep',
      command: 'semgrep',
      args: ['scan', '--json', '--quiet', '.'],
      parse: out => {
        try {
          const j = JSON.parse(out);
          return (j.results ?? []).map((r: any, i: number) => ({
            id: `SEMGREP-${i + 1}`,
            rule_id: r.check_id ?? 'SEMGREP',
            severity: r.extra?.severity === 'ERROR' ? ('high' as const) : ('medium' as const),
            confidence: 0.9,
            status: 'open' as const,
            source: 'semgrep',
            title: r.extra?.message ?? r.check_id ?? 'Semgrep finding',
            description: r.extra?.message ?? 'Semgrep reported a finding.',
            location: {
              file: r.path,
              line: r.start?.line,
              column: r.start?.col
            },
            evidence: [r.extra?.lines ?? 'External SAST finding'],
            required_fix: r.extra?.metadata?.fix ?? 'Review the Semgrep finding.',
            blocks: r.extra?.severity === 'ERROR',
            createdAt: new Date().toISOString()
          }));
        } catch {
          return [];
        }
      }
    },
    {
      name: 'gitleaks',
      command: 'gitleaks',
      args: ['dir', '--report-format', 'json', '--redact', '.'],
      parse: out => {
        try {
          const rows = JSON.parse(out || '[]');
          return rows.map((r: any, i: number) => ({
            id: `GITLEAKS-${i + 1}`,
            rule_id: 'SECRET-001',
            severity: 'critical' as const,
            confidence: 0.98,
            status: 'open' as const,
            source: 'gitleaks',
            title: 'Secret detected by Gitleaks',
            description: r.Description ?? 'Gitleaks detected a secret in repository history or code files.',
            location: {
              file: r.File,
              line: r.StartLine
            },
            evidence: ['Gitleaks matching secret signature: ' + r.RuleID],
            required_fix: 'Remove the secret from code history and rotate the credential immediately.',
            blocks: true,
            createdAt: new Date().toISOString()
          }));
        } catch {
          return [];
        }
      }
    },
    {
      name: 'npm audit',
      command: 'npm',
      args: ['audit', '--json'],
      parse: out => {
        try {
          const j = JSON.parse(out);
          const findings: Finding[] = [];
          const vulns = j.vulnerabilities ?? {};
          let i = 1;
          for (const [pkgName, details] of Object.entries(vulns) as any) {
            findings.push({
              id: `NPMAUDIT-${i++}`,
              rule_id: 'DEP-001',
              severity: details.severity === 'critical' ? 'critical' : details.severity === 'high' ? 'high' : 'medium',
              confidence: 0.9,
              status: 'open' as const,
              source: 'npm-audit',
              title: `Dependency vulnerability in ${pkgName}`,
              description: `Known vulnerability in third-party dependency "${pkgName}" (installed range: ${details.range}).`,
              location: {
                file: 'package.json'
              },
              evidence: [`via: ${JSON.stringify(details.via)}`],
              required_fix: typeof details.fixAvailable === 'object' ? `Upgrade to version ${details.fixAvailable.name}@${details.fixAvailable.version}` : 'Run `npm audit fix` or upgrade package manually.',
              blocks: details.severity === 'critical' || details.severity === 'high',
              createdAt: new Date().toISOString()
            });
          }
          return findings;
        } catch {
          return [];
        }
      }
    },
    {
      name: 'osv-scanner',
      command: 'osv-scanner',
      args: ['--json', '.'],
      parse: out => {
        try {
          const j = JSON.parse(out);
          const findings: Finding[] = [];
          let i = 1;
          for (const res of (j.results ?? [])) {
            for (const pkg of (res.packages ?? [])) {
              for (const vuln of (pkg.vulnerabilities ?? [])) {
                findings.push({
                  id: `OSV-${i++}`,
                  rule_id: 'DEP-002',
                  severity: vuln.database_specific?.severity === 'CRITICAL' ? 'critical' : vuln.database_specific?.severity === 'HIGH' ? 'high' : 'medium',
                  confidence: 0.95,
                  status: 'open' as const,
                  source: 'osv-scanner',
                  title: vuln.summary ?? `Vulnerability in ${pkg.package.name}`,
                  description: vuln.details ?? `OSV-Scanner reported known vulnerability ${vuln.id} in ${pkg.package.name}@${pkg.package.version}.`,
                  location: {
                    file: res.source?.path ?? 'package.json'
                  },
                  evidence: [vuln.id],
                  required_fix: `Upgrade package ${pkg.package.name} to a secure version.`,
                  blocks: true,
                  createdAt: new Date().toISOString()
                });
              }
            }
          }
          return findings;
        } catch {
          return [];
        }
      }
    },
    {
      name: 'trivy',
      command: 'trivy',
      args: ['fs', '--format', 'json', '--quiet', '.'],
      parse: out => {
        try {
          const j = JSON.parse(out);
          const findings: Finding[] = [];
          let i = 1;
          for (const res of (j.Results ?? [])) {
            for (const vuln of (res.Vulnerabilities ?? [])) {
              findings.push({
                id: `TRIVY-${i++}`,
                rule_id: 'DEP-003',
                severity: vuln.Severity === 'CRITICAL' ? 'critical' : vuln.Severity === 'HIGH' ? 'high' : 'medium',
                confidence: 0.95,
                status: 'open' as const,
                source: 'trivy',
                title: vuln.Title ?? `Trivy finding in ${vuln.PkgName}`,
                description: vuln.Description ?? `Trivy reported vulnerability ${vuln.VulnerabilityID} in ${vuln.PkgName}@${vuln.InstalledVersion}.`,
                location: {
                  file: res.Target ?? 'package.json'
                },
                evidence: [vuln.VulnerabilityID],
                required_fix: vuln.FixedVersion ? `Upgrade to version ${vuln.FixedVersion}` : `Review security advisory for ${vuln.VulnerabilityID}.`,
                blocks: vuln.Severity === 'CRITICAL' || vuln.Severity === 'HIGH',
                createdAt: new Date().toISOString()
              });
            }
          }
          return findings;
        } catch {
          return [];
        }
      }
    }
  ];

  const findings: Finding[] = [];
  for (const adapter of adapters) {
    findings.push(...await run(adapter, root));
  }
  return findings;
}
