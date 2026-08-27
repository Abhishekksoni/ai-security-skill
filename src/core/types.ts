export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'open' | 'resolved' | 'ignored';

export interface ProjectContext {
  name: string;
  root: string;
  type: string;
  stack: {
    frontend: string[];
    backend: string[];
    database: string[];
    detectedFiles: string[];
  };
  authentication: { detected: boolean; providers: string[] };
  ai: { detected: boolean; providers: string[]; frameworks: string[] };
  database: { detected: boolean; systems: string[] };
  entryPoints: Array<{ kind: string; path: string }>;
  sensitiveSignals: string[];
  discoveredAt: string;
}

export interface SecurityRequirement {
  id: string;
  category: string;
  severity: Severity;
  description: string;
  blocking: boolean;
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  confidence: number;
  status: FindingStatus;
  source: string;
  location?: {
    file: string;
    line?: number;
    column?: number;
  };
  title: string;
  description: string;
  attack_scenario?: string;
  evidence: string[];
  required_fix?: string;
  blocks: boolean;
  createdAt: string;
}

export interface SecurityPolicy {
  blockOn: Severity[];
  maxFindings: Partial<Record<Severity, number>>;
  requiredRules: string[];
}

export interface SecurityState {
  version: string;
  initializedAt: string;
  lastScanAt?: string;
  lastGateAt?: string;
  scanId?: string;
  status?: 'pass' | 'warn' | 'block';
}
