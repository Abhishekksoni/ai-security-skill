import path from 'node:path';
import ts from 'typescript';
import { listFiles, readText } from '../core/fs.js';
import type { ProjectContext } from '../core/types.js';
import type { SecurityControl } from '../controls/registry.js';
import { TaintAnalyzer } from '../analyzers/taint.js';
import { AIAgentAnalyzer } from '../analyzers/ai_agent.js';

export interface VerificationResult {
  controlId: string;
  status: 'pass' | 'fail' | 'unknown';
  confidence: number;
  evidence: Array<{
    file: string;
    line?: number;
    type: string;
    description: string;
    evidence?: string[];
  }>;
}

export class VerificationEngine {
  private taintAnalyzer = new TaintAnalyzer();
  private aiAnalyzer = new AIAgentAnalyzer();

  constructor() {}

  async verify(
    context: ProjectContext,
    applicableControls: SecurityControl[],
    fileFilter?: string[]
  ): Promise<VerificationResult[]> {
    const results: VerificationResult[] = [];
    
    // List all files to scan
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

    const textFiles = files.filter(f => {
      const base = path.basename(f).toLowerCase();
      return (
        /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|java|json|yaml|yml|env|toml|sql|md|astro|svelte|vue|html)$/i.test(f) ||
        base === '.env' ||
        base.startsWith('.env.') ||
        base === 'env'
      );
    });
    const codeFiles = files.filter(f => /\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(f));

    // Initialize all applicable controls to UNKNOWN
    const controlResults = new Map<string, VerificationResult>();
    for (const ctrl of applicableControls) {
      controlResults.set(ctrl.id, {
        controlId: ctrl.id,
        status: 'unknown',
        confidence: 0.8,
        evidence: []
      });
    }

    // Run analyzers on files
    for (const file of codeFiles) {
      try {
        const raw = await readText(file);
        if (!raw) continue;
        const rel = path.relative(context.root, file);
        const sourceFile = ts.createSourceFile(file, raw, ts.ScriptTarget.Latest, true);

        // 1. Business Logic Taint Flow Scan (CTRL-BL-001)
        if (controlResults.has('CTRL-BL-001')) {
          const taintFlows = this.taintAnalyzer.analyze(sourceFile);
          const res = controlResults.get('CTRL-BL-001')!;
          
          if (taintFlows.length > 0) {
            res.status = 'fail';
            res.confidence = 0.95;
            for (const flow of taintFlows) {
              res.evidence.push({
                file: rel,
                line: flow.line,
                type: 'data-flow',
                description: `Client-controlled financial value reaches payment sink: ${flow.sink}`,
                evidence: flow.flow
              });
            }
          } else {
            // Check if Stripe/PayPal sinks exist and are verified secure (no taint flow, but present)
            const hasStripeSink = /stripe\.(paymentIntents|checkout)\.create/.test(raw) || /paymentIntents\.create/.test(raw);
            if (hasStripeSink && res.status !== 'fail') {
              res.status = 'pass';
              res.confidence = 0.9;
              res.evidence.push({
                file: rel,
                type: 'data-flow-secure',
                description: 'Validated server-side derived payment intent instantiation with no client-controlled price flow.'
              });
            }
          }
        }

        // 2. AI Agent Tool Validation (CTRL-AI-002)
        if (controlResults.has('CTRL-AI-002')) {
          const tools = this.aiAnalyzer.analyze(sourceFile);
          const res = controlResults.get('CTRL-AI-002')!;

          if (tools.length > 0) {
            let hasVulnerable = false;
            for (const tool of tools) {
              if (!tool.hasAuthCheck) {
                hasVulnerable = true;
                res.status = 'fail';
                res.confidence = 0.9;
                res.evidence.push({
                  file: rel,
                  line: tool.line,
                  type: 'ai-tool-bypass',
                  description: `AI Tool ${tool.name} lacks independent application authorization checks in tool declaration.`
                });
              }
            }

            if (!hasVulnerable && res.status !== 'fail') {
              res.status = 'pass';
              res.confidence = 0.85;
              res.evidence.push({
                file: rel,
                type: 'ai-tool-secure',
                description: 'All AI agent tool operations verify user sessions independently of LLM context.'
              });
            }
          }
        }

      } catch {}
    }

    return Array.from(controlResults.values());
  }
}
