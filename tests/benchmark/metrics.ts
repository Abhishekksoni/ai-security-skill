export interface RuleStats {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  total: number;
}

export interface MetricResult {
  ruleId: string;
  total: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number; // 0.0 to 1.0
  recall: number;    // 0.0 to 1.0
  f1: number;        // 0.0 to 1.0
}

export interface OverallMetrics {
  ruleResults: MetricResult[];
  precision: number;
  recall: number;
  f1: number;
  weakRules: string[];
}

export function calculateMetrics(
  statsMap: Record<string, RuleStats>,
  weakThreshold: number = 0.8
): OverallMetrics {
  const ruleResults: MetricResult[] = [];
  let totalTp = 0;
  let totalFp = 0;
  let totalFn = 0;
  
  for (const [ruleId, stats] of Object.entries(statsMap)) {
    const { tp, fp, fn, tn, total } = stats;
    totalTp += tp;
    totalFp += fp;
    totalFn += fn;

    const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0.0;

    ruleResults.push({
      ruleId,
      total,
      tp,
      fp,
      fn,
      precision,
      recall,
      f1
    });
  }

  // Sort rules alphabetically by ID for consistency in report
  ruleResults.sort((a, b) => a.ruleId.localeCompare(b.ruleId));

  const overallPrecision = totalTp + totalFp > 0 ? totalTp / (totalTp + totalFp) : 1.0;
  const overallRecall = totalTp + totalFn > 0 ? totalTp / (totalTp + totalFn) : 1.0;
  const overallF1 = overallPrecision + overallRecall > 0 
    ? (2 * overallPrecision * overallRecall) / (overallPrecision + overallRecall) 
    : 0.0;

  const weakRules = ruleResults
    .filter(r => r.f1 < weakThreshold)
    .map(r => r.ruleId);

  return {
    ruleResults,
    precision: overallPrecision,
    recall: overallRecall,
    f1: overallF1,
    weakRules
  };
}
