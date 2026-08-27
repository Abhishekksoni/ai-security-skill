import type { OverallMetrics } from './metrics.js';

export function printReport(metrics: OverallMetrics) {
  const formatPercent = (val: number) => `${Math.round(val * 100)}%`;
  const formatPercentDec = (val: number) => `${(val * 100).toFixed(1)}%`;

  console.log('\nSECURITY RULE BENCHMARK');
  console.log('─────────────────────────────────────────────────────────────\n');

  console.log(
    'Rule'.padEnd(12) +
    'Cases'.padStart(6) +
    'TP'.padStart(5) +
    'FP'.padStart(5) +
    'FN'.padStart(5) +
    'Precision'.padStart(12) +
    'Recall'.padStart(10)
  );
  console.log('-'.repeat(55));

  for (const r of metrics.ruleResults) {
    console.log(
      r.ruleId.padEnd(12) +
      String(r.total).padStart(6) +
      String(r.tp).padStart(5) +
      String(r.fp).padStart(5) +
      String(r.fn).padStart(5) +
      formatPercent(r.precision).padStart(12) +
      formatPercent(r.recall).padStart(10)
    );
  }

  console.log('\nOverall');
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`Precision: ${formatPercentDec(metrics.precision)}`);
  console.log(`Recall:    ${formatPercentDec(metrics.recall)}`);
  console.log(`F1:        ${formatPercentDec(metrics.f1)}`);
  console.log('─────────────────────────────────────────────────────────────');

  if (metrics.weakRules.length > 0) {
    console.log('\n⚠ Weak rules:');
    for (const ruleId of metrics.weakRules) {
      console.log(`  - ${ruleId}`);
    }
  } else {
    console.log('\n✔ All rules meet the performance threshold!');
  }
  console.log();
}
