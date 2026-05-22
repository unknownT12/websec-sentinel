import type { ScanResult } from "../types.js";

export interface BenchmarkExpectedFinding {
  id: string;
  title: string;
  resultIds?: string[];
  required?: boolean;
}

export interface BenchmarkMetrics {
  expectedRequired: number;
  truePositives: number;
  falsePositiveCandidates: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  matched: Array<{ expectedId: string; matchedResultId: string; title: string }>;
  missed: Array<{ expectedId: string; acceptableResultIds: string[]; title: string }>;
  falsePositiveCandidatesDetail: Array<{ id: string; title: string; severity: string; status: string }>;
}

function rounded(value: number): number {
  return Number(value.toFixed(3));
}

export function calculateBenchmarkMetrics(results: Pick<ScanResult, "id" | "title" | "severity" | "status">[], expected: BenchmarkExpectedFinding[]): BenchmarkMetrics {
  const resultIds = new Set(results.map((r) => r.id));
  const required = expected.filter((e) => e.required !== false);
  const matched: BenchmarkMetrics["matched"] = [];
  const missed: BenchmarkMetrics["missed"] = [];

  for (const exp of required) {
    const acceptable = exp.resultIds ?? [exp.id];
    const found = acceptable.find((id) => resultIds.has(id));
    if (found) matched.push({ expectedId: exp.id, matchedResultId: found, title: exp.title });
    else missed.push({ expectedId: exp.id, acceptableResultIds: acceptable, title: exp.title });
  }

  const relevantIds = new Set(required.flatMap((e) => e.resultIds ?? [e.id]));
  const falsePositiveCandidatesDetail = results
    .filter((r) => r.id.startsWith("vulnvalidation.confirmed"))
    .filter((r) => r.status === "fail" || r.status === "warn")
    .filter((r) => !relevantIds.has(r.id))
    .map((r) => ({ id: r.id, title: r.title, severity: r.severity, status: r.status }));

  const tp = matched.length;
  const fn = missed.length;
  const fp = falsePositiveCandidatesDetail.length;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    expectedRequired: required.length,
    truePositives: tp,
    falsePositiveCandidates: fp,
    falseNegatives: fn,
    precision: rounded(precision),
    recall: rounded(recall),
    f1: rounded(f1),
    matched,
    missed,
    falsePositiveCandidatesDetail,
  };
}
