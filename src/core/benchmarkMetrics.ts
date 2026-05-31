import type { ScanResult } from "../types.js";

export interface BenchmarkExpectedFinding {
  id: string;
  title: string;
  resultIds?: string[];
  required?: boolean;
  metricType?: "vulnerability" | "surface" | "coverage";
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
  surfaceMatches: Array<{ expectedId: string; matchedResultId: string; title: string }>;
  coverageMatches: Array<{ expectedId: string; matchedResultId: string; title: string }>;
}

function rounded(value: number): number {
  return Number(value.toFixed(3));
}

function matchesResultId(resultId: string, acceptable: string): boolean {
  if (acceptable.endsWith("*")) return resultId.startsWith(acceptable.slice(0, -1));
  return resultId === acceptable;
}

export function calculateBenchmarkMetrics(results: Pick<ScanResult, "id" | "title" | "severity" | "status">[], expected: BenchmarkExpectedFinding[]): BenchmarkMetrics {
  const required = expected.filter((e) => e.required !== false && (e.metricType ?? "vulnerability") === "vulnerability");
  const requiredSurface = expected.filter((e) => e.required !== false && e.metricType === "surface");
  const requiredCoverage = expected.filter((e) => e.required !== false && e.metricType === "coverage");
  const matched: BenchmarkMetrics["matched"] = [];
  const missed: BenchmarkMetrics["missed"] = [];
  const surfaceMatches: BenchmarkMetrics["surfaceMatches"] = [];
  const coverageMatches: BenchmarkMetrics["coverageMatches"] = [];

  for (const exp of required) {
    const acceptable = exp.resultIds ?? [exp.id];
    const found = acceptable.find((id) => results.some((r) => matchesResultId(r.id, id)));
    if (found) matched.push({ expectedId: exp.id, matchedResultId: found, title: exp.title });
    else missed.push({ expectedId: exp.id, acceptableResultIds: acceptable, title: exp.title });
  }

  for (const exp of requiredSurface) {
    const acceptable = exp.resultIds ?? [exp.id];
    const found = acceptable.find((id) => results.some((r) => matchesResultId(r.id, id)));
    if (found) surfaceMatches.push({ expectedId: exp.id, matchedResultId: found, title: exp.title });
  }

  for (const exp of requiredCoverage) {
    const acceptable = exp.resultIds ?? [exp.id];
    const found = acceptable.find((id) => results.some((r) => matchesResultId(r.id, id)));
    if (found) coverageMatches.push({ expectedId: exp.id, matchedResultId: found, title: exp.title });
  }

  const relevantIds = new Set(required.flatMap((e) => e.resultIds ?? [e.id]));
  const falsePositiveCandidatesDetail = [...new Map(results
    .filter((r) => r.status === "fail" || r.status === "warn")
    .filter((r) => !/^(coverage|assurance|proofmetrics|benchmark|externalbenchmark|browsermodel|productengine|testvectors|professionalmodel|bookscope|testmodel|enginemodel|evidencequality|validationmatrix)\./.test(r.id))
    .filter((r) => !/\.pass$/.test(r.id))
    .filter((r) => ![...relevantIds].some((id) => matchesResultId(r.id, id)))
    .map((r) => [r.id, { id: r.id, title: r.title, severity: r.severity, status: r.status }])).values()];

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
    surfaceMatches,
    coverageMatches,
  };
}
