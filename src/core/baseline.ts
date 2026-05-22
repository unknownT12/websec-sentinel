import { readFileSync } from "node:fs";
import type { ScanReport, ScanResult } from "../types.js";

export interface BaselineComparison {
  baselineFile: string;
  newFindings: string[];
  resolvedFindings: string[];
  unchangedFindings: string[];
  changedSeverity: Array<{ id: string; before: string; after: string }>;
}

function activeIds(results: ScanResult[]): Map<string, ScanResult> {
  const map = new Map<string, ScanResult>();
  for (const r of results) if (r.status !== "pass" && r.status !== "info") map.set(r.id, r);
  return map;
}

export function compareBaseline(path: string | undefined, current: ScanResult[]): BaselineComparison | undefined {
  if (!path) return undefined;
  try {
    const previous = JSON.parse(readFileSync(path, "utf8")) as Partial<ScanReport>;
    const before = activeIds(previous.results ?? []);
    const after = activeIds(current);
    const newFindings = [...after.keys()].filter((id) => !before.has(id)).sort();
    const resolvedFindings = [...before.keys()].filter((id) => !after.has(id)).sort();
    const unchangedFindings = [...after.keys()].filter((id) => before.has(id)).sort();
    const changedSeverity = unchangedFindings
      .map((id) => ({ id, before: before.get(id)!.severity, after: after.get(id)!.severity }))
      .filter((x) => x.before !== x.after);
    return { baselineFile: path, newFindings, resolvedFindings, unchangedFindings, changedSeverity };
  } catch {
    return { baselineFile: path, newFindings: [], resolvedFindings: [], unchangedFindings: [], changedSeverity: [] };
  }
}
