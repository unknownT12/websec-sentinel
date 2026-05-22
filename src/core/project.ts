import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ScanOptions, ScanReport, ScanResult } from "../types.js";
import { compareBaseline } from "./baseline.js";
import { fingerprintFor } from "./falsepositives.js";

type TriageEntry = {
  status: "open" | "accepted-risk" | "false-positive" | "fixed" | "ignored";
  owner?: string;
  note?: string;
};

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 90) || "project";
}

export function projectName(options: ScanOptions, target: URL): string {
  return slug(options.projectName ?? target.hostname);
}

export function projectPath(options: ScanOptions, target: URL): string | undefined {
  if (!options.projectDir) return undefined;
  return join(options.projectDir, projectName(options, target));
}

export function latestProjectReport(options: ScanOptions, target: URL): string | undefined {
  const dir = projectPath(options, target);
  if (!dir) return undefined;
  const latest = join(dir, "latest.json");
  return existsSync(latest) ? latest : undefined;
}

export function projectBaseline(options: ScanOptions, target: URL, results: ScanResult[]) {
  const latest = latestProjectReport(options, target);
  return compareBaseline(latest, results);
}

export function loadTriage(path: string | undefined): Record<string, TriageEntry> {
  if (!path || !existsSync(path)) return {};
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, TriageEntry>;
  return parsed && typeof parsed === "object" ? parsed : {};
}

export function applyTriage(results: ScanResult[], triage: Record<string, TriageEntry>): ScanResult[] {
  return results.map((result) => {
    const entry = triage[result.id] ?? triage[result.fingerprint ?? fingerprintFor(result)];
    if (!entry) return result;
    const next: ScanResult = { ...result, triage: entry };
    if (entry.status === "false-positive" || entry.status === "ignored") {
      next.status = "info";
      next.severity = "info";
      next.kind = "informational";
      next.falsePositiveNotes = [next.falsePositiveNotes, entry.note ? `Triage: ${entry.note}` : `Triage status: ${entry.status}`].filter(Boolean).join(" ");
    }
    return next;
  });
}

export function filterMetaFindings(results: ScanResult[], includeMetaFindings: boolean): ScanResult[] {
  if (includeMetaFindings) return results;
  return results.filter((result) => {
    if (result.status === "pass" || result.status === "info") return true;
    if (result.kind !== "coverage-gap") return true;
    return /coverage contract|no application pages|browser crawl|external benchmark/i.test(result.title + " " + result.id);
  });
}

export function runSummary(report: ScanReport, options: ScanOptions) {
  const active = report.results.filter((r) => r.status !== "pass" && r.status !== "info");
  const byKind = active.reduce<Record<string, number>>((acc, result) => {
    const key = result.kind ?? "unknown";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  const bySeverity = active.reduce<Record<string, number>>((acc, result) => {
    acc[result.severity] = (acc[result.severity] ?? 0) + 1;
    return acc;
  }, {});
  return {
    tool: report.tool,
    version: report.version,
    timestamp: report.timestamp,
    target: report.target,
    policyFile: options.policyFile,
    grade: report.summary.grade,
    score: report.summary.score,
    coverageScore: report.summary.coverageScore,
    activeFindings: active.length,
    byKind,
    bySeverity,
    fingerprints: active.map((r) => r.fingerprint ?? fingerprintFor(r)).sort(),
  };
}

export function writeSummaryFile(path: string | undefined, report: ScanReport, options: ScanOptions): string | undefined {
  if (!path) return undefined;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(runSummary(report, options), null, 2));
  return path;
}

export function writeTriageTemplate(path: string | undefined, results: ScanResult[]): string | undefined {
  if (!path) return undefined;
  mkdirSync(dirname(path), { recursive: true });
  const active = results.filter((r) => r.status !== "pass" && r.status !== "info");
  const template = Object.fromEntries(active.map((result) => [result.fingerprint ?? fingerprintFor(result), {
    id: result.id,
    title: result.title,
    severity: result.severity,
    kind: result.kind,
    status: "open",
    owner: "",
    note: "",
  }]));
  writeFileSync(path, JSON.stringify(template, null, 2));
  return path;
}

export function saveProjectReport(report: ScanReport, options: ScanOptions, target: URL): { dir: string; reportFile: string } | undefined {
  const dir = projectPath(options, target);
  if (!dir) return undefined;
  mkdirSync(dir, { recursive: true });
  const historyDir = join(dir, "history");
  mkdirSync(historyDir, { recursive: true });
  const stamp = report.timestamp.replace(/[:.]/g, "-");
  const reportFile = join(historyDir, `${stamp}.json`);
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  writeFileSync(join(dir, "latest.json"), JSON.stringify(report, null, 2));
  const indexPath = join(dir, "index.json");
  const summary = runSummary(report, options);
  const manifest = {
    ...summary,
    project: projectName(options, target),
    report: reportFile,
    summary: report.summary,
  };
  const manifestFile = join(historyDir, `${stamp}.manifest.json`);
  writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
  const previous = existsSync(indexPath) ? JSON.parse(readFileSync(indexPath, "utf8")) as { runs?: unknown[] } : {};
  const runs = Array.isArray(previous.runs) ? previous.runs : [];
  runs.push({
    timestamp: report.timestamp,
    target: report.target,
    grade: report.summary.grade,
    score: report.summary.score,
    coverageScore: report.summary.coverageScore,
    findings: summary.activeFindings,
    byKind: summary.byKind,
    bySeverity: summary.bySeverity,
    report: reportFile,
    manifest: manifestFile,
  });
  writeFileSync(indexPath, JSON.stringify({ name: projectName(options, target), latest: reportFile, runs }, null, 2));
  return { dir, reportFile };
}
