import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { FindingKind, ReportFormat, ScanReport, ScanResult, Severity } from "../types.js";

const severityWeight: Record<Severity, number> = { critical: 45, high: 22, medium: 9, low: 3, info: 0 };
const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VALIDATION_DISCLAIMER = "WebSec Sentinel reports assessment signals. Treat findings as confirmed vulnerabilities only after authorized human validation of evidence, business context, and expected access policy.";
const KIND_ORDER: FindingKind[] = ["confirmed-vulnerability", "risk-signal", "coverage-gap", "scanner-diagnostic", "informational", "pass"];
const KIND_LABELS: Record<FindingKind, string> = {
  "confirmed-vulnerability": "Confirmed Vulnerabilities",
  "risk-signal": "Risk Signals",
  "coverage-gap": "Coverage Gaps",
  "scanner-diagnostic": "Scanner Diagnostics",
  informational: "Informational",
  pass: "Passed Controls",
};

function resultKind(result: ScanResult): FindingKind {
  if (result.kind) return result.kind;
  if (result.status === "pass") return "pass";
  if (result.status === "info" || result.severity === "info") return "informational";
  if (/coverage|assurance|maturity|product|benchmark|evidence|proof|model/i.test(`${result.check} ${result.category}`)) return "coverage-gap";
  if (result.exploitability === "validated" && result.confidence === "confirmed") return "confirmed-vulnerability";
  if (/scanner|diagnostic/i.test(result.category)) return "scanner-diagnostic";
  return "risk-signal";
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function stripPasses(results: ScanResult[], includePasses: boolean): ScanResult[] {
  return includePasses ? results : results.filter((r) => r.status !== "pass");
}

function topCategories(results: ScanResult[]): Array<{ category: string; count: number }> {
  const map = new Map<string, number>();
  for (const r of results.filter((x) => x.status !== "pass" && x.status !== "info")) map.set(r.category, (map.get(r.category) ?? 0) + 1);
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([category, count]) => ({ category, count }));
}

function groupedResults(results: ScanResult[]): Array<{ kind: FindingKind; label: string; results: ScanResult[] }> {
  return KIND_ORDER
    .map((kind) => ({
      kind,
      label: KIND_LABELS[kind],
      results: results
        .filter((r) => resultKind(r) === kind)
        .sort((a, b) => order[a.severity] - order[b.severity] || a.title.localeCompare(b.title)),
    }))
    .filter((group) => group.results.length);
}

function coverageScore(report: Omit<ScanReport, "summary" | "executive">): number {
  let score = 0;
  if (report.surface.pagesCrawled > 0) score += 20;
  if (report.surface.pagesCrawled >= Math.max(1, report.quality.coverageContract.minPages)) score += 20;
  if (report.surface.linksObserved > 0) score += 10;
  if (report.surface.routesObserved > 0) score += 15;
  if (report.surface.formsObserved > 0) score += 15;
  if (report.surface.scriptsObserved > 0 || report.surface.technologies.length > 0) score += 10;
  if (report.authorization.authenticated) score += 10;
  if (report.quality.coverageContract.requireAuth && !report.authorization.authenticated) score -= 20;
  return Math.max(0, Math.min(100, score));
}

function executive(results: ScanResult[], score: number, coverage: number): ScanReport["executive"] {
  const actionable = results.filter((r) => r.status !== "pass" && r.status !== "info").sort((a, b) => order[a.severity] - order[b.severity]);
  const priorities = actionable.slice(0, 5).map((r) => `${r.severity.toUpperCase()}: ${r.title}`);
  const coverageWarning = coverage < 40 ? " Coverage is weak, so the grade should not be treated as proof of broad security." : coverage < 70 ? " Coverage is moderate; authenticated and deeper route testing would increase confidence." : "";
  const verdict = score >= 90 ? `Low observed risk across tested controls.${coverageWarning}` : score >= 75 ? `Manageable observed risk with remediation required before high-assurance release.${coverageWarning}` : score >= 60 ? `Moderate observed risk; several weaknesses should be addressed before production confidence.${coverageWarning}` : `Elevated observed risk; immediate remediation and retesting are recommended.${coverageWarning}`;
  const businessRisk = actionable.some((r) => r.severity === "critical") ? "Critical findings may create direct compromise or serious data exposure risk." : actionable.some((r) => r.severity === "high") ? "High-impact issues could materially increase breach likelihood or regulatory exposure." : actionable.length ? "Observed issues mainly increase attack surface and exploit chaining risk." : coverage < 40 ? "No material weakness was proven, but coverage was too limited to support strong assurance." : "No material weaknesses were detected in the tested external controls.";
  return { verdict, businessRisk, immediatePriorities: priorities.length ? priorities : [coverage < 70 ? "Increase crawl/authenticated coverage before relying on this score." : "Maintain continuous monitoring and repeat scans after material releases."] };
}

export function buildReport(input: Omit<ScanReport, "summary" | "executive"> & { startedAt: number; includePasses: boolean }): ScanReport {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, passed: 0 };
  for (const r of input.results) {
    if (r.status === "pass") counts.passed++;
    else counts[r.severity]++;
  }
  const baseRisk = input.results.filter((r) => r.status !== "pass" && r.status !== "info").reduce((sum, r) => sum + severityWeight[r.severity], 0);
  const { startedAt, includePasses, ...report } = input;
  const coverage = coverageScore(report);
  const coveragePenalty = coverage < 20 ? 45 : coverage < 40 ? 30 : coverage < 70 ? 14 : 0;
  const contractPenalty = input.quality.coverageContract.passed ? 0 : 20;
  const weightedRisk = baseRisk + coveragePenalty + contractPenalty;
  const score = Math.max(0, 100 - weightedRisk);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const visibleResults = stripPasses(report.results, includePasses);
  return {
    ...report,
    results: visibleResults,
    summary: { ...counts, score, weightedRisk, coverageScore: coverage, grade, durationMs: Date.now() - startedAt, topCategories: topCategories(report.results) },
    executive: executive(report.results, score, coverage),
  };
}

export function shouldFail(report: ScanReport, threshold: Severity): boolean {
  const thresholdOrder = order[threshold];
  return report.results.some((r) => r.status !== "pass" && r.status !== "info" && order[r.severity] <= thresholdOrder);
}

export function printReport(report: ScanReport, noColor = false): void {
  const c = (code: string) => noColor ? "" : code;
  const reset = c("\x1b[0m"), bold = c("\x1b[1m"), red = c("\x1b[31m"), yellow = c("\x1b[33m"), green = c("\x1b[32m"), cyan = c("\x1b[36m"), gray = c("\x1b[90m");
  const sorted = [...report.results].sort((a, b) => order[a.severity] - order[b.severity] || a.title.localeCompare(b.title));
  console.log(`\n${bold}WebSec Sentinel Report${reset}`);
  console.log(`${yellow}Disclaimer:${reset} ${VALIDATION_DISCLAIMER}`);
  console.log(`${gray}Target:${reset} ${report.target}`);
  console.log(`${gray}Mode:${reset} ${report.mode}  ${gray}Grade:${reset} ${report.summary.grade} (${report.summary.score}/100)  ${gray}Weighted risk:${reset} ${report.summary.weightedRisk}  ${gray}Coverage:${reset} ${report.summary.coverageScore}/100  ${gray}Duration:${reset} ${report.summary.durationMs}ms`);
  console.log(`${gray}Surface:${reset} ${report.surface.pagesCrawled} page(s), ${report.surface.formsObserved} form(s), ${report.surface.linksObserved} link(s), ${report.surface.routesObserved} route hint(s), ${report.surface.scriptsObserved} script(s), technologies: ${report.surface.technologies.join(", ") || "unknown"}`);
  console.log(`${gray}Auth coverage:${reset} ${report.surface.authCoverage}`);
  console.log(`${gray}Coverage contract:${reset} ${report.quality.coverageContract.passed ? "passed" : "failed"}${report.quality.coverageContract.reasons.length ? ` (${report.quality.coverageContract.reasons.join("; ")})` : ""}`);
  console.log(`${gray}Tested controls:${reset} ${report.surface.testedControls.join(", ")}`);
  console.log(`${gray}Verdict:${reset} ${report.executive.verdict}`);
  if (report.quality.baseline) console.log(`${gray}Baseline:${reset} ${report.quality.baseline.newFindings.length} new, ${report.quality.baseline.resolvedFindings.length} resolved, ${report.quality.baseline.unchangedFindings.length} unchanged`);
  console.log(`\n${bold}Findings by Type${reset}`);
  for (const group of groupedResults(sorted)) {
    console.log(`${gray}${group.label}:${reset} ${group.results.length}`);
    for (const r of group.results) {
      const color = r.severity === "critical" || r.severity === "high" ? red : r.severity === "medium" ? yellow : r.severity === "low" ? cyan : gray;
      const icon = r.status === "pass" ? `${green}✓${reset}` : r.status === "info" ? `${gray}i${reset}` : `${color}!${reset}`;
      console.log(`  ${icon} ${bold}${r.title}${reset} ${color}[${r.severity.toUpperCase()}]${reset} ${gray}${r.confidence}${reset} ${gray}${r.exploitability ?? "theoretical"}${reset}`);
      if (r.status !== "pass") {
        console.log(`     ${r.detail}`);
        if (r.remediationPriority || r.sla) console.log(`     ${gray}Priority:${reset} ${r.remediationPriority ?? "review"}${r.sla ? ` | SLA: ${r.sla}` : ""}`);
      }
    }
  }
  console.log(`\n${bold}Summary${reset}: ${red}${report.summary.critical} critical${reset}, ${red}${report.summary.high} high${reset}, ${yellow}${report.summary.medium} medium${reset}, ${cyan}${report.summary.low} low${reset}, ${gray}${report.summary.info} info${reset}, ${green}${report.summary.passed} passed${reset}\n`);
}

function markdown(report: ScanReport): string {
  const rows = report.results
    .sort((a, b) => order[a.severity] - order[b.severity])
    .map((r) => `| ${r.severity} | ${r.status} | ${resultKind(r)} | ${r.confidence} | ${r.exploitability ?? "none"} | ${r.remediationPriority ?? "review"} | ${(r.owasp ?? []).join(", ").replace(/\|/g, "\\|")} | ${r.title.replace(/\|/g, "\\|")} | ${r.impact.replace(/\|/g, "\\|")} | ${r.remediation.replace(/\|/g, "\\|")} |`)
    .join("\n");
  const byKind = groupedResults(report.results)
    .map((group) => `### ${group.label}\n\n${group.results.map((r) => `- **${r.severity.toUpperCase()}** ${r.title} (${r.confidence}; ${r.exploitability ?? "none"})`).join("\n")}`)
    .join("\n\n");
  const baseline = report.quality.baseline ? `\n## Baseline comparison\n\n- Baseline file: ${report.quality.baseline.baselineFile}\n- New findings: ${report.quality.baseline.newFindings.length}\n- Resolved findings: ${report.quality.baseline.resolvedFindings.length}\n- Unchanged findings: ${report.quality.baseline.unchangedFindings.length}\n- Changed severity: ${report.quality.baseline.changedSeverity.length}\n` : "";
  const diagnostics = report.quality.diagnostics.requestFailures.length ? `\n### Request failures\n\n${report.quality.diagnostics.requestFailures.slice(0, 10).map((f) => `- ${f.url}: ${f.error}`).join("\n")}\n` : "";
  return `# WebSec Sentinel Report\n\n> Disclaimer: ${VALIDATION_DISCLAIMER}\n\n**Target:** ${report.target}\n\n**Timestamp:** ${report.timestamp}\n\n**Mode:** ${report.mode}\n\n**Assessment grade:** ${report.summary.grade} (${report.summary.score}/100)\n\n**Coverage score:** ${report.summary.coverageScore}/100\n\n**Executive verdict:** ${report.executive.verdict}\n\n**Business risk:** ${report.executive.businessRisk}\n\n## What was tested\n\n- Tested controls: ${report.surface.testedControls.join(", ")}\n- Authenticated coverage: ${report.surface.authCoverage}\n- Pages crawled: ${report.surface.pagesCrawled}\n- Links observed: ${report.surface.linksObserved}\n- Route hints observed: ${report.surface.routesObserved}\n- Forms observed: ${report.surface.formsObserved}\n- Scripts observed: ${report.surface.scriptsObserved}\n- Technologies: ${report.surface.technologies.join(", ") || "unknown"}\n- Status codes: ${JSON.stringify(report.surface.statusCodes)}\n- Coverage contract: ${report.quality.coverageContract.passed ? "passed" : `failed (${report.quality.coverageContract.reasons.join("; ")})`}\n\n## Immediate priorities\n\n${report.executive.immediatePriorities.map((p) => `- ${p}`).join("\n")}\n\n## Summary\n\n- Critical: ${report.summary.critical}\n- High: ${report.summary.high}\n- Medium: ${report.summary.medium}\n- Low: ${report.summary.low}\n- Passed: ${report.summary.passed}\n- Weighted risk: ${report.summary.weightedRisk}\n${baseline}\n## Authorization\n\n- Authorized: ${report.authorization.authorized}\n- Client: ${report.authorization.client ?? "Not provided"}\n- Assessment ID: ${report.authorization.assessmentId ?? "Not provided"}\n- Tester: ${report.authorization.tester ?? "Not provided"}\n- Scope: ${report.authorization.scope.join(", ")}\n- Authenticated: ${report.authorization.authenticated}\n\n## Findings by type\n\n${byKind || "No findings to display."}\n\n## Findings table\n\n| Severity | Status | Kind | Confidence | Exploitability | Priority | OWASP | Finding | Impact | Remediation |\n|---|---|---|---|---|---|---|---|---|---|\n${rows}\n\n## Crawler diagnostics\n\n- Attempted requests: ${report.quality.diagnostics.attempted}\n- Visited URLs: ${report.quality.diagnostics.visited}\n- Queued URLs: ${report.quality.diagnostics.queued}\n- Blocked by scope: ${report.quality.diagnostics.blockedByScope}\n- Blocked by prohibited paths: ${report.quality.diagnostics.blockedByProhibitedPath}\n- Discovered links: ${report.quality.diagnostics.discoveredLinks}\n- Discovered forms: ${report.quality.diagnostics.discoveredForms}\n- Discovered route hints: ${report.quality.diagnostics.discoveredRouteHints}\n${diagnostics}\n## Quality and limitations\n\n${report.quality.limitations.map((l) => `- ${l}`).join("\n")}\n\n## Methodology sources applied\n\n${(report.quality.methodologySources ?? []).map((m) => `- ${m}`).join("\n")}\n`;
}

function html(report: ScanReport): string {
  const cards = report.results.sort((a, b) => order[a.severity] - order[b.severity]).map((r) => `<section class="card ${r.severity}"><h2>${escapeHtml(r.title)} <span>${r.severity.toUpperCase()}</span></h2><p>${escapeHtml(r.detail)}</p><p class="meta">${escapeHtml(r.category)} · ${escapeHtml(resultKind(r))} · ${escapeHtml(r.confidence)} confidence · ${escapeHtml(r.exploitability ?? "theoretical")} · priority ${escapeHtml(r.remediationPriority ?? "review")}</p><h3>Impact</h3><p>${escapeHtml(r.impact)}</p>${r.businessImpact ? `<h3>Business Impact</h3><p>${escapeHtml(r.businessImpact)}</p>` : ""}<h3>Remediation</h3><p>${escapeHtml(r.remediation)}</p>${r.verification ? `<h3>Verification</h3><p>${escapeHtml(r.verification)}</p>` : ""}${r.falsePositiveNotes ? `<h3>False-positive notes</h3><p>${escapeHtml(r.falsePositiveNotes)}</p>` : ""}${r.evidence?.length ? `<h3>Evidence</h3><pre>${escapeHtml(JSON.stringify(r.evidence, null, 2))}</pre>` : ""}</section>`).join("\n");
  const kindSummary = groupedResults(report.results).map((group) => `<div class="metric">${escapeHtml(group.label)}<br><b>${group.results.length}</b></div>`).join("");
  const tested = report.surface.testedControls.map((c) => `<code>${escapeHtml(c)}</code>`).join(" ");
  return `<!doctype html><html><head><meta charset="utf-8"><title>WebSec Sentinel Report</title><style>body{font-family:Inter,system-ui,sans-serif;background:#080b14;color:#e5e7eb;margin:0;padding:32px}.hero,.card{background:linear-gradient(180deg,#111827,#0f172a);border:1px solid #263044;border-radius:20px;padding:24px;margin:0 0 18px;box-shadow:0 18px 45px rgba(0,0,0,.25)}h1,h2{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.metric{background:#0b1220;border:1px solid #1f2937;border-radius:14px;padding:14px}.critical span,.high span{color:#f87171}.medium span{color:#fbbf24}.low span{color:#67e8f9}.info span{color:#94a3b8}.pass span{color:#86efac}.meta{color:#94a3b8}pre{white-space:pre-wrap;background:#050816;border-radius:12px;padding:12px;overflow:auto}code{background:#020617;border:1px solid #1f2937;border-radius:8px;padding:2px 6px}.warn{color:#fbbf24}</style></head><body><div class="hero"><h1>WebSec Sentinel Report</h1><p class="warn"><b>Disclaimer:</b> ${escapeHtml(VALIDATION_DISCLAIMER)}</p><p><b>Target:</b> ${escapeHtml(report.target)}</p><p><b>Mode:</b> ${report.mode} | <b>Assessment grade:</b> ${report.summary.grade} (${report.summary.score}/100) | <b>Coverage:</b> ${report.summary.coverageScore}/100 | <b>Risk:</b> ${report.summary.weightedRisk}</p><p><b>Executive verdict:</b> ${escapeHtml(report.executive.verdict)}</p><p><b>Coverage contract:</b> ${report.quality.coverageContract.passed ? "passed" : escapeHtml(`failed (${report.quality.coverageContract.reasons.join("; ")})`)}</p><div class="grid"><div class="metric">Critical<br><b>${report.summary.critical}</b></div><div class="metric">High<br><b>${report.summary.high}</b></div><div class="metric">Medium<br><b>${report.summary.medium}</b></div><div class="metric">Low<br><b>${report.summary.low}</b></div><div class="metric">Passed<br><b>${report.summary.passed}</b></div><div class="metric">Pages<br><b>${report.surface.pagesCrawled}</b></div><div class="metric">Forms<br><b>${report.surface.formsObserved}</b></div><div class="metric">Routes<br><b>${report.surface.routesObserved}</b></div></div></div><section class="card"><h2>Findings by type</h2><div class="grid">${kindSummary}</div></section><section class="card"><h2>What was tested</h2><p><b>Controls:</b> ${tested}</p><p><b>Authenticated coverage:</b> ${escapeHtml(report.surface.authCoverage)}</p><p><b>Technologies:</b> ${escapeHtml(report.surface.technologies.join(", ") || "unknown")}</p><p><b>Status codes:</b> ${escapeHtml(JSON.stringify(report.surface.statusCodes))}</p><p class="meta">Crawler diagnostics: attempted ${report.quality.diagnostics.attempted}, discovered links ${report.quality.diagnostics.discoveredLinks}, forms ${report.quality.diagnostics.discoveredForms}, route hints ${report.quality.diagnostics.discoveredRouteHints}, blocked by scope ${report.quality.diagnostics.blockedByScope}.</p></section>${cards}</body></html>`;
}

function sarif(report: ScanReport): string {
  const rules = report.results.map((r) => ({ id: r.id, name: r.title, shortDescription: { text: r.title }, fullDescription: { text: r.detail }, help: { text: `${r.impact}\n\nRemediation: ${r.remediation}` }, properties: { kind: resultKind(r), severity: r.severity, confidence: r.confidence, owasp: r.owasp, cwe: r.cwe } }));
  const results = report.results.filter((r) => r.status !== "pass" && r.status !== "info").map((r) => ({ ruleId: r.id, level: r.severity === "critical" || r.severity === "high" ? "error" : r.severity === "medium" ? "warning" : "note", message: { text: r.detail }, locations: [{ physicalLocation: { artifactLocation: { uri: r.evidence?.[0]?.url ?? report.target } } }], properties: { kind: resultKind(r), severity: r.severity, confidence: r.confidence, exploitability: r.exploitability, remediationPriority: r.remediationPriority, owasp: r.owasp, cwe: r.cwe, coverageScore: report.summary.coverageScore } }));
  return JSON.stringify({ version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: report.tool, version: report.version, rules } }, results }] }, null, 2);
}

export function renderReport(report: ScanReport, format: ReportFormat): string {
  if (format === "json") return JSON.stringify(report, null, 2);
  if (format === "markdown") return markdown(report);
  if (format === "html") return html(report);
  return sarif(report);
}

export function saveReports(report: ScanReport, formats: ReportFormat[], outDir: string): string[] {
  mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return formats.map((format) => {
    const ext = format === "markdown" ? "md" : format === "sarif" ? "sarif" : format;
    const path = join(outDir, `websec-${stamp}.${ext}`);
    writeFileSync(path, renderReport(report, format));
    return path;
  });
}
