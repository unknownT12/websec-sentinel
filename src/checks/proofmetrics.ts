import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { getHttpObservations } from "../core/http.js";

function percent(n: number, d: number): number { return d ? Math.round((n / d) * 100) : 0; }

export const proofMetricsCheck: Check = {
  name: "proofmetrics",
  description: "Scores hard proof quality: benchmark profile, browser trace, role diff, reproducible ledgers, and confirmed validation evidence.",
  async run(context) {
    const obs = getHttpObservations();
    const pages = context.pages.length;
    const forms = context.pages.reduce((s, p) => s + p.forms.length, 0);
    const params = new Set<string>();
    for (const p of context.pages) {
      for (const u of [p.url, p.finalUrl, ...p.links, ...p.routeHints]) {
        try { for (const k of new URL(u).searchParams.keys()) params.add(k); } catch {}
      }
      for (const f of p.forms) for (const i of f.inputs) if (i.name) params.add(i.name);
    }
    const hardProof = [
      context.options.benchmarkProfile ? "benchmark-profile" : "missing-benchmark-profile",
      context.options.benchmarkGroundTruth ? "external-ground-truth" : "missing-external-ground-truth",
      context.options.benchmarkEvidenceOut ? "external-evidence-artifact" : "missing-external-evidence-artifact",
      context.diagnostics.browserExecuted ? "browser-executed" : "no-browser-trace",
      context.options.roleHeaders.length >= 2 ? "role-differential-ready" : "no-role-differential",
      context.options.harFile ? "har-export" : "missing-har-export",
      context.options.replayFile ? "replay-export" : "missing-replay-export",
      context.options.jsonlLog ? "jsonl-ledger" : "missing-jsonl-ledger",
      pages >= context.options.minPages ? "page-threshold-met" : "weak-page-depth",
      forms > 0 ? "form-coverage" : "no-form-coverage",
      params.size > 0 ? "parameter-coverage" : "no-parameter-coverage",
    ];
    const score = Math.min(100, Math.round(
      (context.options.benchmarkProfile ? 10 : 0) +
      (context.options.benchmarkGroundTruth ? 10 : 0) +
      (context.options.benchmarkEvidenceOut ? 5 : 0) +
      (context.diagnostics.browserExecuted ? 15 : 0) +
      (context.options.roleHeaders.length >= 2 ? 15 : 0) +
      (context.options.harFile ? 10 : 0) +
      (context.options.replayFile ? 10 : 0) +
      (context.options.jsonlLog ? 10 : 0) +
      Math.min(15, pages * 3) +
      Math.min(5, forms * 2) +
      Math.min(5, params.size)
    ));

    if (score < 75) return [finding({
      id: "proofmetrics.product-proof-below-8-threshold",
      check: "proofmetrics",
      category: "Product Evidence",
      status: "warn",
      severity: score < 50 ? "high" : "medium",
      confidence: "confirmed",
      title: "Hard proof metrics are below professional threshold",
      detail: `Proof score ${score}/100. Pages=${pages}, forms=${forms}, params=${params.size}, requests=${obs.length}, browser=${Boolean(context.diagnostics.browserExecuted)}, roles=${context.options.roleHeaders.length}.`,
      impact: "The assessment may still be useful, but it lacks enough hard proof to support 8+/10 product claims.",
      remediation: "Run with a benchmark profile, external ground-truth file, browser crawling, approved login automation, two or more role headers, JSONL, HAR and replay exports, and enough seeds to reach real workflows.",
      evidence: [{ observed: hardProof.join(", ") }],
      exploitability: "none",
    })];
    return [pass("proofmetrics", "Product Evidence", "Hard proof metrics reached professional threshold", `Proof score ${score}/100. Coverage: pages=${pages}, forms=${forms}, params=${params.size}, requests=${obs.length}, browser=${Boolean(context.diagnostics.browserExecuted)}, roles=${context.options.roleHeaders.length}.`), {
      id: "proofmetrics.coverage-detail",
      check: "proofmetrics",
      category: "Product Evidence",
      status: "info",
      severity: "info",
      confidence: "confirmed",
      title: "Coverage metric details",
      detail: `Parameter coverage ${params.size}; request-to-page ratio ${percent(obs.length, Math.max(1, pages))}%; browser requests ${context.diagnostics.browserNetworkRequests ?? 0}.`,
      impact: "These metrics support repeatability and identify blind spots.",
      remediation: "Track these metrics across releases and benchmark apps.",
      evidence: [{ observed: hardProof.join(", ") }],
      exploitability: "none",
    } as ScanResult];
  },
};
