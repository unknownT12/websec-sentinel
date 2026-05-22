import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

export const validationMatrixCheck: Check = {
  name: "validationmatrix",
  description: "Scores reproducibility, false-positive controls, benchmark evidence, and tool-readiness as product metrics.",
  async run(context) {
    const pages = context.pages.length;
    const forms = context.pages.reduce((n, p) => n + p.forms.length, 0);
    const params = context.pages.reduce((n, p) => n + [...new URL(p.finalUrl || p.url).searchParams.keys()].length + p.forms.reduce((s, f) => s + f.inputs.filter((i) => i.name).length, 0), 0);
    const evidenceExports = [context.options.jsonlLog, context.options.harFile, context.options.replayFile].filter(Boolean).length;
    const hasBrowser = Boolean(context.diagnostics.browserExecuted);
    const hasRoles = context.options.roleHeaders.length >= 2;
    const benchmarked = Boolean(context.options.benchmarkProfile);
    const externalBenchmarked = Boolean(context.options.benchmarkGroundTruth);
    const score = Math.min(100, (pages >= context.options.minPages ? 15 : 0) + (forms ? 10 : 0) + (params ? 15 : 0) + (evidenceExports * 10) + (hasBrowser ? 15 : 0) + (hasRoles ? 10 : 0) + (benchmarked ? 5 : 0) + (externalBenchmarked ? 10 : 0));
    if (score < 70) {
      return [finding({
        id: "validationmatrix.product-evidence-below-bar",
        check: "validationmatrix",
        category: "Product Evidence",
        status: "warn",
        severity: score < 45 ? "high" : "medium",
        confidence: "confirmed",
        title: "Product evidence matrix is below professional threshold",
        detail: `Evidence score is ${score}/100. Product claims need crawl coverage, parameters/forms, browser execution, role comparison, external benchmarks, and replayable evidence.`,
        impact: "The run may be useful as an assessment assistant but is not enough to support exceptional product claims.",
        remediation: "Run with --browser-crawl, --benchmark-profile, --benchmark-ground-truth, HAR/JSONL/replay exports, approved role headers, adequate seeds, and authenticated sessions.",
        evidence: [{ observed: `pages=${pages}; forms=${forms}; params=${params}; evidenceExports=${evidenceExports}; browser=${hasBrowser}; roles=${context.options.roleHeaders.length}; benchmark=${benchmarked}; externalBenchmark=${externalBenchmarked}` }],
        exploitability: "none",
      })];
    }
    return [pass("validationmatrix", "Product Evidence", "Product evidence matrix reached professional threshold", `Evidence score ${score}/100 with browser=${hasBrowser}, roleHeaders=${context.options.roleHeaders.length}, benchmark=${benchmarked}, externalBenchmark=${externalBenchmarked}.`)];
  },
};
