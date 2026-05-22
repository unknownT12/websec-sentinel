import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildProductEngineModel } from "../core/productengine.js";

export const testVectorsCheck: Check = {
  name: "testvectors",
  description: "Generates and evaluates safe, book-scoped assessment test vectors from the observed application model.",
  async run(context) {
    const model = buildProductEngineModel(context);
    const vectors = model.testVectors;
    if (!vectors.length) {
      return [finding({
        id: "testvectors.none-generated",
        check: "testvectors",
        category: "Product Test Planning",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "No executable product test vectors were generated",
        detail: "The observed surface did not include enough high-value routes, parameters, or state-changing workflows to build a meaningful test queue.",
        impact: "The assessment remains shallow and cannot support medium-impact product claims.",
        remediation: "Improve crawling depth, add approved seeds, and supply authenticated coverage.",
        evidence: [{ observed: JSON.stringify(model.modelEvidence) }],
        exploitability: "none",
      })];
    }

    const blocked = vectors.filter((v) => !v.canRunNow);
    const high = vectors.filter((v) => v.priority === "high" || v.priority === "critical");
    const results: ScanResult[] = [pass("testvectors", "Product Test Planning", "Safe product test vectors generated", `${vectors.length} vector(s) generated from the model; high-priority=${high.length}; blocked=${blocked.length}.`)];
    if (blocked.length) {
      results.push(finding({
        id: "testvectors.blocked-by-coverage",
        check: "testvectors",
        category: "Product Test Planning",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Some high-value test vectors are blocked by missing prerequisites",
        detail: blocked.slice(0, 5).map((v) => `${v.id}: ${v.blockers.join(", ")}`).join(" | "),
        impact: "The engine knows what should be tested, but the current run does not have the auth/coverage prerequisites to execute those checks meaningfully.",
        remediation: "Supply approved authenticated sessions, seeds, and evidence exports. Do not downgrade this as a tool flaw; treat it as a run-readiness gap.",
        evidence: blocked.slice(0, context.options.evidenceLimit).map((v) => ({ url: v.route, method: v.method, observed: v.title, expected: v.promotionRule })),
        exploitability: "none",
      }));
    }
    return results;
  },
};
