import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildAssessmentModel } from "../core/model.js";

export const evidenceQualityCheck: Check = {
  name: "evidencequality",
  description: "Checks whether scanner evidence is reproducible, diverse, authenticated when required, and strong enough to support severity decisions.",
  async run(context) {
    const results: ScanResult[] = [];
    const model = buildAssessmentModel(context);
    const c = model.coverageVector;
    const hasReplay = Boolean(context.options.replayFile);
    const hasHar = Boolean(context.options.harFile);
    const hasJsonl = Boolean(context.options.jsonlLog);
    const hasAuth = c.authenticatedSignals > 0;

    if (!hasJsonl && !hasHar && !hasReplay) {
      results.push(finding({
        id: "evidencequality.no-external-ledger",
        check: "evidencequality",
        category: "Evidence Quality",
        status: "warn",
        severity: context.options.mode === "validate" ? "medium" : "low",
        confidence: "confirmed",
        title: "No external evidence ledger configured",
        detail: "The scan did not request JSONL, HAR-like, or redacted replay evidence export.",
        impact: "Findings are harder to reproduce and review during a professional assessment handoff.",
        remediation: "Use --jsonl-log, --har, and --replay-file for professional runs so every finding can be traced back to redacted request evidence.",
        evidence: [{ observed: `jsonl=${hasJsonl} har=${hasHar} replay=${hasReplay}` }],
        exploitability: "none",
      }));
    }

    if (context.options.requireAuth && !hasAuth) {
      results.push(finding({
        id: "evidencequality.required-auth-missing",
        check: "evidencequality",
        category: "Evidence Quality",
        status: "fail",
        severity: "high",
        confidence: "confirmed",
        title: "Required authenticated evidence is missing",
        detail: "The run required authenticated coverage but the request model did not observe authenticated-supplied traffic.",
        impact: "The scan cannot support claims about protected workflows, roles, IDOR, session handling, or business logic.",
        remediation: "Use a client-approved dedicated test account/session, seed an authenticated route, and prohibit logout/destructive paths.",
        evidence: Object.entries(model.authDistribution).map(([state, count]) => ({ observed: `${state}=${count}` })),
        owasp: ["A01:2021 Broken Access Control"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    const weakEvidence = c.requestCount > 0 && c.routeCount <= 2 && c.formCount === 0 && c.parameterizedRouteCount === 0;
    if (weakEvidence) {
      results.push(finding({
        id: "evidencequality.weak-application-evidence",
        check: "evidencequality",
        category: "Evidence Quality",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Application-layer evidence is weak",
        detail: `The model saw ${c.routeCount} route group(s), ${c.formCount} form(s), and ${c.parameterizedRouteCount} parameterized route group(s).`,
        impact: "The engine may produce correct infrastructure/header findings but lacks enough application evidence for deeper assurance.",
        remediation: "Add seeds, authenticated coverage, and deep crawling; then confirm that routes, forms, scripts, and parameters are present in the model.",
        evidence: [{ observed: JSON.stringify(c) }],
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("evidencequality", "Evidence Quality", "Evidence model is adequate for configured assessment", `Request model captured ${c.requestCount} request(s), ${c.routeCount} route group(s), auth signals=${c.authenticatedSignals}, ledgers=${[hasJsonl ? "jsonl" : "", hasHar ? "har" : "", hasReplay ? "replay" : ""].filter(Boolean).join(",") || "internal-only"}.`));
    }

    return results;
  },
};
