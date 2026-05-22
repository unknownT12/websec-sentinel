import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

function authSupplied(headers: Record<string, string>): boolean {
  return Object.keys(headers).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

function localCoverageScore(context: Parameters<Check["run"]>[0]): number {
  const pages = context.pages.length;
  const forms = context.pages.reduce((s, p) => s + p.forms.length, 0);
  const links = context.pages.reduce((s, p) => s + p.links.length, 0);
  const routes = context.pages.reduce((s, p) => s + p.routeHints.length, 0);
  const scripts = context.pages.reduce((s, p) => s + p.scripts.length, 0);
  let score = 0;
  if (pages > 0) score += 20;
  if (pages >= context.options.minPages) score += 20;
  if (links > 0) score += 10;
  if (routes > 0) score += 15;
  if (forms > 0) score += 15;
  if (scripts > 0) score += 10;
  if (authSupplied(context.options.customHeaders)) score += 10;
  return Math.min(100, score);
}

export const assuranceCheck: Check = {
  name: "assurance",
  description: "Applies an explicit coverage contract so professional reports cannot overclaim shallow testing.",
  async run(context) {
    const results: ScanResult[] = [];
    const score = localCoverageScore(context);
    const auth = authSupplied(context.options.customHeaders);
    const forms = context.pages.reduce((s, p) => s + p.forms.length, 0);
    const routes = context.pages.reduce((s, p) => s + p.routeHints.length, 0);

    if (score < context.options.minCoverageScore || context.pages.length < context.options.minPages || (context.options.requireAuth && !auth)) {
      const reasons = [
        score < context.options.minCoverageScore ? `coverage ${score}/100 below required ${context.options.minCoverageScore}/100` : "",
        context.pages.length < context.options.minPages ? `only ${context.pages.length} page(s) crawled; required ${context.options.minPages}` : "",
        context.options.requireAuth && !auth ? "authenticated coverage required but no auth/session header was supplied" : "",
      ].filter(Boolean);
      results.push(finding({
        id: "assurance.coverage-contract-not-met",
        check: "assurance",
        category: "Assessment Assurance",
        status: "fail",
        severity: context.options.mode === "validate" ? "high" : "medium",
        confidence: "confirmed",
        title: "Assessment coverage contract was not met",
        detail: reasons.join("; "),
        impact: "The scan result cannot be used as professional assurance because the tested surface was too limited for the declared coverage target.",
        businessImpact: "A shallow test can miss access-control, workflow, and application-layer defects while still producing a polished report.",
        remediation: "Add approved seed URLs, authenticated test-session headers, higher crawl depth, and documented scope until the coverage contract passes.",
        evidence: [{ observed: `coverage=${score}/100 pages=${context.pages.length} forms=${forms} routes=${routes} auth=${auth ? "yes" : "no"}` }],
        owasp: ["A04:2021 Insecure Design"],
        cwe: ["CWE-1059"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    } else {
      results.push(pass("assurance", "Assessment Assurance", "Assessment coverage contract passed", `Coverage score ${score}/100 met the configured professional threshold.`));
    }

    if (context.options.mode === "validate" && !context.options.prohibitedPaths.length) {
      results.push(finding({
        id: "assurance.no-prohibited-paths",
        check: "assurance",
        category: "Assessment Safety",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "Validate mode has no prohibited path guardrail",
        detail: "No prohibited paths were supplied for validate mode.",
        impact: "Automated crawlers can accidentally hit logout or state-changing routes unless sensitive paths are explicitly excluded.",
        remediation: "Add --prohibited-paths /logout,/delete,/remove,/reset,/billing,/payment,/admin/delete or client-approved equivalents.",
        evidence: [{ observed: "prohibitedPaths=none" }],
        exploitability: "none",
      }));
    }
    return results;
  },
};
