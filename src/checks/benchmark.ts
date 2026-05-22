import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const PROFILES: Record<string, Array<{ id: string; title: string; pattern: RegExp; weight: number }>> = {
  sentinel: [
    { id: "login-form", title: "Login form discovered", pattern: /\/login|password|session/i, weight: 10 },
    { id: "dashboard", title: "Authenticated dashboard surface discovered", pattern: /\/dashboard/i, weight: 15 },
    { id: "idor-parameter", title: "Identifier-bearing parameter discovered", pattern: /studentId|userId|accountId|id=/i, weight: 20 },
    { id: "admin-route", title: "Admin route hint discovered", pattern: /\/admin/i, weight: 15 },
    { id: "api-route", title: "API route discovered", pattern: /\/api\//i, weight: 15 },
    { id: "state-change", title: "State-changing form discovered", pattern: /method\":\"POST\"|post/i, weight: 10 },
    { id: "reflection", title: "Reflection endpoint or parameter discovered", pattern: /reflect|search|q=/i, weight: 15 },
  ],
  juice: [
    { id: "login", title: "Juice Shop login surface", pattern: /\/login|email|password/i, weight: 20 },
    { id: "rest-api", title: "Juice Shop REST API surface", pattern: /\/rest\/|\/api\//i, weight: 25 },
    { id: "search", title: "Search surface", pattern: /search|q=/i, weight: 20 },
    { id: "basket", title: "Basket/order workflow", pattern: /basket|order|checkout/i, weight: 20 },
    { id: "admin", title: "Admin route signal", pattern: /admin|administration/i, weight: 15 },
  ],
  dvwa: [
    { id: "login", title: "DVWA login surface", pattern: /login|password/i, weight: 20 },
    { id: "sqli", title: "SQL injection training route signal", pattern: /sqli|sql/i, weight: 25 },
    { id: "xss", title: "XSS training route signal", pattern: /xss/i, weight: 25 },
    { id: "csrf", title: "CSRF training route signal", pattern: /csrf/i, weight: 15 },
    { id: "upload", title: "Upload training route signal", pattern: /upload/i, weight: 15 },
  ],
};

export const benchmarkCheck: Check = {
  name: "benchmark",
  description: "Measures scanner detections against known vulnerable app profiles without claiming universal coverage.",
  async run(context) {
    const profileName = context.options.benchmarkProfile;
    if (!profileName) {
      return [finding({
        id: "benchmark.not-configured",
        check: "benchmark",
        category: "Benchmarking",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Benchmark profile not configured",
        detail: "No --benchmark-profile was supplied, so known-vulnerable-app coverage was not measured in this run.",
        impact: "Product claims should be backed by repeatable benchmark runs against controlled vulnerable apps or fixtures.",
        remediation: "Run with --benchmark-profile sentinel, juice, or dvwa against an approved lab target and preserve the JSON report as evidence.",
        exploitability: "none",
      })];
    }
    const profile = PROFILES[profileName];
    if (!profile) {
      return [finding({ id: "benchmark.unknown-profile", check: "benchmark", category: "Benchmarking", status: "warn", severity: "medium", confidence: "confirmed", title: "Unknown benchmark profile", detail: `Unknown profile: ${profileName}.`, impact: "Benchmark expectations could not be evaluated.", remediation: `Use one of: ${Object.keys(PROFILES).join(", ")}.`, exploitability: "none" })];
    }
    const corpus = JSON.stringify({ pages: context.pages.map((p) => ({ url: p.url, finalUrl: p.finalUrl, title: p.title, links: p.links, forms: p.forms, routes: p.routeHints, body: p.body.slice(0, 2000) })) });
    const hits = profile.filter((p) => p.pattern.test(corpus));
    context.diagnostics.benchmarkExpected = profile.length;
    context.diagnostics.benchmarkDetected = hits.length;
    const score = Math.round((hits.reduce((s, h) => s + h.weight, 0) / profile.reduce((s, h) => s + h.weight, 0)) * 100);
    if (score < 70) {
      return [finding({
        id: "benchmark.coverage-below-professional-threshold",
        check: "benchmark",
        category: "Benchmarking",
        status: "warn",
        severity: score < 40 ? "high" : "medium",
        confidence: "confirmed",
        title: "Benchmark coverage is below product threshold",
        detail: `Profile ${profileName} score was ${score}/100 (${hits.length}/${profile.length} expected signals).`,
        impact: "The engine has not demonstrated enough repeatable detection coverage on this known vulnerable/lab profile.",
        remediation: "Improve crawling, browser execution, authentication, and safe validation until benchmark coverage is at least 70% for the selected profile.",
        evidence: profile.map((p) => ({ observed: `${p.id}: ${hits.includes(p) ? "detected" : "missing"}` })).slice(0, context.options.evidenceLimit),
        exploitability: "none",
      })];
    }
    return [pass("benchmark", "Benchmarking", "Benchmark coverage reached product threshold", `Profile ${profileName}: ${score}/100, detected ${hits.length}/${profile.length} expected signals.`)];
  },
};
