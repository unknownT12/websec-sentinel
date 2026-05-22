import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const RISKY_PARAMS = /(redirect|return|next|url|callback|continue|target|dest|destination|file|path|template|debug|admin|token|key|secret|password)/i;

export const surfaceCheck: Check = {
  name: "surface",
  description: "Analyzes crawled attack surface for risky parameters, forms, status-code anomalies, and exposed client routes.",
  async run(context) {
    const results: ScanResult[] = [];
    const riskyUrls = context.pages
      .map((p) => new URL(p.finalUrl || p.url))
      .filter((u) => [...u.searchParams.keys()].some((k) => RISKY_PARAMS.test(k)))
      .slice(0, context.options.evidenceLimit);

    if (riskyUrls.length) {
      results.push(finding({
        id: "surface.risky-parameters",
        check: "surface",
        category: "Attack Surface Management",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Risk-sensitive URL parameters observed",
        detail: "The crawler found parameters commonly associated with redirect, file/path handling, debug toggles, or sensitive token flows.",
        impact: "These parameters often become exploit pivots for open redirects, file access flaws, SSRF-like behavior, token leakage, or authorization bypass chains.",
        businessImpact: "A small number of risky parameters can create high-value entry points for account takeover or data exposure when combined with weak authorization checks.",
        remediation: "Threat-model each parameter, enforce strict allowlists, validate server-side, and add automated tests for redirect/path/token handling.",
        evidence: riskyUrls.map((u) => ({ url: u.toString(), parameter: [...u.searchParams.keys()].filter((k) => RISKY_PARAMS.test(k)).join(", ") })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        cwe: ["CWE-20", "CWE-601"],
        exploitability: "practical",
        tags: ["attack-surface", "parameters"],
      }));
    }

    const passwordForms = context.pages.flatMap((p) => p.forms.filter((f) => f.inputs.some((i) => /password/i.test(i.type))).map((f) => ({ page: p.url, form: f })));
    for (const item of passwordForms.slice(0, context.options.evidenceLimit)) {
      const formUrl = new URL(item.form.action);
      if (formUrl.protocol !== "https:") {
        results.push(finding({
          id: "surface.password-form-insecure-transport",
          check: "surface",
          category: "Authentication Surface",
          status: "fail",
          severity: "high",
          confidence: "strong",
          title: "Password form can submit over non-HTTPS transport",
          detail: "A password input was observed where the form action does not use HTTPS.",
          impact: "Credentials may be exposed to network attackers or downgraded transport paths.",
          businessImpact: "Credential compromise can directly lead to account takeover and incident-response obligations.",
          remediation: "Force HTTPS at the origin/CDN, redirect HTTP to HTTPS, and ensure every credential form action uses HTTPS.",
          evidence: [{ url: item.page, observed: item.form.action }],
          owasp: ["A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"],
          cwe: ["CWE-319"],
          exploitability: "practical",
        }));
      }
    }

    const serverErrors = context.pages.filter((p) => p.status >= 500).slice(0, context.options.evidenceLimit);
    if (serverErrors.length) {
      results.push(finding({
        id: "surface.server-errors",
        check: "surface",
        category: "Reliability and Exposure",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Server errors observed during safe crawl",
        detail: "One or more crawled pages returned HTTP 5xx responses.",
        impact: "Unhandled errors may expose stack traces, unstable code paths, or denial-of-service risk indicators.",
        remediation: "Review application logs for the request IDs, add error handling, and ensure production stack traces are disabled.",
        evidence: serverErrors.map((p) => ({ url: p.url, status: p.status, requestId: p.requestId, elapsedMs: p.elapsedMs })),
        owasp: ["A05:2021 Security Misconfiguration"],
        cwe: ["CWE-209"],
      }));
    }

    if (!results.length) results.push(pass("surface", "Attack Surface Management", "No high-risk crawl surface signals detected", "The crawled pages did not show risky parameter names, insecure password form actions, or HTTP 5xx anomalies."));
    return results;
  },
};
