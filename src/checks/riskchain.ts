import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const HIGH_VALUE = /(admin|dashboard|student|grade|marks|profile|account|api|settings|users|reports|upload|export|payment|billing)/i;
const STATE = /(post|put|patch|delete)/i;

export const riskchainCheck: Check = {
  name: "riskchain",
  description: "Builds non-exploitative attack-path hypotheses from observed routes, forms, auth coverage, cache, and workflow signals.",
  async run(context) {
    const pages = context.pages;
    const highValuePages = pages.filter((p) => HIGH_VALUE.test(p.finalUrl || p.url) || HIGH_VALUE.test(p.title ?? ""));
    const stateForms = pages.flatMap((p) => p.forms.map((f) => ({ page: p, form: f }))).filter(({ form }) => STATE.test(form.method) || form.inputs.some((i) => HIGH_VALUE.test(i.name)));
    const auth = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
    const noCsrf = stateForms.filter(({ form }) => !form.hasCsrfToken);
    const weakCache = highValuePages.filter((p) => !/(no-store|private)/i.test(p.headers["cache-control"] ?? ""));

    const results: ScanResult[] = [];
    if (highValuePages.length && !auth) {
      results.push(finding({
        id: "riskchain.high-value-unauthenticated-observed",
        check: "riskchain",
        category: "Attack Path Analysis",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "High-value route class observed without authenticated coverage",
        detail: `Observed ${highValuePages.length} high-value route/page signal(s), but the scan was not authenticated.`,
        impact: "The most important authorization and workflow risks are likely behind login and were not validated by this run.",
        remediation: "Run with a dedicated approved test account/session, seed dashboard/API URLs, and compare low-privilege vs expected access manually.",
        evidence: highValuePages.slice(0, context.options.evidenceLimit).map((p) => ({ url: p.url, status: p.status, observed: p.title ?? p.finalUrl, requestId: p.requestId })),
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-284"],
      }));
    }

    if (noCsrf.length && highValuePages.length) {
      results.push(finding({
        id: "riskchain.workflow-csrf-chain",
        check: "riskchain",
        category: "Attack Path Analysis",
        status: "warn",
        severity: "high",
        confidence: "moderate",
        title: "Potential workflow abuse chain: high-value area plus forms without CSRF signal",
        detail: "High-value routes and state-changing forms without an obvious CSRF marker were observed in the same assessed surface.",
        impact: "This combination can increase the chance that an authenticated user can be tricked into submitting unintended actions, pending manual confirmation.",
        remediation: "Validate server-side CSRF protections on each state-changing endpoint, add origin checks, and add regression tests for workflow protection.",
        evidence: noCsrf.slice(0, context.options.evidenceLimit).map(({ page, form }) => ({ url: page.url, method: form.method, observed: form.action, requestId: page.requestId })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        cwe: ["CWE-352"],
        exploitability: "practical",
        chainLinks: ["high-value route", "state-changing form", "missing visible CSRF marker"],
      }));
    }

    if (weakCache.length && auth) {
      results.push(finding({
        id: "riskchain.authenticated-cache-chain",
        check: "riskchain",
        category: "Attack Path Analysis",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Authenticated high-value pages may lack strict cache controls",
        detail: "Authenticated scan headers were supplied and high-value pages were observed without strict Cache-Control signals.",
        impact: "Sensitive pages may be retained in browser/proxy caches, increasing local-device and shared-cache exposure risk.",
        remediation: "Set Cache-Control: no-store on authenticated sensitive pages and verify browser back-button/cache behavior after logout.",
        evidence: weakCache.slice(0, context.options.evidenceLimit).map((p) => ({ url: p.url, status: p.status, header: "cache-control", observed: p.headers["cache-control"] ?? "missing", requestId: p.requestId })),
        owasp: ["A02:2021 Cryptographic Failures", "A05:2021 Security Misconfiguration"],
        cwe: ["CWE-525"],
      }));
    }

    if (!results.length) results.push(pass("riskchain", "Attack Path Analysis", "No chained risk hypothesis crossed the reporting threshold", "The observed surface did not combine high-value routes, state-changing forms, weak cache controls, or authentication gaps into a material attack-path hypothesis."));
    return results;
  },
};
