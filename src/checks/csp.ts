import type { Check, ScanResult } from "../types.js";

export const cspCheck: Check = {
  name: "csp",
  description: "Reviews CSP quality, unsafe directives, and frame restrictions.",
  async run(context) {
    const home = context.pages[0];
    if (!home) return [];
    const csp = home.headers["content-security-policy"] ?? "";
    const results: ScanResult[] = [];
    const mk = (id: string, severity: ScanResult["severity"], title: string, detail: string, remediation: string): ScanResult => ({
      id, check: "csp", category: "Content Security Policy", status: severity === "low" ? "warn" : "fail", severity, confidence: "strong", title, detail,
      impact: "A weak CSP makes XSS, clickjacking, and data injection attacks easier to execute and harder to contain.", remediation,
      evidence: [{ url: home.url, status: home.status, header: "content-security-policy", observed: csp.slice(0, 300) }], owasp: ["A03:2021 Injection", "A05:2021 Security Misconfiguration"],
    });
    if (!csp) return [{ id: "csp.missing", check: "csp", category: "Content Security Policy", status: "fail", severity: "high", confidence: "strong", title: "CSP is not configured", detail: "No Content-Security-Policy response header was observed.", impact: "Successful XSS is more likely to result in full session compromise.", remediation: "Define a default-src 'self' baseline, add nonces/hashes for scripts, and tighten connect/img/frame directives.", evidence: [{ url: home.url, status: home.status, header: "content-security-policy" }], owasp: ["A03:2021 Injection"] }];
    if (/unsafe-inline/i.test(csp)) results.push(mk("csp.unsafe-inline", "high", "CSP allows unsafe-inline", "The policy contains unsafe-inline.", "Remove unsafe-inline and use script nonces or hashes."));
    if (/unsafe-eval/i.test(csp)) results.push(mk("csp.unsafe-eval", "medium", "CSP allows unsafe-eval", "The policy contains unsafe-eval.", "Remove unsafe-eval and refactor libraries requiring dynamic evaluation."));
    if (/(script-src|default-src)[^;]*\*/i.test(csp)) results.push(mk("csp.wildcard-script", "high", "CSP has wildcard script source", "script-src/default-src includes a wildcard.", "Replace wildcards with exact trusted origins."));
    if (!/object-src/i.test(csp)) results.push(mk("csp.object-src", "low", "CSP does not restrict object-src", "object-src directive was not found.", "Add object-src 'none'."));
    if (!/base-uri/i.test(csp)) results.push(mk("csp.base-uri", "low", "CSP does not restrict base-uri", "base-uri directive was not found.", "Add base-uri 'self' or 'none'."));
    if (!results.length) results.push({ id: "csp.pass", check: "csp", category: "Content Security Policy", status: "pass", severity: "info", confidence: "strong", title: "CSP baseline is present", detail: "No obvious weak CSP directives were detected.", impact: "CSP can reduce the blast radius of client-side injection.", remediation: "Keep testing CSP through staging and production releases." });
    return results;
  },
};
