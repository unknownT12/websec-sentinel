import type { Check, ScanResult } from "../types.js";

function finding(partial: Omit<ScanResult, "category" | "confidence" | "owasp"> & Partial<Pick<ScanResult, "confidence" | "owasp">>): ScanResult {
  return { category: "Security Headers", confidence: partial.confidence ?? "strong", owasp: partial.owasp ?? ["A05:2021 Security Misconfiguration"], ...partial };
}

export const headersCheck: Check = {
  name: "headers",
  description: "Validates core browser security headers and information disclosure.",
  async run(context) {
    const home = context.pages[0];
    if (!home) return [];
    const h = home.headers;
    const results: ScanResult[] = [];

    const required = [
      ["strict-transport-security", "HSTS is missing", "Add Strict-Transport-Security with max-age>=31536000; includeSubDomains; preload.", "high"],
      ["content-security-policy", "Content Security Policy is missing", "Deploy a restrictive CSP using nonces/hashes and avoid unsafe-inline.", "high"],
      ["x-content-type-options", "X-Content-Type-Options is missing", "Set X-Content-Type-Options: nosniff.", "medium"],
      ["referrer-policy", "Referrer-Policy is missing", "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.", "low"],
      ["permissions-policy", "Permissions-Policy is missing", "Disable unnecessary browser features using Permissions-Policy.", "low"],
    ] as const;

    for (const [header, title, remediation, severity] of required) {
      if (!h[header]) {
        results.push(finding({ id: `headers.${header}.missing`, check: "headers", status: severity === "low" ? "warn" : "fail", severity, title, detail: title, impact: "Missing browser hardening increases the impact of client-side attacks and misconfiguration abuse.", remediation, evidence: [{ url: home.url, status: home.status, header }] }));
      }
    }

    const frame = h["x-frame-options"] ?? "";
    const csp = h["content-security-policy"] ?? "";
    if (!frame && !/frame-ancestors/i.test(csp)) {
      results.push(finding({ id: "headers.clickjacking", check: "headers", status: "fail", severity: "medium", title: "Clickjacking protection is missing", detail: "No X-Frame-Options header and no CSP frame-ancestors directive were observed.", impact: "Users may be tricked into clicking sensitive actions through framed UI overlays.", remediation: "Set CSP frame-ancestors 'none' or a strict allowlist, or X-Frame-Options: DENY/SAMEORIGIN.", evidence: [{ url: home.url, status: home.status }] }));
    }

    for (const leak of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
      if (h[leak]) {
        results.push(finding({ id: `headers.info.${leak}`, check: "headers", status: "warn", severity: "low", title: `Technology disclosure through ${leak}`, detail: `${leak}: ${h[leak]}`, impact: "Version and framework leakage can help attackers tailor exploit research.", remediation: `Remove or minimize the ${leak} response header.`, evidence: [{ url: home.url, status: home.status, header: leak, observed: h[leak] }] }));
      }
    }

    if (!results.length) results.push(finding({ id: "headers.pass", check: "headers", status: "pass", severity: "info", title: "Security headers look production ready", detail: "Core security headers were present.", impact: "Browser-side baseline protections are active.", remediation: "Continue validating header policy during releases." }));
    return results;
  },
};
