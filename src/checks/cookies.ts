import type { Check, ScanResult } from "../types.js";

function splitCookies(value: string): string[] {
  if (!value) return [];
  return value.split(/,(?=\s*[^;,]+=)/g).map((v) => v.trim()).filter(Boolean);
}

export const cookiesCheck: Check = {
  name: "cookies",
  description: "Inspects Set-Cookie attributes for secure production configuration.",
  async run(context) {
    const results: ScanResult[] = [];
    for (const page of context.pages.slice(0, 10)) {
      const raw = page.headers["set-cookie"] ?? "";
      for (const cookie of splitCookies(raw)) {
        const name = cookie.split("=")[0] ?? "cookie";
        const lower = cookie.toLowerCase();
        const evidence = [{ url: page.url, status: page.status, header: "set-cookie", observed: cookie.replace(/=.*/, "=<redacted>") }];
        const base = { check: "cookies", category: "Session Management", confidence: "strong" as const, evidence, owasp: ["A07:2021 Identification and Authentication Failures"] };
        if (!lower.includes("secure")) results.push({ ...base, id: `cookies.${name}.secure`, status: "fail", severity: "high", title: `Cookie ${name} is missing Secure`, detail: "The cookie may be transmitted over plain HTTP.", impact: "Session tokens can leak over insecure transport if users hit HTTP endpoints.", remediation: "Add the Secure attribute to all sensitive cookies." });
        if (!lower.includes("httponly")) results.push({ ...base, id: `cookies.${name}.httponly`, status: "warn", severity: "medium", title: `Cookie ${name} is missing HttpOnly`, detail: "The cookie is accessible to client-side JavaScript.", impact: "XSS can read or exfiltrate the cookie.", remediation: "Add HttpOnly to session and authentication cookies." });
        if (!/samesite=(strict|lax)/i.test(cookie)) results.push({ ...base, id: `cookies.${name}.samesite`, status: "warn", severity: "medium", title: `Cookie ${name} has weak or missing SameSite`, detail: "SameSite was not set to Lax or Strict.", impact: "Cross-site requests may carry the cookie, increasing CSRF risk.", remediation: "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required." });
        if (name.startsWith("__Host-") && (!lower.includes("secure") || /domain=/i.test(cookie) || !/path=\//i.test(cookie))) results.push({ ...base, id: `cookies.${name}.hostprefix`, status: "fail", severity: "medium", title: `Cookie ${name} violates __Host- prefix rules`, detail: "__Host- cookies require Secure, Path=/, and no Domain attribute.", impact: "The browser may reject the cookie or fail to enforce expected host-only isolation.", remediation: "Correct the cookie attributes or remove the __Host- prefix." });
      }
    }
    if (!results.length) results.push({ id: "cookies.pass", check: "cookies", category: "Session Management", status: "pass", severity: "info", confidence: "strong", title: "Cookies look hardened", detail: "No weak Set-Cookie attributes were detected on crawled pages.", impact: "Session cookies appear configured for production browser protections.", remediation: "Continue checking cookies after authentication flows and releases." });
    return results;
  },
};
