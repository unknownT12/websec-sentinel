import type { Check, ScanResult } from "../types.js";
import { request } from "../core/http.js";

const PRIVATE_ROUTES = ["/admin", "/dashboard", "/account", "/profile", "/settings", "/api/me", "/api/user", "/api/admin", "/api/users"];
const LOGIN_HINTS = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth/login", "/admin/login"];

function isLikelyPrivateSuccess(status: number, body: string): boolean {
  if (status === 401 || status === 403 || status === 404) return false;
  if (status >= 200 && status < 300) return /logout|account|dashboard|admin|profile|settings|user/i.test(body);
  return false;
}

export const authCheck: Check = {
  name: "auth",
  description: "Checks unauthenticated access signals and login hardening indicators.",
  async run(context) {
    const results: ScanResult[] = [];
    const base = context.targetUrl.origin;
    if (context.options.mode === "passive") {
      const body = context.pages.map((p) => p.body).join("\n");
      if (/forgot password|reset password/i.test(body) && !/csrf|_token|authenticity_token/i.test(body)) {
        results.push({ id: "auth.reset.csrf-signal", check: "auth", category: "Authentication", status: "warn", severity: "medium", confidence: "low", title: "Password reset flow may need CSRF review", detail: "Password reset content was seen but no obvious CSRF token marker was detected in crawled HTML.", impact: "Weak reset protection can enable account workflow abuse.", remediation: "Ensure reset forms use CSRF tokens, rate limiting, short-lived tokens, and generic responses.", owasp: ["A07:2021 Identification and Authentication Failures"] });
      }
      if (!results.length) results.push({ id: "auth.passive.info", check: "auth", category: "Authentication", status: "info", severity: "info", confidence: "low", title: "Passive auth review completed", detail: "No obvious authentication signals were detected passively.", impact: "Authentication coverage is limited in passive mode.", remediation: "Use standard mode under authorization for route checks." });
      return results;
    }

    for (const path of PRIVATE_ROUTES) {
      try {
        const res = await request(`${base}${path}`, context.options);
        if (isLikelyPrivateSuccess(res.status, res.body)) {
          results.push({ id: `auth.private.${path.replace(/[^a-z0-9]/gi, "_")}`, check: "auth", category: "Authentication", status: "fail", severity: path.includes("admin") ? "critical" : "high", confidence: "moderate", title: `Unauthenticated access signal on ${path}`, detail: `${path} returned HTTP ${res.status} and content that looks like a private area.`, impact: "Private data or privileged functionality may be reachable without authentication.", remediation: "Require server-side authentication and authorization checks on every private route and API endpoint.", evidence: [{ url: res.url, status: res.status, snippet: res.body.replace(/\s+/g, " ").slice(0, 220) }], owasp: ["A01:2021 Broken Access Control", "A07:2021 Identification and Authentication Failures"] });
        }
      } catch {}
    }

    for (const path of LOGIN_HINTS) {
      try {
        const res = await request(`${base}${path}`, context.options, { method: "OPTIONS", redirect: "manual" });
        const methods = res.headers.allow ?? res.headers["access-control-allow-methods"] ?? "";
        if (/PUT|DELETE|TRACE/i.test(methods)) {
          results.push({ id: `auth.methods.${path.replace(/[^a-z0-9]/gi, "_")}`, check: "auth", category: "Authentication", status: "warn", severity: "medium", confidence: "moderate", title: `Risky HTTP methods advertised on ${path}`, detail: `Allowed methods: ${methods}`, impact: "Unexpected HTTP methods on authentication endpoints increase attack surface and misconfiguration risk.", remediation: "Restrict authentication endpoints to the minimum required methods, typically GET/POST plus OPTIONS where needed.", evidence: [{ url: res.url, status: res.status, header: "allow", observed: methods }], owasp: ["A05:2021 Security Misconfiguration"] });
        }
      } catch {}
    }

    if (!results.length) results.push({ id: "auth.pass", check: "auth", category: "Authentication", status: "pass", severity: "info", confidence: "moderate", title: "No unauthenticated private-route signals found", detail: "Common private route checks did not show obvious public access.", impact: "Authentication exposure appears reduced for tested routes.", remediation: "Continue authenticated role-based testing for complete coverage." });
    return results;
  },
};
