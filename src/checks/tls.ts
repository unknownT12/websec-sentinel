import type { Check, ScanResult } from "../types.js";
import { request } from "../core/http.js";

export const tlsCheck: Check = {
  name: "tls",
  description: "Checks HTTPS, HTTP to HTTPS redirect behavior, and HSTS strength.",
  async run(context) {
    const { targetUrl, options } = context;
    const results: ScanResult[] = [];
    const baseEvidence = [{ url: targetUrl.toString() }];
    if (targetUrl.protocol !== "https:") {
      results.push({ id: "tls.no-https", check: "tls", category: "Transport Security", status: "fail", severity: "critical", confidence: "confirmed", title: "Target is not using HTTPS", detail: "The supplied target URL uses plain HTTP.", impact: "Credentials, sessions, and sensitive data can be intercepted or modified in transit.", remediation: "Serve the application exclusively over HTTPS and redirect all HTTP traffic to HTTPS.", evidence: baseEvidence, owasp: ["A02:2021 Cryptographic Failures"] });
      return results;
    }
    results.push({ id: "tls.https", check: "tls", category: "Transport Security", status: "pass", severity: "info", confidence: "confirmed", title: "HTTPS is enabled", detail: "The target uses HTTPS.", impact: "Traffic confidentiality and integrity are protected by TLS.", remediation: "Continue monitoring certificate expiration and TLS configuration." });

    try {
      const httpUrl = `http://${targetUrl.host}${targetUrl.pathname}`;
      const res = await request(httpUrl, options, { method: "HEAD", redirect: "manual" });
      const location = res.headers.location ?? "";
      if (res.status >= 300 && res.status < 400 && location.startsWith("https://")) {
        results.push({ id: "tls.redirect", check: "tls", category: "Transport Security", status: "pass", severity: "info", confidence: "confirmed", title: "HTTP redirects to HTTPS", detail: "Plain HTTP requests are redirected to HTTPS.", impact: "Accidental HTTP access is upgraded to a secure channel.", remediation: "Keep redirect behavior in place." });
      } else if (res.status < 400) {
        results.push({ id: "tls.http-content", check: "tls", category: "Transport Security", status: "fail", severity: "high", confidence: "strong", title: "HTTP endpoint serves content or redirects unsafely", detail: `HTTP returned ${res.status}${location ? ` with Location ${location}` : ""}.`, impact: "Users may access insecure content or lose protection during downgrade attempts.", remediation: "Return a permanent redirect from HTTP to the canonical HTTPS URL.", evidence: [{ url: httpUrl, status: res.status, header: "location", observed: location }], owasp: ["A02:2021 Cryptographic Failures"] });
      }
    } catch {
      results.push({ id: "tls.http-unreachable", check: "tls", category: "Transport Security", status: "info", severity: "info", confidence: "moderate", title: "HTTP endpoint is unreachable", detail: "Plain HTTP did not respond, which may be acceptable if blocked intentionally.", impact: "HTTP downgrade risk appears reduced.", remediation: "Confirm this is enforced at the edge or load balancer." });
    }

    const home = context.pages[0];
    const hsts = home?.headers["strict-transport-security"] ?? "";
    if (!hsts) {
      results.push({ id: "tls.hsts-missing", check: "tls", category: "Transport Security", status: "fail", severity: "high", confidence: "strong", title: "HSTS is missing", detail: "Strict-Transport-Security header was not observed.", impact: "Browsers may be vulnerable to SSL stripping on first connection.", remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload after validating all subdomains support HTTPS.", evidence: [{ url: home?.url, status: home?.status, header: "strict-transport-security" }], owasp: ["A02:2021 Cryptographic Failures"] });
    } else {
      const maxAge = Number(hsts.match(/max-age=(\d+)/i)?.[1] ?? 0);
      if (maxAge < 31536000) results.push({ id: "tls.hsts-short", check: "tls", category: "Transport Security", status: "warn", severity: "medium", confidence: "strong", title: "HSTS max-age is too short", detail: `Observed max-age=${maxAge}.`, impact: "Short HSTS windows reduce downgrade protection.", remediation: "Use max-age of at least 31536000 seconds after rollout validation.", evidence: [{ url: home?.url, status: home?.status, header: "strict-transport-security", observed: hsts }] });
    }
    return results;
  },
};
