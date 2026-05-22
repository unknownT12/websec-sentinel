import type { Check, ScanResult } from "../types.js";
import { request } from "../core/http.js";

export const corsCheck: Check = {
  name: "cors",
  description: "Checks for unsafe CORS wildcard/reflection with credentials.",
  async run(context) {
    const results: ScanResult[] = [];
    const origin = "https://attacker.invalid";
    const page = context.pages[0];
    if (!page) return [];
    try {
      const res = await request(page.url, context.options, { headers: { origin } });
      const allowOrigin = res.headers["access-control-allow-origin"] ?? "";
      const allowCreds = res.headers["access-control-allow-credentials"] ?? "";
      const evidence = [{ url: res.url, status: res.status, header: "access-control-allow-origin", observed: `${allowOrigin}${allowCreds ? `; credentials=${allowCreds}` : ""}` }];
      const base = { check: "cors", category: "Cross-Origin Resource Sharing", confidence: "strong" as const, evidence, owasp: ["A05:2021 Security Misconfiguration"] };
      if (allowOrigin === "*" && /true/i.test(allowCreds)) results.push({ ...base, id: "cors.wildcard.credentials", status: "fail", severity: "critical", title: "CORS wildcard is combined with credentials", detail: "The application allows any origin and credentials.", impact: "Browsers may expose authenticated API responses cross-origin in dangerous configurations.", remediation: "Use an exact origin allowlist and avoid Access-Control-Allow-Credentials unless required." });
      else if (allowOrigin === origin) results.push({ ...base, id: "cors.origin.reflection", status: /true/i.test(allowCreds) ? "fail" : "warn", severity: /true/i.test(allowCreds) ? "high" : "medium", title: "CORS reflects untrusted Origin", detail: `The application reflected ${origin} in Access-Control-Allow-Origin.`, impact: "Origin reflection can expose sensitive API responses to attacker-controlled sites.", remediation: "Validate Origin against a strict allowlist before reflecting it." });
      else if (allowOrigin === "*") results.push({ ...base, id: "cors.wildcard", status: "warn", severity: "medium", title: "CORS wildcard is enabled", detail: "Access-Control-Allow-Origin: * was observed.", impact: "Public cross-origin reads may be acceptable for static assets, but unsafe for authenticated APIs.", remediation: "Restrict CORS on API and authenticated routes to known frontend origins." });
    } catch {
      results.push({ id: "cors.unchecked", check: "cors", category: "Cross-Origin Resource Sharing", status: "info", severity: "info", confidence: "low", title: "CORS check could not complete", detail: "The target did not respond to the CORS probe within the configured timeout.", impact: "No conclusion reached.", remediation: "Re-run with a longer timeout or from a network allowed by the target." });
    }
    if (!results.length) results.push({ id: "cors.pass", check: "cors", category: "Cross-Origin Resource Sharing", status: "pass", severity: "info", confidence: "strong", title: "No unsafe CORS behavior observed", detail: "The tested untrusted Origin was not allowed.", impact: "Cross-origin browser reads appear restricted for the tested page.", remediation: "Continue validating CORS on API endpoints." });
    return results;
  },
};
