import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request } from "../core/http.js";

const DANGEROUS = ["PUT", "PATCH", "DELETE", "TRACE", "CONNECT"];
const WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

function parseAllow(headers: Record<string, string>): string[] {
  const allow = `${headers["allow"] ?? ""},${headers["access-control-allow-methods"] ?? ""}`;
  return [...new Set(allow.split(/[,\s]+/).map((m) => m.trim().toUpperCase()).filter(Boolean))];
}

export const methodsCheck: Check = {
  name: "methods",
  description: "Safely reviews advertised HTTP methods using OPTIONS without sending write requests.",
  async run(context) {
    const results: ScanResult[] = [];
    const urls = [...new Set([context.options.target, ...context.pages.slice(0, context.options.evidenceLimit).map((p) => p.finalUrl || p.url)])];
    const dangerousEvidence: ScanResult["evidence"] = [];
    const writeEvidence: ScanResult["evidence"] = [];

    for (const url of urls) {
      try {
        const res = await request(url, context.options, { method: "OPTIONS", redirect: "manual" });
        const allowed = parseAllow(res.headers);
        if (!allowed.length) continue;
        const dangerous = allowed.filter((m) => DANGEROUS.includes(m));
        if (dangerous.length) dangerousEvidence.push({ url, method: "OPTIONS", status: res.status, header: "allow", observed: dangerous.join(", "), requestId: res.requestId });
        const write = allowed.filter((m) => WRITE_METHODS.includes(m));
        if (write.length) writeEvidence.push({ url, method: "OPTIONS", status: res.status, header: "allow", observed: write.join(", "), requestId: res.requestId });
      } catch {}
    }

    if (dangerousEvidence.length) {
      results.push(finding({
        id: "methods.dangerous-advertised",
        check: "methods",
        category: "HTTP Method Exposure",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Potentially dangerous HTTP methods are advertised",
        detail: "One or more endpoints advertise methods such as PUT, PATCH, DELETE, TRACE, or CONNECT through OPTIONS/Allow headers.",
        impact: "Unexpected write or diagnostic methods can increase attack surface if routing, proxies, or authorization middleware are misconfigured.",
        businessImpact: "Incorrect method exposure can create unauthorized modification, request smuggling support, or legacy diagnostic leakage risks.",
        remediation: "Restrict allowed methods at the application, web server, and reverse proxy layers; explicitly block TRACE and unused write verbs.",
        evidence: dangerousEvidence.slice(0, context.options.evidenceLimit),
        owasp: ["A05:2021 Security Misconfiguration", "A01:2021 Broken Access Control"],
        cwe: ["CWE-650"],
        exploitability: "theoretical",
        verification: "Confirm by reviewing routing/proxy configuration. Do not test write verbs on production unless the engagement explicitly approves safe test objects.",
      }));
    } else if (writeEvidence.length) {
      results.push(finding({
        id: "methods.write-methods-advertised",
        check: "methods",
        category: "HTTP Method Exposure",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Write-capable HTTP methods are advertised",
        detail: "OPTIONS responses include write-capable methods. This may be normal for API endpoints, but should be governed by strong authorization and CSRF/session controls.",
        impact: "Write methods require careful authorization, CSRF, logging, and rate limiting controls.",
        remediation: "Ensure all write methods enforce authorization, anti-CSRF/session protections where applicable, and audit logging.",
        evidence: writeEvidence.slice(0, context.options.evidenceLimit),
        owasp: ["A01:2021 Broken Access Control"],
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("methods", "HTTP Method Exposure", "No dangerous HTTP methods advertised", "OPTIONS/Allow review did not identify dangerous methods on tested endpoints."));
    return results;
  },
};
