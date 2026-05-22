import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request } from "../core/http.js";

const RISKY_METHODS = ["TRACE", "PUT", "DELETE", "PATCH"];

export const resilienceCheck: Check = {
  name: "resilience",
  description: "Checks safe operational resilience signals: risky methods, cache controls, error leakage, and basic abuse-resistance headers.",
  async run(context) {
    const results: ScanResult[] = [];
    const page = context.pages[0];
    if (!page) return [];

    try {
      const res = await request(page.url, context.options, { method: "OPTIONS", redirect: "manual" });
      const allow = `${res.headers.allow ?? ""},${res.headers["access-control-allow-methods"] ?? ""}`;
      const risky = RISKY_METHODS.filter((m) => new RegExp(`(^|[,\\s])${m}([,\\s]|$)`, "i").test(allow));
      if (risky.length) {
        results.push(finding({
          id: "resilience.risky-methods",
          check: "resilience",
          category: "Attack Surface Reduction",
          status: "warn",
          severity: risky.includes("TRACE") ? "high" : "medium",
          confidence: "moderate",
          title: "Risky HTTP methods are advertised",
          detail: `The server advertises potentially risky methods: ${risky.join(", ")}.`,
          impact: "Unexpected methods increase the chance of misconfiguration, cache poisoning, or unsafe object modification paths.",
          remediation: "Disable unused HTTP methods at the edge, load balancer, web server, and application router.",
          evidence: [{ url: res.url, status: res.status, header: "Allow / Access-Control-Allow-Methods", observed: allow, requestId: res.requestId }],
          owasp: ["A05:2021 Security Misconfiguration"],
          cwe: ["CWE-650", "CWE-16"],
          exploitability: "practical",
        }));
      }
    } catch {}

    for (const p of context.pages.slice(0, context.options.evidenceLimit)) {
      if (p.status >= 500) {
        const leaked = /(stack trace|exception|traceback|syntaxerror|referenceerror|sql|odbc|jdbc|mongodb|postgres|mysql|sequelize|typeorm|prisma)/i.test(p.body);
        results.push(finding({
          id: `resilience.5xx.${Buffer.from(p.url).toString("base64url").slice(0, 10)}`,
          check: "resilience",
          category: "Error Handling",
          status: "warn",
          severity: leaked ? "high" : "medium",
          confidence: leaked ? "strong" : "moderate",
          title: leaked ? "Server error leaks implementation details" : "Server error observed during crawl",
          detail: `HTTP ${p.status} was observed${leaked ? " with framework, database, or stack-trace indicators" : " on the crawled surface"}.`,
          impact: leaked ? "Implementation details help attackers refine payloads and identify vulnerable components." : "Unstable endpoints can create availability risk and may hide exploitable edge cases.",
          remediation: "Return generic error pages to users, log details server-side, and triage the failing route.",
          evidence: [{ url: p.url, status: p.status, snippet: p.body.replace(/\s+/g, " ").slice(0, 180), requestId: p.requestId }],
          owasp: ["A05:2021 Security Misconfiguration", "A09:2021 Security Logging and Monitoring Failures"],
          cwe: ["CWE-209", "CWE-755"],
          exploitability: leaked ? "practical" : "theoretical",
        }));
      }

      const cache = p.headers["cache-control"] ?? "";
      const hasSensitiveContent = /login|password|account|profile|dashboard|token|reset/i.test(p.url + " " + p.body.slice(0, 1000));
      if (hasSensitiveContent && !/(no-store|private)/i.test(cache)) {
        results.push(finding({
          id: `resilience.cache.${Buffer.from(p.url).toString("base64url").slice(0, 10)}`,
          check: "resilience",
          category: "Sensitive Data Exposure",
          status: "warn",
          severity: "medium",
          confidence: "moderate",
          title: "Sensitive-looking page lacks strong cache control",
          detail: "A page with authentication/account/reset indicators did not advertise no-store or private cache semantics.",
          impact: "Sensitive pages may be stored by browsers, proxies, shared devices, or intermediary caches.",
          remediation: "Use Cache-Control: no-store for sensitive responses, plus Pragma: no-cache where legacy support is required.",
          evidence: [{ url: p.url, status: p.status, header: "cache-control", observed: cache || "<missing>", requestId: p.requestId }],
          owasp: ["A02:2021 Cryptographic Failures"],
          cwe: ["CWE-525", "CWE-524"],
          exploitability: "practical",
        }));
      }
    }

    if (!results.length) results.push(pass("resilience", "Operational Resilience", "No obvious resilience weaknesses found", "Risky methods, error leakage, and cache-control checks did not identify material issues on the crawled surface."));
    return results;
  },
};
