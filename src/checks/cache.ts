import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const SENSITIVE_PATH = /(login|signin|account|profile|dashboard|student|grade|admin|reset|password|token|session)/i;
const SENSITIVE_BODY = /(password|sign in|login|logout|student|grade|account|profile|csrf|session)/i;

export const cacheCheck: Check = {
  name: "cache",
  description: "Checks cache-control posture for sensitive pages and authenticated-style responses.",
  async run(context) {
    const results: ScanResult[] = [];
    const weak = context.pages.filter((p) => {
      const sensitive = SENSITIVE_PATH.test(new URL(p.finalUrl || p.url).pathname) || p.forms.some((f) => f.inputs.some((i) => /password|email|token/i.test(`${i.type}:${i.name}`))) || SENSITIVE_BODY.test(p.body.slice(0, 5000));
      if (!sensitive) return false;
      const cc = p.headers["cache-control"] ?? "";
      const pragma = p.headers["pragma"] ?? "";
      return !/no-store/i.test(cc) && !/private/i.test(cc) && !/no-cache/i.test(cc) && !/no-cache/i.test(pragma);
    }).slice(0, context.options.evidenceLimit);

    if (weak.length) {
      results.push(finding({
        id: "cache.sensitive-page-cache-control-missing",
        check: "cache",
        category: "Sensitive Response Caching",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Sensitive page may be cacheable",
        detail: "A page with login/account/student-grade/session indicators did not return strong anti-cache headers.",
        impact: "Sensitive pages may be stored in browser, proxy, or shared caches, increasing exposure on shared devices or intermediary infrastructure.",
        businessImpact: "For education or gradebook systems, cached authenticated data can expose student records or account workflow pages.",
        remediation: "For sensitive pages, return Cache-Control: no-store, no-cache, must-revalidate and Pragma: no-cache where legacy compatibility is needed.",
        evidence: weak.map((p) => ({ url: p.url, status: p.status, header: "cache-control", observed: p.headers["cache-control"] ?? "<missing>", requestId: p.requestId })),
        owasp: ["A02:2021 Cryptographic Failures", "A05:2021 Security Misconfiguration"],
        cwe: ["CWE-525"],
        exploitability: "practical",
      }));
    }

    if (!results.length) results.push(pass("cache", "Sensitive Response Caching", "Sensitive responses include acceptable cache controls or no sensitive pages were observed", "No weak cache-control pattern was detected on crawled sensitive pages."));
    return results;
  },
};
