import type { Check, ScanResult } from "../types.js";
import { resolveUrl } from "../core/http.js";
import { request } from "../core/http.js";

const PATTERNS: Array<[string, RegExp, "critical" | "high" | "medium"]> = [
  ["Private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i, "critical"],
  ["AWS access key", /AKIA[0-9A-Z]{16}/g, "critical"],
  ["Google API key", /AIza[0-9A-Za-z_-]{35}/g, "high"],
  ["Generic secret assignment", /(?:secret|token|api[_-]?key|password)\s*[:=]\s*["'][^"']{12,}["']/gi, "medium"],
  ["Source map reference", /sourceMappingURL=.*\.map/gi, "medium"],
];

function redact(value: string): string {
  if (value.length <= 12) return "<redacted>";
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}

export const secretsCheck: Check = {
  name: "secrets",
  description: "Looks for accidental public secrets in crawled HTML/JS/JSON/source maps.",
  async run(context) {
    const results: ScanResult[] = [];
    const assets = new Set<string>();
    for (const page of context.pages) {
      for (const match of page.body.matchAll(/(?:src|href)=["']([^"']+\.(?:js|json|map))(?:\?[^"']*)?["']/gi)) {
        const url = resolveUrl(page.finalUrl || page.url, match[1] ?? "");
        if (url && new URL(url).origin === context.targetUrl.origin) assets.add(url);
      }
    }
    const documents = [...context.pages.map((p) => ({ url: p.url, status: p.status, body: p.body })), ...[]];
    for (const asset of [...assets].slice(0, Math.min(30, context.options.maxPages))) {
      try {
        const res = await request(asset, context.options);
        documents.push({ url: res.url, status: res.status, body: res.body });
      } catch {}
    }

    for (const doc of documents) {
      for (const [name, pattern, severity] of PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(doc.body);
        if (match) {
          const observed = match[0];
          results.push({ id: `secrets.${name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`, check: "secrets", category: "Secret Exposure", status: severity === "medium" ? "warn" : "fail", severity, confidence: "strong", title: `${name} exposed in public response`, detail: `${name} pattern was detected in a public response. Evidence is redacted.`, impact: "Exposed credentials or source maps can enable unauthorized access, source review, or further compromise.", remediation: "Remove the exposed value, rotate affected credentials, disable public source maps where inappropriate, and add secret scanning to CI/CD.", evidence: [{ url: doc.url, status: doc.status, observed: redact(observed) }], owasp: ["A02:2021 Cryptographic Failures", "A05:2021 Security Misconfiguration"] });
        }
      }
    }
    if (!results.length) results.push({ id: "secrets.pass", check: "secrets", category: "Secret Exposure", status: "pass", severity: "info", confidence: "moderate", title: "No public secret patterns detected", detail: "No configured secret patterns were found in crawled pages/assets.", impact: "Public credential exposure appears reduced for the crawled surface.", remediation: "Keep CI/CD secret scanning and artifact reviews enabled." });
    return results;
  },
};
