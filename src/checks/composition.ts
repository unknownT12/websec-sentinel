import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const LIB_VERSION_RE = /(jquery|angular|react|vue|bootstrap|lodash|moment|axios|webpack|vite)[^\n]{0,40}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/ig;
const EXTERNAL_SCRIPT_RE = /<script\b[^>]*\bsrc=['"](https?:\/\/[^'"]+)['"][^>]*>/gi;

function hasIntegrity(tag: string): boolean {
  return /\bintegrity=['"][^'"]+['"]/i.test(tag);
}

export const compositionCheck: Check = {
  name: "composition",
  description: "Assesses frontend supply-chain and composition risk signals from scripts, external assets, and leaked framework/version markers.",
  async run(context) {
    const results: ScanResult[] = [];
    const externalNoSri: ScanResult["evidence"] = [];
    const versions = new Map<string, string>();

    for (const page of context.pages) {
      for (const match of page.body.matchAll(EXTERNAL_SCRIPT_RE)) {
        const tag = match[0] ?? "";
        const src = match[1] ?? "";
        if (!hasIntegrity(tag)) externalNoSri.push({ url: page.url, observed: src, snippet: tag.slice(0, 180), requestId: page.requestId });
      }
      for (const match of page.body.matchAll(LIB_VERSION_RE)) {
        const lib = (match[1] ?? "unknown").toLowerCase();
        const version = match[2] ?? "unknown";
        versions.set(`${lib}@${version}`, page.url);
      }
    }

    if (externalNoSri.length) {
      results.push(finding({
        id: "composition.external-script-without-sri",
        check: "composition",
        category: "Frontend Supply Chain",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "External script loaded without Subresource Integrity",
        detail: `${externalNoSri.length} external script reference(s) were observed without an integrity attribute.`,
        impact: "If a third-party script source is compromised or altered, users can receive malicious code through the trusted application page.",
        remediation: "Self-host critical scripts or add SRI hashes plus crossorigin attributes; monitor third-party dependencies and pin versions.",
        evidence: externalNoSri.slice(0, context.options.evidenceLimit),
        owasp: ["A06:2021 Vulnerable and Outdated Components", "A08:2021 Software and Data Integrity Failures"],
        cwe: ["CWE-829", "CWE-494"],
        exploitability: "theoretical",
      }));
    }

    const versionEvidence = [...versions.entries()].slice(0, context.options.evidenceLimit).map(([observed, url]) => ({ url, observed }));
    if (versionEvidence.length) {
      results.push(finding({
        id: "composition.frontend-version-markers",
        check: "composition",
        category: "Frontend Supply Chain",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Frontend library version markers observed",
        detail: "The scanned surface exposed frontend framework/library version-like markers.",
        impact: "Version markers are not vulnerabilities by themselves, but they help prioritize dependency review and CVE matching.",
        remediation: "Inventory frontend dependencies, remove unnecessary version banners/source maps, and run dependency auditing in CI.",
        evidence: versionEvidence,
        owasp: ["A06:2021 Vulnerable and Outdated Components"],
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("composition", "Frontend Supply Chain", "No frontend composition risk signals detected", "No external scripts without SRI or obvious library version markers were observed in the crawled surface."));
    return results;
  },
};
