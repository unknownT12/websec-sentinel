import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const SINKS: Array<[string, RegExp, "high" | "medium" | "low", string]> = [
  ["DOM write sink", /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)\s*[=(]/i, "medium", "DOM write APIs can become XSS sinks when fed untrusted input."],
  ["Dynamic code execution", /\b(eval|Function|setTimeout|setInterval)\s*\(/i, "high", "Dynamic code execution increases XSS impact and makes input handling harder to reason about."],
  ["URL-controlled navigation", /(location\.(href|assign|replace)|window\.open)\s*\(/i, "medium", "Client-side navigation controlled by parameters can become open redirect or phishing support."],
  ["Local storage token usage", /(localStorage|sessionStorage)\.(setItem|getItem)\s*\([^)]*(token|jwt|session|auth|secret)/i, "medium", "Storing auth tokens in web storage increases exposure after XSS."],
  ["Weak randomness", /Math\.random\s*\(/i, "low", "Math.random is not suitable for security-sensitive identifiers or tokens."],
];

export const domCheck: Check = {
  name: "dom",
  description: "Performs passive JavaScript sink review for client-side security risk patterns.",
  async run(context) {
    const results: ScanResult[] = [];
    const scripts = [...new Set(context.pages.flatMap((p) => p.scripts))].slice(0, Math.min(context.options.evidenceLimit * 3, 50));
    const docs: Array<{ url: string; status: number; body: string; requestId?: string }> = context.pages.map((p) => ({ url: p.url, status: p.status, body: p.body, requestId: p.requestId }));
    for (const script of scripts) {
      try {
        const res = await request(script, context.options);
        docs.push({ url: res.url, status: res.status, body: res.body, requestId: res.requestId });
      } catch {}
    }

    for (const [name, pattern, severity, impact] of SINKS) {
      const evidence = docs.flatMap((doc) => {
        const match = doc.body.match(pattern);
        if (!match) return [];
        const ev: any = { url: doc.url, status: doc.status, snippet: safeSnippet(doc.body.slice(Math.max(0, (match.index ?? 0) - 80), (match.index ?? 0) + 220)) };
        if (doc.requestId) ev.requestId = doc.requestId;
        return [ev];
      }).slice(0, context.options.evidenceLimit);
      if (evidence.length) {
        results.push(finding({
          id: `dom.${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
          check: "dom",
          category: "Client-Side Security",
          status: severity === "low" ? "info" : "warn",
          severity,
          confidence: "moderate",
          title: `${name} pattern observed`,
          detail: `${name} was observed in crawled HTML or JavaScript assets. This is a signal for manual review, not proof of exploitability by itself.`,
          impact,
          businessImpact: "Client-side weaknesses often become high impact when combined with missing CSP, reflected input, or exposed session tokens.",
          remediation: "Review data flow into the sink, encode output by context, avoid dynamic execution, prefer safe DOM APIs, and add unit/security tests for untrusted input.",
          evidence,
          owasp: ["A03:2021 Injection", "A05:2021 Security Misconfiguration"],
          cwe: ["CWE-79", "CWE-95"],
          exploitability: "theoretical",
          falsePositiveNotes: "This is passive sink detection. Confirm exploitability through code review or approved inert canary validation only.",
        }));
      }
    }

    if (!results.length) results.push(pass("dom", "Client-Side Security", "No risky JavaScript sink patterns detected", "The reviewed HTML/JS assets did not expose configured client-side risk patterns."));
    return results;
  },
};
