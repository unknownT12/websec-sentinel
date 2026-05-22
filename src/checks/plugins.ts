import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

interface JsonRule { id: string; title: string; category?: string; severity?: ScanResult["severity"]; pattern: string; where?: "url" | "body" | "header" | "any"; remediation?: string; }

const BUILTIN: JsonRule[] = [
  { id: "builtin.exposed-source-map", title: "Source map exposure signal", category: "Client-Side Exposure", severity: "medium", pattern: "\\.map($|[?#])", where: "url", remediation: "Do not publish production source maps unless explicitly intended and scrubbed." },
  { id: "builtin.debug-route", title: "Debug route exposure signal", category: "Configuration Exposure", severity: "medium", pattern: "debug|trace|actuator|metrics", where: "url", remediation: "Restrict debug/metrics endpoints to authorized internal access." },
  { id: "builtin.stacktrace", title: "Verbose error stack trace signal", category: "Error Handling", severity: "high", pattern: "Stack trace|Traceback|at [a-zA-Z0-9_.$]+\\(|Exception in thread", where: "body", remediation: "Disable verbose errors in production and return generic error pages." },
];

function loadRules(dir?: string): JsonRule[] {
  const rules = [...BUILTIN];
  if (!dir || !existsSync(dir)) return rules;
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    try {
      const raw = JSON.parse(readFileSync(join(dir, file), "utf8"));
      const arr = Array.isArray(raw) ? raw : [raw];
      for (const r of arr) if (r?.id && r?.title && r?.pattern) rules.push(r as JsonRule);
    } catch {}
  }
  return rules;
}

export const pluginsCheck: Check = {
  name: "plugins",
  description: "Runs safe declarative plugin rules against crawled URLs, headers, and response snippets.",
  async run(context) {
    const rules = loadRules(context.options.rulesDir);
    context.diagnostics.pluginRulesLoaded = rules.length;
    const hits: ScanResult[] = [];
    for (const rule of rules) {
      const re = new RegExp(rule.pattern, "i");
      const evidence: NonNullable<ScanResult["evidence"]> = [];
      for (const p of context.pages) {
        const headerBlob = JSON.stringify(p.headers);
        const checks = rule.where === "url" ? [p.url, p.finalUrl] : rule.where === "body" ? [p.body] : rule.where === "header" ? [headerBlob] : [p.url, p.finalUrl, p.body, headerBlob];
        if (checks.some((c) => re.test(c || ""))) evidence.push({ url: p.finalUrl || p.url, status: p.status, observed: rule.title, requestId: p.requestId });
      }
      if (evidence.length) hits.push(finding({ id: `plugins.${rule.id}`, check: "plugins", category: rule.category ?? "Plugin Rule", status: "warn", severity: rule.severity ?? "medium", confidence: "moderate", title: rule.title, detail: `Declarative rule ${rule.id} matched the observed surface.`, impact: "This is a rule-based signal that requires manual verification before client reporting.", remediation: rule.remediation ?? "Verify the signal and remediate according to application context.", evidence: evidence.slice(0, context.options.evidenceLimit), exploitability: "theoretical", falsePositiveNotes: "Plugin rules are intentionally safe pattern checks and should not be treated as confirmed vulnerabilities without validation." }));
    }
    if (!hits.length) return [pass("plugins", "Plugin Rule Engine", "Plugin rule engine executed without matches", `Loaded ${rules.length} safe rule(s).`)];
    return hits;
  },
};
