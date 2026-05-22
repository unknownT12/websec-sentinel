import type { Check, ScanResult } from "../types.js";
import { request, safeSnippet } from "../core/http.js";

const SENSITIVE_PATHS = [
  ["/.env", "critical"], ["/.git/config", "critical"], ["/.git/HEAD", "critical"], ["/config.json", "high"], ["/secrets.json", "critical"],
  ["/phpinfo.php", "high"], ["/server-status", "high"], ["/actuator/env", "critical"], ["/actuator/heapdump", "critical"], ["/debug", "medium"],
  ["/graphql", "medium"], ["/api/docs", "medium"], ["/swagger.json", "medium"], ["/openapi.json", "medium"], ["/robots.txt", "info"], ["/sitemap.xml", "info"],
] as const;

const SIGNATURES: Record<string, RegExp> = {
  "/.env": /(DB_|DATABASE_|APP_KEY|SECRET|AWS_|PASSWORD|TOKEN)/i,
  "/.git/config": /\[core\]|repositoryformatversion|\[remote/i,
  "/.git/HEAD": /^ref:\s+refs\//i,
  "/config.json": /\{[\s\S]{0,400}(api|endpoint|secret|client|auth)/i,
  "/secrets.json": /\{[\s\S]{0,400}(secret|password|token|key)/i,
  "/phpinfo.php": /phpinfo\(\)|PHP Version|System\s*=>/i,
  "/server-status": /Apache Server Status|Server Version|Current Time/i,
  "/actuator/env": /propertySources|activeProfiles|systemEnvironment/i,
  "/actuator/heapdump": /JAVA PROFILE|heapdump|application\/octet-stream/i,
  "/debug": /debug|trace|stack|exception/i,
  "/graphql": /graphql|query|mutation|__schema|graphiql/i,
  "/api/docs": /swagger|openapi|api documentation/i,
  "/swagger.json": /"swagger"|"openapi"|"paths"/i,
  "/openapi.json": /"openapi"|"paths"|"components"/i,
  "/robots.txt": /user-agent|disallow|allow/i,
  "/sitemap.xml": /<urlset|<sitemapindex/i,
};

function normalized(body: string): string {
  return body.replace(/\s+/g, " ").replace(/[a-f0-9]{8,}/gi, "<hex>").slice(0, 500).toLowerCase();
}

function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  const na = normalized(a);
  const nb = normalized(b);
  return na === nb || (na.length > 80 && nb.length > 80 && (na.includes(nb.slice(0, 120)) || nb.includes(na.slice(0, 120))));
}

export const discoveryCheck: Check = {
  name: "discovery",
  description: "Detects accidentally exposed sensitive routes and public metadata with soft-404 false-positive control.",
  async run(context) {
    const results: ScanResult[] = [];
    const base = context.targetUrl.origin;
    if (context.options.mode === "passive") {
      results.push({ id: "discovery.skipped", check: "discovery", category: "Exposure Management", status: "info", severity: "info", confidence: "confirmed", title: "Discovery skipped in passive mode", detail: "Passive mode avoids probing common paths.", impact: "Reduced assessment coverage.", remediation: "Use standard mode for approved production discovery." });
      return results;
    }

    let soft404 = "";
    try { soft404 = (await request(`${base}/websec-sentinel-soft-404-${Date.now()}`, context.options, { redirect: "manual" })).body; } catch {}

    for (const [path, severity] of SENSITIVE_PATHS) {
      try {
        const res = await request(`${base}${path}`, context.options, { redirect: "manual" });
        const signature = SIGNATURES[path];
        const matched = !!signature?.test(res.body || `${res.headers["content-type"] ?? ""}\n${res.body}`);
        const looksLikeCatchAll = soft404 && similar(soft404, res.body);
        const success = res.status >= 200 && res.status < 300;
        if (success && !looksLikeCatchAll && (severity === "info" ? matched || res.body.length > 0 : matched)) {
          const isInfo = severity === "info";
          results.push({
            id: `discovery.${path.replace(/[^a-z0-9]/gi, "_")}`,
            check: "discovery",
            category: "Exposure Management",
            status: isInfo ? "info" : "fail",
            severity,
            confidence: matched ? "strong" : "moderate",
            title: isInfo ? `Public metadata available at ${path}` : `Sensitive endpoint signature exposed at ${path}`,
            detail: `${path} returned HTTP ${res.status} and matched expected content for that endpoint.`,
            impact: isInfo ? "Public metadata can reveal routes and crawler instructions." : "Sensitive files or debug endpoints can expose secrets, configuration, source control data, or operational internals.",
            remediation: isInfo ? "Review metadata content and ensure it does not disclose private routes." : "Block the route at the web server/CDN, remove the artifact, and rotate any leaked secrets.",
            evidence: [{ url: res.url, status: res.status, snippet: safeSnippet(res.body), requestId: res.requestId }],
            owasp: ["A01:2021 Broken Access Control", "A05:2021 Security Misconfiguration"],
            falsePositiveNotes: "This check compares against a random soft-404 path and requires endpoint-specific content signatures for sensitive findings.",
          });
        }
      } catch {}
    }
    if (!results.length) results.push({ id: "discovery.pass", check: "discovery", category: "Exposure Management", status: "pass", severity: "info", confidence: "moderate", title: "No common exposed sensitive paths detected", detail: "The standard sensitive-path checks did not find publicly accessible artifacts with matching endpoint signatures.", impact: "External exposure appears reduced for tested paths.", remediation: "Keep deny rules and deployment artifact checks in CI/CD." });
    return results;
  },
};
