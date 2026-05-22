import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const SENSITIVE_PARAM_RE = /(^|_|-)(token|auth|session|sid|jwt|secret|key|password|passwd|pwd|code|otp|pin)(_|-|$)/i;
const ID_PARAM_RE = /(^|_|-)(id|user|uid|account|customer|invoice|order|profile|tenant)(_|-|$)/i;
const CANARY = "wss-canary-9f2b-safe-validation";

function paramsFromUrl(raw: string): URLSearchParams {
  try { return new URL(raw).searchParams; } catch { return new URLSearchParams(); }
}

function unique<T>(items: T[]): T[] { return [...new Set(items)]; }

export const methodologyCheck: Check = {
  name: "methodology",
  description: "Applies a consulting-grade web assessment methodology: inventory, input exposure, data handling, and safe proof-of-impact signals.",
  async run(context) {
    const results: ScanResult[] = [];
    const pages = context.pages;
    const forms = pages.flatMap((p) => p.forms.map((f) => ({ page: p.url, ...f })));

    const inputNames = unique(forms.flatMap((f) => f.inputs.map((i) => i.name).filter(Boolean)));
    const riskyInputs = inputNames.filter((name) => SENSITIVE_PARAM_RE.test(name) || ID_PARAM_RE.test(name));
    if (riskyInputs.length) {
      results.push(finding({
        id: "methodology.risky-input-inventory",
        check: "methodology",
        category: "Assessment Methodology",
        status: "info",
        severity: "info",
        confidence: "strong",
        title: "Risk-sensitive input inventory created",
        detail: `The crawler observed ${riskyInputs.length} risk-sensitive input/parameter name(s): ${riskyInputs.slice(0, 12).join(", ")}${riskyInputs.length > 12 ? ", ..." : ""}.`,
        impact: "These inputs usually deserve manual review for authorization, injection, logging, and data exposure risks.",
        remediation: "Prioritize manual testing around identifiers, credentials, tokens, and cross-tenant or account-bound parameters.",
        tags: ["methodology", "inventory", "manual-review"],
        owasp: ["A01:2021 Broken Access Control", "A03:2021 Injection", "A04:2021 Insecure Design"],
        cwe: ["CWE-20", "CWE-639"],
        exploitability: "none",
      }));
    }

    for (const f of forms.slice(0, context.options.evidenceLimit)) {
      const hasPassword = f.inputs.some((i) => i.type.toLowerCase() === "password" || /password|passwd|pwd/i.test(i.name));
      if (hasPassword && f.method === "GET") {
        results.push(finding({
          id: `methodology.get-password.${Buffer.from(f.page).toString("base64url").slice(0, 10)}`,
          check: "methodology",
          category: "Credential Handling",
          status: "fail",
          severity: "high",
          confidence: "strong",
          title: "Password-like form submits with GET",
          detail: "A form containing a password-like input uses GET, which can place credentials in URLs, browser history, referrers, logs, and analytics.",
          impact: "Credentials may be exposed through logs or browser artifacts even when TLS is enabled.",
          remediation: "Submit credential-bearing forms using POST over HTTPS, disable caching, and avoid logging sensitive fields.",
          evidence: [{ url: f.page, observed: `${f.method} ${f.action}`, parameter: f.inputs.map((i) => i.name || i.type).join(", ") }],
          owasp: ["A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"],
          cwe: ["CWE-598", "CWE-522"],
          businessImpact: "Credential exposure creates direct account takeover and regulatory-notification risk.",
          exploitability: "practical",
        }));
      }
    }

    for (const page of pages.slice(0, context.options.evidenceLimit)) {
      const params = [...paramsFromUrl(page.finalUrl || page.url).keys()];
      const sensitive = params.filter((p) => SENSITIVE_PARAM_RE.test(p));
      if (sensitive.length) {
        results.push(finding({
          id: `methodology.sensitive-url.${Buffer.from(page.url).toString("base64url").slice(0, 10)}`,
          check: "methodology",
          category: "Sensitive Data Exposure",
          status: "warn",
          severity: "medium",
          confidence: "strong",
          title: "Sensitive-looking parameter found in URL",
          detail: `URL parameters include sensitive-looking names: ${sensitive.join(", ")}.`,
          impact: "Secrets, tokens, reset codes, and credentials in URLs can leak into referrers, logs, screenshots, proxies, and browser history.",
          remediation: "Move sensitive values to request bodies or short-lived server-side state and ensure logs redact them.",
          evidence: [{ url: page.url, status: page.status, parameter: sensitive.join(", "), requestId: page.requestId }],
          owasp: ["A02:2021 Cryptographic Failures"],
          cwe: ["CWE-598", "CWE-200"],
          exploitability: "practical",
        }));
      }
    }

    if (context.options.mode === "validate" && context.options.authorized) {
      const candidates = pages
        .map((p) => p.url)
        .filter((u) => {
          try { return new URL(u).search === ""; } catch { return false; }
        })
        .slice(0, Math.min(8, context.options.evidenceLimit));
      for (const url of candidates) {
        try {
          const testUrl = new URL(url);
          testUrl.searchParams.set("wss_canary", CANARY);
          const res = await request(testUrl.toString(), context.options);
          if (res.body.includes(CANARY)) {
            results.push(finding({
              id: `methodology.reflection.${Buffer.from(url).toString("base64url").slice(0, 10)}`,
              check: "methodology",
              category: "Input Validation",
              status: "warn",
              severity: "medium",
              confidence: "moderate",
              title: "Reflected input canary observed",
              detail: "A harmless validation canary supplied in a query parameter was reflected in the response body.",
              impact: "Reflection is not automatically exploitable, but it marks a sink that should be manually reviewed for context-aware output encoding.",
              remediation: "Apply contextual output encoding and validate reflected parameters against expected formats.",
              evidence: [{ url: res.url, status: res.status, parameter: "wss_canary", observed: CANARY, snippet: safeSnippet(res.body, 180), requestId: res.requestId, elapsedMs: res.elapsedMs }],
              owasp: ["A03:2021 Injection"],
              cwe: ["CWE-79", "CWE-116"],
              exploitability: "theoretical",
              falsePositiveNotes: "This check uses an inert canary only. Manual context review is required before classifying as XSS.",
            }));
          }
        } catch {}
      }
    }

    if (!results.length) results.push(pass("methodology", "Assessment Methodology", "Methodology checks completed", "No credential-handling or input-inventory issues were detected on the crawled surface."));
    return results;
  },
};
