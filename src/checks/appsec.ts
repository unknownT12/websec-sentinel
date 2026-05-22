import type { Check, CrawlPage, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const CANARY = "wss_validation_canary_74b6";
const ERROR_PATTERNS = /(sql syntax|mysql|mariadb|postgres|postgresql|ora-\d+|sqlite|odbc|jdbc|stack trace|exception|traceback|system\.data\.sqlclient|unterminated quoted string|syntax error at or near)/i;
const REDIRECT_PARAMS = /(redirect|return|returnUrl|next|url|continue|target|destination|dest)/i;
const ID_PARAMS = /(id|user|uid|account|profile|student|customer|tenant|invoice|order)/i;

function pagesWithParams(pages: CrawlPage[]): Array<{ page: CrawlPage; url: URL; params: string[] }> {
  const out: Array<{ page: CrawlPage; url: URL; params: string[] }> = [];
  for (const page of pages) {
    try {
      const url = new URL(page.finalUrl || page.url);
      const params = [...url.searchParams.keys()];
      if (params.length) out.push({ page, url, params });
    } catch {}
  }
  return out;
}

export const appsecCheck: Check = {
  name: "appsec",
  description: "Performs safe application-layer validation for forms, CSRF signals, reflection, redirect behavior, identifier parameters, and verbose errors.",
  async run(context) {
    const results: ScanResult[] = [];
    const pages = context.pages;
    const forms = pages.flatMap((p) => p.forms.map((f) => ({ page: p, form: f })));

    for (const item of forms.slice(0, context.options.evidenceLimit)) {
      const method = item.form.method.toUpperCase();
      const hasPassword = item.form.inputs.some((i) => /password|passwd|pwd/i.test(i.type) || /password|passwd|pwd/i.test(i.name));
      const hasStateChangingIntent = method === "POST" || item.form.inputs.some((i) => /email|password|amount|role|delete|update|create|name|phone|student|grade/i.test(i.name));

      if (hasStateChangingIntent && !item.form.hasCsrfToken) {
        results.push(finding({
          id: `appsec.csrf.${Buffer.from(item.page.url + item.form.action).toString("base64url").slice(0, 10)}`,
          check: "appsec",
          category: "Application-Layer Validation",
          status: "warn",
          severity: hasPassword ? "high" : "medium",
          confidence: "moderate",
          title: "State-changing form has no obvious CSRF token",
          detail: "A form that appears to submit credentials or state-changing data did not contain a visible CSRF token marker.",
          impact: "Missing CSRF protection can allow attackers to trigger unwanted actions from an authenticated user's browser.",
          businessImpact: hasPassword ? "Authentication workflows without CSRF controls can expose account security processes to abuse." : "Business workflows may be abused when users are tricked into submitting unintended actions.",
          remediation: "Add server-validated anti-CSRF tokens, SameSite cookies, origin/referrer checks where appropriate, and automated tests for protected forms.",
          evidence: [{ url: item.page.url, method, observed: item.form.action, parameter: item.form.inputs.map((i) => i.name || i.type).filter(Boolean).join(", ") }],
          owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
          cwe: ["CWE-352"],
          exploitability: "practical",
          remediationPriority: hasPassword ? "immediate" : "short-term",
        }));
      }

      if (hasPassword) {
        const autocomplete = item.form.inputs.find((i) => /password/i.test(i.type))?.autocomplete ?? "";
        if (!/current-password|new-password/i.test(autocomplete)) {
          results.push(finding({
            id: `appsec.password-autocomplete.${Buffer.from(item.page.url).toString("base64url").slice(0, 10)}`,
            check: "appsec",
            category: "Authentication UX Security",
            status: "info",
            severity: "info",
            confidence: "moderate",
            title: "Password form autocomplete policy should be reviewed",
            detail: "A password input was found without a clear current-password or new-password autocomplete hint.",
            impact: "This does not directly create a vulnerability, but weak form semantics can reduce password-manager reliability and user security.",
            remediation: "Set appropriate autocomplete attributes on username and password fields and verify password-manager behavior.",
            evidence: [{ url: item.page.url, observed: item.form.action }],
            exploitability: "none",
          }));
        }
      }
    }

    const paramPages = pagesWithParams(pages).slice(0, Math.min(context.options.evidenceLimit, 12));
    for (const { page, url, params } of paramPages) {
      const idParams = params.filter((p) => ID_PARAMS.test(p));
      if (idParams.length) {
        results.push(finding({
          id: `appsec.idor-signal.${Buffer.from(url.toString()).toString("base64url").slice(0, 10)}`,
          check: "appsec",
          category: "Broken Access Control",
          status: "info",
          severity: "info",
          confidence: "moderate",
          title: "Identifier parameter requires authorization review",
          detail: `Identifier-like parameter(s) observed: ${idParams.join(", ")}.`,
          impact: "Identifier parameters are common places for IDOR and broken object-level authorization issues, especially in authenticated portals.",
          remediation: "Manually verify that changing identifiers never exposes another user's records and add server-side object ownership checks.",
          evidence: [{ url: url.toString(), status: page.status, parameter: idParams.join(", "), requestId: page.requestId }],
          owasp: ["A01:2021 Broken Access Control"],
          cwe: ["CWE-639"],
          exploitability: "none",
        }));
      }
    }

    if (context.options.mode === "validate" && context.options.authorized) {
      const validationTargets = pages.slice(0, Math.min(context.options.evidenceLimit, 8));
      for (const page of validationTargets) {
        try {
          const u = new URL(page.finalUrl || page.url);
          if (u.search) continue;
          u.searchParams.set("wss_canary", CANARY);
          const res = await request(u.toString(), context.options);
          if (res.body.includes(CANARY)) {
            results.push(finding({
              id: `appsec.reflection.${Buffer.from(page.url).toString("base64url").slice(0, 10)}`,
              check: "appsec",
              category: "Application-Layer Validation",
              status: "warn",
              severity: "medium",
              confidence: "moderate",
              title: "Safe reflection canary observed",
              detail: "A harmless canary value sent in a query parameter was reflected in the response body.",
              impact: "Reflected input is not automatically exploitable, but it identifies a sink requiring output-encoding review.",
              remediation: "Apply contextual output encoding, validate reflected parameters, and manually test the rendering context with approved procedures.",
              evidence: [{ url: res.url, status: res.status, parameter: "wss_canary", observed: CANARY, snippet: safeSnippet(res.body), requestId: res.requestId }],
              owasp: ["A03:2021 Injection"],
              cwe: ["CWE-79", "CWE-116"],
              exploitability: "theoretical",
              falsePositiveNotes: "The scanner uses an inert canary and does not execute script payloads.",
            }));
          }
        } catch {}
      }

      for (const { url, params } of paramPages) {
        const redirectParam = params.find((p) => REDIRECT_PARAMS.test(p));
        if (!redirectParam) continue;
        try {
          const test = new URL(url.toString());
          test.searchParams.set(redirectParam, "https://example.invalid/websec-sentinel-canary");
          const res = await request(test.toString(), context.options, { redirect: "manual" });
          const location = res.headers.location ?? "";
          if (/example\.invalid\/websec-sentinel-canary/i.test(location)) {
            results.push(finding({
              id: `appsec.open-redirect.${Buffer.from(url.toString()).toString("base64url").slice(0, 10)}`,
              check: "appsec",
              category: "Application-Layer Validation",
              status: "fail",
              severity: "medium",
              confidence: "strong",
              title: "Open redirect behavior validated safely",
              detail: "A redirect-like parameter accepted a harmless external canary URL and returned it in the Location header.",
              impact: "Open redirects can support phishing, OAuth abuse, token leakage, and exploit-chain credibility.",
              remediation: "Replace arbitrary redirect targets with server-side allowlisted route identifiers or strict same-origin validation.",
              evidence: [{ url: res.url, status: res.status, parameter: redirectParam, header: "location", observed: location, requestId: res.requestId }],
              owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
              cwe: ["CWE-601"],
              exploitability: "validated",
            }));
          }
        } catch {}
      }
    }

    for (const page of pages.slice(0, context.options.evidenceLimit)) {
      if (ERROR_PATTERNS.test(page.body)) {
        results.push(finding({
          id: `appsec.verbose-error.${Buffer.from(page.url).toString("base64url").slice(0, 10)}`,
          check: "appsec",
          category: "Application Error Handling",
          status: "warn",
          severity: "medium",
          confidence: "strong",
          title: "Verbose application error pattern observed",
          detail: "The response body contains text commonly associated with stack traces, database errors, or framework exceptions.",
          impact: "Verbose errors can leak implementation details that reduce attacker effort during targeted testing.",
          remediation: "Disable detailed errors in production, return generic error pages, and keep detailed traces in protected logs only.",
          evidence: [{ url: page.url, status: page.status, snippet: safeSnippet(page.body), requestId: page.requestId }],
          owasp: ["A05:2021 Security Misconfiguration"],
          cwe: ["CWE-209"],
          exploitability: "practical",
        }));
      }
    }

    if (!results.length) results.push(pass("appsec", "Application-Layer Validation", "No application-layer risk signals detected", "The crawled application surface did not expose CSRF signals, reflection canaries, redirect validation issues, identifier risk signals, or verbose errors."));
    return results;
  },
};
