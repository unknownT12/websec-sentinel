import type { Check, CrawlPage, PageForm, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, requestWithoutCustomHeaders, requestWithExtraHeaders, safeSnippet } from "../core/http.js";

const CANARY = "wss_deep_canary_49261";
const HIGH_VALUE = /(admin|dashboard|account|profile|student|students|grade|grades|marks|results|report|reports|settings|api\/v?\d*\/|users)/i;
const OBJECT_ID = /(?:\/|=)(?:\d{1,10}|[0-9a-f]{8,}-[0-9a-f-]{8,}|[A-Z]{2,}-?\d{2,})(?:[/?&#]|$)/i;
const STATE_NAMES = /(amount|role|permission|grade|mark|score|student|user|email|phone|password|delete|remove|update|create|submit|approve|reject|status|comment|message|note|title|body)/i;
const LOW_RISK_POST = /(comment|feedback|message|note|contact|search|profile|preferences)/i;
const DANGEROUS_ACTION = /(delete|remove|logout|reset|payment|billing|transfer|approve|reject|publish|deactivate|disable)/i;
const CSRF_NAME = /(csrf|xsrf|authenticity|requestverification|__requestverificationtoken)/i;

function authSupplied(headers: Record<string, string>): boolean {
  return Object.keys(headers).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

function similarity(a: string, b: string): number {
  const normalize = (value: string) => value.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 1600);
  const aa = normalize(a);
  const bb = normalize(b);
  if (!aa || !bb) return 0;
  let same = 0;
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] === bb[i]) same++;
  return same / Math.max(aa.length, bb.length, 1);
}

function allUrls(pages: CrawlPage[], browserNetworkUrls: string[] = []): string[] {
  const urls = new Set<string>();
  for (const page of pages) for (const url of [page.finalUrl || page.url, ...page.links, ...page.routeHints, ...page.forms.map((f) => f.action)]) urls.add(url);
  for (const url of browserNetworkUrls) urls.add(url);
  return [...urls];
}

function staticUrls(pages: CrawlPage[]): string[] {
  const urls = new Set<string>();
  for (const page of pages) for (const url of [page.finalUrl || page.url, ...page.links, ...page.routeHints, ...page.forms.map((f) => f.action)]) urls.add(url);
  return [...urls];
}

function classifyForm(form: PageForm): "login" | "state-change" | "query" | "other" {
  const text = `${form.action} ${form.inputs.map((i) => `${i.name} ${i.type}`).join(" ")}`;
  if (/password/i.test(text) && /(user|email|login|student)/i.test(text)) return "login";
  if (form.method.toUpperCase() === "POST" || STATE_NAMES.test(text)) return "state-change";
  if (/search|query|filter|lookup/i.test(text)) return "query";
  return "other";
}

function formBody(form: PageForm, canary: string): URLSearchParams {
  const body = new URLSearchParams();
  for (const input of form.inputs) {
    if (!input.name || /submit|button|file|image/i.test(input.type)) continue;
    if (CSRF_NAME.test(input.name) && input.value) body.set(input.name, input.value);
    else if (/email/i.test(`${input.name} ${input.type}`)) body.set(input.name, `sentinel+${canary}@example.invalid`);
    else if (/number|amount|score|grade|mark/i.test(`${input.name} ${input.type}`)) body.set(input.name, "1");
    else body.set(input.name, canary);
  }
  if (![...body.keys()].length) body.set("q", canary);
  return body;
}

function safePostCandidate(form: PageForm): boolean {
  const text = `${form.action} ${form.inputs.map((i) => `${i.name} ${i.type}`).join(" ")}`;
  return form.method.toUpperCase() === "POST" && LOW_RISK_POST.test(text) && !DANGEROUS_ACTION.test(text);
}

function statefulForms(pages: CrawlPage[]): Array<{ page: CrawlPage; form: PageForm }> {
  return pages.flatMap((page) => page.forms.map((form) => ({ page, form }))).filter((x) => classifyForm(x.form) === "state-change");
}

export const deepAssessmentCheck: Check = {
  name: "deepassess",
  description: "Safely probes deeper classes: auth boundary signals, business workflows, multi-step state changes, second-order canaries, CSRF markers, IDOR candidates, and browser-hidden APIs.",
  async run(context) {
    const results: ScanResult[] = [];
    const hasAuth = authSupplied(context.options.customHeaders);
    const urls = allUrls(context.pages, context.diagnostics.browserNetworkUrls);
    const staticallyObserved = new Set(staticUrls(context.pages));
    const highValueUrls = urls.filter((url) => {
      try { return new URL(url).origin === context.targetUrl.origin && HIGH_VALUE.test(new URL(url).pathname); } catch { return false; }
    });
    const objectUrls = highValueUrls.filter((url) => OBJECT_ID.test(url));
    const forms = context.pages.flatMap((page) => page.forms.map((form) => ({ page, form, kind: classifyForm(form) })));
    const states = statefulForms(context.pages);

    if (hasAuth && highValueUrls.length && context.options.mode !== "passive") {
      const exposures: ScanResult["evidence"] = [];
      for (const url of highValueUrls.slice(0, Math.min(15, context.options.evidenceLimit * 2))) {
        try {
          const authenticated = await request(url, context.options);
          const anonymous = await requestWithoutCustomHeaders(url, context.options, { redirect: "manual" });
          const redirectedToLogin = anonymous.status >= 300 && anonymous.status < 400 && /(login|signin|auth)/i.test(anonymous.headers.location ?? "");
          const blocked = [401, 403, 404].includes(anonymous.status) || redirectedToLogin;
          const sim = similarity(authenticated.body, anonymous.body);
          if (!blocked && anonymous.status >= 200 && anonymous.status < 300 && sim > 0.75 && /student|grade|account|profile|admin|report|api/i.test(`${url} ${anonymous.body.slice(0, 1200)}`)) {
            exposures.push({ url, status: anonymous.status, observed: `anonymous response similar to authenticated baseline (${Math.round(sim * 100)}%)`, snippet: safeSnippet(anonymous.body), requestId: `${authenticated.requestId},${anonymous.requestId}` });
          }
        } catch {}
      }
      if (exposures.length) {
        results.push(finding({
          id: "deepassess.auth-bypass-reachability-signal",
          check: "deepassess",
          category: "Deep Access Control",
          status: "fail",
          severity: "high",
          confidence: "strong",
          title: "Authenticated surface may be reachable without authentication",
          detail: "Anonymous control requests returned successful, similar content for authenticated high-value routes.",
          impact: "This is a strong authorization-bypass signal. It can expose protected content if manual verification confirms sensitive data in the anonymous response.",
          remediation: "Enforce authentication before route handlers and API controllers, deny by default, and add regression tests for anonymous access to every protected route.",
          evidence: exposures.slice(0, context.options.evidenceLimit),
          owasp: ["A01:2021 Broken Access Control"],
          cwe: ["CWE-306", "CWE-862"],
          exploitability: "practical",
          verification: "Review only with approved test accounts and non-production records; this check does not extract records or bypass login flows.",
        }));
      }
    }

    if (objectUrls.length) {
      const roleCount = context.options.roleHeaders.length;
      const severity = roleCount >= 2 ? "medium" : "high";
      results.push(finding({
        id: roleCount >= 2 ? "deepassess.idor-candidates-with-role-coverage" : "deepassess.idor-candidates-need-role-coverage",
        check: "deepassess",
        category: "Object-Level Authorization",
        status: roleCount >= 2 ? "warn" : "fail",
        severity,
        confidence: "strong",
        title: roleCount >= 2 ? "Object-ID routes queued for role/object authorization review" : "IDOR-prone routes observed without enough role coverage",
        detail: `${objectUrls.length} high-value URL(s) contain object identifiers. ${roleCount >= 2 ? "Role sessions were supplied for differential follow-up." : "At least two approved role sessions are required for meaningful IDOR validation."}`,
        impact: "Object-ID routes are common locations for IDOR and horizontal privilege flaws, especially in student, grade, profile, report, and API surfaces.",
        remediation: "Validate every object read/write with owner and role checks server-side. Test with approved low-privilege accounts that own different fixture records.",
        evidence: objectUrls.slice(0, context.options.evidenceLimit).map((url) => ({ url, observed: "object identifier in high-value route" })),
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-639", "CWE-863"],
        exploitability: "none",
      }));
    }

    if (context.options.roleHeaders.length >= 2 && objectUrls.length && context.options.mode !== "passive") {
      const roleSignals: ScanResult["evidence"] = [];
      for (const url of objectUrls.slice(0, Math.min(10, context.options.evidenceLimit))) {
        const seen: Array<{ role: string; status: number; body: string; requestId: string }> = [];
        for (const role of context.options.roleHeaders.slice(0, 4)) {
          try {
            const obs = await requestWithExtraHeaders(url, context.options, role.headers);
            seen.push({ role: role.role, status: obs.status, body: obs.body, requestId: obs.requestId });
          } catch {}
        }
        const success = seen.filter((s) => s.status >= 200 && s.status < 300 && !/login|sign in|unauthorized|forbidden/i.test(s.body.slice(0, 1200)));
        if (new Set(success.map((s) => s.role)).size >= 2) roleSignals.push({ url, status: 200, observed: `multiple roles received successful object response: ${success.map((s) => s.role).join(", ")}`, snippet: safeSnippet(success[0]?.body ?? ""), requestId: success.map((s) => s.requestId).join(",") });
      }
      if (roleSignals.length) {
        results.push(finding({
          id: "deepassess.object-route-role-boundary-signal",
          check: "deepassess",
          category: "Object-Level Authorization",
          status: "warn",
          severity: "high",
          confidence: "strong",
          title: "Object routes may not enforce role/object boundaries",
          detail: "Approved role-labelled sessions received successful responses from object-ID routes.",
          impact: "This may indicate IDOR or role-boundary weakness if the roles should not share those fixture objects.",
          remediation: "Confirm expected object ownership policy and enforce object-level authorization on every route and API resolver.",
          evidence: roleSignals.slice(0, context.options.evidenceLimit),
          owasp: ["A01:2021 Broken Access Control"],
          cwe: ["CWE-639", "CWE-863"],
          exploitability: "practical",
          falsePositiveNotes: "Shared fixture records or generic shells can look similar. Confirm against the authorization matrix before calling this exploitable.",
        }));
      }
    }

    const missingCsrf = states.filter((x) => !x.form.hasCsrfToken);
    if (missingCsrf.length) {
      results.push(finding({
        id: "deepassess.csrf-state-change-marker-missing",
        check: "deepassess",
        category: "CSRF and Workflow Integrity",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "State-changing forms lack obvious CSRF markers",
        detail: `${missingCsrf.length} state-changing form(s) had no visible CSRF token marker in the observed HTML/DOM.`,
        impact: "This does not prove CSRF, but it identifies realistic state transitions that need token enforcement, SameSite, and Origin/Referer validation review.",
        remediation: "Require server-validated per-request CSRF tokens for cookie-authenticated state changes, reject cross-site origins, and keep SameSite cookies strict enough for the workflow.",
        evidence: missingCsrf.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.finalUrl || x.page.url, method: x.form.method, observed: x.form.action, parameter: x.form.inputs.map((i) => i.name || i.type).join(", ") })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        cwe: ["CWE-352"],
        exploitability: "theoretical",
      }));
    }

    if (states.length >= 2) {
      results.push(finding({
        id: "deepassess.multi-step-workflows-modelled",
        check: "deepassess",
        category: "Business Logic",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Multi-step business workflows modelled",
        detail: `${states.length} state-changing step(s) were mapped across ${new Set(states.map((s) => s.page.url)).size} page(s).`,
        impact: "Mapped workflow steps help focus manual testing for sequence abuse, skipped approvals, replay, duplicate submission, and role-step separation.",
        remediation: "Define an expected workflow state machine and verify each transition server-side with approved role accounts and non-production records.",
        evidence: states.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.finalUrl || x.page.url, method: x.form.method, observed: x.form.action })),
        owasp: ["A04:2021 Insecure Design"],
        exploitability: "none",
      }));
    }

    if (context.options.mode === "validate" && context.options.authorized) {
      const secondOrderEvidence: ScanResult["evidence"] = [];
      for (const { page, form } of forms.filter((x) => x.kind === "query" || safePostCandidate(x.form)).slice(0, 8)) {
        try {
          const method = form.method.toUpperCase();
          const body = formBody(form, CANARY);
          const obs = method === "GET"
            ? await request(`${form.action}${form.action.includes("?") ? "&" : "?"}${body.toString()}`, context.options)
            : await request(form.action, context.options, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
          const followups = [obs, ...await Promise.all(context.pages.slice(0, 5).map((p) => request(p.finalUrl || p.url, context.options).catch(() => null)))].filter((r): r is NonNullable<typeof r> => Boolean(r));
          const later = followups.find((r) => r.body.includes(CANARY));
          if (later) secondOrderEvidence.push({ url: later.finalUrl || later.url, method, status: later.status, observed: "inert canary persisted or reappeared after workflow submission", snippet: safeSnippet(later.body), requestId: `${obs.requestId},${later.requestId}` });
        } catch {}
      }
      if (secondOrderEvidence.length) {
        results.push(finding({
          id: "deepassess.second-order-canary-observed",
          check: "deepassess",
          category: "Second-Order Input Handling",
          status: "warn",
          severity: "medium",
          confidence: "confirmed",
          title: "Second-order input persistence/reflection observed",
          detail: "An inert canary submitted through an approved workflow was observed in a later response.",
          impact: "This is not automatically stored XSS or injection, but it confirms second-order data flow that needs context-aware encoding and storage validation.",
          remediation: "Verify output context, encode on render, validate on write, and add regression tests for stored content in HTML, attribute, script, JSON, and URL contexts.",
          evidence: secondOrderEvidence.slice(0, context.options.evidenceLimit),
          owasp: ["A03:2021 Injection"],
          cwe: ["CWE-79", "CWE-116"],
          exploitability: "validated",
        }));
      }
    }

    const hiddenApiUrls = (context.diagnostics.browserNetworkUrls ?? []).filter((url) => {
      try {
        const u = new URL(url);
        return u.origin === context.targetUrl.origin && /\/api\/|graphql|json|ajax|xhr|rest/i.test(u.pathname + u.search) && !staticallyObserved.has(url);
      } catch { return false; }
    });
    if (hiddenApiUrls.length) {
      results.push(finding({
        id: "deepassess.browser-hidden-api-surfaces",
        check: "deepassess",
        category: "JavaScript API Discovery",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Browser-only API surfaces discovered",
        detail: `${hiddenApiUrls.length} same-origin API-like request(s) were seen during browser execution that were not present in static links/forms.`,
        impact: "Hidden XHR/fetch APIs are where modern apps often expose IDOR, missing authorization, CSRF, and business logic flaws.",
        remediation: "Import OpenAPI/GraphQL schemas where available, seed these endpoints explicitly, and test them with approved role sessions.",
        evidence: hiddenApiUrls.slice(0, context.options.evidenceLimit).map((url) => ({ url, observed: "browser network API candidate" })),
        owasp: ["A01:2021 Broken Access Control", "A05:2021 Security Misconfiguration"],
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("deepassess", "Deep Assessment", "No deep-assessment signals detected on observed surface", "No safe signals for auth bypass, object-level access, CSRF marker gaps, second-order canary behavior, or browser-hidden APIs were detected."));
    }
    return results;
  },
};
