import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const CANARY = "wss_future_canary_91e2";
const ERROR_RE = /(exception|stack trace|traceback|sql syntax|postgres|mysql|mariadb|oracle|sqlite|odbc|jdbc|typeerror|referenceerror|undefined is not|cannot read properties)/i;
const SENSITIVE_PARAM = /^(id|uid|user|student|account|role|tenant|grade|mark|result|file|download|redirect|next|returnUrl)$/i;

export const mutationCheck: Check = {
  name: "mutation",
  description: "Performs controlled, non-destructive parameter mutation to detect fragile input handling, reflection, and error-path exposure.",
  async run(context) {
    const results: ScanResult[] = [];
    if (context.options.mode !== "validate" || !context.options.authorized) {
      results.push(finding({
        id: "mutation.skipped-not-validate",
        check: "mutation",
        category: "Adaptive Validation",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Adaptive mutation skipped outside authorized validate mode",
        detail: "Controlled parameter mutation only runs in validate mode with explicit authorization.",
        impact: "Input-handling fragility cannot be evaluated from passive observation alone.",
        remediation: "Run with --mode validate --authorized inside the signed scope when this testing is approved.",
        exploitability: "none",
      }));
      return results;
    }

    const candidates = context.pages
      .map((page) => {
        try { return { page, url: new URL(page.finalUrl || page.url), params: [...new URL(page.finalUrl || page.url).searchParams.keys()] }; }
        catch { return null; }
      })
      .filter((x): x is NonNullable<typeof x> => Boolean(x && x.params.length));

    const errors: ScanResult["evidence"] = [];
    const reflections: ScanResult["evidence"] = [];
    const statusDeltas: ScanResult["evidence"] = [];

    for (const item of candidates.slice(0, context.options.evidenceLimit)) {
      for (const param of item.params.slice(0, 3)) {
        const test = new URL(item.url.toString());
        const original = test.searchParams.get(param) ?? "";
        test.searchParams.set(param, `${CANARY}_${param}`);
        try {
          const res = await request(test.toString(), context.options);
          if (ERROR_RE.test(res.body.slice(0, 5000))) errors.push({ url: res.url, status: res.status, parameter: param, snippet: safeSnippet(res.body), requestId: res.requestId });
          if (res.body.includes(`${CANARY}_${param}`)) reflections.push({ url: res.url, status: res.status, parameter: param, observed: `${CANARY}_${param}`, requestId: res.requestId });
          if (Math.abs(res.status - item.page.status) >= 100 || (item.page.status < 400 && res.status >= 500)) {
            statusDeltas.push({ url: res.url, status: res.status, parameter: param, observed: `baseline=${item.page.status}, mutated=${res.status}, originalLength=${original.length}`, requestId: res.requestId });
          }
        } catch {}
      }
    }

    if (errors.length) {
      results.push(finding({
        id: "mutation.verbose-error-on-canary",
        check: "mutation",
        category: "Adaptive Validation",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Controlled mutation triggered verbose error signal",
        detail: "A harmless canary mutation produced a response containing framework, database, or stack-trace style error text.",
        impact: "Verbose error paths make targeted vulnerability research easier and may reveal implementation details.",
        remediation: "Normalize error handling, validate parameter types server-side, and keep detailed errors in protected logs only.",
        evidence: errors.slice(0, context.options.evidenceLimit),
        owasp: ["A03:2021 Injection", "A05:2021 Security Misconfiguration"],
        cwe: ["CWE-209", "CWE-20"],
        exploitability: "practical",
      }));
    }

    const sensitiveReflections = reflections.filter((e) => e.parameter && SENSITIVE_PARAM.test(e.parameter));
    if (sensitiveReflections.length) {
      results.push(finding({
        id: "mutation.sensitive-param-reflection",
        check: "mutation",
        category: "Adaptive Validation",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Sensitive parameter reflection observed",
        detail: "A canary placed into a sensitive parameter name was reflected in the response.",
        impact: "Reflection does not prove XSS, but it highlights a rendering sink around high-value parameters that requires contextual encoding review.",
        remediation: "Apply strict output encoding and template escaping; manually inspect rendering context under approved procedures.",
        evidence: sensitiveReflections.slice(0, context.options.evidenceLimit),
        owasp: ["A03:2021 Injection"],
        cwe: ["CWE-79", "CWE-116"],
        exploitability: "theoretical",
        falsePositiveNotes: "Only inert canaries are used; no script execution payloads are sent.",
      }));
    } else if (reflections.length) {
      results.push(finding({
        id: "mutation.general-reflection-observed",
        check: "mutation",
        category: "Adaptive Validation",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "General parameter reflection observed",
        detail: "A harmless canary was reflected in at least one response.",
        impact: "This is a sink-discovery signal for manual encoding review, not proof of exploitability.",
        remediation: "Review the reflected contexts and ensure framework/template escaping is enabled.",
        evidence: reflections.slice(0, context.options.evidenceLimit),
        exploitability: "none",
      }));
    }

    if (statusDeltas.length) {
      results.push(finding({
        id: "mutation.status-delta",
        check: "mutation",
        category: "Adaptive Validation",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Parameter mutation changed response behavior",
        detail: "A canary mutation changed HTTP status behavior compared with the baseline response.",
        impact: "Status deltas identify input-sensitive paths that deserve manual authorization and error-handling review.",
        remediation: "Review these parameters for type validation, access control, and predictable error responses.",
        evidence: statusDeltas.slice(0, context.options.evidenceLimit),
        exploitability: "none",
      }));
    }

    if (!candidates.length) {
      results.push(finding({
        id: "mutation.no-parameter-surface",
        check: "mutation",
        category: "Adaptive Validation",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "No parameterized URLs observed for adaptive mutation",
        detail: "The crawler did not observe query-parameter URLs suitable for controlled mutation.",
        impact: "Parameter-level input validation coverage is limited.",
        remediation: "Increase crawl depth, use authenticated coverage, and seed representative business workflow URLs if approved.",
        exploitability: "none",
      }));
    } else if (!results.length) {
      results.push(pass("mutation", "Adaptive Validation", "Controlled mutation produced no concerning signals", "Inert canary mutations did not trigger verbose errors, status anomalies, or sensitive reflections on the tested parameter surface."));
    }

    return results;
  },
};
