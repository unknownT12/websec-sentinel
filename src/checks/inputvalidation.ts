import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const CANARY = "wss_iv_9f41c2";
const SAFE_GET_NAMES = /(q|query|search|keyword|term|filter|page|sort|return|next|redirect|url)/i;
const UNSAFE_FORM = /(password|passwd|pwd|delete|remove|role|amount|payment|billing|grade|mark|student|admin|user_id|userid)/i;

export const inputValidationCheck: Check = {
  name: "inputvalidation",
  description: "Performs safe, bounded input-validation probes on GET/search-style surfaces using inert canaries only.",
  async run(context) {
    const results: ScanResult[] = [];
    if (context.options.mode !== "validate" || !context.options.authorized) {
      results.push(finding({
        id: "inputvalidation.skipped",
        check: "inputvalidation",
        category: "Input Validation",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Input validation probes skipped outside authorized validate mode",
        detail: "Safe canary probes only run when --mode validate and --authorized are both supplied.",
        impact: "Input sinks were not dynamically probed during this run.",
        remediation: "Use authorized validate mode on client-approved scope for safe application-layer checks.",
        exploitability: "none",
      }));
      return results;
    }

    let probed = 0;
    for (const page of context.pages) {
      if (probed >= context.options.evidenceLimit) break;
      const url = new URL(page.finalUrl || page.url);
      const params = [...url.searchParams.keys()].filter((p) => SAFE_GET_NAMES.test(p));
      for (const param of params) {
        if (probed >= context.options.evidenceLimit) break;
        const test = new URL(url.toString());
        test.searchParams.set(param, CANARY);
        try {
          probed++;
          const res = await request(test.toString(), context.options);
          if (res.body.includes(CANARY)) {
            results.push(finding({
              id: `inputvalidation.reflection.${Buffer.from(test.toString()).toString("base64url").slice(0, 12)}`,
              check: "inputvalidation",
              category: "Input Validation",
              status: "warn",
              severity: "medium",
              confidence: "moderate",
              title: "Reflected input sink requires encoding review",
              detail: `Safe canary value was reflected from parameter ${param}.`,
              impact: "Reflection is not automatically exploitable, but it identifies a rendering sink that requires contextual encoding review.",
              remediation: "Apply contextual output encoding, strict validation, and manual sink-context verification under approved procedures.",
              evidence: [{ url: res.url, status: res.status, parameter: param, observed: CANARY, snippet: safeSnippet(res.body), requestId: res.requestId }],
              owasp: ["A03:2021 Injection"],
              cwe: ["CWE-79", "CWE-116"],
              falsePositiveNotes: "Only an inert canary was used; no script execution or destructive payload was attempted.",
            }));
          }
        } catch {}
      }

      for (const form of page.forms) {
        if (probed >= context.options.evidenceLimit) break;
        if (form.method !== "GET") continue;
        if (form.inputs.some((i) => UNSAFE_FORM.test(`${i.name} ${i.type}`))) continue;
        const names = form.inputs.map((i) => i.name).filter((n) => n && SAFE_GET_NAMES.test(n)).slice(0, 3);
        if (!names.length) continue;
        try {
          const test = new URL(form.action || page.finalUrl || page.url);
          for (const name of names) test.searchParams.set(name, CANARY);
          probed++;
          const res = await request(test.toString(), context.options);
          if (res.body.includes(CANARY)) {
            results.push(finding({
              id: `inputvalidation.form-reflection.${Buffer.from(test.toString()).toString("base64url").slice(0, 12)}`,
              check: "inputvalidation",
              category: "Input Validation",
              status: "warn",
              severity: "medium",
              confidence: "moderate",
              title: "GET form reflects safe canary input",
              detail: "A safe GET form probe was reflected in the response body.",
              impact: "Search/filter surfaces that reflect input need contextual output encoding and input validation.",
              remediation: "Validate and encode all reflected form inputs; add regression tests for output contexts.",
              evidence: [{ url: res.url, status: res.status, parameter: names.join(", "), observed: CANARY, snippet: safeSnippet(res.body), requestId: res.requestId }],
              owasp: ["A03:2021 Injection"],
              cwe: ["CWE-79"],
            }));
          }
        } catch {}
      }
    }
    if (!results.length) results.push(pass("inputvalidation", "Input Validation", "No reflected safe canary sinks observed", `Completed ${probed} safe input-validation probe(s) without reflection findings.`));
    return results;
  },
};
