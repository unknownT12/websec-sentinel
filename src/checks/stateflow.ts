import type { Check, PageForm, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const STATE_METHOD = /^(POST|PUT|PATCH|DELETE)$/i;
const HIGH_VALUE = /(admin|student|grade|mark|profile|account|settings|password|reset|export|upload|download|api|dashboard)/i;

function actionType(form: PageForm): "credential" | "state-change" | "search" | "file" | "unknown" {
  const text = `${form.action} ${form.method} ${form.inputs.map((i) => `${i.name}:${i.type}`).join(" ")}`;
  if (/password|username|email|login|session|token/i.test(text)) return "credential";
  if (/upload|file|document|attachment/i.test(text)) return "file";
  if (/search|query|filter|sort|q|keyword|term/i.test(text) || form.method.toUpperCase() === "GET") return "search";
  if (STATE_METHOD.test(form.method) || /delete|update|create|save|role|grade|mark|student|amount/i.test(text)) return "state-change";
  return "unknown";
}

export const stateFlowCheck: Check = {
  name: "stateflow",
  description: "Builds a non-destructive web workflow/state model from forms and links, then flags weak workflow coverage and high-value transition gaps.",
  async run(context) {
    const results: ScanResult[] = [];
    const transitions = context.pages.flatMap((page) => page.forms.map((form) => ({
      from: page.finalUrl || page.url,
      to: form.action || page.finalUrl || page.url,
      method: form.method.toUpperCase(),
      type: actionType(form),
      hasCsrf: form.hasCsrfToken,
      inputs: form.inputs.map((i) => i.name || i.type).filter(Boolean),
      highValue: HIGH_VALUE.test(`${page.url} ${form.action} ${form.inputs.map((i) => i.name).join(" ")}`),
    })));
    const highValueTransitions = transitions.filter((t) => t.highValue || ["credential", "state-change", "file"].includes(t.type));
    const stateChangingWithoutCsrf = transitions.filter((t) => (STATE_METHOD.test(t.method) || t.type === "state-change" || t.type === "credential") && !t.hasCsrf);

    if (!context.pages.length || !transitions.length) {
      results.push(finding({
        id: "stateflow.no-workflow-model",
        check: "stateflow",
        category: "Workflow Coverage",
        status: "warn",
        severity: context.options.requireAuth ? "high" : "medium",
        confidence: "confirmed",
        title: "No meaningful workflow/state model was built",
        detail: `Pages=${context.pages.length}, form transitions=${transitions.length}.`,
        impact: "Without forms and transitions, the scanner cannot model business workflows where medium/high-impact web issues usually appear.",
        remediation: "Add approved authenticated seeds, a valid session header, and deep crawl coverage for dashboard/workflow pages. Use browser-assisted route discovery if the app is JavaScript-heavy.",
        evidence: [{ observed: `pages=${context.pages.length}; forms=${transitions.length}; links=${context.pages.reduce((s, p) => s + p.links.length, 0)}` }],
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    if (stateChangingWithoutCsrf.length) {
      results.push(finding({
        id: "stateflow.state-changing-transitions-without-csrf-signal",
        check: "stateflow",
        category: "Workflow Control Model",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "State-changing workflow transitions lack visible CSRF signals",
        detail: `${stateChangingWithoutCsrf.length} state-changing/credential transition(s) lacked visible CSRF markers in the parsed form model.`,
        impact: "This is a practical review queue for workflow protection. It is not proof of CSRF, but it points to forms that need server-side verification.",
        remediation: "Confirm server-side CSRF enforcement, SameSite cookie posture, and origin/referrer validation for these workflows.",
        evidence: stateChangingWithoutCsrf.slice(0, context.options.evidenceLimit).map((t) => ({ url: t.from, method: t.method, observed: `${t.type} -> ${t.to}`, parameter: t.inputs.join(",") })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        cwe: ["CWE-352"],
        exploitability: "none",
        falsePositiveNotes: "The scanner does not submit destructive forms; this is a control-signal finding requiring approved validation.",
      }));
    }

    if (highValueTransitions.length) {
      results.push(finding({
        id: "stateflow.high-value-transitions",
        check: "stateflow",
        category: "Workflow Intelligence",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "High-value workflow transitions identified",
        detail: `${highValueTransitions.length} high-value transition(s) should be prioritized for approved manual or role-based validation.`,
        impact: "This gives the assessor a focused medium-impact workflow test plan instead of only header/configuration checks.",
        remediation: "Validate these transitions with approved test accounts and capture baseline/control/replay evidence before escalating any issue.",
        evidence: highValueTransitions.slice(0, context.options.evidenceLimit).map((t) => ({ url: t.from, method: t.method, observed: `${t.type}; action=${t.to}; csrf=${t.hasCsrf}`, parameter: t.inputs.join(",") })),
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("stateflow", "Workflow Coverage", "Workflow/state model built without immediate gaps", `Modelled ${transitions.length} transition(s) across ${context.pages.length} page(s).`));
    return results;
  },
};
