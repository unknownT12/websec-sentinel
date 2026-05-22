import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildAssessmentModel } from "../core/model.js";

const IDENTITY = /(id|uid|user|student|account|profile|owner|tenant|role|course|grade|mark|record)/i;
const REDIRECT = /(redirect|return|returnurl|next|url|continue|destination|target)/i;
const SEARCH = /(q|query|search|filter|sort|keyword|term|page)/i;
const SECRETISH = /(token|key|secret|password|pass|session|auth|jwt)/i;

function classify(name: string): string {
  if (IDENTITY.test(name)) return "identity/access-control";
  if (REDIRECT.test(name)) return "redirect/navigation";
  if (SECRETISH.test(name)) return "secret/session-sensitive";
  if (SEARCH.test(name)) return "search/filter";
  return "generic-input";
}

export const parameterModelCheck: Check = {
  name: "parammodel",
  description: "Builds a parameter risk model from observed URLs and forms without exploiting them.",
  async run(context) {
    const assessment = buildAssessmentModel(context);
    const results: ScanResult[] = [];
    const urlParams = assessment.parameterGroups.flatMap((g) => g.parameters.map((p) => ({ route: g.routeKey, param: p, examples: g.examples })));
    const formParams = context.pages.flatMap((page) => page.forms.flatMap((form) => form.inputs.map((input) => ({ route: `${form.method.toUpperCase()} ${form.action}`, param: input.name || input.type, examples: [page.finalUrl || page.url] }))));
    const all = [...urlParams, ...formParams].filter((p) => p.param);
    const classified = all.map((p) => ({ ...p, kind: classify(p.param) }));
    const risky = classified.filter((p) => p.kind !== "generic-input" && p.kind !== "search/filter");
    const identity = classified.filter((p) => p.kind === "identity/access-control");
    const redirect = classified.filter((p) => p.kind === "redirect/navigation");
    const secretish = classified.filter((p) => p.kind === "secret/session-sensitive");

    if (!all.length) {
      results.push(finding({
        id: "parammodel.no-parameters-observed",
        check: "parammodel",
        category: "Input Surface Model",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "No parameter/input model was observed",
        detail: "The crawler did not observe URL parameters or form input names.",
        impact: "Medium-impact application security testing usually needs parameter and form coverage; otherwise the tool mostly performs configuration review.",
        remediation: "Seed authenticated workflow URLs, enable deep crawl, and run against pages with search/filter/profile/dashboard forms.",
        evidence: [{ observed: `parameterGroups=${assessment.parameterGroups.length}; forms=${context.pages.reduce((s, p) => s + p.forms.length, 0)}` }],
        exploitability: "none",
      }));
      return results;
    }

    if (risky.length) {
      results.push(finding({
        id: "parammodel.risky-parameter-classes",
        check: "parammodel",
        category: "Input Surface Model",
        status: "warn",
        severity: identity.length || secretish.length ? "medium" : "low",
        confidence: "strong",
        title: "Risk-sensitive parameter classes observed",
        detail: `Observed ${identity.length} identity/access-control, ${redirect.length} redirect/navigation, and ${secretish.length} secret/session-sensitive parameter(s).`,
        impact: "These parameters define the safest medium-impact review queue for authorization, redirect, and token-handling checks.",
        remediation: "Validate ownership checks for identity parameters, strict allowlists for redirects, and avoid exposing token/session values in URLs or logs.",
        evidence: risky.slice(0, context.options.evidenceLimit).map((p) => ({ url: p.examples[0], parameter: p.param, observed: `${p.kind} on ${p.route}` })),
        owasp: ["A01:2021 Broken Access Control", "A03:2021 Injection", "A04:2021 Insecure Design"],
        exploitability: "none",
        falsePositiveNotes: "This is a model finding, not proof of exploitability. It prioritizes safe validation work.",
      }));
    }

    results.push(finding({
      id: "parammodel.inventory",
      check: "parammodel",
      category: "Input Surface Model",
      status: "info",
      severity: "info",
      confidence: "confirmed",
      title: "Parameter inventory built",
      detail: `${classified.length} parameter/input observation(s) classified into ${new Set(classified.map((p) => p.kind)).size} class(es).`,
      impact: "A parameter model makes the scanner more useful than a header checker because it tells the assessor what application inputs exist.",
      remediation: "Use the inventory to drive authorized, non-destructive validation and manual review.",
      evidence: classified.slice(0, context.options.evidenceLimit).map((p) => ({ url: p.examples[0], parameter: p.param, observed: `${p.kind} on ${p.route}` })),
      exploitability: "none",
    }));

    if (!results.some((r) => r.status === "warn")) results.unshift(pass("parammodel", "Input Surface Model", "Parameter model built without risky classes", `${classified.length} parameter/input observation(s) were classified.`));
    return results;
  },
};
