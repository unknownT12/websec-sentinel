import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildAssessmentModel } from "../core/model.js";

export const engineModelCheck: Check = {
  name: "enginemodel",
  description: "Evaluates the scanner's internal testing model: route normalization, evidence diversity, auth state, soft-404 behavior, and duplicate request quality.",
  async run(context) {
    const results: ScanResult[] = [];
    const model = buildAssessmentModel(context);
    const c = model.coverageVector;

    if (c.requestCount === 0) {
      results.push(finding({
        id: "enginemodel.no-request-model",
        check: "enginemodel",
        category: "Scanner Model Quality",
        status: "fail",
        severity: "high",
        confidence: "confirmed",
        title: "No request model was produced",
        detail: "The engine did not capture any HTTP observations, so it cannot reason about route coverage, auth state, parameters, or evidence quality.",
        impact: "Without a request model, findings are limited to startup/configuration logic and cannot be considered application assurance.",
        remediation: "Confirm target reachability from the container, increase timeout, check DNS/TLS errors, and seed at least one approved reachable page.",
        evidence: context.diagnostics.requestFailures.slice(0, context.options.evidenceLimit).map((f) => ({ url: f.url, observed: f.error })),
        exploitability: "none",
        remediationPriority: "immediate",
      }));
      return results;
    }

    if (c.routeCount < Math.min(5, context.options.minPages + 2) && context.options.crawlDepth > 1) {
      results.push(finding({
        id: "enginemodel.low-route-diversity",
        check: "enginemodel",
        category: "Scanner Model Quality",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Low normalized route diversity",
        detail: `The model saw ${c.routeCount} normalized route group(s) from ${c.requestCount} request(s).`,
        impact: "Low route diversity means the scanner has limited evidence across workflows and may miss application-layer issues.",
        remediation: "Add approved seed URLs, authenticated entry points, sitemap coverage, or browser-discovered routes until route diversity improves.",
        evidence: model.uniqueRouteKeys.slice(0, context.options.evidenceLimit).map((r) => ({ observed: r })),
        exploitability: "none",
      }));
    }

    if (model.loginWallRatio > 0.5) {
      results.push(finding({
        id: "enginemodel.login-wall-dominates",
        check: "enginemodel",
        category: "Auth-State Modeling",
        status: "warn",
        severity: context.options.requireAuth ? "high" : "medium",
        confidence: "strong",
        title: "Login wall dominates observed traffic",
        detail: `${Math.round(model.loginWallRatio * 100)}% of modelled requests were blocked, forbidden, or redirected to authentication-like routes.`,
        impact: "The scan is mostly testing the wall around the application rather than the protected workflows where access-control and business-logic issues usually live.",
        remediation: "Use a client-approved test account/session and seed the authenticated landing page while keeping logout and destructive paths prohibited.",
        evidence: Object.entries(model.authDistribution).map(([state, count]) => ({ observed: `${state}=${count}` })),
        owasp: ["A01:2021 Broken Access Control"],
        exploitability: "none",
      }));
    }

    if (model.duplicateRouteGroups.length && model.duplicateRouteGroups[0]!.count > Math.max(8, c.routeCount * 2)) {
      const top = model.duplicateRouteGroups[0]!;
      results.push(finding({
        id: "enginemodel.duplicate-request-heavy",
        check: "enginemodel",
        category: "Crawler Efficiency",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Duplicate request pattern observed",
        detail: `The most repeated normalized route was requested ${top.count} times: ${top.routeKey}.`,
        impact: "High duplication reduces assessment efficiency and can make coverage appear broader than it is.",
        remediation: "Tune seed URLs, route normalization, and crawler queue de-duplication for the target application.",
        evidence: top.examples.map((url) => ({ url })),
        exploitability: "none",
      }));
    }

    if (model.soft404Signals.length) {
      results.push(finding({
        id: "enginemodel.soft-404-suspected",
        check: "enginemodel",
        category: "False-Positive Control",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "Soft-404 or generic response family suspected",
        detail: "Multiple different routes returned highly similar 200 responses, which may indicate a generic fallback page, SPA shell, or soft-404 behavior.",
        impact: "Discovery and exposure findings can become false positives when generic fallback pages look like valid routes.",
        remediation: "Manually verify discovered routes and tune the scanner to treat this response family as a fallback for this target.",
        evidence: model.soft404Signals.slice(0, context.options.evidenceLimit).flatMap((s) => s.examples.map((url) => ({ url, status: s.status, observed: `responseFamily=${s.hash}` }))),
        falsePositiveNotes: "This is a quality-control signal, not a vulnerability finding.",
        exploitability: "none",
      }));
    }

    if (c.parameterizedRouteCount > 0 && context.options.mode !== "validate") {
      results.push(finding({
        id: "enginemodel.parameters-not-validated",
        check: "enginemodel",
        category: "Validation Readiness",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Parameterized routes observed but not validated",
        detail: `${c.parameterizedRouteCount} parameterized route group(s) were observed.`,
        impact: "Input validation, reflection, redirect, and authorization signals require validate mode or manual verification to increase confidence.",
        remediation: "For approved scopes, re-run in validate mode with safe canaries and a redacted replay file.",
        evidence: model.parameterGroups.slice(0, context.options.evidenceLimit).map((g) => ({ observed: `${g.routeKey} params=${g.parameters.join(",")}` })),
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("enginemodel", "Scanner Model Quality", "Internal testing model has usable evidence diversity", `Modelled ${c.requestCount} request(s), ${c.routeCount} route group(s), ${c.formCount} form(s), and ${c.parameterizedRouteCount} parameterized route group(s).`));
    }
    return results;
  },
};
