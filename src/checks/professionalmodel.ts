import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildProfessionalModel, professionalMethodologySources } from "../core/professionalmodel.js";

export const professionalModelCheck: Check = {
  name: "professionalmodel",
  description: "Builds the product-grade assessment model: control objectives, maturity gates, safe test cases, and evidence repeatability.",
  async run(context) {
    const model = buildProfessionalModel(context);
    const results: ScanResult[] = [];

    if (model.productTier === "prototype" || model.productTier === "assessment-assistant") {
      results.push(finding({
        id: "professionalmodel.product-readiness-below-medium",
        check: "professionalmodel",
        category: "Product-Grade Assessment Model",
        status: "warn",
        severity: model.productTier === "prototype" ? "high" : "medium",
        confidence: "confirmed",
        title: "Engine model is not yet product-grade for medium-impact assurance",
        detail: `Product model score is ${model.productScore}/100 and tier=${model.productTier}. Blockers: ${model.blockers.slice(0, 6).join("; ") || "none recorded"}.`,
        impact: "The scanner can still help an assessor, but it should not be treated as a professional product unless the model covers scoping, mapping, authenticated state, access control, input handling, and reproducible evidence.",
        businessImpact: "A product-grade security tool must prevent shallow scans from creating executive confidence without exercised controls.",
        remediation: "Close the failed maturity gates: provide approved authenticated seeds/sessions, enable deep crawl, export evidence ledgers, and ensure routes/forms/parameters are actually modelled before trusting impact ratings.",
        evidence: [
          { observed: `score=${model.productScore}; tier=${model.productTier}` },
          ...model.gates.map((g) => ({ observed: `${g.name}=${g.status}: ${g.reason}` })),
        ],
        references: professionalMethodologySources(),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design", "A05:2021 Security Misconfiguration"],
        exploitability: "none",
        remediationPriority: "immediate",
        falsePositiveNotes: "This is a product-readiness model finding, not a target vulnerability.",
      }));
    } else {
      results.push(pass("professionalmodel", "Product-Grade Assessment Model", "Engine model meets medium-impact product threshold", `Product model score ${model.productScore}/100 and tier=${model.productTier}.`));
    }

    const notCovered = model.controls.filter((c) => c.status === "not-covered");
    if (notCovered.length) {
      results.push(finding({
        id: "professionalmodel.control-objectives-not-covered",
        check: "professionalmodel",
        category: "Control Objective Coverage",
        status: "warn",
        severity: notCovered.some((c) => c.weight >= 13) ? "high" : "medium",
        confidence: "confirmed",
        title: "Professional control objectives are not covered by the current scan model",
        detail: `${notCovered.length} control objective(s) are not covered: ${notCovered.map((c) => c.domain).join(", ")}.`,
        impact: "Uncovered controls must be treated as assessment gaps, not passing results.",
        remediation: "Use the control objective evidence list to configure the next authorized run and collect the missing evidence.",
        evidence: notCovered.slice(0, context.options.evidenceLimit).map((c) => ({ observed: `${c.id}: ${c.reason}; required=${c.requiredEvidence.join(" | ")}` })),
        references: professionalMethodologySources(),
        exploitability: "none",
      }));
    }

    if (model.testCases.length) {
      const high = model.testCases.filter((t) => t.priority === "critical" || t.priority === "high");
      results.push(finding({
        id: "professionalmodel.safe-test-case-plan",
        check: "professionalmodel",
        category: "Model-Driven Test Planning",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Product-grade safe test case plan generated from the model",
        detail: `${model.testCases.length} safe test case(s) generated, including ${high.length} high-priority case(s).`,
        impact: "The product is now driven by an explicit test model instead of generic checks or report cosmetics.",
        remediation: "Execute the generated test cases only inside the approved scope, capturing the required evidence and applying the confirmation gate before escalating any issue.",
        evidence: model.testCases.slice(0, context.options.evidenceLimit).map((t) => ({ url: t.route, method: t.method, observed: `${t.priority.toUpperCase()} ${t.domain}: ${t.title}; gate=${t.confirmationGate}` })),
        references: professionalMethodologySources(),
        exploitability: "none",
        falsePositiveNotes: "Generated test cases are not vulnerability findings; they are the product's controlled assessment plan.",
      }));
    } else {
      results.push(finding({
        id: "professionalmodel.no-test-cases-generated",
        check: "professionalmodel",
        category: "Model-Driven Test Planning",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "No product-grade test cases were generated",
        detail: "The current crawl did not expose enough routes, parameters, or forms for the engine to build a meaningful test plan.",
        impact: "Without generated test cases, the tool behaves more like a configuration checker than an application security assessment product.",
        remediation: "Add approved seed URLs, authenticated session headers, deeper crawl settings, and pages with forms/parameters.",
        evidence: [{ observed: JSON.stringify(model.modelEvidence) }],
        exploitability: "none",
      }));
    }

    const failedGates = model.gates.filter((g) => g.status === "fail");
    if (failedGates.length) {
      results.push(finding({
        id: "professionalmodel.failed-maturity-gates",
        check: "professionalmodel",
        category: "Maturity Gates",
        status: "warn",
        severity: "high",
        confidence: "confirmed",
        title: "One or more product maturity gates failed",
        detail: failedGates.map((g) => `${g.name}: ${g.reason}`).join("; "),
        impact: "A failed maturity gate means the tool should block or downgrade assurance claims for this run.",
        remediation: failedGates.map((g) => g.remediation).join(" "),
        evidence: failedGates.map((g) => ({ observed: `${g.name}=${g.status}; ${g.reason}` })),
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    return results;
  },
};
