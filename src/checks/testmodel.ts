import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildTestModel } from "../core/testmodel.js";

export const testModelCheck: Check = {
  name: "testmodel",
  description: "Builds a book-inspired assessment model: surface nodes, control expectations, high-value hypotheses, and assurance readiness.",
  async run(context) {
    const results: ScanResult[] = [];
    const model = buildTestModel(context);

    if (model.readinessScore < 70) {
      results.push(finding({
        id: "testmodel.readiness-below-professional-threshold",
        check: "testmodel",
        category: "Assessment Model",
        status: "warn",
        severity: model.readinessScore < 45 ? "high" : "medium",
        confidence: "confirmed",
        title: "Testing model is not mature enough for strong assurance",
        detail: `Readiness score is ${model.readinessScore}/100. Blockers: ${model.blockers.join("; ") || "control gaps remain"}.`,
        impact: "The tool can still identify issues, but it should not claim professional assurance until the model has enough route, auth, client-side, and evidence coverage.",
        businessImpact: "A weak model can create executive confidence without actually exercising the workflows where high-impact defects usually exist.",
        remediation: "Add approved authenticated seeds, enable deep crawl, supply test-session headers, and close the listed not-tested control expectations.",
        evidence: [
          { observed: `readiness=${model.readinessScore}/100` },
          ...model.controlMatrix.map((c) => ({ observed: `${c.control}=${c.status}: ${c.reason}` })).slice(0, context.options.evidenceLimit),
        ],
        owasp: ["A04:2021 Insecure Design"],
        cwe: ["CWE-1059"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    const highHypotheses = model.hypotheses.filter((h) => h.priority === "high" || h.priority === "critical");
    if (highHypotheses.length) {
      results.push(finding({
        id: "testmodel.high-value-test-hypotheses",
        check: "testmodel",
        category: "Assessment Planning",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "High-value validation hypotheses require manual or controlled follow-up",
        detail: `${highHypotheses.length} high-value hypothesis/hypotheses were generated from the observed surface model.`,
        impact: "These are the areas most likely to reveal access-control, workflow, or input-validation issues if the client approves deeper validation.",
        remediation: "Use the hypotheses as a controlled manual test plan. Capture baseline, control, mutated, and replay evidence before escalating severity.",
        evidence: highHypotheses.slice(0, context.options.evidenceLimit).map((h) => ({ observed: `${h.priority.toUpperCase()}: ${h.title}; gate=${h.confidenceGate}` })),
        owasp: ["A01:2021 Broken Access Control", "A03:2021 Injection", "A04:2021 Insecure Design"],
        exploitability: "none",
        falsePositiveNotes: "Hypotheses are not vulnerability findings. They are prioritized validation tasks derived from the current model.",
      }));
    }

    const notTested = model.controlMatrix.filter((c) => c.status === "not-tested");
    if (notTested.length) {
      results.push(finding({
        id: "testmodel.control-expectations-not-tested",
        check: "testmodel",
        category: "Coverage Honesty",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "Some expected security controls were not actually tested",
        detail: notTested.map((c) => `${c.control}: ${c.reason}`).join("; "),
        impact: "A professional assessment must separate controls that passed from controls that were never exercised.",
        remediation: "Treat not-tested controls as scope gaps. Add authorized seeds, browser-side crawling, authenticated sessions, or manual review evidence.",
        evidence: notTested.map((c) => ({ observed: `${c.control} expectedOn=${c.expectedOn} reason=${c.reason}` })),
        exploitability: "none",
      }));
    }

    const topNodes = model.nodes.slice(0, Math.min(context.options.evidenceLimit, 8));
    if (!results.length) {
      results.push(pass("testmodel", "Assessment Model", "Testing model has strong readiness", `Readiness score ${model.readinessScore}/100 across ${model.nodes.length} modelled surface node(s).`));
    } else if (topNodes.length) {
      results.push(finding({
        id: "testmodel.top-surface-nodes",
        check: "testmodel",
        category: "Surface Intelligence",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Highest-value surface nodes modelled",
        detail: "The scanner ranked observed surfaces so the operator can focus validation effort where impact is highest.",
        impact: "Prioritized surface modelling improves assessment depth and reduces wasted automated probing.",
        remediation: "Review the listed nodes and confirm that high-risk workflows have approved validation coverage.",
        evidence: topNodes.map((n) => ({ url: n.url, method: n.method, observed: `route=${n.route} classes=${n.classes.join(",")} weight=${n.riskWeight} params=${n.parameters.join(",") || "none"}` })),
        exploitability: "none",
      }));
    }

    return results;
  },
};
