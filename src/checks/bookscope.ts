import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildBookScopeModel } from "../core/bookscope.js";

export const bookScopeCheck: Check = {
  name: "bookscope",
  description: "Enforces the uploaded-books boundary as a safe assessment lifecycle model: authorization, mapping, vulnerability analysis, validation, evidence, and reporting.",
  async run(context) {
    const results: ScanResult[] = [];
    const model = buildBookScopeModel(context);

    if (model.minimumImpact === "low" || model.modelScore < 60) {
      results.push(finding({
        id: "bookscope.below-medium-impact",
        check: "bookscope",
        category: "Book-Scoped Assessment Model",
        status: "warn",
        severity: "high",
        confidence: "confirmed",
        title: "Book-scoped testing model is below medium impact",
        detail: `Book-scope model score is ${model.modelScore}/100 and impact is ${model.minimumImpact}. Blockers: ${model.blockers.join("; ") || "insufficient surface/sink/evidence depth"}.`,
        impact: "The assessment may still produce useful findings, but it does not yet meet a medium-impact assurance threshold because the underlying testing lifecycle is incomplete.",
        businessImpact: "A shallow lifecycle creates a risk of missing the practical workflow flaws that usually matter most to clients.",
        remediation: "Improve the missing phase gates: add approved seeds, authenticated coverage, validate mode, parameterized surface coverage, HAR/replay evidence, and manual follow-up for generated sink tests.",
        evidence: model.phaseGates.map((g) => ({ observed: `${g.phase}=${g.status} (${g.reason})` })),
        references: ["The Web Application Hacker's Handbook", "Penetration Testing: A Hands-On Introduction to Hacking", "The Hacker Playbook 2/3", "RTFM"],
        owasp: ["A04:2021 Insecure Design", "A05:2021 Security Misconfiguration"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    } else {
      results.push(pass("bookscope", "Book-Scoped Assessment Model", "Book-scoped model meets at least medium impact", `Model score ${model.modelScore}/100 with ${model.sinkInventory.length} sink(s) and impact=${model.minimumImpact}.`));
    }

    const missing = model.phaseGates.filter((g) => g.status !== "met");
    if (missing.length) {
      results.push(finding({
        id: "bookscope.phase-gates-open",
        check: "bookscope",
        category: "Assessment Lifecycle",
        status: "warn",
        severity: missing.some((g) => g.status === "missing") ? "medium" : "low",
        confidence: "confirmed",
        title: "Some book-derived phase gates are not fully met",
        detail: missing.map((g) => `${g.phase}: ${g.status}`).join(", "),
        impact: "The scanner should not claim broad assurance until the missing lifecycle gates are closed or explicitly accepted as out of scope.",
        remediation: "Treat these as operator tasks before relying on a strong assurance rating.",
        evidence: missing.map((g) => ({ observed: `${g.phase} weight=${g.weight}: ${g.reason}` })),
        exploitability: "none",
      }));
    }

    if (model.sinkInventory.length) {
      results.push(finding({
        id: "bookscope.sink-inventory",
        check: "bookscope",
        category: "Input Surface Model",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Book-scoped sink inventory generated",
        detail: `${model.sinkInventory.length} input/workflow sink(s) were classified for safe follow-up testing.`,
        impact: "Sink classification focuses validation on identity, redirect, file, credential, state-change, API, and search surfaces instead of blind scanning.",
        remediation: "Use the safe test list as an operator checklist and only escalate a vulnerability when evidence crosses the stated confidence gate.",
        evidence: model.sinkInventory.slice(0, context.options.evidenceLimit).map((s) => ({ url: s.url, method: s.method, parameter: s.parameters.join(",") || `forms=${s.forms}`, observed: `${s.sinkType}; tests=${s.safeTests.join(" | ")}` })),
        exploitability: "none",
        falsePositiveNotes: "This inventory is not a vulnerability list. It is a model-driven testing queue.",
      }));
    }

    return results;
  },
};
