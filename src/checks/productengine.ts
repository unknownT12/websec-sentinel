import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { buildProductEngineModel } from "../core/productengine.js";

export const productEngineCheck: Check = {
  name: "productengine",
  description: "Book-scoped professional product engine gate. Scores whether the scanner model is acting like a real assessment product, not a prototype/report generator.",
  async run(context) {
    const model = buildProductEngineModel(context);
    const results: ScanResult[] = [];

    if (!model.mediumImpactReady) {
      results.push(finding({
        id: "productengine.medium-impact-not-ready",
        check: "productengine",
        category: "Product Engine",
        status: "fail",
        severity: "high",
        confidence: "confirmed",
        title: "Book-scoped product model has not reached medium-impact readiness",
        detail: `Product engine score ${model.score}/100, stage=${model.stage}. Heavy blockers remain: ${model.blockers.slice(0, 4).join(" | ") || "none listed"}`,
        impact: "The tool may still behave like an assessment assistant instead of a product-grade testing engine for the configured run.",
        remediation: "Close failed gates: improve scope metadata, authenticated coverage, route/form/parameter depth, differential access modelling, safe validation, and repeatable evidence exports.",
        evidence: model.gates.map((g) => ({ observed: `${g.id}=${g.status}:${g.score}`, snippet: g.evidence.join("; ") })).slice(0, context.options.evidenceLimit),
        references: ["Book-scoped lifecycle/product model: authorization, reconnaissance, mapping, safe validation, evidence, reporting."],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    } else {
      results.push(pass("productengine", "Product Engine", "Book-scoped product model reached medium-impact readiness", `Product engine score ${model.score}/100, stage=${model.stage}, vectors=${model.testVectors.length}, evidence=${model.modelEvidence.evidenceExports.join(",") || "internal"}.`));
    }

    if (!model.exceptionalReady) {
      results.push(finding({
        id: "productengine.exceptional-gaps",
        check: "productengine",
        category: "Product Engine",
        status: "warn",
        severity: model.mediumImpactReady ? "medium" : "high",
        confidence: "confirmed",
        title: "Exceptional product criteria are not fully met",
        detail: `Exceptional readiness requires score>=90, no failed gates, authenticated high-value coverage, parameterized surfaces, and JSONL+HAR+replay evidence. Current score=${model.score}, auth=${model.modelEvidence.authSupplied}, highValue=${model.modelEvidence.highValueSurfaces}, parameterized=${model.modelEvidence.parameterizedSurfaces}, exports=${model.modelEvidence.evidenceExports.join(",") || "none"}.`,
        impact: "The engine can support medium-impact assessment work but still has measurable gaps before it should be presented as exceptional.",
        remediation: "Run with approved authenticated seeds, deep crawl, all evidence exports, differential/input validation checks, and enough route diversity to satisfy all product gates.",
        evidence: model.engineeringDebt.slice(0, context.options.evidenceLimit).map((d) => ({ observed: d })),
        exploitability: "none",
        remediationPriority: "planned",
      }));
    }

    const runnableVectors = model.testVectors.filter((v) => v.canRunNow).length;
    if (model.testVectors.length < 3) {
      results.push(finding({
        id: "productengine.insufficient-test-vectors",
        check: "productengine",
        category: "Product Engine",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Too few model-generated test vectors",
        detail: `Only ${model.testVectors.length} test vector(s) were generated from the observed surface.`,
        impact: "The system has limited ability to guide a professional assessment beyond basic checks.",
        remediation: "Seed approved authenticated routes and enable deep crawling until the model generates access, input, and workflow vectors.",
        evidence: [{ observed: JSON.stringify(model.modelEvidence) }],
        exploitability: "none",
      }));
    } else {
      results.push(pass("productengine", "Product Engine", "Model-generated test vectors are available", `${model.testVectors.length} vector(s) generated; ${runnableVectors} runnable under current auth/scope settings.`));
    }

    return results;
  },
};
