import type { ScanContext } from "../types.js";
import { buildAssessmentModel } from "./model.js";
import { buildTestModel, type SurfaceNode } from "./testmodel.js";

export type BookPhase =
  | "authorization"
  | "reconnaissance"
  | "mapping"
  | "vulnerability-analysis"
  | "safe-validation"
  | "evidence"
  | "reporting";

export interface PhaseGate {
  phase: BookPhase;
  status: "met" | "partial" | "missing";
  reason: string;
  weight: number;
}

export interface SinkModel {
  route: string;
  url: string;
  method: string;
  sinkType: "identity" | "redirect" | "search" | "file" | "credential" | "state-change" | "api" | "unknown";
  parameters: string[];
  forms: number;
  confidence: "strong" | "moderate" | "low";
  safeTests: string[];
}

export interface BookScopeModel {
  phaseGates: PhaseGate[];
  sinkInventory: SinkModel[];
  minimumImpact: "low" | "medium" | "high";
  modelScore: number;
  blockers: string[];
  recommendedNextSafeTests: string[];
}

const IDENTITY = /(id|uid|user|student|account|profile|owner|tenant|role|course|grade|mark)/i;
const REDIRECT = /(redirect|return|returnurl|next|url|continue|destination|target)/i;
const SEARCH = /(q|query|search|filter|sort|keyword|term|page)/i;
const FILE = /(upload|download|export|import|file|document|csv|pdf|attachment)/i;
const CREDENTIAL = /(password|passwd|pwd|username|email|login|session|token)/i;
const API = /(api|graphql|json|ajax|rest|openapi|swagger)/i;

function status(condition: boolean, partial: boolean): "met" | "partial" | "missing" {
  if (condition) return "met";
  if (partial) return "partial";
  return "missing";
}

function phaseScore(gates: PhaseGate[]): number {
  const max = gates.reduce((s, g) => s + g.weight, 0);
  const actual = gates.reduce((s, g) => s + (g.status === "met" ? g.weight : g.status === "partial" ? g.weight * 0.45 : 0), 0);
  return Math.round((actual / Math.max(1, max)) * 100);
}

function sinkType(node: SurfaceNode, params: string[]): SinkModel["sinkType"] {
  const text = `${node.url} ${node.route} ${params.join(" ")}`;
  if (IDENTITY.test(text)) return "identity";
  if (REDIRECT.test(text)) return "redirect";
  if (FILE.test(text)) return "file";
  if (CREDENTIAL.test(text) || node.hasPasswordInput) return "credential";
  if (API.test(text) || node.classes.includes("api")) return "api";
  if (node.hasPostForm || node.classes.includes("state-changing")) return "state-change";
  if (SEARCH.test(text)) return "search";
  return "unknown";
}

function safeTestsFor(sink: SinkModel["sinkType"]): string[] {
  switch (sink) {
    case "identity": return ["authenticated-vs-anonymous differential", "lower-privilege comparison where approved", "response-family comparison without data extraction"];
    case "redirect": return ["same-origin allowlist check", "external inert canary redirect check", "Location-header comparison"];
    case "search": return ["inert reflection canary", "verbose-error pattern check", "response-delta comparison"];
    case "file": return ["metadata-only exposure review", "content-type and disposition check", "extension allowlist review"];
    case "credential": return ["cookie flag review", "CSRF signal review", "cache-control review"];
    case "state-change": return ["CSRF token signal check", "method safety review", "prohibited-path enforcement"];
    case "api": return ["schema exposure review", "sensitive JSON key scan", "auth-boundary differential where approved"];
    default: return ["baseline and response-family mapping", "manual review queue"];
  }
}

export function buildBookScopeModel(context: ScanContext): BookScopeModel {
  const assessment = buildAssessmentModel(context);
  const testModel = buildTestModel(context);
  const authSupplied = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
  const hasReportEvidence = Boolean(context.options.jsonlLog || context.options.harFile || context.options.replayFile || assessment.requests.length > 0);
  const parameterized = testModel.nodes.filter((n) => n.parameters.length || n.forms || n.hasPostForm);
  const highValue = testModel.nodes.filter((n) => n.riskWeight >= 8);

  const gates: PhaseGate[] = [
    { phase: "authorization", status: status(context.options.authorized && Boolean(context.options.client || context.options.assessmentId), context.options.authorized), reason: context.options.authorized ? "Authorization flag supplied; client/assessment metadata improves auditability." : "No authorization metadata supplied.", weight: 14 },
    { phase: "reconnaissance", status: status(assessment.coverageVector.requestCount >= 3, assessment.coverageVector.requestCount > 0), reason: `${assessment.coverageVector.requestCount} request observation(s) collected.`, weight: 12 },
    { phase: "mapping", status: status(testModel.nodes.length >= context.options.minPages && assessment.coverageVector.routeCount >= 3, testModel.nodes.length > 0), reason: `${testModel.nodes.length} surface node(s), ${assessment.coverageVector.routeCount} route key(s).`, weight: 18 },
    { phase: "vulnerability-analysis", status: status(parameterized.length > 0 && testModel.controlMatrix.some((c) => c.control === "input-validation" && c.status !== "not-tested"), parameterized.length > 0 || highValue.length > 0), reason: `${parameterized.length} input/workflow sink(s), ${highValue.length} high-value node(s).`, weight: 18 },
    { phase: "safe-validation", status: status(context.options.mode === "validate" && context.options.authorized && (authSupplied || parameterized.length > 0), context.options.mode === "validate" || context.options.authorized), reason: `mode=${context.options.mode}, authorized=${context.options.authorized}, authHeader=${authSupplied}.`, weight: 16 },
    { phase: "evidence", status: status(hasReportEvidence && assessment.requests.length > 0, hasReportEvidence), reason: `${assessment.requests.length} modelled request(s); jsonl=${Boolean(context.options.jsonlLog)}, har=${Boolean(context.options.harFile)}, replay=${Boolean(context.options.replayFile)}.`, weight: 14 },
    { phase: "reporting", status: status(context.options.formats.includes("json") && (context.options.formats.includes("markdown") || context.options.formats.includes("html") || context.options.formats.includes("sarif")), context.options.formats.length > 0), reason: `formats=${context.options.formats.join(",")}.`, weight: 8 },
  ];

  const sinkInventory = parameterized.slice(0, 50).map((node) => {
    const type = sinkType(node, node.parameters);
    return {
      route: node.route,
      url: node.url,
      method: node.method,
      sinkType: type,
      parameters: node.parameters,
      forms: node.forms,
      confidence: node.riskWeight >= 8 ? "strong" : node.parameters.length || node.forms ? "moderate" : "low",
      safeTests: safeTestsFor(type),
    } satisfies SinkModel;
  });

  const score = phaseScore(gates);
  const blockers = gates.filter((g) => g.status === "missing" && g.weight >= 14).map((g) => `${g.phase}: ${g.reason}`);
  const minimumImpact = score >= 80 && sinkInventory.length >= 3 ? "high" : score >= 55 && (sinkInventory.length >= 1 || testModel.nodes.length >= 3) ? "medium" : "low";
  const recommendedNextSafeTests = [
    !authSupplied ? "Add an approved test-session cookie/header so access-control differentials are meaningful." : "Run anonymous-vs-authenticated differential checks on high-value routes.",
    context.options.mode !== "validate" ? "Use authorized validate mode for inert canary and response-delta validation." : "Keep validate mode bounded to inert canaries and non-state-changing probes unless a lab workflow is approved.",
    assessment.coverageVector.scriptCount === 0 ? "Seed known dashboard/API routes or enable deep crawl to improve SPA route discovery." : "Review mined client-side route hints and manually verify high-value workflows.",
    !context.options.harFile || !context.options.replayFile ? "Export HAR/replay evidence for reproducibility." : "Use HAR/replay evidence to manually reproduce every escalated finding.",
  ];

  return { phaseGates: gates, sinkInventory, minimumImpact, modelScore: score, blockers, recommendedNextSafeTests };
}
