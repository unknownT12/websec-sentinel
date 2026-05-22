import type { ScanContext } from "../types.js";
import { buildAssessmentModel } from "./model.js";
import { buildBookScopeModel } from "./bookscope.js";
import { buildProfessionalModel } from "./professionalmodel.js";
import { buildTestModel, type SurfaceNode } from "./testmodel.js";

export type ProductPillar =
  | "engagement-safety"
  | "reconnaissance-depth"
  | "surface-modelling"
  | "authentication-coverage"
  | "session-review"
  | "access-control-review"
  | "input-validation-review"
  | "workflow-integrity"
  | "api-client-review"
  | "evidence-repeatability"
  | "false-positive-control"
  | "operator-productization"
  | "regression-readiness";

export type ProductStage = "prototype" | "usable-assessment-assistant" | "medium-impact-product" | "professional-product-core" | "exceptional-controlled-product";
export type GateStatus = "pass" | "warn" | "fail";

export interface ProductGate {
  id: string;
  pillar: ProductPillar;
  title: string;
  status: GateStatus;
  score: number;
  weight: number;
  evidence: string[];
  productRequirement: string;
  remediation: string;
  bookScopeBasis: string[];
}

export interface ProductTestVector {
  id: string;
  pillar: ProductPillar;
  route: string;
  method: string;
  title: string;
  intent: string;
  priority: "critical" | "high" | "medium" | "low";
  canRunNow: boolean;
  blockers: string[];
  safeSteps: string[];
  evidenceContract: string[];
  promotionRule: string;
}

export interface ProductEngineModel {
  score: number;
  stage: ProductStage;
  gates: ProductGate[];
  testVectors: ProductTestVector[];
  strengths: string[];
  blockers: string[];
  engineeringDebt: string[];
  mediumImpactReady: boolean;
  exceptionalReady: boolean;
  modelEvidence: {
    requestCount: number;
    routeCount: number;
    pageCount: number;
    formCount: number;
    parameterizedSurfaces: number;
    highValueSurfaces: number;
    authSupplied: boolean;
    evidenceExports: string[];
    selfTestAvailable: boolean;
  };
}

const BOOK_SCOPE = {
  lifecycle: ["Penetration Testing: A Hands-On Introduction", "The Basics of Hacking and Penetration Testing"],
  webapp: ["The Web Application Hacker's Handbook"],
  operator: ["The Hacker Playbook 2/3", "RTFM"],
  engineering: ["Black Hat Python", "Hacking: The Art of Exploitation"],
  evidence: ["Practical Malware Analysis", "RTFM"],
};

function hasAuth(context: ScanContext): boolean {
  return Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

function pct(condition: boolean, partial: boolean, pass = 100, warn = 55): number {
  return condition ? pass : partial ? warn : 0;
}

function gate(input: Omit<ProductGate, "status">): ProductGate {
  const status: GateStatus = input.score >= 80 ? "pass" : input.score >= 45 ? "warn" : "fail";
  return { ...input, status };
}

function nodeIsHighValue(node: SurfaceNode): boolean {
  return node.riskWeight >= 8 || node.classes.some((c) => ["admin", "student-data", "authorization", "account-recovery", "api"].includes(c));
}

function buildGates(context: ScanContext): ProductGate[] {
  const assessment = buildAssessmentModel(context);
  const testModel = buildTestModel(context);
  const bookScope = buildBookScopeModel(context);
  const professional = buildProfessionalModel(context);
  const auth = hasAuth(context);
  const evidenceExports = [context.options.jsonlLog ? "jsonl" : "", context.options.harFile ? "har" : "", context.options.replayFile ? "replay" : ""].filter(Boolean);
  const highValue = testModel.nodes.filter(nodeIsHighValue);
  const parameterized = testModel.nodes.filter((n) => n.parameters.length || n.forms > 0);
  const stateful = testModel.nodes.filter((n) => n.hasPostForm || n.classes.includes("state-changing"));
  const clientSideSignals = context.pages.reduce((s, p) => s + p.scripts.length + p.routeHints.length, 0);
  const soft404 = assessment.soft404Signals.length;
  const duplicateHeavy = assessment.duplicateRouteGroups.filter((g) => g.count >= 4).length;
  const hasRegressionHarness = true;

  return [
    gate({
      id: "product.engagement.scope-control",
      pillar: "engagement-safety",
      title: "Signed-scope execution model",
      score: pct(context.options.authorized && Boolean(context.options.client || context.options.assessmentId) && context.options.scope.length > 0 && context.options.prohibitedPaths.length > 0, context.options.authorized),
      weight: 11,
      evidence: [`authorized=${context.options.authorized}`, `metadata=${Boolean(context.options.client || context.options.assessmentId)}`, `scope=${context.options.scope.join(",")}`, `prohibitedPaths=${context.options.prohibitedPaths.length}`],
      productRequirement: "Professional assessments must be bounded by explicit authorization, target scope, and no-touch paths before any validation logic runs.",
      remediation: "Use --authorized, client/assessment metadata, --scope, and --prohibited-paths for every non-passive run.",
      bookScopeBasis: BOOK_SCOPE.lifecycle,
    }),
    gate({
      id: "product.recon.request-ledger",
      pillar: "reconnaissance-depth",
      title: "Request-ledger driven reconnaissance",
      score: pct(assessment.requests.length >= 10 && assessment.uniqueRouteKeys.length >= 4, assessment.requests.length > 0),
      weight: 10,
      evidence: [`requests=${assessment.requests.length}`, `routeKeys=${assessment.uniqueRouteKeys.length}`, `status=${JSON.stringify(assessment.statusDistribution)}`],
      productRequirement: "The model must reason from observed requests, redirects, response families, and route keys rather than from report text.",
      remediation: "Increase seeds/depth or run authenticated so the ledger captures enough route diversity.",
      bookScopeBasis: [...BOOK_SCOPE.lifecycle, ...BOOK_SCOPE.operator],
    }),
    gate({
      id: "product.surface.graph",
      pillar: "surface-modelling",
      title: "Application surface graph depth",
      score: pct(testModel.nodes.length >= context.options.minPages && (parameterized.length > 0 || clientSideSignals > 0) && highValue.length > 0, testModel.nodes.length > 0),
      weight: 13,
      evidence: [`nodes=${testModel.nodes.length}`, `parameterized=${parameterized.length}`, `highValue=${highValue.length}`, `clientSignals=${clientSideSignals}`],
      productRequirement: "The engine must build route, form, parameter, script, and workflow nodes before making assurance claims.",
      remediation: "Use --deep-crawl, approved --seed routes, and authenticated sessions until the model contains forms, parameters, and high-value routes.",
      bookScopeBasis: BOOK_SCOPE.webapp,
    }),
    gate({
      id: "product.auth.state",
      pillar: "authentication-coverage",
      title: "Authenticated state separation",
      score: pct(auth && assessment.coverageVector.authenticatedSignals > 0, auth || assessment.coverageVector.loginWallSignals > 0),
      weight: 12,
      evidence: [`authSupplied=${auth}`, `authSignals=${assessment.coverageVector.authenticatedSignals}`, `loginWallRatio=${Math.round(assessment.loginWallRatio * 100)}%`],
      productRequirement: "Public, login-wall, forbidden, and authenticated-supplied traffic must be separated so shallow login-only scans cannot look mature.",
      remediation: "Use approved test-account cookies/headers and seed a dashboard or internal route.",
      bookScopeBasis: [...BOOK_SCOPE.webapp, ...BOOK_SCOPE.lifecycle],
    }),
    gate({
      id: "product.session.cookie-token",
      pillar: "session-review",
      title: "Session and token surface model",
      score: pct(auth || assessment.requests.some((r) => /set-cookie/i.test(JSON.stringify(r))), assessment.coverageVector.pageCount > 0),
      weight: 8,
      evidence: [`authSupplied=${auth}`, `pages=${assessment.coverageVector.pageCount}`, `credentialSinks=${bookScope.sinkInventory.filter((s) => s.sinkType === "credential").length}`],
      productRequirement: "Session-sensitive routes must be connected to cookie/token/caching checks, not treated as generic pages.",
      remediation: "Run through the login workflow with an approved test session and include cookie/cache checks in the selected controls.",
      bookScopeBasis: BOOK_SCOPE.webapp,
    }),
    gate({
      id: "product.access.differential",
      pillar: "access-control-review",
      title: "Differential access-control model",
      score: pct(auth && highValue.length > 0 && context.options.checks.includes("differential"), highValue.length > 0 || context.options.checks.includes("differential")),
      weight: 14,
      evidence: [`auth=${auth}`, `highValue=${highValue.length}`, `differentialCheck=${context.options.checks.includes("differential")}`],
      productRequirement: "High-value routes must be queued for anonymous-vs-authenticated and, where approved, role-vs-role comparison.",
      remediation: "Keep differential enabled, use approved sessions, and add role-labelled seeds when available.",
      bookScopeBasis: BOOK_SCOPE.webapp,
    }),
    gate({
      id: "product.input.safe-oracles",
      pillar: "input-validation-review",
      title: "Safe input-validation oracle",
      score: pct(context.options.mode === "validate" && parameterized.length > 0 && context.options.checks.some((c) => ["inputvalidation", "parammodel", "mutation"].includes(c)), parameterized.length > 0),
      weight: 12,
      evidence: [`mode=${context.options.mode}`, `parameterized=${parameterized.length}`, `inputChecks=${context.options.checks.filter((c) => ["inputvalidation", "parammodel", "mutation"].includes(c)).join(",")}`],
      productRequirement: "Input findings must be promoted by baseline-vs-mutated response evidence, not by parameter-name guessing alone.",
      remediation: "Use validate mode and keep parameter modelling plus inert canary validation enabled.",
      bookScopeBasis: [...BOOK_SCOPE.webapp, ...BOOK_SCOPE.engineering],
    }),
    gate({
      id: "product.workflow.fences",
      pillar: "workflow-integrity",
      title: "State-changing workflow fencing",
      score: pct(stateful.length > 0 && context.options.prohibitedPaths.length > 0, stateful.length > 0 || context.options.prohibitedPaths.length > 0),
      weight: 8,
      evidence: [`statefulNodes=${stateful.length}`, `prohibitedPaths=${context.options.prohibitedPaths.length}`],
      productRequirement: "State-changing actions must be inventoried and fenced so the product remains safe while still surfacing workflow risk.",
      remediation: "Provide prohibited paths and treat state-changing submissions as manual/lab-only unless explicit workflow approval exists.",
      bookScopeBasis: [...BOOK_SCOPE.webapp, ...BOOK_SCOPE.lifecycle],
    }),
    gate({
      id: "product.api.client",
      pillar: "api-client-review",
      title: "Modern API and client-side model",
      score: pct(testModel.controlMatrix.some((c) => c.control === "api" && c.status !== "not-tested") && testModel.controlMatrix.some((c) => c.control === "client-side" && c.status !== "not-tested"), clientSideSignals > 0 || assessment.requests.some((r) => r.isJson)),
      weight: 9,
      evidence: [`clientSignals=${clientSideSignals}`, `jsonRequests=${assessment.requests.filter((r) => r.isJson).length}`, `scriptsFetched=${context.diagnostics.fetchedScripts ?? 0}`],
      productRequirement: "A modern web scanner must model JavaScript-discovered routes and API/schema surfaces as first-class test targets.",
      remediation: "Enable --deep-crawl and seed API/dashboard routes where authorized.",
      bookScopeBasis: BOOK_SCOPE.webapp,
    }),
    gate({
      id: "product.evidence.repeatable",
      pillar: "evidence-repeatability",
      title: "Repeatable evidence contract",
      score: pct(evidenceExports.includes("jsonl") && evidenceExports.includes("har") && evidenceExports.includes("replay") && assessment.requests.length > 0, evidenceExports.length > 0 || assessment.requests.length > 0),
      weight: 12,
      evidence: [`exports=${evidenceExports.join(",") || "none"}`, `requests=${assessment.requests.length}`],
      productRequirement: "Every escalated claim should be replayable from redacted request evidence and request IDs.",
      remediation: "Use --jsonl-log, --har, and --replay-file on professional runs.",
      bookScopeBasis: [...BOOK_SCOPE.evidence, ...BOOK_SCOPE.operator],
    }),
    gate({
      id: "product.falsepositive.controls",
      pillar: "false-positive-control",
      title: "False-positive control model",
      score: pct(soft404 === 0 && duplicateHeavy <= 1 && assessment.requests.length > 0, assessment.requests.length > 0),
      weight: 9,
      evidence: [`soft404Signals=${soft404}`, `duplicateHeavyGroups=${duplicateHeavy}`, `responseFamilies=${new Set(assessment.requests.map((r) => r.responseFamily)).size}`],
      productRequirement: "The engine must detect fallback pages, duplicate families, and weak evidence before promoting severity.",
      remediation: "Tune seeds, improve route normalization, and manually review repeated response families before accepting findings.",
      bookScopeBasis: [...BOOK_SCOPE.webapp, ...BOOK_SCOPE.evidence],
    }),
    gate({
      id: "product.operator.productization",
      pillar: "operator-productization",
      title: "Operator-ready product flow",
      score: pct(context.options.save && context.options.formats.includes("json") && (context.options.formats.includes("sarif") || context.options.formats.includes("markdown") || context.options.formats.includes("html")), context.options.formats.length > 0),
      weight: 6,
      evidence: [`save=${context.options.save}`, `formats=${context.options.formats.join(",")}`],
      productRequirement: "A product run must produce machine-readable output and human review artifacts for handoff.",
      remediation: "Save JSON plus SARIF/Markdown/HTML depending on the audience.",
      bookScopeBasis: BOOK_SCOPE.operator,
    }),
    gate({
      id: "product.regression.selftest",
      pillar: "regression-readiness",
      title: "Regression fixture and self-test availability",
      score: hasRegressionHarness ? 100 : 0,
      weight: 8,
      evidence: ["tools/selftest-server.mjs", "tools/run-selftest.mjs", "npm run selftest"],
      productRequirement: "The product must ship with a deterministic fixture so engine changes can be tested against known routes, forms, parameters, and APIs.",
      remediation: "Keep expanding fixtures whenever a new model check is added.",
      bookScopeBasis: [...BOOK_SCOPE.lifecycle, ...BOOK_SCOPE.operator],
    }),
    gate({
      id: "product.professional.maturity",
      pillar: "operator-productization",
      title: "Professional model convergence",
      score: Math.round((professional.productScore * 0.65) + (bookScope.modelScore * 0.35)),
      weight: 12,
      evidence: [`professionalScore=${professional.productScore}`, `professionalTier=${professional.productTier}`, `bookScopeScore=${bookScope.modelScore}`, `minimumImpact=${bookScope.minimumImpact}`],
      productRequirement: "The professional control model and book-scoped lifecycle model must agree that the run has moved beyond prototype depth.",
      remediation: "Close professional-model blockers and lifecycle gaps before calling the run product-grade.",
      bookScopeBasis: [...BOOK_SCOPE.lifecycle, ...BOOK_SCOPE.webapp, ...BOOK_SCOPE.operator],
    }),
  ];
}

function weightedScore(gates: ProductGate[]): number {
  const max = gates.reduce((s, g) => s + g.weight, 0);
  const actual = gates.reduce((s, g) => s + g.weight * (g.score / 100), 0);
  return Math.round((actual / Math.max(1, max)) * 100);
}

function stageFor(score: number, gates: ProductGate[]): ProductStage {
  const failedHeavy = gates.filter((g) => g.status === "fail" && g.weight >= 10).length;
  if (score >= 90 && failedHeavy === 0) return "exceptional-controlled-product";
  if (score >= 80 && failedHeavy === 0) return "professional-product-core";
  if (score >= 68 && failedHeavy <= 1) return "medium-impact-product";
  if (score >= 50) return "usable-assessment-assistant";
  return "prototype";
}

function testVectorsForNode(node: SurfaceNode, auth: boolean): ProductTestVector[] {
  const baseBlockers = [auth ? "" : "approved authenticated session not supplied"].filter(Boolean);
  const vectors: ProductTestVector[] = [];
  if (nodeIsHighValue(node)) {
    vectors.push({
      id: `pv-access-${node.id}`,
      pillar: "access-control-review",
      route: node.route,
      method: node.method,
      title: `Access boundary vector for ${node.route}`,
      intent: "Confirm whether protected route families behave differently across anonymous and approved authenticated states without extracting records.",
      priority: node.classes.includes("admin") || node.classes.includes("student-data") ? "high" : "medium",
      canRunNow: auth,
      blockers: baseBlockers,
      safeSteps: ["Capture anonymous baseline", "Capture approved authenticated observation", "Compare status, redirect chain, cache headers, and response family", "Escalate only with operator-confirmed authorization expectation"],
      evidenceContract: ["anonymous request id", "authenticated request id", "response family delta", "route class", "operator expectation note"],
      promotionRule: "Promote from hypothesis to finding only when unauthorized state reaches a protected content/API family or bypasses expected redirect/403 behavior.",
    });
  }
  if (node.parameters.length) {
    vectors.push({
      id: `pv-param-${node.id}`,
      pillar: "input-validation-review",
      route: node.route,
      method: node.method,
      title: `Parameter oracle vector for ${node.route}`,
      intent: "Use inert one-at-a-time mutation to detect response-family, redirect, reflection, or verbose-error changes.",
      priority: node.classes.includes("authorization") ? "high" : "medium",
      canRunNow: true,
      blockers: [],
      safeSteps: ["Record baseline", "Mutate one parameter with inert sentinel", "Compare response family/status/redirect/reflection context", "Do not enumerate identifiers or extract records"],
      evidenceContract: ["parameter", "baseline request id", "mutated request id", "response delta", "redacted snippet"],
      promotionRule: "Promote only when the mutated response proves unsafe behavior; otherwise keep as a signal/test vector.",
    });
  }
  if (node.hasPostForm) {
    vectors.push({
      id: `pv-workflow-${node.id}`,
      pillar: "workflow-integrity",
      route: node.route,
      method: node.method,
      title: `State-change fence vector for ${node.route}`,
      intent: "Inventory state-changing workflow controls without performing destructive actions.",
      priority: "medium",
      canRunNow: true,
      blockers: [],
      safeSteps: ["Inventory method/action/input names", "Check CSRF-token signal", "Check SameSite/session-cookie context", "Do not submit destructive workflow unless explicit lab approval exists"],
      evidenceContract: ["form action", "method", "CSRF signal", "cookie context", "prohibited-path decision"],
      promotionRule: "Promote only after approved server-side acceptance testing or strong missing-control evidence on a state-changing route.",
    });
  }
  return vectors;
}

export function buildProductEngineModel(context: ScanContext): ProductEngineModel {
  const assessment = buildAssessmentModel(context);
  const testModel = buildTestModel(context);
  const gates = buildGates(context);
  const score = weightedScore(gates);
  const stage = stageFor(score, gates);
  const auth = hasAuth(context);
  const testVectors = testModel.nodes.flatMap((n) => testVectorsForNode(n, auth)).slice(0, 80);
  const failed = gates.filter((g) => g.status === "fail");
  const warned = gates.filter((g) => g.status === "warn");
  const evidenceExports = [context.options.jsonlLog ? "jsonl" : "", context.options.harFile ? "har" : "", context.options.replayFile ? "replay" : ""].filter(Boolean);
  const highValue = testModel.nodes.filter(nodeIsHighValue);
  const parameterized = testModel.nodes.filter((n) => n.parameters.length || n.forms > 0);
  const strengths = gates.filter((g) => g.status === "pass").slice(0, 6).map((g) => `${g.title}: ${g.evidence.join("; ")}`);
  const blockers = failed.map((g) => `${g.pillar}: ${g.title} (${g.evidence.join("; ")})`);
  const engineeringDebt = [
    ...warned.map((g) => `${g.pillar}: ${g.title} needs hardening — ${g.remediation}`),
    testVectors.length < 3 ? "Expand seeded/authenticated coverage so the engine can generate at least three concrete test vectors." : "",
    evidenceExports.length < 3 ? "Use all three evidence exports (JSONL, HAR, replay) for professional-grade reproducibility." : "",
  ].filter(Boolean);
  const mediumImpactReady = score >= 68 && failed.filter((g) => g.weight >= 12).length <= 1;
  const exceptionalReady = score >= 90 && failed.length === 0 && evidenceExports.length === 3 && auth && highValue.length > 0 && parameterized.length > 0;

  return {
    score,
    stage,
    gates,
    testVectors,
    strengths,
    blockers,
    engineeringDebt,
    mediumImpactReady,
    exceptionalReady,
    modelEvidence: {
      requestCount: assessment.requests.length,
      routeCount: assessment.uniqueRouteKeys.length,
      pageCount: assessment.coverageVector.pageCount,
      formCount: assessment.coverageVector.formCount,
      parameterizedSurfaces: parameterized.length,
      highValueSurfaces: highValue.length,
      authSupplied: auth,
      evidenceExports,
      selfTestAvailable: true,
    },
  };
}
