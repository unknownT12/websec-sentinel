import type { ScanContext } from "../types.js";
import { buildAssessmentModel, type AssessmentModel } from "./model.js";
import { buildBookScopeModel } from "./bookscope.js";
import { buildTestModel, type SurfaceNode } from "./testmodel.js";

export type ControlStatus = "verified" | "observable" | "planned" | "not-covered";
export type ConfirmationLevel = "confirmed" | "probable" | "signal" | "hypothesis" | "not-observed";
export type ProfessionalDomain =
  | "scoping"
  | "reconnaissance"
  | "application-mapping"
  | "authentication"
  | "session-management"
  | "access-control"
  | "input-handling"
  | "workflow-integrity"
  | "api-review"
  | "client-side-review"
  | "privacy-cache"
  | "error-handling"
  | "evidence-repeatability";

export interface ControlObjective {
  id: string;
  domain: ProfessionalDomain;
  objective: string;
  requiredEvidence: string[];
  status: ControlStatus;
  confirmation: ConfirmationLevel;
  reason: string;
  weight: number;
}

export interface TestCase {
  id: string;
  domain: ProfessionalDomain;
  route: string;
  method: string;
  title: string;
  priority: "critical" | "high" | "medium" | "low";
  preconditions: string[];
  safeProcedure: string[];
  confirmationGate: string;
  evidenceToCapture: string[];
  destructive: false;
}

export interface MaturityGate {
  name: string;
  status: "pass" | "warn" | "fail";
  reason: string;
  remediation: string;
}

export interface ProfessionalModel {
  assessment: AssessmentModel;
  controls: ControlObjective[];
  testCases: TestCase[];
  gates: MaturityGate[];
  productScore: number;
  productTier: "prototype" | "assessment-assistant" | "medium-impact-product" | "professional-ready-core";
  blockers: string[];
  modelEvidence: {
    nodeCount: number;
    requestCount: number;
    routeCount: number;
    parameterizedSurfaces: number;
    stateChangingForms: number;
    authSupplied: boolean;
    repeatableEvidence: boolean;
  };
}

const WEB_APP_SOURCES = [
  "The Web Application Hacker's Handbook: mapped to workflow, parameter, session, access-control, and evidence-first web testing discipline.",
  "Penetration Testing: A Hands-On Introduction to Hacking: mapped to authorization, reconnaissance, vulnerability analysis, validation, and reporting gates.",
  "The Basics of Hacking and Penetration Testing: mapped to beginner-to-repeatable assessment lifecycle checks and documentation discipline.",
  "The Hacker Playbook 2/3 and RTFM: mapped to operator workflow, concise repeatability, and evidence handoff boundaries.",
  "Practical Malware Analysis: mapped only to evidence hygiene, artefact handling, and redaction discipline.",
  "Black Hat Python and Hacking: The Art of Exploitation: mapped only to defensive engineering, input modelling, and controlled lab validation thinking.",
];

function hasAuth(context: ScanContext): boolean {
  return Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

function statusFrom(condition: boolean, partial: boolean): ControlStatus {
  if (condition) return "verified";
  if (partial) return "observable";
  return "not-covered";
}

function confirmationFrom(status: ControlStatus): ConfirmationLevel {
  if (status === "verified") return "confirmed";
  if (status === "observable") return "signal";
  if (status === "planned") return "hypothesis";
  return "not-observed";
}

function control(input: Omit<ControlObjective, "confirmation">): ControlObjective {
  return { ...input, confirmation: confirmationFrom(input.status) };
}

function buildControls(context: ScanContext, assessment: AssessmentModel, nodes: SurfaceNode[]): ControlObjective[] {
  const auth = hasAuth(context);
  const forms = context.pages.flatMap((p) => p.forms);
  const postForms = forms.filter((f) => /post|put|patch|delete/i.test(f.method));
  const csrfPost = postForms.filter((f) => f.hasCsrfToken);
  const parameterized = nodes.filter((n) => n.parameters.length || n.forms > 0);
  const highValue = nodes.filter((n) => n.riskWeight >= 8);
  const apiNodes = nodes.filter((n) => n.classes.includes("api"));
  const scripts = context.pages.reduce((s, p) => s + p.scripts.length, 0);
  const hasEvidenceExport = Boolean(context.options.jsonlLog || context.options.harFile || context.options.replayFile);
  const hasErrors = assessment.requests.some((r) => r.status >= 500);
  const cacheRelevant = nodes.some((n) => n.classes.includes("authentication") || n.classes.includes("student-data") || n.classes.includes("admin"));

  return [
    control({
      id: "pm.scope.authorization",
      domain: "scoping",
      objective: "Every higher-impact test must be tied to explicit authorization metadata and scope.",
      requiredEvidence: ["--authorized", "client or assessment id", "approved host scope"],
      status: statusFrom(context.options.authorized && Boolean(context.options.client || context.options.assessmentId) && context.options.scope.length > 0, context.options.authorized),
      reason: `authorized=${context.options.authorized}; client=${Boolean(context.options.client)}; assessmentId=${Boolean(context.options.assessmentId)}; scope=${context.options.scope.join(",")}`,
      weight: 12,
    }),
    control({
      id: "pm.recon.request-ledger",
      domain: "reconnaissance",
      objective: "The engine must maintain a request ledger, not just final report text.",
      requiredEvidence: ["request ids", "status distribution", "response families", "route keys"],
      status: statusFrom(assessment.requests.length >= 5, assessment.requests.length > 0),
      reason: `${assessment.requests.length} request(s), ${assessment.uniqueRouteKeys.length} route key(s), status=${JSON.stringify(assessment.statusDistribution)}`,
      weight: 10,
    }),
    control({
      id: "pm.mapping.surface-graph",
      domain: "application-mapping",
      objective: "The engine must model routes, forms, parameters, scripts, and high-value workflows before judging risk.",
      requiredEvidence: ["surface nodes", "forms", "parameters", "route classes", "scripts"],
      status: statusFrom(nodes.length >= context.options.minPages && assessment.uniqueRouteKeys.length >= 3 && (forms.length > 0 || assessment.parameterGroups.length > 0 || scripts > 0), nodes.length > 0),
      reason: `${nodes.length} node(s), ${forms.length} form(s), ${assessment.parameterGroups.length} parameter group(s), ${scripts} script(s)` ,
      weight: 14,
    }),
    control({
      id: "pm.auth.authenticated-state",
      domain: "authentication",
      objective: "Authenticated coverage must be modelled separately from public/login-only coverage.",
      requiredEvidence: ["auth/session header supplied", "authenticated route observations", "login-wall ratio"],
      status: statusFrom(auth && assessment.coverageVector.authenticatedSignals > 0, auth),
      reason: `authHeader=${auth}; authSignals=${assessment.coverageVector.authenticatedSignals}; loginWallRatio=${Math.round(assessment.loginWallRatio * 100)}%`,
      weight: 13,
    }),
    control({
      id: "pm.session.cookies",
      domain: "session-management",
      objective: "Session-sensitive surfaces must be checked for cookie and token handling signals.",
      requiredEvidence: ["Set-Cookie observations", "SameSite/Secure/HttpOnly review", "token-in-url absence"],
      status: statusFrom(assessment.requests.some((r) => /set-cookie/i.test(JSON.stringify(r))) || auth, context.pages.length > 0),
      reason: `authHeader=${auth}; pages=${context.pages.length}; tokenSensitiveParameters=${assessment.parameterGroups.filter((g) => /token|session|auth|password/i.test(g.parameters.join(" "))).length}`,
      weight: 10,
    }),
    control({
      id: "pm.access.high-value-differential",
      domain: "access-control",
      objective: "High-value routes must be tested using differential access thinking, not only discovered.",
      requiredEvidence: ["anonymous baseline", "authenticated observation", "response-family comparison", "role boundary notes"],
      status: statusFrom(auth && highValue.length > 0 && assessment.requests.length >= 4, highValue.length > 0 || auth),
      reason: `${highValue.length} high-value node(s); auth=${auth}; requests=${assessment.requests.length}`,
      weight: 16,
    }),
    control({
      id: "pm.input.parameter-model",
      domain: "input-handling",
      objective: "Parameterised inputs must be inventoried before safe validation is attempted.",
      requiredEvidence: ["parameter classes", "baseline response", "mutated response", "response delta"],
      status: statusFrom(parameterized.length > 0 && context.options.mode === "validate", parameterized.length > 0),
      reason: `${parameterized.length} parameterized/form surface(s); mode=${context.options.mode}`,
      weight: 13,
    }),
    control({
      id: "pm.workflow.state-change",
      domain: "workflow-integrity",
      objective: "State-changing workflows must be identified and fenced before any validation.",
      requiredEvidence: ["POST/PUT/PATCH/DELETE form inventory", "CSRF token signal", "prohibited path list"],
      status: statusFrom(postForms.length > 0 && context.options.prohibitedPaths.length > 0 && csrfPost.length >= Math.max(1, postForms.length), postForms.length > 0 || context.options.prohibitedPaths.length > 0),
      reason: `${postForms.length} state-changing form(s); csrfSignals=${csrfPost.length}; prohibitedPaths=${context.options.prohibitedPaths.length}`,
      weight: 11,
    }),
    control({
      id: "pm.api.schema-and-json",
      domain: "api-review",
      objective: "API-like routes and JSON responses must be separated from HTML page checks.",
      requiredEvidence: ["API route class", "JSON response observation", "schema exposure check"],
      status: statusFrom(apiNodes.length > 0 || assessment.requests.some((r) => r.isJson), assessment.uniqueRouteKeys.some((r) => /api|graphql|swagger|openapi/i.test(r))),
      reason: `${apiNodes.length} API node(s); jsonRequests=${assessment.requests.filter((r) => r.isJson).length}`,
      weight: 8,
    }),
    control({
      id: "pm.client.spa-routes",
      domain: "client-side-review",
      objective: "Modern apps require script/SPA route mining and client-side sink review.",
      requiredEvidence: ["scripts", "script-mined routes", "DOM sink signals"],
      status: statusFrom(scripts > 0 && (context.diagnostics.discoveredScriptRoutes ?? 0) > 0, scripts > 0 || context.options.deepCrawl),
      reason: `scripts=${scripts}; deepCrawl=${context.options.deepCrawl}; scriptRoutes=${context.diagnostics.discoveredScriptRoutes ?? 0}`,
      weight: 9,
    }),
    control({
      id: "pm.privacy.cache",
      domain: "privacy-cache",
      objective: "Authenticated or student-data pages must be reviewed for privacy-preserving cache behaviour.",
      requiredEvidence: ["cache-control headers", "high-value route class", "authenticated context"],
      status: statusFrom(cacheRelevant && assessment.requests.some((r) => /no-store|private|no-cache/i.test(JSON.stringify(r))), cacheRelevant),
      reason: `cacheRelevant=${cacheRelevant}; highValue=${highValue.length}`,
      weight: 7,
    }),
    control({
      id: "pm.errors.response-family",
      domain: "error-handling",
      objective: "Unexpected server errors and generic response families must be tracked to control false positives.",
      requiredEvidence: ["5xx observations", "soft-404 families", "duplicate response families"],
      status: statusFrom(!hasErrors && assessment.soft404Signals.length === 0 && assessment.requests.length > 0, assessment.requests.length > 0),
      reason: `serverErrors=${assessment.requests.filter((r) => r.status >= 500).length}; soft404Signals=${assessment.soft404Signals.length}`,
      weight: 6,
    }),
    control({
      id: "pm.evidence.replayability",
      domain: "evidence-repeatability",
      objective: "Any product-grade finding must be reproducible from redacted evidence.",
      requiredEvidence: ["JSONL/HAR/replay file", "request id", "redaction policy"],
      status: statusFrom(hasEvidenceExport && assessment.requests.length > 0, assessment.requests.length > 0),
      reason: `jsonl=${Boolean(context.options.jsonlLog)}; har=${Boolean(context.options.harFile)}; replay=${Boolean(context.options.replayFile)}; requests=${assessment.requests.length}`,
      weight: 12,
    }),
  ];
}

function testCasesForNode(node: SurfaceNode, auth: boolean): TestCase[] {
  const basePreconditions = ["Signed authorization", "Target route is in scope", "Use non-destructive/inert canaries only", "Capture request id and redacted replay evidence"];
  const out: TestCase[] = [];
  if (node.classes.includes("authorization") || node.classes.includes("student-data") || node.classes.includes("admin")) {
    out.push({
      id: `tc-access-${node.id}`,
      domain: "access-control",
      route: node.route,
      method: node.method,
      title: `Differential access review for ${node.route}`,
      priority: node.classes.includes("admin") || node.classes.includes("student-data") ? "high" : "medium",
      preconditions: [...basePreconditions, auth ? "Authenticated test session supplied" : "Authenticated test session required before execution"],
      safeProcedure: ["Request route anonymously", "Request route with approved test session", "Compare status, redirect chain, response family, and high-level content class", "Do not extract records or enumerate identifiers"],
      confirmationGate: "Escalate only if protected content family or privileged API response is reachable from an unauthorized or lower-privilege control.",
      evidenceToCapture: ["anonymous request id", "authenticated request id", "response family delta", "route class", "operator note on expected access"],
      destructive: false,
    });
  }
  if (node.parameters.length) {
    out.push({
      id: `tc-input-${node.id}`,
      domain: "input-handling",
      route: node.route,
      method: node.method,
      title: `Safe parameter validation model for ${node.route}`,
      priority: node.classes.includes("authorization") ? "high" : "medium",
      preconditions: basePreconditions,
      safeProcedure: ["Capture baseline request", "Mutate one parameter with inert sentinel value", "Compare status, reflection context, redirect target, and response family", "Stop if state change or sensitive data exposure is possible"],
      confirmationGate: "Escalate only when baseline-vs-mutated evidence proves unsafe reflection, unsafe redirect, verbose server error, or unexpected access change.",
      evidenceToCapture: ["parameter name", "baseline request id", "mutated request id", "response delta", "redacted snippet"],
      destructive: false,
    });
  }
  if (node.hasPostForm) {
    out.push({
      id: `tc-state-${node.id}`,
      domain: "workflow-integrity",
      route: node.route,
      method: node.method,
      title: `State-changing workflow fence review for ${node.route}`,
      priority: "medium",
      preconditions: [...basePreconditions, "Only execute against lab or explicitly approved non-production workflow"],
      safeProcedure: ["Inventory method/action and input names", "Check CSRF token presence signal", "Confirm route is not prohibited", "Do not submit destructive actions unless explicit lab approval exists"],
      confirmationGate: "Do not claim CSRF or workflow weakness without an approved safe server-side acceptance test.",
      evidenceToCapture: ["form action", "method", "CSRF signal", "SameSite cookie context", "prohibited-path decision"],
      destructive: false,
    });
  }
  return out;
}

function scoreControls(controls: ControlObjective[]): number {
  const max = controls.reduce((s, c) => s + c.weight, 0);
  const actual = controls.reduce((s, c) => {
    const factor = c.status === "verified" ? 1 : c.status === "observable" ? 0.55 : c.status === "planned" ? 0.25 : 0;
    return s + c.weight * factor;
  }, 0);
  return Math.round((actual / Math.max(1, max)) * 100);
}

function buildGates(context: ScanContext, controls: ControlObjective[], testCases: TestCase[], score: number): MaturityGate[] {
  const missingHeavy = controls.filter((c) => c.status === "not-covered" && c.weight >= 10);
  const authMissing = controls.some((c) => c.id === "pm.auth.authenticated-state" && c.status !== "verified");
  const mappingWeak = controls.some((c) => c.id === "pm.mapping.surface-graph" && c.status === "not-covered");
  const evidenceWeak = controls.some((c) => c.id === "pm.evidence.replayability" && c.status !== "verified");
  return [
    {
      name: "Book-scoped lifecycle completeness",
      status: score >= 70 ? "pass" : score >= 50 ? "warn" : "fail",
      reason: `Professional model score ${score}/100; ${missingHeavy.length} heavy control(s) missing.`,
      remediation: "Close missing heavy controls before calling the assessment product-grade.",
    },
    {
      name: "Authenticated product coverage",
      status: !context.options.requireAuth ? "warn" : authMissing ? "fail" : "pass",
      reason: context.options.requireAuth ? (authMissing ? "--require-auth was set but authenticated state is not verified." : "Authenticated state is verified.") : "--require-auth was not set; product assurance remains limited for portals.",
      remediation: "Use approved test accounts/session headers and seed authenticated dashboards where authorized.",
    },
    {
      name: "Surface model depth",
      status: mappingWeak ? "fail" : testCases.length >= 3 ? "pass" : "warn",
      reason: `${testCases.length} executable safe test case(s) generated from observed surface.`,
      remediation: "Add seeds, enable deep crawl, or run after login so routes, forms, and parameters exist in the model.",
    },
    {
      name: "Evidence repeatability",
      status: evidenceWeak ? "warn" : "pass",
      reason: evidenceWeak ? "Request observations exist but HAR/JSONL/replay evidence was not fully exported." : "Repeatable evidence export is configured.",
      remediation: "Use --jsonl-log, --har, and --replay-file for product-grade assessment runs.",
    },
  ];
}

export function buildProfessionalModel(context: ScanContext): ProfessionalModel {
  const assessment = buildAssessmentModel(context);
  const testModel = buildTestModel(context);
  const bookScope = buildBookScopeModel(context);
  const controls = buildControls(context, assessment, testModel.nodes);
  const auth = hasAuth(context);
  const testCases = testModel.nodes.flatMap((n) => testCasesForNode(n, auth)).slice(0, 60);
  const productScore = Math.max(0, Math.min(100, Math.round((scoreControls(controls) * 0.72) + (testModel.readinessScore * 0.14) + (bookScope.modelScore * 0.14))));
  const gates = buildGates(context, controls, testCases, productScore);
  const blockers = [
    ...controls.filter((c) => c.status === "not-covered" && c.weight >= 10).map((c) => `${c.domain}: ${c.objective} (${c.reason})`),
    ...gates.filter((g) => g.status === "fail").map((g) => `${g.name}: ${g.reason}`),
  ];
  const productTier = productScore >= 85 && gates.every((g) => g.status !== "fail")
    ? "professional-ready-core"
    : productScore >= 70 && gates.filter((g) => g.status === "fail").length === 0
      ? "medium-impact-product"
      : productScore >= 50
        ? "assessment-assistant"
        : "prototype";

  return {
    assessment,
    controls,
    testCases,
    gates,
    productScore,
    productTier,
    blockers,
    modelEvidence: {
      nodeCount: testModel.nodes.length,
      requestCount: assessment.requests.length,
      routeCount: assessment.uniqueRouteKeys.length,
      parameterizedSurfaces: testModel.nodes.filter((n) => n.parameters.length || n.forms > 0).length,
      stateChangingForms: context.pages.flatMap((p) => p.forms).filter((f) => /post|put|patch|delete/i.test(f.method)).length,
      authSupplied: auth,
      repeatableEvidence: Boolean(context.options.jsonlLog || context.options.harFile || context.options.replayFile),
    },
  };
}

export function professionalMethodologySources(): string[] {
  return WEB_APP_SOURCES;
}
