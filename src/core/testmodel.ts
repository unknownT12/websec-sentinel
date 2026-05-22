import { createHash } from "node:crypto";
import type { CrawlPage, PageForm, ScanContext } from "../types.js";
import { buildAssessmentModel, normalizeRoute, type AssessmentModel } from "./model.js";

export type SurfaceClass =
  | "authentication"
  | "authorization"
  | "account-recovery"
  | "admin"
  | "student-data"
  | "api"
  | "state-changing"
  | "file-transfer"
  | "search-filter"
  | "static"
  | "unknown";

export interface SurfaceNode {
  id: string;
  url: string;
  route: string;
  method: string;
  classes: SurfaceClass[];
  parameters: string[];
  forms: number;
  hasPostForm: boolean;
  hasPasswordInput: boolean;
  hasCsrfCoverage: boolean;
  evidenceBasis: string[];
  riskWeight: number;
}

export interface ControlExpectation {
  control: "transport" | "headers" | "cookies" | "auth" | "access-control" | "csrf" | "input-validation" | "cache" | "api" | "client-side" | "evidence";
  expectedOn: string;
  status: "tested" | "partially-tested" | "not-tested";
  reason: string;
}

export interface TestHypothesis {
  id: string;
  title: string;
  whyItMatters: string;
  safeValidation: string;
  evidenceNeeded: string[];
  confidenceGate: string;
  priority: "critical" | "high" | "medium" | "low";
  mappedSources: string[];
}

export interface TestModel {
  assessment: AssessmentModel;
  nodes: SurfaceNode[];
  controlMatrix: ControlExpectation[];
  hypotheses: TestHypothesis[];
  readinessScore: number;
  blockers: string[];
}

const CLASSIFIERS: Array<[SurfaceClass, RegExp]> = [
  ["authentication", /(login|signin|sign-in|logout|session|sso|oauth|auth)/i],
  ["account-recovery", /(forgot|reset|recover|change-password|password)/i],
  ["admin", /(admin|manage|staff|superuser|dashboard|settings|config)/i],
  ["student-data", /(student|grade|result|mark|course|class|enrol|profile|transcript|assessment)/i],
  ["api", /(\/api\/|graphql|swagger|openapi|json|ajax|rest)/i],
  ["file-transfer", /(upload|download|export|import|file|document|csv|pdf|attachment)/i],
  ["search-filter", /(search|query|filter|sort|page|q=|keyword|term)/i],
  ["authorization", /(id|uid|user|student|account|tenant|role|owner|profile)/i],
];
const STATE_CHANGING = /^(POST|PUT|PATCH|DELETE)$/i;
const STATIC_EXT = /\.(css|js|map|png|jpe?g|gif|svg|webp|ico|woff2?|pdf|zip)$/i;

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 10);
}

function formTraits(forms: PageForm[]): Pick<SurfaceNode, "hasPostForm" | "hasPasswordInput" | "hasCsrfCoverage"> {
  const hasPostForm = forms.some((f) => STATE_CHANGING.test(f.method));
  const hasPasswordInput = forms.some((f) => f.inputs.some((i) => /password/i.test(`${i.type} ${i.name}`)));
  const stateForms = forms.filter((f) => STATE_CHANGING.test(f.method));
  const hasCsrfCoverage = stateForms.length > 0 ? stateForms.every((f) => f.hasCsrfToken) : forms.some((f) => f.hasCsrfToken);
  return { hasPostForm, hasPasswordInput, hasCsrfCoverage };
}

function classify(url: string, route: string, method: string, forms: PageForm[], params: string[]): SurfaceClass[] {
  const text = `${url} ${route} ${method} ${params.join(" ")} ${forms.flatMap((f) => f.inputs.map((i) => `${i.name}:${i.type}`)).join(" ")}`;
  const classes = new Set<SurfaceClass>();
  for (const [name, re] of CLASSIFIERS) if (re.test(text)) classes.add(name);
  if (STATE_CHANGING.test(method) || forms.some((f) => STATE_CHANGING.test(f.method))) classes.add("state-changing");
  if (STATIC_EXT.test(new URL(url).pathname)) classes.add("static");
  if (!classes.size) classes.add("unknown");
  return [...classes];
}

function weight(classes: SurfaceClass[], params: string[], forms: PageForm[]): number {
  let score = 1;
  if (classes.includes("admin")) score += 6;
  if (classes.includes("student-data")) score += 6;
  if (classes.includes("authorization")) score += 5;
  if (classes.includes("api")) score += 4;
  if (classes.includes("account-recovery")) score += 4;
  if (classes.includes("state-changing")) score += 4;
  if (classes.includes("file-transfer")) score += 3;
  if (classes.includes("authentication")) score += 3;
  if (params.length) score += Math.min(4, params.length);
  if (forms.length) score += Math.min(4, forms.length * 2);
  if (classes.includes("static")) score = Math.max(1, score - 5);
  return score;
}

function buildNodes(context: ScanContext): SurfaceNode[] {
  const nodes: SurfaceNode[] = [];
  for (const page of context.pages) {
    const url = page.finalUrl || page.url;
    const u = new URL(url);
    const route = normalizeRoute(url);
    const params = [...u.searchParams.keys()].sort();
    const traits = formTraits(page.forms);
    const classes = classify(url, route, page.method, page.forms, params);
    const evidenceBasis = [
      `status=${page.status}`,
      `contentType=${page.contentType || page.headers["content-type"] || "unknown"}`,
      `forms=${page.forms.length}`,
      `links=${page.links.length}`,
      `routeHints=${page.routeHints.length}`,
    ];
    nodes.push({
      id: `node-${shortHash(`${page.method}:${route}:${params.join(",")}`)}`,
      url,
      route,
      method: page.method,
      classes,
      parameters: params,
      forms: page.forms.length,
      ...traits,
      evidenceBasis,
      riskWeight: weight(classes, params, page.forms),
    });
  }
  return nodes.sort((a, b) => b.riskWeight - a.riskWeight);
}

function controlStatus(condition: boolean, partial: boolean): "tested" | "partially-tested" | "not-tested" {
  if (condition) return "tested";
  if (partial) return "partially-tested";
  return "not-tested";
}

function buildControlMatrix(context: ScanContext, nodes: SurfaceNode[], assessment: AssessmentModel): ControlExpectation[] {
  const authSupplied = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
  const stateNodes = nodes.filter((n) => n.hasPostForm || n.classes.includes("state-changing"));
  const apiNodes = nodes.filter((n) => n.classes.includes("api"));
  const paramNodes = nodes.filter((n) => n.parameters.length);
  const highValue = nodes.filter((n) => n.riskWeight >= 7);
  return [
    { control: "transport", expectedOn: "all HTTPS entry points", status: "tested", reason: "TLS/HSTS/header modules are in the default control set." },
    { control: "headers", expectedOn: "all HTML and API responses", status: context.pages.length ? "tested" : "not-tested", reason: `${context.pages.length} page response(s) were modelled.` },
    { control: "cookies", expectedOn: "login and authenticated workflows", status: controlStatus(authSupplied, context.pages.some((p) => /set-cookie/i.test(Object.keys(p.headers).join(" ")))), reason: authSupplied ? "Caller supplied an authenticated/session header." : "No authenticated session header was supplied." },
    { control: "auth", expectedOn: "protected routes and workflow transitions", status: controlStatus(authSupplied && assessment.coverageVector.authenticatedSignals > 0, authSupplied || assessment.coverageVector.loginWallSignals > 0), reason: `authSignals=${assessment.coverageVector.authenticatedSignals}, loginWallSignals=${assessment.coverageVector.loginWallSignals}` },
    { control: "access-control", expectedOn: "admin, student-data, and identifier-based routes", status: controlStatus(authSupplied && highValue.length > 0, highValue.length > 0), reason: `${highValue.length} high-value surface node(s) were identified.` },
    { control: "csrf", expectedOn: "state-changing forms", status: controlStatus(stateNodes.length > 0 && stateNodes.every((n) => n.hasCsrfCoverage), stateNodes.length > 0), reason: `${stateNodes.length} state-changing node(s) were observed; ${stateNodes.filter((n) => n.hasCsrfCoverage).length} show CSRF-token signals.` },
    { control: "input-validation", expectedOn: "parameterized routes and search/filter inputs", status: controlStatus(context.options.mode === "validate" && paramNodes.length > 0, paramNodes.length > 0), reason: `${paramNodes.length} parameterized node(s) were identified.` },
    { control: "api", expectedOn: "JSON/API/schema routes", status: controlStatus(apiNodes.length > 0, context.pages.some((p) => /json/i.test(p.contentType))), reason: `${apiNodes.length} API-like node(s) were identified.` },
    { control: "client-side", expectedOn: "JavaScript-heavy frontends", status: controlStatus(context.options.deepCrawl && context.diagnostics.fetchedScripts ? context.diagnostics.fetchedScripts > 0 : false, context.pages.some((p) => p.scripts.length > 0)), reason: `scriptsObserved=${context.pages.reduce((s, p) => s + p.scripts.length, 0)}, scriptsFetched=${context.diagnostics.fetchedScripts ?? 0}` },
    { control: "evidence", expectedOn: "all findings and validation claims", status: controlStatus(assessment.requests.length > 0, context.diagnostics.attempted > 0), reason: `${assessment.requests.length} request model observation(s) are available for replay/evidence.` },
  ];
}

function buildHypotheses(context: ScanContext, nodes: SurfaceNode[], matrix: ControlExpectation[]): TestHypothesis[] {
  const out: TestHypothesis[] = [];
  const highValue = nodes.filter((n) => n.riskWeight >= 8).slice(0, 8);
  const authSupplied = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
  for (const node of highValue) {
    if ((node.classes.includes("admin") || node.classes.includes("student-data") || node.classes.includes("authorization")) && authSupplied) {
      out.push({
        id: `hyp-access-${node.id}`,
        title: `Verify access-control boundary for ${node.route}`,
        whyItMatters: "High-value routes with identity, student-data, or admin semantics are common places where business authorization breaks.",
        safeValidation: "Compare authenticated response to an unauthenticated control request and, where approved, a lower-privilege test account. Do not extract records or modify state.",
        evidenceNeeded: ["authenticated status/body family", "anonymous status/body family", "redirect chain", "role/test-account identity used", "redacted replay command"],
        confidenceGate: "Only escalate beyond a signal if the anonymous or lower-privilege control receives the same protected content family or privileged API response.",
        priority: node.classes.includes("admin") || node.classes.includes("student-data") ? "high" : "medium",
        mappedSources: ["web workflow mapping", "access-control test discipline", "evidence-first validation"],
      });
    }
    if (node.hasPostForm && !node.hasCsrfCoverage) {
      out.push({
        id: `hyp-csrf-${node.id}`,
        title: `Review CSRF protection for state-changing workflow ${node.route}`,
        whyItMatters: "State-changing forms should have a server-validated anti-CSRF control, especially in authenticated portals.",
        safeValidation: "Inspect token presence and server behaviour using approved non-destructive form submissions only in a lab or explicitly approved workflow.",
        evidenceNeeded: ["form method/action", "token field presence", "cookie SameSite", "approved workflow notes"],
        confidenceGate: "Do not claim CSRF without demonstrating token absence/weakness and a safe server-side acceptance condition.",
        priority: "medium",
        mappedSources: ["web form workflow assessment", "safe validation boundaries"],
      });
    }
    if (node.parameters.length) {
      out.push({
        id: `hyp-input-${node.id}`,
        title: `Validate parameter handling for ${node.route}`,
        whyItMatters: "Parameterized routes define input surfaces; fragile handling can cause reflection, verbose errors, redirect weakness, or authorization confusion.",
        safeValidation: "Use inert canaries and response-family comparison only; avoid destructive payloads and data extraction.",
        evidenceNeeded: ["baseline response", "mutated response", "status delta", "reflection context", "error-signal evidence"],
        confidenceGate: "Escalate only when baseline-vs-mutated evidence shows reflection, verbose errors, unsafe redirect, or unexpected access change.",
        priority: node.classes.includes("authorization") ? "high" : "medium",
        mappedSources: ["input surface modelling", "controlled proof discipline"],
      });
    }
  }

  for (const gap of matrix.filter((m) => m.status !== "tested" && ["auth", "access-control", "input-validation", "client-side"].includes(m.control))) {
    out.push({
      id: `hyp-gap-${gap.control}`,
      title: `Close ${gap.control} coverage gap before assurance claims`,
      whyItMatters: gap.reason,
      safeValidation: "Add approved seed URLs, session headers, browser-discovered routes, or manual verification evidence depending on the missing control.",
      evidenceNeeded: ["coverage vector", "seed list", "request ledger", "operator notes"],
      confidenceGate: "Do not raise assurance grade until the missing control moves from not-tested/partial to tested.",
      priority: gap.status === "not-tested" ? "high" : "medium",
      mappedSources: ["assessment lifecycle discipline", "operator repeatability"],
    });
  }

  return out.slice(0, 20);
}

export function buildTestModel(context: ScanContext): TestModel {
  const assessment = buildAssessmentModel(context);
  const nodes = buildNodes(context);
  const controlMatrix = buildControlMatrix(context, nodes, assessment);
  const hypotheses = buildHypotheses(context, nodes, controlMatrix);
  let readinessScore = 100;
  readinessScore -= controlMatrix.filter((c) => c.status === "not-tested").length * 9;
  readinessScore -= controlMatrix.filter((c) => c.status === "partially-tested").length * 4;
  if (!nodes.length) readinessScore -= 30;
  if (assessment.loginWallRatio > 0.5) readinessScore -= 15;
  if (hypotheses.filter((h) => h.priority === "high" || h.priority === "critical").length > 5) readinessScore -= 10;
  readinessScore = Math.max(0, Math.min(100, readinessScore));
  const blockers = [
    !nodes.length ? "no surface nodes were modelled" : "",
    controlMatrix.some((c) => c.control === "auth" && c.status === "not-tested") ? "authenticated workflow model is missing" : "",
    controlMatrix.some((c) => c.control === "client-side" && c.status === "not-tested") ? "client-side route model is missing" : "",
    controlMatrix.some((c) => c.control === "access-control" && c.status === "not-tested") ? "access-control model has no high-value tested surface" : "",
  ].filter(Boolean);
  return { assessment, nodes, controlMatrix, hypotheses, readinessScore, blockers };
}
