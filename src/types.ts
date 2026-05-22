export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "warn" | "info";
export type Confidence = "confirmed" | "strong" | "moderate" | "low";
export type ScanMode = "passive" | "standard" | "validate";
export type ReportFormat = "json" | "markdown" | "html" | "sarif";
export type AuthState = "anonymous" | "header-authenticated" | "browser-authenticated" | "role-authenticated" | "unknown";
export type Exploitability = "none" | "theoretical" | "practical" | "validated";
export type AttackPhase = "reconnaissance" | "mapping" | "validation" | "impact-analysis" | "remediation";
export type RemediationPriority = "immediate" | "short-term" | "planned" | "monitor";
export type FindingKind = "confirmed-vulnerability" | "risk-signal" | "coverage-gap" | "scanner-diagnostic" | "informational" | "pass";

export interface Evidence {
  url?: string | undefined;
  method?: string;
  status?: number | undefined;
  header?: string;
  parameter?: string;
  observed?: string;
  expected?: string;
  snippet?: string;
  requestId?: string;
  elapsedMs?: number;
}

export interface ScanResult {
  id: string;
  check: string;
  category: string;
  status: Status;
  kind?: FindingKind;
  severity: Severity;
  confidence: Confidence;
  title: string;
  detail: string;
  impact: string;
  businessImpact?: string;
  remediation: string;
  evidence?: Evidence[];
  references?: string[];
  owasp?: string[];
  cwe?: string[];
  cvss?: string;
  tags?: string[];
  exploitability?: Exploitability;
  attackPhase?: AttackPhase;
  remediationPriority?: RemediationPriority;
  likelihood?: "very-high" | "high" | "medium" | "low";
  assetExposure?: "internet" | "authenticated" | "internal" | "unknown";
  verification?: string;
  falsePositiveNotes?: string;
  sla?: string;
  compliance?: string[];
  chainLinks?: string[];
  triage?: { status: "open" | "accepted-risk" | "false-positive" | "fixed" | "ignored"; owner?: string; note?: string };
  fingerprint?: string;
}

export interface HttpObservation {
  url: string;
  method: string;
  status: number;
  redirected: boolean;
  finalUrl: string;
  headers: Record<string, string>;
  requestHeaders?: Record<string, string>;
  body: string;
  elapsedMs: number;
  requestId: string;
  sizeBytes: number;
  bodyHash?: string;
  responseFamily?: string;
  authState?: AuthState;
}

export interface CrawlPage extends HttpObservation {
  depth: number;
  contentType: string;
  links: string[];
  forms: PageForm[];
  scripts: string[];
  routeHints: string[];
  title?: string;
}

export interface PageForm {
  action: string;
  method: string;
  inputs: Array<{ name: string; type: string; autocomplete?: string; required?: boolean; value?: string }>;
  hasCsrfToken: boolean;
}

export interface CrawlDiagnostics {
  attempted: number;
  visited: number;
  queued: number;
  blockedByScope: number;
  blockedByProhibitedPath: number;
  requestFailures: Array<{ url: string; error: string }>;
  skippedNonHtml: number;
  discoveredLinks: number;
  discoveredForms: number;
  discoveredRouteHints: number;
  discoveredScriptRoutes?: number;
  fetchedScripts?: number;
  browserExecuted?: boolean;
  browserPages?: number;
  browserConsoleErrors?: number;
  browserNetworkRequests?: number;
  browserNetworkUrls?: string[];
  browserPackage?: string;
  browserLaunchMode?: string;
  pluginRulesLoaded?: number;
  benchmarkExpected?: number;
  benchmarkDetected?: number;
  externalBenchmarkExpected?: number;
  externalBenchmarkMatched?: number;
  externalBenchmarkPrecision?: number;
  externalBenchmarkRecall?: number;
  externalBenchmarkF1?: number;
}

export interface ScanOptions {
  target: string;
  mode: ScanMode;
  checks: string[];
  formats: ReportFormat[];
  save: boolean;
  outputDir: string;
  timeoutMs: number;
  maxPages: number;
  crawlDepth: number;
  rateLimitMs: number;
  userAgent: string;
  failOn: Severity;
  authorized: boolean;
  client?: string | undefined;
  assessmentId?: string | undefined;
  tester?: string | undefined;
  scope: string[];
  noColor: boolean;
  includePasses: boolean;
  maxBodyBytes: number;
  evidenceLimit: number;
  jsonlLog?: string | undefined;
  baseline?: string | undefined;
  customHeaders: Record<string, string>;
  prohibitedPaths: string[];
  includeExternalLinks: boolean;
  insecureTls: boolean;
  deepCrawl: boolean;
  seedUrls: string[];
  harFile?: string | undefined;
  replayFile?: string | undefined;
  minCoverageScore: number;
  minPages: number;
  requireAuth: boolean;
  browserCrawl: boolean;
  browserHeadful: boolean;
  browserChannel?: string | undefined;
  browserExecutable?: string | undefined;
  loginUrl?: string | undefined;
  loginUsername?: string | undefined;
  loginPassword?: string | undefined;
  loginUsernameSelector?: string | undefined;
  loginPasswordSelector?: string | undefined;
  loginSubmitSelector?: string | undefined;
  roleHeaders: Array<{ role: string; headers: Record<string, string> }>;
  rulesDir?: string | undefined;
  benchmarkProfile?: string | undefined;
  benchmarkGroundTruth?: string | undefined;
  benchmarkEvidenceOut?: string | undefined;
  projectDir?: string | undefined;
  projectName?: string | undefined;
  triageFile?: string | undefined;
  includeMetaFindings: boolean;
  policyFile?: string | undefined;
  openApiFiles: string[];
  summaryFile?: string | undefined;
  triageOut?: string | undefined;
}

export interface ScanContext {
  options: ScanOptions;
  targetUrl: URL;
  pages: CrawlPage[];
  diagnostics: CrawlDiagnostics;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  score: number;
  weightedRisk: number;
  coverageScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
  durationMs: number;
  topCategories: Array<{ category: string; count: number }>;
}

export interface ScanReport {
  tool: string;
  version: string;
  target: string;
  timestamp: string;
  mode: ScanMode;
  authorization: {
    authorized: boolean;
    client?: string | undefined;
    assessmentId?: string | undefined;
    tester?: string | undefined;
    scope: string[];
    authenticated: boolean;
  };
  summary: ScanSummary;
  executive: {
    verdict: string;
    businessRisk: string;
    immediatePriorities: string[];
  };
  results: ScanResult[];
  surface: {
    pagesCrawled: number;
    uniqueHosts: string[];
    technologies: string[];
    formsObserved: number;
    linksObserved: number;
    routesObserved: number;
    scriptsObserved: number;
    statusCodes: Record<string, number>;
    authCoverage: "none" | "header-supplied" | "browser-supplied" | "role-supplied";
    testedControls: string[];
    browserExecuted?: boolean;
    roleCount?: number;
  };
  quality: {
    requestCount: number;
    evidencePolicy: string;
    coverageContract: { minCoverageScore: number; minPages: number; requireAuth: boolean; passed: boolean; reasons: string[] };
    limitations: string[];
    diagnostics: CrawlDiagnostics;
    baseline?: { baselineFile: string; newFindings: string[]; resolvedFindings: string[]; unchangedFindings: string[]; changedSeverity: Array<{ id: string; before: string; after: string }> } | undefined;
    project?: { name: string; directory: string; previousReport?: string; historyCount: number } | undefined;
    methodologySources?: string[];
  };
}

export type Check = {
  name: string;
  description: string;
  run: (context: ScanContext) => Promise<ScanResult[]>;
};
