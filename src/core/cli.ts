import { readFileSync } from "node:fs";
import type { ReportFormat, ScanMode, ScanOptions, Severity } from "../types.js";

const DEFAULT_CHECKS = ["coverage", "proofmetrics", "vulnvalidation", "assurance", "externalbenchmark", "benchmark", "browsermodel", "rolecompare", "plugins", "validationmatrix", "productengine", "testvectors", "professionalmodel", "bookscope", "stateflow", "parammodel", "testmodel", "differential", "enginemodel", "evidencequality", "tls", "headers", "csp", "cors", "cookies", "cache", "methods", "discovery", "auth", "access", "api", "jwt", "secrets", "dom", "surface", "appsec", "inputvalidation", "riskchain", "foresight", "workflows", "deepassess", "composition", "mutation", "governance", "methodology", "resilience"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const FORMATS: ReportFormat[] = ["json", "markdown", "html", "sarif"];
const MODES: ScanMode[] = ["passive", "standard", "validate"];

function readValue(args: string[], name: string): string | undefined {
  const eq = args.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1];
  return undefined;
}

function readAllValues(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const item = args[i]!;
    if (item.startsWith(`${name}=`)) values.push(item.slice(name.length + 1));
    else if (item === name && args[i + 1]) values.push(args[i + 1]!);
  }
  return values;
}

function readList(value: string | undefined): string[] {
  return value?.split(",").map((v) => v.trim()).filter(Boolean) ?? [];
}

type ScanPolicy = Partial<{
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
  maxBodyBytes: number;
  evidenceLimit: number;
  userAgent: string;
  failOn: Severity;
  authorized: boolean;
  client: string;
  assessmentId: string;
  tester: string;
  scope: string[];
  includePasses: boolean;
  jsonlLog: string;
  baseline: string;
  prohibitedPaths: string[];
  includeExternalLinks: boolean;
  insecureTls: boolean;
  deepCrawl: boolean;
  seedUrls: string[];
  harFile: string;
  replayFile: string;
  minCoverageScore: number;
  minPages: number;
  requireAuth: boolean;
  browserCrawl: boolean;
  browserHeadful: boolean;
  browserChannel: string;
  browserExecutable: string;
  loginUrl: string;
  loginUsername: string;
  loginPassword: string;
  loginUsernameSelector: string;
  loginPasswordSelector: string;
  loginSubmitSelector: string;
  rulesDir: string;
  benchmarkProfile: string;
  benchmarkGroundTruth: string;
  benchmarkEvidenceOut: string;
  projectDir: string;
  projectName: string;
  triageFile: string;
  includeMetaFindings: boolean;
  openApiFiles: string[];
  summaryFile: string;
  triageOut: string;
}>;

function readPolicy(args: string[]): { file?: string; policy: ScanPolicy } {
  const file = readValue(args, "--policy");
  if (!file) return { policy: {} };
  const policy = JSON.parse(readFileSync(file, "utf8")) as ScanPolicy;
  if (!policy || typeof policy !== "object") throw new Error("--policy must point to a JSON object.");
  return { file, policy };
}

function policyList(value: string[] | undefined): string[] {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()).map((v) => v.trim()) : [];
}

function readListOption(args: string[], flag: string, policyValue: string[] | undefined): string[] {
  const cli = readList(readValue(args, flag));
  return cli.length ? cli : policyList(policyValue);
}

function readAllOption(args: string[], flag: string, policyValue: string[] | undefined): string[] {
  const cli = readAllValues(args, flag);
  return cli.length ? cli : policyList(policyValue);
}

function readIntOption(args: string[], flag: string, fallback: number | undefined, defaultValue: number, max: number): number {
  const raw = readValue(args, flag);
  const value = Number(raw ?? fallback ?? defaultValue);
  if (!Number.isInteger(value) || value <= 0 || value > max) throw new Error(`${flag} must be a positive integer up to ${max}.`);
  return value;
}

function boolOption(args: string[], flag: string, fallback = false): boolean {
  return args.includes(flag) || fallback;
}

function parseHeader(raw: string): [string, string] {
  const index = raw.indexOf(":");
  if (index <= 0) throw new Error("Header must use the format 'Name: value'.");
  const name = raw.slice(0, index).trim().toLowerCase();
  const value = raw.slice(index + 1).trim();
  if (!name || /[\r\n]/.test(name + value)) throw new Error("Invalid header value.");
  return [name, value];
}

function readHeaders(args: string[]): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const raw of readAllValues(args, "--header")) {
    const [name, value] = parseHeader(raw);
    headers[name] = value;
  }
  return headers;
}

function readRoleHeaders(args: string[]): Array<{ role: string; headers: Record<string, string> }> {
  return readAllValues(args, "--role-header").map((raw) => {
    const split = raw.indexOf("|");
    if (split <= 0) throw new Error("--role-header must use the format 'role|Name: value'.");
    const role = raw.slice(0, split).trim();
    const [name, value] = parseHeader(raw.slice(split + 1));
    return { role, headers: { [name]: value } };
  });
}

function readPositiveInt(args: string[], flag: string, fallback: number, max: number): number {
  const raw = readValue(args, flag);
  const value = Number(raw ?? fallback);
  if (!Number.isInteger(value) || value <= 0 || value > max) throw new Error(`${flag} must be a positive integer up to ${max}.`);
  return value;
}

export function usage(): string {
  return `
WebSec Sentinel — evidence-driven defensive web security assessment scanner

V12 product focus: external benchmark proof, confirmed validation evidence, browser workflow crawling, role differential evidence, precision/recall metrics, and reproducible case-study artifacts.

Usage:
  npm run scan -- <target> [options]
  npx websec-sentinel <target> [options]

Assessment modes:
  passive    Uses only the crawled responses. Lowest production risk.
  standard   Performs safe same-origin discovery and configuration checks. Default.
  validate   Enables stronger proof-of-impact validation. Requires --authorized.

Options:
  --mode <passive|standard|validate>   Scan depth. validate requires --authorized. Default: standard
  --policy <file>                      Load repeatable scan defaults from a JSON policy file
  --checks <list>                      Comma-separated checks. Default: all
  --deep-crawl                         Fetch same-origin JavaScript assets and mine route hints aggressively
  --seed <url>                         Add approved same-origin seed URL. Repeatable
  --har <file>                         Export a redacted HAR-like request ledger
  --replay-file <file>                 Export redacted replay commands for manual verification
  --min-coverage-score <n>             Coverage contract threshold. Default: 60
  --min-pages <n>                      Minimum pages expected for high-confidence scans. Default: 1

  --browser-crawl                      Use optional Playwright browser execution for JavaScript-rendered pages
  --browser-headful                    Run Playwright with a visible browser window. Default: headless
  --browser-channel <name>             Playwright channel, for example chrome or msedge
  --browser-executable <path>          Browser executable path for playwright-core/custom installs
  --login-url <url>                    Optional approved login URL for browser login automation
  --login-username <value>             Approved test-account username for browser login automation
  --login-password <value>             Approved test-account password for browser login automation
  --login-username-selector <selector> Login username selector. Default: input[type=email], input[name*=user], input[name*=email]
  --login-password-selector <selector> Login password selector. Default: input[type=password]
  --login-submit-selector <selector>   Login submit selector. Default: button[type=submit], input[type=submit]
  --role-header "role|Name: value"      Add approved role-labelled session header for role comparison. Repeatable
  --rules-dir <dir>                    Load safe JSON plugin rules from directory
  --benchmark-profile <name>           Evaluate expected detections for known vulnerable benchmark apps/fixtures
  --benchmark-ground-truth <file>      JSON ground-truth file for external benchmark targets such as Juice Shop, DVWA, or WebGoat
  --benchmark-evidence-out <file>      Save external benchmark precision/recall/F1 evidence artifact
  --require-auth                       Mark scan incomplete unless an auth/session header is supplied
  --checks deepassess,vulnvalidation,rolecompare Run deeper safe checks for auth, workflow, second-order, CSRF, IDOR, and role signals
  --checks productengine,testvectors     Run only the v9 book-scoped product engine gates and safe test-vector model
  --checks professionalmodel,bookscope,stateflow,parammodel Run only the v8/v7 book-scoped engine model checks
  --checks testmodel,differential     Run only the v6 book-referenced model and safe access differential checks
  --checks enginemodel,evidencequality Run only the v5 model/evidence quality checks
  --format <list>                      json,markdown,html,sarif. Default: json,markdown
  --save                               Save report files to output directory
  --out <dir>                          Output directory. Default: ./reports
  --crawl-depth <n>                    Same-origin crawl depth. Default: 1
  --max-pages <n>                      Maximum same-origin pages. Default: 50
  --timeout <ms>                       Request timeout. Default: 8000
  --rate-limit <ms>                    Delay between requests. Default: 100
  --max-body-bytes <n>                 Max stored response body size. Default: 1048576
  --evidence-limit <n>                 Max evidence items per finding/report area. Default: 10
  --fail-on <severity>                 CI fail threshold. Default: high
  --scope <list>                       Approved hostnames. Default: target host only
  --authorized                         Required for validate mode
  --client <name>                      Client name for report metadata
  --assessment-id <id>                 Authorization / engagement identifier
  --tester <name>                      Assessor/team name for report metadata
  --include-passes                     Include pass findings in output
  --jsonl-log <file>                   Save append-only request observations as JSONL
  --baseline <file>                    Compare against a previous JSON report
  --project-dir <dir>                  Persist scan history, latest report pointer, and automatic diffs
  --project-name <name>                Stable project name for persisted history. Default: target hostname
  --triage-file <file>                 JSON triage overlay keyed by finding id
  --triage-out <file>                  Write a triage template for active findings
  --summary-file <file>                Write a compact CI-friendly JSON run summary
  --openapi-file <file>                Import OpenAPI/Swagger JSON as API inventory input. Repeatable
  --include-meta-findings              Include noisy model/coverage meta-findings even when not actionable
  --header "Name: value"               Add an assessment header/session token. Repeatable. Values are redacted in logs
  --user-agent <value>                 Override the browser-like assessment user agent
  --include-external-links             Record external links in reports without crawling them
  --insecure-tls                       Allow crawling targets with broken TLS chains. Findings still report TLS risk
  --prohibited-paths <list>            Comma-separated paths that must never be requested
  --no-color                           Disable terminal colors
  -h, --help                           Show help

Examples:
  npm run scan -- https://example.com --save --format html,markdown,json,sarif
  npm run scan -- https://example.com --mode passive --checks tls,headers,cookies,secrets
  npm run scan -- https://example.com --mode validate --authorized --client "Client Ltd" --assessment-id "AUTH-001" --tester "Red Team"
  npm run scan -- https://example.com --header "Cookie: session=<value>" --prohibited-paths /logout,/delete-account
`;
}

export function parseCli(argv: string[]): ScanOptions | null {
  if (!argv.length || argv.includes("--help") || argv.includes("-h")) return null;
  const { file: policyFile, policy } = readPolicy(argv);
  const target = argv[0]?.startsWith("--") ? policy.target : argv[0] ?? policy.target;
  if (!target) return null;

  let targetUrl: URL;
  try {
    targetUrl = new URL(target);
  } catch {
    throw new Error("Target must be a valid absolute URL, for example https://example.com");
  }
  if (!["http:", "https:"].includes(targetUrl.protocol)) throw new Error("Target protocol must be http or https.");

  const mode = (readValue(argv, "--mode") ?? policy.mode ?? "standard") as ScanMode;
  if (!MODES.includes(mode)) throw new Error(`Unsupported mode: ${mode}`);

  const formats = readListOption(argv, "--format", policy.formats) as ReportFormat[];
  const selectedFormats = formats.length ? formats : (["json", "markdown"] as ReportFormat[]);
  for (const f of selectedFormats) if (!FORMATS.includes(f)) throw new Error(`Unsupported format: ${f}`);

  const checks = readListOption(argv, "--checks", policy.checks);
  const failOn = (readValue(argv, "--fail-on") ?? policy.failOn ?? "high") as Severity;
  if (!SEVERITIES.includes(failOn)) throw new Error(`Unsupported fail threshold: ${failOn}`);

  const scope = readListOption(argv, "--scope", policy.scope);
  const authorized = boolOption(argv, "--authorized", Boolean(policy.authorized));
  if (mode === "validate" && !authorized) throw new Error("validate mode requires --authorized plus a signed assessment scope.");

  return {
    target: targetUrl.toString(),
    mode,
    checks: checks.length ? checks : DEFAULT_CHECKS,
    formats: selectedFormats,
    save: boolOption(argv, "--save", Boolean(policy.save)),
    outputDir: readValue(argv, "--out") ?? policy.outputDir ?? "./reports",
    timeoutMs: readIntOption(argv, "--timeout", policy.timeoutMs, 8000, 120000),
    maxPages: readIntOption(argv, "--max-pages", policy.maxPages, 50, 5000),
    crawlDepth: readIntOption(argv, "--crawl-depth", policy.crawlDepth, 1, 8),
    rateLimitMs: readIntOption(argv, "--rate-limit", policy.rateLimitMs, 100, 60000),
    maxBodyBytes: readIntOption(argv, "--max-body-bytes", policy.maxBodyBytes, 1048576, 10485760),
    evidenceLimit: readIntOption(argv, "--evidence-limit", policy.evidenceLimit, 10, 100),
    userAgent: readValue(argv, "--user-agent") ?? policy.userAgent ?? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36 WebSec-Sentinel/12.0 External-Benchmark-Product-Engine",
    failOn,
    authorized,
    client: readValue(argv, "--client") ?? policy.client,
    assessmentId: readValue(argv, "--assessment-id") ?? policy.assessmentId,
    tester: readValue(argv, "--tester") ?? policy.tester,
    scope: scope.length ? scope : [targetUrl.hostname],
    noColor: argv.includes("--no-color"),
    includePasses: boolOption(argv, "--include-passes", Boolean(policy.includePasses)),
    jsonlLog: readValue(argv, "--jsonl-log") ?? policy.jsonlLog,
    baseline: readValue(argv, "--baseline") ?? policy.baseline,
    customHeaders: readHeaders(argv),
    prohibitedPaths: readListOption(argv, "--prohibited-paths", policy.prohibitedPaths),
    includeExternalLinks: boolOption(argv, "--include-external-links", Boolean(policy.includeExternalLinks)),
    insecureTls: boolOption(argv, "--insecure-tls", Boolean(policy.insecureTls)),
    deepCrawl: boolOption(argv, "--deep-crawl", Boolean(policy.deepCrawl)),
    seedUrls: readAllOption(argv, "--seed", policy.seedUrls),
    harFile: readValue(argv, "--har") ?? policy.harFile,
    replayFile: readValue(argv, "--replay-file") ?? policy.replayFile,
    minCoverageScore: readIntOption(argv, "--min-coverage-score", policy.minCoverageScore, 60, 100),
    minPages: readIntOption(argv, "--min-pages", policy.minPages, 1, 5000),
    requireAuth: boolOption(argv, "--require-auth", Boolean(policy.requireAuth)),
    browserCrawl: boolOption(argv, "--browser-crawl", Boolean(policy.browserCrawl)),
    browserHeadful: boolOption(argv, "--browser-headful", Boolean(policy.browserHeadful)),
    browserChannel: readValue(argv, "--browser-channel") ?? policy.browserChannel,
    browserExecutable: readValue(argv, "--browser-executable") ?? policy.browserExecutable,
    loginUrl: readValue(argv, "--login-url") ?? policy.loginUrl,
    loginUsername: readValue(argv, "--login-username") ?? policy.loginUsername,
    loginPassword: readValue(argv, "--login-password") ?? policy.loginPassword,
    loginUsernameSelector: readValue(argv, "--login-username-selector") ?? policy.loginUsernameSelector,
    loginPasswordSelector: readValue(argv, "--login-password-selector") ?? policy.loginPasswordSelector,
    loginSubmitSelector: readValue(argv, "--login-submit-selector") ?? policy.loginSubmitSelector,
    roleHeaders: readRoleHeaders(argv),
    rulesDir: readValue(argv, "--rules-dir") ?? policy.rulesDir,
    benchmarkProfile: readValue(argv, "--benchmark-profile") ?? policy.benchmarkProfile,
    benchmarkGroundTruth: readValue(argv, "--benchmark-ground-truth") ?? policy.benchmarkGroundTruth,
    benchmarkEvidenceOut: readValue(argv, "--benchmark-evidence-out") ?? policy.benchmarkEvidenceOut,
    projectDir: readValue(argv, "--project-dir") ?? policy.projectDir,
    projectName: readValue(argv, "--project-name") ?? policy.projectName,
    triageFile: readValue(argv, "--triage-file") ?? policy.triageFile,
    includeMetaFindings: boolOption(argv, "--include-meta-findings", Boolean(policy.includeMetaFindings)),
    policyFile,
    openApiFiles: readAllOption(argv, "--openapi-file", policy.openApiFiles),
    summaryFile: readValue(argv, "--summary-file") ?? policy.summaryFile,
    triageOut: readValue(argv, "--triage-out") ?? policy.triageOut,
  };
}
