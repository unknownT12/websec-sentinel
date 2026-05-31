#!/usr/bin/env node
import { parseCli, usage } from "./core/cli.js";
import { crawl } from "./core/crawler.js";
import { browserCrawl } from "./core/browserCrawler.js";
import { detectTechnologies } from "./core/technology.js";
import { appsecCheck } from "./checks/appsec.js";
import { assuranceCheck } from "./checks/assurance.js";
import { engineModelCheck } from "./checks/enginemodel.js";
import { evidenceQualityCheck } from "./checks/evidencequality.js";
import { testModelCheck } from "./checks/testmodel.js";
import { bookScopeCheck } from "./checks/bookscope.js";
import { stateFlowCheck } from "./checks/stateflow.js";
import { parameterModelCheck } from "./checks/parammodel.js";
import { professionalModelCheck } from "./checks/professionalmodel.js";
import { differentialCheck } from "./checks/differential.js";
import { inputValidationCheck } from "./checks/inputvalidation.js";
import { riskchainCheck } from "./checks/riskchain.js";
import { authCheck } from "./checks/auth.js";
import { accessCheck } from "./checks/access.js";
import { apiCheck } from "./checks/api.js";
import { cacheCheck } from "./checks/cache.js";
import { domCheck } from "./checks/dom.js";
import { methodsCheck } from "./checks/methods.js";
import { coverageCheck } from "./checks/coverage.js";
import { productEngineCheck } from "./checks/productengine.js";
import { testVectorsCheck } from "./checks/testvectors.js";
import { benchmarkCheck } from "./checks/benchmark.js";
import { browserModelCheck } from "./checks/browsermodel.js";
import { roleCompareCheck } from "./checks/rolecompare.js";
import { pluginsCheck } from "./checks/plugins.js";
import { validationMatrixCheck } from "./checks/validationmatrix.js";
import { vulnerabilityValidationCheck } from "./checks/vulnvalidation.js";
import { proofMetricsCheck } from "./checks/proofmetrics.js";
import { externalBenchmarkCheck } from "./checks/externalbenchmark.js";
import { cookiesCheck } from "./checks/cookies.js";
import { corsCheck } from "./checks/cors.js";
import { cspCheck } from "./checks/csp.js";
import { discoveryCheck } from "./checks/discovery.js";
import { governanceCheck } from "./checks/governance.js";
import { methodologyCheck } from "./checks/methodology.js";
import { resilienceCheck } from "./checks/resilience.js";
import { foresightCheck } from "./checks/foresight.js";
import { workflowsCheck } from "./checks/workflows.js";
import { deepAssessmentCheck } from "./checks/deepassess.js";
import { compositionCheck } from "./checks/composition.js";
import { mutationCheck } from "./checks/mutation.js";
import { headersCheck } from "./checks/headers.js";
import { jwtCheck } from "./checks/jwt.js";
import { secretsCheck } from "./checks/secrets.js";
import { surfaceCheck } from "./checks/surface.js";
import { tlsCheck } from "./checks/tls.js";
import { buildReport, printReport, saveReports, shouldFail } from "./reporters/report.js";
import { compareBaseline } from "./core/baseline.js";
import { getHttpObservations, resetHttpState } from "./core/http.js";
import { saveHarLike, saveReplayFile } from "./core/evidence.js";
import { reduceFalsePositiveNoise } from "./core/falsepositives.js";
import { applyTriage, filterMetaFindings, loadTriage, projectBaseline, projectPath, saveProjectReport, writeSummaryFile, writeTriageTemplate } from "./core/project.js";
import type { Check, ScanContext, ScanResult } from "./types.js";

const VERSION = "12.0.0";
const CHECKS: Record<string, Check> = {
  coverage: coverageCheck,
  proofmetrics: proofMetricsCheck,
  vulnvalidation: vulnerabilityValidationCheck,
  assurance: assuranceCheck,
  benchmark: benchmarkCheck,
  externalbenchmark: externalBenchmarkCheck,
  browsermodel: browserModelCheck,
  rolecompare: roleCompareCheck,
  plugins: pluginsCheck,
  validationmatrix: validationMatrixCheck,
  productengine: productEngineCheck,
  testvectors: testVectorsCheck,
  professionalmodel: professionalModelCheck,
  bookscope: bookScopeCheck,
  stateflow: stateFlowCheck,
  parammodel: parameterModelCheck,
  testmodel: testModelCheck,
  differential: differentialCheck,
  enginemodel: engineModelCheck,
  evidencequality: evidenceQualityCheck,
  tls: tlsCheck,
  headers: headersCheck,
  csp: cspCheck,
  cors: corsCheck,
  cookies: cookiesCheck,
  cache: cacheCheck,
  methods: methodsCheck,
  discovery: discoveryCheck,
  auth: authCheck,
  access: accessCheck,
  api: apiCheck,
  jwt: jwtCheck,
  secrets: secretsCheck,
  dom: domCheck,
  surface: surfaceCheck,
  appsec: appsecCheck,
  inputvalidation: inputValidationCheck,
  riskchain: riskchainCheck,
  foresight: foresightCheck,
  workflows: workflowsCheck,
  deepassess: deepAssessmentCheck,
  composition: compositionCheck,
  mutation: mutationCheck,
  governance: governanceCheck,
  methodology: methodologyCheck,
  resilience: resilienceCheck,
};

function statusCodes(pages: ScanContext["pages"]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const p of pages) out[String(p.status)] = (out[String(p.status)] ?? 0) + 1;
  return out;
}

async function main(): Promise<void> {
  let options;
  try {
    options = parseCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    console.log(usage());
    process.exit(2);
  }
  if (!options) {
    console.log(usage());
    return;
  }

  const targetUrl = new URL(options.target);
  resetHttpState();
  const unknownChecks = options.checks.filter((c) => !CHECKS[c]);
  if (unknownChecks.length) throw new Error(`Unknown check(s): ${unknownChecks.join(", ")}. Available: ${Object.keys(CHECKS).join(", ")}`);

  const startedAt = Date.now();
  console.log(`\nWebSec Sentinel v${VERSION}`);
  console.log(`Target: ${options.target}`);
  console.log(`Mode: ${options.mode} | Scope: ${options.scope.join(", ")}`);
  if (options.mode === "validate") console.log(`Authorization: ${options.authorized ? "provided" : "missing"} | Client: ${options.client ?? "not provided"} | Assessment: ${options.assessmentId ?? "not provided"}`);
  if (Object.keys(options.customHeaders).length) console.log(`Custom headers: ${Object.keys(options.customHeaders).map((h) => `${h}=<redacted>`).join(", ")}`);
  if (options.browserCrawl) console.log(`Browser crawl: enabled${options.loginUrl ? " with login automation" : ""}`);
  if (options.roleHeaders.length) console.log(`Role comparison sessions: ${options.roleHeaders.map((r) => r.role).join(", ")}`);
  if (options.prohibitedPaths.length) console.log(`Prohibited paths: ${options.prohibitedPaths.join(", ")}`);
  if (options.insecureTls) console.log("TLS verification: relaxed for crawling (--insecure-tls)");
  if (options.projectDir) console.log(`Project history: ${projectPath(options, targetUrl)}`);

  const baseCrawl = await crawl(targetUrl, options);
  let pages = baseCrawl.pages;
  let diagnostics = baseCrawl.diagnostics;
  if (options.browserCrawl) {
    const browser = await browserCrawl(targetUrl, options);
    const seen = new Set(pages.map((p) => p.finalUrl || p.url));
    for (const p of browser.pages) {
      const key = p.finalUrl || p.url;
      if (!seen.has(key)) { pages.push(p); seen.add(key); }
    }
    diagnostics = { ...diagnostics, ...browser.diagnostics, requestFailures: [...diagnostics.requestFailures, ...(browser.diagnostics.requestFailures ?? [])] };
  }
  console.log(`Crawled ${pages.length} same-origin page(s). Forms: ${pages.reduce((sum, p) => sum + p.forms.length, 0)} | Links: ${pages.reduce((sum, p) => sum + p.links.length, 0)} | Route hints: ${pages.reduce((sum, p) => sum + p.routeHints.length, 0)}`);
  if (!pages.length && diagnostics.requestFailures.length) console.log(`Crawler diagnostics: ${diagnostics.requestFailures.slice(0, 3).map((f) => `${f.url} => ${f.error}`).join(" | ")}`);

  const context: ScanContext = { options, targetUrl, pages, diagnostics };
  const results: ScanResult[] = [];

  for (const name of options.checks) {
    const check = CHECKS[name]!;
    process.stdout.write(`Running ${name}... `);
    try {
      const checkResults = await check.run(context);
      results.push(...checkResults);
      const issues = checkResults.filter((r) => r.status === "fail" || r.status === "warn").length;
      console.log(issues ? `${issues} issue(s)` : "ok");
    } catch (error) {
      results.push({
        id: `scanner.${name}.error`,
        check: name,
        category: "Scanner Reliability",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: `${name} check failed safely`,
        detail: error instanceof Error ? error.message : String(error),
        impact: "This scanner module did not complete, so coverage is reduced.",
        remediation: "Re-run with debug logging or a longer timeout, and inspect target availability.",
        exploitability: "none",
      });
      console.log("error");
    }
  }

  const refinedResults = filterMetaFindings(applyTriage(reduceFalsePositiveNoise(results, options.evidenceLimit), loadTriage(options.triageFile)), options.includeMetaFindings);
  const baseline = compareBaseline(options.baseline, refinedResults) ?? projectBaseline(options, targetUrl, refinedResults);
  const authSupplied = Object.keys(options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));
  const quickCoverage = (() => {
    let score = 0;
    if (pages.length > 0) score += 20;
    if (pages.length >= options.minPages) score += 20;
    if (pages.reduce((sum, p) => sum + p.links.length, 0) > 0) score += 10;
    if (pages.reduce((sum, p) => sum + p.routeHints.length, 0) > 0) score += 15;
    if (pages.reduce((sum, p) => sum + p.forms.length, 0) > 0) score += 15;
    if (pages.reduce((sum, p) => sum + p.scripts.length, 0) > 0) score += 10;
    if (authSupplied) score += 10;
    return Math.min(100, score);
  })();
  const coverageReasons = [
    quickCoverage < options.minCoverageScore ? `coverage ${quickCoverage}/100 below ${options.minCoverageScore}/100` : "",
    pages.length < options.minPages ? `pages ${pages.length} below ${options.minPages}` : "",
    options.requireAuth && !authSupplied ? "auth required but no auth header supplied" : "",
  ].filter(Boolean);

  const report = buildReport({
    tool: "WebSec Sentinel",
    version: VERSION,
    target: options.target,
    timestamp: new Date().toISOString(),
    mode: options.mode,
    authorization: { authorized: options.authorized, client: options.client, assessmentId: options.assessmentId, tester: options.tester, scope: options.scope, authenticated: Object.keys(options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h)) },
    results: refinedResults,
    surface: {
      pagesCrawled: pages.length,
      uniqueHosts: [...new Set(pages.map((p) => new URL(p.finalUrl || p.url).hostname))],
      technologies: detectTechnologies(pages),
      formsObserved: pages.reduce((sum, p) => sum + p.forms.length, 0),
      linksObserved: pages.reduce((sum, p) => sum + p.links.length, 0),
      routesObserved: pages.reduce((sum, p) => sum + p.routeHints.length, 0),
      scriptsObserved: pages.reduce((sum, p) => sum + p.scripts.length, 0),
      statusCodes: statusCodes(pages),
      authCoverage: (diagnostics.browserExecuted ? "browser-supplied" : options.roleHeaders.length ? "role-supplied" : authSupplied ? "header-supplied" : "none"),
      testedControls: options.checks,
      ...(diagnostics.browserExecuted !== undefined ? { browserExecuted: diagnostics.browserExecuted } : {}),
      roleCount: options.roleHeaders.length,
    },
    quality: {
      requestCount: getHttpObservations().length,
      evidencePolicy: "Evidence is redacted where patterns may contain secrets. The scanner stores snippets, headers, status codes, and request IDs, not full sensitive payloads.",
      coverageContract: { minCoverageScore: options.minCoverageScore, minPages: options.minPages, requireAuth: options.requireAuth, passed: coverageReasons.length === 0, reasons: coverageReasons },
      limitations: [
        "This tool performs black-box external checks and cannot prove absence of vulnerabilities.",
        "v11 is constrained to the uploaded book scope and moves from model checks toward hard proof: confirmed safe application-layer validation, improved browser workflow crawling, role differential evidence, precision/recall benchmark metrics, proof coverage scoring, plugin rules, false-positive controls, and reproducible JSONL/HAR/replay evidence. It still requires approved scope, reliable seeds, authenticated coverage, and human review for professional conclusions.",
        "Authenticated coverage depends on caller-supplied session headers and the configured safe path exclusions.",
        "Results depend on the crawled surface, rate limits, target availability, and configured scope.",
        ...(options.insecureTls ? ["TLS certificate verification was relaxed for crawling because --insecure-tls was supplied. Treat TLS findings as requiring manual certificate-chain review."] : []),
        "Validate mode uses inert proof-of-impact canaries only; it does not perform destructive exploitation, persistence, stealth, or data extraction.",
      ],
      diagnostics,
      baseline,
      project: options.projectDir ? { name: options.projectName ?? targetUrl.hostname, directory: projectPath(options, targetUrl) ?? options.projectDir, ...(baseline?.baselineFile ? { previousReport: baseline.baselineFile } : {}), historyCount: 0 } : undefined,
      methodologySources: [
        "The Web Application Hacker's Handbook — used as safe inspiration for web workflow mapping, input surface modelling, auth/session review, and evidence-first application assessment.",
        "Penetration Testing: A Hands-On Introduction to Hacking — used as safe inspiration for assessment lifecycle structure, scoping, and validation discipline.",
        "The Basics of Hacking and Penetration Testing — used as safe inspiration for recon-to-report methodology and beginner-friendly control coverage.",
        "The Hacker Playbook 2 and 3 — used as safe inspiration for operator workflow, evidence handoff, and assessment repeatability without adding weaponized behavior.",
        "RTFM: Red Team Field Manual — used as safe inspiration for concise operator checklists and command hygiene, not stealth or exploitation.",
        "Practical Malware Analysis — used as safe inspiration for evidence hygiene, redaction, repeatability, and cautious handling of suspicious artefacts.",
        "Black Hat Python and Hacking: The Art of Exploitation — referenced only for defensive engineering mindset, safe input modelling, and controlled lab thinking; no weaponized payloads or offensive exploitation were implemented.",
      ],
    },
    startedAt,
    includePasses: options.includePasses,
  });

  printReport(report, options.noColor);
  const savedPaths: string[] = [];
  if (options.save) savedPaths.push(...saveReports(report, options.formats, options.outputDir));
  const projectSaved = saveProjectReport(report, options, targetUrl);
  if (projectSaved) savedPaths.push(projectSaved.reportFile);
  const summaryPath = writeSummaryFile(options.summaryFile, report, options);
  if (summaryPath) savedPaths.push(summaryPath);
  const triagePath = writeTriageTemplate(options.triageOut, report.results);
  if (triagePath) savedPaths.push(triagePath);
  if (options.harFile) { saveHarLike(options.harFile, report, getHttpObservations()); savedPaths.push(options.harFile); }
  if (options.replayFile) { saveReplayFile(options.replayFile, report); savedPaths.push(options.replayFile); }
  if (savedPaths.length) console.log(`Saved reports/evidence:\n${savedPaths.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(shouldFail(report, options.failOn) ? 1 : 0);

}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
