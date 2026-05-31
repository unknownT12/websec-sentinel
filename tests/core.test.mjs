import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { parseCli } from "../dist/core/cli.js";
import { finding, pass } from "../dist/core/findings.js";
import { calculateBenchmarkMetrics } from "../dist/core/benchmarkMetrics.js";
import { renderReport } from "../dist/reporters/report.js";
import { applyTriage, filterMetaFindings } from "../dist/core/project.js";
import { discoverApis } from "../dist/core/apiDiscovery.js";
import { fingerprintFor, reduceFalsePositiveNoise } from "../dist/core/falsepositives.js";
import { deepAssessmentCheck } from "../dist/checks/deepassess.js";
import { sameOriginOnly } from "../dist/core/http.js";

test("parseCli requires explicit authorization for validate mode", () => {
  assert.throws(
    () => parseCli(["https://example.com", "--mode", "validate"]),
    /validate mode requires --authorized/,
  );
});

test("parseCli exposes explicit Playwright launch options", () => {
  const options = parseCli([
    "https://example.com",
    "--browser-crawl",
    "--browser-channel",
    "chrome",
    "--browser-executable",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "--browser-headful",
  ]);

  assert.equal(options.browserCrawl, true);
  assert.equal(options.browserHeadful, true);
  assert.equal(options.browserChannel, "chrome");
  assert.equal(options.browserExecutable, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
});

test("parseCli exposes project history and triage options", () => {
  const options = parseCli([
    "https://example.com",
    "--project-dir",
    "reports/projects",
    "--project-name",
    "Example Client",
    "--triage-file",
    "triage.json",
    "--include-meta-findings",
    "--insecure-tls",
  ]);

  assert.equal(options.projectDir, "reports/projects");
  assert.equal(options.projectName, "Example Client");
  assert.equal(options.triageFile, "triage.json");
  assert.equal(options.includeMetaFindings, true);
  assert.equal(options.insecureTls, true);
});

test("parseCli loads repeatable scan policy files with CLI override", () => {
  const dir = mkdtempSync(join(tmpdir(), "wss-policy-"));
  try {
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify({
      target: "https://policy.example",
      mode: "standard",
      checks: ["headers", "api"],
      formats: ["json"],
      projectDir: "reports/projects",
      seedUrls: ["https://policy.example/api"],
      prohibitedPaths: ["/logout"],
      minPages: 3,
      deepCrawl: true,
    }));

    const options = parseCli(["--policy", policyPath, "--min-pages", "5"]);
    assert.equal(options.target, "https://policy.example/");
    assert.deepEqual(options.checks, ["headers", "api"]);
    assert.deepEqual(options.seedUrls, ["https://policy.example/api"]);
    assert.deepEqual(options.prohibitedPaths, ["/logout"]);
    assert.equal(options.minPages, 5);
    assert.equal(options.deepCrawl, true);
    assert.equal(options.policyFile, policyPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseCli accepts OpenAPI import and CI artifact outputs", () => {
  const options = parseCli([
    "https://example.com",
    "--openapi-file",
    "openapi.json",
    "--summary-file",
    "reports/summary.json",
    "--triage-out",
    "reports/triage-template.json",
  ]);

  assert.deepEqual(options.openApiFiles, ["openapi.json"]);
  assert.equal(options.summaryFile, "reports/summary.json");
  assert.equal(options.triageOut, "reports/triage-template.json");
});

test("parseCli includes deep assessment in the default commercial check set", () => {
  const options = parseCli(["https://example.com"]);

  assert.ok(options.checks.includes("deepassess"));
});

function contextForDeepAssess(overrides = {}) {
  const options = parseCli(["https://example.com", "--mode", "passive"]);
  return {
    options: { ...options, ...(overrides.options ?? {}) },
    targetUrl: new URL("https://example.com"),
    diagnostics: {
      attempted: 1,
      visited: 1,
      queued: 1,
      blockedByScope: 0,
      blockedByProhibitedPath: 0,
      requestFailures: [],
      skippedNonHtml: 0,
      discoveredLinks: 0,
      discoveredForms: 0,
      discoveredRouteHints: 0,
      ...(overrides.diagnostics ?? {}),
    },
    pages: overrides.pages ?? [],
  };
}

test("deepassess flags object-ID routes that need role coverage", async () => {
  const context = contextForDeepAssess({
    pages: [{
      url: "https://example.com/dashboard",
      finalUrl: "https://example.com/dashboard",
      method: "GET",
      status: 200,
      redirected: false,
      headers: {},
      body: "<a href='/students/42/grades'>grades</a>",
      elapsedMs: 1,
      requestId: "req-test",
      sizeBytes: 1,
      depth: 0,
      contentType: "text/html",
      links: ["https://example.com/students/42/grades"],
      forms: [],
      scripts: [],
      routeHints: [],
    }],
  });

  const results = await deepAssessmentCheck.run(context);
  const result = results.find((r) => r.id === "deepassess.idor-candidates-need-role-coverage");
  assert.ok(result);
  assert.equal(result.kind, "coverage-gap");
  assert.equal(result.severity, "low");
  assert.equal(result.exploitability, "none");
});

test("deepassess identifies CSRF marker gaps on state-changing forms", async () => {
  const context = contextForDeepAssess({
    pages: [{
      url: "https://example.com/profile",
      finalUrl: "https://example.com/profile",
      method: "GET",
      status: 200,
      redirected: false,
      headers: {},
      body: "<form method='post' action='/profile'><input name='email'></form>",
      elapsedMs: 1,
      requestId: "req-test",
      sizeBytes: 1,
      depth: 0,
      contentType: "text/html",
      links: [],
      forms: [{ action: "https://example.com/profile", method: "POST", inputs: [{ name: "email", type: "text" }], hasCsrfToken: false }],
      scripts: [],
      routeHints: [],
    }],
  });

  const results = await deepAssessmentCheck.run(context);
  assert.ok(results.some((r) => r.id === "deepassess.csrf-state-change-marker-missing"));
});

test("deepassess reports browser-only API surfaces from Playwright network", async () => {
  const context = contextForDeepAssess({
    diagnostics: { browserNetworkUrls: ["https://example.com/api/hidden?x=1"] },
    pages: [{
      url: "https://example.com/",
      finalUrl: "https://example.com/",
      method: "GET",
      status: 200,
      redirected: false,
      headers: {},
      body: "<html></html>",
      elapsedMs: 1,
      requestId: "req-test",
      sizeBytes: 1,
      depth: 0,
      contentType: "text/html",
      links: [],
      forms: [],
      scripts: [],
      routeHints: [],
    }],
  });

  const results = await deepAssessmentCheck.run(context);
  assert.ok(results.some((r) => r.id === "deepassess.browser-hidden-api-surfaces"));
});

test("API discovery imports OpenAPI files as operations and candidates", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wss-openapi-"));
  try {
    const specPath = join(dir, "openapi.json");
    writeFileSync(specPath, JSON.stringify({
      openapi: "3.0.0",
      paths: {
        "/api/users": { get: {} },
        "/api/users/{id}": { get: {} },
      },
    }));
    const options = parseCli(["https://example.com", "--mode", "passive", "--openapi-file", specPath]);
    const api = await discoverApis(new URL("https://example.com"), [], options);

    assert.equal(api.discoveredOperations.length, 2);
    assert.equal(api.openApiDocs[0].observed, "imported 2 operation(s)");
    assert.ok(api.candidates.includes("https://example.com/api/users"));
    assert.ok(!api.candidates.includes("https://example.com/api/users/{id}"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("finding helper classifies confirmed vulnerabilities separately from coverage gaps", () => {
  const confirmed = finding({
    id: "vulnvalidation.confirmed-open-redirect",
    check: "vulnvalidation",
    category: "Input Validation",
    status: "warn",
    severity: "medium",
    confidence: "confirmed",
    title: "Confirmed open redirect behaviour",
    detail: "A redirect parameter controlled the Location header.",
    impact: "Can support phishing or token leakage.",
    remediation: "Allow-list redirect targets.",
    exploitability: "validated",
  });
  const coverage = finding({
    id: "assurance.coverage-contract-not-met",
    check: "assurance",
    category: "Assessment Assurance",
    status: "fail",
    severity: "medium",
    title: "Assessment coverage contract was not met",
    detail: "Only one page crawled.",
    impact: "The scan cannot support assurance claims.",
    remediation: "Add seeds and authenticated coverage.",
  });

  assert.equal(confirmed.kind, "confirmed-vulnerability");
  assert.equal(coverage.kind, "coverage-gap");
  assert.equal(pass("headers", "Headers", "ok", "ok").kind, "pass");
});

test("triage overlay can suppress accepted false positives without deleting evidence", () => {
  const original = finding({
    id: "headers.missing-csp",
    check: "headers",
    category: "Security Headers",
    status: "warn",
    severity: "medium",
    title: "CSP is missing",
    detail: "Missing CSP.",
    impact: "Browser hardening is weaker.",
    remediation: "Add CSP.",
    evidence: [{ url: "https://example.com" }],
  });
  const [triaged] = applyTriage([original], { "headers.missing-csp": { status: "false-positive", owner: "appsec", note: "Static host has no script execution." } });

  assert.equal(triaged.status, "info");
  assert.equal(triaged.severity, "info");
  assert.equal(triaged.kind, "informational");
  assert.equal(triaged.evidence?.[0]?.url, "https://example.com");
});

test("fingerprints are stable across query-string noise and dedupe retains evidence", () => {
  const a = finding({
    id: "appsec.reflection",
    check: "appsec",
    category: "Input Validation",
    status: "warn",
    severity: "medium",
    title: "Reflection",
    detail: "Reflected.",
    impact: "Needs review.",
    remediation: "Encode.",
    evidence: [{ url: "https://example.com/search?q=a", parameter: "q" }],
  });
  const b = { ...a, evidence: [{ url: "https://example.com/search?q=b&page=2", parameter: "q" }] };

  assert.equal(fingerprintFor(a), fingerprintFor(b));
  const deduped = reduceFalsePositiveNoise([a, b], 3);
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].evidence?.length, 2);
  assert.equal(deduped[0].fingerprint, "appsec.reflection|https://example.com/search|q");
});

test("meta-finding filter keeps core coverage gaps but hides noisy model gaps by default", () => {
  const coverageContract = finding({
    id: "assurance.coverage-contract-not-met",
    check: "assurance",
    category: "Assessment Assurance",
    status: "fail",
    severity: "medium",
    title: "Assessment coverage contract was not met",
    detail: "Too shallow.",
    impact: "Weak assurance.",
    remediation: "Crawl more.",
  });
  const modelGap = finding({
    id: "productengine.exceptional-gaps",
    check: "productengine",
    category: "Product Engine",
    status: "warn",
    severity: "medium",
    title: "Exceptional product criteria are not fully met",
    detail: "Meta gate.",
    impact: "Meta gate.",
    remediation: "Improve evidence.",
  });

  const filtered = filterMetaFindings([coverageContract, modelGap], false);
  assert.deepEqual(filtered.map((r) => r.id), ["assurance.coverage-contract-not-met"]);
  assert.equal(filterMetaFindings([coverageContract, modelGap], true).length, 2);
});

test("benchmark metrics score actual result IDs, not just reachable surfaces", () => {
  const results = [
    { id: "vulnvalidation.confirmed-open-redirect", title: "Open redirect", severity: "medium", status: "warn" },
    { id: "vulnvalidation.confirmed-reflection", title: "Reflection", severity: "medium", status: "warn" },
  ];
  const expected = [
    { id: "expected.open-redirect", title: "Expected open redirect", resultIds: ["vulnvalidation.confirmed-open-redirect"] },
    { id: "expected.verbose-error", title: "Expected verbose error", resultIds: ["vulnvalidation.confirmed-verbose-error"] },
  ];

  const metrics = calculateBenchmarkMetrics(results, expected);

  assert.equal(metrics.truePositives, 1);
  assert.equal(metrics.falseNegatives, 1);
  assert.equal(metrics.falsePositiveCandidates, 1);
  assert.equal(metrics.precision, 0.5);
  assert.equal(metrics.recall, 0.5);
  assert.equal(metrics.f1, 0.5);
});

test("benchmark metrics separate vulnerability recall from surface and coverage matches", () => {
  const results = [
    { id: "api.route-hints-observed", title: "API routes", severity: "info", status: "info" },
    { id: "externalbenchmark.evidence-detail", title: "Reachability", severity: "info", status: "info" },
    { id: "headers.missing-csp", title: "Missing CSP", severity: "medium", status: "warn" },
  ];
  const expected = [
    { id: "api-surface", title: "API surface", resultIds: ["api.route-hints-observed"], metricType: "surface", required: true },
    { id: "benchmark-readiness", title: "Readiness", resultIds: ["externalbenchmark.evidence-detail"], metricType: "coverage", required: true },
    { id: "confirmed-reflection", title: "Confirmed reflection", resultIds: ["vulnvalidation.confirmed-reflection"], metricType: "vulnerability", required: true },
  ];

  const metrics = calculateBenchmarkMetrics(results, expected);

  assert.equal(metrics.truePositives, 0);
  assert.equal(metrics.falseNegatives, 1);
  assert.equal(metrics.falsePositiveCandidates, 1);
  assert.equal(metrics.surfaceMatches.length, 1);
  assert.equal(metrics.coverageMatches.length, 1);
});

test("scope allows approved hosts without requiring exact origin", () => {
  const target = new URL("https://app.example.com");

  assert.equal(sameOriginOnly(target, new URL("https://api.example.com/v1"), ["app.example.com", "api.example.com"]), true);
  assert.equal(sameOriginOnly(target, new URL("https://evil.example.net"), ["app.example.com", "api.example.com"]), false);
});

test("markdown reports expose finding kind", () => {
  const report = {
    tool: "WebSec Sentinel",
    version: "test",
    target: "https://example.com/",
    timestamp: new Date(0).toISOString(),
    mode: "standard",
    authorization: { authorized: false, scope: ["example.com"], authenticated: false },
    surface: {
      pagesCrawled: 0,
      uniqueHosts: [],
      technologies: [],
      formsObserved: 0,
      linksObserved: 0,
      routesObserved: 0,
      scriptsObserved: 0,
      statusCodes: {},
      authCoverage: "none",
      testedControls: ["assurance"],
    },
    quality: {
      requestCount: 0,
      evidencePolicy: "test",
      coverageContract: { minCoverageScore: 60, minPages: 1, requireAuth: false, passed: false, reasons: ["coverage weak"] },
      limitations: ["test"],
      diagnostics: { attempted: 0, visited: 0, queued: 0, blockedByScope: 0, blockedByProhibitedPath: 0, requestFailures: [], skippedNonHtml: 0, discoveredLinks: 0, discoveredForms: 0, discoveredRouteHints: 0 },
    },
    results: [
      finding({
        id: "assurance.coverage-contract-not-met",
        check: "assurance",
        category: "Assessment Assurance",
        status: "fail",
        severity: "medium",
        title: "Coverage weak",
        detail: "Coverage weak.",
        impact: "Cannot support assurance.",
        remediation: "Crawl more.",
      }),
    ],
    summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0, passed: 0, score: 50, weightedRisk: 50, coverageScore: 0, grade: "D", durationMs: 1, topCategories: [] },
    executive: { verdict: "test", businessRisk: "test", immediatePriorities: [] },
  };

  const md = renderReport(report, "markdown");
  assert.match(md, /Disclaimer:/);
  assert.match(md, /## Findings by type/);
  assert.match(md, /\| Severity \| Status \| Kind \|/);
  assert.match(md, /coverage-gap/);
});

test("report schema is committed with required product contract fields", () => {
  const schema = JSON.parse(readFileSync("schemas/report.schema.json", "utf8"));

  assert.ok(schema.required.includes("summary"));
  assert.ok(schema.required.includes("results"));
  assert.ok(schema.properties.results.items.required.includes("kind") === false);
  assert.deepEqual(schema.properties.results.items.properties.kind.enum, ["confirmed-vulnerability", "risk-signal", "coverage-gap", "scanner-diagnostic", "informational", "pass"]);
});
