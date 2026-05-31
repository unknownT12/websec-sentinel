# WebSec Sentinel

[![CI](https://github.com/unknownT12/websec-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/unknownT12/websec-sentinel/actions/workflows/ci.yml)

Defensive web security assessment CLI for authorized testing, CI gates, and evidence-based reports.

WebSec Sentinel crawls approved targets, maps routes/forms/headers/API surfaces, runs safe validation checks, and produces JSON, Markdown, HTML, and SARIF reports with coverage-aware scoring.

## Quick Start

```bash
npm install
npm test
npm run scan -- https://example.com --mode passive --save --format markdown,json
```

Requires Node.js 20+.

## Short Demo

Run the built-in local fixture to see the scanner work without touching a real target:

```bash
npm run selftest
```

Run a passive scan against a site you are allowed to test:

```bash
npm run scan -- https://example.com \
  --mode passive \
  --checks tls,headers,csp,cookies,secrets \
  --save \
  --format markdown,json
```

## Example Scan Output

Example excerpt from `npm run selftest`:

```text
WebSec Sentinel v12.0.0
Target: http://127.0.0.1:48181/login
Mode: validate | Scope: 127.0.0.1
Authorization: provided | Client: SelfTest | Assessment: SELFTEST-BOOK-MODEL
Custom headers: cookie=<redacted>
Prohibited paths: /logout, /delete, /remove, /reset, /billing, /payment, /admin/delete
Crawled 11 same-origin page(s). Forms: 3 | Links: 21 | Route hints: 12
Running productengine... ok
Running testvectors... ok
Running professionalmodel... ok
Running bookscope... ok
Running stateflow... ok
Running parammodel... 1 issue(s)
Running testmodel... 1 issue(s)
Running enginemodel... ok
Running evidencequality... ok
Running coverage... ok
Running assurance... ok
Running differential... 1 issue(s)
Running deepassess... 3 issue(s)
Running inputvalidation... ok
Running mutation... ok

Disclaimer: WebSec Sentinel reports assessment signals. Treat findings as confirmed vulnerabilities only after authorized human validation of evidence, business context, and expected access policy.

Summary
- Grade: D (44/100)
- Weighted risk: 56
- Coverage: 100/100
- Surface: 11 pages, 3 forms, 21 links, 12 route hints
- Findings: 0 critical, 2 high, 1 medium, 1 low, 7 info, 9 passed

Findings by type
- Risk signals: 3
- Coverage gaps: 1
- Informational: 7

Evidence
- reports/selftest/websec-<timestamp>.json
- reports/selftest/websec-<timestamp>.md
- reports/selftest/ledger.har.json
- reports/selftest/replay-redacted.sh
```

Findings include severity, confidence, remediation, business impact, tested controls, and redacted evidence snippets where available.

## CI/CD

This repository includes GitHub Actions workflows for continuous integration and tag-based releases:

- CI runs on pull requests and pushes to `main`.
- CI checks Node.js 20 and 22, runs linting, typechecking, tests, the local selftest, dependency audit, and a Docker build.
- Release/CD runs when a version tag such as `v12.0.1` is pushed.
- Releases create an npm package tarball, publish a Docker image to GitHub Container Registry, and attach the package artifact to a GitHub release.

Before enabling required branch protection checks, confirm the Actions workflow is green in GitHub. If GitHub Actions is blocked by an account or billing issue, required checks will fail before the workflow can start.

Create a release:

```bash
npm version patch
git push origin main --follow-tags
```

The release workflow publishes the container as:

```text
ghcr.io/unknownt12/websec-sentinel:v12.0.1
ghcr.io/unknownt12/websec-sentinel:latest
```

## What It Does

- Produces JSON, Markdown, HTML, and SARIF reports for security review and CI/CD gates.
- Scores both risk and coverage so shallow scans cannot look more complete than they are.
- Supports passive, standard, and explicitly authorized validation modes.
- Maps links, forms, scripts, route hints, headers, cookies, API surfaces, and authentication signals.
- Includes safe checks for headers, TLS, CSP, CORS, cookies, cache, auth surfaces, JWT exposure, secrets, DOM risks, and application workflow signals.
- Supports optional Playwright browser crawling for JavaScript-heavy applications.
- Includes a local dashboard for reviewing saved report history.
- Keeps generated reports, local evidence, build output, dependencies, IDE metadata, and environment files out of Git by default.

## v12.0 External Benchmark Evidence

v12 focuses on turning the project from an internal-fixture prototype into a more defensible scanner core. It adds external benchmark evidence against approved local known-vulnerable apps such as OWASP Juice Shop, DVWA, WebGoat, or a custom lab app.

The committed benchmark proof inputs are:

- [Juice Shop ground-truth contract](examples/benchmarks/juice-shop.groundtruth.json)
- [DVWA ground-truth contract](examples/benchmarks/dvwa.groundtruth.json)
- [WebGoat ground-truth contract](examples/benchmarks/webgoat.groundtruth.json)
- [Sentinel local fixture ground-truth contract](examples/benchmarks/sentinel-local.groundtruth.json)
- [External benchmark runner](tools/run-external-benchmark.mjs)
- [Internal benchmark runner](tools/run-benchmark.mjs)
- [V12 external benchmark proof notes](docs/V12_EXTERNAL_BENCHMARK_PROOF.md)

External benchmark runs produce reviewable output artifacts under the selected report directory:

- scanner JSON, Markdown, and SARIF reports
- `external-benchmark-reachability.json`
- `external-benchmark-metrics.json`
- TP / FP / FN metrics
- precision, recall, and F1 score
- JSONL request evidence, HAR-like ledger, and redacted replay file when enabled

Benchmark metric semantics are intentionally strict:

- `metricType: "vulnerability"` counts toward vulnerability TP / FP / FN, precision, recall, and F1.
- `metricType: "surface"` records route/API/workflow reachability, not vulnerability detection.
- `metricType: "coverage"` records assessment readiness or evidence quality, not vulnerability detection.
- Reachability details and coverage gaps do not count as vulnerability true positives.

Run an internal controlled benchmark:

```bash
npm run benchmark
```

Run an external benchmark against an approved local Juice Shop instance:

```bash
npm run external-benchmark -- \
  --target http://localhost:3000 \
  --ground-truth examples/benchmarks/juice-shop.groundtruth.json \
  --profile juice \
  --browser-crawl \
  --deep-crawl \
  --seed http://localhost:3000/#/login \
  --seed http://localhost:3000/#/search \
  --out reports/external-benchmark/juice
```

For release history, see [CHANGELOG.md](CHANGELOG.md).

Trust and product-readiness artifacts:

- [Security policy](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Data handling and redaction](docs/DATA_HANDLING.md)
- [Benchmark proof policy](docs/BENCHMARK_PROOF_POLICY.md)
- [Report JSON schema](schemas/report.schema.json)

**WebSec Sentinel** is a defensive web security assessment CLI for authorized testing, CI/CD gates, and report generation. It is useful as an assessment aid, but it is not a replacement for a mature DAST platform or expert manual review.

This release moves the system toward a more disciplined assessment workflow: crawl coverage, route/form/script extraction, authenticated assessment support, safe application-layer validation, deeper workflow/object/API signal detection, explicit tested-control reporting, coverage-aware scoring, baseline comparison, executive risk language, and traceable evidence handling.

## What makes this version stronger

- Evidence-driven findings with severity, confidence, finding kind, exploitability, OWASP, CWE, remediation, business impact, verification notes, false-positive notes, and priority metadata.
- Executive verdict and immediate-priority section for client-ready reporting.
- A-F grade plus weighted risk score and separate coverage score so reports cannot look stronger than the tested surface.
- Browser-like same-origin crawler with depth, page, timeout, body-size, prohibited-path, route-hint extraction, soft-404 diagnostics, and rate-limit controls.
- Repeatable `--header "Name: value"` support for authorized authenticated scans while redacting header values in logs.
- Request IDs and optional JSONL request audit log.
- Scope enforcement for approved hostnames.
- CI/CD fail gates with `--fail-on`.
- Baseline comparison using a previous JSON report.
- Reports in JSON, Markdown, HTML, and SARIF.
- Governance checks for `security.txt`, change-password routing, and engagement metadata.
- Surface analysis for risky parameters, password forms, server errors, links, forms, route hints, scripts, technologies, and status-code distribution.
- Application-layer checks for CSRF signals, password form handling, identifier-parameter review, safe reflection canaries, open-redirect validation, verbose errors, and inert validation evidence.
- `deepassess` check for deeper but still safe coverage: authenticated-vs-anonymous route comparison, IDOR-prone object-route inventory, role/object boundary signals, multi-step workflow mapping, CSRF marker gaps, second-order inert canary reappearance, and Playwright-discovered hidden API surfaces.
- Resilience checks for risky HTTP methods, server-error leakage, and sensitive-page cache control.
- Secret scanning with redacted evidence.


## Safety boundaries

This project is built for authorized defensive assessment. It does **not** include destructive payloads, persistence, credential theft, stealth/evasion, malware behavior, data extraction, or post-exploitation logic.

Validate mode uses inert canaries only. It is intended to help a security team validate specific risk signals without damaging systems or extracting sensitive records.

`deepassess` does not brute force, guess credentials, bypass login, extract records, or run destructive payloads. Its IDOR, business-logic, and auth-bypass findings are intentionally labeled as confirmed findings only when safe evidence supports that level; otherwise they remain risk signals or coverage gaps requiring approved manual validation.

## Install

```bash
npm install
npm run build
```

Requires Node.js 20+.

## Basic scan

```bash
npm run scan -- https://example.com --save --format html,markdown,json,sarif
```

## Passive production-safe scan

```bash
npm run scan -- https://example.com \
  --mode passive \
  --checks tls,headers,csp,cookies,secrets \
  --save \
  --format html,markdown,json
```

## Authorized validation-style assessment

```bash
npm run scan -- https://client.example \
  --mode validate \
  --authorized \
  --client "Client Ltd" \
  --assessment-id "AUTH-2026-001" \
  --tester "Cyber Firm Red Team" \
  --scope client.example \
  --crawl-depth 2 \
  --max-pages 150 \
  --rate-limit 250 \
  --jsonl-log reports/evidence.jsonl \
  --format html,markdown,json,sarif \
  --save
```

## Authenticated authorized scan

Use only with explicit approval from the client and avoid logout, destructive, billing, deletion, or write-heavy routes using `--prohibited-paths`.

```bash
npm run scan -- https://client.example \
  --authorized \
  --client "Client Ltd" \
  --assessment-id "AUTH-2026-001" \
  --header "Cookie: session=<client-provided-session>" \
  --header "X-Assessment-ID: AUTH-2026-001" \
  --prohibited-paths /logout,/delete-account,/billing/charge,/admin/delete \
  --crawl-depth 2 \
  --max-pages 120 \
  --rate-limit 300 \
  --save \
  --format html,markdown,json
```

## Browser crawling

`--browser-crawl` uses Playwright for JavaScript-rendered routes, DOM forms, conservative click exploration, network URLs, network counts, console-error counts, and optional login automation. Playwright is an optional peer dependency so normal installs stay small. Browser network URLs are fed into `deepassess` so SPA-only APIs can be reported even when they are not present in static links.

Use the browser Docker image when you want the simplest working browser runtime:

```bash
docker build -f Dockerfile.browser -t websec-sentinel:browser .
docker run --rm websec-sentinel:browser https://client.example \
  --browser-crawl \
  --deep-crawl \
  --save
```

For a local Node.js runtime:

```bash
npm i -D playwright
npx playwright install chromium
npm run scan -- https://client.example --browser-crawl --deep-crawl
```

If you already have a managed browser, point Playwright at it:

```bash
npm run scan -- https://client.example \
  --browser-crawl \
  --browser-channel chrome
```

or:

```bash
npm run scan -- https://client.example \
  --browser-crawl \
  --browser-executable "/path/to/chromium"
```

## Deeper Safe Assessment

Use `deepassess` with `vulnvalidation` and `rolecompare` when you have written authorization, non-production records, and approved role-labelled sessions:

```bash
npm run scan -- https://staging.example.com/login \
  --mode validate \
  --authorized \
  --require-auth \
  --header "Cookie: <student-test-session>" \
  --role-header "student|Cookie: <student-test-session>" \
  --role-header "staff|Cookie: <staff-test-session>" \
  --browser-crawl \
  --deep-crawl \
  --checks deepassess,vulnvalidation,rolecompare,workflows,api,access \
  --prohibited-paths /logout,/delete,/remove,/reset,/billing,/payment,/admin/delete \
  --save
```

This mode improves coverage for complex auth boundaries, business workflows, second-order input behavior, stored-content signals, CSRF review, IDOR candidate inventory, role comparison, and hidden API discovery. It still cannot prove absence of business-logic flaws and does not replace human review of expected role/object policy.

## Baseline comparison

After saving a JSON report, use it as a baseline for remediation retesting or release regression checks:

```bash
npm run scan -- https://staging.example.com \
  --baseline reports/previous-websec-report.json \
  --format json,markdown,html \
  --save
```

The report includes new, resolved, unchanged, and changed-severity findings.

## Local dashboard

Review saved JSON reports in a local-only dashboard:

```bash
npm run dashboard -- --reports reports --port 4173
```

Open `http://127.0.0.1:4173`. The dashboard is for local triage review of saved reports; do not expose it directly to the internet.

## Project history and triage

For repeated assessment work, use a project directory. The scanner stores a `latest.json`, timestamped history reports, an `index.json`, and automatically compares the current run with the previous project run:

```bash
npm run scan -- https://staging.example.com \
  --project-dir reports/projects \
  --project-name staging-example \
  --save \
  --format json,markdown,html
```

Triage overlays are JSON files keyed by finding id. They preserve evidence while marking known false positives or accepted risk:

```json
{
  "headers.missing-csp": {
    "status": "accepted-risk",
    "owner": "appsec",
    "note": "Temporary exception until the CSP rollout finishes."
  },
  "plugins.custom-rule": {
    "status": "false-positive",
    "owner": "security",
    "note": "Rule matched synthetic fixture content."
  }
}
```

Run with:

```bash
npm run scan -- https://staging.example.com \
  --project-dir reports/projects \
  --project-name staging-example \
  --triage-file triage.json
```

By default, the report hides some noisy model-readiness meta-findings while keeping core coverage failures. Use `--include-meta-findings` when you want the full internal model output.

## Scan policies

Commercial/repeatable scans should use a policy file so scope, thresholds, output, and safety controls are reviewable:

```json
{
  "target": "https://staging.example.com",
  "mode": "standard",
  "checks": ["coverage", "headers", "cookies", "api", "appsec"],
  "formats": ["json", "markdown", "html"],
  "projectDir": "reports/projects",
  "projectName": "staging-example",
  "openApiFiles": ["openapi.json"],
  "seedUrls": ["https://staging.example.com/login", "https://staging.example.com/api/docs"],
  "prohibitedPaths": ["/logout", "/delete", "/billing"],
  "minCoverageScore": 70,
  "minPages": 5,
  "deepCrawl": true,
  "save": true
}
```

Run:

```bash
npm run scan -- --policy staging.policy.json
```

CLI flags override policy values where supplied, for example `--min-pages 10`.

Useful CI/review artifacts:

```bash
npm run scan -- --policy staging.policy.json \
  --summary-file reports/ci-summary.json \
  --triage-out reports/triage-template.json \
  --openapi-file openapi.json
```

`--summary-file` writes a compact JSON summary with score, coverage, severity counts, kind counts, and fingerprints. `--triage-out` writes a triage template keyed by stable fingerprints so future runs can suppress accepted false positives without losing evidence.

## CI gate example

```bash
npm run scan -- https://staging.example.com \
  --mode standard \
  --fail-on high \
  --format sarif,json \
  --save
```

The command exits with code `1` if a finding at or above the selected threshold is detected.

## Scheduled scans

For simple recurring scans, create a schedule file:

```json
{
  "jobs": [
    {
      "name": "staging",
      "target": "https://staging.example.com",
      "args": ["--project-dir", "reports/projects", "--save", "--format", "json,markdown"],
      "intervalSeconds": 3600
    }
  ]
}
```

Run once:

```bash
npm run schedule -- --config schedule.json --once
```

Run continuously:

```bash
npm run schedule -- --config schedule.json
```

## Checks

| Check | Purpose |
|---|---|
| `coverage` | Explains exactly what was tested and flags weak crawl/auth coverage |
| `tls` | HTTPS, TLS, HSTS, certificate posture signals |
| `headers` | Browser security headers and information disclosure |
| `csp` | Content Security Policy weakness analysis |
| `cors` | Cross-origin policy exposure |
| `cookies` | Secure, HttpOnly, SameSite, and cookie scope review |
| `discovery` | Common sensitive path and metadata exposure |
| `auth` | Authentication surface and unauthenticated private route signals |
| `jwt` | JWT exposure and risky token characteristics in public responses |
| `secrets` | Public secret/source-map pattern detection with redaction |
| `surface` | Risky parameters, forms, status anomalies, and crawl surface signals |
| `appsec` | Safe application-layer validation for forms, CSRF signals, reflection, redirects, ID parameters, and verbose errors |
| `governance` | `security.txt`, change-password routing, and engagement metadata |
| `methodology` | Input inventory, credential-handling review, sensitive URL parameters, and inert validation canaries |
| `resilience` | Risky methods, server-error leakage, and sensitive-page cache-control review |

## Report formats

- **HTML**: executive-friendly visual report.
- **Markdown**: consulting-deliverable draft format.
- **JSON**: machine-readable full report.
- **SARIF**: CI/security dashboard integration.

## Evidence quality

The scanner records status codes, URLs, headers, request IDs, snippets, and redacted observations. It avoids storing full secrets and does not extract sensitive records.

Use `--jsonl-log reports/evidence.jsonl` to create an append-only request observation log suitable for engagement notes and reproducibility.

## Important options

```txt
--mode passive|standard|validate
--checks coverage,tls,headers,csp,cors,cookies,discovery,auth,jwt,secrets,surface,appsec,governance,methodology,resilience
--format json,markdown,html,sarif
--save
--out ./reports
--crawl-depth 2
--max-pages 150
--timeout 8000
--rate-limit 250
--max-body-bytes 1048576
--evidence-limit 10
--fail-on critical|high|medium|low|info
--scope example.com,www.example.com
--authorized
--client "Client Ltd"
--assessment-id "AUTH-001"
--tester "Your Team"
--header "Name: value"
--user-agent "Mozilla/5.0 ..."
--include-external-links
--prohibited-paths /logout,/delete-account
--baseline reports/previous.json
--include-passes
--jsonl-log reports/evidence.jsonl
--no-color
```

## Production-readiness checklist

Before running against a client system:

1. Confirm written authorization and in-scope domains.
2. Start with passive or standard mode.
3. Set conservative `--rate-limit`, `--max-pages`, and `--crawl-depth` values.
4. Use `--prohibited-paths` for logout, deletion, payment, administrative write, or fragile endpoints.
5. Use `--header` only for client-approved test accounts or tokens.
6. Save JSON and HTML reports for technical and executive audiences.
7. Use SARIF in CI/CD for repeatable security gates.
8. Re-test after remediation and compare risk score, grade, baseline deltas, and top categories.

## Development

```bash
npm run typecheck
npm run build
npm test
npm run audit:deps
```

## License

MIT

## Running with Docker

The default Node.js install no longer depends on `tsx`/`esbuild`; `npm ci`, `npm run build`, and `npm test` should work with Node.js 20+. Docker remains available for isolated scans and browser-crawl builds. This project includes a `Dockerfile`, `docker-compose.yml`, and `RUN_WITH_DOCKER.md`.

Build:

```bash
docker compose build
```

Run help:

```bash
docker compose run --rm websec-sentinel --help
```

Run a scan:

```bash
docker compose run --rm websec-sentinel https://example.com \
  --mode standard \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --crawl-depth 2 \
  --max-pages 100 \
  --rate-limit 300 \
  --save \
  --format html,markdown,json,sarif
```

Reports are saved to the local `reports/` folder.
