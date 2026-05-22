# WebSec Sentinel v12

## v12.0 External Benchmark Evidence

v12 focuses on turning the project from an internal-fixture prototype into a more defensible scanner core. It adds external benchmark evidence against approved local known-vulnerable apps such as OWASP Juice Shop, DVWA, WebGoat, or a custom lab app.

The key change is that benchmark claims now require evidence artifacts:

- external ground-truth JSON contracts
- external benchmark runner
- TP / FP / FN metrics
- precision, recall, and F1 score
- browser-crawl trace support
- deeper safe assessment layer for auth-boundary, IDOR-candidate, CSRF, workflow, second-order, and browser-hidden API signals
- HAR-like request ledger
- redacted replay file
- benchmark reachability artifact plus post-report result-ID matching
- case-study-ready report package

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

See `docs/V12_EXTERNAL_BENCHMARK_PROOF.md`.

---


## v8.0 Professional Book-Scoped Product Model

v8 focuses on the scanner engine, not the UI. It adds a professional control-objective model, maturity gates, and model-driven safe test cases derived from the uploaded hacking/security books as methodology scope. The scanner now separates prototype-level runs from medium-impact product-level runs using evidence, authenticated-state coverage, application mapping depth, and repeatability.

Useful command:

```bash
npm run selftest
```

This runs a local controlled fixture and proves the engine can crawl routes, detect forms/parameters, classify high-value surfaces, and generate safe test cases without destructive exploitation.


## v4.0 Assurance Build

This build focuses on measurable testing quality rather than cosmetic UI. It adds coverage contracts, seed URLs, authenticated-assessment requirements, safe input-validation canaries, attack-path reasoning, redacted HAR-like evidence exports, and replay files for manual verification.

Professional scans should use `--require-auth`, `--min-coverage-score`, `--min-pages`, approved `--seed` URLs, and `--prohibited-paths` so the report clearly states whether it has enough evidence to support its grade.

See `docs/V4_PROFESSIONAL_ASSURANCE_UPGRADE.md`.


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


## What changed in v2.3

This version directly addresses the weaknesses from the earlier report:

1. **Crawler reliability**: the crawler now uses a browser-like default user agent, extracts normal links, asset links, JavaScript route hints, scripts, titles, and forms, and records request diagnostics when no pages are collected.
2. **Forms, links, technologies, and routes**: reports now show pages, forms, links, route hints, scripts, technologies, status-code distribution, and tested controls.
3. **Authenticated testing**: repeated `--header` support remains, but reports now explicitly label whether authenticated coverage was supplied.
4. **Application-layer validation**: new `appsec` checks safely review CSRF signals, password forms, identifier parameters, reflection canaries, open redirect behavior, and verbose error leakage without destructive exploitation.
5. **Honest scoring**: grade now includes a coverage penalty and a separate coverage score. A zero-page crawl can no longer produce a polished-looking high-confidence report.
6. **What did it test?**: terminal, JSON, Markdown, HTML, and SARIF outputs now include tested controls and crawler diagnostics.

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

## v2.4 exceptional testing depth

This build improves testing depth rather than UI. New modules include `methods`, `cache`, `dom`, `access`, and `api`. The crawler can now use `--deep-crawl` to mine same-origin JavaScript for route hints and non-passive scans seed from `robots.txt` / `sitemap.xml`. Reports are coverage-aware so a shallow scan cannot look more impressive than it actually is.

Recommended deep validation command:

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://example.com \
  --mode validate \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --crawl-depth 3 \
  --max-pages 300 \
  --rate-limit 500 \
  --deep-crawl \
  --jsonl-log reports/evidence.jsonl \
  --save \
  --format html,markdown,json,sarif
```


## v3.0 Forward Security Intelligence

This build adds forward-looking assessment modules that go beyond normal header scanning:

- `foresight` — predictive route and attack-path intelligence
- `workflows` — login/reset/state-changing workflow assurance
- `composition` — frontend supply-chain and script integrity review
- `mutation` — authorized safe adaptive parameter validation

The goal is not to claim “no vulnerabilities exist.” The goal is to answer a better professional question:

> What surface was actually tested, what workflows were reached, what high-value routes were mapped, and what still needs manual role-pair validation?

Strongest safe run:

```bash
docker run --rm   -v "$PWD/reports:/app/reports"   websec-sentinel   https://example.com/login   --mode validate   --authorized   --client "Client Name"   --assessment-id "AUTH-2026-001"   --tester "Assessment Team"   --scope example.com   --crawl-depth 4   --max-pages 500   --rate-limit 500   --deep-crawl   --jsonl-log reports/evidence.jsonl   --save   --format html,markdown,json,sarif
```


## v5.0 Engine Model

This build focuses on the scanner model, not the report UI. It adds an internal request/evidence model that normalizes routes, classifies auth state, groups duplicate requests, detects soft-404 style response families, and checks whether evidence is strong enough for professional conclusions.

New checks:

- `enginemodel` — evaluates route diversity, duplicate request quality, login-wall dominance, parameter coverage, and soft-404/fallback behaviour.
- `evidencequality` — evaluates whether JSONL/HAR/replay evidence, authenticated evidence, and application-layer evidence are strong enough for the declared assessment.

The methodology references from the uploaded books were applied only as defensive assessment principles: lifecycle discipline, workflow mapping, evidence hygiene, repeatability, and safe validation boundaries. No destructive exploitation, stealth, persistence, credential theft, or data extraction has been added.

See `docs/V5_ENGINE_MODEL_UPGRADE.md` for details.

## v6.0 Book-Referenced Engine Model

Version 6 improves the underlying scanner model rather than the report appearance.

New engine-level features:

- surface-node classification and risk weighting
- explicit control expectation matrix
- high-value safe test hypotheses
- authenticated vs anonymous differential access checks
- stronger distinction between findings, signals, hypotheses, and coverage gaps
- improved professional honesty around what was actually tested

The uploaded security books were used only as safe methodology references for assessment lifecycle, workflow mapping, evidence handling, repeatability, and validation discipline. No destructive exploitation, credential theft, persistence, stealth, malware behaviour, or data extraction was added.

Useful focused run:

```bash
npm run scan -- https://example.com --checks testmodel,differential,enginemodel,evidencequality --mode validate --authorized --header "Cookie: <approved-test-session>"
```


## v7.0 Book-Scoped Medium-Impact Engine

This version focuses on improving the scanner model rather than the report output. The new engine is constrained to the uploaded book scope and adds:

- `bookscope` lifecycle gates for authorization, recon, mapping, vulnerability analysis, safe validation, evidence, and reporting
- `stateflow` workflow/state modelling from forms and high-value transitions
- `parammodel` parameter/input classification for identity, redirect, credential, API, file, state-change, and search surfaces
- medium-impact threshold logic so shallow scans are called out instead of over-scored
- stronger safe testing queues based on what was actually crawled and modelled

See `docs/V7_BOOK_SCOPED_MEDIUM_IMPACT_ENGINE.md`.

## v9 Exceptional Book-Scoped Product Engine

v9 focuses on the scanner model rather than the UI. It adds `productengine` and `testvectors` checks that evaluate whether a run has enough scoped authorization, route/form/parameter coverage, authenticated-state separation, safe validation readiness, false-positive controls, and replayable evidence to be treated as a medium-impact product run. See `docs/V9_EXCEPTIONAL_BOOK_SCOPED_PRODUCT_ENGINE.md`.

## v10 Product Engine: benchmarks, browser crawling, role testing and plugins

v10 moves the project toward product evidence rather than better-looking output. The main additions are benchmark profiles, optional browser-based crawling with JavaScript execution, approved login automation, role-based comparison, safe plugin rules, false-positive grouping, and a validation matrix.

Run the local benchmark fixture:

```bash
npm run benchmark
```

Build the browser-enabled Docker image:

```bash
docker build -f Dockerfile.browser -t websec-sentinel:browser .
```

Use browser crawling and approved login automation:

```bash
docker run --rm -v "$PWD/reports:/app/reports" websec-sentinel:browser \
  https://client.example/login \
  --mode validate \
  --authorized \
  --client "Client" \
  --assessment-id "AUTH-001" \
  --scope client.example \
  --browser-crawl \
  --login-url https://client.example/login \
  --login-username "approved-test-user" \
  --login-password "approved-test-password" \
  --seed https://client.example/dashboard \
  --prohibited-paths /logout,/delete,/remove,/billing,/payment \
  --jsonl-log reports/evidence.jsonl \
  --har reports/ledger.har.json \
  --replay-file reports/replay-redacted.sh \
  --save \
  --format html,markdown,json,sarif
```

See `docs/V10_PRODUCT_BENCHMARK_BROWSER_ROLE_ENGINE.md` for details.


## v11 confirmed product-engine upgrade

This build focuses on the scanner model, not the UI. The main improvement is that benchmark and application-layer checks now move beyond route/keyword signals toward reproducible safe validation.

New engine capabilities:

- `vulnvalidation` confirms safe reflected-input, open-redirect, verbose-error, and role-boundary behaviours when evidence exists.
- `proofmetrics` scores hard product evidence: benchmark profile, browser trace, role sessions, JSONL, HAR, replay, page depth, form coverage, and parameter coverage.
- `npm run benchmark` now produces `reports/benchmark/benchmark-metrics.json` with TP/FP/FN, precision, recall, and F1 against a controlled local fixture.
- The browser crawler now performs workflow-oriented Playwright crawling, conservative click exploration, SPA route extraction, login automation, and network/console tracing.
- Role comparison uses approved labelled sessions and produces reproducible evidence IDs.

Run the benchmark:

```bash
npm run benchmark
cat reports/benchmark/benchmark-metrics.json
```

Browser-enabled Docker runtime:

```bash
docker build -f Dockerfile.browser -t websec-sentinel-browser .
```

See `docs/V11_CONFIRMED_PRODUCT_ENGINE.md` for details.
