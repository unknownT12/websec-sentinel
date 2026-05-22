# WebSec Sentinel v10 — Product Benchmark, Browser, Role and Validation Engine

This version stays inside the uploaded book scope: disciplined authorization, reconnaissance, web workflow mapping, safe validation, evidence handling, repeatability, and reporting. The goal is to make the engine behave more like a product and less like a prototype.

## What changed in the model/engine

- Benchmark profiles for known vulnerable/lab apps: `sentinel`, `juice`, and `dvwa`.
- Optional real browser crawling with Playwright through `--browser-crawl`.
- Optional approved login automation through `--login-url`, `--login-username`, and `--login-password`.
- Role-based comparison using repeatable `--role-header "role|Header: value"` inputs.
- Safe declarative plugin/rule architecture through `--rules-dir` plus built-in safe rules.
- False-positive noise reduction by grouping similar findings by finding, route, and parameter.
- Validation matrix scoring for coverage, evidence exports, browser execution, role testing, and benchmarks.
- Benchmark fixture and repeatable command: `npm run benchmark`.
- Browser-enabled Dockerfile: `Dockerfile.browser`.

## Product gates added

v10 is stricter about product claims. A professional run should include:

1. Adequate crawl depth and seeds.
2. Browser execution for modern JavaScript apps.
3. Authenticated coverage using approved test accounts or session headers.
4. Role comparison where the client approves multiple test roles.
5. HAR, JSONL, and replay evidence exports.
6. Benchmark profile evidence against a controlled fixture or known vulnerable app.
7. Plugin rules that are safe, declarative, and reviewable.

## Browser-enabled Docker build

```bash
docker build -f Dockerfile.browser -t websec-sentinel:browser .
```

Example:

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel:browser \
  https://example.test/login \
  --mode validate \
  --authorized \
  --client "Client" \
  --assessment-id "AUTH-001" \
  --scope example.test \
  --browser-crawl \
  --login-url https://example.test/login \
  --login-username "approved-test-user" \
  --login-password "approved-test-password" \
  --seed https://example.test/dashboard \
  --require-auth \
  --min-coverage-score 80 \
  --min-pages 5 \
  --prohibited-paths /logout,/delete,/remove,/billing,/payment \
  --jsonl-log reports/evidence.jsonl \
  --har reports/ledger.har.json \
  --replay-file reports/replay-redacted.sh \
  --benchmark-profile sentinel \
  --save \
  --format html,markdown,json,sarif
```

## Role comparison

Use only approved test accounts. Example:

```bash
--role-header "student|Cookie: student_session=..." \
--role-header "lecturer|Cookie: lecturer_session=..."
```

The engine performs safe GET comparisons and reports role-boundary uncertainty or similar high-value responses. It does not attempt destructive state changes.

## Benchmarking

Run the built-in benchmark fixture:

```bash
npm run benchmark
```

This starts a local lab target, runs the scanner, and saves JSON/Markdown/HAR/replay evidence under `reports/benchmark`.

## What v10 still does not claim

- It does not prove absence of vulnerabilities.
- It does not replace expert manual review.
- It does not perform destructive exploitation, credential theft, persistence, stealth, or data extraction.
- It does not claim to outperform Burp/ZAP/Nuclei unless benchmark evidence is produced and reviewed.
