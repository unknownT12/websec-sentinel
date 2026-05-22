# WebSec Sentinel v11 — Confirmed Product Engine

This release is scoped to the uploaded books as methodology inspiration, but it moves the project away from prototype-style model checks and toward product-grade evidence.

## What changed

### 1. Confirmed vulnerability validation
The new `vulnvalidation` module performs safe, reproducible validation checks instead of only keyword or route matching.

It can confirm, using inert/non-destructive requests:

- reflected input behaviour
- open redirect behaviour
- verbose error disclosure
- role-boundary concerns using approved role-labelled sessions

Findings from this module are marked as validated only when a safe request produces evidence.

### 2. Better browser crawler model
The browser crawler is now closer to a real workflow crawler:

- uses Playwright when available
- supports login automation
- follows DOM-discovered links and routes
- extracts SPA route hints from DOM and scripts
- records console and network activity
- performs conservative click exploration while avoiding dangerous text such as delete/logout/pay/reset

Use `Dockerfile.browser` for browser-enabled scans.

### 3. Benchmark precision and recall
`npm run benchmark` now runs a controlled local vulnerable fixture with known ground truth.

The benchmark produces:

- `reports/benchmark/benchmark-metrics.json`
- true positives
- false positives
- false negatives
- precision
- recall
- F1 score

The local fixture currently contains expected safe confirmations for:

- reflected input
- open redirect
- verbose error disclosure
- role-boundary concern

### 4. Product proof metrics
The new `proofmetrics` module scores whether an assessment has enough hard evidence to support strong product claims.

It checks for:

- benchmark profile
- browser execution
- role differential readiness
- HAR export
- replay export
- JSONL evidence ledger
- page depth
- form coverage
- parameter coverage

### 5. Role-differential evidence
Role testing is still non-destructive and requires approved role sessions.

Example:

```bash
--role-header "student|Cookie: ..." \
--role-header "lecturer|Cookie: ..."
```

The scanner compares high-value routes using separate approved sessions and records reproducible request IDs.

## What this version still does not claim

This version does not claim to replace Burp Suite, OWASP ZAP, Nuclei, or manual testing. It also does not perform destructive exploitation, credential theft, persistence, stealth, malware behaviour, or data extraction.

The improvement is that it now has a stronger product core: benchmarked, reproducible, role-aware, browser-capable, and less dependent on shallow signal matching.

## Commands

Standard build:

```bash
npm run typecheck
npm run build
npm run benchmark
```

Browser-enabled Docker build:

```bash
docker build -f Dockerfile.browser -t websec-sentinel-browser .
```

Browser workflow scan:

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel-browser \
  https://target.example/login \
  --mode validate \
  --authorized \
  --client "Approved Client" \
  --assessment-id "AUTH-001" \
  --scope target.example \
  --browser-crawl \
  --login-url https://target.example/login \
  --login-username "test@example.com" \
  --login-password "REDACTED" \
  --deep-crawl \
  --jsonl-log reports/evidence.jsonl \
  --har reports/ledger.har.json \
  --replay-file reports/replay-redacted.sh \
  --save \
  --format json,markdown,html,sarif
```
