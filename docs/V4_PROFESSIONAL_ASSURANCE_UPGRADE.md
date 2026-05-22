# WebSec Sentinel v4.0 — Professional Assurance Upgrade

This release moves the project from “scanner with many checks” toward a defensible professional assessment product.

## Brutal honesty improvements

The tool now refuses to let a shallow scan look impressive. It adds explicit coverage contracts and report penalties when the scanner does not crawl enough pages, does not observe forms/routes, or lacks the authenticated coverage required for the engagement.

## New capabilities

- `--seed <url>`: add approved same-origin seed URLs for dashboards, known routes, or client-provided paths.
- `--min-coverage-score <n>`: define the required evidence/coverage threshold.
- `--min-pages <n>`: define the minimum crawled surface required for assurance.
- `--require-auth`: mark an assessment incomplete unless a session/auth header is supplied.
- `--har <file>`: save a redacted HAR-like request ledger.
- `--replay-file <file>`: save redacted curl commands for manual verification.
- `assurance` module: enforces the coverage contract.
- `inputvalidation` module: safe inert-canary testing for GET/search-style inputs only.
- `riskchain` module: non-exploitative attack-path hypotheses built from observed routes, forms, cache, and auth coverage.

## Why this matters

A professional security report must answer:

- What was actually requested?
- What pages, routes, forms, scripts, and parameters were observed?
- Was the scan authenticated?
- What validation was performed?
- What was not tested?
- Can an engineer reproduce the evidence?

v4.0 adds those controls directly into the product.

## Strong professional command

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://student-portal.example/login \
  --mode validate \
  --authorized \
  --client "Example University" \
  --assessment-id "EXAMPLE-PROFESSIONAL-ASSURANCE-001" \
  --tester "Assessment Team" \
  --scope student-portal.example \
  --seed https://student-portal.example/dashboard \
  --require-auth \
  --min-coverage-score 75 \
  --min-pages 5 \
  --prohibited-paths /logout,/delete,/remove,/reset,/change-password,/admin/delete,/billing,/payment \
  --crawl-depth 4 \
  --max-pages 500 \
  --rate-limit 700 \
  --deep-crawl \
  --jsonl-log reports/evidence.jsonl \
  --har reports/request-ledger.har.json \
  --replay-file reports/replay-redacted.sh \
  --save \
  --format html,markdown,json,sarif
```

## Safety boundary

This remains defensive and authorized. It does not perform destructive exploitation, credential theft, persistence, stealth, malware behavior, or data extraction.
