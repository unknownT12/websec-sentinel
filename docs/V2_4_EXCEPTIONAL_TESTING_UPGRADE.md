# WebSec Sentinel v2.4 Exceptional Testing Upgrade

This release focuses on testing depth instead of visual polish. The goal is to make every report answer the question a serious cyber firm would ask first: **what did this tool actually test, and how reliable is the evidence?**

## Major improvements

### 1. Deep crawl mode
- Added `--deep-crawl`.
- Validate mode automatically mines same-origin JavaScript assets for client routes.
- The crawler now extracts:
  - page links
  - form actions
  - script sources
  - JavaScript route strings
  - meta refresh targets
  - robots.txt and sitemap.xml URLs in non-passive modes

### 2. More honest coverage
- Coverage score now matters more because reports should not look impressive when the crawler saw almost nothing.
- Diagnostics include discovered links, forms, route hints, script-mined routes, fetched scripts, blocked paths, and request failures.

### 3. New testing modules

#### `methods`
Safely checks advertised HTTP methods using `OPTIONS` only. It flags dangerous or unexpected methods without sending destructive write requests.

#### `cache`
Checks whether sensitive login/account/student-grade style pages are missing strong anti-cache headers.

#### `dom`
Reviews HTML and JavaScript assets for risky client-side sinks such as `innerHTML`, `document.write`, `eval`, dynamic navigation, web-storage token usage, and weak randomness.

#### `access`
Maps sensitive routes and safely checks for unauthenticated sensitive-route exposure signals without credential guessing, brute force, or data extraction.

#### `api`
Maps API/schema/documentation exposure and checks unauthenticated JSON responses for sensitive-field signals with redacted evidence.

### 4. Better TypeScript/portfolio value
The scanner now demonstrates stronger engineering depth:
- modular checks
- evidence objects
- scope controls
- prohibited paths
- Docker compatibility
- SARIF/JSON/HTML/Markdown outputs
- coverage-aware risk scoring
- CI-friendly fail gates
- safe validation boundaries

## Recommended high-depth command

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

## What this still does not do

This is intentionally not a destructive exploit framework. It does not perform credential theft, persistence, stealth, malware behavior, destructive writes, brute force, or data extraction. It is designed for authorized assessment acceleration and safe proof-of-risk reporting.
