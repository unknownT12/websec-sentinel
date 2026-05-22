# WebSec Sentinel v3.0 — Forward Security Upgrade

This release moves the project away from a traditional checklist scanner and toward a forward-looking assessment engine.

## What changed

### 1. Predictive surface intelligence
The new `foresight` module builds a lightweight model of routes, scripts, forms, workflow signals, route classes, and graph chokepoints. Instead of only saying what headers are missing, it tells the assessor which routes deserve manual role-pair testing first.

### 2. Workflow assurance
The new `workflows` module models login, password reset, registration, state-changing forms, CSRF visibility, and authenticated coverage gaps. This directly addresses the top cyber-firm question: **what business workflows were actually tested?**

### 3. Frontend composition review
The new `composition` module reviews external scripts, Subresource Integrity usage, and frontend library/version markers. This treats the browser bundle as part of the security boundary, which is critical for modern TypeScript/SPA systems.

### 4. Safe adaptive validation
The new `mutation` module performs controlled, non-destructive query-parameter mutation in authorized validate mode only. It uses inert canaries to detect fragile error handling, reflection sinks, and status deltas without executing exploit payloads or extracting data.

### 5. Better professional positioning
The tool is now positioned as a defensive assessment accelerator with:

- deep crawling
- JavaScript route mining
- authenticated assessment support
- workflow modeling
- predictive route prioritization
- coverage-aware scoring
- evidence handling
- CI/SARIF output
- Docker support for older Macs

## What it still does not do

This project intentionally avoids destructive exploitation, persistence, stealth, credential theft, shell access, malware behavior, and data extraction. It is designed to support authorized security assessment and professional reporting, not unauthorized attacks.

## Strongest safe command

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://client.example/login \
  --mode validate \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope client.example \
  --crawl-depth 4 \
  --max-pages 500 \
  --rate-limit 500 \
  --deep-crawl \
  --jsonl-log reports/evidence.jsonl \
  --save \
  --format html,markdown,json,sarif
```
