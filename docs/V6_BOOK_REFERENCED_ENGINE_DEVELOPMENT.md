# WebSec Sentinel v6.0 — Book-Referenced Engine Development

This release focuses on the scanner's testing model rather than the visual report layer.

## Safety boundary

The uploaded books were used as methodology inspiration only: assessment lifecycle, workflow mapping, evidence handling, repeatability, and cautious validation. This release does not implement destructive exploitation, credential theft, persistence, stealth, malware behaviour, or data extraction.

## What changed in the engine

### 1. Surface-node model

The scanner now converts crawled pages into ranked surface nodes. Each node captures:

- normalized route
- method
- parameters
- form count
- state-changing workflow signals
- password/authentication signals
- CSRF-token signals
- semantic classes such as authentication, account recovery, admin, student-data, API, file-transfer, search/filter, and authorization
- risk weight based on business impact and test value

This is designed to make the scanner ask: **which observed surfaces deserve deeper attention?**

### 2. Control expectation matrix

The scanner now builds an explicit control matrix for:

- transport
- security headers
- cookies
- authentication
- access control
- CSRF
- input validation
- API exposure
- client-side route coverage
- evidence quality

Each control is marked as `tested`, `partially-tested`, or `not-tested`. This prevents the tool from implying that a control passed when it was never exercised.

### 3. High-value test hypotheses

Instead of blindly probing, the scanner generates prioritized safe test hypotheses. Examples:

- verify access-control boundary on admin/student-data routes
- review CSRF on state-changing workflows
- validate parameter handling using inert canaries
- close auth/client-side/input-validation coverage gaps before assurance claims

Hypotheses are deliberately not reported as vulnerabilities. They are follow-up test plans with evidence gates.

### 4. Authenticated vs anonymous differential checks

When an approved session header is supplied, v6 safely replays selected high-value GET routes without that session to compare:

- status codes
- login redirects
- response family similarity
- protected-route exposure signals

This helps identify possible broken access-control or cache exposure signals without extracting data or modifying state.

### 5. Stronger professional honesty

The tool now distinguishes:

- a vulnerability
- a signal
- a hypothesis
- a coverage gap
- a control that was not tested

This makes the engine more useful for serious assessment work because it reduces overclaiming.

## Book-inspired mapping

- Web application workflow mapping inspired the surface-node and form/control matrix model.
- Penetration testing lifecycle discipline inspired the readiness score and evidence gates.
- Red-team operator references inspired repeatability, runbook thinking, and redacted replay evidence.
- Malware-analysis style caution inspired evidence hygiene and safe artefact handling.
- Exploitation-oriented material was not weaponized; it was converted into defensive validation boundaries and confidence gates.

## Recommended v6 command

```bash
docker build -t websec-sentinel .

docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://student-portal.example/login \
  --mode validate \
  --authorized \
  --client "Example University" \
  --assessment-id "EXAMPLE-V6-ENGINE-001" \
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
