# WebSec Sentinel v5.0 — Engine Model Upgrade

This release improves the scanner's internal testing model rather than its visual output.

## What changed

### 1. Request model
Every observed request is now normalized into an internal model containing:

- method
- original URL and final URL
- normalized route
- route key
- status class
- content type
- detected auth state
- query parameter signature
- response hash
- response family
- redirect state
- static asset classification

This makes the scanner better at explaining what it truly tested instead of relying only on raw crawled pages.

### 2. Route normalization
The model collapses volatile path segments such as numeric IDs, UUIDs, long tokens, and opaque identifiers into stable route templates. This helps detect whether the scanner reached genuinely different application routes or repeatedly hit the same workflow.

Examples:

```text
/student/12345/profile       -> /student/:number/profile
/api/user/550e8400-e29b...   -> /api/user/:uuid
/reset/ab38d92e9f0a9f...     -> /reset/:token
```

### 3. Auth-state modelling
The engine now classifies observed traffic as:

- anonymous
- authenticated-supplied
- login-wall
- forbidden
- unknown

This helps prevent shallow unauthenticated scans from being interpreted as strong assurance.

### 4. Evidence-quality checks
The new `evidencequality` module checks whether the run has enough evidence to support professional conclusions. It flags missing JSONL/HAR/replay exports, missing required authentication evidence, and weak application-layer evidence.

### 5. Engine-model checks
The new `enginemodel` module checks the scanner's own reasoning quality:

- low route diversity
- login-wall dominated scans
- duplicate request patterns
- suspected soft-404 or SPA fallback response families
- parameterized routes that were observed but not validated

### 6. Referenced methodology material
The uploaded books were used only as safe methodology inspiration, not to add weaponized exploitation. The upgrade borrows professional assessment ideas such as lifecycle discipline, workflow mapping, evidence hygiene, operator repeatability, and report defensibility.

Referenced titles include:

- The Web Application Hacker's Handbook
- Penetration Testing: A Hands-On Introduction to Hacking
- The Basics of Hacking and Penetration Testing
- The Hacker Playbook 2
- The Hacker Playbook 3
- RTFM: Red Team Field Manual
- Practical Malware Analysis
- Black Hat Python
- Hacking: The Art of Exploitation

## What this does not do

This release does not add destructive exploitation, credential theft, persistence, stealth, malware behavior, unauthorized access automation, or data extraction. It improves defensive assessment quality, evidence strength, and scanner self-awareness.

## Recommended professional command

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://example.com \
  --mode validate \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --seed https://example.com/dashboard \
  --require-auth \
  --min-coverage-score 75 \
  --min-pages 5 \
  --prohibited-paths /logout,/delete,/remove,/reset,/billing,/payment,/admin/delete \
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
