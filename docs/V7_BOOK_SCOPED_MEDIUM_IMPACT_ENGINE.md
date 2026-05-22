# WebSec Sentinel v7.0 — Book-Scoped Medium-Impact Engine

This upgrade deliberately stays inside the uploaded book scope: assessment lifecycle, web workflow mapping, input surface modelling, evidence discipline, repeatability, and safe validation boundaries.

It does not add destructive exploitation, credential theft, stealth, persistence, malware behavior, data extraction, or post-exploitation.

## What changed

### 1. Book-scope lifecycle gates

The new `bookscope` check measures the assessment engine against seven safe phase gates:

- authorization
- reconnaissance
- mapping
- vulnerability analysis
- safe validation
- evidence
- reporting

The scanner now fails its own model if it cannot reach at least medium impact.

### 2. Sink inventory model

The engine classifies observed routes, URL parameters, and form inputs into safe testing queues:

- identity / access-control
- redirect / navigation
- search / filter
- file transfer
- credential workflows
- state-changing workflows
- API surfaces

These are not vulnerabilities by themselves. They are a prioritized review model for authorized validation.

### 3. Workflow/state model

The new `stateflow` check builds a non-destructive transition model from parsed forms:

- source page
- form action
- method
- workflow type
- CSRF signal
- high-value workflow signal

This prevents the scanner from pretending a scan is strong when it only saw a login page and no workflow transitions.

### 4. Parameter model

The new `parammodel` check gives the engine better reasoning about application inputs:

- identity parameters imply access-control review
- redirect parameters imply navigation/allowlist review
- token/session parameters imply leakage review
- search/filter parameters imply safe canary validation

### 5. Medium-impact threshold

A scan is treated as below medium impact when it lacks the basics required by the book-scoped model:

- enough requests
- routes/pages
- forms or parameterized inputs
- authorized validate mode
- evidence/replay capability
- authenticated coverage where required

## Why this matters

The project is now less report-driven and more engine-driven. It does not simply produce a nice grade; it asks whether the assessment lifecycle, input model, workflow model, and evidence model are strong enough to support the conclusion.

## Strong command

```bash
docker build -t websec-sentinel .

docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://student-portal.example/login \
  --mode validate \
  --authorized \
  --client "Example University" \
  --assessment-id "EXAMPLE-V7-BOOK-SCOPE-001" \
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

## Book references used as safe inspiration

- The Web Application Hacker's Handbook: workflow mapping, input surfaces, session/auth thinking, evidence discipline.
- Penetration Testing: A Hands-On Introduction to Hacking: lifecycle, authorization, repeatability, validation boundaries.
- The Basics of Hacking and Penetration Testing: recon-to-report flow and beginner-friendly assessment structure.
- The Hacker Playbook 2/3: operator workflow, checklists, evidence handoff.
- RTFM: concise operator checklists and command hygiene.
- Practical Malware Analysis: cautious artefact handling, redaction, reproducibility.
- Black Hat Python and Hacking: The Art of Exploitation: defensive engineering mindset and controlled lab thinking only.

## Honest status

This should now reach at least medium impact as an authorized assessment assistant when it has authenticated coverage and meaningful seeds. It is still not a Burp/ZAP replacement and still requires human validation.
