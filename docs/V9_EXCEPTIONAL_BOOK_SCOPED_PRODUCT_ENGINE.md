# WebSec Sentinel v9 — Exceptional Book-Scoped Product Engine

This release continues the book-scoped development line and focuses on the internal assessment model, not the report UI.

The goal of v9 is to move the project from a polished assessment assistant toward a product core that can explain whether a run is genuinely ready for medium-impact or exceptional controlled assessment work.

## Scope boundary

The model remains constrained to the uploaded book library as methodology inspiration:

- **The Web Application Hacker's Handbook**: web workflow mapping, parameter modelling, session/access-control thinking, evidence-first application review.
- **Penetration Testing: A Hands-On Introduction** and **The Basics of Hacking and Penetration Testing**: authorization, reconnaissance, mapping, validation, evidence and reporting lifecycle gates.
- **The Hacker Playbook 2/3** and **RTFM**: operator flow, repeatability, handoff hygiene and concise assessment discipline.
- **Practical Malware Analysis**: evidence hygiene, artefact handling and redaction discipline only.
- **Black Hat Python** and **Hacking: The Art of Exploitation**: defensive engineering mindset, input modelling and controlled lab validation thinking only.

No destructive exploitation, credential theft, persistence, stealth, malware behaviour or data extraction was added.

## What changed in the model

### 1. Product engine gates

The new `productengine` check measures whether the scanner behaves like a product instead of a prototype. It evaluates:

- engagement safety and scope controls
- request-ledger reconnaissance
- route/form/parameter/client-side surface modelling
- authenticated-state separation
- session/token review readiness
- differential access-control readiness
- safe input-validation oracles
- state-changing workflow fences
- API/client-side coverage
- repeatable evidence exports
- false-positive controls
- operator productization
- regression/self-test readiness
- convergence with the professional and book-scope models

### 2. Product test vectors

The new `testvectors` check generates safe assessment vectors from the observed surface instead of relying on generic scanner wording. Vectors are generated for:

- high-value access-control routes
- parameterized inputs
- state-changing workflows

Each vector includes:

- intent
- priority
- run prerequisites
- safe steps
- evidence contract
- promotion rule

### 3. Exceptional readiness

v9 distinguishes:

- `prototype`
- `usable-assessment-assistant`
- `medium-impact-product`
- `professional-product-core`
- `exceptional-controlled-product`

A run is not considered exceptional unless it has strong score, no failed gates, authenticated high-value coverage, parameterized surfaces and JSONL + HAR + replay evidence.

## Recommended v9 command

```bash
docker build -t websec-sentinel .

docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://example.com/login \
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

## Honest product boundary

v9 is materially stronger as a product model because it fails weak runs, generates safe test vectors, and insists on evidence repeatability. It is still not a replacement for Burp/ZAP/Nuclei or manual expert testing. It is best positioned as a book-scoped, authorized, evidence-driven web assessment engine for learning, internal assessment support and medium-impact controlled reviews.
