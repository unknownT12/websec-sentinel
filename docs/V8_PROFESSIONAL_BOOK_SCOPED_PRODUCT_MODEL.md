# WebSec Sentinel v8.0 — Professional Book-Scoped Product Model

This upgrade focuses on the engine/model rather than the UI. The goal is to move the project from a prototype-style scanner into a medium-impact assessment product core within the methodology boundary of the uploaded books.

## What changed

### 1. Professional control objective model
The engine now evaluates explicit control objectives instead of only producing findings. The model covers:

- scoping and authorization
- reconnaissance/request ledger
- application surface mapping
- authenticated-state separation
- session-management signals
- access-control differential readiness
- input-handling model coverage
- workflow integrity and state-changing form fencing
- API/JSON surface separation
- client-side route mining
- privacy/cache review
- error/soft-404 false-positive control
- evidence repeatability

Each objective records required evidence, status, confirmation level, reason, and weight.

### 2. Product maturity gates
v8 introduces maturity gates that decide whether the scan behaves like:

- prototype
- assessment assistant
- medium-impact product
- professional-ready core

A shallow scan is now downgraded at the engine level, not merely described in the report.

### 3. Model-driven safe test cases
The engine generates a controlled test case plan from discovered surfaces. It does not generate exploit payloads. Instead, each test case includes:

- domain
- route and method
- priority
- preconditions
- safe procedure
- confirmation gate
- evidence to capture
- destructive=false

This makes the system behave more like a repeatable professional assessment workflow.

### 4. Book-scoped methodology boundary
The uploaded books were used as methodology scope, safely translated into:

- lifecycle discipline
- mapping before validation
- evidence-first assessment
- input surface modelling
- access-control thinking
- session/workflow review
- operator repeatability
- redacted proof handling

No destructive exploitation, credential theft, stealth, persistence, malware behaviour, or data extraction was implemented.

### 5. Built-in self-test fixture
v8 includes a local self-test fixture to prove the model can crawl, classify, and generate product-grade test cases against a controlled app.

Run:

```bash
npm run selftest
```

The fixture includes login, dashboard, student-data, API, parameterized routes, forms, JavaScript route hints, robots, and sitemap.

## Why this is more product-like

Previous versions could look strong while still being shallow. v8 improves the core model so the scanner asks:

- Did we actually map the application?
- Did we distinguish public from authenticated surface?
- Did we generate safe tests from observed routes/inputs?
- Did we capture repeatable evidence?
- Which controls were verified, observable, or not covered?
- Should this scan be treated as a product-grade result or downgraded?

That is a product-engine improvement, not a UI improvement.
