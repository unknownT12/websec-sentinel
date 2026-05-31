# Changelog

All notable project changes are summarized here. Detailed upgrade notes remain in `docs/`.

## v12.0.0

- Added external benchmark proof support for approved local known-vulnerable apps such as OWASP Juice Shop, DVWA, WebGoat, and custom lab targets.
- Added committed ground-truth contracts in `examples/benchmarks/`.
- Added `tools/run-external-benchmark.mjs` for post-report TP/FP/FN, precision, recall, and F1 scoring.
- Added benchmark reachability evidence and case-study package guidance.
- Added deeper safe assessment signals for auth-boundary, IDOR-candidate, CSRF, workflow, second-order, and browser-hidden API review.

See `docs/V12_EXTERNAL_BENCHMARK_PROOF.md`.

## v11.0.0

- Moved benchmark and application-layer checks beyond route/keyword signals toward reproducible safe validation.
- Added `vulnvalidation` for safe reflected-input, open-redirect, verbose-error, and role-boundary evidence when present.
- Added `proofmetrics` for hard product evidence scoring.
- Updated `npm run benchmark` to produce TP/FP/FN, precision, recall, and F1 metrics for the controlled local fixture.
- Improved browser workflow crawling, SPA route extraction, login automation, and network/console tracing.

See `docs/V11_CONFIRMED_PRODUCT_ENGINE.md`.

## v10.0.0

- Added benchmark profiles, optional browser crawling, approved login automation, role-based comparison, safe plugin rules, false-positive grouping, and validation matrix support.
- Added browser-enabled Docker workflow guidance.

See `docs/V10_PRODUCT_BENCHMARK_BROWSER_ROLE_ENGINE.md`.

## v9.0.0

- Added `productengine` and `testvectors` checks for scoped authorization, route/form/parameter coverage, authenticated-state separation, safe validation readiness, false-positive controls, and replayable evidence.

See `docs/V9_EXCEPTIONAL_BOOK_SCOPED_PRODUCT_ENGINE.md`.

## v8.0.0

- Added a professional control-objective model, maturity gates, and model-driven safe test cases.
- Separated prototype-level runs from medium-impact product-level runs using evidence, authenticated-state coverage, application mapping depth, and repeatability.

See `docs/V8_PROFESSIONAL_BOOK_SCOPED_PRODUCT_MODEL.md`.

## v7.0.0

- Added `bookscope`, `stateflow`, and `parammodel` checks.
- Added medium-impact threshold logic and safer testing queues based on crawled/modelled surface.

See `docs/V7_BOOK_SCOPED_MEDIUM_IMPACT_ENGINE.md`.

## v6.0.0

- Added surface-node classification, risk weighting, control expectation matrix, safe test hypotheses, and authenticated-vs-anonymous differential access checks.
- Strengthened distinction between findings, signals, hypotheses, and coverage gaps.

See `docs/V6_BOOK_REFERENCED_ENGINE_DEVELOPMENT.md`.

## v5.0.0

- Added an internal request/evidence model for normalized routes, auth state, duplicate request grouping, soft-404 families, and evidence-strength checks.
- Added `enginemodel` and `evidencequality`.

See `docs/V5_ENGINE_MODEL_UPGRADE.md`.

## v4.0.0

- Added coverage contracts, seed URLs, authenticated-assessment requirements, safe input-validation canaries, attack-path reasoning, redacted HAR-like evidence exports, and replay files.

See `docs/V4_PROFESSIONAL_ASSURANCE_UPGRADE.md`.

## v3.0.0

- Added forward-looking assessment modules: `foresight`, `workflows`, `composition`, and `mutation`.
- Emphasized tested surface, reached workflows, mapped high-value routes, and manual role-pair validation needs.

See `docs/V3_FORWARD_SECURITY_UPGRADE.md`.

## v2.4.0

- Added `methods`, `cache`, `dom`, `access`, and `api`.
- Added `--deep-crawl` JavaScript route mining and non-passive seeds from `robots.txt` / `sitemap.xml`.
- Kept reports coverage-aware so shallow scans are not over-scored.

See `docs/V2_4_EXCEPTIONAL_TESTING_UPGRADE.md`.

## v2.3.0

- Improved crawler reliability, browser-like user agent, route/form/script extraction, and diagnostics.
- Added clearer report surface metrics, authenticated coverage labels, safe application-layer validation, and honest coverage-aware scoring.

See `docs/V2_3_TOP_FIRM_UPGRADE.md`.
