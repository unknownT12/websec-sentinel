# Benchmark Proof Policy

Benchmark claims must be backed by preserved artifacts, not README assertions.

## Required External Benchmark Package

For each Juice Shop, DVWA, WebGoat, or custom lab run, preserve:

- target name, version, container/image tag or setup instructions
- command used to run the scanner
- ground-truth JSON file
- scanner JSON, Markdown, and SARIF reports
- `external-benchmark-reachability.json`
- `external-benchmark-metrics.json`
- JSONL request ledger when enabled
- HAR-like ledger when enabled
- redacted replay file when enabled
- documented false negatives and false-positive candidates

## Metric Semantics

- Vulnerability precision/recall/F1 counts only expectations with `metricType: "vulnerability"`.
- `metricType: "surface"` proves route/API/workflow reachability, not vulnerability detection.
- `metricType: "coverage"` proves assessment readiness or evidence quality, not vulnerability detection.
- Coverage gaps and `externalbenchmark.evidence-detail` must not be counted as vulnerability true positives.

## Minimum Product Claim Bar

A startup-grade product claim needs:

- one internal controlled benchmark
- at least three preserved external known-vulnerable benchmark packages
- documented target versions
- documented misses and false-positive candidates
- reproducible commands and artifacts
- stable trend across repeated runs
