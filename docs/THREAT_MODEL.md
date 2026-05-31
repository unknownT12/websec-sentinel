# Threat Model

## Assets

- scanner runtime and local workstation/CI runner
- supplied target URLs, scope, headers, and role-labelled sessions
- generated JSON, Markdown, HTML, SARIF, HAR-like, JSONL, replay, summary, and triage artifacts
- benchmark ground-truth files and benchmark result packages

## Trust Boundaries

- target applications are untrusted network services
- report artifacts are confidential assessment outputs
- caller-supplied headers and login credentials are sensitive
- plugin rules and policy files are local trusted inputs
- browser crawling executes untrusted target JavaScript inside Playwright

## Main Risks

- accidental requests to out-of-scope or destructive paths
- leaking session headers or secrets into logs/reports
- overclaiming a risk signal as a confirmed vulnerability
- hostile target content causing excessive resource use
- stale in-process scan state affecting a later scan
- browser crawling expanding the tested surface beyond intended scope

## Controls Implemented

- explicit `--authorized` gate for `validate` mode
- scope and prohibited-path checks before requests
- redaction for sensitive request headers
- coverage-aware scoring and report limitations
- finding kinds that separate confirmed vulnerabilities, risk signals, coverage gaps, diagnostics, informational results, and passes
- explicit report disclaimer requiring human validation
- reset of HTTP observation/rate-limit state at CLI run start
- local-only dashboard binding to `127.0.0.1`

## Residual Risks

- black-box scans cannot prove absence of vulnerabilities
- heuristic route/body matching can produce false positives or false negatives
- Playwright crawling depends on target behavior and login stability
- external benchmark results require independently preserved target versions and artifacts
