# Data Handling and Redaction

WebSec Sentinel stores assessment evidence to make findings reproducible. Generated artifacts should be treated as confidential.

## Data Collected

- target URLs and final URLs
- HTTP status codes and selected headers
- request IDs and elapsed times
- short response snippets
- route hints, forms, scripts, technologies, and crawler diagnostics
- finding metadata, severity, confidence, evidence, remediation, and triage status

## Redaction

Request headers matching authorization, cookie, token, secret, or key patterns are redacted before being written into observations and replay commands.

Response snippets are truncated and intended for evidence context, not data extraction. Operators should avoid scanning production records unless the engagement explicitly authorizes it.

## Artifact Types

- JSON report: full machine-readable report
- Markdown/HTML report: human review output
- SARIF: CI/security dashboard import
- JSONL ledger: append-only request observations
- HAR-like ledger: request/response summary
- replay file: redacted manual verification commands
- triage template: finding fingerprints and review workflow

## Retention Guidance

Store artifacts in approved engagement storage. Do not commit client reports, headers, HAR/JSONL files, or replay commands unless they are sanitized benchmark fixtures.
