# Security Policy

WebSec Sentinel is a defensive assessment aid for authorized testing. It is not an exploit framework and does not intentionally include destructive payloads, credential theft, persistence, stealth, malware behavior, or data extraction.

## Supported Versions

Security fixes are accepted for the current major version in `main`.

## Reporting a Vulnerability

Do not open public issues containing exploit details, secrets, client data, or live target information.

Report security issues by creating a private advisory in the repository host, or by contacting the maintainer through the package/repository contact channel when configured.

Include:

- affected version or commit
- reproduction steps against a local fixture or synthetic target
- expected and observed behavior
- whether sensitive data, credentials, or report artifacts were exposed

## Scanner Safety Boundaries

- `validate` mode requires `--authorized`.
- Use `--prohibited-paths` for logout, deletion, billing, payment, administrative writes, and fragile workflows.
- Use only approved test accounts and non-production records.
- Findings are assessment signals unless the report marks them as confirmed and the operator validates the evidence.

## Artifact Handling

Reports can contain URLs, route names, redacted headers, snippets, request IDs, and risk details. Treat generated reports, HAR-like ledgers, JSONL logs, and replay files as confidential engagement artifacts.
