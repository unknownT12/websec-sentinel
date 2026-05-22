# Top-Firm Upgrade Notes

This release upgrades WebSec Sentinel from a basic production scanner into a more mature assessment product.

## Added

- Executive verdict and business-risk narrative.
- Immediate remediation priorities.
- Weighted risk scoring and top category aggregation.
- Request IDs for evidence traceability.
- Optional JSONL request observation log.
- Crawl form/link extraction.
- Attack-surface module for risky parameters, insecure password form actions, and 5xx anomalies.
- Governance module for `security.txt`, `.well-known/change-password`, and validation-mode metadata quality.
- Extended finding schema: OWASP, CWE, exploitability, business impact, tags, CVSS placeholder, and evidence.
- Stronger CLI validation for bounds and modes.
- Output quality section with limitations and evidence policy.

## Improved

- Safer response-body handling with `--max-body-bytes`.
- Better scope and crawl controls for production environments.
- Client-ready HTML and Markdown reports.
- SARIF properties for severity, confidence, and exploitability.
- Versioning updated to 2.1.0.

## Deliberate exclusions

- No destructive exploitation.
- No credential theft.
- No persistence.
- No stealth/evasion.
- No shell or post-exploitation capability.
- No sensitive data extraction.

The tool is suitable for authorized defensive security validation, external posture checks, and CI/CD governance.
