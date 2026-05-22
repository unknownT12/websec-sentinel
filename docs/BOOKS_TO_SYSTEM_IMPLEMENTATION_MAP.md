# Books-to-System Implementation Map

The uploaded book collection was treated as methodology inspiration for defensive engineering, not as a source for weaponized exploitation. The system now absorbs the professional patterns that are safe and useful for authorized client work.

## Material reviewed at a high level

- Web application security testing and flaw discovery methodology.
- Penetration-testing lifecycle discipline: authorization, scope, reconnaissance, mapping, validation, evidence, and retesting.
- Red-team operational note-taking and repeatable command discipline.
- Python/security automation principles adapted into safe TypeScript modules.
- Malware-analysis style evidence hygiene adapted into redaction and traceability.

## What was implemented

| Methodology idea | System implementation |
|---|---|
| Start with scope and authorization | `--authorized`, `--scope`, client, tester, assessment ID, and report authorization metadata |
| Avoid out-of-scope or destructive paths | `--prohibited-paths` enforced by both crawler and request layer |
| Evidence must be reproducible | Request IDs, JSONL request log, report evidence snippets, status codes, headers, elapsed time |
| Evidence must not leak secrets | Header redaction, secret evidence redaction, snippets instead of full sensitive payload capture |
| Web app mapping matters | Same-origin crawler, forms, links, technologies, status codes, risky parameter inventory |
| Validate carefully, do not guess | `validate` mode with inert canaries and explicit false-positive notes |
| Authenticated areas need controlled coverage | Repeatable `--header` support for client-provided test sessions/tokens |
| Findings need business language | Executive verdict, business impact, immediate priorities, remediation and report grades |
| Retesting should show deltas | `--baseline` report comparison for new, resolved, unchanged, and changed-severity findings |
| Operations need resilience checks | Risky method review, sensitive-page cache-control review, 5xx/error leakage review |

## What was intentionally not implemented

- Exploit chains that modify data or extract records.
- Credential harvesting, token theft, password spraying, brute force, phishing, or session hijacking.
- Malware, persistence, shell access, payload droppers, evasion, or stealth logic.
- Destructive fuzzing, denial of service, or high-volume attacks.
- Post-exploitation automation.

## New modules

- `src/checks/methodology.ts`
- `src/checks/resilience.ts`
- `src/core/baseline.ts`

## New CLI flags

```txt
--header "Name: value"
--prohibited-paths /logout,/delete-account,/billing/charge
--baseline reports/previous.json
```
