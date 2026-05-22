# Operator Runbook

## 1. Pre-engagement

- Confirm signed authorization.
- Confirm in-scope domains and environments.
- Confirm test accounts or client-approved session headers.
- Confirm prohibited paths: logout, deletion, payment, billing, notification, admin write, batch jobs, and fragile legacy endpoints.

## 2. Low-risk first pass

```bash
npm run scan -- https://client.example \
  --mode passive \
  --scope client.example \
  --client "Client Ltd" \
  --assessment-id "AUTH-001" \
  --tester "Assessment Team" \
  --rate-limit 500 \
  --save \
  --format html,markdown,json
```

## 3. Standard mapped scan

```bash
npm run scan -- https://client.example \
  --mode standard \
  --authorized \
  --scope client.example \
  --prohibited-paths /logout,/delete-account,/billing/charge,/admin/delete \
  --crawl-depth 2 \
  --max-pages 150 \
  --rate-limit 300 \
  --jsonl-log reports/evidence.jsonl \
  --save \
  --format html,markdown,json,sarif
```

## 4. Authenticated coverage

```bash
npm run scan -- https://client.example \
  --authorized \
  --header "Cookie: session=<client-approved-test-session>" \
  --prohibited-paths /logout,/delete-account,/billing/charge,/admin/delete \
  --save \
  --format html,markdown,json
```

## 5. Safe validation

Only run validate mode when explicitly approved.

```bash
npm run scan -- https://client.example \
  --mode validate \
  --authorized \
  --client "Client Ltd" \
  --assessment-id "AUTH-001" \
  --scope client.example \
  --prohibited-paths /logout,/delete-account,/billing/charge,/admin/delete \
  --rate-limit 500 \
  --save
```

## 6. Retesting

```bash
npm run scan -- https://client.example \
  --baseline reports/previous.json \
  --save \
  --format html,markdown,json
```

## 7. Report handling

- Share HTML with executives or managers.
- Share Markdown with technical stakeholders.
- Store JSON for future baselines.
- Import SARIF into CI/security dashboards.
- Store JSONL evidence logs securely because they contain target URLs and redacted headers.
