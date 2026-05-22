# WebSec Sentinel v2.3 Top-Firm Upgrade

This upgrade focuses on evidence quality and honest assessment depth. The system now answers the question a serious cyber firm would ask first: **what did it actually test?**

## Implemented improvements

- Coverage check that warns when no pages, forms, or authenticated coverage were observed.
- Coverage-aware grading so low-coverage scans are penalized instead of looking artificially strong.
- Browser-like crawler with extraction for links, scripts, HTML forms, JavaScript route hints, page titles, status codes, and request diagnostics.
- Authenticated coverage labeling when Cookie or Authorization-style headers are supplied.
- Safe application-layer validation module for CSRF signals, password-form handling, identifier parameters, reflected canaries, open redirects, and verbose errors.
- Discovery false-positive control using random soft-404 comparison and endpoint-specific content signatures.
- HTML and Markdown reports now include a `What was tested` section.

## Safety boundary

The scanner remains defensive and authorized-assessment oriented. It does not add destructive exploitation, data extraction, persistence, stealth, credential theft, or post-exploitation behavior. Validate mode uses inert proof-of-impact canaries only.

## Recommended high-impact command

```bash
docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel \
  https://client.example/login \
  --mode validate \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope client.example \
  --header "Cookie: APPROVED_TEST_SESSION" \
  --prohibited-paths /logout,/delete,/remove,/billing,/admin/delete \
  --crawl-depth 3 \
  --max-pages 200 \
  --rate-limit 500 \
  --jsonl-log reports/evidence.jsonl \
  --save \
  --format html,markdown,json,sarif
```
