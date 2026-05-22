# Run WebSec Sentinel with Docker

Your npm install failed because your Mac is too old for the native `esbuild` binary used by `tsx`. Docker fixes this by running the project inside Linux.

## 1. Build the container

From inside the project folder:

```bash
cd "/Users/apple/Desktop/topfirm_latest 4"
docker compose build
```

If your Docker version uses the older command style, use:

```bash
docker-compose build
```

## 2. Run help

```bash
docker compose run --rm websec-sentinel --help
```

## 3. Run a basic authorized scan

Replace the URL and client details with your approved target:

```bash
docker compose run --rm websec-sentinel https://example.com \
  --mode standard \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --crawl-depth 2 \
  --max-pages 100 \
  --rate-limit 300 \
  --save \
  --format html,markdown,json,sarif
```

Reports will appear on your Mac in:

```text
/Users/apple/Desktop/topfirm_latest 4/reports
```

## 4. Run validate mode

```bash
docker compose run --rm websec-sentinel https://example.com \
  --mode validate \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --crawl-depth 2 \
  --max-pages 150 \
  --rate-limit 300 \
  --jsonl-log reports/evidence.jsonl \
  --save \
  --format html,markdown,json,sarif
```

## 5. Authenticated scan

Use only a test account or session supplied by the client:

```bash
docker compose run --rm websec-sentinel https://example.com \
  --authorized \
  --client "Client Name" \
  --assessment-id "AUTH-2026-001" \
  --tester "Assessment Team" \
  --scope example.com \
  --header "Cookie: session=PASTE_TEST_SESSION_HERE" \
  --prohibited-paths /logout,/delete,/delete-account,/billing,/admin/delete \
  --crawl-depth 2 \
  --max-pages 100 \
  --save \
  --format html,markdown,json
```

## 6. Rebuild after code changes

```bash
docker compose build --no-cache
```

## 7. Clean old reports

```bash
rm -rf reports/*
```
