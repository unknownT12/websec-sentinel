# WebSec Sentinel v12 — External Benchmark Proof Engine

v12 focuses on the weakness that mattered most: internal fixtures are not enough. A product claim needs proof against external, repeatable, known-vulnerable lab applications.

This version adds an external benchmark contract and runner for approved local targets such as:

- OWASP Juice Shop
- DVWA
- WebGoat
- custom client-like lab apps

The goal is not to claim universal exploitation. The goal is to prove, with artifacts, what the engine can detect, what it missed, and where false positives may exist.

## New model pieces

### 1. External ground-truth contract

Ground-truth files live in `examples/benchmarks/`.

Each file defines:

- target identity and family
- expected routes/surfaces
- expected safe findings
- acceptable scanner result IDs
- required vs optional expectations

Example:

```json
{
  "targetName": "OWASP Juice Shop",
  "targetFamily": "juice",
  "surfaces": [
    { "id": "login-surface", "urlPattern": "login|email|password", "required": true }
  ],
  "expectedFindings": [
    {
      "id": "search-reflection-or-input-surface",
      "resultIds": ["vulnvalidation.confirmed-reflection", "inputvalidation.safe-canary-reflection"],
      "urlPattern": "search|q=",
      "parameter": "q",
      "required": true
    }
  ]
}
```

### 2. External benchmark check

The new `externalbenchmark` check measures whether the scanner actually reached the surfaces required by the benchmark profile.

It does not fake confirmed vulnerabilities. It separates:

- reached benchmark surfaces
- missed benchmark surfaces
- reachable expected finding surfaces
- unreachable expected finding surfaces

### 3. Post-scan TP/FP/FN scoring

The new runner calculates:

- true positives
- false positive candidates
- false negatives
- precision
- recall
- F1 score

Output:

```txt
reports/external-benchmark/<name>/external-benchmark-metrics.json
```

This is the evidence needed to judge whether the scanner is becoming a real product.

## Running Juice Shop benchmark

Start Juice Shop locally using your preferred approved method, then run:

```bash
npm run external-benchmark -- \
  --target http://localhost:3000 \
  --ground-truth examples/benchmarks/juice-shop.groundtruth.json \
  --profile juice \
  --browser-crawl \
  --deep-crawl \
  --seed http://localhost:3000/#/login \
  --seed http://localhost:3000/#/search \
  --out reports/external-benchmark/juice
```

Docker browser build:

```bash
docker build -f Dockerfile.browser -t websec-sentinel-browser .

docker run --rm \
  -v "$PWD/reports:/app/reports" \
  websec-sentinel-browser \
  node tools/run-external-benchmark.mjs \
  --target http://host.docker.internal:3000 \
  --ground-truth examples/benchmarks/juice-shop.groundtruth.json \
  --profile juice \
  --browser-crawl \
  --deep-crawl \
  --out reports/external-benchmark/juice
```

## Running DVWA benchmark

```bash
npm run external-benchmark -- \
  --target http://localhost:8080/login.php \
  --ground-truth examples/benchmarks/dvwa.groundtruth.json \
  --profile dvwa \
  --browser-crawl \
  --deep-crawl \
  --header "Cookie: PHPSESSID=<approved_lab_session>; security=low" \
  --seed http://localhost:8080/vulnerabilities/xss_r/ \
  --seed http://localhost:8080/vulnerabilities/sqli/ \
  --out reports/external-benchmark/dvwa
```

## Running WebGoat benchmark

```bash
npm run external-benchmark -- \
  --target http://localhost:8080/WebGoat/login \
  --ground-truth examples/benchmarks/webgoat.groundtruth.json \
  --profile webgoat \
  --browser-crawl \
  --deep-crawl \
  --login-url http://localhost:8080/WebGoat/login \
  --login-username <lab_user> \
  --login-password <lab_password> \
  --out reports/external-benchmark/webgoat
```

## Evidence package

Each external benchmark run produces:

- scanner JSON report
- scanner Markdown report
- SARIF report
- `external-benchmark-reachability.json`
- `external-benchmark-metrics.json`
- JSONL request evidence
- HAR-like request ledger
- redacted replay commands

This gives a reviewer a real basis to ask:

- What did it find?
- What did it miss?
- What is the false-positive candidate count?
- What evidence proves the scanner reached the vulnerable surface?
- Can the request path be replayed manually?

## Brutal product rule

v12 is not allowed to claim strong product readiness from internal fixtures alone.

A serious claim needs at least:

- one internal controlled benchmark
- one external known-vulnerable benchmark
- preserved TP/FP/FN metrics
- browser trace when the app is JavaScript-heavy
- replayable evidence
- documented misses

That is the difference between a prototype and a product core.
