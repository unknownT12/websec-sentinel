# External Benchmark Case Study Template

## Target

- Application:
- Version / image tag:
- Deployment method:
- Date tested:
- Ground-truth file:
- Scanner version:

## Command

```bash
npm run external-benchmark -- \
  --target <local-target-url> \
  --ground-truth examples/benchmarks/<target>.groundtruth.json \
  --profile <juice|dvwa|webgoat|custom> \
  --browser-crawl \
  --deep-crawl \
  --out reports/external-benchmark/<target>
```

## Evidence artifacts

- JSON report:
- Markdown report:
- SARIF report:
- HAR-like ledger:
- JSONL evidence log:
- Redacted replay file:
- External benchmark metrics:

## Metrics

```json
{
  "truePositives": 0,
  "falsePositiveCandidates": 0,
  "falseNegatives": 0,
  "precision": 0,
  "recall": 0,
  "f1": 0
}
```

## What it found

| Expected item | Scanner result ID | Evidence artifact | Status |
|---|---|---|---|
|  |  |  |  |

## What it missed

| Expected item | Reason missed | Fix plan |
|---|---|---|
|  |  |  |

## False-positive candidates

| Result ID | Why it may be false positive | Tuning decision |
|---|---|---|
|  |  |  |

## Product decision

- Is this benchmark strong enough for product evidence? Yes / No
- Minimum fix required before next release:
