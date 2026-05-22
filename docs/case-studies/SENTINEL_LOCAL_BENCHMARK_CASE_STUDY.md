# Case Study — Sentinel Local Benchmark Fixture

This case study verifies the v12 external benchmark runner mechanics using the built-in local fixture. It is not a substitute for Juice Shop/DVWA/WebGoat proof, but it proves that the benchmark pipeline produces real TP/FP/FN metrics from a ground-truth file.

## Target

- Target: Sentinel Local Benchmark Fixture
- Ground truth: `examples/benchmarks/sentinel-local.groundtruth.json`
- Runner: `npm run external-benchmark`

## Command used during package verification

```bash
PORT=49212 node tools/benchmark-server.mjs &

npm run external-benchmark -- \
  --target http://localhost:49212/login \
  --ground-truth examples/benchmarks/sentinel-local.groundtruth.json \
  --profile sentinel \
  --out reports/external-benchmark/sentinel \
  --header "Cookie: bench_session=abc; role=student" \
  --role-header "student|Cookie: bench_session=abc; role=student" \
  --role-header "lecturer|Cookie: bench_session=abc; role=lecturer" \
  --seed http://localhost:49212/dashboard \
  --seed "http://localhost:49212/search?q=test" \
  --seed "http://localhost:49212/redirect?next=/dashboard" \
  --seed "http://localhost:49212/error?debug=true" \
  --deep-crawl
```

## Verified metrics

The generated metrics artifact reported:

```json
{
  "truePositives": 4,
  "falsePositiveCandidates": 0,
  "falseNegatives": 0,
  "precision": 1,
  "recall": 1,
  "f1": 1
}
```

## Confirmed behaviours

- reflected input behaviour
- open redirect behaviour
- verbose error disclosure
- role-boundary concern

## Limitations

This is a controlled local fixture. It proves the benchmark runner and validation model, but it does not prove broad external performance. For product-level evidence, run the same pipeline against Juice Shop, DVWA, and WebGoat and preserve the generated metrics artifacts.
