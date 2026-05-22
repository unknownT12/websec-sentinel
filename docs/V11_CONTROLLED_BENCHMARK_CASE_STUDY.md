# Controlled Benchmark Case Study — v11

This is a controlled local benchmark, not a real client case study.

## Target

`tools/benchmark-server.mjs` — intentionally vulnerable local fixture used for repeatable scanner validation.

## Ground truth

The fixture intentionally exposes four safe-to-confirm behaviours:

1. Reflected input on a search/reflection surface.
2. Open redirect through a redirect parameter.
3. Verbose error disclosure through a debug/error route.
4. Role-boundary concern where two role-labelled sessions can reach a high-value route.

## Benchmark command

```bash
npm run benchmark
```

## Latest local result during packaging

```json
{
  "profile": "sentinel-local-fixture",
  "truePositives": 4,
  "falsePositives": 0,
  "falseNegatives": 0,
  "precision": 1,
  "recall": 1,
  "f1": 1
}
```

## Interpretation

This does not prove the scanner is universally strong. It proves the v11 engine can run a repeatable benchmark against known ground truth and report precision/recall instead of relying only on route keywords.

The next benchmark layer should run the same evidence format against OWASP Juice Shop, DVWA, and WebGoat in approved local lab containers.
