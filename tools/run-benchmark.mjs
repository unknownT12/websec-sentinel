import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const port = 49210;
const out = 'reports/benchmark';
mkdirSync(out, { recursive: true });
const server = spawn(process.execPath, ['tools/benchmark-server.mjs'], { env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'inherit'] });
async function waitForFixture(url) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) break;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(500) });
      if (res.status < 500) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  server.kill('SIGTERM');
  throw new Error(`Benchmark fixture did not become reachable at ${url}`);
}
await waitForFixture(`http://127.0.0.1:${port}/login`);
const args = ['dist/index.js', `http://127.0.0.1:${port}/login`, '--mode', 'validate', '--authorized', '--client', 'BenchmarkFixture', '--assessment-id', 'BENCH-V11', '--tester', 'WebSec Sentinel', '--scope', '127.0.0.1', '--header', 'Cookie: bench_session=abc; role=student', '--role-header', 'student|Cookie: bench_session=abc; role=student', '--role-header', 'lecturer|Cookie: bench_session=abc; role=lecturer', '--seed', `http://127.0.0.1:${port}/dashboard`, '--seed', `http://127.0.0.1:${port}/search?q=test`, '--seed', `http://127.0.0.1:${port}/redirect?next=/dashboard`, '--seed', `http://127.0.0.1:${port}/error?debug=true`, '--benchmark-profile', 'sentinel', '--checks', 'benchmark,vulnvalidation,proofmetrics,rolecompare,deepassess,validationmatrix,coverage,assurance,productengine,testvectors,professionalmodel,bookscope,stateflow,parammodel,differential,inputvalidation,mutation,plugins', '--require-auth', '--min-coverage-score', '75', '--min-pages', '5', '--crawl-depth', '4', '--max-pages', '120', '--deep-crawl', '--prohibited-paths', '/logout,/delete,/remove,/reset,/billing,/payment,/admin/delete', '--jsonl-log', `${out}/evidence.jsonl`, '--har', `${out}/ledger.har.json`, '--replay-file', `${out}/replay-redacted.sh`, '--save', '--out', out, '--format', 'json,markdown', '--fail-on', 'critical'];
const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
server.kill('SIGTERM');
const json = readdirSync(out).filter(f => f.endsWith('.json') && f.startsWith('websec-')).sort().pop();
if (json) {
  const report = JSON.parse(readFileSync(join(out, json), 'utf8'));
  const gt = JSON.parse(readFileSync('examples/benchmarks/sentinel-local.groundtruth.json', 'utf8'));
  const { calculateBenchmarkMetrics } = await import('../dist/core/benchmarkMetrics.js');
  const scored = calculateBenchmarkMetrics(report.results, gt.expectedFindings || []);
  const metrics = {
    profile: 'sentinel-local-fixture',
    expected: gt.expectedFindings,
    truePositives: scored.matched,
    falseNegatives: scored.missed,
    falsePositiveCandidates: scored.falsePositiveCandidatesDetail,
    surfaceMatches: scored.surfaceMatches,
    coverageMatches: scored.coverageMatches,
    precision: scored.precision,
    recall: scored.recall,
    f1: scored.f1,
    report: json
  };
  writeFileSync(join(out, 'benchmark-metrics.json'), JSON.stringify(metrics, null, 2));
  console.log(`\nBenchmark summary: grade=${report.summary.grade}, score=${report.summary.score}, coverage=${report.summary.coverageScore}, findings=${report.results.length}`);
  console.log(`Benchmark proof: TP=${scored.truePositives}, FP candidates=${scored.falsePositiveCandidates}, FN=${scored.falseNegatives}, precision=${metrics.precision}, recall=${metrics.recall}, f1=${metrics.f1}`);
  if (scored.falseNegatives) process.exitCode = 1;
}
process.exit(result.status ?? process.exitCode ?? 0);
