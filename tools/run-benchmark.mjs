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
  const expected = [
    'vulnvalidation.confirmed-reflection',
    'vulnvalidation.confirmed-open-redirect',
    'vulnvalidation.confirmed-verbose-error',
    'vulnvalidation.confirmed-role-boundary-risk'
  ];
  const actual = new Set(report.results.map(r => r.id));
  const tp = expected.filter(e => actual.has(e));
  const fn = expected.filter(e => !actual.has(e));
  const validationIds = report.results.filter(r => String(r.id).startsWith('vulnvalidation.confirmed')).map(r => r.id);
  const fp = validationIds.filter(id => !expected.includes(id));
  const precision = validationIds.length ? tp.length / validationIds.length : 0;
  const recall = expected.length ? tp.length / expected.length : 0;
  const f1 = (precision + recall) ? (2 * precision * recall) / (precision + recall) : 0;
  const metrics = { profile: 'sentinel-local-fixture', expected, truePositives: tp, falseNegatives: fn, falsePositives: fp, precision: Number(precision.toFixed(3)), recall: Number(recall.toFixed(3)), f1: Number(f1.toFixed(3)), report: json };
  writeFileSync(join(out, 'benchmark-metrics.json'), JSON.stringify(metrics, null, 2));
  console.log(`\nBenchmark summary: grade=${report.summary.grade}, score=${report.summary.score}, coverage=${report.summary.coverageScore}, findings=${report.results.length}`);
  console.log(`Benchmark proof: TP=${tp.length}, FP=${fp.length}, FN=${fn.length}, precision=${metrics.precision}, recall=${metrics.recall}, f1=${metrics.f1}`);
  if (fn.length) process.exitCode = 1;
}
process.exit(result.status ?? process.exitCode ?? 0);
