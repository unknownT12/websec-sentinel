import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

function arg(name, fallback = undefined) {
  const eq = process.argv.find(a => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}
function all(name) {
  const out = [];
  for (let i = 0; i < process.argv.length; i++) {
    const v = process.argv[i];
    if (v.startsWith(`${name}=`)) out.push(v.slice(name.length + 1));
    else if (v === name && process.argv[i + 1]) out.push(process.argv[i + 1]);
  }
  return out;
}
function usage() {
  return `\nExternal benchmark runner\n\nRequired:\n  --target <url>\n  --ground-truth <file>\n\nRecommended:\n  --profile <juice|dvwa|webgoat|custom>\n  --out reports/external-benchmark/<name>\n  --browser-crawl\n  --seed <url> repeatable\n  --header "Cookie: ..." repeatable\n  --role-header "role|Cookie: ..." repeatable\n\nExample:\n  npm run external-benchmark -- --target http://localhost:3000 --ground-truth examples/benchmarks/juice-shop.groundtruth.json --profile juice --browser-crawl --out reports/external-benchmark/juice\n`;
}

const target = arg('--target');
const gtFile = arg('--ground-truth');
if (!target || !gtFile || process.argv.includes('--help')) { console.log(usage()); process.exit(target && gtFile ? 0 : 2); }
if (!existsSync(gtFile)) { console.error(`Ground truth file not found: ${gtFile}`); process.exit(2); }
const gt = JSON.parse(readFileSync(gtFile, 'utf8'));
const profile = arg('--profile', gt.targetFamily || 'custom');
const out = arg('--out', `reports/external-benchmark/${profile}`);
mkdirSync(out, { recursive: true });
const evidenceOut = join(out, 'external-benchmark-reachability.json');
const har = join(out, 'request-ledger.har.json');
const replay = join(out, 'replay-redacted.sh');
const jsonl = join(out, 'evidence.jsonl');

const scanArgs = [
  'dist/index.js', target,
  '--mode', 'validate',
  '--authorized',
  '--client', arg('--client', `External Benchmark - ${gt.targetName}`),
  '--assessment-id', arg('--assessment-id', `EXT-BENCH-${new Date().toISOString().slice(0,10)}`),
  '--tester', arg('--tester', 'WebSec Sentinel Benchmark Runner'),
  '--scope', arg('--scope', new URL(target).hostname),
  '--benchmark-profile', profile,
  '--benchmark-ground-truth', gtFile,
  '--benchmark-evidence-out', evidenceOut,
  '--crawl-depth', arg('--crawl-depth', '5'),
  '--max-pages', arg('--max-pages', '500'),
  '--rate-limit', arg('--rate-limit', '100'),
  '--min-coverage-score', arg('--min-coverage-score', '70'),
  '--min-pages', arg('--min-pages', '3'),
  '--jsonl-log', jsonl,
  '--har', har,
  '--replay-file', replay,
  '--save', '--out', out,
  '--format', 'json,markdown,sarif',
  '--fail-on', arg('--fail-on', 'critical'),
];
if (arg('--checks')) scanArgs.push('--checks', arg('--checks'));
if (process.argv.includes('--browser-crawl')) scanArgs.push('--browser-crawl');
if (process.argv.includes('--deep-crawl')) scanArgs.push('--deep-crawl');
if (process.argv.includes('--browser-headful')) scanArgs.push('--browser-headful');
if (arg('--browser-channel')) scanArgs.push('--browser-channel', arg('--browser-channel'));
if (arg('--browser-executable')) scanArgs.push('--browser-executable', arg('--browser-executable'));
for (const s of all('--seed')) scanArgs.push('--seed', s);
for (const h of all('--header')) scanArgs.push('--header', h);
for (const rh of all('--role-header')) scanArgs.push('--role-header', rh);
if (arg('--login-url')) scanArgs.push('--login-url', arg('--login-url'));
if (arg('--login-username')) scanArgs.push('--login-username', arg('--login-username'));
if (arg('--login-password')) scanArgs.push('--login-password', arg('--login-password'));
if (arg('--login-username-selector')) scanArgs.push('--login-username-selector', arg('--login-username-selector'));
if (arg('--login-password-selector')) scanArgs.push('--login-password-selector', arg('--login-password-selector'));
if (arg('--login-submit-selector')) scanArgs.push('--login-submit-selector', arg('--login-submit-selector'));
if (arg('--rules-dir')) scanArgs.push('--rules-dir', arg('--rules-dir'));
if (arg('--prohibited-paths')) scanArgs.push('--prohibited-paths', arg('--prohibited-paths'));

console.log(`Running external benchmark: ${gt.targetName} (${profile})`);
console.log(`Target: ${target}`);
const result = spawnSync(process.execPath, scanArgs, { stdio: 'inherit' });
const reportFile = readdirSync(out).filter(f => f.endsWith('.json') && f.startsWith('websec-')).sort().pop();
if (!reportFile) { console.error('No JSON report was produced; benchmark metrics cannot be calculated.'); process.exit(result.status || 1); }
const report = JSON.parse(readFileSync(join(out, reportFile), 'utf8'));
const results = report.results || [];
const expected = gt.expectedFindings || [];
const { calculateBenchmarkMetrics } = await import('../dist/core/benchmarkMetrics.js');
const scored = calculateBenchmarkMetrics(results, expected);
const metrics = {
  generatedAt: new Date().toISOString(),
  benchmark: { targetName: gt.targetName, targetFamily: gt.targetFamily || profile, version: gt.version || 'unknown', groundTruth: resolve(gtFile), target },
  report: reportFile,
  counts: { expectedRequired: scored.expectedRequired, truePositives: scored.truePositives, falsePositiveCandidates: scored.falsePositiveCandidates, falseNegatives: scored.falseNegatives, totalFindings: results.length },
  precision: scored.precision,
  recall: scored.recall,
  f1: scored.f1,
  matched: scored.matched,
  missed: scored.missed,
  surfaceMatches: scored.surfaceMatches,
  coverageMatches: scored.coverageMatches,
  falsePositiveCandidates: scored.falsePositiveCandidatesDetail,
  artifacts: { report: join(out, reportFile), reachability: evidenceOut, har, replay, jsonl },
  interpretation: scored.f1 >= 0.8 ? 'strong external benchmark proof for this target/version' : scored.f1 >= 0.6 ? 'moderate external benchmark proof; improve missed detections and false-positive control' : 'weak external benchmark proof; product claim not yet supported',
};
writeFileSync(join(out, 'external-benchmark-metrics.json'), JSON.stringify(metrics, null, 2));
console.log(`\nExternal benchmark proof: TP=${scored.truePositives}, FP candidates=${scored.falsePositiveCandidates}, FN=${scored.falseNegatives}, precision=${metrics.precision}, recall=${metrics.recall}, f1=${metrics.f1}`);
console.log(`Artifacts: ${out}`);
if (scored.falseNegatives > 0) process.exitCode = 1;
// Vulnerable benchmark apps intentionally produce high/critical findings, so the
// scanner process status is not treated as a runner failure when a report exists.
process.exit(process.exitCode || 0);
