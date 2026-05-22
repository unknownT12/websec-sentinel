import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

const port = 48181;
mkdirSync('reports/selftest', { recursive: true });
const server = spawn(process.execPath, ['tools/selftest-server.mjs'], { env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'inherit'] });
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
  throw new Error(`Selftest fixture did not become reachable at ${url}`);
}
await waitForFixture(`http://127.0.0.1:${port}/login`);
const args = [
  'dist/index.js', `http://127.0.0.1:${port}/login`,
  '--mode', 'validate', '--authorized', '--client', 'SelfTest', '--assessment-id', 'SELFTEST-BOOK-MODEL', '--tester', 'WebSec Sentinel',
  '--scope', '127.0.0.1', '--checks', 'productengine,testvectors,professionalmodel,bookscope,stateflow,parammodel,testmodel,enginemodel,evidencequality,coverage,assurance,differential,deepassess,inputvalidation,mutation', '--header', 'Cookie: fixture_session=abc', '--seed', `http://127.0.0.1:${port}/dashboard`,
  '--require-auth', '--min-coverage-score', '60', '--min-pages', '2', '--crawl-depth', '3', '--max-pages', '50', '--deep-crawl',
  '--prohibited-paths', '/logout,/delete,/remove,/reset,/billing,/payment,/admin/delete',
  '--jsonl-log', 'reports/selftest/evidence.jsonl', '--har', 'reports/selftest/ledger.har.json', '--replay-file', 'reports/selftest/replay-redacted.sh',
  '--save', '--out', 'reports/selftest', '--format', 'json,markdown', '--fail-on', 'critical'
];
const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
server.kill('SIGTERM');
process.exit(result.status ?? 1);
