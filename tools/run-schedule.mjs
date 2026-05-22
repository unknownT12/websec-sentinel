import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

function arg(name, fallback = undefined) {
  const eq = process.argv.find(a => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

function usage() {
  return `\nWebSec Sentinel scheduler\n\nUsage:\n  npm run schedule -- --config schedule.json [--once]\n\nConfig:\n{\n  "jobs": [\n    {\n      "name": "staging",\n      "target": "https://staging.example.com",\n      "args": ["--project-dir", "reports/projects", "--save", "--format", "json,markdown"],\n      "intervalSeconds": 3600\n    }\n  ]\n}\n`;
}

const configPath = arg('--config');
const once = process.argv.includes('--once');
if (!configPath || process.argv.includes('--help')) {
  console.log(usage());
  process.exit(process.argv.includes('--help') ? 0 : 2);
}
if (!existsSync(configPath)) {
  console.error(`Schedule config not found: ${configPath}`);
  process.exit(2);
}

const config = JSON.parse(readFileSync(configPath, 'utf8'));
const jobs = Array.isArray(config.jobs) ? config.jobs : [];
if (!jobs.length) {
  console.error('Schedule config must include at least one job.');
  process.exit(2);
}

function validateJob(job) {
  if (!job || typeof job !== 'object') throw new Error('Job must be an object.');
  if (!job.name || typeof job.name !== 'string') throw new Error('Job name is required.');
  if (!job.target || typeof job.target !== 'string') throw new Error(`Job ${job.name} target is required.`);
  new URL(job.target);
  if (job.args !== undefined && !Array.isArray(job.args)) throw new Error(`Job ${job.name} args must be an array.`);
  if (job.intervalSeconds !== undefined && (!Number.isInteger(job.intervalSeconds) || job.intervalSeconds < 60)) throw new Error(`Job ${job.name} intervalSeconds must be an integer >= 60.`);
}

for (const job of jobs) validateJob(job);

function runJob(job) {
  const args = ['dist/index.js', job.target, ...(job.args || [])];
  const started = new Date().toISOString();
  console.log(`[${started}] Running scheduled scan: ${job.name} -> ${job.target}`);
  const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
  const ended = new Date().toISOString();
  console.log(`[${ended}] Completed ${job.name} with exit=${result.status ?? 1}`);
  return result.status ?? 1;
}

let exitCode = 0;
for (const job of jobs) {
  const status = runJob(job);
  if (status && !exitCode) exitCode = status;
}
if (once) process.exit(exitCode);

for (const job of jobs) {
  const interval = (job.intervalSeconds || 3600) * 1000;
  setInterval(() => {
    const status = runJob(job);
    if (status) process.exitCode = status;
  }, interval);
}
