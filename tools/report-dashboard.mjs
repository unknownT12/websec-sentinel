#!/usr/bin/env node
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

function arg(name, fallback) {
  const eq = process.argv.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const root = resolve(arg("--reports", "reports"));
const port = Number(arg("--port", "4173"));
if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("--port must be a TCP port.");

function reportFiles(dir = root) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const item of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, item.name);
    if (item.isDirectory()) out.push(...reportFiles(path));
    else if (/websec-.*\.json$/.test(item.name)) out.push(path);
  }
  return out.sort();
}

function loadReports() {
  return reportFiles().map((path) => {
    try {
      const report = JSON.parse(readFileSync(path, "utf8"));
      return {
        path: path.replace(`${root}/`, ""),
        target: report.target,
        timestamp: report.timestamp,
        grade: report.summary?.grade,
        score: report.summary?.score,
        coverage: report.summary?.coverageScore,
        counts: report.summary,
        findings: (report.results ?? []).map((r) => ({
          id: r.id,
          title: r.title,
          severity: r.severity,
          status: r.status,
          kind: r.kind,
          confidence: r.confidence,
          exploitability: r.exploitability,
          category: r.category,
        })),
      };
    } catch (error) {
      return { path: path.replace(`${root}/`, ""), error: error instanceof Error ? error.message : String(error) };
    }
  });
}

function html(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function page(reports) {
  const rows = reports.map((r, i) => `<tr><td><button data-i="${i}">${html(r.timestamp)}</button></td><td>${html(r.target)}</td><td>${html(r.grade)} (${html(r.score)})</td><td>${html(r.coverage)}</td><td>${html(r.path)}</td></tr>`).join("");
  const payload = JSON.stringify(reports).replace(/</g, "\\u003c");
  return `<!doctype html><html><head><meta charset="utf-8"><title>WebSec Sentinel Dashboard</title><style>body{font-family:Inter,system-ui,sans-serif;margin:0;background:#f8fafc;color:#111827}.wrap{max-width:1200px;margin:0 auto;padding:24px}table{width:100%;border-collapse:collapse;background:white;border:1px solid #d1d5db}th,td{text-align:left;border-bottom:1px solid #e5e7eb;padding:10px;font-size:14px}button{border:1px solid #9ca3af;background:white;border-radius:6px;padding:6px 8px;cursor:pointer}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}.panel{background:white;border:1px solid #d1d5db;border-radius:8px;padding:16px}.finding{border-bottom:1px solid #e5e7eb;padding:8px 0}.meta{color:#6b7280;font-size:13px}@media(max-width:800px){.grid{grid-template-columns:1fr}table{display:block;overflow:auto}}</style></head><body><div class="wrap"><h1>WebSec Sentinel Dashboard</h1><p class="meta">Local review surface for saved JSON reports in ${html(root)}. This server is local-only by default; use it for triage review, not public hosting.</p><table><thead><tr><th>Scan</th><th>Target</th><th>Grade</th><th>Coverage</th><th>File</th></tr></thead><tbody>${rows}</tbody></table><div class="grid"><section class="panel"><h2>Scan Summary</h2><pre id="summary">Select a scan.</pre></section><section class="panel"><h2>Findings</h2><div id="findings"></div></section></div></div><script type="application/json" id="reports">${payload}</script><script>const reports=JSON.parse(document.getElementById('reports').textContent);function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}document.addEventListener('click',e=>{if(!e.target.matches('button[data-i]'))return;const r=reports[Number(e.target.dataset.i)];document.getElementById('summary').textContent=JSON.stringify({target:r.target,timestamp:r.timestamp,grade:r.grade,score:r.score,coverage:r.coverage,counts:r.counts,path:r.path},null,2);document.getElementById('findings').innerHTML=(r.findings||[]).map(f=>'<div class="finding"><b>'+esc(f.severity).toUpperCase()+'</b> '+esc(f.title)+'<div class="meta">'+esc(f.kind)+' · '+esc(f.status)+' · '+esc(f.confidence)+' · '+esc(f.exploitability)+' · '+esc(f.category)+'</div><code>'+esc(f.id)+'</code></div>').join('')||'No findings.';});</script></body></html>`;
}

const server = createServer((req, res) => {
  if (req.url === "/reports.json") {
    res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(loadReports(), null, 2));
    return;
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(page(loadReports()));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`WebSec Sentinel dashboard: http://127.0.0.1:${port}`);
  console.log(`Reports root: ${root}`);
});
