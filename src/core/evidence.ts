import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { HttpObservation, ScanReport } from "../types.js";
import { replayCommands } from "./http.js";

function ensure(path: string): void {
  mkdirSync(dirname(path), { recursive: true });
}

export function saveHarLike(path: string, report: ScanReport, observations: HttpObservation[]): void {
  ensure(path);
  const har = {
    log: {
      version: "1.2-redacted",
      creator: { name: report.tool, version: report.version },
      comment: "Redacted defensive assessment request ledger. Sensitive headers and bodies are not stored.",
      pages: [{ id: "assessment", title: report.target, startedDateTime: report.timestamp }],
      entries: observations.map((obs) => ({
        startedDateTime: report.timestamp,
        time: obs.elapsedMs,
        request: {
          method: obs.method,
          url: obs.url,
          headers: Object.entries(obs.requestHeaders ?? {}).map(([name, value]) => ({ name, value })),
        },
        response: {
          status: obs.status,
          redirectURL: obs.redirected ? obs.finalUrl : "",
          headers: Object.entries(obs.headers).map(([name, value]) => ({ name, value })),
          content: { size: obs.sizeBytes, mimeType: obs.headers["content-type"] ?? "", text: obs.body },
        },
        _requestId: obs.requestId,
      })),
    },
  };
  writeFileSync(path, JSON.stringify(har, null, 2));
}

export function saveReplayFile(path: string, report: ScanReport): void {
  ensure(path);
  const header = [
    `# ${report.tool} ${report.version} replay notes`,
    `# Target: ${report.target}`,
    `# Timestamp: ${report.timestamp}`,
    "# Headers and secrets are redacted. Use this only as a manual verification checklist.",
    "",
  ].join("\n");
  writeFileSync(path, header + replayCommands().join("\n"));
}
