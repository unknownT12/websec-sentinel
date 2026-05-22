import type { ScanResult } from "../types.js";

function normalizeRoute(url: string | undefined): string {
  if (!url) return "";
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return url;
  }
}

export function fingerprintFor(result: ScanResult): string {
  const ev = result.evidence?.[0];
  const route = normalizeRoute(ev?.url);
  const param = ev?.parameter ?? "";
  return `${result.id}|${route}|${param}`;
}

function keyFor(result: ScanResult): string {
  return `${fingerprintFor(result)}|${result.severity}`;
}

function withLimitedEvidence(result: ScanResult, limit: number): ScanResult {
  const clone: ScanResult = { ...result, fingerprint: result.fingerprint ?? fingerprintFor(result) };
  if (result.evidence) clone.evidence = result.evidence.slice(0, limit);
  return clone;
}

export function reduceFalsePositiveNoise(results: ScanResult[], limit = 5): ScanResult[] {
  const grouped = new Map<string, ScanResult>();
  for (const result of results) {
    const key = keyFor(result);
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, withLimitedEvidence(result, limit));
      continue;
    }
    const merged: ScanResult = {
      ...existing,
      fingerprint: existing.fingerprint ?? fingerprintFor(existing),
      detail: existing.detail === result.detail ? existing.detail : `${existing.detail} Additional similar observations were suppressed into this finding to reduce false positives/noise.`,
      falsePositiveNotes: existing.falsePositiveNotes ?? "Similar observations are grouped by finding, route, and parameter to reduce duplicate report noise.",
    };
    const evidence = [...(existing.evidence ?? []), ...(result.evidence ?? [])].slice(0, limit);
    if (evidence.length) merged.evidence = evidence;
    grouped.set(key, merged);
  }
  return [...grouped.values()];
}
