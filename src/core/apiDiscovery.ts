import { existsSync, readFileSync } from "node:fs";
import type { CrawlPage, Evidence, ScanOptions } from "../types.js";
import { request, safeSnippet } from "./http.js";

const API_ROUTE = /\/api\/|\/graphql|\/openapi|\/swagger|\/v\d+\/|\.json(?:$|\?)/i;
const OPENAPI_HINT = /"openapi"\s*:|"swagger"\s*:|"paths"\s*:|"components"\s*:/i;
const GRAPHQL_HINT = /graphql|__schema|Cannot query field|Must provide query string|GraphQL/i;

export interface ApiDiscovery {
  candidates: string[];
  openApiDocs: Evidence[];
  graphqlEndpoints: Evidence[];
  sensitiveJson: Evidence[];
  discoveredOperations: Array<{ method: string; path: string; source: string }>;
}

function addCandidate(candidates: Set<string>, target: URL, raw: string): void {
  try {
    const url = new URL(raw, target);
    if (url.origin === target.origin && API_ROUTE.test(url.pathname)) candidates.add(url.toString());
  } catch {}
}

function operationsFromOpenApi(body: string, source: string): Array<{ method: string; path: string; source: string }> {
  try {
    const parsed = JSON.parse(body) as { paths?: Record<string, Record<string, unknown>> };
    return Object.entries(parsed.paths ?? {}).flatMap(([path, methods]) =>
      Object.keys(methods ?? {})
        .filter((method) => /^(get|post|put|patch|delete|head|options)$/i.test(method))
        .map((method) => ({ method: method.toUpperCase(), path, source })),
    );
  } catch {
    return [];
  }
}

function candidateUrlsFromOperations(target: URL, operations: Array<{ path: string }>): string[] {
  return operations
    .filter((op) => !/[{}]/.test(op.path))
    .map((op) => {
      try { return new URL(op.path, target).toString(); } catch { return ""; }
    })
    .filter(Boolean);
}

export async function discoverApis(target: URL, pages: CrawlPage[], options: ScanOptions): Promise<ApiDiscovery> {
  const candidates = new Set<string>();
  const openApiDocs: Evidence[] = [];
  const graphqlEndpoints: Evidence[] = [];
  const sensitiveJson: Evidence[] = [];
  const discoveredOperations: ApiDiscovery["discoveredOperations"] = [];

  for (const file of options.openApiFiles) {
    try {
      if (!existsSync(file)) continue;
      const body = readFileSync(file, "utf8");
      const operations = operationsFromOpenApi(body, file);
      if (operations.length) {
        openApiDocs.push({ observed: `imported ${operations.length} operation(s)`, url: file });
        discoveredOperations.push(...operations);
        for (const url of candidateUrlsFromOperations(target, operations)) addCandidate(candidates, target, url);
      }
    } catch {}
  }

  for (const page of pages) {
    for (const raw of [page.url, page.finalUrl, ...page.links, ...page.routeHints, ...page.scripts]) addCandidate(candidates, target, raw);
  }
  if (options.mode !== "passive") {
    for (const path of ["/api", "/api/health", "/api/docs", "/swagger.json", "/openapi.json", "/v1/openapi.json", "/graphql"]) addCandidate(candidates, target, path);
  }

  for (const url of [...candidates].slice(0, options.evidenceLimit * 3)) {
    try {
      const res = await request(url, options, { redirect: "manual" });
      const bodyHead = res.body.slice(0, 8000);
      const content = `${res.headers["content-type"] ?? ""}\n${bodyHead}`;
      if (res.status >= 200 && res.status < 300 && OPENAPI_HINT.test(content)) {
        openApiDocs.push({ url: res.url, status: res.status, snippet: safeSnippet(res.body), requestId: res.requestId });
        discoveredOperations.push(...operationsFromOpenApi(res.body, res.url));
      }
      if (/\/graphql(?:$|\?)/i.test(new URL(res.url).pathname) || GRAPHQL_HINT.test(content)) {
        graphqlEndpoints.push({ url: res.url, status: res.status, snippet: safeSnippet(res.body), requestId: res.requestId });
      }
      if (!Object.keys(options.customHeaders).some((h) => /cookie|authorization/i.test(h)) && /"(email|phone|studentId|student_id|grade|marks|role|isAdmin|token|session|password|secret)"\s*:/i.test(bodyHead)) {
        sensitiveJson.push({ url: res.url, status: res.status, snippet: safeSnippet(res.body.replace(/"[^"\n]{20,}"/g, '"<redacted>"')), requestId: res.requestId });
      }
    } catch {}
  }

  return { candidates: [...candidates], openApiDocs, graphqlEndpoints, sensitiveJson, discoveredOperations };
}
