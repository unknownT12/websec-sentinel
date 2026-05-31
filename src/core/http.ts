import { appendFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import type { HttpObservation, ScanOptions } from "../types.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
let lastRequestAt = 0;
let requestCounter = 0;
const observations: HttpObservation[] = [];

function bodyHash(body: string): string { return createHash("sha256").update(body).digest("hex").slice(0, 16); }
function responseFamily(body: string): string { return body.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 700); }

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => { out[key.toLowerCase()] = value; });
  return out;
}

export function sameOriginOnly(target: URL, candidate: URL, scope: string[]): boolean {
  const allowed = new Set(scope.map((h) => h.toLowerCase()));
  if (!["http:", "https:"].includes(candidate.protocol)) return false;
  if (!allowed.has(candidate.hostname.toLowerCase())) return false;
  if (!["http:", "https:"].includes(target.protocol)) return false;
  return true;
}

export function safeSnippet(value: string, max = 220): string {
  return value.replace(/[\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").slice(0, max);
}

export function isProhibitedPath(url: string, prohibitedPaths: string[]): boolean {
  if (!prohibitedPaths.length) return false;
  try {
    const candidate = new URL(url);
    return prohibitedPaths.some((path) => candidate.pathname === path || candidate.pathname.startsWith(path.endsWith("/") ? path : `${path}/`));
  } catch {
    return false;
  }
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const clone = { ...headers };
  for (const key of Object.keys(clone)) {
    if (/authorization|cookie|token|secret|key/i.test(key)) clone[key] = "<redacted>";
  }
  return clone;
}

function logObservation(path: string | undefined, obs: HttpObservation): void {
  if (!path) return;
  mkdirSync(dirname(path), { recursive: true });
  const entry = {
    requestId: obs.requestId,
    timestamp: new Date().toISOString(),
    method: obs.method,
    url: obs.url,
    finalUrl: obs.finalUrl,
    status: obs.status,
    elapsedMs: obs.elapsedMs,
    sizeBytes: obs.sizeBytes,
    redirected: obs.redirected,
    headers: redactHeaders(obs.headers),
  };
  appendFileSync(path, `${JSON.stringify(entry)}\n`);
}

async function performRequest(url: string, options: ScanOptions, init: RequestInit = {}, useCustomHeaders = true): Promise<HttpObservation> {
  if (isProhibitedPath(url, options.prohibitedPaths)) throw new Error(`Refusing prohibited path: ${new URL(url).pathname}`);
  if (options.insecureTls) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const now = Date.now();
  const wait = Math.max(0, options.rateLimitMs - (now - lastRequestAt));
  if (wait) await sleep(wait);
  lastRequestAt = Date.now();

  const started = performance.now();
  const method = String(init.method ?? "GET").toUpperCase();
  const requestId = `req-${++requestCounter}`;
  const requestHeaders: Record<string, string> = {
    "user-agent": options.userAgent,
    "accept": "text/html,application/xhtml+xml,application/json;q=0.9,text/plain;q=0.8,*/*;q=0.7",
    "x-websec-sentinel-request-id": requestId,
    ...(useCustomHeaders ? options.customHeaders : {}),
    ...(init.headers as Record<string, string> | undefined ?? {}),
  };
  const res = await fetch(url, {
    ...init,
    redirect: init.redirect ?? "follow",
    headers: requestHeaders,
    signal: AbortSignal.timeout(options.timeoutMs),
  });

  const contentType = res.headers.get("content-type") ?? "";
  let body = "";
  if (method !== "HEAD" && /text|json|xml|javascript|html|css|plain/i.test(contentType)) {
    const text = await res.text();
    body = text.slice(0, options.maxBodyBytes);
  }

  const obs: HttpObservation = {
    url,
    method,
    status: res.status,
    redirected: res.redirected,
    finalUrl: res.url,
    headers: headersToRecord(res.headers),
    requestHeaders: redactHeaders(requestHeaders),
    body,
    elapsedMs: Math.round(performance.now() - started),
    requestId,
    sizeBytes: Number(res.headers.get("content-length") ?? body.length),
    bodyHash: bodyHash(body),
    responseFamily: responseFamily(body),
    authState: Object.keys(requestHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h)) ? "header-authenticated" : "anonymous",
  };
  observations.push({ ...obs, headers: redactHeaders(obs.headers), requestHeaders: redactHeaders(obs.requestHeaders ?? {}), body: obs.body ? safeSnippet(obs.body, 500) : "" });
  logObservation(options.jsonlLog, obs);
  return obs;
}

export async function request(url: string, options: ScanOptions, init: RequestInit = {}): Promise<HttpObservation> {
  return performRequest(url, options, init, true);
}

export async function requestWithoutCustomHeaders(url: string, options: ScanOptions, init: RequestInit = {}): Promise<HttpObservation> {
  return performRequest(url, options, init, false);
}

export async function requestWithExtraHeaders(url: string, options: ScanOptions, headers: Record<string, string>, init: RequestInit = {}): Promise<HttpObservation> {
  return performRequest(url, options, { ...init, headers: { ...(init.headers as Record<string, string> | undefined ?? {}), ...headers } }, true);
}

export function getHttpObservations(): HttpObservation[] {
  return [...observations];
}

export function resetHttpState(): void {
  lastRequestAt = 0;
  requestCounter = 0;
  observations.length = 0;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function replayCommands(): string[] {
  return observations.map((obs) => {
    const headerBits = Object.entries(redactHeaders(obs.requestHeaders ?? {}))
      .filter(([k]) => !/content-length|transfer-encoding|connection/i.test(k))
      .slice(0, 20)
      .map(([k, v]) => `-H ${shellQuote(`${k}: ${v}`)}`)
      .join(" ");
    return `curl -i -X ${obs.method} ${headerBits} ${shellQuote(obs.url)}`.replace(/\s+/g, " ").trim();
  });
}

export function resolveUrl(base: string, href: string): string | null {
  try {
    const url = new URL(href, base);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}
