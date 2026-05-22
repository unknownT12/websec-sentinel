import { createHash } from "node:crypto";
import type { CrawlPage, HttpObservation, ScanContext } from "../types.js";
import { getHttpObservations } from "./http.js";

export type AuthState = "anonymous" | "authenticated-supplied" | "login-wall" | "forbidden" | "unknown";

export interface RequestModel {
  requestId: string;
  method: string;
  url: string;
  finalUrl: string;
  normalizedRoute: string;
  routeKey: string;
  status: number;
  statusClass: string;
  contentType: string;
  authState: AuthState;
  parameters: string[];
  parameterSignature: string;
  responseHash: string;
  responseFamily: string;
  responseLength: number;
  redirected: boolean;
  isHtml: boolean;
  isJson: boolean;
  isStaticAsset: boolean;
}

export interface AssessmentModel {
  requests: RequestModel[];
  pages: RequestModel[];
  uniqueRouteKeys: string[];
  duplicateRouteGroups: Array<{ routeKey: string; count: number; examples: string[] }>;
  parameterGroups: Array<{ routeKey: string; parameters: string[]; examples: string[] }>;
  statusDistribution: Record<string, number>;
  authDistribution: Record<AuthState, number>;
  loginWallRatio: number;
  soft404Signals: Array<{ routeKey: string; status: number; hash: string; examples: string[] }>;
  coverageVector: {
    requestCount: number;
    pageCount: number;
    routeCount: number;
    parameterizedRouteCount: number;
    formCount: number;
    scriptCount: number;
    authenticatedSignals: number;
    loginWallSignals: number;
  };
}

const STATIC_EXT = /\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|tar|gz|rar|7z|mp4|mp3|avi|mov|css|map)$/i;
const HEXISH = /^[a-f0-9]{12,}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LOGIN_HINT = /(login|signin|sign-in|auth|session|sso|account\/login)/i;

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function suppliedAuth(headers?: Record<string, string>): boolean {
  return Object.keys(headers ?? {}).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

export function normalizeRoute(raw: string): string {
  const url = new URL(raw);
  const parts = url.pathname.split("/").filter(Boolean).map((part) => {
    const decoded = decodeURIComponent(part);
    if (/^\d+$/.test(decoded)) return ":number";
    if (UUID.test(decoded)) return ":uuid";
    if (HEXISH.test(decoded)) return ":token";
    if (/^[A-Za-z0-9_-]{24,}$/.test(decoded)) return ":opaque";
    return decoded.toLowerCase();
  });
  return `/${parts.join("/")}${url.pathname.endsWith("/") && parts.length ? "/" : ""}` || "/";
}

function parameterSignature(url: URL): string {
  return [...url.searchParams.keys()].sort().join(",");
}

function classifyAuth(obs: HttpObservation, hasAuth: boolean): AuthState {
  const finalPath = (() => { try { return new URL(obs.finalUrl || obs.url).pathname; } catch { return ""; } })();
  if (obs.status === 401 || obs.status === 403) return "forbidden";
  if (obs.status >= 300 && obs.status < 400 && LOGIN_HINT.test(obs.headers.location ?? "")) return "login-wall";
  if (LOGIN_HINT.test(finalPath) && !LOGIN_HINT.test(new URL(obs.url).pathname)) return "login-wall";
  if (hasAuth) return "authenticated-supplied";
  if (LOGIN_HINT.test(finalPath)) return "anonymous";
  return hasAuth ? "authenticated-supplied" : "anonymous";
}

function responseFamily(obs: HttpObservation): string {
  const body = obs.body.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 1800);
  return hash(`${obs.status}:${obs.headers["content-type"] ?? ""}:${body}`);
}

export function buildRequestModel(obs: HttpObservation, hasAuth: boolean): RequestModel {
  const u = new URL(obs.finalUrl || obs.url);
  const contentType = obs.headers["content-type"] ?? "";
  const normalizedRoute = normalizeRoute(u.toString());
  const params = [...u.searchParams.keys()].sort();
  const sig = parameterSignature(u);
  const isStaticAsset = STATIC_EXT.test(u.pathname);
  return {
    requestId: obs.requestId,
    method: obs.method,
    url: obs.url,
    finalUrl: obs.finalUrl,
    normalizedRoute,
    routeKey: `${obs.method} ${normalizedRoute}${sig ? `?${sig}` : ""}`,
    status: obs.status,
    statusClass: `${Math.floor(obs.status / 100)}xx`,
    contentType,
    authState: classifyAuth(obs, hasAuth),
    parameters: params,
    parameterSignature: sig,
    responseHash: hash(obs.body),
    responseFamily: responseFamily(obs),
    responseLength: obs.body.length || obs.sizeBytes,
    redirected: obs.redirected,
    isHtml: /html/i.test(contentType),
    isJson: /json/i.test(contentType),
    isStaticAsset,
  };
}

export function buildAssessmentModel(context: ScanContext): AssessmentModel {
  const hasAuth = suppliedAuth(context.options.customHeaders);
  const observations = getHttpObservations();
  const requests = observations.map((obs) => buildRequestModel(obs, hasAuth));
  const pageIds = new Set(context.pages.map((p: CrawlPage) => p.requestId));
  const pages = requests.filter((r) => pageIds.has(r.requestId) || (r.isHtml && !r.isStaticAsset));

  const routeMap = new Map<string, RequestModel[]>();
  for (const r of requests) routeMap.set(r.routeKey, [...(routeMap.get(r.routeKey) ?? []), r]);

  const duplicateRouteGroups = [...routeMap.entries()]
    .filter(([, group]) => group.length > 1)
    .map(([routeKey, group]) => ({ routeKey, count: group.length, examples: group.slice(0, 3).map((r) => r.finalUrl || r.url) }))
    .sort((a, b) => b.count - a.count);

  const parameterGroups = [...routeMap.entries()]
    .map(([routeKey, group]) => ({ routeKey, parameters: [...new Set(group.flatMap((r) => r.parameters))].sort(), examples: group.slice(0, 3).map((r) => r.finalUrl || r.url) }))
    .filter((g) => g.parameters.length > 0);

  const statusDistribution: Record<string, number> = {};
  const authDistribution: Record<AuthState, number> = { anonymous: 0, "authenticated-supplied": 0, "login-wall": 0, forbidden: 0, unknown: 0 };
  for (const r of requests) {
    statusDistribution[r.statusClass] = (statusDistribution[r.statusClass] ?? 0) + 1;
    authDistribution[r.authState] = (authDistribution[r.authState] ?? 0) + 1;
  }

  const familyMap = new Map<string, RequestModel[]>();
  for (const r of requests.filter((x) => x.status === 200 && !x.isStaticAsset)) familyMap.set(r.responseFamily, [...(familyMap.get(r.responseFamily) ?? []), r]);
  const soft404Signals = [...familyMap.entries()]
    .filter(([, group]) => group.length >= 4 && new Set(group.map((r) => r.normalizedRoute)).size >= 3)
    .map(([hashValue, group]) => ({ routeKey: "multiple-routes", status: 200, hash: hashValue, examples: group.slice(0, 4).map((r) => r.finalUrl || r.url) }));

  const uniqueRouteKeys = [...new Set(requests.map((r) => r.routeKey))].sort();
  const formCount = context.pages.reduce((s, p) => s + p.forms.length, 0);
  const scriptCount = context.pages.reduce((s, p) => s + p.scripts.length, 0);
  const loginWallSignals = requests.filter((r) => r.authState === "login-wall" || r.authState === "forbidden").length;

  return {
    requests,
    pages,
    uniqueRouteKeys,
    duplicateRouteGroups,
    parameterGroups,
    statusDistribution,
    authDistribution,
    loginWallRatio: requests.length ? loginWallSignals / requests.length : 0,
    soft404Signals,
    coverageVector: {
      requestCount: requests.length,
      pageCount: pages.length,
      routeCount: uniqueRouteKeys.length,
      parameterizedRouteCount: parameterGroups.length,
      formCount,
      scriptCount,
      authenticatedSignals: requests.filter((r) => r.authState === "authenticated-supplied").length,
      loginWallSignals,
    },
  };
}
