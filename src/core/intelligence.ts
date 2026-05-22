import type { CrawlPage, ScanResult } from "../types.js";

export type RouteClass = "auth" | "admin" | "student-data" | "account" | "api" | "billing" | "file" | "health" | "static" | "unknown";

const CLASSIFIERS: Array<[RouteClass, RegExp]> = [
  ["auth", /(login|signin|logout|register|signup|password|reset|forgot|mfa|2fa|otp|sso|oauth|saml)/i],
  ["admin", /(admin|manage|staff|moderator|superuser|console|cms|backoffice)/i],
  ["student-data", /(student|grade|marks|result|transcript|course|class|attendance|assessment)/i],
  ["account", /(account|profile|user|users|settings|me|tenant|role|permission)/i],
  ["api", /(\/api\/|graphql|openapi|swagger|rest|rpc|json)/i],
  ["billing", /(billing|payment|invoice|receipt|subscription|checkout|wallet)/i],
  ["file", /(upload|download|file|attachment|export|import|csv|xlsx|pdf)/i],
  ["health", /(health|status|metrics|actuator|ready|live|version|debug)/i],
  ["static", /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map)$/i],
];

export interface RouteSignal {
  url: string;
  path: string;
  klass: RouteClass;
  source: "page" | "link" | "script" | "form";
  risk: number;
}

export interface SurfaceIntelligence {
  routes: RouteSignal[];
  classCounts: Record<RouteClass, number>;
  highValueRoutes: RouteSignal[];
  graphChokePoints: Array<{ url: string; inbound: number; outbound: number; score: number }>;
  authWorkflows: {
    login: boolean;
    logout: boolean;
    register: boolean;
    passwordReset: boolean;
    mfa: boolean;
    sso: boolean;
  };
}

function classify(path: string): RouteClass {
  for (const [klass, re] of CLASSIFIERS) if (re.test(path)) return klass;
  return "unknown";
}

function riskOf(klass: RouteClass, path: string): number {
  const base: Record<RouteClass, number> = {
    auth: 8,
    admin: 10,
    "student-data": 10,
    account: 9,
    api: 8,
    billing: 10,
    file: 7,
    health: 6,
    static: 1,
    unknown: 2,
  };
  let score = base[klass] ?? 2;
  if (/[?&](id|user|uid|student|account|role|tenant|invoice)=/i.test(path)) score += 3;
  if (/(delete|remove|disable|reset|impersonate|export|download)/i.test(path)) score += 3;
  return Math.min(15, score);
}

function toSignal(raw: string, source: RouteSignal["source"]): RouteSignal | null {
  try {
    const u = new URL(raw);
    const path = `${u.pathname}${u.search}`;
    const klass = classify(path);
    return { url: u.toString(), path, klass, source, risk: riskOf(klass, path) };
  } catch {
    return null;
  }
}

export function surfaceIntelligence(pages: CrawlPage[]): SurfaceIntelligence {
  const byUrl = new Map<string, RouteSignal>();
  const inbound = new Map<string, number>();
  const outbound = new Map<string, number>();

  const add = (raw: string, source: RouteSignal["source"]) => {
    const sig = toSignal(raw, source);
    if (!sig) return;
    const existing = byUrl.get(sig.url);
    if (!existing || sig.risk > existing.risk) byUrl.set(sig.url, sig);
  };

  for (const page of pages) {
    add(page.finalUrl || page.url, "page");
    const outgoing = new Set<string>();
    for (const link of page.links) { add(link, "link"); outgoing.add(link); }
    for (const script of page.scripts) { add(script, "script"); outgoing.add(script); }
    for (const route of page.routeHints) { add(route, "script"); outgoing.add(route); }
    for (const form of page.forms) { add(form.action, "form"); outgoing.add(form.action); }
    outbound.set(page.finalUrl || page.url, outgoing.size);
    for (const dest of outgoing) inbound.set(dest, (inbound.get(dest) ?? 0) + 1);
  }

  const routes = [...byUrl.values()].sort((a, b) => b.risk - a.risk || a.path.localeCompare(b.path));
  const classCounts = {
    auth: 0,
    admin: 0,
    "student-data": 0,
    account: 0,
    api: 0,
    billing: 0,
    file: 0,
    health: 0,
    static: 0,
    unknown: 0,
  } satisfies Record<RouteClass, number>;
  for (const route of routes) classCounts[route.klass]++;

  const graphChokePoints = routes.map((route) => {
    const inCount = inbound.get(route.url) ?? 0;
    const outCount = outbound.get(route.url) ?? 0;
    return { url: route.url, inbound: inCount, outbound: outCount, score: route.risk + inCount + outCount };
  }).sort((a, b) => b.score - a.score).slice(0, 10);

  const allText = routes.map((r) => r.path).join("\n");
  const authWorkflows = {
    login: /(login|signin|auth)/i.test(allText) || pages.some((p) => p.forms.some((f) => f.inputs.some((i) => /password/i.test(i.type || i.name)))),
    logout: /logout|signout/i.test(allText),
    register: /register|signup|create-account/i.test(allText),
    passwordReset: /forgot|reset-password|password\/reset|change-password/i.test(allText),
    mfa: /mfa|2fa|otp|totp|webauthn|passkey/i.test(allText),
    sso: /sso|oauth|saml|openid|oidc/i.test(allText),
  };

  return {
    routes,
    classCounts,
    highValueRoutes: routes.filter((r) => r.risk >= 8).slice(0, 20),
    graphChokePoints,
    authWorkflows,
  };
}

export function evidenceFromRoutes(routes: RouteSignal[], limit: number): ScanResult["evidence"] {
  return routes.slice(0, limit).map((r) => ({ url: r.url, observed: `${r.klass} route from ${r.source}`, parameter: `risk=${r.risk}` }));
}
