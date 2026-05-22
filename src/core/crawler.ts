import type { CrawlDiagnostics, CrawlPage, PageForm, ScanOptions } from "../types.js";
import { isProhibitedPath, request, resolveUrl, sameOriginOnly } from "./http.js";

const LINK_RE = /(?:href|src|action)=['"]([^"'#]+)['"]/gi;
const FORM_RE = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
const ATTR_RE = /([a-zA-Z:-]+)(?:=['"]([^'"]*)['"])?/g;
const INPUT_RE = /<(input|textarea|select|button)\b[^>]*>/gi;
const ROUTE_RE = /["'`](\/[a-zA-Z0-9][a-zA-Z0-9_./?&=%:@-]{1,220})["'`]/g;
const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const META_REFRESH_RE = /<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+content=['"][^;]+;\s*url=([^'"]+)['"]/i;
const CSRF_RE = /(csrf|xsrf|authenticity|requestverification|__requestverificationtoken)/i;
const SKIP_EXT = /\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|tar|gz|rar|7z|mp4|mp3|avi|mov)$/i;

function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(ATTR_RE)) {
    const key = m[1]?.toLowerCase();
    if (!key) continue;
    out[key] = m[2] ?? "true";
  }
  return out;
}

function decodeHtml(value: string): string {
  return value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

function normalizeUrl(raw: string): string {
  const u = new URL(raw);
  u.hash = "";
  if ((u.pathname.endsWith("/") && u.pathname !== "/") && !u.search) u.pathname = u.pathname.slice(0, -1);
  return u.toString();
}

function extractTitle(body: string): string | undefined {
  const match = body.match(TITLE_RE)?.[1]?.replace(/\s+/g, " ").trim();
  return match ? decodeHtml(match) : undefined;
}

function extractForms(base: string, body: string): PageForm[] {
  const forms: PageForm[] = [];
  for (const formMatch of body.matchAll(FORM_RE)) {
    const formHtml = formMatch[0] ?? "";
    const formAttrs = attrs(formHtml.split(">", 1)[0] ?? "");
    const action = resolveUrl(base, formAttrs.action && formAttrs.action !== "true" ? decodeHtml(formAttrs.action) : base) ?? base;
    const method = (formAttrs.method && formAttrs.method !== "true" ? formAttrs.method : "GET").toUpperCase();
    const inputs: PageForm["inputs"] = [];
    let hasCsrfToken = CSRF_RE.test(formHtml);
    for (const inputMatch of formHtml.matchAll(INPUT_RE)) {
      const inputTag = inputMatch[0] ?? "";
      const inputAttrs = attrs(inputTag);
      const name = inputAttrs.name && inputAttrs.name !== "true" ? decodeHtml(inputAttrs.name) : "";
      const type = inputAttrs.type && inputAttrs.type !== "true" ? inputAttrs.type : inputMatch[1] ?? "input";
      if (CSRF_RE.test(name)) hasCsrfToken = true;
      const input = { name, type, required: inputAttrs.required === "true" || inputAttrs.required === "required" } as PageForm["inputs"][number];
      if (inputAttrs.autocomplete && inputAttrs.autocomplete !== "true") input.autocomplete = inputAttrs.autocomplete;
      if (inputAttrs.value && inputAttrs.value !== "true") input.value = decodeHtml(inputAttrs.value);
      inputs.push(input);
    }
    forms.push({ action: normalizeUrl(action), method, inputs, hasCsrfToken });
  }
  return forms;
}

function addResolved(links: Set<string>, base: string, raw: string | undefined): void {
  if (!raw) return;
  const value = decodeHtml(raw.trim());
  if (!value || value.startsWith("mailto:") || value.startsWith("tel:") || value.startsWith("javascript:") || value.startsWith("data:")) return;
  const resolved = resolveUrl(base, value);
  if (!resolved) return;
  try {
    const u = new URL(resolved);
    if (SKIP_EXT.test(u.pathname)) return;
    links.add(normalizeUrl(resolved));
  } catch {}
}

function extractLinks(base: string, body: string, includeRoutes = true): string[] {
  const links = new Set<string>();
  for (const match of body.matchAll(LINK_RE)) addResolved(links, base, match[1]);
  const meta = body.match(META_REFRESH_RE)?.[1];
  addResolved(links, base, meta);
  if (includeRoutes) {
    for (const match of body.matchAll(ROUTE_RE)) {
      const route = match[1];
      if (!route || route.startsWith("//") || SKIP_EXT.test(route)) continue;
      addResolved(links, base, route);
    }
  }
  return [...links];
}

function extractScripts(base: string, body: string): string[] {
  const scripts = new Set<string>();
  for (const match of body.matchAll(/<script\b[^>]*\bsrc=['"]([^'"]+)['"]/gi)) {
    const resolved = resolveUrl(base, decodeHtml(match[1] ?? ""));
    if (resolved) scripts.add(normalizeUrl(resolved));
  }
  return [...scripts];
}

function routeHints(base: string, body: string): string[] {
  return extractLinks(base, body, true).filter((u) => {
    try {
      const path = new URL(u).pathname;
      return !SKIP_EXT.test(path) && !/\.(css|js|map)$/i.test(path);
    } catch { return false; }
  });
}

async function addRobotsAndSitemapSeeds(target: URL, options: ScanOptions, queue: Array<{ url: string; depth: number }>, queued: Set<string>, diagnostics: CrawlDiagnostics): Promise<void> {
  if (options.mode === "passive") return;
  const seedUrls = [`${target.origin}/robots.txt`, `${target.origin}/sitemap.xml`];
  for (const seed of seedUrls) {
    try {
      const res = await request(seed, options, { redirect: "manual" });
      const matches = [...res.body.matchAll(/(?:Sitemap:\s*)?(https?:\/\/[^\s<]+)|<(?:loc)>([^<]+)<\/loc>|(?:Allow|Disallow):\s*(\/[^\s#]*)/gi)];
      for (const m of matches) {
        const raw = m[1] || m[2] || (m[3] && m[3] !== "/" ? `${target.origin}${m[3]}` : "");
        if (!raw) continue;
        const resolved = resolveUrl(target.toString(), raw);
        if (!resolved) continue;
        let u: URL;
        try { u = new URL(resolved); } catch { continue; }
        if (!sameOriginOnly(target, u, options.scope) || SKIP_EXT.test(u.pathname)) continue;
        const clean = normalizeUrl(u.toString());
        if (!queued.has(clean) && !isProhibitedPath(clean, options.prohibitedPaths)) {
          queued.add(clean);
          queue.push({ url: clean, depth: 1 });
        }
      }
    } catch (error) {
      diagnostics.requestFailures.push({ url: seed, error: `metadata seed failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }
}

export async function crawl(target: URL, options: ScanOptions): Promise<{ pages: CrawlPage[]; diagnostics: CrawlDiagnostics }> {
  const visited = new Set<string>();
  const queued = new Set<string>([normalizeUrl(target.toString())]);
  const queue: Array<{ url: string; depth: number }> = [{ url: normalizeUrl(target.toString()), depth: 0 }];
  const pages: CrawlPage[] = [];
  const diagnostics: CrawlDiagnostics = { attempted: 0, visited: 0, queued: 1, blockedByScope: 0, blockedByProhibitedPath: 0, requestFailures: [], skippedNonHtml: 0, discoveredLinks: 0, discoveredForms: 0, discoveredRouteHints: 0, discoveredScriptRoutes: 0, fetchedScripts: 0 };

  for (const seed of options.seedUrls) {
    const resolved = resolveUrl(target.toString(), seed);
    if (!resolved) continue;
    try {
      const u = new URL(resolved);
      if (!sameOriginOnly(target, u, options.scope)) { diagnostics.blockedByScope++; continue; }
      if (isProhibitedPath(u.toString(), options.prohibitedPaths)) { diagnostics.blockedByProhibitedPath++; continue; }
      const clean = normalizeUrl(u.toString());
      if (!queued.has(clean)) {
        queued.add(clean);
        queue.push({ url: clean, depth: 0 });
      }
    } catch {
      diagnostics.requestFailures.push({ url: seed, error: "seed URL was invalid" });
    }
  }

  await addRobotsAndSitemapSeeds(target, options, queue, queued, diagnostics);
  const fetchedScripts = new Set<string>();

  while (queue.length && pages.length < options.maxPages) {
    const item = queue.shift();
    if (!item || visited.has(item.url)) continue;
    if (isProhibitedPath(item.url, options.prohibitedPaths)) { diagnostics.blockedByProhibitedPath++; continue; }
    visited.add(item.url);
    diagnostics.attempted++;

    let obs;
    try {
      obs = await request(item.url, options);
    } catch (error) {
      diagnostics.requestFailures.push({ url: item.url, error: error instanceof Error ? error.message : String(error) });
      continue;
    }

    const contentType = obs.headers["content-type"] ?? "";
    const looksText = /html|text|json|xml|javascript|css|plain/i.test(contentType) || /^\s*</.test(obs.body) || obs.body.length > 0;
    if (!looksText) diagnostics.skippedNonHtml++;

    const base = obs.finalUrl || item.url;
    const links = extractLinks(base, obs.body, true);
    const forms = extractForms(base, obs.body);
    const scripts = extractScripts(base, obs.body);
    let routes = routeHints(base, obs.body);

    if (options.deepCrawl || options.mode === "validate") {
      for (const script of scripts.slice(0, 40)) {
        if (fetchedScripts.has(script)) continue;
        fetchedScripts.add(script);
        try {
          const scriptRes = await request(script, options);
          diagnostics.fetchedScripts = (diagnostics.fetchedScripts ?? 0) + 1;
          const scriptRoutes = routeHints(scriptRes.finalUrl || scriptRes.url, scriptRes.body).filter((u) => {
            try { return sameOriginOnly(target, new URL(u), options.scope); } catch { return false; }
          });
          diagnostics.discoveredScriptRoutes = (diagnostics.discoveredScriptRoutes ?? 0) + scriptRoutes.length;
          links.push(...scriptRoutes);
          routes.push(...scriptRoutes);
        } catch (error) {
          diagnostics.requestFailures.push({ url: script, error: `script route mining failed: ${error instanceof Error ? error.message : String(error)}` });
        }
      }
    }

    routes = [...new Set(routes)];
    diagnostics.discoveredLinks += links.length;
    diagnostics.discoveredForms += forms.length;
    diagnostics.discoveredRouteHints += routes.length;

    const title = extractTitle(obs.body);
    const page: CrawlPage = { ...obs, depth: item.depth, contentType, links: [...new Set(links)], forms, scripts, routeHints: routes };
    if (title) page.title = title;
    pages.push(page);

    if (item.depth >= options.crawlDepth) continue;
    for (const resolved of [...new Set(links)]) {
      if (pages.length + queue.length >= options.maxPages) break;
      if (isProhibitedPath(resolved, options.prohibitedPaths)) { diagnostics.blockedByProhibitedPath++; continue; }
      let candidate: URL;
      try { candidate = new URL(resolved); } catch { continue; }
      if (!sameOriginOnly(target, candidate, options.scope)) { diagnostics.blockedByScope++; continue; }
      const clean = normalizeUrl(candidate.toString());
      if (!visited.has(clean) && !queued.has(clean)) {
        queued.add(clean);
        queue.push({ url: clean, depth: item.depth + 1 });
      }
    }
  }

  diagnostics.visited = visited.size;
  diagnostics.queued = queued.size;
  return { pages, diagnostics };
}
