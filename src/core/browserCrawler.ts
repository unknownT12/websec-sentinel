import type { CrawlDiagnostics, CrawlPage, PageForm, ScanOptions } from "../types.js";
import { createHash } from "node:crypto";
import { isProhibitedPath, resolveUrl, sameOriginOnly, safeSnippet } from "./http.js";

type PlaywrightRuntime = { chromium: any; packageName: string };

function normalize(raw: string): string {
  const u = new URL(raw);
  u.hash = "";
  if (u.pathname.endsWith("/") && u.pathname !== "/" && !u.search) u.pathname = u.pathname.slice(0, -1);
  return u.toString();
}

function bodyHash(body: string): string {
  return createHash("sha256").update(body).digest("hex").slice(0, 16);
}

function responseFamily(body: string): string {
  return body.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 700);
}

async function importPlaywright(): Promise<PlaywrightRuntime | null> {
  try {
    const loader = new Function("return import('playwright')") as () => Promise<any>;
    const mod = await loader();
    if (mod?.chromium) return { chromium: mod.chromium, packageName: "playwright" };
  } catch {}
  try {
    const loader = new Function("return import('playwright-core')") as () => Promise<any>;
    const mod = await loader();
    if (mod?.chromium) return { chromium: mod.chromium, packageName: "playwright-core" };
  } catch {}
  return null;
}

async function fillFirst(page: any, selectors: string[], value: string): Promise<boolean> {
  for (const selector of selectors) {
    try {
      const loc = page.locator(selector).first();
      if ((await loc.count()) > 0) { await loc.fill(value, { timeout: 2500 }); return true; }
    } catch {}
  }
  return false;
}

async function clickFirst(page: any, selectors: string[]): Promise<boolean> {
  for (const selector of selectors) {
    try {
      const loc = page.locator(selector).first();
      if ((await loc.count()) > 0) {
        await Promise.allSettled([loc.click({ timeout: 2500 }), page.waitForLoadState("networkidle", { timeout: 8000 })]);
        return true;
      }
    } catch {}
  }
  return false;
}

function formsFromDom(raw: any[], base: string): PageForm[] {
  return raw.map((f) => ({
    action: normalize(resolveUrl(base, String(f.action || base)) ?? base),
    method: String(f.method || "GET").toUpperCase(),
    inputs: (Array.isArray(f.inputs) ? f.inputs : []).map((i: any) => ({
      name: String(i.name || ""),
      type: String(i.type || "input"),
      ...(i.autocomplete ? { autocomplete: String(i.autocomplete) } : {}),
      ...(i.value ? { value: String(i.value) } : {}),
      required: Boolean(i.required),
    })),
    hasCsrfToken: /csrf|xsrf|authenticity|requestverification/i.test(JSON.stringify(f)),
  }));
}

function sameScope(target: URL, candidate: string, options: ScanOptions): boolean {
  try { return sameOriginOnly(target, new URL(candidate), options.scope) && !isProhibitedPath(candidate, options.prohibitedPaths); } catch { return false; }
}

async function domSnapshot(browserPage: any, response: any | null, url: string, options: ScanOptions, depth: number, requestId: string): Promise<CrawlPage> {
  const data = await browserPage.evaluate(() => {
    const abs = (v: string | null) => { try { return v ? new URL(v, location.href).toString() : ""; } catch { return ""; } };
    const links = [...document.querySelectorAll('a[href],link[href],area[href]')].map((a: any) => abs(a.getAttribute('href'))).filter(Boolean);
    const scripts = [...document.querySelectorAll('script[src]')].map((s: any) => abs(s.getAttribute('src'))).filter(Boolean);
    const forms = [...document.querySelectorAll('form')].map((f: any) => ({
      action: f.getAttribute('action') || location.href,
      method: f.getAttribute('method') || 'GET',
      inputs: [...f.querySelectorAll('input,textarea,select,button')].map((i: any) => ({ name: i.getAttribute('name') || '', type: i.getAttribute('type') || i.tagName.toLowerCase(), autocomplete: i.getAttribute('autocomplete') || '', required: i.required, value: i.getAttribute('value') || '' }))
    }));
    const clickableTextRoutes = [...document.querySelectorAll('[data-route],[data-url],[routerlink],[href]')].map((e: any) => e.getAttribute('data-route') || e.getAttribute('data-url') || e.getAttribute('routerlink') || e.getAttribute('href')).filter(Boolean).map(abs);
    const html = document.documentElement.outerHTML;
    const routes = [...html.matchAll(/["'`](\/[a-zA-Z0-9][a-zA-Z0-9_./?&=%:@-]{1,220})["'`]/g)].map((m: any) => abs(m[1])).filter(Boolean);
    return { title: document.title, html, links: [...links, ...clickableTextRoutes], scripts, forms, routes, contentType: document.contentType || 'text/html' };
  });
  const headers = response ? await response.allHeaders().catch(() => ({})) : {};
  const body = safeSnippet(String(data.html || ""), options.maxBodyBytes);
  const page: CrawlPage = {
    url,
    method: "GET",
    status: response ? response.status() : 0,
    redirected: false,
    finalUrl: browserPage.url(),
    headers,
    requestHeaders: { "user-agent": options.userAgent },
    requestId,
    body,
    elapsedMs: 0,
    sizeBytes: body.length,
    bodyHash: bodyHash(body),
    responseFamily: responseFamily(body),
    depth,
    contentType: String(data.contentType || "text/html"),
    links: [...new Set((data.links as string[]).filter((l) => sameScope(new URL(options.target), l, options)).map(normalize))],
    forms: formsFromDom(data.forms, url),
    scripts: [...new Set((data.scripts as string[]).filter((s) => sameScope(new URL(options.target), s, options)).map(normalize))],
    routeHints: [...new Set((data.routes as string[]).filter((l) => sameScope(new URL(options.target), l, options)).map(normalize))],
    authState: options.loginUsername && options.loginPassword ? "browser-authenticated" : Object.keys(options.customHeaders).length ? "header-authenticated" : "unknown",
  };
  if (data.title) page.title = String(data.title);
  return page;
}

async function safeExploreClicks(page: any, target: URL, options: ScanOptions, queue: Array<{ url: string; depth: number }>, queued: Set<string>, depth: number): Promise<number> {
  let added = 0;
  if (!options.deepCrawl || depth >= options.crawlDepth) return 0;
  const selectors = ['a[href]', 'button:not([type=submit])', '[role=button]', '[data-route]', '[data-url]'];
  for (const selector of selectors) {
    let count = 0;
    try { count = Math.min(await page.locator(selector).count(), 12); } catch { continue; }
    for (let i = 0; i < count; i++) {
      try {
        const before = page.url();
        const item = page.locator(selector).nth(i);
        const text = (await item.innerText({ timeout: 1000 }).catch(() => "")).toLowerCase();
        if (/delete|remove|logout|pay|submit|save|update|reset|change password/.test(text)) continue;
        await Promise.allSettled([item.click({ timeout: 1000 }), page.waitForLoadState('networkidle', { timeout: 3000 })]);
        const after = normalize(page.url());
        if (after !== normalize(before) && sameScope(target, after, options) && !queued.has(after)) {
          queued.add(after); queue.push({ url: after, depth: depth + 1 }); added++;
        }
        if (page.url() !== before) await page.goto(before, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs }).catch(() => undefined);
      } catch {}
    }
  }
  return added;
}

export async function browserCrawl(target: URL, options: ScanOptions): Promise<{ pages: CrawlPage[]; diagnostics: Partial<CrawlDiagnostics> }> {
  if (!options.browserCrawl) return { pages: [], diagnostics: {} };
  const pw = await importPlaywright();
  if (!pw?.chromium) return { pages: [], diagnostics: { browserExecuted: false, requestFailures: [{ url: target.toString(), error: "--browser-crawl requested but Playwright is not installed. Use Dockerfile.browser or install Playwright with `npm i -D playwright && npx playwright install chromium`." }] } };

  const launchOptions: Record<string, unknown> = { headless: !options.browserHeadful };
  if (options.browserChannel) launchOptions.channel = options.browserChannel;
  if (options.browserExecutable) launchOptions.executablePath = options.browserExecutable;
  const browser = await pw.chromium.launch(launchOptions);
  const context = await browser.newContext({ userAgent: options.userAgent, extraHTTPHeaders: options.customHeaders, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  let consoleErrors = 0;
  const network = new Set<string>();
  const failures: Array<{ url: string; error: string }> = [];
  page.on('console', (msg: any) => { if (String(msg.type()) === 'error') consoleErrors++; });
  page.on('request', (req: any) => { try { network.add(req.url()); } catch {} });

  const pages: CrawlPage[] = [];
  const queued = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [];
  for (const seed of [options.loginUrl || options.target, ...options.seedUrls]) {
    const resolved = resolveUrl(target.toString(), seed);
    if (resolved && sameScope(target, resolved, options) && !queued.has(normalize(resolved))) { queued.add(normalize(resolved)); queue.push({ url: normalize(resolved), depth: 0 }); }
  }

  try {
    if (options.loginUrl && options.loginUsername && options.loginPassword) {
      await page.goto(options.loginUrl, { waitUntil: 'networkidle', timeout: options.timeoutMs });
      const userFilled = await fillFirst(page, [options.loginUsernameSelector || "", "input[type=email]", "input[name*=user i]", "input[name*=email i]", "input[name*=login i]", "input[name=username]"].filter(Boolean), options.loginUsername);
      const passFilled = await fillFirst(page, [options.loginPasswordSelector || "", "input[type=password]"].filter(Boolean), options.loginPassword);
      const clicked = await clickFirst(page, [options.loginSubmitSelector || "", "button[type=submit]", "input[type=submit]", "button"].filter(Boolean));
      if (!(userFilled && passFilled && clicked)) failures.push({ url: options.loginUrl, error: `login automation incomplete user=${userFilled} password=${passFilled} submit=${clicked}` });
      const current = normalize(page.url());
      if (sameScope(target, current, options) && !queued.has(current)) { queued.add(current); queue.push({ url: current, depth: 0 }); }
    }

    while (queue.length && pages.length < options.maxPages) {
      const item = queue.shift()!;
      try {
        const response = await page.goto(item.url, { waitUntil: 'networkidle', timeout: options.timeoutMs });
        const snap = await domSnapshot(page, response, page.url(), options, item.depth, `browser-${pages.length + 1}`);
        pages.push(snap);
        for (const next of [...snap.links, ...snap.routeHints]) {
          if (pages.length + queue.length >= options.maxPages) break;
          const clean = normalize(next);
          if (item.depth < options.crawlDepth && !queued.has(clean) && sameScope(target, clean, options)) { queued.add(clean); queue.push({ url: clean, depth: item.depth + 1 }); }
        }
        const added = await safeExploreClicks(page, target, options, queue, queued, item.depth);
        if (added) network.add(`browser-click-discovered:${added}`);
      } catch (error) {
        failures.push({ url: item.url, error: error instanceof Error ? error.message : String(error) });
      }
    }
  } finally { await browser.close(); }
  const launchMode = options.browserExecutable ? `executable:${options.browserExecutable}` : options.browserChannel ? `channel:${options.browserChannel}` : "bundled-chromium";
  return { pages, diagnostics: { browserExecuted: true, browserPages: pages.length, browserConsoleErrors: consoleErrors, browserNetworkRequests: network.size, browserNetworkUrls: [...network].filter((u) => sameScope(target, u, options)).slice(0, 200), browserPackage: pw.packageName, browserLaunchMode: `${launchMode};${options.browserHeadful ? "headful" : "headless"}`, requestFailures: failures } };
}
