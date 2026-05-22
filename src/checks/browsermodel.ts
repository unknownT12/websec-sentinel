import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

export const browserModelCheck: Check = {
  name: "browsermodel",
  description: "Validates whether modern JavaScript/browser execution was used or required for adequate surface coverage.",
  async run(context) {
    const d = context.diagnostics;
    const results: ScanResult[] = [];
    const hasBrowserPages = (d.browserPages ?? 0) > 0;
    const jsSignals = context.pages.reduce((n, p) => n + p.scripts.length + p.routeHints.length, 0);

    if (context.options.browserCrawl && !hasBrowserPages) {
      results.push(finding({
        id: "browsermodel.requested-but-not-executed",
        check: "browsermodel",
        category: "Browser Crawling",
        status: "warn",
        severity: "high",
        confidence: "confirmed",
        title: "Browser crawl was requested but did not execute successfully",
        detail: "The assessment requested real browser execution, but no browser-rendered pages were collected.",
        impact: "Modern JavaScript-heavy applications may hide routes, forms, tokens, and client-side workflows from a raw HTTP crawler.",
        remediation: "Run inside the Playwright Docker image or install Playwright, then rerun with --browser-crawl and approved login automation where applicable.",
        evidence: d.requestFailures.filter((f) => /browser|playwright/i.test(f.error)).slice(0, context.options.evidenceLimit).map((f) => ({ url: f.url, observed: f.error })),
        owasp: ["Security Testing Coverage"],
        exploitability: "none",
      }));
    }

    if (!context.options.browserCrawl && jsSignals >= 8) {
      results.push(finding({
        id: "browsermodel.javascript-surface-without-browser",
        check: "browsermodel",
        category: "Browser Crawling",
        status: "info",
        severity: "medium",
        confidence: "moderate",
        title: "JavaScript-rich surface observed without browser execution",
        detail: `The raw crawler observed ${jsSignals} script/route signals, but --browser-crawl was not enabled.`,
        impact: "Client-rendered routes and workflows may be under-tested.",
        remediation: "For professional assurance, rerun with --browser-crawl and approved login automation so JavaScript-rendered forms/routes are included.",
        evidence: [{ url: context.options.target, observed: `${jsSignals} script/route signals` }],
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("browsermodel", "Browser Crawling", "Browser crawling model is acceptable for configured run", hasBrowserPages ? `Browser pages collected: ${d.browserPages}` : "No strong browser-execution requirement was detected from the crawled surface."));
    }
    return results;
  },
};
