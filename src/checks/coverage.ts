import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

export const coverageCheck: Check = {
  name: "coverage",
  description: "Explains exactly what was tested and flags weak scan coverage so scores cannot overstate confidence.",
  async run(context) {
    const results: ScanResult[] = [];
    const d = context.diagnostics;
    const pages = context.pages.length;
    const forms = context.pages.reduce((sum, p) => sum + p.forms.length, 0);
    const links = context.pages.reduce((sum, p) => sum + p.links.length, 0);
    const routes = context.pages.reduce((sum, p) => sum + p.routeHints.length, 0);
    const hasAuth = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));

    if (pages === 0) {
      results.push(finding({
        id: "coverage.no-pages-crawled",
        check: "coverage",
        category: "Assessment Coverage",
        status: "warn",
        severity: "high",
        confidence: "confirmed",
        title: "No application pages were crawled",
        detail: "The scanner could not collect a usable page body from the target, so application-layer coverage is effectively zero.",
        impact: "A report with zero crawled pages cannot support strong claims about forms, routes, authentication, business logic, or client-side exposure.",
        businessImpact: "The assessment may create false confidence because the score is based on a tiny tested surface.",
        remediation: "Re-run with browser-like headers, confirm the target is reachable from the scanner container, add an approved authenticated session if required, and check the request failure diagnostics.",
        evidence: d.requestFailures.slice(0, context.options.evidenceLimit).map((e) => ({ url: e.url, observed: e.error })),
        owasp: ["Security Testing Coverage"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    } else if (pages < 3 && context.options.crawlDepth > 1) {
      results.push(finding({
        id: "coverage.shallow-crawl",
        check: "coverage",
        category: "Assessment Coverage",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Crawler coverage is shallow",
        detail: `Only ${pages} page(s) were crawled despite crawl depth ${context.options.crawlDepth}.`,
        impact: "Important routes, forms, APIs, and client-side assets may not have been tested.",
        remediation: "Use an approved session, start from an authenticated landing page, or provide a URL that exposes navigable application links.",
        evidence: [{ url: context.options.target, observed: `${pages} pages, ${forms} forms, ${links} links, ${routes} route hints` }],
        exploitability: "none",
      }));
    }

    if (!hasAuth) {
      results.push(finding({
        id: "coverage.unauthenticated-only",
        check: "coverage",
        category: "Assessment Coverage",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Unauthenticated-only application coverage",
        detail: "No Cookie or Authorization-style header was supplied, so the scan only covered externally reachable behavior.",
        impact: "Access-control, IDOR, role separation, session workflow, and business-logic risks usually require approved authenticated test accounts.",
        remediation: "For client-approved testing, supply a dedicated test session with --header and add --prohibited-paths for logout/delete/billing/admin-write routes.",
        evidence: [{ url: context.options.target, observed: "No authenticated assessment header detected" }],
        exploitability: "none",
      }));
    }

    if (forms === 0 && pages > 0) {
      results.push(finding({
        id: "coverage.no-forms-detected",
        check: "coverage",
        category: "Assessment Coverage",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "No forms detected on crawled pages",
        detail: "The crawler did not observe HTML forms on the collected surface.",
        impact: "Form security checks such as CSRF, password handling, autocomplete, and method review had limited or no targets.",
        remediation: "Confirm whether the application renders forms client-side, requires authentication, or needs a browser-based crawler for full coverage.",
        evidence: [{ url: context.options.target, observed: `${pages} crawled page(s), 0 forms` }],
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("coverage", "Assessment Coverage", "Assessment coverage is adequate for configured mode", `Crawled ${pages} page(s), observed ${forms} form(s), ${links} link(s), and ${routes} route hint(s).`));
    }
    return results;
  },
};
