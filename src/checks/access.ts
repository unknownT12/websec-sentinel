import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { request, safeSnippet } from "../core/http.js";

const SENSITIVE_ROUTE = /(admin|dashboard|account|profile|student|grade|marks|results|api\/v?\d*\/|users|reports|settings)/i;
const SENSITIVE_CONTENT = /(student|grade|marks|account|profile|dashboard|admin|email|phone|user id|results)/i;
const COMMON_PROTECTED = ["/admin", "/dashboard", "/account", "/profile", "/student", "/students", "/grades", "/results", "/api/user", "/api/users", "/api/profile"];

export const accessCheck: Check = {
  name: "access",
  description: "Reviews access-control exposure signals without brute force, credential guessing, or data extraction.",
  async run(context) {
    const results: ScanResult[] = [];
    const observed = new Set<string>();
    for (const page of context.pages) {
      for (const u of [page.url, ...page.routeHints, ...page.links]) {
        try {
          const url = new URL(u);
          if (url.origin === context.targetUrl.origin && SENSITIVE_ROUTE.test(url.pathname)) observed.add(url.toString());
        } catch {}
      }
    }
    if (context.options.mode !== "passive") {
      for (const path of COMMON_PROTECTED) observed.add(`${context.targetUrl.origin}${path}`);
    }

    const exposures: ScanResult["evidence"] = [];
    for (const url of [...observed].slice(0, context.options.evidenceLimit * 2)) {
      try {
        const res = await request(url, context.options, { redirect: "manual" });
        const redirectedToLogin = res.status >= 300 && res.status < 400 && /(login|signin|auth)/i.test(res.headers.location ?? "");
        const blocked = [401, 403, 404].includes(res.status) || redirectedToLogin;
        if (!blocked && res.status >= 200 && res.status < 300 && SENSITIVE_CONTENT.test(res.body.slice(0, 3000))) {
          exposures.push({ url: res.url, status: res.status, snippet: safeSnippet(res.body), requestId: res.requestId });
        }
      } catch {}
    }

    if (exposures.length && !Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h))) {
      results.push(finding({
        id: "access.unauthenticated-sensitive-route-signal",
        check: "access",
        category: "Access Control",
        status: "fail",
        severity: "high",
        confidence: "moderate",
        title: "Unauthenticated sensitive route exposure signal",
        detail: "A route with account/admin/student-grade/API indicators returned successful content without an authenticated assessment header.",
        impact: "Sensitive routes that do not require authentication can expose records, account functions, or administrative surfaces.",
        businessImpact: "For gradebook or student systems, unauthenticated access-control weakness can create direct privacy and institutional trust impact.",
        remediation: "Require authentication and authorization on every sensitive route, deny by default at route middleware, and add automated access-control regression tests.",
        evidence: exposures.slice(0, context.options.evidenceLimit),
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-862", "CWE-863"],
        exploitability: "practical",
        verification: "Manually verify using an unauthenticated browser session and approved test accounts; avoid accessing real user records.",
      }));
    } else if (observed.size) {
      results.push(finding({
        id: "access.sensitive-routes-mapped",
        check: "access",
        category: "Access Control",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Sensitive routes mapped for manual authorization review",
        detail: "The scanner mapped routes that appear security-sensitive and should be included in manual role/access testing.",
        impact: "Access-control defects usually require authenticated role-pair testing that automated unauthenticated scans cannot prove.",
        remediation: "Test mapped routes with approved low-privilege and elevated test accounts; verify deny-by-default authorization behavior.",
        evidence: [...observed].slice(0, context.options.evidenceLimit).map((url) => ({ url, observed: "candidate sensitive route" })),
        owasp: ["A01:2021 Broken Access Control"],
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("access", "Access Control", "No unauthenticated sensitive route exposure signals detected", "No mapped sensitive route returned obvious unauthenticated successful sensitive content during safe checks."));
    return results;
  },
};
