import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { requestWithoutCustomHeaders, safeSnippet } from "../core/http.js";
import { buildTestModel } from "../core/testmodel.js";

const PROTECTED_HINT = /(admin|dashboard|student|grade|result|profile|account|settings|api|export|report|marks?|assessment|course)/i;
const LOGIN_HINT = /(login|signin|sign-in|auth|session|sso)/i;

function hasAuth(headers: Record<string, string>): boolean {
  return Object.keys(headers).some((h) => /cookie|authorization|x-auth|session/i.test(h));
}

function family(body: string): string {
  return body.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 900);
}

function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  const fa = family(a);
  const fb = family(b);
  if (fa === fb) return true;
  const shorter = Math.min(fa.length, fb.length);
  const longer = Math.max(fa.length, fb.length);
  if (shorter < 200) return false;
  return shorter / Math.max(1, longer) > 0.88 && fa.slice(0, 200) === fb.slice(0, 200);
}

export const differentialCheck: Check = {
  name: "differential",
  description: "Safely compares authenticated observations against anonymous control requests to detect access-boundary uncertainty.",
  async run(context) {
    const results: ScanResult[] = [];
    if (!hasAuth(context.options.customHeaders)) {
      results.push(finding({
        id: "differential.skipped-no-auth-header",
        check: "differential",
        category: "Access-Control Differential",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Differential access testing skipped because no auth header was supplied",
        detail: "The check needs a client-approved test session header so it can compare authenticated vs anonymous responses safely.",
        impact: "Access-control boundaries cannot be evaluated from a single unauthenticated view.",
        remediation: "Run with an approved test account/session cookie and keep destructive/logout routes prohibited.",
        exploitability: "none",
      }));
      return results;
    }

    const model = buildTestModel(context);
    const candidates = model.nodes
      .filter((n) => n.method === "GET" && !n.classes.includes("static"))
      .filter((n) => n.riskWeight >= 6 || PROTECTED_HINT.test(`${n.url} ${n.route}`))
      .slice(0, context.options.evidenceLimit);

    const possibleExposure: ScanResult["evidence"] = [];
    const protectedBoundary: ScanResult["evidence"] = [];
    const uncertain: ScanResult["evidence"] = [];

    for (const node of candidates) {
      const baseline = context.pages.find((p) => (p.finalUrl || p.url) === node.url);
      if (!baseline) continue;
      try {
        const anon = await requestWithoutCustomHeaders(node.url, context.options);
        const redirectedToLogin = anon.status >= 300 && anon.status < 400 && LOGIN_HINT.test(anon.headers.location ?? anon.finalUrl ?? "");
        const loginBody = LOGIN_HINT.test(anon.finalUrl || "") || /password/i.test(anon.body.slice(0, 2000));
        if (anon.status === 401 || anon.status === 403 || redirectedToLogin || loginBody) {
          protectedBoundary.push({ url: node.url, status: anon.status, observed: `anonymous control blocked or login-like; baseline=${baseline.status}`, requestId: anon.requestId });
          continue;
        }
        if (anon.status === baseline.status && similar(anon.body, baseline.body) && PROTECTED_HINT.test(`${node.url} ${node.route}`)) {
          possibleExposure.push({ url: node.url, status: anon.status, observed: `anonymous response similar to authenticated baseline for ${node.route}`, snippet: safeSnippet(anon.body), requestId: anon.requestId });
        } else {
          uncertain.push({ url: node.url, status: anon.status, observed: `baseline=${baseline.status}, anonymous=${anon.status}, similar=${similar(anon.body, baseline.body)}`, requestId: anon.requestId });
        }
      } catch (error) {
        uncertain.push({ url: node.url, observed: `anonymous control request failed: ${error instanceof Error ? error.message : String(error)}` });
      }
    }

    if (possibleExposure.length) {
      results.push(finding({
        id: "differential.authenticated-content-accessible-anonymously",
        check: "differential",
        category: "Access-Control Differential",
        status: "warn",
        severity: "high",
        confidence: "strong",
        title: "Authenticated-looking content may be reachable without the supplied session",
        detail: "Anonymous control requests returned responses that were similar to authenticated baseline responses on protected-looking routes.",
        impact: "This may indicate missing server-side access control, cached authenticated content, or a route that appears protected but is actually public.",
        businessImpact: "For portals that contain student, grade, account, or administrative workflows, this kind of boundary weakness can become high-impact if manually confirmed.",
        remediation: "Manually verify each route, confirm cache behavior, require server-side authorization checks, and retest with multiple roles/test accounts.",
        evidence: possibleExposure,
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-284", "CWE-862"],
        exploitability: "practical",
        falsePositiveNotes: "This is a safe differential signal. Confirm manually before treating as a vulnerability; generic SPA shells can look similar.",
        verification: "Repeat the redacted replay/control request in a clean browser profile with no cookies and compare protected content presence, not just page shell similarity.",
      }));
    }

    if (uncertain.length && !possibleExposure.length) {
      results.push(finding({
        id: "differential.boundary-tested-with-uncertainty",
        check: "differential",
        category: "Access-Control Differential",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Differential access checks completed with no obvious exposure",
        detail: `${protectedBoundary.length} route(s) showed blocking/login-like behaviour; ${uncertain.length} route(s) require manual interpretation.`,
        impact: "No direct anonymous exposure signal was observed, but some comparisons were inconclusive due to redirects, generic shells, or response variance.",
        remediation: "Use role-based test accounts and browser capture to verify business authorization on high-value workflows.",
        evidence: [...protectedBoundary, ...uncertain].slice(0, context.options.evidenceLimit),
        exploitability: "none",
      }));
    }

    if (!results.length) {
      results.push(pass("differential", "Access-Control Differential", "Authenticated routes showed access-boundary controls in anonymous comparison", `Compared ${candidates.length} high-value candidate route(s) against anonymous controls.`));
    }

    return results;
  },
};
