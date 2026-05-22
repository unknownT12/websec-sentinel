import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { evidenceFromRoutes, surfaceIntelligence } from "../core/intelligence.js";

export const foresightCheck: Check = {
  name: "foresight",
  description: "Builds a forward-looking attack-surface intelligence model from routes, scripts, forms, and workflow signals.",
  async run(context) {
    const intel = surfaceIntelligence(context.pages);
    const results: ScanResult[] = [];
    const limit = context.options.evidenceLimit;

    if (!context.pages.length) {
      results.push(finding({
        id: "foresight.no-surface-model",
        check: "foresight",
        category: "Predictive Surface Intelligence",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "No surface model could be built",
        detail: "The crawler did not obtain enough application surface to build route, workflow, or attack-path intelligence.",
        impact: "Without a route model, the assessment cannot answer what business functions, roles, or workflows were actually tested.",
        remediation: "Run with browser-like headers, approved test credentials, --deep-crawl, and an explicit scope. Confirm the target is reachable from the assessment environment.",
        exploitability: "none",
        remediationPriority: "immediate",
      }));
      return results;
    }

    const highValue = intel.highValueRoutes.filter((r) => r.klass !== "static");
    if (highValue.length) {
      results.push(finding({
        id: "foresight.high-value-route-map",
        check: "foresight",
        category: "Predictive Surface Intelligence",
        status: "info",
        severity: "info",
        confidence: "strong",
        title: "High-value business routes mapped",
        detail: `Mapped ${highValue.length} high-value route signal(s) across auth, admin, account, API, file, billing, or student-data surfaces.`,
        impact: "These routes are the priority set for manual role-pair testing, workflow abuse review, and regression protection.",
        remediation: "Use the mapped route list as the test plan for authorized manual validation: unauthenticated, low-privilege, expected user, and elevated role comparisons.",
        evidence: evidenceFromRoutes(highValue, limit),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        exploitability: "none",
        verification: "Confirm that each route denies unauthorized users and returns only records owned by the approved test identity.",
      }));
    }

    const adminOrStudent = highValue.filter((r) => r.klass === "admin" || r.klass === "student-data" || r.klass === "account");
    if (adminOrStudent.length && !Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h))) {
      results.push(finding({
        id: "foresight.unauthenticated-high-value-model",
        check: "foresight",
        category: "Predictive Surface Intelligence",
        status: "warn",
        severity: "high",
        confidence: "moderate",
        title: "High-value routes observed without authenticated coverage",
        detail: "The scanner observed high-value route names but the assessment did not include authenticated headers/session context.",
        impact: "A serious firm would not accept access-control assurance without testing these routes with approved role-pair sessions.",
        businessImpact: "Student, account, and administrative workflows are where privacy, integrity, and institutional trust failures usually occur.",
        remediation: "Create approved test users for each role, rerun authenticated scans, and compare allowed/denied behavior per route and object type.",
        evidence: evidenceFromRoutes(adminOrStudent, limit),
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-862", "CWE-863", "CWE-639"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    const api = intel.routes.filter((r) => r.klass === "api");
    const scripts = context.pages.flatMap((p) => p.scripts);
    if (api.length && scripts.length) {
      results.push(finding({
        id: "foresight.frontend-api-contract",
        check: "foresight",
        category: "API Contract Intelligence",
        status: "info",
        severity: "info",
        confidence: "strong",
        title: "Frontend-discovered API contract signals",
        detail: `Detected ${api.length} API-like route signal(s) from crawled pages and scripts.`,
        impact: "Modern applications often expose their effective API contract in frontend bundles, even when documentation is hidden.",
        remediation: "Treat client-discovered API routes as first-class test cases; enforce deny-by-default authorization and response-field minimization.",
        evidence: evidenceFromRoutes(api, limit),
        owasp: ["A01:2021 Broken Access Control", "A05:2021 Security Misconfiguration"],
        exploitability: "none",
      }));
    }

    const workflows = intel.authWorkflows;
    if (workflows.login && !workflows.logout) {
      results.push(finding({
        id: "foresight.auth-flow-no-logout-signal",
        check: "foresight",
        category: "Workflow Intelligence",
        status: "info",
        severity: "info",
        confidence: "low",
        title: "Login workflow observed without logout signal",
        detail: "The surface suggests a login workflow, but no logout/sign-out route was observed in the crawled model.",
        impact: "This may simply be due to unauthenticated coverage, but it should be checked because session termination is part of authentication assurance.",
        remediation: "During authenticated testing, verify logout invalidates the server session/token and prevents browser-back access to protected content.",
        evidence: [{ observed: JSON.stringify(workflows) }],
        owasp: ["A07:2021 Identification and Authentication Failures"],
        exploitability: "none",
      }));
    }

    if (!workflows.mfa && workflows.login) {
      results.push(finding({
        id: "foresight.no-mfa-signal",
        check: "foresight",
        category: "Workflow Intelligence",
        status: "info",
        severity: "info",
        confidence: "low",
        title: "No MFA/passkey workflow signal observed",
        detail: "No MFA, OTP, passkey, or WebAuthn route/signal appeared in the crawled application surface.",
        impact: "This is not a vulnerability by itself, but high-value portals should be reviewed for step-up authentication on sensitive actions.",
        remediation: "Assess MFA requirements for administrators, staff users, password reset, grade export, and other high-impact actions.",
        evidence: [{ observed: JSON.stringify(workflows) }],
        owasp: ["A07:2021 Identification and Authentication Failures"],
        exploitability: "none",
      }));
    }

    const choke = intel.graphChokePoints.filter((c) => c.score >= 10).slice(0, limit);
    if (choke.length) {
      results.push(finding({
        id: "foresight.route-graph-chokepoints",
        check: "foresight",
        category: "Attack Path Modeling",
        status: "info",
        severity: "info",
        confidence: "moderate",
        title: "Route graph chokepoints identified",
        detail: "The scanner identified routes with high route risk or graph centrality that should be prioritized during manual assessment.",
        impact: "Graph chokepoints often sit near authentication, dashboard, API, or workflow transitions where chained vulnerabilities become business-impactful.",
        remediation: "Review these routes first for access control, CSRF, caching, sensitive data, and state transition controls.",
        evidence: choke.map((c) => ({ url: c.url, observed: `inbound=${c.inbound}, outbound=${c.outbound}, graphScore=${c.score}` })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("foresight", "Predictive Surface Intelligence", "No predictive surface intelligence issues detected", "The observed surface did not expose high-value route, workflow, or graph-risk signals beyond the existing tested controls."));
    return results;
  },
};
