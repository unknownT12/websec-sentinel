import type { Check, PageForm, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

const STATE_NAMES = /(amount|role|permission|grade|mark|score|student|user|email|phone|password|delete|remove|update|create|submit|approve|reject|status)/i;
const RESET_NAMES = /(reset|forgot|recover|password)/i;
const USERNAME_NAMES = /(user|email|login|student|id)/i;

function formKind(form: PageForm): "login" | "reset" | "register" | "state-change" | "search" | "unknown" {
  const names = form.inputs.map((i) => `${i.name} ${i.type}`).join(" ");
  const hasPassword = form.inputs.some((i) => /password/i.test(`${i.name} ${i.type}`));
  if (hasPassword && USERNAME_NAMES.test(names)) return "login";
  if (RESET_NAMES.test(`${form.action} ${names}`)) return "reset";
  if (/register|signup|create.?account/i.test(`${form.action} ${names}`)) return "register";
  if (form.method.toUpperCase() === "POST" || STATE_NAMES.test(names)) return "state-change";
  if (/search|query|filter/i.test(names)) return "search";
  return "unknown";
}

export const workflowsCheck: Check = {
  name: "workflows",
  description: "Models authentication and business workflows so reports explain what was actually exercised and what still needs role-pair testing.",
  async run(context) {
    const results: ScanResult[] = [];
    const forms = context.pages.flatMap((page) => page.forms.map((form) => ({ page, form, kind: formKind(form) })));
    const byKind = new Map<string, typeof forms>();
    for (const item of forms) byKind.set(item.kind, [...(byKind.get(item.kind) ?? []), item]);

    const loginForms = byKind.get("login") ?? [];
    const resetForms = byKind.get("reset") ?? [];
    const stateForms = [...(byKind.get("state-change") ?? []), ...(byKind.get("register") ?? [])];
    const authenticated = Object.keys(context.options.customHeaders).some((h) => /cookie|authorization|x-auth|session/i.test(h));

    if (loginForms.length) {
      results.push(finding({
        id: "workflows.login-flow-mapped",
        check: "workflows",
        category: "Workflow Assurance",
        status: "info",
        severity: "info",
        confidence: "strong",
        title: "Login workflow mapped",
        detail: `Detected ${loginForms.length} login-like form(s).`,
        impact: "Authentication is now part of the tested surface rather than an assumed control.",
        remediation: "Validate lockout policy, password reset, session regeneration, secure cookies, MFA/step-up rules, and post-login authorization with approved test accounts.",
        evidence: loginForms.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.url, method: x.form.method, observed: x.form.action, parameter: x.form.inputs.map((i) => i.name || i.type).join(", ") })),
        owasp: ["A07:2021 Identification and Authentication Failures"],
        exploitability: "none",
      }));
    }

    if (loginForms.length && !authenticated) {
      results.push(finding({
        id: "workflows.login-without-authenticated-followthrough",
        check: "workflows",
        category: "Workflow Assurance",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "Login found but authenticated follow-through was not tested",
        detail: "The scanner reached a login workflow but no approved session header was supplied for post-login route and role testing.",
        impact: "Most serious portal flaws live after authentication: IDOR, role bypass, data leakage, insecure caching, and unsafe workflow transitions.",
        businessImpact: "For education portals, post-login testing is required to evaluate student privacy, grade integrity, and staff-only controls.",
        remediation: "Use dedicated test accounts for each role and rerun with --header Cookie:<approved-test-session> plus prohibited path exclusions.",
        evidence: loginForms.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.url, observed: x.form.action })),
        owasp: ["A01:2021 Broken Access Control", "A07:2021 Identification and Authentication Failures"],
        exploitability: "none",
        remediationPriority: "immediate",
      }));
    }

    const missingCsrf = stateForms.filter((x) => !x.form.hasCsrfToken);
    if (missingCsrf.length) {
      results.push(finding({
        id: "workflows.state-change-csrf-coverage-gap",
        check: "workflows",
        category: "Workflow Assurance",
        status: "warn",
        severity: "medium",
        confidence: "moderate",
        title: "State-changing workflow needs CSRF verification",
        detail: `${missingCsrf.length} state-changing form(s) lacked an obvious visible CSRF marker in the crawled HTML.`,
        impact: "A missing marker does not prove exploitability, but it flags workflows that need server-side CSRF verification review.",
        remediation: "Confirm that every state-changing workflow has server-enforced CSRF protection, SameSite cookie strategy, and origin/referrer defenses where appropriate.",
        evidence: missingCsrf.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.url, method: x.form.method, observed: x.form.action })),
        owasp: ["A01:2021 Broken Access Control", "A04:2021 Insecure Design"],
        cwe: ["CWE-352"],
        exploitability: "theoretical",
      }));
    }

    if (resetForms.length && !context.pages.some((p) => /(otp|mfa|2fa|verification|token|code)/i.test(`${p.url}\n${p.body.slice(0, 2000)}`))) {
      results.push(finding({
        id: "workflows.password-reset-stepup-review",
        check: "workflows",
        category: "Workflow Assurance",
        status: "info",
        severity: "info",
        confidence: "low",
        title: "Password reset workflow needs step-up review",
        detail: "A password reset/recovery workflow was observed, but no obvious verification, MFA, OTP, or token-step signal was detected in the crawled surface.",
        impact: "Password reset is a high-value workflow that can become account takeover risk if verification, token expiry, or rate limiting is weak.",
        remediation: "Manually verify reset token entropy, expiry, single-use behavior, rate limiting, user enumeration resistance, and session invalidation after password change.",
        evidence: resetForms.slice(0, context.options.evidenceLimit).map((x) => ({ url: x.page.url, observed: x.form.action })),
        owasp: ["A07:2021 Identification and Authentication Failures"],
        exploitability: "none",
      }));
    }

    if (!forms.length) {
      results.push(finding({
        id: "workflows.no-forms-observed",
        check: "workflows",
        category: "Workflow Assurance",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "No forms observed, workflow testing is incomplete",
        detail: "The crawler did not observe any forms, so authentication, search, submission, and state-changing workflows could not be modeled.",
        impact: "The scan cannot claim deep application-layer coverage without exercising workflows or API contracts.",
        remediation: "Use --deep-crawl, a browser-like user-agent, and approved authenticated headers; consider adding scripted navigation for SPA-only applications.",
        exploitability: "none",
      }));
    } else if (!results.length) {
      results.push(pass("workflows", "Workflow Assurance", "Workflow model built without high-risk gaps", "Observed forms and workflows did not expose obvious assurance gaps within the safe automated checks."));
    }

    return results;
  },
};
