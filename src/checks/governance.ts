import type { Check, ScanResult } from "../types.js";
import { request, safeSnippet } from "../core/http.js";
import { finding, pass } from "../core/findings.js";

const WELL_KNOWN = [
  ["/.well-known/security.txt", "security contact policy"],
  ["/.well-known/change-password", "change password endpoint"],
] as const;

export const governanceCheck: Check = {
  name: "governance",
  description: "Checks production security governance signals such as security.txt, change-password support, and authorization metadata.",
  async run(context) {
    const results: ScanResult[] = [];
    if (context.options.mode !== "passive") {
      for (const [path, label] of WELL_KNOWN) {
        try {
          const res = await request(`${context.targetUrl.origin}${path}`, context.options, { redirect: "manual" });
          if (res.status === 404) {
            results.push(finding({
              id: `governance.${path.replace(/[^a-z0-9]/gi, "_")}.missing`,
              check: "governance",
              category: "Security Governance",
              status: "warn",
              severity: "low",
              confidence: "strong",
              title: `Missing ${label}`,
              detail: `${path} was not available on the target origin.`,
              impact: "Missing governance endpoints can slow vulnerability disclosure, password reset UX, or incident coordination.",
              remediation: path.includes("security.txt") ? "Publish RFC 9116 security.txt with contact, policy, and expiry fields." : "Provide a well-known change-password redirect to the account password change flow.",
              evidence: [{ url: res.url, status: res.status }],
              references: path.includes("security.txt") ? ["RFC 9116"] : ["W3C Well-Known Change Password URL"],
              tags: ["governance", "production-readiness"],
            }));
          } else if (res.status >= 200 && res.status < 400) {
            results.push(finding({
              id: `governance.${path.replace(/[^a-z0-9]/gi, "_")}.present`,
              check: "governance",
              category: "Security Governance",
              status: "info",
              severity: "info",
              confidence: "moderate",
              title: `Governance endpoint present: ${label}`,
              detail: `${path} returned HTTP ${res.status}.`,
              impact: "This improves operational maturity and external security coordination.",
              remediation: "Review the content periodically and keep ownership, expiry, and contact details current.",
              evidence: [{ url: res.url, status: res.status, snippet: safeSnippet(res.body) }],
              exploitability: "none",
            }));
          }
        } catch {}
      }
    }

    if (context.options.mode === "validate" && (!context.options.client || !context.options.assessmentId || !context.options.tester)) {
      results.push(finding({
        id: "governance.authorization-metadata-incomplete",
        check: "governance",
        category: "Engagement Governance",
        status: "warn",
        severity: "medium",
        confidence: "confirmed",
        title: "Validation-mode report metadata is incomplete",
        detail: "validate mode was used without complete client, assessment-id, and tester metadata.",
        impact: "Incomplete authorization metadata weakens audit defensibility and evidence chain quality for client engagements.",
        remediation: "Run validate mode with --authorized --client --assessment-id --tester and the approved --scope list.",
        tags: ["authorization", "auditability"],
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("governance", "Security Governance", "Governance signals look acceptable", "No governance gaps were detected by this module."));
    return results;
  },
};
