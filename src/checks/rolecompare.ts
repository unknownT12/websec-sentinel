import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { requestWithExtraHeaders, safeSnippet } from "../core/http.js";
import { buildTestModel } from "../core/testmodel.js";

function similarity(a: string, b: string): number {
  const clean = (x: string) => x.replace(/\d{4,}/g, "#").replace(/[a-f0-9]{16,}/gi, "#").replace(/\s+/g, " ").slice(0, 1200);
  const aa = clean(a); const bb = clean(b);
  if (!aa || !bb) return 0;
  let same = 0;
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] === bb[i]) same++;
  return same / Math.max(aa.length, bb.length, 1);
}

export const roleCompareCheck: Check = {
  name: "rolecompare",
  description: "Performs safe role-vs-role response comparison using approved role-labelled session headers.",
  async run(context) {
    const roles = context.options.roleHeaders;
    if (roles.length < 2) {
      return [finding({
        id: "rolecompare.not-enough-roles",
        check: "rolecompare",
        category: "Role-Based Access Control",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "Role comparison not executed",
        detail: "Fewer than two approved role headers were supplied.",
        impact: "Student-vs-lecturer-vs-admin authorization boundaries cannot be evaluated without approved role-labelled sessions.",
        remediation: "Use repeatable --role-header \"student|Cookie: ...\" and --role-header \"lecturer|Cookie: ...\" with dedicated test accounts.",
        exploitability: "none",
      })];
    }

    const model = buildTestModel(context);
    const candidates = model.nodes.filter((n) => n.method === "GET" && (n.riskWeight >= 6 || /admin|student|grade|profile|account|api|report/i.test(n.url))).slice(0, Math.min(10, context.options.evidenceLimit));
    const exposures: ScanResult["evidence"] = [];
    const tested: ScanResult["evidence"] = [];

    for (const node of candidates) {
      const responses = [] as Array<{ role: string; status: number; body: string; requestId: string }>;
      for (const role of roles.slice(0, 4)) {
        try {
          const obs = await requestWithExtraHeaders(node.url, context.options, role.headers);
          responses.push({ role: role.role, status: obs.status, body: obs.body, requestId: obs.requestId });
        } catch {}
      }
      for (let i = 0; i < responses.length; i++) {
        for (let j = i + 1; j < responses.length; j++) {
          const a = responses[i]!; const b = responses[j]!;
          const sim = similarity(a.body, b.body);
          tested.push({ url: node.url, observed: `${a.role}/${a.status} vs ${b.role}/${b.status}; similarity=${Math.round(sim * 100)}%`, requestId: `${a.requestId},${b.requestId}` });
          if (a.status === 200 && b.status === 200 && sim > 0.92 && /admin|grade|student|profile|report|api/i.test(node.url)) {
            exposures.push({ url: node.url, status: 200, observed: `${a.role} and ${b.role} saw highly similar high-value content`, snippet: safeSnippet(a.body), requestId: `${a.requestId},${b.requestId}` });
          }
        }
      }
    }

    if (exposures.length) {
      return [finding({
        id: "rolecompare.high-value-content-not-role-separated",
        check: "rolecompare",
        category: "Role-Based Access Control",
        status: "warn",
        severity: "high",
        confidence: "strong",
        title: "High-value routes may not be separated across roles",
        detail: "Approved role-labelled sessions received highly similar responses on protected-looking routes.",
        impact: "This may indicate broken role-level authorization or generic shells that require manual content verification.",
        remediation: "Manually verify role-specific data and enforce server-side authorization checks for each role and object.",
        evidence: exposures,
        owasp: ["A01:2021 Broken Access Control"],
        cwe: ["CWE-862", "CWE-863"],
        exploitability: "practical",
        falsePositiveNotes: "SPA shells can appear similar; confirm whether sensitive role-specific data is actually present.",
      })];
    }

    return [pass("rolecompare", "Role-Based Access Control", "Role comparison completed without obvious shared high-value content", `Compared ${candidates.length} candidate route(s) across ${roles.length} supplied role(s).`), ...(tested.length ? [{ id: "rolecompare.evidence", check: "rolecompare", category: "Role-Based Access Control", status: "info", severity: "info", confidence: "confirmed", title: "Role comparison evidence summary", detail: "Role comparison generated reproducible comparison observations.", impact: "Evidence supports manual verification of role boundaries.", remediation: "Review role comparison observations and preserve approved test credentials separately from reports.", evidence: tested.slice(0, context.options.evidenceLimit), exploitability: "none" } as ScanResult] : [])];
  },
};
