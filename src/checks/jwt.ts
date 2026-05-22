import type { Check, ScanResult } from "../types.js";

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return {
      header: JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")),
      payload: JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")),
    };
  } catch { return null; }
}

export const jwtCheck: Check = {
  name: "jwt",
  description: "Passively inspects observed JWTs for unsafe algorithms and missing expiry.",
  async run(context) {
    const results: ScanResult[] = [];
    const jwtRe = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
    for (const page of context.pages) {
      const joined = `${Object.values(page.headers).join("\n")}\n${page.body}`;
      for (const match of joined.matchAll(jwtRe)) {
        const token = match[0];
        const decoded = decodeJwt(token);
        if (!decoded) continue;
        const alg = String(decoded.header.alg ?? "unknown");
        const evidence = [{ url: page.url, status: page.status, observed: `${token.slice(0, 18)}…<redacted>` }];
        const base = { check: "jwt", category: "Token Security", confidence: "strong" as const, evidence, owasp: ["A07:2021 Identification and Authentication Failures", "A02:2021 Cryptographic Failures"] };
        if (/^none$/i.test(alg)) results.push({ ...base, id: "jwt.alg.none", status: "fail", severity: "critical", title: "JWT uses alg=none", detail: "An observed JWT declares the unsigned none algorithm.", impact: "Unsigned tokens can allow authentication bypass if accepted by the server.", remediation: "Reject alg=none and pin accepted algorithms server-side." });
        if (/^HS(256|384|512)$/i.test(alg)) results.push({ ...base, id: "jwt.alg.symmetric", status: "warn", severity: "low", title: `JWT uses symmetric algorithm ${alg}`, detail: "Symmetric JWT signing requires strict secret management across services.", impact: "Weak shared secrets or broad distribution can increase token forgery risk.", remediation: "Use strong rotated secrets or consider asymmetric algorithms such as RS256/ES256 for distributed systems." });
        if (!decoded.payload.exp) results.push({ ...base, id: "jwt.no-exp", status: "fail", severity: "medium", title: "JWT has no exp claim", detail: "An observed JWT does not include an expiry claim.", impact: "Compromised tokens may remain valid indefinitely.", remediation: "Set short-lived exp claims and enforce them server-side." });
      }
    }
    if (!results.length) results.push({ id: "jwt.pass", check: "jwt", category: "Token Security", status: "info", severity: "info", confidence: "low", title: "No JWTs observed", detail: "No JWTs were found in crawled responses or headers.", impact: "JWT-specific posture could not be determined without authenticated traffic.", remediation: "Run authenticated scans or review token issuance configuration." });
    return results;
  },
};
