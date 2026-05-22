import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";
import { discoverApis } from "../core/apiDiscovery.js";

export const apiCheck: Check = {
  name: "api",
  description: "Maps API/documentation exposure and checks public JSON responses for sensitive-field signals.",
  async run(context) {
    const results: ScanResult[] = [];
    const api = await discoverApis(context.targetUrl, context.pages, context.options);

    if (api.sensitiveJson.length) {
      results.push(finding({
        id: "api.public-sensitive-json-signal",
        check: "api",
        category: "API Exposure",
        status: "fail",
        severity: "high",
        confidence: "moderate",
        title: "Public API response contains sensitive-field signals",
        detail: "An unauthenticated API-like endpoint returned JSON containing keys associated with accounts, students, grades, tokens, or privileged state.",
        impact: "Public APIs returning sensitive fields can expose personal data or support account/role abuse.",
        remediation: "Require authentication/authorization on sensitive APIs, minimize response fields, and add integration tests for unauthenticated and low-privilege access.",
        evidence: api.sensitiveJson.slice(0, context.options.evidenceLimit),
        owasp: ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures"],
        cwe: ["CWE-200", "CWE-862"],
        exploitability: "practical",
        falsePositiveNotes: "The scanner redacts long values and reports only field-name signals. Manually confirm with approved test data only.",
      }));
    }

    if (api.openApiDocs.length) {
      results.push(finding({
        id: "api.public-api-documentation",
        check: "api",
        category: "API Exposure",
        status: "warn",
        severity: "medium",
        confidence: "strong",
        title: "Public API documentation or schema detected",
        detail: `API documentation/schema content was reachable from the tested surface. Parsed ${api.discoveredOperations.length} operation(s).`,
        impact: "Public API schemas accelerate route discovery and validation planning if sensitive endpoints are documented.",
        remediation: "Restrict internal schemas/docs, or publish only intentionally public documentation without sensitive admin/internal routes.",
        evidence: api.openApiDocs.slice(0, context.options.evidenceLimit),
        owasp: ["A05:2021 Security Misconfiguration"],
        cwe: ["CWE-200"],
        exploitability: "theoretical",
      }));
    }

    if (api.graphqlEndpoints.length) {
      results.push(finding({
        id: "api.graphql-endpoint-detected",
        check: "api",
        category: "API Exposure",
        status: "info",
        severity: "info",
        confidence: "strong",
        title: "GraphQL endpoint signal detected",
        detail: "A GraphQL-looking endpoint or response was observed. Introspection and resolver authorization require approved follow-up testing.",
        impact: "GraphQL endpoints often concentrate object access controls and should be included in the assessment plan.",
        remediation: "Confirm introspection policy, authorization per resolver/object, query depth limits, and error-message hygiene.",
        evidence: api.graphqlEndpoints.slice(0, context.options.evidenceLimit),
        exploitability: "none",
      }));
    }

    if (api.discoveredOperations.length) {
      results.push(finding({
        id: "api.operation-inventory",
        check: "api",
        category: "API Inventory",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "API operation inventory generated",
        detail: `${api.discoveredOperations.length} OpenAPI/Swagger operation(s) were parsed for assessment planning.`,
        impact: "Operation inventory improves test planning and reduces blind spots.",
        remediation: "Use the operation inventory to seed authorized validation and role comparison runs.",
        evidence: api.discoveredOperations.slice(0, context.options.evidenceLimit).map((op) => ({ observed: `${op.method} ${op.path}`, url: op.source })),
        exploitability: "none",
      }));
    }

    if (!results.length) results.push(pass("api", "API Exposure", "No public sensitive API exposure signals detected", "No API documentation or sensitive unauthenticated JSON-field signal was detected on the tested surface."));
    return results;
  },
};
