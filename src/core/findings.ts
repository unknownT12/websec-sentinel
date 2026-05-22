import type { AttackPhase, Confidence, FindingKind, RemediationPriority, ScanResult, Severity, Status } from "../types.js";

export type FindingInput = {
  id: string;
  check: string;
  category: string;
  status: Status;
  kind?: FindingKind;
  severity: Severity;
  confidence?: Confidence;
  title: string;
  detail: string;
  impact: string;
  remediation: string;
  evidence?: ScanResult["evidence"];
  references?: string[];
  owasp?: string[];
  tags?: string[];
  cwe?: string[];
  cvss?: string;
  businessImpact?: string;
  exploitability?: "none" | "theoretical" | "practical" | "validated";
  attackPhase?: AttackPhase;
  remediationPriority?: RemediationPriority;
  likelihood?: ScanResult["likelihood"];
  assetExposure?: ScanResult["assetExposure"];
  verification?: string;
  falsePositiveNotes?: string;
  sla?: string;
  compliance?: string[];
  chainLinks?: string[];
};

function defaultKind(input: FindingInput): FindingKind {
  if (input.status === "pass") return "pass";
  if (input.status === "info" || input.severity === "info") return "informational";
  if (/coverage|assurance|maturity|product|benchmark|evidence|proof|model/i.test(input.check + " " + input.category)) return "coverage-gap";
  if (input.exploitability === "validated" && input.confidence === "confirmed") return "confirmed-vulnerability";
  if (/scanner|diagnostic/i.test(input.category)) return "scanner-diagnostic";
  return "risk-signal";
}

export function finding(input: FindingInput): ScanResult {
  const result: ScanResult = {
    id: input.id,
    check: input.check,
    category: input.category,
    status: input.status,
    kind: input.kind ?? defaultKind(input),
    severity: input.severity,
    confidence: input.confidence ?? "moderate",
    title: input.title,
    detail: input.detail,
    impact: input.impact,
    remediation: input.remediation,
    exploitability: input.exploitability ?? (input.status === "pass" ? "none" : "theoretical"),
  };
  if (input.evidence) result.evidence = input.evidence;
  if (input.references) result.references = input.references;
  if (input.owasp) result.owasp = input.owasp;
  if (input.tags) result.tags = input.tags;
  if (input.cwe) result.cwe = input.cwe;
  if (input.cvss) result.cvss = input.cvss;
  if (input.businessImpact) result.businessImpact = input.businessImpact;
  if (input.attackPhase) result.attackPhase = input.attackPhase;
  if (input.remediationPriority) result.remediationPriority = input.remediationPriority;
  if (input.likelihood) result.likelihood = input.likelihood;
  if (input.assetExposure) result.assetExposure = input.assetExposure;
  if (input.verification) result.verification = input.verification;
  if (input.falsePositiveNotes) result.falsePositiveNotes = input.falsePositiveNotes;
  if (input.sla) result.sla = input.sla;
  if (input.compliance) result.compliance = input.compliance;
  if (input.chainLinks) result.chainLinks = input.chainLinks;
  return result;
}

export function pass(check: string, category: string, title: string, detail: string, remediation = "Continue monitoring this control during future releases."): ScanResult {
  return finding({
    id: `${check}.pass`,
    check,
    category,
    status: "pass",
    severity: "info",
    confidence: "moderate",
    title,
    detail,
    impact: "The tested control appears to be in place for the observed surface.",
    remediation,
    exploitability: "none",
  });
}
