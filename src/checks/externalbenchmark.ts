import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Check, ScanResult } from "../types.js";
import { finding, pass } from "../core/findings.js";

type GroundTruthSurface = {
  id: string;
  description?: string;
  urlPattern?: string;
  formActionPattern?: string;
  parameter?: string;
  required?: boolean;
};

type GroundTruthFinding = {
  id: string;
  title: string;
  resultIds?: string[];
  category?: string;
  severity?: string;
  validationType?: "reflection" | "open-redirect" | "verbose-error" | "role-boundary" | "access-control" | "csrf" | "auth" | "headers";
  metricType?: "vulnerability" | "surface" | "coverage";
  urlPattern?: string;
  parameter?: string;
  required?: boolean;
};

type GroundTruth = {
  targetName: string;
  targetFamily?: "juice-shop" | "dvwa" | "webgoat" | "custom-lab" | string;
  version?: string;
  notes?: string;
  surfaces?: GroundTruthSurface[];
  expectedFindings?: GroundTruthFinding[];
};

function loadGroundTruth(file: string): GroundTruth {
  const parsed = JSON.parse(readFileSync(file, "utf8")) as GroundTruth;
  if (!parsed.targetName) throw new Error("Ground truth file must include targetName.");
  return parsed;
}

function matchRegex(pattern: string | undefined, value: string): boolean {
  if (!pattern) return false;
  try { return new RegExp(pattern, "i").test(value); } catch { return value.toLowerCase().includes(pattern.toLowerCase()); }
}

function corpus(context: Parameters<Check["run"]>[0]): string {
  return JSON.stringify(context.pages.map((p) => ({
    url: p.url,
    finalUrl: p.finalUrl,
    title: p.title,
    status: p.status,
    links: p.links,
    routes: p.routeHints,
    forms: p.forms,
    body: p.body.slice(0, 3500)
  })));
}

function surfaceMatched(surface: GroundTruthSurface, context: Parameters<Check["run"]>[0], text: string): boolean {
  if (surface.urlPattern && !matchRegex(surface.urlPattern, text)) return false;
  if (surface.formActionPattern) {
    const forms = context.pages.flatMap((p) => p.forms.map((f) => f.action));
    if (!forms.some((a) => matchRegex(surface.formActionPattern, a))) return false;
  }
  if (surface.parameter) {
    const paramSeen = context.pages.some((p) => {
      const urls = [p.url, p.finalUrl, ...p.links, ...p.routeHints];
      const inUrl = urls.some((u) => { try { return new URL(u).searchParams.has(surface.parameter!); } catch { return false; } });
      const inForm = p.forms.some((f) => f.inputs.some((i) => i.name === surface.parameter));
      return inUrl || inForm;
    });
    if (!paramSeen) return false;
  }
  return true;
}

function expectedFindingDiscoverable(f: GroundTruthFinding, context: Parameters<Check["run"]>[0], text: string): boolean {
  const urlOk = f.urlPattern ? matchRegex(f.urlPattern, text) : true;
  const paramOk = f.parameter ? context.pages.some((p) => {
    const urls = [p.url, p.finalUrl, ...p.links, ...p.routeHints];
    const inUrl = urls.some((u) => { try { return new URL(u).searchParams.has(f.parameter!); } catch { return false; } });
    const inForm = p.forms.some((form) => form.inputs.some((i) => i.name === f.parameter));
    return inUrl || inForm;
  }) : true;
  return urlOk && paramOk;
}

export const externalBenchmarkCheck: Check = {
  name: "externalbenchmark",
  description: "Evaluates whether an external benchmark target was reached deeply enough before post-report TP/FP/FN scoring.",
  async run(context) {
    if (!context.options.benchmarkGroundTruth) {
      return [finding({
        id: "externalbenchmark.not-provided",
        check: "externalbenchmark",
        category: "External Benchmarking",
        status: "info",
        severity: "info",
        confidence: "confirmed",
        title: "External benchmark ground truth not provided",
        detail: "No --benchmark-ground-truth file was supplied. Internal fixtures alone are not enough to support strong product claims.",
        impact: "Benchmark claims remain unsupported without a ground-truth contract and post-report TP/FP/FN metrics from the external benchmark runner.",
        remediation: "Run the scanner against a local authorized benchmark target and provide --benchmark-ground-truth examples/benchmarks/<target>.groundtruth.json.",
        exploitability: "none",
      })];
    }

    let gt: GroundTruth;
    try { gt = loadGroundTruth(context.options.benchmarkGroundTruth); }
    catch (error) {
      return [finding({
        id: "externalbenchmark.invalid-ground-truth",
        check: "externalbenchmark",
        category: "External Benchmarking",
        status: "fail",
        severity: "medium",
        confidence: "confirmed",
        title: "External benchmark ground-truth file could not be read",
        detail: error instanceof Error ? error.message : String(error),
        impact: "The scan cannot produce external benchmark proof without a valid ground-truth contract.",
        remediation: "Validate the JSON file against the documented schema in docs/V12_EXTERNAL_BENCHMARK_PROOF.md.",
        exploitability: "none",
      })];
    }

    const text = corpus(context);
    const surfaces = gt.surfaces ?? [];
    const expected = gt.expectedFindings ?? [];
    const matchedSurfaces = surfaces.filter((s) => surfaceMatched(s, context, text));
    const discoverableFindings = expected.filter((f) => expectedFindingDiscoverable(f, context, text));
    const surfaceScore = surfaces.length ? Math.round((matchedSurfaces.length / surfaces.length) * 100) : 100;
    const findingReachabilityScore = expected.length ? Math.round((discoverableFindings.length / expected.length) * 100) : 100;
    const score = Math.round((surfaceScore * 0.55) + (findingReachabilityScore * 0.45));

    context.diagnostics.externalBenchmarkExpected = surfaces.length + expected.length;
    context.diagnostics.externalBenchmarkMatched = matchedSurfaces.length + discoverableFindings.length;

    if (context.options.benchmarkEvidenceOut) {
      const artifact = {
        generatedAt: new Date().toISOString(),
        targetName: gt.targetName,
        targetFamily: gt.targetFamily,
        score,
        surfaceScore,
        findingReachabilityScore,
        matchedSurfaces: matchedSurfaces.map((s) => s.id),
        missedSurfaces: surfaces.filter((s) => !matchedSurfaces.includes(s)).map((s) => s.id),
        discoverableExpectedFindings: discoverableFindings.map((f) => f.id),
        unreachableExpectedFindings: expected.filter((f) => !discoverableFindings.includes(f)).map((f) => f.id),
        limitation: "This pre-report artifact measures benchmark reachability and surface coverage. Final TP/FP/FN metrics are calculated after report generation by tools/run-external-benchmark.mjs."
      };
      mkdirSync(dirname(context.options.benchmarkEvidenceOut), { recursive: true });
      writeFileSync(context.options.benchmarkEvidenceOut, JSON.stringify(artifact, null, 2));
    }

    const evidence = [
      { observed: `target=${gt.targetName}; family=${gt.targetFamily ?? "custom"}; score=${score}/100` },
      ...surfaces.map((s) => ({ observed: `surface ${s.id}: ${matchedSurfaces.includes(s) ? "reached" : "missed"}` })),
      ...expected.map((f) => ({ observed: `expected ${f.id}: ${discoverableFindings.includes(f) ? "reachable" : "not-reached"}` })),
    ].slice(0, context.options.evidenceLimit);

    if (score < 75) {
      return [finding({
        id: "externalbenchmark.external-proof-below-threshold",
        check: "externalbenchmark",
        category: "External Benchmarking",
        status: "warn",
        severity: score < 45 ? "high" : "medium",
        confidence: "confirmed",
        title: "External benchmark reachability is below threshold",
        detail: `${gt.targetName} benchmark reachability score was ${score}/100. Surfaces ${matchedSurfaces.length}/${surfaces.length}; expected finding surfaces ${discoverableFindings.length}/${expected.length}.`,
        impact: "The scan did not reach enough benchmark surface to make later TP/FP/FN scoring meaningful.",
        remediation: "Improve browser crawling, login automation, seeds, role sessions, and safe validation until benchmark reachability and final TP/FP/FN metrics are consistently strong.",
        evidence,
        exploitability: "none",
      })];
    }

    return [pass("externalbenchmark", "External Benchmarking", "External benchmark reachability reached threshold", `${gt.targetName}: score ${score}/100; surfaces ${matchedSurfaces.length}/${surfaces.length}; expected finding surfaces ${discoverableFindings.length}/${expected.length}.`), {
      id: "externalbenchmark.evidence-detail",
      check: "externalbenchmark",
      category: "External Benchmarking",
      status: "info",
      severity: "info",
      confidence: "confirmed",
      title: "External benchmark reachability detail",
      detail: `Ground-truth target ${gt.targetName}. This run established reachable benchmark surfaces before post-report TP/FP/FN scoring.`,
      impact: "This is a prerequisite for benchmark proof, not proof by itself. The external benchmark runner must still match actual result IDs against expected findings.",
      remediation: "Preserve the report JSON, evidence artifact, HAR, replay file, and benchmark metrics JSON as the case-study package.",
      evidence,
      exploitability: "none",
    } as ScanResult];
  },
};
