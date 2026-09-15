import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import { SCANNER_VERSION, RULESET_VERSION } from "@/lib/scanners/types";
import type { SecurityFinding, ScanScope, ScanStep } from "@/lib/domain/types";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { HeaderScanner } from "@/lib/scanners/headerScanner";
import { AuthorizationScanner } from "@/lib/scanners/authorizationScanner";
import { DependencyScanner } from "@/lib/scanners/dependencyScanner";
import { BaaSConfigScanner } from "@/lib/scanners/baasScanner";
import { AiCodeScanner } from "@/lib/scanners/aiCodeScanner";
import { now, SCAN_STEP_LABELS } from "@/lib/util";

/**
 * SecurityOrchestrator
 *
 * Owns the registry of scanners, decides which are applicable to a given
 * project (Zero-Prompt: the user never picks scanners), runs them, and
 * assembles the scan scope. AI's role here is limited to interpretation and
 * selection — the evidence comes from the scanners themselves.
 */

const CATEGORY_BY_STEP: Partial<Record<ScanStep, string[]>> = {
  secret_scan: ["Secret Exposure"],
  authorization_analysis: ["Broken Access Control"],
  deployment_check: ["Security Headers", "CORS"],
  dependency_scan: ["Vulnerable Dependencies"],
  static_analysis: ["BaaS Misconfiguration"],
};

const UNTESTED_CATEGORIES = [
  "Complex Business Logic",
  "Social Engineering",
  "DDoS",
  "Internal Infrastructure",
  "Advanced Supply Chain Attacks",
];

export class SecurityOrchestrator {
  private readonly scanners: SecurityScanner[];

  constructor(scanners?: SecurityScanner[]) {
    this.scanners = scanners ?? [
      new SecretScanner(),
      new DependencyScanner(),
      new BaaSConfigScanner(),
      new AuthorizationScanner(),
      new HeaderScanner(),
      new AiCodeScanner(),
    ];
  }

  getScanner(name: string): SecurityScanner | undefined {
    return this.scanners.find((s) => s.name === name);
  }

  /** Find the scanner that owns a finding, based on its verificationKey prefix. */
  scannerForFinding(finding: SecurityFinding): SecurityScanner | undefined {
    const key = finding.verificationKey ?? "";
    if (key.startsWith("idor:")) return this.getScanner("authorization-scanner");
    if (key.startsWith("secret:")) return this.getScanner("secret-scanner");
    if (key.startsWith("headers:") || key.startsWith("cors:"))
      return this.getScanner("header-cors-scanner");
    if (key.startsWith("dep:")) return this.getScanner("dependency-scanner");
    if (key.startsWith("rls:")) return this.getScanner("baas-config-scanner");
    return undefined;
  }

  async selectApplicable(context: ProjectContext): Promise<SecurityScanner[]> {
    const applicable: SecurityScanner[] = [];
    for (const s of this.scanners) {
      if (await s.isApplicable(context)) applicable.push(s);
    }
    return applicable;
  }

  async run(
    context: ProjectContext
  ): Promise<{ findings: SecurityFinding[]; scope: ScanScope }> {
    const applicable = await this.selectApplicable(context);
    const findings: SecurityFinding[] = [];
    const testedCategories = new Set<string>();

    for (const scanner of applicable) {
      const results = await scanner.scan(context);
      findings.push(...results);
      for (const cat of CATEGORY_BY_STEP[scanner.step] ?? []) {
        testedCategories.add(cat);
      }
      if (scanner.name === "ai-code-scanner") {
        testedCategories.add("AI Detected");
      }
    }

    const scope: ScanScope = {
      scanDate: now(),
      repository: context.repositoryUrl,
      deploymentUrl: context.deploymentUrl,
      testedCommit: context.commitSha,
      scannerVersion: SCANNER_VERSION,
      rulesetVersion: RULESET_VERSION,
      testedCategories: [...testedCategories],
      untestedCategories: UNTESTED_CATEGORIES,
    };

    return { findings, scope };
  }

  /** Pipeline steps for the progress UI, in display order, with applicability. */
  async plan(context: ProjectContext) {
    const applicable = await this.selectApplicable(context);
    const applicableSteps = new Set(applicable.map((s) => s.step));
    // detect_stack and generating_findings always run.
    applicableSteps.add("detect_stack");
    applicableSteps.add("generating_findings");
    // dynamic_testing is represented by the authorization attack reproduction.
    if (applicableSteps.has("authorization_analysis")) {
      applicableSteps.add("dynamic_testing");
    }
    return (Object.keys(SCAN_STEP_LABELS) as ScanStep[]).map((step) => ({
      step,
      label: SCAN_STEP_LABELS[step],
      active: applicableSteps.has(step),
    }));
  }
}
