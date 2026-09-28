import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import { SCANNER_VERSION, RULESET_VERSION } from "@/lib/scanners/types";
import type { SecurityFinding, ScanScope, ScanStep, ScanPlan, PlannedCheck, CoverageGap } from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { HeaderScanner } from "@/lib/scanners/headerScanner";
import { AuthorizationScanner } from "@/lib/scanners/authorizationScanner";
import { DependencyScanner } from "@/lib/scanners/dependencyScanner";
import { BaaSConfigScanner } from "@/lib/scanners/baasScanner";
import { StaticWebScanner } from "@/lib/scanners/staticWebScanner";
import { Asvs5Scanner } from "@/lib/scanners/asvs5Scanner";
import { ExposedEndpointScanner } from "@/lib/scanners/exposedEndpointScanner";
import { TlsScanner } from "@/lib/scanners/tlsScanner";
import { UserEnumerationScanner } from "@/lib/scanners/userEnumerationScanner";
import { BruteForceScanner } from "@/lib/scanners/bruteForceScanner";
import { CookieScanner } from "@/lib/scanners/cookieScanner";
import { BflaScanner } from "@/lib/scanners/bflaScanner";
import { AiCodeScanner } from "@/lib/scanners/aiCodeScanner";
import { RuleToolRuntime, type ProbeFetch } from "@/lib/scanners/ruleToolRuntime";
import { NEW_TOOL_CHECKS, executeNewToolCheck, supportsNewToolCheck } from "@/lib/scanners/newRuleTools";
import { extractBaasProjects } from "@/lib/scanners/deployedRuleTools";
import { verifyTargetOwnership } from "@/lib/scanners/ownershipVerification";
import { MODE_INCLUDES } from "@/lib/rules/definitions";
import { conditionMatches, modeForContext, selectorMatches } from "@/lib/rules/selectorEvaluation";
import { now, SCAN_STEP_LABELS, id } from "@/lib/util";
import { getRule, getRules, registryDigest, POLICY_VERSION } from "@/lib/rules/registry";
import { ruleForScanner, ruleIdForVerificationKey, STATIC_WEB_RULES } from "@/lib/rules/scannerBinding";
import { assertRegisteredRule, assertRegisteredTool, assertTierAllowed, assertNonDestructive, evaluatePrerequisites, GateError } from "@/lib/rules/executionGate";
import type { SecurityRule } from "@/lib/rules/types";
import { ASVS5_STATIC_SIGNALS } from "@/lib/rules/asvs5Catalog";

const UNTESTED_CATEGORIES = ["Complex Business Logic", "Social Engineering", "DDoS", "Internal Infrastructure", "Advanced Supply Chain Attacks"];

/** Existing scanners support only these exact checks; new declaration-only checks stay gaps. */
const LEGACY_CHECKS: Record<string, readonly string[]> = {
  "secret-scanner": ["SEC-001/scan-secrets"],
  "dependency-scanner": ["SEC-004/sca-audit"],
  "baas-config-scanner": ["BAAS-001/rls-policy-read"],
  "static-web-scanner": ["WEB-003/scan-xss-sinks", "WEB-004/scan-sql-injection", "WEB-004/scan-command-injection", "WEB-004/scan-code-eval", "WEB-005/scan-response-fields", "WEB-006/scan-path-traversal", "WEB-014/scan-idor-static"],
  "authorization-scanner": ["WEB-002/locate-object-endpoints", "WEB-002/cross-user-read", "WEB-002/owner-read", "WEB-002/cross-user-update", "WEB-002/owner-update"],
  "header-cors-scanner": ["WEB-007/http-headers"],
  "exposed-endpoint-scanner": ["WEB-008/probe-exposed-paths"],
  "tls-scanner": ["WEB-009/probe-tls"],
  "bruteforce-scanner": ["WEB-011/probe-bruteforce"],
  "cookie-scanner": ["WEB-012/probe-cookie-flags"],
  // ASVS 5.0.0 자동화 가능 정적 신호(모드 A).
  "asvs5-static-scanner": ASVS5_STATIC_SIGNALS.map((s) => `${s.ruleId}/scan-${s.key}`),
};

export class SecurityOrchestrator {
  private readonly scanners: SecurityScanner[];

  constructor(scanners?: SecurityScanner[], private readonly toolFetch?: ProbeFetch,
    private readonly ownershipVerifier: (context: ProjectContext) => Promise<boolean> = verifyTargetOwnership) {
    this.scanners = scanners ?? [new SecretScanner(), new DependencyScanner(), new BaaSConfigScanner(),
      new AuthorizationScanner(), new StaticWebScanner(), new Asvs5Scanner(), new HeaderScanner(), new ExposedEndpointScanner(),
      new TlsScanner(), new UserEnumerationScanner(), new BruteForceScanner(), new CookieScanner(),
      new BflaScanner(), new AiCodeScanner()];
  }

  getScanner(name: string): SecurityScanner | undefined { return this.scanners.find((s) => s.name === name); }

  scannerForFinding(finding: SecurityFinding): SecurityScanner | undefined {
    const key = finding.verificationKey ?? "";
    if (key.startsWith("tool:")) return undefined; // No automatic resolution without a dedicated regression contract.
    const names: Record<string, string> = {
      idor: "authorization-scanner", secret: "secret-scanner", headers: "header-cors-scanner", cors: "header-cors-scanner",
      dep: "dependency-scanner", rls: "baas-config-scanner", asvs5: "asvs5-static-scanner", xss: "static-web-scanner", inj: "static-web-scanner",
      expose: "static-web-scanner", trav: "static-web-scanner", sidor: "static-web-scanner", exposed: "exposed-endpoint-scanner",
      tls: "tls-scanner", enum: "user-enumeration-scanner", brute: "bruteforce-scanner", cookie: "cookie-scanner", bfla: "bfla-scanner", ai: "ai-code-scanner",
    };
    return this.getScanner(names[key.split(":")[0]]);
  }

  async selectApplicable(context: ProjectContext): Promise<SecurityScanner[]> {
    const applicable: SecurityScanner[] = [];
    for (const scanner of this.scanners) if (await scanner.isApplicable(context)) applicable.push(scanner);
    return applicable;
  }

  private async prepareContext(context: ProjectContext): Promise<ProjectContext> {
    return { ...context, ownershipVerified: modeForContext(context) === "A" ? false : await this.ownershipVerifier(context),
      linkedBaasProjects: extractBaasProjects(context.files, "verified_source") };
  }

  async buildScanPlan(context: ProjectContext): Promise<ScanPlan> {
    return this.buildPreparedPlan(await this.prepareContext(context));
  }

  private async buildPreparedPlan(context: ProjectContext): Promise<ScanPlan> {
    const applicable = await this.selectApplicable(context);
    const legacyChecks = new Set(applicable.flatMap((scanner) => LEGACY_CHECKS[scanner.name] ?? []));
    const selectedChecks: PlannedCheck[] = [];
    const coverageGaps: CoverageGap[] = [];
    for (const rule of getRules()) {
      if (!MODE_INCLUDES[modeForContext(context)].includes(rule.mode)) continue;
      if (rule.mode === "A" && !Object.keys(context.files).length) {
        for (const check of rule.checks) coverageGaps.push({ ruleId: rule.id, checkId: check.id, reason: "소스가 없어 정적 점검을 수행하지 못했습니다." });
        continue;
      }
      if (!selectorMatches(rule.selector, context)) continue;
      if (rule.coverageGap && conditionMatches(rule.coverageGap.when, context)) coverageGaps.push({
        ruleId: rule.id, checkId: "coverage", reason: rule.coverageGap.messageKo,
      });
      this.planRule(rule, context, selectedChecks, coverageGaps, legacyChecks);
    }
    return { schemaVersion: "1.0", planId: id("plan"), projectId: context.projectId,
      sourceCommitSha: context.commitSha, policyVersion: POLICY_VERSION, ruleRegistryDigest: registryDigest(), selectedChecks, coverageGaps };
  }

  private planRule(rule: SecurityRule, context: ProjectContext, selected: PlannedCheck[], gaps: CoverageGap[], legacyChecks: ReadonlySet<string>): void {
    const prereq = evaluatePrerequisites(rule, context);
    let gateReason = "";
    try {
      assertRegisteredRule(rule); assertNonDestructive(rule); assertTierAllowed(rule, context);
      for (const check of rule.checks) assertRegisteredTool(check);
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
      gateReason = error.message;
    }
    for (const check of rule.checks) {
      let reason = gateReason;
      if (check.when && !conditionMatches(check.when, context)) reason ||= "체크의 실행 조건에 필요한 입력이 없습니다.";
      const missing = (rule.prerequisites[check.method] ?? []).filter((p) => prereq.missing.includes(p));
      if (missing.length) reason ||= `선행 조건 부족: ${missing.join(", ")}`;
      const internalDemoCheck = context.isUserProject === false && rule.id === "WEB-002";
      if (rule.mode !== "A" && !internalDemoCheck && !context.ownershipVerified) reason ||= "DNS/파일 토큰으로 검증된 대상 소유권이 필요합니다.";
      if (!supportsNewToolCheck(check) && !legacyChecks.has(`${rule.id}/${check.id}`)) reason ||= "현재 구현에서 이 체크를 실행하지 못합니다.";
      if (reason) gaps.push({ ruleId: rule.id, checkId: check.id, reason });
      else selected.push({ ruleId: rule.id, ruleVersion: rule.version, componentId: context.projectId, checkId: check.id,
        toolId: check.toolId, tier: rule.execution.tier, prerequisiteStatus: "READY" });
    }
  }

  async run(context: ProjectContext): Promise<{ findings: SecurityFinding[]; scope: ScanScope; plan: ScanPlan }> {
    context = await this.prepareContext(context);
    const plan = await this.buildPreparedPlan(context);
    const findings: SecurityFinding[] = [];
    const testedCategories = new Set<string>();
    // Rules are in A/B/C order. Bundle discovery fills actual BaaS prerequisites before BaaS checks.
    for (const rule of getRules()) {
      const checks = rule.checks.filter((check) => check.toolId in NEW_TOOL_CHECKS &&
        plan.selectedChecks.some((selected) => selected.ruleId === rule.id && selected.checkId === check.id));
      if (!checks.length) continue;
      const runtime = new RuleToolRuntime(context, rule, this.toolFetch);
      for (const check of checks) {
        const result = await executeNewToolCheck(runtime, check);
        result.findings.forEach((finding) => { this.decorateWithRule(finding); findings.push(finding); });
        if (result.gap) {
          plan.coverageGaps.push({ ruleId: rule.id, checkId: check.id, reason: result.gap });
          plan.selectedChecks = plan.selectedChecks.filter((selected) => selected.ruleId !== rule.id || selected.checkId !== check.id);
        } else testedCategories.add(rule.titleKo);
        if (result.linkedBaasProjects?.length && rule.produces?.includes("linked_baas_project")) {
          context = { ...context, linkedBaasProjects: [...(context.linkedBaasProjects ?? []), ...result.linkedBaasProjects] };
          const refreshed = await this.buildPreparedPlan(context);
          for (const selected of refreshed.selectedChecks) {
            if (selected.toolId === "baas_access_probe" && !plan.selectedChecks.some((old) => old.ruleId === selected.ruleId && old.checkId === selected.checkId)) {
              plan.selectedChecks.push(selected);
              plan.coverageGaps = plan.coverageGaps.filter((old) => old.ruleId !== selected.ruleId || old.checkId !== selected.checkId);
            }
          }
        }
      }
    }
    const plannedIds = new Set(plan.selectedChecks.map((check) => check.ruleId));
    const plannedKeys = new Set(plan.selectedChecks.map((check) => `${check.ruleId}/${check.checkId}`));
    for (const scanner of await this.selectApplicable(context)) {
      if (scanner.name !== "ai-code-scanner" && !(LEGACY_CHECKS[scanner.name] ?? []).some((key) => plannedKeys.has(key))) continue;
      const results = await scanner.scan(context);
      for (const finding of results) {
        this.decorateWithRule(finding);
        if (finding.ruleId && !plannedIds.has(finding.ruleId)) continue;
        findings.push(finding);
      }
      const rule = ruleForScanner(scanner.name);
      if (rule) testedCategories.add(rule.titleKo);
      if (scanner.name === "static-web-scanner") {
        for (const ruleId of STATIC_WEB_RULES) if (plannedIds.has(ruleId)) testedCategories.add(getRule(ruleId)!.titleKo);
      }
      if (scanner.name === "ai-code-scanner") testedCategories.add("AI 분석 발견");
    }
    const scope: ScanScope = { scanDate: now(), repository: context.repositoryUrl, deploymentUrl: context.deploymentUrl,
      testedCommit: context.commitSha, scannerVersion: SCANNER_VERSION, rulesetVersion: RULESET_VERSION,
      testedCategories: [...testedCategories],
      untestedCategories: [...UNTESTED_CATEGORIES, ...new Set(plan.coverageGaps.map((gap) => getRule(gap.ruleId)?.titleKo ?? gap.ruleId))] };
    return { findings, scope, plan };
  }

  private decorateWithRule(finding: SecurityFinding): void {
    const rule = getRule(finding.ruleId ?? ruleIdForVerificationKey(finding.verificationKey) ?? "");
    if (rule) {
      finding.ruleId = rule.id; finding.family = rule.family;
      finding.standards = rule.standards.map((standard) => `${standard.framework} ${standard.id}`);
      finding.executionTier = rule.execution.tier;
      if (rule.checks.every((check) => check.confidence === "tentative")) finding.status = "detected";
    }
    finding.testStatus = toTestStatus(finding.status);
  }

  async plan(context: ProjectContext) {
    const plan = await this.buildScanPlan(context);
    const steps = new Set<ScanStep>(["detect_stack", "generating_findings"]);
    for (const scanner of await this.selectApplicable(context)) {
      if ((LEGACY_CHECKS[scanner.name] ?? []).some((key) => plan.selectedChecks.some((c) => `${c.ruleId}/${c.checkId}` === key))) steps.add(scanner.step);
    }
    for (const check of plan.selectedChecks) {
      if (check.toolId in NEW_TOOL_CHECKS) steps.add(check.tier === "PASSIVE" ? check.toolId === "package_provenance_checker" ? "dependency_scan" : "static_analysis" : "dynamic_testing");
    }
    return (Object.keys(SCAN_STEP_LABELS) as ScanStep[]).map((step) => ({ step, label: SCAN_STEP_LABELS[step], active: steps.has(step) }));
  }
}
