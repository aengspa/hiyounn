import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import { SCANNER_VERSION, RULESET_VERSION } from "@/lib/scanners/types";
import type { SecurityFinding, ScanScope, ScanStep, ScanPlan, PlannedCheck, CoverageGap, AiScanCoverage } from "@/lib/domain/types";
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
import { AiCodeScanner, AI_SCAN_GAP_RULE } from "@/lib/scanners/aiCodeScanner";
import { SemgrepScanner } from "@/lib/scanners/semgrepScanner";
import { GitleaksScanner } from "@/lib/scanners/gitleaksScanner";
import { CustomRuleScanner } from "@/lib/rules/customRules";
import { mergeAiIntoRules, mergeCorroborating } from "@/lib/scanners/findingMerge";
import type { RouteAuthzEntry } from "@/lib/domain/types";
import { isConfigured as isLlmConfigured } from "@/lib/ai/llmClient";
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

/** 확인하지 못한 검사 이유에 보여 줄 선행 조건의 쉬운 이름. */
const PREREQUISITE_KO: Record<string, string> = {
  source_checkout: "올린 코드",
  authorized_test_deployment: "주인임을 확인한 배포 주소",
  linked_baas_project: "연결된 데이터베이스 서비스(Supabase·Firebase) 정보",
  test_user_a: "시험용 계정 A",
  test_user_b: "시험용 계정 B",
  object_owned_by_a: "계정 A가 가진 시험용 데이터",
  object_owned_by_b: "계정 B가 가진 시험용 데이터",
  admin_session: "시험용 관리자 계정",
};

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
      // Gitleaks는 실행 파일이 있을 때만 적용된다(isApplicable).
      new BflaScanner(), new CustomRuleScanner(), new SemgrepScanner(), new GitleaksScanner(), new AiCodeScanner()];
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
      semgrep: "semgrep-scanner", gitleaks: "gitleaks-scanner", custom: "custom-rule-scanner",
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
        for (const check of rule.checks) coverageGaps.push({ ruleId: rule.id, checkId: check.id, reason: "올린 코드가 없어 코드 점검을 하지 못했어요." });
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
      if (check.when && !conditionMatches(check.when, context)) reason ||= "이 검사에 필요한 정보가 없어 하지 않았어요.";
      const missing = (rule.prerequisites[check.method] ?? []).filter((p) => prereq.missing.includes(p));
      if (missing.length) reason ||= `준비되지 않은 것이 있어 하지 않았어요: ${missing.map((p) => PREREQUISITE_KO[p] ?? p).join(", ")}`;
      const internalDemoCheck = context.isUserProject === false && rule.id === "WEB-002";
      if (rule.mode !== "A" && !internalDemoCheck && !context.ownershipVerified) reason ||= "사이트 주인임을 확인(DNS 또는 파일 확인 값)하지 않아 실제 사이트에 요청을 보내는 검사는 하지 않았어요.";
      if (!supportsNewToolCheck(check) && !legacyChecks.has(`${rule.id}/${check.id}`)) reason ||= "아직 이 검사를 실행하는 기능이 없어 하지 않았어요.";
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
    let aiCoverage: AiScanCoverage | undefined;
    let authzMatrix: RouteAuthzEntry[] | undefined;
    let semgrep: ScanScope["semgrep"] | undefined;
    const plannedIds = new Set(plan.selectedChecks.map((check) => check.ruleId));
    const plannedKeys = new Set(plan.selectedChecks.map((check) => `${check.ruleId}/${check.checkId}`));
    for (const scanner of await this.selectApplicable(context)) {
      const alwaysRun = ["ai-code-scanner", "semgrep-scanner", "gitleaks-scanner", "custom-rule-scanner"].includes(scanner.name);
      if (!alwaysRun && !(LEGACY_CHECKS[scanner.name] ?? []).some((key) => plannedKeys.has(key))) continue;
      if (scanner instanceof CustomRuleScanner) {
        // 사람이 승인한 규칙도 기준 규칙이다. 기존 규칙 결과와 같은 문제면 합친다.
        const custom = await scanner.scan(context);
        custom.forEach((finding) => this.decorateWithRule(finding));
        const merged = mergeCorroborating(findings, custom, "custom-rule");
        findings.push(...merged.kept);
        if (custom.length > 0) testedCategories.add("승인한 규칙");
        continue;
      }
      if (scanner instanceof SemgrepScanner) {
        // Semgrep은 기준 규칙 검사기다. 기존 규칙 결과와 같은 문제면 합치고 "Semgrep도 확인" 표시.
        const report = await scanner.scanWithReport(context);
        report.findings.forEach((finding) => this.decorateWithRule(finding));
        const merged = mergeCorroborating(findings, report.findings, "semgrep");
        findings.push(...merged.kept);
        semgrep = report.status;
        if (report.status.status === "ran") testedCategories.add("Semgrep 규칙 검사");
        continue;
      }
      if (scanner instanceof GitleaksScanner) {
        // 기본 비밀키 검사와 같은 줄의 같은 문제면 합치고 "Gitleaks도 확인" 표시.
        const report = await scanner.scanWithReport(context);
        report.findings.forEach((finding) => this.decorateWithRule(finding));
        const merged = mergeCorroborating(findings, report.findings, "gitleaks");
        findings.push(...merged.kept);
        if (report.status === "ran") testedCategories.add("Gitleaks 비밀키 검사");
        else if (report.status === "failed") plan.coverageGaps.push({ ruleId: "SEC-001", checkId: "gitleaks", reason: "Gitleaks 실행에 실패해 추가 비밀키 검사를 하지 못했어요." });
        continue;
      }
      if (scanner instanceof AiCodeScanner) {
        // 규칙 결과가 기준이다. AI는 (1) 규칙이 놓친 문제를 더하고 (2) 규칙 항목에
        // 의견을 붙인다. 같은 문제를 가리키면 규칙 항목 하나로 합친다.
        // AI가 못 본 파일은 "발견 0건"이 아니라 "검사하지 못함"으로 남긴다.
        const report = await scanner.scanWithReport(context, { ruleFindings: findings });
        for (const f of findings) {
          const review = report.ruleReviews.get(f.id);
          if (review) f.aiReview = review;
        }
        const aiFindings = report.findings.filter((finding) => {
          this.decorateWithRule(finding);
          return !finding.ruleId || plannedIds.has(finding.ruleId);
        });
        // 권한 표 발견(규칙 판단) → 기존 규칙 발견과 합친 뒤, AI 발견을 전체와 합친다.
        report.authzFindings.forEach((finding) => this.decorateWithRule(finding));
        const table = mergeCorroborating(findings, report.authzFindings, "authz-table");
        findings.push(...table.kept);
        authzMatrix = report.authzMatrix;
        const { aiKept, merged } = mergeAiIntoRules(findings, aiFindings);
        findings.push(...aiKept);
        aiCoverage = { ...report.coverage, mergedWithRules: merged };
        this.recordAiGaps(plan, report.coverage);
        if (report.coverage.filesReviewed > 0) testedCategories.add("AI 분석 발견");
        continue;
      }
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
    if (!semgrep && context.isUserProject !== false) semgrep = { status: "not_installed", findings: 0 };
    if (!aiCoverage && context.isUserProject !== false && !isLlmConfigured()) {
      aiCoverage = { status: "off", filesTotal: 0, filesReviewed: 0, omitted: [], calls: 0, mergedWithRules: 0 };
    }
    // 일부 검사라도 실행한 분류는 "확인하지 못한 항목"에 다시 넣지 않는다.
    // 실행하지 못한 개별 검사는 plan.coverageGaps에 그대로 남는다.
    const gapCategories = [...new Set(plan.coverageGaps.map((gap) => getRule(gap.ruleId)?.titleKo ?? gap.ruleId))]
      .filter((title) => !testedCategories.has(title));
    const scope: ScanScope = { scanDate: now(), repository: context.repositoryUrl, deploymentUrl: context.deploymentUrl,
      testedCommit: context.commitSha, scannerVersion: SCANNER_VERSION, rulesetVersion: RULESET_VERSION,
      testedCategories: [...testedCategories],
      untestedCategories: [...UNTESTED_CATEGORIES, ...gapCategories],
      ...(aiCoverage ? { aiCoverage } : {}),
      ...(authzMatrix ? { authzMatrix } : {}),
      ...(semgrep ? { semgrep } : {}) };
    return { findings, scope, plan };
  }

  /** AI가 보지 못한 파일을 이유별로 한 줄씩 남긴다(파일마다 쓰지 않음). */
  private recordAiGaps(plan: ScanPlan, coverage: AiScanCoverage): void {
    const counts = new Map<string, number>();
    for (const o of coverage.omitted) counts.set(o.reason, (counts.get(o.reason) ?? 0) + 1);
    const text: Record<string, (n: number) => string> = {
      too_large: (n) => `너무 긴 파일 ${n}개는 AI 분석에 보내지 않았어요.`,
      over_budget: (n) => `한 번에 분석할 수 있는 양을 넘은 파일 ${n}개는 AI가 보지 못했어요.`,
      time_budget: (n) => `시간 한도 때문에 파일 ${n}개는 AI 분석을 시작하지 못했어요. 다시 점검하면 이어서 확인할 수 있어요.`,
      call_failed: (n) => `AI 응답을 받지 못해 파일 ${n}개를 분석하지 못했어요. 다시 점검하면 이어서 확인할 수 있어요.`,
      ai_unavailable: (n) => `AI 설정 문제(키 확인 필요)로 파일 ${n}개를 분석하지 못했어요.`,
    };
    for (const [reason, n] of counts) {
      plan.coverageGaps.push({ ruleId: AI_SCAN_GAP_RULE, checkId: "ai-code-review", reason: text[reason]?.(n) ?? `AI가 파일 ${n}개를 분석하지 못했어요.` });
    }
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
