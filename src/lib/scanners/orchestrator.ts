import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import { SCANNER_VERSION, RULESET_VERSION } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  ScanScope,
  ScanStep,
  ScanPlan,
  PlannedCheck,
  CoverageGap,
} from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { HeaderScanner } from "@/lib/scanners/headerScanner";
import { AuthorizationScanner } from "@/lib/scanners/authorizationScanner";
import { DependencyScanner } from "@/lib/scanners/dependencyScanner";
import { BaaSConfigScanner } from "@/lib/scanners/baasScanner";
import { StaticWebScanner } from "@/lib/scanners/staticWebScanner";
import { ExposedEndpointScanner } from "@/lib/scanners/exposedEndpointScanner";
import { TlsScanner } from "@/lib/scanners/tlsScanner";
import { UserEnumerationScanner } from "@/lib/scanners/userEnumerationScanner";
import { BruteForceScanner } from "@/lib/scanners/bruteForceScanner";
import { CookieScanner } from "@/lib/scanners/cookieScanner";
import { BflaScanner } from "@/lib/scanners/bflaScanner";
import { AiCodeScanner } from "@/lib/scanners/aiCodeScanner";
import { now, SCAN_STEP_LABELS, id } from "@/lib/util";
import { getRule, getRules, registryDigest, POLICY_VERSION } from "@/lib/rules/registry";
import {
  ruleForScanner,
  ruleIdForVerificationKey,
  STATIC_WEB_RULES,
} from "@/lib/rules/scannerBinding";
import {
  assertRegisteredRule,
  assertRegisteredTool,
  assertTierAllowed,
  assertNonDestructive,
  evaluatePrerequisites,
  GateError,
} from "@/lib/rules/executionGate";
import type { SecurityRule } from "@/lib/rules/types";

/**
 * SecurityOrchestrator (규칙 기반, 문서 Phase A)
 *
 * 흐름: 규칙 레지스트리로 계획(ScanPlan)을 만들고 → 실행 게이트를 통과한
 * 스캐너만 실행 → 결과 finding에 규칙 메타(ruleId/standards/tier/testStatus)를
 * 부착한다. 게이트를 통과하지 못한 검사는 coverage_gap으로 기록한다.
 *
 * 도구 실행 승인과 최종 판정은 서버(이 클래스)만 한다. 모델/사용자 입력은
 * 실행 대상을 확정하지 못한다.
 */

// 미검사 카테고리(문서 13). 웹 대상 MVP 기준.
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
      new StaticWebScanner(),
      new HeaderScanner(),
      new ExposedEndpointScanner(),
      new TlsScanner(),
      new UserEnumerationScanner(),
      new BruteForceScanner(),
      new CookieScanner(),
      new BflaScanner(),
      new AiCodeScanner(),
    ];
  }

  getScanner(name: string): SecurityScanner | undefined {
    return this.scanners.find((s) => s.name === name);
  }

  scannerForFinding(finding: SecurityFinding): SecurityScanner | undefined {
    const key = finding.verificationKey ?? "";
    if (key.startsWith("idor:")) return this.getScanner("authorization-scanner");
    if (key.startsWith("secret:")) return this.getScanner("secret-scanner");
    if (key.startsWith("headers:") || key.startsWith("cors:"))
      return this.getScanner("header-cors-scanner");
    if (key.startsWith("dep:")) return this.getScanner("dependency-scanner");
    if (key.startsWith("rls:")) return this.getScanner("baas-config-scanner");
    if (
      key.startsWith("xss:") ||
      key.startsWith("inj:") ||
      key.startsWith("expose:") ||
      key.startsWith("trav:")
    )
      return this.getScanner("static-web-scanner");
    if (key.startsWith("exposed:"))
      return this.getScanner("exposed-endpoint-scanner");
    if (key.startsWith("tls:")) return this.getScanner("tls-scanner");
    if (key.startsWith("enum:"))
      return this.getScanner("user-enumeration-scanner");
    if (key.startsWith("brute:"))
      return this.getScanner("bruteforce-scanner");
    if (key.startsWith("cookie:")) return this.getScanner("cookie-scanner");
    if (key.startsWith("bfla:")) return this.getScanner("bfla-scanner");
    return undefined;
  }

  async selectApplicable(context: ProjectContext): Promise<SecurityScanner[]> {
    const applicable: SecurityScanner[] = [];
    for (const s of this.scanners) {
      if (await s.isApplicable(context)) applicable.push(s);
    }
    return applicable;
  }

  /**
   * 규칙 레지스트리로 스캔 계획을 만든다. 각 스캐너는 규칙에 바인딩되고,
   * 실행 게이트를 통과하면 selected_checks에, 못하면 coverage_gaps에 들어간다.
   */
  async buildScanPlan(context: ProjectContext): Promise<ScanPlan> {
    const applicable = await this.selectApplicable(context);
    const selectedChecks: PlannedCheck[] = [];
    const coverageGaps: CoverageGap[] = [];

    const applicableNames = new Set(applicable.map((s) => s.name));

    for (const scanner of applicable) {
      const rule = ruleForScanner(scanner.name);
      if (!rule) continue; // 단일 규칙에 매이지 않은 스캐너는 아래에서 별도 처리
      this.planRule(rule, context, selectedChecks, coverageGaps);
    }

    // 정적 웹 스캐너는 여러 규칙(WEB-003/004/005)을 담당한다. 스캐너가
    // 적용 대상이면 각 규칙을 개별적으로 게이트에 통과시켜 계획에 반영한다.
    if (applicableNames.has("static-web-scanner")) {
      for (const ruleId of STATIC_WEB_RULES) {
        const rule = getRule(ruleId);
        if (rule) this.planRule(rule, context, selectedChecks, coverageGaps);
      }
    }

    return {
      schemaVersion: "1.0",
      planId: id("plan"),
      projectId: context.projectId,
      sourceCommitSha: context.commitSha,
      policyVersion: POLICY_VERSION,
      ruleRegistryDigest: registryDigest(),
      selectedChecks,
      coverageGaps,
    };
  }

  /**
   * 단일 규칙을 게이트에 통과시켜 selectedChecks 또는 coverageGaps에 반영한다.
   * (여러 규칙을 담당하는 스캐너를 위해 규칙별 로직을 분리.)
   */
  private planRule(
    rule: SecurityRule,
    context: ProjectContext,
    selectedChecks: PlannedCheck[],
    coverageGaps: CoverageGap[]
  ): void {
    const gate = this.gateRule(rule, context);
    if (gate.blocked) {
      for (const chk of rule.checks) {
        coverageGaps.push({ ruleId: rule.id, checkId: chk.id, reason: gate.reason });
      }
      return;
    }

    const prereq = evaluatePrerequisites(rule, context);
    for (const chk of rule.checks) {
      const methodMissing = (rule.prerequisites[chk.method] ?? []).filter((c) =>
        prereq.missing.includes(c)
      );
      if (methodMissing.length > 0) {
        coverageGaps.push({
          ruleId: rule.id,
          checkId: chk.id,
          reason: `선행 조건 부족: ${methodMissing.join(", ")}`,
        });
        continue;
      }
      selectedChecks.push({
        ruleId: rule.id,
        ruleVersion: rule.version,
        componentId: context.projectId,
        checkId: chk.id,
        toolId: chk.toolId,
        tier: rule.execution.tier,
        prerequisiteStatus: "READY",
      });
    }
  }

  /** 규칙에 대해 게이트를 실행하고 차단 여부/사유를 반환(예외를 잡아서 사유화). */
  private gateRule(
    rule: SecurityRule,
    context: ProjectContext
  ): { blocked: boolean; reason: string } {
    try {
      assertRegisteredRule(rule);
      assertNonDestructive(rule);
      for (const chk of rule.checks) assertRegisteredTool(chk);
      assertTierAllowed(rule, context);
      return { blocked: false, reason: "" };
    } catch (e) {
      if (e instanceof GateError) {
        // TIER_NOT_ALLOWED는 "테스트 대상 없음" 등 정상적 미검사 사유.
        const reason =
          e.code === "TIER_NOT_ALLOWED"
            ? "테스트 배포 대상이 없어 능동 검사를 실행하지 않음"
            : e.message;
        return { blocked: true, reason };
      }
      throw e;
    }
  }

  async run(
    context: ProjectContext
  ): Promise<{ findings: SecurityFinding[]; scope: ScanScope; plan: ScanPlan }> {
    const plan = await this.buildScanPlan(context);
    const applicable = await this.selectApplicable(context);
    const findings: SecurityFinding[] = [];
    const testedCategories = new Set<string>();

    // 계획에 포함된 규칙 ID(게이트 통과) 집합.
    const plannedRuleIds = new Set(plan.selectedChecks.map((c) => c.ruleId));

    for (const scanner of applicable) {
      const rule = ruleForScanner(scanner.name);

      // 규칙에 바인딩된 스캐너는 계획에 없으면(게이트 차단) 실행하지 않음.
      if (rule && !plannedRuleIds.has(rule.id)) continue;

      const results = await scanner.scan(context);
      for (const f of results) {
        this.decorateWithRule(f);
        findings.push(f);
      }

      if (rule) testedCategories.add(rule.titleKo);
      if (scanner.name === "static-web-scanner") {
        // 여러 규칙을 담당: 계획에 포함된 정적 웹 규칙 제목을 카테고리로 추가.
        for (const ruleId of STATIC_WEB_RULES) {
          if (plannedRuleIds.has(ruleId)) {
            const r = getRule(ruleId);
            if (r) testedCategories.add(r.titleKo);
          }
        }
      }
      if (scanner.name === "ai-code-scanner") testedCategories.add("AI 분석 발견");
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

    return { findings, scope, plan };
  }

  /** finding에 규칙 메타(ruleId/standards/tier/testStatus)를 부착한다. */
  private decorateWithRule(f: SecurityFinding): void {
    const ruleId = ruleIdForVerificationKey(f.verificationKey);
    if (ruleId) {
      const rule = getRules().find((r) => r.id === ruleId);
      if (rule) {
        f.ruleId = rule.id;
        f.standards = rule.standards.map((s) => `${s.framework} ${s.id}`);
        f.executionTier = rule.execution.tier;
      }
    }
    f.testStatus = toTestStatus(f.status);
  }

  /** 진행 UI용 파이프라인 단계(적용 여부 포함). */
  async plan(context: ProjectContext) {
    const applicable = await this.selectApplicable(context);
    const applicableSteps = new Set(applicable.map((s) => s.step));
    applicableSteps.add("detect_stack");
    applicableSteps.add("generating_findings");
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
