import type { SecurityFinding } from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import type { ProjectContext } from "@/lib/scanners/types";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { StaticWebScanner } from "@/lib/scanners/staticWebScanner";
import { BaaSConfigScanner } from "@/lib/scanners/baasScanner";
import { AiCodeScanner } from "@/lib/scanners/aiCodeScanner";
import { getRules } from "@/lib/rules/registry";
import { ruleIdForVerificationKey } from "@/lib/rules/scannerBinding";
import { buildProjectContext } from "@/lib/demo/sourceFiles";

/**
 * "Quick code check" — a lightweight, STATELESS static/secret pass over pasted
 * or dropped-in source. Distinct from a project scan:
 *   - runs ONLY passive, source-based scanners (secrets, static web signals,
 *     BaaS SQL/RLS, and AI if configured);
 *   - does NOT run dependency (needs a real manifest+network), any DAST/network
 *     scanner, or the authorization attack-reproduction engine;
 *   - creates NO Project and NO Scan, and persists nothing.
 *
 * What it can NOT see (stated up front to the user, never implied as "safe"):
 *   - dependency/CVE risk, cross-file data flow, git history, deployment/runtime
 *     behavior, and anything requiring a live target.
 */

export interface QuickCheckResult {
  findings: SecurityFinding[];
  /** Files the check actually looked at (post-filter). */
  scannedFiles: string[];
  /** Categories explicitly NOT covered by a quick check. */
  notCovered: string[];
}

const NOT_COVERED = [
  "프로젝트가 쓰는 외부 도구(라이브러리)의 알려진 보안 문제(CVE)",
  "여러 파일을 거쳐 전달되는 값의 흐름",
  "예전에 저장소에 올렸다가 지운 비밀키 기록(Git 이력)",
  "배포된 사이트가 실제로 어떻게 동작하는지(DAST)",
  "실제로 요청을 보내 문제가 생기는지 확인하는 시험",
];

function decorate(f: SecurityFinding): SecurityFinding {
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
  return f;
}

/** Run the quick check over a pasted source blob. */
export async function runQuickCheck(sourceBlob: string): Promise<QuickCheckResult> {
  const context: ProjectContext = buildProjectContext("quick-check", {
    name: "quick-check",
    sourceBlob,
  });

  const scanners = [
    new SecretScanner(),
    new StaticWebScanner(),
    new BaaSConfigScanner(),
    new AiCodeScanner(), // no-ops unless an LLM is configured
  ];

  const findings: SecurityFinding[] = [];
  for (const scanner of scanners) {
    if (!(await scanner.isApplicable(context))) continue;
    const results = await scanner.scan(context);
    for (const f of results) findings.push(decorate(f));
  }

  return {
    findings,
    scannedFiles: Object.keys(context.files),
    notCovered: NOT_COVERED,
  };
}
