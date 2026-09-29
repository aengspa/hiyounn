import type {
  ScanReport,
  ScanScope,
  SecurityFinding,
  Severity,
} from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import { now } from "@/lib/util";
import { isConfigured, completeJson } from "@/lib/ai/llmClient";

/**
 * 스캔 결과 요약 보고서 생성기.
 *
 * - LLM이 설정되어 있으면 AI로 사람이 읽기 쉬운 요약을 생성(source: "llm").
 * - 미설정이거나 실패하면 결정적 요약으로 안전하게 fallback(source: "deterministic").
 *
 * 원칙(fixGenerator와 동일): AI는 "설명·요약"에만 사용합니다. 취약점의 실제
 * 존재/해결 여부는 결정적 스캔·검증 결과가 결정하며, 보고서가 이를 바꾸지 않습니다.
 */

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "심각",
  high: "높음",
  medium: "보통",
  low: "낮음",
};

const REPORT_SYSTEM_PROMPT = `당신은 보안 점검 결과를 요약 보고서로 정리하는 보안 엔지니어입니다.
입력으로 받은 점검 범위와 발견 목록만 근거로 한국어 보고서를 씁니다.
반드시 아래 JSON 하나만 출력하세요.

{
  "summary": "이번 점검 결과와 확인 범위 요약(2~4문장)",
  "highlights": ["중요한 문제와 가능한 영향(항목당 한 문장, 3~5개)"],
  "recommendation": "먼저 할 수정과 그 뒤에 확인할 내용(1~3문장)"
}

[필드별 역할]
- summary: 발견한 문제 수와 심각도, 이번에 확인한 범위와 확인하지 못한 범위를 쉬운 말로 요약한다.
  실제 요청으로 확인한 항목과 코드·설정에서 찾은 의심 신호가 섞여 있으면 둘을 구분해서 쓴다.
- highlights: 심각도가 높은 항목부터 고른다. 기술 분류명(예: IDOR, XSS)을 나열하지 말고,
  어떤 문제가 있고 그 때문에 어떤 일이 생길 수 있는지 한 문장으로 쓴다.
  가능한 영향은 발견 목록의 설명에 있는 범위 안에서만 쓴다.
- recommendation: 가장 먼저 고칠 항목과 구체적인 행동을 쓰고, 이어서 수정 후 무엇을 다시 확인할지 쓴다.
  "보안을 강화하세요"처럼 추상적인 말로 끝내지 않는다.

[작업 규칙]
- 발견 목록에 없는 문제, 기능, 피해를 지어내지 않는다.
- 의심 신호로 표시된 항목을 공격이 성공한 것처럼 쓰지 않는다.
- 심각도를 낮추거나 높여서 표현하지 않는다.
- 발견이 없으면 highlights는 빈 배열로 둔다. summary에는 "이번에 확인한 범위에서는 문제를 찾지 못했다"는 사실과
  확인하지 못한 범위를 함께 쓴다. "완전히 안전해요", "배포해도 돼요"처럼 안전을 보장하는 표현은 쓰지 않는다.`;

interface RawReport {
  summary?: string;
  highlights?: unknown;
  recommendation?: string;
}

function countBySeverity(findings: SecurityFinding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity] += 1;
  return c;
}

/** 실제 요청·재현으로 확인한 항목인지(아니면 코드·설정에서 찾은 의심 신호). */
function isConfirmed(f: SecurityFinding): boolean {
  return (f.testStatus ?? toTestStatus(f.status)) === "CONFIRMED";
}

/** 설명의 첫 문장만(보고서 한 줄 요약용). */
function firstSentence(text: string | undefined, max = 140): string {
  const t = (text ?? "").replace(/\s+/g, " ").trim();
  if (!t) return "";
  const m = t.match(/^.*?[.!?](?=\s|$)/);
  const s = m ? m[0] : t;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** 확인한 범위·확인하지 못한 범위를 한두 문장으로. */
function scopeSentence(scope: ScanScope): string {
  const tested = scope.testedCategories.length;
  const untested = scope.untestedCategories.length;
  const testedPart =
    tested > 0 ? `이번에는 ${tested}개 항목을 확인했어요.` : "이번 점검에서 기록된 확인 항목이 없어요.";
  const untestedPart =
    untested > 0
      ? ` 확인하지 못한 항목이 ${untested}개 있어서, 그 부분의 문제는 이 결과에 들어 있지 않아요.`
      : "";
  return `${testedPart}${untestedPart}`;
}

/** 결정적(규칙 기반) 요약 — AI 없이도 항상 동작. */
function deterministicReport(
  findings: SecurityFinding[],
  scope: ScanScope
): ScanReport {
  const counts = countBySeverity(findings);
  const total = findings.length;
  const confirmed = findings.filter(isConfirmed).length;

  const parts = (["critical", "high", "medium", "low"] as Severity[])
    .filter((s) => counts[s] > 0)
    .map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}건`);

  const basis =
    confirmed === 0
      ? " 모두 코드나 설정에서 찾은 의심 신호라서, 실제로 문제가 되는지는 각 항목의 근거를 보고 확인해 주세요."
      : confirmed === total
        ? " 모두 점검 도구가 실제 요청으로 확인한 항목이에요."
        : ` 그중 ${confirmed}건은 점검 도구가 실제 요청으로 확인했고, ${total - confirmed}건은 코드나 설정에서 찾은 의심 신호예요.`;

  const summary =
    total === 0
      ? `이번에 확인한 범위에서는 문제를 찾지 못했어요. ${scopeSentence(scope)} 문제를 찾지 못했다는 것이 모든 위험이 없다는 뜻은 아니에요.`
      : `이번 점검에서 확인이 필요한 문제를 ${total}건 찾았어요(${parts.join(", ")}).${basis} ${scopeSentence(scope)}`;

  const highlights = findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 5)
    .map((f) => {
      const title = f.title.trim().replace(/[.。]\s*$/, "");
      const impact = firstSentence(f.humanReadableImpact);
      const withImpact = impact && impact !== f.title.trim() ? `${title}. ${impact}` : title;
      return `[${SEVERITY_LABEL[f.severity]}] ${withImpact}`;
    });

  const top = (["critical", "high", "medium", "low"] as Severity[]).find((s) => counts[s] > 0);
  const recommendation =
    total === 0
      ? "코드를 바꾼 뒤에는 다시 점검해 주세요. 확인하지 못한 항목은 '점검 범위와 한계'에서 이유를 확인하고, 코드만으로 확인할 수 없는 부분은 직접 확인해 주세요."
      : `먼저 심각도 '${SEVERITY_LABEL[top!]}' 항목 ${counts[top!]}건의 근거와 수정 방법을 확인하고 수정안을 만들어 적용해 주세요. 적용한 뒤에는 재검증을 실행해 같은 문제가 남았는지, 평소 쓰던 기능이 그대로 동작하는지 확인해 주세요.${
          total > counts[top!] ? " 그다음 나머지 항목도 같은 순서로 처리해 주세요." : ""
        }`;

  return {
    summary,
    highlights,
    recommendation,
    generatedAt: now(),
    source: "deterministic",
  };
}

function severityRank(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3 }[s];
}

/** Keep every finding/evidence in storage; summarize mode variants once per family. */
export function groupFindingsForReport(findings: SecurityFinding[]): SecurityFinding[] {
  const groups = new Map<string, SecurityFinding[]>();
  for (const finding of findings) {
    const key = finding.family ?? finding.ruleId ?? finding.id;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  return [...groups.values()].map((group) => {
    const ranked = group.slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    return { ...ranked[0], title: group.length > 1 ? `${ranked[0].title} (${group.length}개 근거)` : ranked[0].title };
  });
}

function stripFence(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const b = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (b >= 0 && e > b) return text.slice(b, e + 1);
  return text.trim();
}

/**
 * 보고서 생성 진입점. AI 설정 시 LLM 요약을 시도하고, 실패하면 결정적 요약으로
 * fallback합니다. 어떤 경우에도 유효한 ScanReport를 반환합니다.
 */
export async function generateScanReport(
  findings: SecurityFinding[],
  scope: ScanScope
): Promise<ScanReport> {
  findings = groupFindingsForReport(findings);
  if (!isConfigured()) {
    return deterministicReport(findings, scope);
  }

  try {
    const list = findings
      .map(
        (f) =>
          `- [${SEVERITY_LABEL[f.severity]}] (${isConfirmed(f) ? "실제 요청으로 확인" : "코드·설정에서 찾은 의심 신호"}) ${f.title} :: ${f.humanReadableImpact}`
      )
      .join("\n");
    const user = `확인한 항목 ${scope.testedCategories.length}개: ${scope.testedCategories.join(", ") || "(없음)"}
확인하지 못한 항목 ${scope.untestedCategories.length}개: ${scope.untestedCategories.join(", ") || "(없음)"}
발견 ${findings.length}건:
${list || "(발견 없음)"}

위 결과만을 근거로 JSON으로 답하세요.`;

    const raw = await completeJson(REPORT_SYSTEM_PROMPT, user);
    const parsed = JSON.parse(stripFence(raw)) as RawReport;

    const highlights = Array.isArray(parsed.highlights)
      ? parsed.highlights.map((h) => String(h)).filter(Boolean).slice(0, 6)
      : [];

    const fallback = deterministicReport(findings, scope);
    return {
      summary: (parsed.summary && String(parsed.summary)) || fallback.summary,
      highlights: highlights.length > 0 ? highlights : fallback.highlights,
      recommendation:
        (parsed.recommendation && String(parsed.recommendation)) ||
        fallback.recommendation,
      generatedAt: now(),
      source: "llm",
    };
  } catch {
    return deterministicReport(findings, scope);
  }
}
