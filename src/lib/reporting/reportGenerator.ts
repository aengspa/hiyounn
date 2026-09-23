import type {
  ScanReport,
  ScanScope,
  SecurityFinding,
  Severity,
} from "@/lib/domain/types";
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

const REPORT_SYSTEM_PROMPT = `당신은 시니어 보안 엔지니어입니다.
보안 스캔 결과를 개발자가 이해하기 쉽게 한국어로 요약합니다.
반드시 아래 JSON 하나만 출력하세요.

{
  "summary": "전체 상황을 한 문단으로 요약(한국어). 과장 없이 사실 기반.",
  "highlights": ["가장 중요한 발견 3~5개를 짧은 문장으로"],
  "recommendation": "지금 무엇부터 해야 하는지 한두 문장(한국어)"
}

규칙: 발견 목록에 근거하여 사실만 쓰고, 없는 취약점을 지어내지 마세요.
심각도가 높은 항목을 우선 언급하세요.`;

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

/** 결정적(규칙 기반) 요약 — AI 없이도 항상 동작. */
function deterministicReport(
  findings: SecurityFinding[],
  scope: ScanScope
): ScanReport {
  const counts = countBySeverity(findings);
  const total = findings.length;

  const parts = (["critical", "high", "medium", "low"] as Severity[])
    .filter((s) => counts[s] > 0)
    .map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}건`);

  const summary =
    total === 0
      ? "이번 스캔에서는 검사한 범위 내에서 취약점이 발견되지 않았습니다. 다만 이는 점검한 항목에 한정된 결과입니다."
      : `이번 스캔에서 총 ${total}건의 보안 문제를 발견했습니다(${parts.join(
          ", "
        )}). 아래 목록에서 각 항목의 영향과 근거를 확인할 수 있습니다.`;

  const highlights = findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 5)
    .map((f) => `[${SEVERITY_LABEL[f.severity]}] ${f.title}`);

  const recommendation =
    counts.critical > 0
      ? "심각 항목부터 수정안을 생성해 적용하고, 같은 공격이 막히는지 검증하세요."
      : total > 0
        ? "발견된 항목의 수정안을 생성해 적용한 뒤 검증하세요."
        : "정기적으로 재스캔하여 변경된 코드에 새로운 문제가 없는지 확인하세요.";

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
  if (!isConfigured()) {
    return deterministicReport(findings, scope);
  }

  try {
    const list = findings
      .map(
        (f) =>
          `- [${SEVERITY_LABEL[f.severity]}] ${f.title} :: ${f.humanReadableImpact}`
      )
      .join("\n");
    const user = `검사 범위: 테스트 ${scope.testedCategories.length}개 항목, 미검사 ${scope.untestedCategories.length}개 항목.
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
