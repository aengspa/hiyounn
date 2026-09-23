import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding, Severity } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { isConfigured, completeJson } from "@/lib/ai/llmClient";

/**
 * 실제 AI API를 사용하는 코드 스캐너.
 *
 * 사용자가 붙여넣은 소스 코드(context.files 중 "user-source:" 로 시작하는 키)를
 * LLM에게 보내 취약점을 분석합니다. AI는 "해석·설명" 역할만 하며, 결과에는
 * simulated:false + verificationKey "ai:..." 를 붙여 UI에서 "AI 분석"으로
 * 명확히 구분합니다.
 *
 * 키가 없으면 isApplicable()이 false를 반환해 조용히 비활성화됩니다.
 */

interface AiFindingRaw {
  title?: string;
  severity?: string;
  category?: string;
  owasp?: string;
  cwe?: string;
  humanReadableImpact?: string;
  whyItMatters?: string;
  file?: string;
  line?: number;
  codeSnippet?: string;
  remediation?: string;
}

const SYSTEM_PROMPT = `당신은 시니어 애플리케이션 보안 엔지니어입니다.
비전공 개발자가 AI 도구로 만든 웹 서비스 코드를 검토합니다.
반드시 아래 JSON 스키마 하나만 출력하세요. 설명 문장은 넣지 마세요.

{
  "findings": [
    {
      "title": "짧은 제목(한국어, 비전문가도 이해 가능)",
      "severity": "critical|high|medium|low",
      "category": "취약점 분류(영문 표준 명칭)",
      "owasp": "OWASP 분류(예: A01 - Broken Access Control) 또는 빈 문자열",
      "cwe": "CWE 번호(예: CWE-89) 또는 빈 문자열",
      "humanReadableImpact": "이 취약점으로 사용자에게 실제로 무슨 일이 생기는지 한국어로 쉽게",
      "whyItMatters": "왜 위험한지 한국어로 쉽게",
      "file": "파일 경로(코드에 '// file: 경로'가 있으면 그 값)",
      "line": 관련 줄 번호(정수, 모르면 0),
      "codeSnippet": "문제되는 코드 몇 줄",
      "remediation": "어떻게 고치면 되는지 한국어 요약"
    }
  ]
}

규칙:
- 확실한 근거가 있는 취약점만 보고합니다. 추측성/스타일 문제는 제외합니다.
- 발견이 없으면 {"findings": []} 를 출력합니다.
- 민감한 실제 비밀값은 마스킹해서 넣습니다.`;

function normSeverity(s?: string): Severity {
  const v = (s ?? "").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "medium";
}

export class AiCodeScanner implements SecurityScanner {
  readonly name = "ai-code-scanner";
  readonly displayName = "AI 코드 분석";
  readonly step = "static_analysis" as const;
  readonly simulated = false;

  private userSource(context: ProjectContext): string | null {
    // buildDemoContext 는 데모 파일만 넣습니다. 사용자 붙여넣기 코드는
    // "user-source:main" 키로 주입됩니다.
    const entries = Object.entries(context.files).filter(([k]) =>
      k.startsWith("user-source:")
    );
    if (entries.length === 0) return null;
    return entries.map(([, v]) => v).join("\n\n");
  }

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return isConfigured() && this.userSource(context) !== null;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const source = this.userSource(context);
    if (!source) return [];

    // 프롬프트 폭주 방지를 위해 코드 길이 제한.
    const clipped = source.slice(0, 24000);

    let raw: string;
    try {
      raw = await completeJson(
        SYSTEM_PROMPT,
        `다음 코드를 분석하고 JSON으로만 답하세요:\n\n\`\`\`\n${clipped}\n\`\`\``
      );
    } catch {
      // AI 호출 실패 시 조용히 빈 결과 (앱은 계속 동작).
      return [];
    }

    let parsed: { findings?: AiFindingRaw[] };
    try {
      parsed = JSON.parse(extractJson(raw));
    } catch {
      // 스키마 파싱 실패는 정상 통과가 아님 — 빈 결과로 처리(오탐 방지).
      return [];
    }

    const items = Array.isArray(parsed.findings) ? parsed.findings : [];

    // 응답 검증: 모델이 지어낸(환각) 근거를 걸러낸다.
    //  - 각 항목이 최소 필드(title/impact)를 갖췄는지
    //  - codeSnippet이 실제 입력 코드에 존재하는지(없으면 근거 없는 주장)
    // 검증을 통과한 항목만 finding으로 만든다.
    const normalizedSource = normalizeForMatch(source);
    const valid = items.filter((it) => this.isCredible(it, normalizedSource));
    return valid.map((it) => this.toFinding(it));
  }

  /**
   * 모델 응답 항목의 신뢰성 검증.
   * 근거(codeSnippet)가 입력 코드에 실제로 있어야 evidence로 인정한다.
   * 스니펫이 비었거나 입력에 없으면 "증거 없는 AI 주장"으로 보고 버린다.
   */
  private isCredible(it: AiFindingRaw, normalizedSource: string): boolean {
    if (!it || typeof it !== "object") return false;
    if (!it.title && !it.humanReadableImpact) return false;

    const snippet = (it.codeSnippet ?? "").trim();
    if (snippet.length < 8) return false; // 너무 짧으면 검증 불가 → 제외

    // 스니펫의 첫 유의미한 줄이 원본에 존재하는지 확인.
    const firstLine = snippet
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length >= 8);
    if (!firstLine) return false;
    return normalizedSource.includes(normalizeForMatch(firstLine));
  }

  private toFinding(it: AiFindingRaw): SecurityFinding {
    const severity = normSeverity(it.severity);
    const file = it.file || "붙여넣은 코드";
    const line = typeof it.line === "number" && it.line > 0 ? it.line : undefined;

    return {
      id: id("finding"),
      scanId: "",
      title: it.title || "AI가 발견한 잠재적 취약점",
      severity,
      category: it.category || "AI Detected",
      owasp: it.owasp || undefined,
      cwe: it.cwe || undefined,
      description: it.remediation
        ? `AI 분석 결과. 권장 조치: ${it.remediation}`
        : "AI 코드 분석으로 발견된 항목입니다.",
      humanReadableImpact:
        it.humanReadableImpact || "이 코드로 인해 보안 문제가 생길 수 있습니다.",
      whyItMatters:
        it.whyItMatters || "공격자가 악용할 경우 피해가 발생할 수 있습니다.",
      location: line ? { file, line } : undefined,
      evidence: [
        {
          id: id("ev"),
          kind: "source_code",
          label: line ? `${file}:${line}` : file,
          content: it.codeSnippet || "(코드 스니펫 없음)",
          language: "typescript",
        },
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "AI 코드 분석 출력",
          content: [
            `분류: ${it.category ?? "-"}`,
            `OWASP: ${it.owasp ?? "-"}`,
            `CWE: ${it.cwe ?? "-"}`,
            `권장 조치: ${it.remediation ?? "-"}`,
          ].join("\n"),
        },
      ],
      remediation: it.remediation || undefined,
      status: "detected",
      simulated: false,
      // AI가 찾은 항목은 결정적 재현 테스트가 없으므로 "ai:" 접두어.
      verificationKey: `ai:${file}:${line ?? 0}`,
      createdAt: now(),
      updatedAt: now(),
    };
  }
}

/** 응답에서 JSON 본문만 뽑아냅니다(코드펜스로 감싼 경우 대비). */
function extractJson(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const brace = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (brace >= 0 && last > brace) return text.slice(brace, last + 1);
  return text.trim();
}

/** 공백을 정규화해 스니펫 존재 여부를 유연하게 대조한다. */
function normalizeForMatch(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}
