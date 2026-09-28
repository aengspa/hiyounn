import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  Severity,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { isConfigured, completeJson } from "@/lib/ai/llmClient";
import { VerificationUnavailableError } from "@/lib/store/errors";

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

type FindingVerdict = "still_present" | "fixed" | "inconclusive";
type RegressionVerdict = "preserved" | "broken" | "inconclusive";

type EvidenceRole = "vulnerable_code" | "mitigation";

interface SourceReference {
  file: string;
  snippet: string;
  explanation: string;
}

interface ReviewEvidence extends SourceReference {
  role: EvidenceRole;
}

interface ReviewCheck extends SourceReference {
  label: string;
  expectation: string;
  verdict: RegressionVerdict;
}

interface AiVerificationReview {
  verdict: FindingVerdict;
  summary: string;
  evidence: ReviewEvidence[];
  regression: {
    verdict: RegressionVerdict;
    checks: ReviewCheck[];
  };
}

interface PromptFile {
  file: string;
  content: string;
}

const SOURCE_PROMPT_LIMIT = 24000;

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

const VERIFY_SYSTEM_PROMPT = `당신은 기존 AI 보안 발견 항목 하나를 현재 소스와 대조하는 보수적인 소스 코드 재검토자입니다.
새 취약점을 찾는 광범위한 스캔을 하지 말고, 입력의 originalFinding 하나만 평가하세요.
코드를 실행하거나 공격/런타임 테스트를 했다고 주장하지 마세요. 제공된 현재 소스만 근거로 판단하세요.
반드시 다른 문장이나 코드 펜스 없이 아래 JSON 객체 하나만 출력하세요.

{
  "verdict": "still_present|fixed|inconclusive",
  "summary": "현재 소스에서 원본 발견 항목을 재검토한 요약",
  "evidence": [
    {
      "role": "vulnerable_code|mitigation",
      "file": "currentFiles에 제공된 정확한 파일 이름",
      "snippet": "해당 파일에 문자 그대로 존재하는 현재 소스 일부",
      "explanation": "이 현재 소스가 취약점 잔존 또는 완화를 입증하는 이유"
    }
  ],
  "regression": {
    "verdict": "preserved|broken|inconclusive",
    "checks": [
      {
        "label": "정상 동작 보존 여부 검사 이름",
        "expectation": "현재 소스에서 유지되어야 할 정상 동작",
        "verdict": "preserved|broken|inconclusive",
        "file": "currentFiles에 제공된 정확한 파일 이름",
        "snippet": "해당 파일에 문자 그대로 존재하는 현재 소스 일부",
        "explanation": "이 소스가 정상 동작 보존 또는 손상을 뒷받침하는 이유"
      }
    ]
  }
}

판정 규칙:
- fixed는 현재 소스에 실제로 존재하는 role=mitigation 완화 코드 evidence가 있을 때만 사용하세요.
- still_present는 원본 취약점이 현재 소스에 남아 있음을 보여 주는 role=vulnerable_code evidence가 있을 때만 사용하세요.
- preserved는 현재 소스에 실제로 존재하는 근거를 가진 check가 하나 이상이고 모든 check가 preserved일 때만 사용하세요.
- broken은 하나 이상의 source-backed check가 broken일 때만 사용하세요.
- 근거가 부족하거나 관련 소스가 제공되지 않았으면 inconclusive를 사용하세요.
- 입력의 줄 번호는 신뢰하지 말고, file과 snippet만 사용하세요.`;

/** AI 코드 분석을 끝내지 못함. 발견 0건과 구분해 "검사하지 못함"으로 기록한다. */
export class AiScanUnavailableError extends Error {
  constructor(
    readonly reason: "llm_failed" | "invalid_response" | "too_large",
    readonly omittedFiles: string[]
  ) {
    super(`AI scan unavailable: ${reason}`);
    this.name = "AiScanUnavailableError";
  }
}

export const AI_SCAN_GAP_RULE = "AI 코드 분석";

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

  private userSourceEntries(context: ProjectContext): Array<[string, string]> {
    return Object.entries(context.files).filter(
      ([k]) => context.isUserProject || k.startsWith("user-source:")
    );
  }

  private userSource(context: ProjectContext): string | null {
    // 실제 사용자 프로젝트(isUserProject)면 모든 파일이 사용자 소스다.
    // (구버전 호환: "user-source:" 접두 키도 계속 인식.)
    const entries = this.userSourceEntries(context);
    if (entries.length === 0) return null;
    return entries
      .map(([k, v]) => `// file: ${k}\n${v}`)
      .join("\n\n");
  }

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return isConfigured() && this.userSource(context) !== null;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    return (await this.scanWithReport(context)).findings;
  }

  /**
   * AI 코드 분석. 실패를 "발견 0건"으로 바꾸지 않는다.
   *  - 호출 실패·응답 형식 오류 → AiScanUnavailableError (오케스트레이터가
   *    "검사하지 못한 항목"으로 기록)
   *  - 길이 한도 때문에 보내지 못한 파일은 잘라 보내지 않고 omittedFiles로 알린다.
   */
  async scanWithReport(
    context: ProjectContext
  ): Promise<{ findings: SecurityFinding[]; sentFiles: string[]; omittedFiles: string[] }> {
    const entries = this.userSourceEntries(context).filter(([, v]) => v.trim());
    if (entries.length === 0) return { findings: [], sentFiles: [], omittedFiles: [] };

    // 파일 단위로 한도 안에 들어가는 만큼만 보낸다(파일 중간을 자르지 않음).
    const sent: Array<[string, string]> = [];
    const omittedFiles: string[] = [];
    let used = 0;
    for (const [file, content] of entries) {
      const block = `// file: ${file}\n${content}\n\n`;
      if (used + block.length > SOURCE_PROMPT_LIMIT) {
        omittedFiles.push(file);
        continue;
      }
      sent.push([file, content]);
      used += block.length;
    }
    if (sent.length === 0) {
      throw new AiScanUnavailableError("too_large", omittedFiles);
    }
    const source = sent.map(([k, v]) => `// file: ${k}\n${v}`).join("\n\n");

    let raw: string;
    try {
      raw = await completeJson(
        SYSTEM_PROMPT,
        `다음 코드를 분석하고 JSON으로만 답하세요:\n\n\`\`\`\n${source}\n\`\`\``,
        30000,
        "scan"
      );
    } catch {
      throw new AiScanUnavailableError("llm_failed", omittedFiles);
    }

    let parsed: { findings?: AiFindingRaw[] };
    try {
      parsed = JSON.parse(extractJson(raw));
    } catch {
      throw new AiScanUnavailableError("invalid_response", omittedFiles);
    }
    if (!parsed || !Array.isArray(parsed.findings)) {
      throw new AiScanUnavailableError("invalid_response", omittedFiles);
    }

    const items = parsed.findings;

    // 응답 검증: 모델이 지어낸(환각) 근거를 걸러낸다.
    //  - 각 항목이 최소 필드(title/impact)를 갖췄는지
    //  - codeSnippet이 실제 입력 코드에 존재하는지(없으면 근거 없는 주장)
    // 검증을 통과한 항목만 finding으로 만든다.
    const normalizedSource = normalizeForMatch(source);
    const valid = items.filter((it) => this.isCredible(it, normalizedSource));
    return {
      findings: valid.map((it) => this.toFinding(it)),
      sentFiles: sent.map(([f]) => f),
      omittedFiles,
    };
  }

  /**
   * 원본 AI finding 하나만 현재 소스와 대조한다. 이 검사는 소스 재검토이며
   * 공격 실행이나 런타임 테스트가 아니다. 불확실하거나 근거를 현재 소스에서
   * 검증할 수 없으면 이진 pass/fail을 만들지 않고 unavailable로 중단한다.
   */
  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    if (!finding.verificationKey?.startsWith("ai:")) {
      throw new VerificationUnavailableError();
    }
    if (!isConfigured()) throw new VerificationUnavailableError();

    const entries = this.userSourceEntries(context);
    if (entries.length === 0 || !entries.some(([, source]) => source.trim())) {
      throw new VerificationUnavailableError();
    }

    const targetFile = originalTargetFile(finding, entries.map(([file]) => file));
    const targetSource = entries.find(([file]) => file === targetFile)?.[1];
    if (!targetFile || targetSource === undefined || !targetSource.trim()) {
      throw new VerificationUnavailableError();
    }

    const { prompt, includedFiles } = buildVerificationPrompt(
      finding,
      targetFile,
      entries
    );

    let raw: string;
    try {
      raw = await completeJson(VERIFY_SYSTEM_PROMPT, prompt);
    } catch {
      throw new VerificationUnavailableError();
    }

    const review = parseVerificationReview(raw);
    if (
      review.verdict === "inconclusive" ||
      review.regression.verdict === "inconclusive"
    ) {
      throw new VerificationUnavailableError();
    }

    const currentFiles = new Map(entries);
    const validatedEvidence = review.evidence.map((evidence) =>
      validateSourceEvidence(evidence, currentFiles, includedFiles)
    );
    if (
      validatedEvidence.length === 0 ||
      !validatedEvidence.some((evidence) => evidence.file === targetFile) ||
      (review.verdict === "fixed" &&
        (!validatedEvidence.some(
          (evidence) => evidence.role === "mitigation"
        ) ||
          validatedEvidence.some(
            (evidence) => evidence.role === "vulnerable_code"
          ))) ||
      (review.verdict === "still_present" &&
        !validatedEvidence.some(
          (evidence) => evidence.role === "vulnerable_code"
        ))
    ) {
      throw new VerificationUnavailableError();
    }

    const validatedChecks = review.regression.checks.map((check) => {
      const evidence = validateSourceEvidence(check, currentFiles, includedFiles);
      if (check.verdict === "inconclusive") {
        throw new VerificationUnavailableError();
      }
      return { ...check, ...evidence };
    });
    if (validatedChecks.length === 0) throw new VerificationUnavailableError();

    if (
      (review.regression.verdict === "preserved" &&
        validatedChecks.some((check) => check.verdict !== "preserved")) ||
      (review.regression.verdict === "broken" &&
        !validatedChecks.some((check) => check.verdict === "broken"))
    ) {
      throw new VerificationUnavailableError();
    }

    const securityPassed = review.verdict === "fixed";
    const regressionPassed = review.regression.verdict === "preserved";
    const evidenceSummary = validatedEvidence
      .map(
        (evidence) =>
          `${evidence.file}: ${evidence.explanation}\n${evidence.snippet}`
      )
      .join("\n\n");

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "AI 원본 발견 항목 소스 재검토(공격/런타임 실행 아님)",
      before: {
        label: "원본 AI 발견",
        request: "원본 finding 한 건을 현재 소스와 비교하는 정적 AI 재검토",
        response: "원본 스캔의 AI 발견 항목이며 실행된 공격 증거가 아님",
        attackSucceeded: true,
      },
      after: {
        label: "현재 소스 AI 재검토",
        request: `AI source re-review only: ${targetFile} (no attack/runtime execution)`,
        response: `${review.summary}\n\n현재 소스 근거:\n${evidenceSummary}`,
        attackSucceeded: !securityPassed,
      },
      outcome: securityPassed ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: validatedChecks.map((check) => ({
        label: `AI 소스 재검토(런타임 미실행): ${check.label}`,
        expectation: check.expectation,
        outcome: check.verdict === "preserved" ? "pass" : "fail",
        detail: `${check.file}: ${check.explanation}\n${check.snippet}`,
      })),
      outcome: regressionPassed ? "pass" : "fail",
      createdAt: now(),
    };

    // AI source review is useful evidence but is not deterministic proof. Keep
    // the finding fixed-but-unverified until an independent rule/runtime check.
    return {
      findingId: finding.id,
      security,
      regression,
      resolved: false,
    };
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

function originalTargetFile(
  finding: SecurityFinding,
  availableFiles: string[]
): string | undefined {
  if (finding.location?.file?.trim()) return finding.location.file.trim();

  const available = new Set(availableFiles);
  const sourceEvidence = finding.evidence.find(
    (evidence) => evidence.kind === "source_code" && evidence.label.trim()
  );
  if (sourceEvidence) {
    const label = sourceEvidence.label.trim();
    if (available.has(label)) return label;
    const withoutLine = label.replace(/:\d+$/, "");
    if (withoutLine) return withoutLine;
  }

  const key = finding.verificationKey ?? "";
  if (key.startsWith("ai:")) {
    const fromKey = key.slice(3).replace(/:\d+$/, "").trim();
    if (fromKey) return fromKey;
  }
  return undefined;
}

function buildVerificationPrompt(
  finding: SecurityFinding,
  targetFile: string,
  entries: Array<[string, string]>
): { prompt: string; includedFiles: Set<string> } {
  const targetSource = entries.find(([file]) => file === targetFile)?.[1];
  if (targetSource === undefined) throw new VerificationUnavailableError();

  let files: PromptFile[] = [{ file: targetFile, content: targetSource }];
  const additional = entries.filter(
    ([file, content]) => file !== targetFile && content.trim().length > 0
  );

  const serialize = (currentFiles: PromptFile[], omitted: boolean) =>
    JSON.stringify({
      task: "Re-review exactly this original AI finding against current source only; this is not an executed attack or runtime test.",
      originalFinding: finding,
      targetFile,
      currentFiles,
      additionalFilesOmitted: omitted,
    });

  if (serialize(files, additional.length > 0).length > SOURCE_PROMPT_LIMIT) {
    // 대상 파일은 일부만 보내지 않는다. 잘린 대상 소스로 fixed를 허용할 수 없다.
    throw new VerificationUnavailableError();
  }

  for (const [file, content] of additional) {
    const candidate = [...files, { file, content }];
    if (serialize(candidate, true).length <= SOURCE_PROMPT_LIMIT) {
      files = candidate;
    }
  }

  const nonEmptyFileCount = entries.filter(([, content]) => content.trim()).length;
  const additionalFilesOmitted = files.length < nonEmptyFileCount;
  const prompt = serialize(files, additionalFilesOmitted);
  if (prompt.length > SOURCE_PROMPT_LIMIT) {
    throw new VerificationUnavailableError();
  }

  return { prompt, includedFiles: new Set(files.map(({ file }) => file)) };
}

function parseVerificationReview(raw: string): AiVerificationReview {
  let value: unknown;
  try {
    value = JSON.parse(raw.trim());
  } catch {
    throw new VerificationUnavailableError();
  }
  if (!isRecord(value)) throw new VerificationUnavailableError();

  const verdict = value.verdict;
  const summary = value.summary;
  const evidence = value.evidence;
  const regression = value.regression;
  if (
    !isFindingVerdict(verdict) ||
    !isNonEmptyString(summary) ||
    !Array.isArray(evidence) ||
    !evidence.every(isReviewEvidence) ||
    !isRecord(regression) ||
    !isRegressionVerdict(regression.verdict) ||
    !Array.isArray(regression.checks) ||
    !regression.checks.every(isReviewCheck)
  ) {
    throw new VerificationUnavailableError();
  }

  return {
    verdict,
    summary: summary.trim(),
    evidence,
    regression: {
      verdict: regression.verdict,
      checks: regression.checks,
    },
  };
}

function validateSourceEvidence<T extends SourceReference>(
  evidence: T,
  currentFiles: Map<string, string>,
  includedFiles: Set<string>
): T {
  const snippet = evidence.snippet.trim();
  const source = currentFiles.get(evidence.file);
  if (
    snippet.length < 8 ||
    source === undefined ||
    !includedFiles.has(evidence.file) ||
    !source.includes(snippet)
  ) {
    throw new VerificationUnavailableError();
  }
  return { ...evidence, snippet };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isFindingVerdict(value: unknown): value is FindingVerdict {
  return value === "still_present" || value === "fixed" || value === "inconclusive";
}

function isRegressionVerdict(value: unknown): value is RegressionVerdict {
  return value === "preserved" || value === "broken" || value === "inconclusive";
}

function isReviewEvidence(value: unknown): value is ReviewEvidence {
  return (
    isRecord(value) &&
    (value.role === "vulnerable_code" || value.role === "mitigation") &&
    isNonEmptyString(value.file) &&
    isNonEmptyString(value.snippet) &&
    isNonEmptyString(value.explanation)
  );
}

function isReviewCheck(value: unknown): value is ReviewCheck {
  return (
    isRecord(value) &&
    isNonEmptyString(value.label) &&
    isNonEmptyString(value.expectation) &&
    isRegressionVerdict(value.verdict) &&
    isNonEmptyString(value.file) &&
    isNonEmptyString(value.snippet) &&
    isNonEmptyString(value.explanation)
  );
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
