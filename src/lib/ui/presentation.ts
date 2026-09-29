/**
 * 순수 표현 로직 (hoi-warm-redesign 설계 4장).
 *
 * - React·DOM에 의존하지 않는다. 서버·클라이언트 컴포넌트 양쪽에서 import 가능.
 * - 도메인 타입은 `import type`으로만 참조한다. 표시 라벨은 화면 표시에만 쓰고
 *   저장·API에 쓰이는 enum 값은 그대로 둔다(요구사항 4.7).
 * - 모든 문구는 절대 보장 표현을 쓰지 않는다(요구사항 12.4).
 */
import type { FindingStatus, Severity, TestStatus } from "@/lib/domain/types";
import { DEFAULT_LIMITS } from "@/lib/config/limits";

// ─────────────────────────────────────────────────────────────
// 호이 Mood
// ─────────────────────────────────────────────────────────────

/**
 * 호이의 표정·자세 상태. `Hoi.tsx`가 `export type { HoiMood }`로 다시 내보낸다
 * (lib → components 의존 방지, 기존 import 경로 유지. 요구사항 3.6).
 */
export type HoiMood =
  | "welcome"
  | "guide"
  | "searching"
  | "thinking"
  | "concerned"
  | "cheer"
  | "celebrate"
  | "rest";

// ─────────────────────────────────────────────────────────────
// 표시 라벨 (요구사항 4)
// ─────────────────────────────────────────────────────────────

/** 심각도 쉬운 라벨 (요구사항 4.1). */
export const SEV_LABEL: Record<Severity, string> = {
  critical: "지금 확인해요",
  high: "먼저 고쳐요",
  medium: "다듬어 봐요",
  low: "여유 있을 때",
};

/** "기술 정보 보기" 안에 쓰는 원래 심각도 의미 (요구사항 4.6). */
export const SEV_EXPERT_LABEL: Record<Severity, string> = {
  critical: "심각(Critical)",
  high: "높음(High)",
  medium: "보통(Medium)",
  low: "낮음(Low)",
};

/** 발견 상태 라벨 (요구사항 4.2). */
export const STATUS_LABEL: Record<FindingStatus, string> = {
  detected: "확인이 필요해요",
  verified: "실제로 문제가 생기는 걸 확인했어요",
  fixing: "고치는 중이에요",
  fixed: "수정을 적용했어요",
  verification_failed: "아직 완전히 막히지 않았어요",
  regression_failed: "기존 기능을 다시 봐야 해요",
  resolved: "잘 해결했어요",
};

/** 검사 상태 라벨 (요구사항 4.3). */
export const TEST_STATUS_LABEL: Record<TestStatus, string> = {
  CONFIRMED: "문제를 확인했어요",
  SUSPECTED: "가능성이 있어요",
  NOT_DETECTED: "이번에는 보이지 않았어요",
  NOT_APPLICABLE: "이 프로젝트에는 해당하지 않아요",
  NOT_TESTED: "아직 확인하지 않았어요",
  TEST_FAILED: "확인 과정이 끝나지 않았어요",
  FIXED_VERIFIED: "고친 뒤 잘 막히는 걸 확인했어요",
  REGRESSION_FAILED: "기존 기능을 다시 봐야 해요",
};

/** 목록에 없는 값에 쓰는 대체 라벨 (요구사항 4.8). */
export const UNKNOWN_STATUS_LABEL = "아직 알 수 없는 상태예요";

/** `value`가 `map`의 자기 키일 때만 true. `"toString"` 같은 프로토타입 키는 거른다. */
function isOwnKey<K extends string>(map: Record<K, unknown>, value: unknown): value is K {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(map, value);
}

function lookupLabel<K extends string>(map: Record<K, string>, value: unknown): string {
  return isOwnKey(map, value) ? map[value] : UNKNOWN_STATUS_LABEL;
}

export function severityLabel(value: unknown): string {
  return lookupLabel(SEV_LABEL, value);
}

export function statusLabel(value: unknown): string {
  return lookupLabel(STATUS_LABEL, value);
}

export function testStatusLabel(value: unknown): string {
  return lookupLabel(TEST_STATUS_LABEL, value);
}

/** 심각도 배지 아이콘 모양. 색 없이도 4개 심각도를 구분한다(요구사항 4.4). */
export type SeverityIconShape = "octagon" | "triangle" | "diamond" | "circle" | "dot";

const SEV_ICON: Record<Severity, SeverityIconShape> = {
  critical: "octagon",
  high: "triangle",
  medium: "diamond",
  low: "circle",
};

export function severityDisplay(value: unknown): { label: string; icon: SeverityIconShape } {
  if (isOwnKey(SEV_LABEL, value)) {
    return { label: SEV_LABEL[value], icon: SEV_ICON[value] };
  }
  return { label: UNKNOWN_STATUS_LABEL, icon: "dot" };
}

// ─────────────────────────────────────────────────────────────
// 정렬·집계
// ─────────────────────────────────────────────────────────────

/** 작을수록 급하다. critical 0 … low 3. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** 목록에 없는 심각도는 가장 뒤로 보낸다. */
const UNKNOWN_SEVERITY_RANK = 4;

function rankOf(severity: unknown): number {
  return isOwnKey(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity] : UNKNOWN_SEVERITY_RANK;
}

/**
 * critical → high → medium → low 순서로 정렬한 새 배열을 돌려준다.
 * 같은 심각도끼리는 입력 순서를 유지하고(안정 정렬), 입력 배열은 바꾸지 않는다.
 */
export function sortBySeverity<T extends { severity: Severity }>(items: readonly T[]): T[] {
  return items
    .map((item, index) => ({ item, index, rank: rankOf(item.severity) }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .map((entry) => entry.item);
}

/** 심각도별 개수. 목록에 없는 심각도는 세지 않는다. */
export function countSeverities(
  items: readonly { severity: Severity }[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const { severity } of items) {
    if (isOwnKey(counts, severity)) counts[severity] += 1;
  }
  return counts;
}

// ─────────────────────────────────────────────────────────────
// 결과 요약 (요구사항 8.1~8.4, 12.5)
// ─────────────────────────────────────────────────────────────

export interface ResultSummary {
  mood: HoiMood;
  /** 공백 포함 80자 이하 한 문장. */
  message: string;
  /**
   * true면 같은 Hoi_Speech 영역에 `LIMIT_NOTICE`를 함께 표시한다.
   * "안전"·"문제없어요"로 읽힐 수 있는 결과(0개, medium·low만)에서 true다(요구사항 8.3, 12.5).
   * critical·high가 있으면 위험을 알리는 결과이므로 false다.
   */
  showLimitNotice: boolean;
}

export const NO_FINDINGS_MESSAGE = "이번에 확인한 범위에서는 큰 문제가 보이지 않았어요.";

export const LIMIT_NOTICE =
  "호이가 열심히 살펴보지만 자동 점검만으로 모든 위험을 찾을 수는 없어요. 중요한 서비스는 보안 전문가의 검토도 함께 받아보세요.";

const RESULT_MESSAGE = {
  critical: "급하게 살펴볼 곳이 있어요. 가장 중요한 1개부터 같이 해결해요.",
  high: "고치면 훨씬 든든해질 부분을 찾았어요.",
  minor: "큰 위험은 보이지 않았어요. 아래 항목도 다듬으면 더 좋아요.",
} as const;

export function summarizeResult(findings: readonly { severity: Severity }[]): ResultSummary {
  if (findings.length === 0) {
    return { mood: "rest", message: NO_FINDINGS_MESSAGE, showLimitNotice: true };
  }
  const counts = countSeverities(findings);
  if (counts.critical >= 1) {
    return { mood: "concerned", message: RESULT_MESSAGE.critical, showLimitNotice: false };
  }
  if (counts.high >= 1) {
    return { mood: "guide", message: RESULT_MESSAGE.high, showLimitNotice: false };
  }
  // "큰 위험은 보이지 않았어요"는 안전 취지로 읽히므로 한계 고지를 함께 보인다(요구사항 12.5).
  return { mood: "cheer", message: RESULT_MESSAGE.minor, showLimitNotice: true };
}

export interface FindingSummary {
  mood: HoiMood;
  title?: string;
  /** 공백 포함 80자 이하 한 문장. */
  message: string;
}

export const RESOLVED_FINDING_TITLE = "잘 막았어요. 한 단계 더 튼튼해졌어요";

const FINDING_MESSAGE: Record<FindingStatus, string> = {
  detected: "확인이 필요한 곳이에요. 아래 설명을 보고 차근차근 고쳐봐요.",
  verified: "실제로 문제가 생기는 걸 확인했어요. 수정안을 만들어 같이 고쳐요.",
  fixing: "지금 고치는 중이에요. 준비되면 다음 단계를 알려드릴게요.",
  fixed: "수정 내용을 적용했어요. 문제가 해결됐는지 다시 확인해 주세요.",
  verification_failed: "아직 완전히 막히지 않았어요. 수정안을 다시 살펴보고 한 번 더 확인해요.",
  regression_failed: "기존 기능 하나가 달라졌어요. 수정안을 같이 다시 살펴봐요.",
  resolved: "같은 공격을 다시 해 보고, 기존 기능도 그대로인지 확인했어요.",
};

const UNKNOWN_FINDING_MESSAGE = "아래 설명을 보고 다음 단계를 같이 정해 봐요.";

export function summarizeFinding(status: FindingStatus): FindingSummary {
  const message = isOwnKey(FINDING_MESSAGE, status)
    ? FINDING_MESSAGE[status]
    : UNKNOWN_FINDING_MESSAGE;
  if (status === "resolved") {
    return { mood: "celebrate", title: RESOLVED_FINDING_TITLE, message };
  }
  if (status === "verification_failed" || status === "regression_failed") {
    return { mood: "concerned", message };
  }
  return { mood: "guide", message };
}

// ─────────────────────────────────────────────────────────────
// 한 화면 하나의 다음 행동 (요구사항 8.7)
// ─────────────────────────────────────────────────────────────

export type FindingPrimaryAction = "generate" | "review" | "verify" | "next";

const VERIFY_STATUSES: ReadonlySet<FindingStatus> = new Set<FindingStatus>([
  "fixed",
  "verification_failed",
  "regression_failed",
]);

/** 위에서부터 첫 일치 규칙(설계 4-1). */
export function primaryActionForFinding(input: {
  status: FindingStatus;
  hasFix: boolean;
  applied: boolean;
}): FindingPrimaryAction {
  const { status, hasFix, applied } = input;
  if (status === "resolved") return "next";
  if (!hasFix) return "generate";
  if (!applied) return "review";
  if (VERIFY_STATUSES.has(status)) return "verify";
  return "next";
}

export type ScanPrimaryAction =
  | { kind: "open-finding"; findingId: string }
  | { kind: "rescan" };

/** 미해결 발견 중 가장 급한 심각도의 첫 항목, 없으면 다시 점검. */
export function primaryActionForScan(
  findings: readonly { id: string; severity: Severity; status: FindingStatus }[],
): ScanPrimaryAction {
  let best: { id: string; rank: number } | null = null;
  for (const finding of findings) {
    if (finding.status === "resolved") continue;
    const rank = rankOf(finding.severity);
    if (best === null || rank < best.rank) best = { id: finding.id, rank };
  }
  return best ? { kind: "open-finding", findingId: best.id } : { kind: "rescan" };
}

// ─────────────────────────────────────────────────────────────
// 빠른 점검 입력·오류 (요구사항 6.2, 6.3, 6.5~6.8)
// ─────────────────────────────────────────────────────────────

/** 서버(`/api/quick-check`)와 같은 기준. 문자열 `length`로 센다. */
export const MAX_SOURCE_CHARS = 100_000;

const MAX_SOURCE_CHARS_TEXT = MAX_SOURCE_CHARS.toLocaleString("en-US");

/** `12345` → `"12,345 / 100,000자"`. 음수·소수는 0 이상 정수로 맞춘다. */
export function formatCharCount(length: number): string {
  const n = Math.max(0, Math.floor(length));
  return `${n.toLocaleString("en-US")} / ${MAX_SOURCE_CHARS_TEXT}자`;
}

/** 100,001자 이상이면 true. 정확히 100,000자는 허용한다(요구사항 6.8). */
export function isOverSourceLimit(source: string): boolean {
  return source.length > MAX_SOURCE_CHARS;
}

/** 진행 중이거나 글자 수를 넘으면 제출 버튼을 막는다(요구사항 6.3, 6.7). */
export function isQuickCheckSubmitDisabled(state: { source: string; running: boolean }): boolean {
  return state.running || isOverSourceLimit(state.source);
}

/**
 * 제출 전 검사. 공백만 있으면 `"empty"`, 글자 수 초과면 `"too_large"`, 통과면 `null`.
 * `String.prototype.trim`은 스페이스·탭·개행과 전각 공백(U+3000)을 모두 지운다.
 */
export function validateQuickCheckSource(source: string): "empty" | "too_large" | null {
  if (source.trim().length === 0) return "empty";
  if (isOverSourceLimit(source)) return "too_large";
  return null;
}

/** 빈 입력 제출 때 `role="alert"`에 보이는 문구(요구사항 6.5). */
export const QUICK_CHECK_EMPTY_MESSAGE = "확인할 코드를 먼저 붙여 넣어 주세요.";

export type QuickCheckErrorKind = "source_too_large" | "internal_error" | "network" | "other";

/** 네트워크 실패가 먼저, 그다음 서버 오류 코드. 모르는 코드는 `other`. */
export function classifyQuickCheckError(input: {
  networkFailed: boolean;
  errorCode?: unknown;
}): QuickCheckErrorKind {
  if (input.networkFailed) return "network";
  if (input.errorCode === "source_too_large") return "source_too_large";
  if (input.errorCode === "internal_error") return "internal_error";
  return "other";
}

/** 오류 종류별 FriendlyError 문구. 설명은 "다음에 할 일" 문장으로 끝난다(설계 Error Handling). */
export const QUICK_CHECK_ERROR_COPY: Record<
  QuickCheckErrorKind,
  { title: string; description: string }
> = {
  source_too_large: {
    title: "코드가 조금 길어요",
    description: `한 번에 ${MAX_SOURCE_CHARS_TEXT}자까지 살펴볼 수 있어요. 코드를 여러 번에 나눠 넣어 주세요.`,
  },
  internal_error: {
    title: "지금은 코드를 살펴보기 어려워요",
    description: "호이 쪽에서 잠시 문제가 생겼어요. 잠시 후 다시 시도해 주세요.",
  },
  network: {
    title: "연결이 잠깐 끊겼어요",
    description: "붙여 넣은 코드는 그대로 있어요. 인터넷 연결을 확인하고 다시 시도해 주세요.",
  },
  other: {
    title: "검사를 마치지 못했어요",
    description: "로그인 상태와 코드를 확인한 뒤 다시 시도해 주세요.",
  },
};

// ─────────────────────────────────────────────────────────────
// 새 프로젝트 (요구사항 7.9, 7.10, 7.11)
// ─────────────────────────────────────────────────────────────

/**
 * 8MB = 8,388,608바이트. 이 값을 넘으면(초과) 막는다.
 * 서버 한도(src/lib/config/limits.ts)와 같은 기본값을 쓴다.
 */
export const MAX_ZIP_BYTES = DEFAULT_LIMITS.uploadZipBytes;
/** 붙여넣은 코드 최대 길이. 넘으면 잘라내지 않고 막는다. */
export const MAX_PASTED_SOURCE_CHARS = DEFAULT_LIMITS.pastedSourceChars;

/** 이름 공백 검사 → ZIP 크기 검사 순서. `zipSize`가 `null`이면 ZIP 없음. */
export function validateProjectDraft(draft: {
  name: string;
  zipSize: number | null;
}): "name_required" | "zip_too_large" | null {
  if (draft.name.trim().length === 0) return "name_required";
  if (draft.zipSize !== null && draft.zipSize > MAX_ZIP_BYTES) return "zip_too_large";
  return null;
}

/** 기존 두 생성 경로를 그대로 쓴다. */
export function projectEndpoint(hasZip: boolean): "/api/projects/upload" | "/api/projects" {
  return hasZip ? "/api/projects/upload" : "/api/projects";
}

// ─────────────────────────────────────────────────────────────
// 탭 roving (요구사항 7.4)
// ─────────────────────────────────────────────────────────────

export type TabKey = "ArrowLeft" | "ArrowRight" | "Home" | "End";

/** 다음 선택 탭 인덱스. 양 끝에서는 반대쪽으로 돌아간다. `count ≤ 0`이면 0. */
export function nextTabIndex(current: number, key: TabKey, count: number): number {
  if (count <= 0) return 0;
  switch (key) {
    case "ArrowRight":
      return (current + 1) % count;
    case "ArrowLeft":
      return (current - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return current;
  }
}

// ─────────────────────────────────────────────────────────────
// 대시보드 지표 (요구사항 9.6, 9.7, 9.8)
// ─────────────────────────────────────────────────────────────

/**
 * 프로젝트 한 개의 집계 입력. `dashboard/page.tsx`의 행에서 그대로 만든다:
 * `{ hasLatestScan: Boolean(latest), findings, lastCheckedAt }`.
 * `findings`는 최신 스캔의 발견(`getFindingsForScan(latest.id)`)이고, 최신 스캔이 없으면 빈 배열이다.
 */
export interface DashboardRowInput {
  hasLatestScan: boolean;
  findings: readonly { severity: Severity; status: FindingStatus }[];
  /** `project.lastScanDate ?? latest?.completedAt ?? latest?.startedAt` */
  lastCheckedAt?: string | null;
}

export interface DashboardMetrics {
  /** 최신 스캔 발견 중 `status === "resolved"` 수 ("잘 해결했어요"). */
  resolvedTotal: number;
  /** 최신 스캔 발견 중 미해결이면서 critical·high인 수 ("먼저 살펴봐요"). */
  urgentTotal: number;
  /** 최신 스캔이 없는 프로젝트 수 ("점검 기다리는 중"). */
  waitingTotal: number;
  /** 모든 행의 `lastCheckedAt` 중 가장 최근 값. 없으면 `null` → "아직 없어요" ("최근 점검"). */
  recentCheckedAt: string | null;
}

/** 저장된 데이터만으로 계산한다. 빈 목록이면 0·0·0·null. */
export function computeDashboardMetrics(rows: readonly DashboardRowInput[]): DashboardMetrics {
  let resolvedTotal = 0;
  let urgentTotal = 0;
  let waitingTotal = 0;
  let recentCheckedAt: string | null = null;
  let recentTime = Number.NEGATIVE_INFINITY;

  for (const row of rows) {
    if (!row.hasLatestScan) waitingTotal += 1;
    for (const finding of row.findings) {
      if (finding.status === "resolved") {
        resolvedTotal += 1;
      } else if (finding.severity === "critical" || finding.severity === "high") {
        urgentTotal += 1;
      }
    }
    if (row.lastCheckedAt) {
      // 해석할 수 없는 시각은 건너뛴다. 같은 시각이면 먼저 나온 값을 유지한다.
      const time = Date.parse(row.lastCheckedAt);
      if (!Number.isNaN(time) && time > recentTime) {
        recentTime = time;
        recentCheckedAt = row.lastCheckedAt;
      }
    }
  }

  return { resolvedTotal, urgentTotal, waitingTotal, recentCheckedAt };
}

// ─────────────────────────────────────────────────────────────
// 정직한 안내 (요구사항 12.4)
// ─────────────────────────────────────────────────────────────

/**
 * 위험이 전혀 없음을 보장하는 표현. `g` 플래그를 쓰지 않아 `test()`가 상태를 갖지 않는다.
 * "아직 완전히 막히지 않았어요"처럼 부정·한계를 말하는 문구는 걸리지 않게 좁게 잡는다.
 */
export const FORBIDDEN_GUARANTEE_PATTERNS: readonly RegExp[] = [
  /100\s*%\s*(안전|보호|방어|차단|막)/,
  /완벽(해요|히|하게|한|합니다|하다|\s*(보호|방어|차단))/,
  /절대\s*(안전|뚫리지|해킹)/,
  /완전히\s*안전/,
  /문제\s*없음을\s*보장/,
  /(안전|보안)(을|이)?\s*보장/,
  /위험(이|은)?\s*전혀\s*없/,
  /100\s*%\s*(safe|secure)/i,
];

export function containsGuaranteePhrase(text: string): boolean {
  return FORBIDDEN_GUARANTEE_PATTERNS.some((pattern) => pattern.test(text));
}
