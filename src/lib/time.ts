/**
 * 서비스 표준 시간대: 한국 표준시(KST, Asia/Seoul, UTC+9, 서머타임 없음).
 *
 * - 저장·비교용 시각은 지금처럼 ISO 8601(UTC, "Z")로 둔다. 같은 순간을 가리키고
 *   문자열 정렬·DB(timestamptz)·만료 계산이 서버 시간대와 상관없이 맞는다.
 * - 사람에게 보여 주는 시각과 ZIP 안 파일 시각은 서버가 어느 시간대에서 돌든(Vercel은 UTC)
 *   항상 KST로 만든다. 이 파일의 함수만 쓴다.
 */
export const KST_TIME_ZONE = "Asia/Seoul";
const KST_OFFSET_MS = 9 * 60 * 60 * 1000;

type DateInput = string | number | Date;

function toDate(value: DateInput): Date | null {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** 날짜와 시각: "2026. 9. 29. 오후 3:16:25" 형식(ko-KR 기본), 시간대는 KST. */
export function formatKstDateTime(value: DateInput, options?: Intl.DateTimeFormatOptions): string {
  const d = toDate(value);
  if (!d) return "기록 없음";
  return new Intl.DateTimeFormat("ko-KR", { ...(options ?? DEFAULT_DATE_TIME), timeZone: KST_TIME_ZONE }).format(d);
}

const DEFAULT_DATE_TIME: Intl.DateTimeFormatOptions = {
  year: "numeric",
  month: "numeric",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
};

/** KST 기준 연·월·일·시·분·초(ZIP 파일 시각처럼 숫자 조각이 필요할 때). */
export function kstParts(value: DateInput = new Date()): {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
} {
  const d = toDate(value) ?? new Date();
  // KST는 서머타임이 없어 고정 +9시간을 더한 뒤 UTC 필드로 읽으면 된다.
  const k = new Date(d.getTime() + KST_OFFSET_MS);
  return {
    year: k.getUTCFullYear(),
    month: k.getUTCMonth() + 1,
    day: k.getUTCDate(),
    hour: k.getUTCHours(),
    minute: k.getUTCMinutes(),
    second: k.getUTCSeconds(),
  };
}
