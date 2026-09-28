/**
 * 서버 처리 한도 (서버 전용). 환경변수로 바꿀 수 있고, 값이 없거나 잘못되면
 * 보수적인 기본값을 쓴다.
 *
 * 기준:
 *  - 업로드 ZIP은 기존 정책 8MB를 유지한다(UI의 MAX_ZIP_BYTES와 같은 기본값).
 *  - Vercel Fluid compute 기본 함수 실행 시간은 300초다. 전체 수정·재검증은
 *    요청 안에서 동기로 처리하므로 라우트 maxDuration은 120초, 내부 작업
 *    예산은 그보다 짧은 90초로 잡아 응답을 보낼 여유를 둔다.
 *  - LLM 한 번 호출은 30초에서 끊는다.
 *
 * 한도를 넘으면 잘라서 처리하지 않고 명확한 오류로 돌려준다.
 */

function intFromEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

const MB = 1024 * 1024;

/** 기본값. UI와 서버가 같은 값을 보도록 여기서만 정의한다. */
export const DEFAULT_LIMITS = {
  uploadZipBytes: 8 * MB,
  unzipTotalBytes: 20 * MB,
  unzipFileBytes: 2 * MB,
  unzipMaxEntries: 2000,
  pastedSourceChars: 100_000,
  fixAllMaxItems: 20,
  fixAllTimeBudgetMs: 90_000,
  verifyTimeBudgetMs: 90_000,
  llmCallTimeoutMs: 30_000,
  /** LLM에 보낼 한 파일의 최대 길이. 넘으면 그 파일은 LLM 수정·검토 대상에서 뺀다. */
  llmFileChars: 24_000,
  /** 실행 중으로 남은 작업을 실패로 볼 때까지의 시간. */
  staleJobMs: 180_000,
} as const;

export interface Limits {
  uploadZipBytes: number;
  unzipTotalBytes: number;
  unzipFileBytes: number;
  unzipMaxEntries: number;
  pastedSourceChars: number;
  fixAllMaxItems: number;
  fixAllTimeBudgetMs: number;
  verifyTimeBudgetMs: number;
  llmCallTimeoutMs: number;
  llmFileChars: number;
  staleJobMs: number;
}

export function readLimits(): Limits {
  const d = DEFAULT_LIMITS;
  return {
    uploadZipBytes: intFromEnv("LIMIT_UPLOAD_ZIP_BYTES", d.uploadZipBytes, 1024, 50 * MB),
    unzipTotalBytes: intFromEnv("LIMIT_UNZIP_TOTAL_BYTES", d.unzipTotalBytes, 1024, 200 * MB),
    unzipFileBytes: intFromEnv("LIMIT_UNZIP_FILE_BYTES", d.unzipFileBytes, 1024, 20 * MB),
    unzipMaxEntries: intFromEnv("LIMIT_UNZIP_MAX_ENTRIES", d.unzipMaxEntries, 1, 20_000),
    pastedSourceChars: intFromEnv("LIMIT_PASTED_SOURCE_CHARS", d.pastedSourceChars, 100, 2_000_000),
    fixAllMaxItems: intFromEnv("LIMIT_FIX_ALL_MAX_ITEMS", d.fixAllMaxItems, 1, 200),
    fixAllTimeBudgetMs: intFromEnv("LIMIT_FIX_ALL_TIME_BUDGET_MS", d.fixAllTimeBudgetMs, 5_000, 280_000),
    verifyTimeBudgetMs: intFromEnv("LIMIT_VERIFY_TIME_BUDGET_MS", d.verifyTimeBudgetMs, 5_000, 280_000),
    llmCallTimeoutMs: intFromEnv("LIMIT_LLM_CALL_TIMEOUT_MS", d.llmCallTimeoutMs, 1_000, 120_000),
    llmFileChars: intFromEnv("LIMIT_LLM_FILE_CHARS", d.llmFileChars, 1_000, 200_000),
    staleJobMs: intFromEnv("LIMIT_STALE_JOB_MS", d.staleJobMs, 10_000, 3_600_000),
  };
}

/** 요청 시점마다 다시 읽지 않아도 되도록 모듈 로드 시 한 번 읽는다. */
export const LIMITS: Limits = readLimits();
