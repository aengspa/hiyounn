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
  verifyTimeBudgetMs: 150_000,
  llmCallTimeoutMs: 30_000,
  /** LLM에 보낼 한 파일의 최대 길이. 넘으면 그 파일은 LLM 수정·검토 대상에서 뺀다. */
  llmFileChars: 24_000,
  /** 실행 중으로 남은 작업을 실패로 볼 때까지의 시간. */
  staleJobMs: 180_000,
  /** 재검증 한 번에 AI로 보낼 파일 내용 총량. 넘는 파일은 보내지 않고 기록한다. */
  reverifyPromptChars: 60_000,
  /** 재검증 AI 호출 한 번의 제한 시간. */
  reverifyLlmTimeoutMs: 60_000,
  /** AI 코드 분석: 한 번의 호출에 담을 파일 내용 총량(파일 중간은 자르지 않음). */
  aiScanChunkChars: 12_000,
  /** AI 코드 분석: 한 번의 점검에서 보낼 최대 묶음 수. 넘는 파일은 기록만 한다. */
  aiScanMaxChunks: 10,
  /** AI 코드 분석: 동시에 보내는 호출 수. */
  aiScanConcurrency: 3,
  /** AI 코드 분석: 호출 한 번의 제한 시간. */
  aiScanCallTimeoutMs: 60_000,
  /** AI 코드 분석 전체 예산. 이 시간이 지나면 남은 묶음은 시작하지 않는다. */
  aiScanTimeBudgetMs: 150_000,
  /** 전체 수정: 서로 다른 파일을 동시에 고치는 작업 수. */
  fixAllConcurrency: 3,
  /** 재검증 한 번에 만들 공격 재현 테스트 최대 수. */
  exploitMaxTests: 6,
  /** 공격 재현 테스트 한 번(격리 프로세스)의 제한 시간. */
  exploitRunTimeoutMs: 10_000,
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
  reverifyPromptChars: number;
  reverifyLlmTimeoutMs: number;
  aiScanChunkChars: number;
  aiScanMaxChunks: number;
  aiScanConcurrency: number;
  aiScanCallTimeoutMs: number;
  aiScanTimeBudgetMs: number;
  fixAllConcurrency: number;
  exploitMaxTests: number;
  exploitRunTimeoutMs: number;
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
    reverifyPromptChars: intFromEnv("LIMIT_REVERIFY_PROMPT_CHARS", d.reverifyPromptChars, 5_000, 400_000),
    reverifyLlmTimeoutMs: intFromEnv("LIMIT_REVERIFY_LLM_TIMEOUT_MS", d.reverifyLlmTimeoutMs, 5_000, 110_000),
    aiScanChunkChars: intFromEnv("LIMIT_AI_SCAN_CHUNK_CHARS", d.aiScanChunkChars, 2_000, 100_000),
    aiScanMaxChunks: intFromEnv("LIMIT_AI_SCAN_MAX_CHUNKS", d.aiScanMaxChunks, 1, 50),
    aiScanConcurrency: intFromEnv("LIMIT_AI_SCAN_CONCURRENCY", d.aiScanConcurrency, 1, 8),
    aiScanCallTimeoutMs: intFromEnv("LIMIT_AI_SCAN_CALL_TIMEOUT_MS", d.aiScanCallTimeoutMs, 5_000, 180_000),
    aiScanTimeBudgetMs: intFromEnv("LIMIT_AI_SCAN_TIME_BUDGET_MS", d.aiScanTimeBudgetMs, 10_000, 280_000),
    fixAllConcurrency: intFromEnv("LIMIT_FIX_ALL_CONCURRENCY", d.fixAllConcurrency, 1, 8),
    exploitMaxTests: intFromEnv("LIMIT_EXPLOIT_MAX_TESTS", d.exploitMaxTests, 0, 30),
    exploitRunTimeoutMs: intFromEnv("LIMIT_EXPLOIT_RUN_TIMEOUT_MS", d.exploitRunTimeoutMs, 2_000, 60_000),
  };
}

/** 요청 시점마다 다시 읽지 않아도 되도록 모듈 로드 시 한 번 읽는다. */
export const LIMITS: Limits = readLimits();
