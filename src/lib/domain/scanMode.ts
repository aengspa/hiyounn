import type { ExecutionTier } from "@/lib/domain/types";

/**
 * 사용자가 프로젝트를 만들 때 고르는 보안 스캔 방식.
 *
 *   A. static          — ZIP(소스)만으로 정적 분석. 서비스에 요청을 보내지 않는다.
 *   B. safe_active     — 배포 URL에 비파괴(safe) 요청만 보내는 동적 분석.
 *   C. isolated_active — 운영과 격리된 서버 + 테스트 계정 2개로, 더 공격적인
 *                        샘플(IDOR·권한 상승 재현 등)까지 동적 분석.
 *
 * 스캔 범위는 A ⊂ B ⊂ C 순으로 넓어진다. 서버는 선택된 방식을 실행 게이트의
 * 최고 허용 등급으로 사용하므로, 사용자가 고른 범위를 넘는 검사는 실행되지 않는다.
 */
export type ScanMode = "static" | "safe_active" | "isolated_active";

export const SCAN_MODES: readonly ScanMode[] = [
  "static",
  "safe_active",
  "isolated_active",
] as const;

export interface ScanModeInfo {
  mode: ScanMode;
  letter: "A" | "B" | "C";
  title: string;
  tagline: string;
  /** 1~3. 스캔 범위 막대 표시에 사용. */
  scope: 1 | 2 | 3;
  /** 이 방식에서 서버가 허용하는 최고 실행 등급. */
  maxTier: ExecutionTier;
  /** 사용자가 준비해야 하는 것. */
  needs: string[];
  /** 이 방식에서 추가로 확인하는 것(이전 단계 포함). */
  covers: string[];
  /** 알아둘 점 / 위험도 안내. */
  caution: string;
}

export const SCAN_MODE_INFO: Record<ScanMode, ScanModeInfo> = {
  static: {
    mode: "static",
    letter: "A",
    title: "코드만 살펴보기",
    tagline: "ZIP 파일만으로 정적 분석해요",
    scope: 1,
    maxTier: "PASSIVE",
    needs: ["프로젝트 소스 ZIP (또는 붙여넣은 코드)"],
    covers: [
      "하드코딩된 비밀키·토큰",
      "취약한 의존성(OSV)",
      "코드 속 인가·입력 검증 누락 패턴",
      "ASVS 기반 설정 점검",
    ],
    caution: "서비스에 요청을 전혀 보내지 않아 가장 안전해요. 대신 실제로 동작 중인 서버의 설정·응답은 확인하지 못해요.",
  },
  safe_active: {
    mode: "safe_active",
    letter: "B",
    title: "배포된 서비스 안전 점검",
    tagline: "배포 URL로 비파괴 동적 분석까지 해요",
    scope: 2,
    maxTier: "SAFE_ACTIVE",
    needs: ["배포된 서비스 URL", "소유·점검 권한 확인", "소스 ZIP (선택, 있으면 A도 함께)"],
    covers: [
      "A의 모든 항목 (ZIP을 올린 경우)",
      "보안 헤더·쿠키 속성·TLS 설정",
      "노출된 엔드포인트·관리자 경로",
      "CORS·사용자 열거 등 응답 기반 점검",
    ],
    caution: "데이터를 바꾸거나 계정을 만드는 요청은 보내지 않아요. 운영 서비스에 가벼운 조회 요청만 보내요.",
  },
  isolated_active: {
    mode: "isolated_active",
    letter: "C",
    title: "격리 서버 심층 점검",
    tagline: "테스트 계정 2개로 공격을 재현해요",
    scope: 3,
    maxTier: "ISOLATED_ACTIVE",
    needs: [
      "운영과 분리된 테스트 서버 URL",
      "소유·점검 권한 확인",
      "서로 다른 테스트 계정 2개",
      "소스 ZIP (선택)",
    ],
    covers: [
      "B의 모든 항목",
      "계정 A로 계정 B의 데이터 접근 시도 (IDOR/BOLA)",
      "일반 사용자의 관리자 기능 호출 (BFLA·권한 상승)",
      "로그인 무차별 대입 방어 확인 등 위험도 높은 샘플",
    ],
    caution: "실제 공격에 가까운 요청을 보내 데이터가 바뀔 수 있어요. 반드시 운영 서버가 아닌 격리된 테스트 서버와 테스트 계정을 사용해 주세요.",
  },
};

export function parseScanMode(value: unknown): ScanMode | null {
  if (typeof value !== "string") return null;
  const v = value.trim().toLowerCase();
  if (v === "a" || v === "static") return "static";
  if (v === "b" || v === "safe_active" || v === "safe-active") return "safe_active";
  if (v === "c" || v === "isolated_active" || v === "isolated-active") return "isolated_active";
  return null;
}

export interface TestAccount {
  /** 화면에 보이는 이름. 예: "계정 A" */
  label: string;
  /** 로그인 ID 또는 이메일 */
  username: string;
  /** 서버에만 보관. API 응답으로 내보내지 않는다. */
  password: string;
}

/** 격리 동적 분석(C)에 필요한 테스트 계정 수. */
export const REQUIRED_TEST_ACCOUNTS = 2;

/** 클라이언트로 보낼 때 비밀번호를 제거한 계정 정보. */
export type PublicTestAccount = Omit<TestAccount, "password"> & { hasPassword: boolean };

export function toPublicTestAccounts(
  accounts: TestAccount[] | undefined
): PublicTestAccount[] | undefined {
  if (!accounts) return undefined;
  return accounts.map(({ label, username, password }) => ({
    label,
    username,
    hasPassword: Boolean(password),
  }));
}

/**
 * 요청 본문에서 테스트 계정 목록을 검증·정규화한다.
 * 형식이 잘못되면 null, 입력이 없으면 빈 배열.
 */
export function parseTestAccounts(value: unknown): TestAccount[] | null {
  if (value == null || value === "") return [];
  let raw: unknown = value;
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!Array.isArray(raw) || raw.length > 5) return null;
  const out: TestAccount[] = [];
  for (const [i, item] of raw.entries()) {
    if (!item || typeof item !== "object") return null;
    const r = item as Record<string, unknown>;
    const username = typeof r.username === "string" ? r.username.trim().slice(0, 200) : "";
    const password = typeof r.password === "string" ? r.password.slice(0, 200) : "";
    if (!username && !password) continue;
    if (!username || !password) return null;
    const label =
      typeof r.label === "string" && r.label.trim()
        ? r.label.trim().slice(0, 40)
        : `계정 ${String.fromCharCode(65 + i)}`;
    out.push({ label, username, password });
  }
  return out;
}

export type ScanModeValidationError =
  | "source_required"
  | "deployment_required"
  | "authorization_required"
  | "test_accounts_required"
  | "test_accounts_distinct";

/** 선택한 스캔 방식에 필요한 입력이 모두 있는지 서버에서 확인한다. */
export function validateScanModeInput(
  mode: ScanMode,
  input: {
    hasSource: boolean;
    deploymentUrl?: string;
    deploymentAuthorized: boolean;
    testAccounts: TestAccount[];
  }
): ScanModeValidationError | null {
  if (mode === "static") {
    return input.hasSource ? null : "source_required";
  }
  if (!input.deploymentUrl) return "deployment_required";
  if (!input.deploymentAuthorized) return "authorization_required";
  if (mode === "isolated_active") {
    if (input.testAccounts.length < REQUIRED_TEST_ACCOUNTS) return "test_accounts_required";
    const names = new Set(input.testAccounts.map((a) => a.username.toLowerCase()));
    if (names.size < input.testAccounts.length) return "test_accounts_distinct";
  }
  return null;
}

export const SCAN_MODE_ERROR_MESSAGE: Record<ScanModeValidationError, string> = {
  source_required: "A 방식은 소스 ZIP이나 붙여넣은 코드가 필요해요.",
  deployment_required: "B·C 방식은 배포된 서비스 URL이 필요해요.",
  authorization_required: "동적 분석을 하려면 이 주소의 소유·점검 권한을 확인해 주세요.",
  test_accounts_required: "C 방식은 서로 다른 테스트 계정 2개가 필요해요.",
  test_accounts_distinct: "테스트 계정 2개는 서로 다른 계정이어야 해요.",
};

/** API 응답용: 테스트 계정 비밀번호를 빼고 내보낸다. */
export function redactProject<P extends { testAccounts?: TestAccount[] }>(
  project: P
): Omit<P, "testAccounts"> & { testAccounts?: PublicTestAccount[] } {
  const { testAccounts, ...rest } = project;
  return { ...rest, testAccounts: toPublicTestAccounts(testAccounts) };
}
