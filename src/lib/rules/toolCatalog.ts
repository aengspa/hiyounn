import type { ToolCatalogEntry } from "@/lib/rules/types";

/**
 * 도구 카탈로그.
 *
 * 규칙은 여기 등록된 tool_id만 참조할 수 있다. 실행 게이트가
 * assertRegisteredTool로 검사하므로, 규칙이나 모델이 임의 도구를 끼워 넣을 수
 * 없다. 각 tool_id는 실제 스캐너 구현(src/lib/scanners/*)에 연결된다.
 */
export const TOOL_CATALOG: ToolCatalogEntry[] = [
  {
    toolId: "secret_scanner",
    displayName: "비밀정보 스캐너",
    method: "SAST",
    producesEvidence: ["source_code", "scanner_output"],
  },
  {
    // 실제 OSV.dev 조회 기반 SCA. src/lib/net/osv.ts + dependencyScanner.ts.
    toolId: "sca_scanner",
    displayName: "의존성 취약점 스캐너(SCA · OSV.dev)",
    method: "CONFIG",
    producesEvidence: ["configuration", "scanner_output"],
  },
  {
    toolId: "route_inventory",
    displayName: "라우트 인벤토리",
    method: "SAST",
    producesEvidence: ["source_code"],
  },
  {
    toolId: "authorization_test_runner",
    displayName: "권한 검사 러너",
    method: "TEST",
    producesEvidence: ["http_request", "http_response", "attack_reproduction"],
  },
  {
    toolId: "anonymous_request_probe",
    displayName: "익명 요청 프로브",
    method: "TEST",
    producesEvidence: ["http_request", "http_response"],
  },
  {
    toolId: "http_config_scanner",
    displayName: "HTTP 설정/헤더 스캐너",
    method: "CONFIG",
    producesEvidence: ["http_response", "configuration"],
  },
  {
    toolId: "baas_policy_scanner",
    displayName: "BaaS 정책 스캐너",
    method: "CONFIG",
    producesEvidence: ["configuration", "scanner_output"],
  },
  {
    toolId: "ai_code_analyzer",
    displayName: "AI 코드 분석기",
    method: "SAST",
    producesEvidence: ["source_code", "scanner_output"],
  },
  {
    // 정적 웹 코드 분석기(정규식/AST 신호 기반). Semgrep 등 실제 도구로 교체 가능.
    // XSS(WEB-003), 인젝션(WEB-004), 민감정보 과다 노출(WEB-005),
    // 경로 트래버설(WEB-006)에 공용으로 쓰인다.
    toolId: "static_web_analyzer",
    displayName: "정적 웹 코드 분석기",
    method: "SAST",
    producesEvidence: ["source_code", "scanner_output"],
  },
  {
    // 노출 경로 프로브(WEB-008). SSRF 안전 계층(safeFetch)으로 읽기 전용 GET을
    // 보내 민감 경로 노출을 관측한다. ZAP 등 실제 DAST 도구로 교체 가능.
    toolId: "exposed_path_probe",
    displayName: "노출 경로 프로브",
    method: "CONFIG",
    producesEvidence: ["http_request", "http_response", "scanner_output"],
  },
  {
    // TLS/HTTPS 강제 프로브(WEB-009). http→https 리다이렉트와 HSTS를 관측한다.
    toolId: "tls_probe",
    displayName: "TLS/HTTPS 강제 프로브",
    method: "CONFIG",
    producesEvidence: ["http_request", "http_response", "configuration"],
  },
  {
    // 인증 응답 프로브(WEB-010). 로그인에 잘못된 비밀번호로만 시도(비파괴)하여
    // 존재/비존재 계정 응답 차이(사용자 열거)를 관측한다.
    toolId: "auth_probe",
    displayName: "인증 응답 프로브",
    method: "TEST",
    producesEvidence: ["http_request", "http_response", "scanner_output"],
  },
  {
    // 무차별 대입 방어 프로브(WEB-011). 합성 계정에 잘못된 비밀번호로 소수 회
    // 연속 시도해 레이트 리밋/잠금(429 등) 존재 여부를 관측한다. 비파괴·저빈도.
    toolId: "bruteforce_probe",
    displayName: "무차별 대입 방어 프로브",
    method: "TEST",
    producesEvidence: ["http_request", "http_response", "scanner_output"],
  },
  {
    // 세션 쿠키 속성 프로브(WEB-012). Set-Cookie의 HttpOnly/Secure/SameSite 관측.
    toolId: "cookie_probe",
    displayName: "세션 쿠키 속성 프로브",
    method: "CONFIG",
    producesEvidence: ["http_response", "configuration"],
  },
  {
    // 함수 수준 권한 프로브(WEB-013 / BFLA). 일반 사용자 세션으로 관리자 함수를
    // 호출해 거부되는지 격리 환경에서 확인한다. 관리자 세션은 대조군.
    toolId: "bfla_probe",
    displayName: "함수 수준 권한 프로브(BFLA)",
    method: "TEST",
    producesEvidence: ["http_request", "http_response", "attack_reproduction"],
  },
];

const BY_ID = new Map(TOOL_CATALOG.map((t) => [t.toolId, t]));

export function isRegisteredTool(toolId: string): boolean {
  return BY_ID.has(toolId);
}

export function getTool(toolId: string): ToolCatalogEntry | undefined {
  return BY_ID.get(toolId);
}
