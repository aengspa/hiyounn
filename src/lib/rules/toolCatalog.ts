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
    toolId: "sca_scanner",
    displayName: "의존성 취약점 스캐너(SCA)",
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
];

const BY_ID = new Map(TOOL_CATALOG.map((t) => [t.toolId, t]));

export function isRegisteredTool(toolId: string): boolean {
  return BY_ID.has(toolId);
}

export function getTool(toolId: string): ToolCatalogEntry | undefined {
  return BY_ID.get(toolId);
}
