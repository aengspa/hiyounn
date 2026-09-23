import type { SecurityRule } from "@/lib/rules/types";

/**
 * v1 규칙 정의 — 웹사이트 점검 대상.
 *
 * 문서 1-4의 웹 관련 규칙만 등록한다(앱/모바일/게임 제외).
 * 각 규칙은 스캐너에서 분리되어 선언형으로 관리되며, 서버가 이 규칙으로
 * 도구 입력을 조립하고 실행 등급/전제조건을 확정한다.
 */
export const RULES: SecurityRule[] = [
  {
    id: "SEC-001",
    version: "1.0.0",
    title: "Hardcoded secret exposure",
    titleKo: "비밀정보 노출",
    severity: "critical",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A07:2021" },
    ],
    appliesTo: ["web", "api", "baas"],
    selector: {
      all: [{ field: "source.access", op: "equals", value: "read_only" }],
    },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-secrets", toolId: "secret_scanner", method: "SAST" }],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**", ".env*"],
      productionChange: "approval_required", // 노출된 키 폐기·교체는 운영 작업
    },
    verificationRequiredChecks: ["scan-secrets", "changed-code-scan"],
  },

  {
    id: "SEC-004",
    version: "1.0.0",
    title: "Vulnerable dependencies",
    titleKo: "취약한 의존성",
    severity: "high",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A06:2021" },
    ],
    appliesTo: ["web", "api", "baas"],
    selector: {
      all: [{ field: "capabilities.lockfile", op: "equals", value: "detected" }],
    },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [{ id: "sca-audit", toolId: "sca_scanner", method: "CONFIG" }],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["package.json", "package-lock.json"],
      productionChange: "not_applicable",
    },
    verificationRequiredChecks: ["sca-audit"],
  },

  {
    id: "WEB-001",
    version: "1.0.0",
    title: "Unauthenticated access to protected API",
    titleKo: "보호된 API의 무인증 접근",
    severity: "high",
    standards: [
      {
        framework: "OWASP_API_SECURITY_TOP_10",
        version: "2023",
        id: "API2:2023",
      },
    ],
    appliesTo: ["api", "web"],
    selector: {
      all: [
        { field: "components.kind", op: "contains", value: "api" },
        {
          field: "capabilities.authentication",
          op: "equals",
          value: "detected",
        },
      ],
    },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "anonymous-access",
        toolId: "anonymous_request_probe",
        method: "TEST",
        expected: "denied",
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 10,
      timeoutSeconds: 60,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["anonymous-access", "existing-functional-tests"],
  },

  {
    id: "WEB-002",
    version: "1.0.0",
    title: "Cross-user object authorization",
    titleKo: "사용자 간 데이터 접근(IDOR)",
    severity: "critical",
    standards: [
      {
        framework: "OWASP_API_SECURITY_TOP_10",
        version: "2023",
        id: "API1:2023",
      },
    ],
    appliesTo: ["api", "web", "baas"],
    selector: {
      all: [
        { field: "components.kind", op: "contains", value: "api" },
        {
          field: "capabilities.authentication",
          op: "equals",
          value: "detected",
        },
        {
          field: "capabilities.user_owned_data",
          op: "equals",
          value: "detected",
        },
      ],
    },
    methods: ["SAST", "TEST"],
    prerequisites: {
      SAST: ["source_checkout"],
      TEST: [
        "authorized_test_deployment",
        "test_user_a",
        "test_user_b",
        "object_owned_by_a",
        "object_owned_by_b",
      ],
    },
    checks: [
      { id: "locate-object-endpoints", toolId: "route_inventory", method: "SAST" },
      {
        id: "cross-user-read",
        toolId: "authorization_test_runner",
        method: "TEST",
        actor: "test_user_a",
        object: "object_owned_by_b",
        operation: "read",
        expected: "denied",
      },
      {
        id: "owner-read",
        toolId: "authorization_test_runner",
        method: "TEST",
        actor: "test_user_b",
        object: "object_owned_by_b",
        operation: "read",
        expected: "allowed",
      },
      {
        id: "cross-user-update",
        toolId: "authorization_test_runner",
        method: "TEST",
        actor: "test_user_a",
        object: "object_owned_by_b",
        operation: "update",
        expected: "denied",
      },
      {
        id: "owner-update",
        toolId: "authorization_test_runner",
        method: "TEST",
        actor: "test_user_b",
        object: "object_owned_by_b",
        operation: "update",
        expected: "allowed",
      },
    ],
    execution: {
      tier: "ISOLATED_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 40,
      timeoutSeconds: 120,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**", "supabase/migrations/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: [
      "cross-user-read",
      "owner-read",
      "cross-user-update",
      "owner-update",
      "existing-functional-tests",
      "changed-code-scan",
    ],
  },

  {
    id: "WEB-007",
    version: "1.0.0",
    title: "Session, CORS and security headers",
    titleKo: "세션·CORS·보안 헤더",
    severity: "medium",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A05:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [
        { field: "components.kind", op: "contains", value: "web" },
        { field: "environment.testOrigin", op: "exists" },
      ],
    },
    methods: ["CONFIG"],
    prerequisites: {}, // 배포 URL 없으면 정적 설정으로 대체(coverage_gap 없이 SAFE_ACTIVE 축소)
    checks: [
      { id: "http-headers", toolId: "http_config_scanner", method: "CONFIG" },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 5,
      timeoutSeconds: 30,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["next.config.js", "next.config.mjs", "src/**"],
      productionChange: "not_applicable",
    },
    verificationRequiredChecks: ["http-headers"],
  },

  {
    id: "BAAS-001",
    version: "1.0.0",
    title: "Supabase Row Level Security",
    titleKo: "Supabase RLS(행 수준 보안)",
    severity: "high",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A01:2021" },
    ],
    appliesTo: ["baas"],
    selector: {
      all: [{ field: "components.kind", op: "contains", value: "baas" }],
    },
    methods: ["CONFIG", "TEST"],
    prerequisites: {
      CONFIG: ["source_checkout"],
      // 사용자 세션으로 검사해야 함(서비스 역할 키로 검사 금지)
      TEST: ["test_user_a", "test_user_b"],
    },
    checks: [
      { id: "rls-policy-read", toolId: "baas_policy_scanner", method: "CONFIG" },
    ],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["supabase/migrations/**", "supabase/policies.sql"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["rls-policy-read"],
  },
];
