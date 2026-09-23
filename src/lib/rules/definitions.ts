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
    // 지식 베이스 F-2. DOM/저장 XSS(정적 신호).
    id: "WEB-003",
    version: "1.0.0",
    title: "DOM/Stored Cross-Site Scripting (static signal)",
    titleKo: "XSS(교차 사이트 스크립팅)",
    severity: "high",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A03:2021" },
    ],
    appliesTo: ["web"],
    selector: {
      all: [{ field: "components.kind", op: "contains", value: "web" }],
    },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-xss-sinks", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "not_applicable",
    },
    verificationRequiredChecks: ["scan-xss-sinks", "changed-code-scan"],
  },

  {
    // 지식 베이스 F-1 + F-3. SQL/NoSQL 인젝션 및 커맨드/역직렬화 인젝션(정적 신호).
    id: "WEB-004",
    version: "1.0.0",
    title: "Injection (SQL / command / eval) — static signal",
    titleKo: "인젝션(SQL·커맨드·eval)",
    severity: "critical",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A03:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [
        { field: "components.kind", op: "contains", value: "api" },
        { field: "components.kind", op: "contains", value: "web" },
      ],
    },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-sql-injection", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-command-injection", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: [
      "scan-sql-injection",
      "scan-command-injection",
      "changed-code-scan",
    ],
  },

  {
    // 지식 베이스 D-2. 민감정보 응답 과다 노출(정적 신호).
    id: "WEB-005",
    version: "1.0.0",
    title: "Excessive data exposure in API responses (static signal)",
    titleKo: "민감정보 응답 과다 노출",
    severity: "high",
    standards: [
      {
        framework: "OWASP_API_SECURITY_TOP_10",
        version: "2023",
        id: "API3:2023",
      },
    ],
    appliesTo: ["api", "web"],
    selector: {
      all: [{ field: "components.kind", op: "contains", value: "api" }],
    },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-response-fields", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "not_applicable",
    },
    verificationRequiredChecks: ["scan-response-fields", "changed-code-scan"],
  },

  {
    // 지식 베이스 A-3. 경로 트래버설(정적 신호).
    id: "WEB-006",
    version: "1.0.0",
    title: "Path traversal via unsanitized file access (static signal)",
    titleKo: "경로 트래버설(디렉터리 접근 우회)",
    severity: "high",
    standards: [
      // ASVS 4.3.2 접근제어(경로) — 프레임워크 표준으로는 A01 계열.
      { framework: "OWASP_TOP_10", version: "2021", id: "A01:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [
        { field: "components.kind", op: "contains", value: "api" },
        { field: "components.kind", op: "contains", value: "web" },
      ],
    },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-path-traversal", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: {
      tier: "PASSIVE",
      target: "source_checkout",
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "not_applicable",
    },
    verificationRequiredChecks: ["scan-path-traversal", "changed-code-scan"],
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
    // 지식 베이스 C-3. 노출된 관리/디버그 엔드포인트(능동 점검).
    id: "WEB-008",
    version: "1.0.0",
    title: "Exposed administrative or debug endpoints",
    titleKo: "노출된 관리/디버그 엔드포인트",
    severity: "high",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A05:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [{ field: "environment.testOrigin", op: "exists" }],
    },
    methods: ["CONFIG"],
    // 배포 URL(테스트 대상)이 없으면 검사 불가 → coverage_gap. 정적 대체 없음.
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-exposed-paths",
        toolId: "exposed_path_probe",
        method: "CONFIG",
        expected: "denied",
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 12,
      timeoutSeconds: 30,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["next.config.js", "next.config.mjs"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-exposed-paths"],
  },

  {
    // 지식 베이스 C-2. 평문 HTTP / TLS 미강제(능동 관측).
    id: "WEB-009",
    version: "1.0.0",
    title: "Plaintext HTTP allowed / TLS not enforced",
    titleKo: "평문 HTTP 허용·TLS 미강제",
    severity: "medium",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A05:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [{ field: "environment.testOrigin", op: "exists" }],
    },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-tls",
        toolId: "tls_probe",
        method: "CONFIG",
        expected: "denied", // 평문 HTTP는 거부(→https)되어야 함
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 4,
      timeoutSeconds: 20,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["next.config.js", "next.config.mjs"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-tls"],
  },

  {
    // 지식 베이스 B-3. 사용자 열거(능동, 비파괴 로그인 프로브).
    id: "WEB-010",
    version: "1.0.0",
    title: "Username enumeration via auth responses",
    titleKo: "사용자 열거(로그인 응답 차이)",
    severity: "medium",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A07:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      all: [
        { field: "environment.testOrigin", op: "exists" },
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
        id: "probe-user-enumeration",
        toolId: "auth_probe",
        method: "TEST",
        expected: "denied", // 존재/비존재 응답이 구분 불가여야 함
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 4,
      timeoutSeconds: 30,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-user-enumeration"],
  },

  {
    // 지식 베이스 B-2. 무차별 대입 방어 부재(능동, 비파괴 저빈도 프로브).
    id: "WEB-011",
    version: "1.0.0",
    title: "Missing brute-force protection on login",
    titleKo: "무차별 대입 방어 부재",
    severity: "medium",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A07:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      all: [
        { field: "environment.testOrigin", op: "exists" },
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
        id: "probe-bruteforce",
        toolId: "bruteforce_probe",
        method: "TEST",
        expected: "denied", // 연속 실패는 차단(429/잠금)되어야 함
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 8,
      timeoutSeconds: 40,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-bruteforce"],
  },

  {
    // 지식 베이스 B-4. 세션 쿠키 속성 미흡(능동 관측).
    id: "WEB-012",
    version: "1.0.0",
    title: "Insecure session cookie attributes",
    titleKo: "세션 쿠키 속성 미흡",
    severity: "medium",
    standards: [
      { framework: "OWASP_TOP_10", version: "2021", id: "A05:2021" },
    ],
    appliesTo: ["web", "api"],
    selector: {
      any: [{ field: "environment.testOrigin", op: "exists" }],
    },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-cookie-flags",
        toolId: "cookie_probe",
        method: "CONFIG",
        expected: "denied", // 미흡 속성이 없어야(=모두 설정) 함
      },
    ],
    execution: {
      tier: "SAFE_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 2,
      timeoutSeconds: 20,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-cookie-flags"],
  },

  {
    // 지식 베이스 A-2. 함수 수준 권한 상승(BFLA, 격리 능동 재현).
    id: "WEB-013",
    version: "1.0.0",
    title: "Broken function-level authorization (BFLA)",
    titleKo: "함수 수준 권한 상승(BFLA)",
    severity: "high",
    standards: [
      {
        framework: "OWASP_API_SECURITY_TOP_10",
        version: "2023",
        id: "API5:2023",
      },
    ],
    appliesTo: ["api", "web"],
    selector: {
      all: [
        { field: "environment.testOrigin", op: "exists" },
        {
          field: "capabilities.authentication",
          op: "equals",
          value: "detected",
        },
        {
          field: "capabilities.admin_functions",
          op: "equals",
          value: "detected",
        },
      ],
    },
    methods: ["TEST"],
    prerequisites: {
      TEST: ["authorized_test_deployment", "test_user_a", "admin_session"],
    },
    checks: [
      {
        id: "probe-bfla",
        toolId: "bfla_probe",
        method: "TEST",
        actor: "test_user_a",
        operation: "update",
        expected: "denied", // 일반 사용자의 관리자 함수 호출은 거부되어야 함
      },
    ],
    execution: {
      tier: "ISOLATED_ACTIVE",
      target: "registered_test_deployment",
      maxRequests: 12,
      timeoutSeconds: 60,
      destructiveOperations: false,
    },
    remediation: {
      autoPatch: "branch_only",
      allowedPaths: ["app/**", "src/**"],
      productionChange: "approval_required",
    },
    verificationRequiredChecks: ["probe-bfla"],
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
