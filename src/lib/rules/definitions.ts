/**
 * 보안 점검 규칙 정의 v2 — 웹사이트/웹앱 대상 (개인 바이브코더용)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 점검 모드 (사용자가 선택)
 * ─────────────────────────────────────────────────────────────────────────────
 *   A. 소스 점검      : zip(소스)만 업로드. 정적 분석(PASSIVE)만 수행.
 *   B. 배포 URL 점검  : 소유권이 검증된 배포 URL 필요. 비파괴 능동 점검(SAFE_ACTIVE).
 *   C. 계정 기반 점검 : 검증된 URL + 테스트 계정 2개 이상. 격리 능동 점검(ISOLATED_ACTIVE).
 *
 *   각 규칙의 mode는 "그 규칙을 돌리는 데 필요한 최소 입력"이다.
 *   상위 모드는 하위 모드 규칙을 포함한다(C ⊃ B ⊃ A). 단 A 규칙은 소스가
 *   업로드된 경우에만 실행되며, 없으면 coverage_gap으로 보고한다.
 *   → selectRulesForMode() 참고.
 *
 *   같은 점검의 모드별 변형은 family로 묶는다(예: SEC-002 / SEC-002-B).
 *   리포트는 family 단위로 병합해 같은 문제가 두 번 나오지 않게 한다.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 근거 표준
 * ─────────────────────────────────────────────────────────────────────────────
 *   1차 근거 : CWE (결함 분류), CAPEC (그 결함을 악용하는 공격 패턴)
 *   보조 근거 : OWASP Top 10:2025, OWASP API Security Top 10:2023,
 *              OWASP Top 10 for LLM Applications:2025,
 *              MITRE ATT&CK (Enterprise), MITRE ATLAS (AI 시스템 대상)
 *
 *   CAPEC 매핑은 각 CWE 항목의 "Related Attack Patterns"를 우선으로 하되,
 *   직접 대응 패턴이 없으면 상위(메타/표준) 패턴을 쓴다. LLM 프롬프트 인젝션은
 *   CAPEC에 대응 패턴이 없어 MITRE ATLAS로 보완했다(해당 규칙 주석 참고).
 *   릴리스 전 cwe.mitre.org / capec.mitre.org / attack.mitre.org에서
 *   최신 버전 기준으로 ID를 한 번 검증하고 version 필드를 고정할 것.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 스캐너 자체 보안(소유권 검증, SSRF 차단, zip 처리 등)은
 * @/lib/scanners/definitions.ts 에 분리되어 있다. 특히 prerequisite
 * "authorized_test_deployment"는 SCN-001(대상 소유권 검증)을 통과해야만 충족된다.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ═════════════════════════════════════════════════════════════════════════════
// 타입
// (공유 스키마 @/lib/rules/types 로 통합: mode, family, summaryKo, produces,
//  coverageGap, check.when/params/confidence, remediation.manualStepsKo,
//  target "linked_baas_project", 신규 framework/prerequisite/toolId 가 추가됨)
// ═════════════════════════════════════════════════════════════════════════════

import type {
  AppKind,
  Check,
  Condition,
  Execution,
  Framework,
  Method,
  Prerequisite,
  Remediation,
  ScanMode,
  SecurityRule,
  Selector,
  Severity,
  StandardRef,
  Target,
  Tier,
} from "@/lib/rules/types";

type RuleDef = Omit<SecurityRule, "mode">;
// ═════════════════════════════════════════════════════════════════════════════
// 헬퍼
// ═════════════════════════════════════════════════════════════════════════════

const cwe = (...n: number[]): StandardRef[] =>
  n.map((x) => ({ framework: "CWE", id: `CWE-${x}` }));
const capec = (...n: number[]): StandardRef[] =>
  n.map((x) => ({ framework: "CAPEC", version: "3.9", id: `CAPEC-${x}` }));
const ref =
  (framework: Framework, version?: string) =>
  (...ids: string[]): StandardRef[] =>
    ids.map((id) => ({ framework, version, id }));
const owasp = ref("OWASP_TOP_10", "2025");
const apiTop10 = ref("OWASP_API_SECURITY_TOP_10", "2023");
const llmTop10 = ref("OWASP_LLM_TOP_10", "2025");
const attack = ref("MITRE_ATTACK", "enterprise");
const atlas = ref("MITRE_ATLAS");
const std = (...groups: StandardRef[][]): StandardRef[] => groups.flat();

const detected = (capability: string): Condition => ({
  field: `capabilities.${capability}`,
  op: "equals",
  value: "detected",
});
const kind = (k: string): Condition => ({
  field: "components.kind",
  op: "contains",
  value: k,
});
const provider = (p: string): Condition => ({
  field: "components.provider",
  op: "contains",
  value: p,
});
const HAS_ORIGIN: Condition = { field: "environment.testOrigin", op: "exists" };
const HAS_SOURCE: Condition = {
  field: "source.access",
  op: "equals",
  value: "read_only",
};
const HAS_GIT_HISTORY: Condition = { field: "source.gitHistory", op: "exists" };
const WEB_OR_API: Selector = { any: [kind("web"), kind("api")] };

const PASSIVE: Execution = {
  tier: "PASSIVE",
  target: "source_checkout",
  destructiveOperations: false,
};
const safeActive = (
  maxRequests: number,
  timeoutSeconds: number,
  target: Target = "registered_test_deployment",
): Execution => ({
  tier: "SAFE_ACTIVE",
  target,
  maxRequests,
  timeoutSeconds,
  destructiveOperations: false,
});
const isolated = (
  maxRequests: number,
  timeoutSeconds: number,
  opts: { target?: Target; mutatesOwnTestData?: boolean } = {},
): Execution => ({
  tier: "ISOLATED_ACTIVE",
  target: opts.target ?? "registered_test_deployment",
  maxRequests,
  timeoutSeconds,
  destructiveOperations: false,
  ...(opts.mutatesOwnTestData ? { mutatesOwnTestData: true } : {}),
});

const patch = (
  allowedPaths: string[],
  productionChange: Remediation["productionChange"] = "not_applicable",
  manualStepsKo?: string[],
): Remediation => ({
  autoPatch: "branch_only",
  allowedPaths,
  productionChange,
  ...(manualStepsKo ? { manualStepsKo } : {}),
});

const APP_PATHS = ["app/**", "src/**", "pages/**", "lib/**"];
const CONFIG_PATHS = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "middleware.ts",
  "src/middleware.ts",
  "vercel.json",
];
const DEPENDENCY_PATHS = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "uv.lock",
];
const SUPABASE_PATHS = ["supabase/migrations/**", "supabase/policies.sql"];
const FIREBASE_PATHS = [
  "firestore.rules",
  "storage.rules",
  "database.rules.json",
  "firebase.json",
];

const withMode = (mode: ScanMode, defs: RuleDef[]): SecurityRule[] =>
  defs.map((d) => ({ ...d, mode }));

// ═════════════════════════════════════════════════════════════════════════════
// 모드 A — 소스(zip)만으로 실행: 정적 분석 (PASSIVE)
// ═════════════════════════════════════════════════════════════════════════════

export const MODE_A_RULES: SecurityRule[] = withMode("A", [
  // ── 비밀정보 · 공급망 ────────────────────────────────────────────────────
  {
    id: "SEC-001",
    family: "SEC-001",
    version: "2.0.0",
    title: "Hardcoded secret exposure",
    titleKo: "비밀정보 하드코딩",
    summaryKo:
      "소스 코드·설정 파일·git 히스토리에 API 키, DB 비밀번호, 토큰이 들어 있는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(798, 540),
      capec(37, 191),
      owasp("A07:2025"),
      attack("T1552.001", "T1593.003"),
    ),
    appliesTo: ["web", "api", "baas"],
    selector: { all: [HAS_SOURCE] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-secrets", toolId: "secret_scanner", method: "SAST" },
      {
        // zip에 .git/이 포함된 경우: 지운 줄 알았던 키가 과거 커밋에 남아 있음
        id: "scan-secrets-git-history",
        toolId: "secret_scanner",
        method: "SAST",
        when: HAS_GIT_HISTORY,
        params: { includeGitHistory: true },
      },
    ],
    execution: PASSIVE,
    remediation: patch(
      [...APP_PATHS, ".gitignore", ".env.example"],
      "approval_required",
      [
        "노출된 키를 발급처(OpenAI, Supabase, Stripe 등)에서 즉시 폐기(revoke)하고 새 키를 발급하세요.",
        "새 키는 배포 플랫폼(Vercel 등)의 환경변수에만 저장하세요.",
        ".env, .env.local 등을 .gitignore에 추가하세요.",
        "git 히스토리에 남은 키는 히스토리 정리만으로는 불충분합니다. 반드시 폐기가 먼저입니다.",
      ],
    ),
    verificationRequiredChecks: ["scan-secrets", "changed-code-scan"],
  },

  {
    id: "SEC-002",
    family: "SEC-002",
    version: "1.0.0",
    title: "Secrets exposed to the client bundle",
    titleKo: "프론트엔드에 노출된 비밀키",
    summaryKo:
      "NEXT_PUBLIC_·VITE_ 등 공개 접두사 환경변수나 클라이언트 코드에 서버 전용 키(OpenAI 키, Supabase service_role 키 등)가 들어가 누구나 브라우저에서 볼 수 있는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(798, 200, 540),
      capec(37),
      owasp("A07:2025"),
      attack("T1552.001", "T1496.004"),
    ),
    appliesTo: ["web", "baas"],
    selector: { all: [kind("web")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      {
        id: "scan-public-env-prefix",
        toolId: "secret_scanner",
        method: "SAST",
        params: {
          publicPrefixes: ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "PUBLIC_"],
        },
      },
      {
        id: "scan-privileged-baas-key-in-client",
        toolId: "secret_scanner",
        method: "SAST",
        params: { patterns: ["supabase_service_role", "firebase_admin_sdk_json"] },
      },
      {
        // 빌드 산출물이 zip에 포함된 경우
        id: "scan-client-build-output",
        toolId: "secret_scanner",
        method: "SAST",
        params: { paths: [".next/static/**", "dist/**", "build/**", "out/**"] },
      },
    ],
    execution: PASSIVE,
    remediation: patch([...APP_PATHS, ".env.example"], "approval_required", [
      "노출된 키를 즉시 폐기하고 재발급하세요(브라우저로 이미 배포됐다면 유출된 것으로 간주).",
      "서버 전용 키는 공개 접두사 없이 선언하고, 서버(API Route/Server Action)에서만 사용하세요.",
      "외부 AI API는 반드시 자체 서버를 거쳐 호출하고, 그 서버 엔드포인트에 인증과 호출 제한을 거세요.",
    ]),
    verificationRequiredChecks: [
      "scan-public-env-prefix",
      "scan-privileged-baas-key-in-client",
      "changed-code-scan",
    ],
  },

  {
    id: "SEC-004",
    family: "SEC-004",
    version: "2.0.0",
    title: "Vulnerable dependencies",
    titleKo: "취약한 의존성",
    summaryKo:
      "사용 중인 라이브러리에 알려진 취약점(CVE)이 있는지 lockfile 기준으로 확인합니다.",
    severity: "high",
    standards: std(
      cwe(1395, 1104),
      capec(538),
      owasp("A03:2025"),
      attack("T1195.001"),
    ),
    appliesTo: ["web", "api", "baas"],
    selector: { all: [detected("dependency_manifest")] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [{ id: "sca-audit", toolId: "sca_scanner", method: "CONFIG" }],
    execution: PASSIVE,
    remediation: patch(DEPENDENCY_PATHS),
    verificationRequiredChecks: ["sca-audit"],
    coverageGap: {
      when: { field: "capabilities.lockfile", op: "not_equals", value: "detected" },
      messageKo:
        "lockfile(package-lock.json, pnpm-lock.yaml 등)이 없어 실제 설치 버전을 알 수 없습니다. package.json의 범위 기준으로만 추정했으니 lockfile을 포함해 다시 올려주세요.",
    },
  },

  {
    id: "SEC-005",
    family: "SEC-005",
    version: "1.0.0",
    title: "Hallucinated or typosquatted packages",
    titleKo: "AI 환각 패키지·타이포스쿼팅",
    summaryKo:
      "AI가 지어낸(실존하지 않거나 최근 선점된) 패키지, 유명 패키지와 이름이 비슷한 가짜 패키지, 설치 시 스크립트를 실행하는 패키지를 찾습니다.",
    severity: "high",
    standards: std(
      cwe(1357, 829),
      capec(538),
      owasp("A03:2025"),
      attack("T1195.001"),
    ),
    appliesTo: ["web", "api", "baas"],
    selector: { all: [detected("dependency_manifest")] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [
      // 레지스트리 조회는 스캐너 서비스가 수행(샌드박스 밖). SCN-004 참고
      { id: "registry-existence", toolId: "package_provenance_checker", method: "CONFIG" },
      { id: "typosquat-similarity", toolId: "package_provenance_checker", method: "CONFIG" },
      { id: "install-script-audit", toolId: "package_provenance_checker", method: "CONFIG" },
      {
        id: "package-age-popularity",
        toolId: "package_provenance_checker",
        method: "CONFIG",
        confidence: "tentative",
        params: { minAgeDays: 30, minWeeklyDownloads: 100 },
      },
    ],
    execution: PASSIVE,
    remediation: patch(DEPENDENCY_PATHS, "not_applicable", [
      "의심 패키지는 이름 철자와 공식 저장소(GitHub) 링크를 직접 확인하세요.",
      "이미 설치했다면 해당 환경의 키를 모두 교체하는 것을 권장합니다.",
    ]),
    verificationRequiredChecks: ["registry-existence", "typosquat-similarity"],
  },

  {
    id: "SEC-006",
    family: "SEC-006",
    version: "1.0.0",
    title: "Weak password storage",
    titleKo: "취약한 비밀번호 저장 방식",
    summaryKo:
      "직접 구현한 로그인에서 비밀번호를 평문·MD5·SHA-1 등으로 저장하는지 확인합니다(bcrypt·argon2·scrypt 권장).",
    severity: "high",
    standards: std(
      cwe(916, 328, 256),
      capec(55, 16),
      owasp("A04:2025"),
      attack("T1110.002"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [detected("custom_password_auth")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-password-hashing", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required", [
      "기존 사용자 비밀번호는 다음 로그인 시 새 해시로 재저장(rehash-on-login)하도록 마이그레이션하세요.",
    ]),
    verificationRequiredChecks: ["scan-password-hashing", "changed-code-scan"],
  },

  // ── 인젝션 · 입력 처리 ──────────────────────────────────────────────────
  {
    id: "WEB-003",
    family: "WEB-003",
    version: "2.0.0",
    title: "DOM/Stored Cross-Site Scripting (static signal)",
    titleKo: "XSS(교차 사이트 스크립팅)",
    summaryKo:
      "사용자 입력이 innerHTML, dangerouslySetInnerHTML, v-html 등으로 이스케이프 없이 화면에 들어가는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(79),
      capec(63, 588, 592),
      owasp("A05:2025"),
      attack("T1189", "T1059.007"),
    ),
    appliesTo: ["web"],
    selector: { all: [kind("web")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-xss-sinks", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["scan-xss-sinks", "changed-code-scan"],
  },

  {
    id: "WEB-004",
    family: "WEB-004",
    version: "2.0.0",
    title: "Injection (SQL / NoSQL / command / eval / deserialization) — static signal",
    titleKo: "인젝션(SQL·NoSQL·커맨드·eval·역직렬화)",
    summaryKo:
      "입력값이 SQL 문자열, NoSQL 쿼리 객체, 셸 명령, eval(), 안전하지 않은 역직렬화에 그대로 들어가는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(89, 943, 78, 95, 502),
      capec(66, 676, 88, 242, 586),
      owasp("A05:2025"),
      attack("T1190", "T1059"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-sql-injection", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-nosql-injection", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-command-injection", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-code-eval", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-unsafe-deserialization", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: [
      "scan-sql-injection",
      "scan-nosql-injection",
      "scan-command-injection",
      "scan-code-eval",
      "scan-unsafe-deserialization",
      "changed-code-scan",
    ],
  },

  {
    id: "WEB-006",
    family: "WEB-006",
    version: "1.1.0",
    title: "Path traversal via unsanitized file access (static signal)",
    titleKo: "경로 트래버설(디렉터리 접근 우회)",
    summaryKo:
      "파일 경로에 사용자 입력이 들어가 ../ 등으로 의도하지 않은 파일을 읽거나 쓸 수 있는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(22, 23),
      capec(126, 139),
      owasp("A01:2025"),
      attack("T1190", "T1005"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-path-traversal", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["scan-path-traversal", "changed-code-scan"],
  },

  {
    id: "WEB-017",
    family: "WEB-017",
    version: "1.0.0",
    title: "Server-Side Request Forgery (static signal)",
    titleKo: "SSRF(서버 측 요청 위조)",
    summaryKo:
      "사용자가 준 URL을 서버가 그대로 요청하는 기능(링크 미리보기, 이미지 프록시, URL 요약 등)에 허용 목록이 없는지, next/image remotePatterns가 전체 허용인지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(918),
      capec(664),
      owasp("A01:2025"),
      attack("T1190", "T1552.005"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-user-controlled-fetch", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-image-remote-patterns", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "approval_required"),
    verificationRequiredChecks: [
      "scan-user-controlled-fetch",
      "scan-image-remote-patterns",
      "changed-code-scan",
    ],
  },

  {
    id: "WEB-020",
    family: "WEB-020",
    version: "1.0.0",
    title: "Unrestricted file upload (static signal)",
    titleKo: "파일 업로드 검증 미흡",
    summaryKo:
      "업로드 파일의 확장자·MIME·크기를 검증하지 않거나, public 폴더에 저장하거나, HTML/SVG를 그대로 서빙하는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(434, 400),
      capec(650, 17),
      owasp("A06:2025"),
      attack("T1505.003", "T1190"),
    ),
    appliesTo: ["web", "api", "baas"],
    selector: { all: [detected("file_upload")] },
    // 능동 업로드 테스트는 대상에 파일을 남기므로 정적 점검만 수행
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-upload-validation", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["scan-upload-validation", "changed-code-scan"],
  },

  {
    id: "WEB-023",
    family: "WEB-023",
    version: "1.0.0",
    title: "Verbose error disclosure (static signal)",
    titleKo: "에러 메시지·스택 트레이스 노출",
    summaryKo:
      "API가 에러 발생 시 error.stack, DB 에러 원문, 내부 경로를 응답으로 그대로 돌려주는지 확인합니다.",
    severity: "low",
    standards: std(cwe(209, 215), capec(54, 215), owasp("A10:2025")),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-error-leak", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["scan-error-leak", "changed-code-scan"],
  },

  // ── 인가 · 인증 · 세션 ─────────────────────────────────────────────────
  {
    id: "WEB-014",
    family: "WEB-014",
    version: "1.1.0",
    title: "Broken object-level authorization / IDOR (static signal)",
    titleKo: "IDOR(객체 수준 권한 확인 누락)",
    summaryKo:
      "/api/orders/:id처럼 ID로 데이터를 조회·수정할 때 \"요청자 본인의 데이터인지\" 확인하는 코드가 빠졌는지 확인합니다. (실제 재현은 모드 C의 WEB-002)",
    severity: "critical",
    standards: std(
      cwe(639, 862),
      capec(1, 122),
      apiTop10("API1:2023"),
      owasp("A01:2025"),
      attack("T1190"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-idor-static", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["scan-idor-static", "changed-code-scan"],
  },

  {
    id: "WEB-005",
    family: "WEB-005",
    version: "2.0.0",
    title: "Excessive data exposure in API responses (static signal)",
    titleKo: "민감정보 응답 과다 노출",
    summaryKo:
      "API가 DB 레코드를 통째로 반환해 비밀번호 해시, 이메일, 내부 필드 등 화면에 필요 없는 값까지 내보내는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(213, 200, 359),
      capec(116), // MITRE CAPEC v3.9: Meta 패턴 Excavation(상세 오류·과다 응답을 통한 정보 수집)
      apiTop10("API3:2023"),
      owasp("A01:2025"),
      attack("T1213"),
    ),
    appliesTo: ["api", "web"],
    selector: { all: [kind("api")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-response-fields", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["scan-response-fields", "changed-code-scan"],
  },

  {
    // API3:2023의 나머지 절반(Mass Assignment). 능동 재현은 WEB-016-C
    id: "WEB-016",
    family: "WEB-016",
    version: "1.0.0",
    title: "Mass assignment (static signal)",
    titleKo: "대량 할당(Mass Assignment)",
    summaryKo:
      "요청 body를 그대로 DB update/create에 넣어 사용자가 role, is_admin, plan, credits 같은 필드를 임의로 바꿀 수 있는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(915),
      capec(77),
      apiTop10("API3:2023"),
      owasp("A08:2025"),
      attack("T1190"),
    ),
    appliesTo: ["api", "web", "baas"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-mass-assignment", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["scan-mass-assignment", "changed-code-scan"],
  },

  {
    id: "WEB-019",
    family: "WEB-019",
    version: "1.0.0",
    title: "Insecure JWT handling (static signal)",
    titleKo: "JWT 검증 결함",
    summaryKo:
      "JWT를 decode만 하고 서명을 검증하지 않거나, 허용 알고리즘을 지정하지 않거나, 만료를 무시하거나, 약한 시크릿을 쓰는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(347, 345, 613, 922),
      capec(196, 473),
      owasp("A07:2025"),
      attack("T1606"),
    ),
    appliesTo: ["api", "web"],
    selector: { all: [detected("jwt_auth")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-jwt-decode-without-verify", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-jwt-algorithm-pinning", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-jwt-expiry-ignored", toolId: "static_web_analyzer", method: "SAST" },
      {
        id: "scan-token-in-localstorage",
        toolId: "static_web_analyzer",
        method: "SAST",
        confidence: "tentative",
      },
    ],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: [
      "scan-jwt-decode-without-verify",
      "scan-jwt-algorithm-pinning",
      "scan-jwt-expiry-ignored",
      "changed-code-scan",
    ],
  },

  {
    id: "WEB-021",
    family: "WEB-021",
    version: "1.0.0",
    title: "Cross-Site Request Forgery (static signal)",
    titleKo: "CSRF(교차 사이트 요청 위조)",
    summaryKo:
      "쿠키로 인증하는 앱에서 GET 요청으로 데이터를 변경하거나, 상태 변경 요청에 CSRF 토큰·Origin 검증이 없는지 확인합니다.",
    severity: "medium",
    standards: std(cwe(352), capec(62), owasp("A01:2025")),
    appliesTo: ["web", "api"],
    selector: { all: [detected("cookie_auth")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-state-changing-get", toolId: "static_web_analyzer", method: "SAST" },
      // Next.js Server Actions처럼 프레임워크가 Origin 검사를 내장한 경로는 제외
      { id: "scan-missing-csrf-defense", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS]),
    verificationRequiredChecks: [
      "scan-state-changing-get",
      "scan-missing-csrf-defense",
      "changed-code-scan",
    ],
  },

  {
    id: "WEB-022",
    family: "WEB-022",
    version: "1.0.0",
    title: "Open redirect (static signal)",
    titleKo: "오픈 리다이렉트",
    summaryKo:
      "?next=, ?redirect= 같은 파라미터 값으로 허용 목록 없이 리다이렉트해 피싱에 악용될 수 있는지 확인합니다(로그인·OAuth 콜백 포함).",
    severity: "medium",
    standards: std(
      cwe(601),
      capec(178), // MITRE CAPEC v3.9: Cross-Site Flashing의 CWE-601 연계에 따른 간접·기술 특화 매핑
      owasp("A01:2025"),
      attack("T1566.002"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [{ id: "scan-open-redirect", toolId: "static_web_analyzer", method: "SAST" }],
    execution: PASSIVE,
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS]),
    verificationRequiredChecks: ["scan-open-redirect", "changed-code-scan"],
  },

  {
    id: "WEB-018",
    family: "WEB-018",
    version: "1.0.0",
    title: "Unverified webhook signatures",
    titleKo: "결제·웹훅 서명 미검증",
    summaryKo:
      "Stripe·토스페이먼츠 등 웹훅을 받을 때 서명을 검증하지 않아, 누구나 가짜 \"결제 완료\" 이벤트를 보내 유료 기능을 열 수 있는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(345, 347, 294),
      capec(473, 151),
      owasp("A08:2025"),
      attack("T1190"),
    ),
    appliesTo: ["api", "web"],
    selector: { all: [detected("webhook_receiver")] },
    // 능동 점검 제외: 가짜 결제 이벤트는 실제 비즈니스 상태를 바꾸므로 비파괴 원칙에 위배
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-webhook-signature", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-webhook-raw-body", toolId: "static_web_analyzer", method: "SAST" },
      {
        id: "scan-webhook-replay-window",
        toolId: "static_web_analyzer",
        method: "SAST",
        confidence: "tentative",
      },
    ],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "approval_required", [
      "결제 상태는 웹훅 내용만 믿지 말고 결제사 API로 한 번 더 조회해 확정하세요.",
    ]),
    verificationRequiredChecks: [
      "scan-webhook-signature",
      "scan-webhook-raw-body",
      "changed-code-scan",
    ],
  },

  // ── 설정 · 헤더 (정적) ─────────────────────────────────────────────────
  {
    // URL이 있으면 WEB-007(모드 B)이 실제 응답으로 확정한다
    id: "WEB-007-A",
    family: "WEB-007",
    version: "1.0.0",
    title: "CORS and security headers (static config)",
    titleKo: "CORS·보안 헤더(설정 파일)",
    summaryKo:
      "설정 파일에서 CORS 전체 허용(*), 자격증명 포함 CORS, CSP·HSTS·X-Frame-Options 누락을 확인합니다.",
    severity: "medium",
    standards: std(
      cwe(942, 693, 1021),
      capec(103, 111),
      owasp("A02:2025"),
      attack("T1185"),
    ),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [
      {
        id: "static-header-config",
        toolId: "http_config_scanner",
        method: "CONFIG",
        params: { mode: "static" },
      },
      {
        id: "static-cors-config",
        toolId: "http_config_scanner",
        method: "CONFIG",
        params: { mode: "static" },
      },
    ],
    execution: PASSIVE,
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS]),
    verificationRequiredChecks: ["static-header-config", "static-cors-config"],
  },

  {
    // URL이 있으면 WEB-008(모드 B)이 실제 접근 가능 여부를 확정한다
    id: "WEB-008-A",
    family: "WEB-008",
    version: "1.0.0",
    title: "Debug mode and unauthenticated admin routes (static)",
    titleKo: "디버그 설정·무인증 관리자 라우트(정적)",
    summaryKo:
      "운영 설정에 디버그 모드가 켜져 있는지, 인증 미들웨어 없이 열려 있는 /admin 계열 라우트가 있는지, public 폴더에 .env 등 민감 파일이 있는지 확인합니다.",
    severity: "high",
    standards: std(cwe(489, 306, 540), capec(121, 36), owasp("A02:2025")),
    appliesTo: ["web", "api"],
    selector: WEB_OR_API,
    methods: ["SAST", "CONFIG"],
    prerequisites: { SAST: ["source_checkout"], CONFIG: ["source_checkout"] },
    checks: [
      { id: "scan-debug-flags", toolId: "http_config_scanner", method: "CONFIG" },
      { id: "scan-unauth-admin-routes", toolId: "route_inventory", method: "SAST" },
      {
        id: "scan-sensitive-public-files",
        toolId: "secret_scanner",
        method: "SAST",
        params: { paths: ["public/**", "static/**"] },
      },
    ],
    execution: PASSIVE,
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS], "approval_required"),
    verificationRequiredChecks: [
      "scan-debug-flags",
      "scan-unauth-admin-routes",
      "scan-sensitive-public-files",
    ],
  },

  // ── 비용 · 남용 ───────────────────────────────────────────────────────
  {
    id: "WEB-015",
    family: "WEB-015",
    version: "1.0.0",
    title: "Unrestricted consumption of costly operations (static signal)",
    titleKo: "비용 유발 기능 무제한 호출",
    summaryKo:
      "AI 호출, 이메일·SMS 발송, 이미지 생성 등 돈이 드는 엔드포인트에 인증이나 호출 횟수 제한(rate limit)이 없는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(770, 799, 400),
      capec(125, 130),
      apiTop10("API4:2023", "API6:2023"),
      attack("T1496.003", "T1496.004", "T1499.003"),
    ),
    appliesTo: ["api", "web"],
    selector: { any: [detected("llm_usage"), detected("outbound_messaging")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-costly-route-auth", toolId: "route_inventory", method: "SAST" },
      { id: "scan-costly-route-rate-limit", toolId: "static_web_analyzer", method: "SAST" },
      { id: "scan-llm-max-tokens", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "not_applicable", [
      "AI·SMS 제공사 콘솔에서 월 사용 한도(hard limit)와 알림을 설정하세요.",
    ]),
    verificationRequiredChecks: [
      "scan-costly-route-auth",
      "scan-costly-route-rate-limit",
      "changed-code-scan",
    ],
  },

  {
    // 프롬프트 인젝션은 CAPEC에 직접 대응 패턴이 없어 MITRE ATLAS로 보완.
    // CAPEC-242는 "LLM 출력이 코드/쿼리로 실행되는 경우"에 대한 매핑.
    id: "LLM-001",
    family: "LLM-001",
    version: "1.0.0",
    title: "LLM integration security (static signal)",
    titleKo: "AI(LLM) 기능 보안",
    summaryKo:
      "시스템 프롬프트에 비밀정보가 들어 있는지, 사용자 입력이나 LLM 출력이 검증 없이 DB 쿼리·셸·eval·HTML 렌더링·도구 호출로 이어지는지, 응답 토큰 상한이 있는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(1427, 1426, 200, 79),
      capec(242),
      llmTop10("LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM07:2025", "LLM10:2025"),
      atlas("AML.T0051", "AML.T0056"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [detected("llm_usage")] },
    methods: ["SAST"],
    prerequisites: { SAST: ["source_checkout"] },
    checks: [
      { id: "scan-secret-in-system-prompt", toolId: "llm_integration_analyzer", method: "SAST" },
      { id: "scan-llm-output-to-sink", toolId: "llm_integration_analyzer", method: "SAST" },
      { id: "scan-llm-tool-permissions", toolId: "llm_integration_analyzer", method: "SAST" },
      { id: "scan-llm-output-rendered-html", toolId: "llm_integration_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch(APP_PATHS, "not_applicable", [
      "시스템 프롬프트는 유출될 수 있다고 가정하고 비밀정보를 넣지 마세요.",
      "LLM이 호출할 수 있는 도구는 최소 권한으로 제한하고, 쓰기 작업은 사용자 확인을 거치게 하세요.",
    ]),
    verificationRequiredChecks: [
      "scan-secret-in-system-prompt",
      "scan-llm-output-to-sink",
      "changed-code-scan",
    ],
  },

  // ── BaaS (Supabase · Firebase) ────────────────────────────────────────
  {
    id: "BAAS-001",
    family: "BAAS-001",
    version: "2.0.0",
    title: "Supabase Row Level Security (static policy)",
    titleKo: "Supabase RLS(행 수준 보안) 정책",
    summaryKo:
      "Supabase 테이블에 RLS가 꺼져 있거나, 정책이 USING (true)처럼 전부 허용인지 마이그레이션 파일로 확인합니다. 대시보드에서 만든 테이블은 파일에 없을 수 있어 모드 B/C 점검을 권장합니다.",
    severity: "high",
    standards: std(
      cwe(284, 862, 639),
      capec(1, 122),
      owasp("A01:2025"),
      attack("T1530"),
    ),
    appliesTo: ["baas"],
    selector: { all: [kind("baas"), provider("supabase")] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [
      { id: "rls-policy-read", toolId: "baas_policy_scanner", method: "CONFIG" },
      { id: "rls-permissive-policy", toolId: "baas_policy_scanner", method: "CONFIG" },
      {
        // 코드에서 쓰는 테이블이 마이그레이션에 없음 → 정책 판단 불가
        id: "rls-untracked-tables",
        toolId: "baas_policy_scanner",
        method: "CONFIG",
        confidence: "tentative",
      },
    ],
    execution: PASSIVE,
    remediation: patch(SUPABASE_PATHS, "approval_required"),
    verificationRequiredChecks: ["rls-policy-read", "rls-permissive-policy"],
  },

  {
    id: "BAAS-002",
    family: "BAAS-002",
    version: "1.0.0",
    title: "Firebase security rules (static)",
    titleKo: "Firebase 보안 규칙",
    summaryKo:
      "Firestore·Realtime DB·Storage 규칙이 allow read, write: if true 이거나, 테스트 모드 규칙(request.time < 기한)이 그대로 남아 있는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(284, 862, 732),
      capec(1, 122),
      owasp("A01:2025"),
      attack("T1530"),
    ),
    appliesTo: ["baas"],
    selector: { all: [kind("baas"), provider("firebase")] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["source_checkout"] },
    checks: [
      { id: "firebase-rules-open", toolId: "baas_policy_scanner", method: "CONFIG" },
      { id: "firebase-test-mode-rules", toolId: "baas_policy_scanner", method: "CONFIG" },
      { id: "firebase-auth-only-rules", toolId: "baas_policy_scanner", method: "CONFIG" }, // "로그인만 하면 전부 허용"
    ],
    execution: PASSIVE,
    remediation: patch(FIREBASE_PATHS, "approval_required"),
    verificationRequiredChecks: ["firebase-rules-open", "firebase-test-mode-rules"],
    coverageGap: {
      when: { field: "capabilities.firebase_rules_file", op: "not_equals", value: "detected" },
      messageKo:
        "Firebase 규칙 파일이 없어 콘솔에만 규칙이 있는 것으로 보입니다. 모드 B로 실제 접근 가능 여부를 확인하세요.",
    },
  },

  {
    id: "BAAS-003",
    family: "BAAS-003",
    version: "1.0.0",
    title: "Public storage buckets (static)",
    titleKo: "스토리지 버킷 공개 설정",
    summaryKo:
      "Supabase Storage 버킷이 public이거나 익명 목록 조회를 허용하는지, S3 등에 public-read ACL을 쓰는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(552, 284),
      capec(127, 1),
      owasp("A01:2025"),
      attack("T1530", "T1619"),
    ),
    appliesTo: ["baas", "web"],
    selector: { any: [kind("baas"), detected("object_storage")] },
    methods: ["CONFIG", "SAST"],
    prerequisites: { CONFIG: ["source_checkout"], SAST: ["source_checkout"] },
    checks: [
      { id: "bucket-public-flag", toolId: "baas_policy_scanner", method: "CONFIG" },
      { id: "bucket-anon-list-policy", toolId: "baas_policy_scanner", method: "CONFIG" },
      { id: "object-acl-public-read", toolId: "static_web_analyzer", method: "SAST" },
    ],
    execution: PASSIVE,
    remediation: patch([...SUPABASE_PATHS, ...FIREBASE_PATHS, ...APP_PATHS], "approval_required"),
    verificationRequiredChecks: ["bucket-public-flag", "bucket-anon-list-policy"],
  },
]);

// ═════════════════════════════════════════════════════════════════════════════
// 모드 B — 소유권 검증된 배포 URL 필요: 비파괴 능동 점검 (SAFE_ACTIVE)
//   요청 수·메서드·속도 상한은 스캐너가 서버 측에서 강제한다(SCN-005).
// ═════════════════════════════════════════════════════════════════════════════

export const MODE_B_RULES: SecurityRule[] = withMode("B", [
  {
    id: "SEC-002-B",
    family: "SEC-002",
    version: "1.0.0",
    title: "Secrets in deployed JavaScript bundles",
    titleKo: "배포된 JS 번들 내 비밀키",
    summaryKo:
      "실제 배포된 페이지의 JavaScript 파일을 내려받아 서버 전용 키가 들어 있는지 확인합니다. 발견한 Supabase/Firebase 공개 설정은 BaaS 점검에 사용합니다.",
    severity: "critical",
    standards: std(
      cwe(798, 200, 540),
      capec(37),
      owasp("A07:2025"),
      attack("T1552.001", "T1496.004"),
    ),
    appliesTo: ["web", "baas"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "fetch-and-scan-bundles",
        toolId: "bundle_secret_scanner",
        method: "CONFIG",
        params: { sameOriginOnly: true, maxBundles: 30 },
      },
      { id: "extract-baas-public-config", toolId: "bundle_secret_scanner", method: "CONFIG" },
    ],
    execution: safeActive(40, 90),
    remediation: patch([...APP_PATHS, ".env.example"], "approval_required", [
      "번들에서 발견된 키는 이미 공개된 것이므로 즉시 폐기·재발급하세요.",
    ]),
    verificationRequiredChecks: ["fetch-and-scan-bundles"],
    produces: ["linked_baas_project"],
  },

  {
    id: "WEB-001",
    family: "WEB-001",
    version: "2.0.0",
    title: "Unauthenticated access to protected API",
    titleKo: "보호된 API의 무인증 접근",
    summaryKo:
      "로그인이 필요한 API를 로그인 없이 호출했을 때 거부(401/403)되는지 확인합니다. 소스가 있으면 라우트 목록을, 없으면 크롤링 결과를 사용합니다.",
    severity: "high",
    standards: std(
      cwe(306, 862),
      capec(115, 36),
      apiTop10("API2:2023"),
      owasp("A01:2025", "A07:2025"),
      attack("T1190"),
    ),
    appliesTo: ["api", "web"],
    selector: { all: [HAS_ORIGIN, detected("authentication")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "anonymous-access",
        toolId: "anonymous_request_probe",
        method: "TEST",
        actor: "anonymous",
        expected: "denied",
        params: { routeSource: "source_inventory_or_crawl", methods: ["GET", "HEAD"] },
      },
    ],
    execution: safeActive(15, 60),
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "approval_required"),
    verificationRequiredChecks: ["anonymous-access", "existing-functional-tests"],
  },

  {
    id: "WEB-007",
    family: "WEB-007",
    version: "2.0.0",
    title: "CORS and security headers",
    titleKo: "CORS·보안 헤더",
    summaryKo:
      "실제 응답 헤더에서 CSP, HSTS, X-Frame-Options, X-Content-Type-Options 설정과, 임의 Origin을 허용하는 CORS 응답이 있는지 확인합니다.",
    severity: "medium",
    standards: std(
      cwe(942, 693, 1021),
      capec(103, 111),
      owasp("A02:2025"),
      attack("T1185"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      { id: "http-headers", toolId: "http_config_scanner", method: "CONFIG" },
      {
        id: "cors-origin-reflection",
        toolId: "http_config_scanner",
        method: "CONFIG",
        expected: "denied",
        params: { probeOrigin: "https://cors-canary.invalid" },
      },
    ],
    execution: safeActive(6, 30),
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS]),
    verificationRequiredChecks: ["http-headers", "cors-origin-reflection"],
  },

  {
    id: "WEB-008",
    family: "WEB-008",
    version: "2.0.0",
    title: "Exposed administrative or debug endpoints",
    titleKo: "노출된 관리자·디버그 경로",
    summaryKo:
      "/admin, /debug, /.env, /.git/HEAD 같은 경로가 로그인 없이 외부에서 열리는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(489, 538, 306, 425),
      capec(121, 87),
      owasp("A02:2025"),
      attack("T1595.003"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-exposed-paths",
        toolId: "exposed_path_probe",
        method: "CONFIG",
        expected: "denied",
        params: {
          methods: ["GET", "HEAD"],
          paths: [
            "/admin",
            "/api/admin",
            "/dashboard/admin",
            "/debug",
            "/_debug",
            "/.env",
            "/.env.local",
            "/.git/HEAD",
            "/api/graphql",
          ],
        },
      },
    ],
    execution: safeActive(15, 30),
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS], "approval_required"),
    verificationRequiredChecks: ["probe-exposed-paths"],
  },

  {
    // P2 중 유일하게 반영한 항목
    id: "WEB-025",
    family: "WEB-025",
    version: "1.0.0",
    title: "Admin paths disclosed via robots.txt / sitemap.xml",
    titleKo: "robots.txt·sitemap을 통한 관리자 경로 노출",
    summaryKo:
      "robots.txt나 sitemap.xml에 관리자·내부 경로가 적혀 있어 공격자에게 위치를 알려주는지, 그 경로가 실제로 로그인 없이 열리는지 확인합니다.",
    severity: "low", // 해당 경로가 무인증 접근 가능하면 결과를 high로 상향
    standards: std(
      cwe(200, 425),
      capec(169, 87),
      owasp("A02:2025"),
      attack("T1594", "T1595.003"),
    ),
    appliesTo: ["web"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      {
        id: "robots-sitemap-admin-paths",
        toolId: "exposed_path_probe",
        method: "CONFIG",
        params: { sources: ["/robots.txt", "/sitemap.xml"], keywords: ["admin", "internal", "manage", "dashboard", "staff", "debug"] },
      },
      {
        id: "disclosed-path-access",
        toolId: "exposed_path_probe",
        method: "CONFIG",
        expected: "denied",
        params: { methods: ["HEAD", "GET"], maxPaths: 8 },
      },
    ],
    execution: safeActive(10, 30),
    remediation: patch(["public/robots.txt", "app/robots.ts", "app/sitemap.ts", ...CONFIG_PATHS]),
    verificationRequiredChecks: ["robots-sitemap-admin-paths", "disclosed-path-access"],
  },

  {
    id: "WEB-009",
    family: "WEB-009",
    version: "2.0.0",
    title: "Plaintext HTTP allowed / TLS not enforced",
    titleKo: "평문 HTTP 허용·HTTPS 미강제",
    summaryKo:
      "http:// 로 접속했을 때 https로 강제 전환되는지, 로그인 폼이 평문으로 전송되지 않는지 확인합니다.",
    severity: "medium",
    // v1의 A05(Misconfiguration) → 암호화 실패(A04:2025)로 정정
    standards: std(
      cwe(319, 523),
      capec(94, 157),
      owasp("A04:2025"),
      attack("T1557", "T1040"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [{ id: "probe-tls", toolId: "tls_probe", method: "CONFIG", expected: "denied" }],
    execution: safeActive(4, 20),
    remediation: patch(CONFIG_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-tls"],
  },

  {
    id: "WEB-010",
    family: "WEB-010",
    version: "2.0.0",
    title: "Username enumeration via auth responses",
    titleKo: "사용자 계정 존재 여부 노출",
    summaryKo:
      "로그인·회원가입·비밀번호 찾기에서 \"없는 계정\"과 \"틀린 비밀번호\"의 응답(메시지·상태코드·응답시간)이 달라 가입 여부를 알아낼 수 있는지 확인합니다.",
    severity: "medium",
    standards: std(cwe(204, 203), capec(575), owasp("A07:2025"), attack("T1589.002")),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN, detected("authentication")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-user-enumeration",
        toolId: "auth_probe",
        method: "TEST",
        expected: "denied",
        params: { flows: ["login", "signup", "password_reset"] },
      },
    ],
    execution: safeActive(6, 30),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-user-enumeration"],
  },

  {
    id: "WEB-011",
    family: "WEB-011",
    version: "2.0.0",
    title: "Missing brute-force protection on login",
    titleKo: "로그인 무차별 대입 방어 부재",
    summaryKo:
      "존재하지 않는 계정으로 로그인을 연속 실패했을 때 차단(429·잠금·CAPTCHA)이 걸리는지 확인합니다. 요청 수가 적어 차단 기준이 더 높으면 탐지하지 못할 수 있어 '경고'로 보고합니다.",
    severity: "medium",
    standards: std(
      cwe(307),
      capec(49, 16, 565, 600),
      owasp("A07:2025"),
      attack("T1110.001", "T1110.003", "T1110.004"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN, detected("authentication")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-bruteforce",
        toolId: "bruteforce_probe",
        method: "TEST",
        expected: "denied",
        confidence: "tentative", // 8회 내 차단 없음 = "방어 없음 의심"
        params: { account: "nonexistent_random" }, // 실제 계정 잠금 방지
      },
    ],
    execution: safeActive(8, 40),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-bruteforce"],
  },

  {
    id: "WEB-012",
    family: "WEB-012",
    version: "1.1.0",
    title: "Insecure session cookie attributes",
    titleKo: "세션 쿠키 속성 미흡",
    summaryKo:
      "세션 쿠키에 Secure(HTTPS 전용), HttpOnly(스크립트 접근 차단), SameSite 속성이 설정되어 있는지 확인합니다.",
    severity: "medium",
    standards: std(
      cwe(614, 1004, 1275),
      capec(31, 102),
      owasp("A02:2025"),
      attack("T1539"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["CONFIG"],
    prerequisites: { CONFIG: ["authorized_test_deployment"] },
    checks: [
      { id: "probe-cookie-flags", toolId: "cookie_probe", method: "CONFIG", expected: "denied" },
    ],
    execution: safeActive(2, 20),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-cookie-flags"],
  },

  {
    id: "WEB-015-B",
    family: "WEB-015",
    version: "1.0.0",
    title: "Anonymous reachability of costly endpoints",
    titleKo: "비용 유발 엔드포인트 무인증 접근",
    summaryKo:
      "AI·SMS·이메일 엔드포인트에 형식이 틀린 요청을 보내 인증 단계에서 막히는지(401) 아니면 통과하는지(400) 확인합니다. 실제 AI 호출이나 문자 발송은 일어나지 않습니다.",
    severity: "high",
    standards: std(
      cwe(770, 306),
      capec(125),
      apiTop10("API4:2023", "API6:2023"),
      attack("T1496.003", "T1496.004"),
    ),
    appliesTo: ["api", "web"],
    selector: {
      all: [HAS_ORIGIN, { any: [detected("llm_usage"), detected("outbound_messaging")] }],
    },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "costly-endpoint-anon-reachability",
        toolId: "anonymous_request_probe",
        method: "TEST",
        actor: "anonymous",
        expected: "denied",
        params: { payload: "schema_invalid_only" },
      },
      {
        id: "costly-endpoint-rate-limit-headers",
        toolId: "anonymous_request_probe",
        method: "TEST",
        confidence: "tentative",
      },
    ],
    execution: safeActive(10, 30),
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS]),
    verificationRequiredChecks: ["costly-endpoint-anon-reachability"],
  },

  {
    id: "WEB-022-B",
    family: "WEB-022",
    version: "1.0.0",
    title: "Open redirect (active probe)",
    titleKo: "오픈 리다이렉트(실제 확인)",
    summaryKo:
      "리다이렉트 파라미터에 외부 도메인을 넣었을 때 실제로 그 도메인으로 이동시키는지 확인합니다(이동은 따라가지 않고 Location 헤더만 확인).",
    severity: "medium",
    standards: std(
      cwe(601),
      capec(178), // MITRE CAPEC v3.9: Cross-Site Flashing의 CWE-601 연계에 따른 간접·기술 특화 매핑
      owasp("A01:2025"),
      attack("T1566.002"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-open-redirect",
        toolId: "redirect_probe",
        method: "TEST",
        expected: "denied",
        params: {
          canaryHost: "open-redirect.canary.invalid",
          params: ["next", "redirect", "redirect_to", "returnTo", "callbackUrl", "url"],
          followRedirects: false,
        },
      },
    ],
    execution: safeActive(12, 30),
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS]),
    verificationRequiredChecks: ["probe-open-redirect"],
  },

  {
    id: "WEB-023-B",
    family: "WEB-023",
    version: "1.0.0",
    title: "Verbose error disclosure (active probe)",
    titleKo: "에러 메시지 노출(실제 확인)",
    summaryKo:
      "API에 깨진 JSON이나 잘못된 타입을 보내 응답에 스택 트레이스, DB 에러, 서버 경로가 나오는지 확인합니다.",
    severity: "low",
    standards: std(cwe(209, 215), capec(54, 215), owasp("A10:2025")),
    appliesTo: ["api", "web"],
    selector: { all: [HAS_ORIGIN] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-error-leak",
        toolId: "error_probe",
        method: "TEST",
        expected: "denied",
        params: { payloads: ["malformed_json", "type_mismatch"] },
      },
    ],
    execution: safeActive(8, 30),
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["probe-error-leak"],
  },

  {
    id: "LLM-001-B",
    family: "LLM-001",
    version: "1.0.0",
    title: "System prompt leakage (active probe)",
    titleKo: "AI 시스템 프롬프트 유출(실제 확인)",
    summaryKo:
      "공개된 AI 채팅 엔드포인트에 정해진 추출 문장 3개를 보내 시스템 프롬프트나 내부 지시가 응답에 나오는지 확인합니다(사용자 AI 토큰이 소량 사용됨).",
    severity: "medium",
    // CAPEC 대응 패턴 없음 → CWE + OWASP LLM + MITRE ATLAS로 근거
    standards: std(
      cwe(1427, 200),
      llmTop10("LLM07:2025", "LLM01:2025"),
      atlas("AML.T0056", "AML.T0051.000"),
    ),
    appliesTo: ["web", "api"],
    selector: { all: [HAS_ORIGIN, detected("llm_usage")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment"] },
    checks: [
      {
        id: "probe-system-prompt-leak",
        toolId: "llm_prompt_probe",
        method: "TEST",
        expected: "denied",
        confidence: "tentative",
        params: { promptSet: "system_prompt_extraction_v1", maxPrompts: 3 },
      },
    ],
    execution: safeActive(3, 60),
    remediation: patch(APP_PATHS),
    verificationRequiredChecks: ["probe-system-prompt-leak"],
  },

  // ── BaaS 실제 접근 확인 (anon 키만 사용) ─────────────────────────────
  {
    id: "BAAS-001-B",
    family: "BAAS-001",
    version: "1.0.0",
    title: "Supabase anonymous table read (active probe)",
    titleKo: "Supabase 익명 테이블 조회(실제 확인)",
    summaryKo:
      "배포된 앱에 들어 있는 공개(anon) 키로 각 테이블을 1행씩 조회해, 로그인 없이 데이터가 나오는지 확인합니다. service_role 키는 발견되더라도 절대 사용하지 않습니다.",
    severity: "critical",
    standards: std(
      cwe(284, 862),
      capec(1, 122),
      owasp("A01:2025"),
      attack("T1530"),
    ),
    appliesTo: ["baas"],
    selector: { all: [HAS_ORIGIN, provider("supabase")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment", "linked_baas_project"] },
    checks: [
      { id: "supabase-list-exposed-tables", toolId: "baas_access_probe", method: "TEST" },
      {
        id: "supabase-anon-select",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "anonymous",
        operation: "read",
        expected: "denied",
        params: { limitRows: 1, redactValues: true, keyRole: "anon_only" },
      },
    ],
    execution: safeActive(30, 60, "linked_baas_project"),
    remediation: patch(SUPABASE_PATHS, "approval_required"),
    verificationRequiredChecks: ["supabase-anon-select"],
  },

  {
    id: "BAAS-002-B",
    family: "BAAS-002",
    version: "1.0.0",
    title: "Firebase anonymous read (active probe)",
    titleKo: "Firebase 익명 조회(실제 확인)",
    summaryKo:
      "로그인 없이 Realtime DB(/.json)나 앱에서 쓰는 Firestore 컬렉션을 읽을 수 있는지 확인합니다.",
    severity: "critical",
    standards: std(cwe(284, 862), capec(1, 122), owasp("A01:2025"), attack("T1530")),
    appliesTo: ["baas"],
    selector: { all: [HAS_ORIGIN, provider("firebase")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment", "linked_baas_project"] },
    checks: [
      {
        id: "firebase-anon-read",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "anonymous",
        operation: "read",
        expected: "denied",
        params: { rtdbShallow: true, limitDocs: 1, redactValues: true },
      },
    ],
    execution: safeActive(15, 60, "linked_baas_project"),
    remediation: patch(FIREBASE_PATHS, "approval_required"),
    verificationRequiredChecks: ["firebase-anon-read"],
  },

  {
    id: "BAAS-003-B",
    family: "BAAS-003",
    version: "1.0.0",
    title: "Anonymous storage bucket listing (active probe)",
    titleKo: "스토리지 버킷 익명 목록 조회(실제 확인)",
    summaryKo:
      "로그인 없이 스토리지 버킷의 파일 목록을 볼 수 있는지 확인합니다(파일 내용은 내려받지 않음).",
    severity: "high",
    standards: std(
      cwe(552, 284),
      capec(127, 1),
      owasp("A01:2025"),
      attack("T1619", "T1530"),
    ),
    appliesTo: ["baas"],
    selector: { all: [HAS_ORIGIN, kind("baas")] },
    methods: ["TEST"],
    prerequisites: { TEST: ["authorized_test_deployment", "linked_baas_project"] },
    checks: [
      {
        id: "storage-anon-list",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "anonymous",
        operation: "read",
        expected: "denied",
        params: { listOnly: true, maxBuckets: 10 },
      },
    ],
    execution: safeActive(15, 45, "linked_baas_project"),
    remediation: patch([...SUPABASE_PATHS, ...FIREBASE_PATHS], "approval_required"),
    verificationRequiredChecks: ["storage-anon-list"],
  },
]);

// ═════════════════════════════════════════════════════════════════════════════
// 모드 C — 검증된 URL + 테스트 계정: 격리 능동 점검 (ISOLATED_ACTIVE)
//   반드시 테스트 전용 계정만 사용(SCN-007). 삭제(DELETE) 요청은 보내지 않는다.
// ═════════════════════════════════════════════════════════════════════════════

export const MODE_C_RULES: SecurityRule[] = withMode("C", [
  {
    id: "WEB-002",
    family: "WEB-002",
    version: "2.0.0",
    title: "Cross-user object authorization",
    titleKo: "다른 사용자 데이터 접근(IDOR)",
    summaryKo:
      "A 계정으로 B의 데이터를 읽거나 수정하면 거부되는지, B 본인은 정상적으로 되는지 4가지 조합으로 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(639, 862),
      capec(1, 122),
      apiTop10("API1:2023"),
      owasp("A01:2025"),
      attack("T1190", "T1078"),
    ),
    appliesTo: ["api", "web", "baas"],
    // v1은 api만 선택되어 순수 BaaS 앱에서 누락 → api 또는 baas
    selector: {
      all: [
        { any: [kind("api"), kind("baas")] },
        detected("authentication"),
        detected("user_owned_data"),
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
      {
        id: "locate-object-endpoints",
        toolId: "route_inventory",
        method: "SAST",
        when: HAS_SOURCE,
      },
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
    execution: isolated(40, 120, { mutatesOwnTestData: true }),
    remediation: patch([...APP_PATHS, ...SUPABASE_PATHS], "approval_required"),
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
    id: "WEB-013",
    family: "WEB-013",
    version: "2.0.0",
    title: "Broken function-level authorization (BFLA)",
    titleKo: "일반 사용자의 관리자 기능 호출(BFLA)",
    summaryKo:
      "일반 계정으로 관리자 전용 기능(회원 목록, 권한 변경 등)을 호출하면 거부되는지 확인합니다.",
    severity: "high",
    standards: std(
      cwe(285, 863),
      capec(58, 1),
      apiTop10("API5:2023"),
      owasp("A01:2025"),
      attack("T1078"),
    ),
    appliesTo: ["api", "web"],
    selector: {
      all: [HAS_ORIGIN, detected("authentication"), detected("admin_functions")],
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
        expected: "denied",
      },
    ],
    execution: isolated(12, 60),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-bfla"],
  },

  {
    id: "WEB-016-C",
    family: "WEB-016",
    version: "1.0.0",
    title: "Mass assignment (active probe)",
    titleKo: "대량 할당(실제 확인)",
    summaryKo:
      "A 계정이 자기 프로필을 수정할 때 role, is_admin, plan, credits 같은 필드를 몰래 끼워 넣으면 반영되는지 확인하고, 점검 후 원래 값으로 되돌립니다.",
    severity: "high",
    standards: std(
      cwe(915),
      capec(77),
      apiTop10("API3:2023"),
      owasp("A08:2025"),
      attack("T1190"),
    ),
    appliesTo: ["api", "web", "baas"],
    selector: { all: [HAS_ORIGIN, detected("authentication")] },
    methods: ["TEST"],
    prerequisites: {
      TEST: ["authorized_test_deployment", "test_user_a", "object_owned_by_a"],
    },
    checks: [
      {
        id: "probe-mass-assignment",
        toolId: "authorization_test_runner",
        method: "TEST",
        actor: "test_user_a",
        object: "object_owned_by_a",
        operation: "update",
        expected: "denied",
        params: {
          injectedFields: ["role", "is_admin", "isAdmin", "plan", "tier", "credits", "user_id", "owner_id"],
          restoreAfter: true,
        },
      },
    ],
    execution: isolated(10, 60, { mutatesOwnTestData: true }),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["probe-mass-assignment", "existing-functional-tests"],
  },

  {
    id: "WEB-019-C",
    family: "WEB-019",
    version: "1.0.0",
    title: "JWT tampering (active probe)",
    titleKo: "JWT 위변조(실제 확인)",
    summaryKo:
      "A 계정의 토큰을 alg=none으로 바꾸거나, 서명을 지우거나, 사용자 ID를 B로 바꿔 보냈을 때 모두 거부되는지 확인합니다.",
    severity: "critical",
    standards: std(
      cwe(347, 345),
      capec(196, 473),
      owasp("A07:2025"),
      attack("T1606"),
    ),
    appliesTo: ["api", "web"],
    selector: { all: [HAS_ORIGIN, detected("jwt_auth")] },
    methods: ["TEST"],
    prerequisites: {
      TEST: ["authorized_test_deployment", "test_user_a", "test_user_b"],
    },
    checks: [
      {
        id: "jwt-alg-none",
        toolId: "jwt_tamper_probe",
        method: "TEST",
        actor: "test_user_a",
        operation: "read",
        expected: "denied",
      },
      {
        id: "jwt-signature-stripped",
        toolId: "jwt_tamper_probe",
        method: "TEST",
        actor: "test_user_a",
        operation: "read",
        expected: "denied",
      },
      {
        id: "jwt-subject-swapped",
        toolId: "jwt_tamper_probe",
        method: "TEST",
        actor: "test_user_a",
        operation: "read",
        expected: "denied",
        params: { swapSubjectTo: "test_user_b" },
      },
    ],
    execution: isolated(10, 60),
    remediation: patch(APP_PATHS, "approval_required"),
    verificationRequiredChecks: ["jwt-alg-none", "jwt-signature-stripped", "jwt-subject-swapped"],
  },

  {
    id: "BAAS-001-C",
    family: "BAAS-001",
    version: "1.0.0",
    title: "Supabase cross-user RLS (active probe)",
    titleKo: "Supabase 사용자 간 데이터 접근(실제 확인)",
    summaryKo:
      "A 계정 세션으로 B가 소유한 행을 조회·수정할 수 있는지 확인합니다. 반드시 사용자 세션으로만 점검하며 service_role 키는 사용하지 않습니다.",
    severity: "critical",
    standards: std(
      cwe(639, 284, 862),
      capec(1, 122),
      owasp("A01:2025"),
      attack("T1530", "T1078"),
    ),
    appliesTo: ["baas"],
    selector: { all: [provider("supabase"), detected("user_owned_data")] },
    methods: ["TEST"],
    prerequisites: {
      TEST: ["linked_baas_project", "test_user_a", "test_user_b", "object_owned_by_b"],
    },
    checks: [
      {
        id: "rls-cross-user-read",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "test_user_a",
        object: "object_owned_by_b",
        operation: "read",
        expected: "denied",
      },
      {
        id: "rls-cross-user-update",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "test_user_a",
        object: "object_owned_by_b",
        operation: "update",
        expected: "denied",
      },
      {
        id: "rls-owner-read",
        toolId: "baas_access_probe",
        method: "TEST",
        actor: "test_user_b",
        object: "object_owned_by_b",
        operation: "read",
        expected: "allowed",
      },
    ],
    execution: isolated(40, 120, { target: "linked_baas_project" }),
    remediation: patch(SUPABASE_PATHS, "approval_required"),
    verificationRequiredChecks: [
      "rls-cross-user-read",
      "rls-cross-user-update",
      "rls-owner-read",
    ],
  },
]);

// ═════════════════════════════════════════════════════════════════════════════
// 모드 선택
// ═════════════════════════════════════════════════════════════════════════════

export const RULES: SecurityRule[] = [
  ...MODE_A_RULES,
  ...MODE_B_RULES,
  ...MODE_C_RULES,
];

export const RULES_BY_MODE: Record<ScanMode, SecurityRule[]> = {
  A: MODE_A_RULES,
  B: MODE_B_RULES,
  C: MODE_C_RULES,
};

/** 사용자에게 보여줄 모드 설명 */
export const MODE_INFO: Record<
  ScanMode,
  { labelKo: string; requiredKo: string[]; optionalKo: string[]; descriptionKo: string }
> = {
  A: {
    labelKo: "소스 점검",
    requiredKo: ["프로젝트 zip 파일"],
    optionalKo: [],
    descriptionKo:
      "코드만 읽어서 점검합니다. 사이트에 어떤 요청도 보내지 않습니다.",
  },
  B: {
    labelKo: "배포 URL 점검",
    requiredKo: ["배포 URL", "URL 소유권 인증(DNS 또는 파일)"],
    optionalKo: ["프로젝트 zip 파일(함께 올리면 소스 점검도 수행)"],
    descriptionKo:
      "실제 사이트에 소량의 안전한 요청을 보내 설정과 노출 여부를 확인합니다. 데이터를 바꾸지 않습니다.",
  },
  C: {
    labelKo: "계정 기반 점검",
    requiredKo: ["배포 URL", "URL 소유권 인증", "테스트 전용 계정 2개와 각 계정 소유 데이터"],
    optionalKo: ["프로젝트 zip 파일", "관리자 테스트 계정(관리자 기능 점검 시)"],
    descriptionKo:
      "테스트 계정으로 로그인해 다른 사용자 데이터 접근, 권한 상승 등을 실제로 재현합니다. 테스트 계정 데이터만 수정하고 점검 후 되돌립니다.",
  },
};

/** 상위 모드는 하위 모드 규칙을 포함한다 */
export const MODE_INCLUDES: Record<ScanMode, ScanMode[]> = {
  A: ["A"],
  B: ["A", "B"],
  C: ["A", "B", "C"],
};

export interface ModeSelection {
  rules: SecurityRule[];
  coverageGaps: Array<{ ruleId: string; reasonKo: string }>;
}

/**
 * 선택한 모드와 실제 제공된 입력으로 실행할 규칙을 고른다.
 * 소스가 없으면 A 규칙은 실행하지 않고 coverage_gap으로 남긴다.
 * (규칙별 selector·prerequisite 평가는 이후 서버 단계에서 수행)
 */
export function selectRulesForMode(
  mode: ScanMode,
  inputs: { hasSource: boolean },
): ModeSelection {
  const rules: SecurityRule[] = [];
  const coverageGaps: ModeSelection["coverageGaps"] = [];

  for (const m of MODE_INCLUDES[mode]) {
    for (const rule of RULES_BY_MODE[m]) {
      if (m === "A" && !inputs.hasSource) {
        coverageGaps.push({
          ruleId: rule.id,
          reasonKo: "소스(zip)가 없어 정적 점검을 수행하지 못했습니다.",
        });
        continue;
      }
      rules.push(rule);
    }
  }
  return { rules, coverageGaps };
}
