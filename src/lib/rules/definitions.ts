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
import { ASVS5_RULES } from "@/lib/rules/asvs5Catalog";

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
    titleKo: "코드에 직접 적힌 비밀키(하드코딩)",
    summaryKo:
      "비밀키가 코드에 들어 있으면 코드를 볼 수 있는 사람 누구나 그 키로 외부 서비스나 데이터베이스에 접속할 수 있어요. 소스 코드, 설정 파일, git 기록에 API 키·DB 비밀번호·토큰이 직접 적혀 있는지 확인해요.",
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
        "키를 발급한 서비스(OpenAI, Supabase, Stripe 등)에서 노출된 키를 사용할 수 없게 하고(폐기) 새 키를 발급하세요.",
        "새 키는 코드에 넣지 말고 배포 서비스(Vercel 등)의 환경변수 설정에만 저장하세요.",
        ".env, .env.local 같은 비밀 설정 파일을 .gitignore에 추가해 저장소에 올라가지 않게 하세요.",
        "git 기록에 남은 키는 기록을 지워도 이미 누군가 복사했을 수 있어요. 기록 정리보다 키 폐기를 먼저 하세요.",
      ],
    ),
    verificationRequiredChecks: ["scan-secrets", "changed-code-scan"],
  },

  {
    id: "SEC-002",
    family: "SEC-002",
    version: "1.0.0",
    title: "Secrets exposed to the client bundle",
    titleKo: "브라우저로 전달되는 서버 전용 비밀키",
    summaryKo:
      "서버에서만 써야 하는 키가 화면 코드에 들어가면, 사이트 방문자 누구나 브라우저에서 그 키를 꺼내 쓸 수 있어요. NEXT_PUBLIC_·VITE_ 같은 공개용 이름을 붙인 환경변수나 화면 코드에 OpenAI 키, Supabase service_role 키 같은 서버 전용 키가 들어 있는지 확인해요.",
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
      "노출된 키는 발급한 서비스에서 폐기하고 새로 발급하세요. 이미 배포됐다면 누군가 가져갔을 수 있다고 보고 처리해야 해요.",
      "서버 전용 키는 공개용 이름(NEXT_PUBLIC_ 등) 없이 선언하고, 서버 코드(API Route, Server Action)에서만 읽으세요.",
      "외부 AI 서비스는 브라우저에서 직접 부르지 말고 내 서버를 거쳐 부르세요. 그 서버 API에는 로그인 확인과 호출 횟수 제한을 넣으세요.",
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
    titleKo: "알려진 보안 문제가 있는 외부 라이브러리 버전(취약한 의존성)",
    summaryKo:
      "프로젝트에서 쓰는 외부 라이브러리의 현재 버전에 이미 알려진 보안 문제(CVE)가 있으면, 그 문제를 이용한 공격을 받을 수 있어요. lockfile에 적힌 설치 버전을 알려진 문제 목록과 비교해요. 프로젝트에서 문제가 되는 기능을 실제로 쓰는지까지는 확인하지 않아요.",
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
        "lockfile(package-lock.json, pnpm-lock.yaml 등)이 없어서 실제로 설치되는 버전을 알 수 없었어요. package.json에 적힌 버전 범위로만 추정했어요. lockfile을 함께 넣어 다시 올려 주세요.",
    },
  },

  {
    id: "SEC-005",
    family: "SEC-005",
    version: "1.0.0",
    title: "Hallucinated or typosquatted packages",
    titleKo: "없는 이름이거나 유명 패키지를 흉내 낸 의심 패키지",
    summaryKo:
      "AI가 지어낸 이름의 패키지나 유명 패키지 이름을 흉내 낸 가짜 패키지를 설치하면, 설치하는 순간 악성 코드가 실행될 수 있어요. 패키지 저장소에 실제로 없거나 최근에 만들어진 패키지, 유명 패키지와 철자가 비슷한 패키지, 설치할 때 스크립트를 실행하는 패키지가 있는지 확인해요.",
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
      "의심 패키지는 이름 철자와 공식 저장소(GitHub) 주소가 맞는지 직접 확인하세요. 필요 없는 패키지라면 package.json에서 지우세요.",
      "이미 설치했다면 그 컴퓨터나 서버에서 쓰던 키를 모두 새로 발급받아 바꾸는 것을 권장해요.",
    ]),
    verificationRequiredChecks: ["registry-existence", "typosquat-similarity"],
  },

  {
    id: "SEC-006",
    family: "SEC-006",
    version: "1.0.0",
    title: "Weak password storage",
    titleKo: "알아내기 쉬운 방식으로 저장한 비밀번호",
    summaryKo:
      "비밀번호를 그대로 저장하거나 MD5·SHA-1처럼 빠른 방식으로만 바꿔 저장하면, 데이터가 유출됐을 때 원래 비밀번호를 쉽게 알아낼 수 있어요. 직접 만든 로그인 코드에서 비밀번호를 어떤 방식으로 저장하는지 확인해요.",
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
      "비밀번호는 bcrypt, argon2, scrypt처럼 비밀번호 저장용 방식으로 바꿔 저장하세요.",
      "이미 저장된 비밀번호는 사용자가 다음에 로그인할 때 새 방식으로 다시 저장하도록 바꾸세요(rehash-on-login).",
    ]),
    verificationRequiredChecks: ["scan-password-hashing", "changed-code-scan"],
  },

  // ── 인젝션 · 입력 처리 ──────────────────────────────────────────────────
  {
    id: "WEB-003",
    family: "WEB-003",
    version: "2.0.0",
    title: "DOM/Stored Cross-Site Scripting (static signal)",
    titleKo: "입력한 글이 화면에서 코드로 실행될 가능성(XSS)",
    summaryKo:
      "사용자가 입력한 글이 글자가 아니라 화면 코드로 들어가면, 다른 방문자의 브라우저에서 원하지 않는 스크립트가 실행될 수 있어요. 입력값이 innerHTML, dangerouslySetInnerHTML, v-html 같은 곳에 글자로 바꾸는 처리(이스케이프) 없이 들어가는지 확인해요.",
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
    titleKo: "입력값이 DB 명령이나 서버 명령으로 실행될 가능성(인젝션)",
    summaryKo:
      "사용자가 보낸 값이 DB 조회문이나 서버 명령에 그대로 섞이면, 그 값으로 데이터를 몰래 읽거나 바꾸거나 서버에서 명령을 실행할 수 있어요. 입력값이 SQL 문자열, NoSQL 조회 조건, 셸 명령, eval(), 안전하지 않은 데이터 복원(역직렬화)에 그대로 들어가는지 확인해요.",
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
    titleKo: "입력값으로 허용하지 않은 파일에 접근할 가능성(경로 트래버설)",
    summaryKo:
      "파일 이름이나 경로에 사용자가 보낸 값이 그대로 들어가면, ../ 같은 값으로 허용한 폴더 밖의 파일을 읽거나 덮어쓸 수 있어요. 파일을 읽고 쓰는 코드의 경로에 사용자 입력이 검사 없이 들어가는지 확인해요.",
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
    titleKo: "사용자가 준 주소로 서버가 대신 보내는 요청(SSRF)",
    summaryKo:
      "사용자가 준 주소로 서버가 직접 요청을 보내면, 외부에서는 닿을 수 없는 내부 서비스나 클라우드 설정 정보에 서버를 통해 접근할 수 있어요. 링크 미리보기, 이미지 프록시, URL 요약처럼 사용자가 준 주소를 서버가 요청하는 코드에 허용 주소 목록이 있는지, next/image의 remotePatterns가 모든 주소를 허용하는지 확인해요.",
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
    titleKo: "업로드 파일 검사가 부족한 처리",
    summaryKo:
      "업로드 파일의 종류와 크기를 확인하지 않으면, 사이트에서 실행되는 파일이나 매우 큰 파일이 올라올 수 있어요. 업로드 처리에서 확장자·파일 형식(MIME)·크기를 확인하는지, public 폴더에 저장하는지, HTML·SVG 파일을 그대로 보여 주는지 확인해요.",
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
    titleKo: "오류 응답에 드러나는 내부 정보",
    summaryKo:
      "오류 내용을 그대로 응답하면 서버의 파일 경로, DB 구조, 사용 중인 라이브러리 같은 내부 정보가 외부에 보여 공격 준비에 쓰일 수 있어요. API가 오류가 났을 때 error.stack, DB 오류 원문, 내부 경로를 응답에 담는지 확인해요.",
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
    titleKo: "요청한 데이터의 주인 확인 누락(IDOR)",
    summaryKo:
      "요청한 데이터가 로그인한 사람의 것인지 확인하지 않으면, 주소의 번호만 바꿔 다른 사람의 데이터를 보거나 바꿀 수 있어요. /api/orders/:id처럼 번호로 데이터를 찾는 코드에 데이터의 주인을 확인하는 부분이 있는지 코드에서 확인해요. 실제로 다른 계정의 데이터가 열리는지는 계정 기반 점검(WEB-002)에서 확인해요.",
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
    titleKo: "화면에 필요 없는 정보까지 보내는 API 응답",
    summaryKo:
      "API가 DB 기록을 통째로 보내면, 화면에는 안 보여도 비밀번호 해시, 이메일, 내부 값 같은 정보를 누구나 응답에서 꺼내 볼 수 있어요. API 응답에 DB 기록 전체를 그대로 담는지, 필요한 값만 골라 보내는지 확인해요.",
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
    titleKo: "사용자가 바꾸면 안 되는 값까지 저장되는 처리(대량 할당)",
    summaryKo:
      "요청 내용을 통째로 DB에 저장하면, 사용자가 role, is_admin, plan, credits처럼 스스로 바꾸면 안 되는 값까지 바꿀 수 있어요. 요청 본문(body)을 그대로 DB 생성·수정 함수에 넣는지 확인해요.",
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
    titleKo: "로그인 토큰(JWT) 확인 방식의 빈틈",
    summaryKo:
      "로그인 토큰(JWT)이 진짜인지 확인하지 않으면, 누군가 토큰 내용을 바꿔 다른 사람이나 관리자인 척할 수 있어요. 토큰을 읽기만 하고 서명을 확인하지 않는지, 허용할 서명 방식을 정해 두지 않았는지, 만료 시간을 무시하는지, 추측하기 쉬운 비밀값을 쓰는지 확인해요.",
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
    titleKo: "다른 사이트가 사용자 몰래 요청을 보낼 가능성(CSRF)",
    summaryKo:
      "로그인 쿠키로 사용자를 확인하는 사이트에서는, 사용자가 다른 사이트를 열기만 해도 그 사이트가 사용자 몰래 데이터 변경 요청을 보낼 수 있어요. GET 요청으로 데이터를 바꾸는지, 데이터를 바꾸는 요청에 CSRF 토큰이나 요청 출처(Origin) 확인이 있는지 확인해요.",
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
    titleKo: "외부 사이트로 보낼 수 있는 이동 처리(오픈 리다이렉트)",
    summaryKo:
      "?next=, ?redirect= 같은 주소 값대로 이동시키면, 내 사이트 주소로 시작하는 링크로 사용자를 가짜 사이트(피싱)로 보낼 수 있어요. 로그인·OAuth 콜백을 포함해, 이동할 주소를 허용 목록으로 제한하는지 확인해요.",
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
    titleKo: "진짜인지 확인하지 않는 결제·웹훅 알림",
    summaryKo:
      "웹훅 서명을 확인하지 않으면, 누구나 가짜 \"결제 완료\" 알림을 보내 유료 기능을 열 수 있어요. Stripe·토스페이먼츠 같은 서비스의 웹훅을 받는 코드가 서명을 확인하는지, 서명 확인에 필요한 원본 요청 본문을 쓰는지 확인해요.",
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
      "웹훅을 받는 코드에서 결제사가 준 서명 비밀값으로 서명을 먼저 확인하고, 맞지 않으면 처리를 멈추세요.",
      "결제 상태는 웹훅 내용만 믿지 말고, 결제사 API로 한 번 더 조회해서 확정하세요.",
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
    titleKo: "브라우저 보호 설정(CORS·보안 헤더, 설정 파일)",
    summaryKo:
      "브라우저 보호 설정이 빠지거나 너무 넓으면, 다른 사이트가 내 사이트 응답을 읽거나 내 화면을 몰래 겹쳐 띄울 수 있어요. 설정 파일에서 모든 사이트를 허용하는 CORS(*), 로그인 정보까지 허용하는 CORS, CSP·HSTS·X-Frame-Options 누락을 확인해요.",
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
    titleKo: "디버그 설정·로그인 없이 열리는 관리자 경로(코드)",
    summaryKo:
      "디버그 모드가 켜져 있거나 관리자 경로가 로그인 없이 열리면, 누구나 내부 정보를 보거나 관리 기능을 쓸 수 있어요. 운영 설정에 디버그 모드가 켜져 있는지, 로그인 확인 없이 열린 /admin 계열 경로가 있는지, public 폴더에 .env 같은 비밀 파일이 있는지 확인해요.",
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
    titleKo: "돈이 드는 기능의 호출 제한 누락",
    summaryKo:
      "AI 호출, 이메일·문자 발송, 이미지 생성처럼 쓸 때마다 비용이 드는 기능을 누구나 무제한으로 부를 수 있으면 요금이 크게 늘 수 있어요. 이런 기능의 API에 로그인 확인, 호출 횟수 제한(rate limit), AI 응답 길이 상한이 있는지 확인해요.",
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
      "비용이 드는 API에는 로그인 확인과 사용자별 호출 횟수 제한을 넣으세요. AI를 부를 때는 응답 길이 상한(max tokens)도 정하세요.",
      "AI·문자 서비스 관리 화면에서 월 사용 한도(hard limit)와 사용량 알림을 설정하세요.",
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
    titleKo: "AI(LLM) 기능 연결 방식의 빈틈",
    summaryKo:
      "AI에게 주는 지시문(시스템 프롬프트)에 비밀정보가 있거나 AI 답변을 검사 없이 실행하면, 사용자가 AI를 속여 비밀정보를 꺼내거나 원하지 않는 동작을 하게 만들 수 있어요. 시스템 프롬프트에 비밀정보가 있는지, 사용자 입력이나 AI 답변이 DB 조회·셸 명령·eval·화면 HTML·도구 호출로 검사 없이 이어지는지, 답변 길이 상한이 있는지 확인해요.",
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
      "시스템 프롬프트는 사용자가 꺼내 볼 수 있다고 생각하고, 비밀키나 내부 정보를 넣지 마세요.",
      "AI 답변은 DB 조회, 셸 명령, eval, 화면 HTML에 그대로 넣지 마세요. 화면에 보여 줄 때는 글자로만 표시하세요.",
      "AI가 쓸 수 있는 도구에는 꼭 필요한 권한만 주고, 데이터를 바꾸는 작업은 사용자가 확인한 뒤에 실행하세요.",
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
    titleKo: "Supabase 테이블 접근 규칙(RLS)",
    summaryKo:
      "Supabase 테이블에 행마다 접근을 막는 규칙(RLS)이 꺼져 있거나 모두 허용이면, 앱에 들어 있는 공개 키만으로 누구나 테이블 데이터를 읽거나 바꿀 수 있어요. 마이그레이션 파일에서 RLS가 꺼져 있는지, USING (true)처럼 모두 허용하는 규칙이 있는지 확인해요. Supabase 관리 화면에서 만든 테이블은 파일에 없을 수 있어서 배포 URL 점검(모드 B/C)도 권장해요.",
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
    titleKo: "Firebase 데이터 접근 규칙",
    summaryKo:
      "Firebase 규칙이 모두 허용이면 앱에 들어 있는 공개 설정만으로 누구나 데이터를 읽거나 바꿀 수 있어요. Firestore·Realtime DB·Storage 규칙이 allow read, write: if true 인지, 테스트용 기한 규칙(request.time < 기한)이 남아 있는지, 로그인만 하면 모두 허용하는지 확인해요.",
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
        "프로젝트에 Firebase 규칙 파일이 없어서 규칙을 확인하지 못했어요. 규칙이 Firebase 콘솔에만 있는 것으로 보여요. 배포 URL 점검(모드 B)으로 로그인 없이 데이터가 읽히는지 확인해 주세요.",
    },
  },

  {
    id: "BAAS-003",
    family: "BAAS-003",
    version: "1.0.0",
    title: "Public storage buckets (static)",
    titleKo: "누구나 볼 수 있게 열린 파일 저장소(스토리지 버킷)",
    summaryKo:
      "파일 저장소가 공개로 설정되면 누구나 저장된 파일 목록을 보거나 파일을 내려받을 수 있어요. Supabase Storage 버킷이 public인지, 로그인 없이 목록을 볼 수 있게 허용하는지, S3 등에 public-read 권한을 쓰는지 확인해요.",
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
    titleKo: "배포된 화면 코드(JS 번들)에 들어 있는 비밀키",
    summaryKo:
      "배포된 사이트의 JavaScript 파일에 서버 전용 키가 들어 있으면, 방문자 누구나 그 키를 꺼내 쓸 수 있어요. 실제 배포된 페이지의 JavaScript 파일을 내려받아 서버 전용 키가 있는지 확인해요. 함께 찾은 Supabase·Firebase 공개 설정은 데이터 접근 점검에 사용해요.",
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
      "화면 코드에서 발견된 키는 이미 공개된 것이에요. 발급한 서비스에서 바로 폐기하고 새로 발급하세요.",
      "새 키는 서버 코드에서만 읽고, 공개용 이름(NEXT_PUBLIC_ 등)을 붙이지 마세요.",
    ]),
    verificationRequiredChecks: ["fetch-and-scan-bundles"],
    produces: ["linked_baas_project"],
  },

  {
    id: "WEB-001",
    family: "WEB-001",
    version: "2.0.0",
    title: "Unauthenticated access to protected API",
    titleKo: "로그인 없이 열리는 보호 API",
    summaryKo:
      "로그인이 필요한 API가 로그인 없이 응답하면, 누구나 그 API의 데이터나 기능을 쓸 수 있어요. 로그인하지 않은 상태로 API를 불렀을 때 거부(401/403)되는지 실제 요청으로 확인해요. 소스가 있으면 코드의 경로 목록을, 없으면 사이트를 둘러본 결과를 사용해요.",
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
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "approval_required", [
      "로그인이 필요한 API는 처리 전에 서버에서 로그인한 사용자인지 확인하고, 아니면 401을 돌려주세요.",
      "여러 API에 같은 확인이 필요하면 middleware 같은 공통 위치에서 한 번에 확인하세요.",
    ]),
    verificationRequiredChecks: ["anonymous-access", "existing-functional-tests"],
  },

  {
    id: "WEB-007",
    family: "WEB-007",
    version: "2.0.0",
    title: "CORS and security headers",
    titleKo: "브라우저 보호 설정(CORS·보안 헤더)",
    summaryKo:
      "브라우저 보호 설정이 빠지거나 너무 넓으면, 다른 사이트가 내 사이트 응답을 읽거나 내 화면을 몰래 겹쳐 띄울 수 있어요. 실제 사이트 응답에 CSP, HSTS, X-Frame-Options, X-Content-Type-Options 설정이 있는지, 아무 사이트 주소(Origin)나 허용하는 CORS 응답이 오는지 확인해요.",
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
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS], "not_applicable", [
      "모든 사이트를 허용하는 CORS(*) 대신 내 사이트 주소만 허용하세요. 요청에 온 Origin 값을 그대로 돌려주지 마세요.",
      "next.config나 middleware에서 CSP, HSTS, X-Frame-Options, X-Content-Type-Options 헤더를 설정하세요.",
    ]),
    verificationRequiredChecks: ["http-headers", "cors-origin-reflection"],
  },

  {
    id: "WEB-008",
    family: "WEB-008",
    version: "2.0.0",
    title: "Exposed administrative or debug endpoints",
    titleKo: "외부에서 열리는 관리자·디버그 경로",
    summaryKo:
      "관리자·디버그 경로나 .env, .git 같은 파일이 외부에서 열리면, 누구나 관리 기능을 쓰거나 비밀 설정을 내려받을 수 있어요. /admin, /debug, /.env, /.git/HEAD 같은 경로가 로그인 없이 열리는지 실제 요청으로 확인해요.",
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
    remediation: patch([...CONFIG_PATHS, ...APP_PATHS], "approval_required", [
      "관리자·디버그 경로는 운영 배포에서 빼거나, 서버에서 관리자 로그인을 확인한 뒤에만 열리게 하세요.",
      ".env, .git 같은 파일이 배포 폴더(public 등)에 들어가지 않게 하세요. 이미 열려 있었다면 그 안의 키를 새로 발급하세요.",
    ]),
    verificationRequiredChecks: ["probe-exposed-paths"],
  },

  {
    // P2 중 유일하게 반영한 항목
    id: "WEB-025",
    family: "WEB-025",
    version: "1.0.0",
    title: "Admin paths disclosed via robots.txt / sitemap.xml",
    titleKo: "robots.txt·sitemap에 적힌 관리자 경로",
    summaryKo:
      "robots.txt나 sitemap.xml에 관리자·내부 경로를 적으면 누구나 그 위치를 알 수 있어요. 그 경로가 로그인 없이 열리면 위험이 더 커져요. 두 파일에 관리자·내부 경로가 있는지, 그 경로가 실제로 로그인 없이 열리는지 확인해요.",
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
    remediation: patch(["public/robots.txt", "app/robots.ts", "app/sitemap.ts", ...CONFIG_PATHS], "not_applicable", [
      "robots.txt와 sitemap에서 관리자·내부 경로를 빼세요.",
      "경로를 숨기는 것만으로는 보호되지 않아요. 그 경로는 서버에서 관리자 로그인을 확인한 뒤에만 열리게 하세요.",
    ]),
    verificationRequiredChecks: ["robots-sitemap-admin-paths", "disclosed-path-access"],
  },

  {
    id: "WEB-009",
    family: "WEB-009",
    version: "2.0.0",
    title: "Plaintext HTTP allowed / TLS not enforced",
    titleKo: "암호화되지 않은 http 접속 허용",
    summaryKo:
      "http:// 로 접속해도 https로 바뀌지 않으면, 같은 와이파이처럼 통신 중간에 있는 사람이 로그인 정보와 주고받는 내용을 엿볼 수 있어요. http:// 로 접속했을 때 https로 자동 이동하는지, 로그인 폼이 암호화 없이 전송되지 않는지 확인해요.",
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
    remediation: patch(CONFIG_PATHS, "approval_required", [
      "배포 서비스 설정이나 middleware에서 http 접속을 https로 자동 이동하게 하고, HSTS 헤더를 켜세요.",
    ]),
    verificationRequiredChecks: ["probe-tls"],
  },

  {
    id: "WEB-010",
    family: "WEB-010",
    version: "2.0.0",
    title: "Username enumeration via auth responses",
    titleKo: "가입한 계정인지 알 수 있는 로그인 응답",
    summaryKo:
      "\"없는 계정\"과 \"틀린 비밀번호\"의 응답이 다르면, 누군가 이메일 목록을 넣어 보며 가입한 사람을 알아낼 수 있어요. 로그인·회원가입·비밀번호 찾기에서 두 경우의 메시지, 상태 코드, 응답 시간이 다른지 확인해요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "없는 계정과 틀린 비밀번호에 같은 메시지와 같은 상태 코드를 돌려주세요. 예: \"이메일 또는 비밀번호가 맞지 않아요.\"",
    ]),
    verificationRequiredChecks: ["probe-user-enumeration"],
  },

  {
    id: "WEB-011",
    family: "WEB-011",
    version: "2.0.0",
    title: "Missing brute-force protection on login",
    titleKo: "로그인 반복 시도 차단 부족",
    summaryKo:
      "로그인을 여러 번 틀려도 막히지 않으면, 비밀번호를 자동으로 계속 넣어 보는 공격(무차별 대입)에 계정이 뚫릴 수 있어요. 없는 계정으로 로그인을 연달아 실패했을 때 차단(429, 잠금, CAPTCHA)이 걸리는지 확인해요. 시도 횟수가 적어서 차단 기준이 더 높으면 찾지 못할 수 있어 '의심'으로 알려 드려요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "로그인 API에 계정별·IP별 시도 횟수 제한을 넣고, 여러 번 틀리면 잠시 막거나 추가 확인(CAPTCHA)을 요청하세요.",
    ]),
    verificationRequiredChecks: ["probe-bruteforce"],
  },

  {
    id: "WEB-012",
    family: "WEB-012",
    version: "1.1.0",
    title: "Insecure session cookie attributes",
    titleKo: "로그인 쿠키 보호 설정 부족",
    summaryKo:
      "로그인 쿠키에 보호 설정이 빠지면, 암호화되지 않은 연결이나 화면 스크립트를 통해 로그인 상태를 빼앗길 수 있어요. 로그인 쿠키에 Secure(https에서만 전송), HttpOnly(스크립트로 읽기 차단), SameSite(다른 사이트 요청에 붙지 않게) 설정이 있는지 확인해요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "로그인 쿠키를 만드는 코드에 Secure, HttpOnly, SameSite=Lax(또는 Strict) 설정을 넣으세요.",
    ]),
    verificationRequiredChecks: ["probe-cookie-flags"],
  },

  {
    id: "WEB-015-B",
    family: "WEB-015",
    version: "1.0.0",
    title: "Anonymous reachability of costly endpoints",
    titleKo: "로그인 없이 부를 수 있는 비용 발생 API",
    summaryKo:
      "AI·문자·이메일 API를 로그인 없이 부를 수 있으면, 누구나 반복해서 불러 요금을 늘릴 수 있어요. 형식이 틀린 요청을 보내 로그인 확인에서 막히는지(401), 아니면 로그인 확인을 통과하는지(400) 확인해요. 실제 AI 호출이나 문자 발송은 일어나지 않아요.",
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
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "not_applicable", [
      "비용이 드는 API는 처리 전에 로그인한 사용자인지 확인하고, 사용자별 호출 횟수 제한을 넣으세요.",
      "AI·문자 서비스 관리 화면에서 월 사용 한도와 사용량 알림을 설정하세요.",
    ]),
    verificationRequiredChecks: ["costly-endpoint-anon-reachability"],
  },

  {
    id: "WEB-022-B",
    family: "WEB-022",
    version: "1.0.0",
    title: "Open redirect (active probe)",
    titleKo: "외부 사이트로 보낼 수 있는 이동 처리(실제 확인)",
    summaryKo:
      "이동할 주소 값에 외부 주소를 넣었을 때 그대로 보내면, 내 사이트 링크로 사용자를 가짜 사이트(피싱)로 보낼 수 있어요. 이동할 주소 값에 외부 도메인을 넣어 보내고, 응답의 이동 주소(Location 헤더)만 확인해요. 실제로 그 주소로 이동하지는 않아요.",
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
    remediation: patch([...APP_PATHS, ...CONFIG_PATHS], "not_applicable", [
      "이동할 주소는 내 사이트 안의 경로(/로 시작)나 허용 목록에 있는 주소만 받고, 나머지는 기본 페이지로 보내세요.",
    ]),
    verificationRequiredChecks: ["probe-open-redirect"],
  },

  {
    id: "WEB-023-B",
    family: "WEB-023",
    version: "1.0.0",
    title: "Verbose error disclosure (active probe)",
    titleKo: "오류 응답에 드러나는 내부 정보(실제 확인)",
    summaryKo:
      "오류 응답에 스택 트레이스, DB 오류, 서버 경로가 나오면 서버 내부 구조가 외부에 보여 공격 준비에 쓰일 수 있어요. API에 깨진 JSON이나 형식이 틀린 값을 보내 응답에 이런 정보가 나오는지 실제 요청으로 확인해요.",
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
    remediation: patch(APP_PATHS, "not_applicable", [
      "사용자에게는 \"요청을 처리하지 못했어요\" 같은 일반 오류 메시지만 보내고, 자세한 오류 내용은 서버 로그에만 남기세요.",
    ]),
    verificationRequiredChecks: ["probe-error-leak"],
  },

  {
    id: "LLM-001-B",
    family: "LLM-001",
    version: "1.0.0",
    title: "System prompt leakage (active probe)",
    titleKo: "AI 지시문(시스템 프롬프트) 유출(실제 확인)",
    summaryKo:
      "AI 지시문(시스템 프롬프트)이나 내부 지시가 답변에 나오면, 그 안에 적힌 규칙이나 비밀정보가 누구에게나 보여요. 공개된 AI 채팅 API에 정해진 추출 문장 3개를 보내 지시문이 답변에 나오는지 확인해요. 이 점검에는 사용자의 AI 사용량이 조금 들어요.",
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
    remediation: patch(APP_PATHS, "not_applicable", [
      "시스템 프롬프트에는 비밀키나 내부 정보를 넣지 마세요. 사용자가 꺼내 볼 수 있다고 생각하고 작성하세요.",
      "비밀이 필요한 처리는 AI에게 맡기지 말고 서버 코드에서 처리하세요.",
    ]),
    verificationRequiredChecks: ["probe-system-prompt-leak"],
  },

  // ── BaaS 실제 접근 확인 (anon 키만 사용) ─────────────────────────────
  {
    id: "BAAS-001-B",
    family: "BAAS-001",
    version: "1.0.0",
    title: "Supabase anonymous table read (active probe)",
    titleKo: "로그인 없이 읽히는 Supabase 테이블(실제 확인)",
    summaryKo:
      "앱에 들어 있는 공개(anon) 키만으로 테이블 데이터가 나오면, 방문자 누구나 그 데이터를 읽을 수 있어요. 배포된 앱에 들어 있는 공개 키로 각 테이블을 1행씩 조회해 로그인 없이 데이터가 나오는지 확인해요. service_role 키는 발견하더라도 절대 사용하지 않아요.",
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
    remediation: patch(SUPABASE_PATHS, "approval_required", [
      "먼저 그 테이블이 누구나 봐도 되는 데이터인지 확인하세요.",
      "공개용이 아니라면 테이블에 RLS를 켜고, 로그인한 사용자가 자기 행만 읽을 수 있는 규칙(예: auth.uid() = user_id)을 추가하세요.",
    ]),
    verificationRequiredChecks: ["supabase-anon-select"],
  },

  {
    id: "BAAS-002-B",
    family: "BAAS-002",
    version: "1.0.0",
    title: "Firebase anonymous read (active probe)",
    titleKo: "로그인 없이 읽히는 Firebase 데이터(실제 확인)",
    summaryKo:
      "로그인 없이 Firebase 데이터가 읽히면 방문자 누구나 그 데이터를 볼 수 있어요. 로그인하지 않은 상태로 Realtime DB(/.json)나 앱에서 쓰는 Firestore 컬렉션을 읽을 수 있는지 확인해요.",
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
    remediation: patch(FIREBASE_PATHS, "approval_required", [
      "먼저 그 데이터가 누구나 봐도 되는 데이터인지 확인하세요.",
      "공개용이 아니라면 Firebase 규칙의 읽기 조건에 로그인 확인(request.auth != null)과 데이터 주인 확인(예: request.auth.uid == resource.data.ownerId)을 넣으세요.",
    ]),
    verificationRequiredChecks: ["firebase-anon-read"],
  },

  {
    id: "BAAS-003-B",
    family: "BAAS-003",
    version: "1.0.0",
    title: "Anonymous storage bucket listing (active probe)",
    titleKo: "로그인 없이 보이는 파일 저장소 목록(실제 확인)",
    summaryKo:
      "로그인 없이 파일 저장소 목록이 보이면 누구나 저장된 파일 이름을 알 수 있고, 공개 설정이면 파일도 내려받을 수 있어요. 로그인하지 않은 상태로 스토리지 버킷의 파일 목록을 볼 수 있는지 확인해요. 파일 내용은 내려받지 않아요.",
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
    remediation: patch([...SUPABASE_PATHS, ...FIREBASE_PATHS], "approval_required", [
      "버킷을 비공개로 바꾸고, 파일 목록 조회는 로그인한 사용자에게만 허용하세요.",
      "파일을 보여 줘야 하면 짧은 기간만 쓸 수 있는 서명된 주소(signed URL)를 만들어 주세요.",
    ]),
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
    titleKo: "다른 사용자 데이터 읽기·수정(IDOR, 실제 확인)",
    summaryKo:
      "다른 사용자의 데이터를 읽거나 바꿀 수 있으면, 로그인한 누구나 남의 정보를 보거나 고칠 수 있어요. 테스트 계정 A로 B의 데이터를 읽고 수정했을 때 거부되는지, B 본인은 정상적으로 되는지 4가지 경우를 실제로 확인해요.",
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
    remediation: patch([...APP_PATHS, ...SUPABASE_PATHS], "approval_required", [
      "데이터를 보여 주거나 바꾸기 전에, 그 데이터가 현재 로그인한 사람의 것인지 서버에서 확인하세요(예: 조회 조건에 로그인한 사용자 id 넣기).",
      "수정한 뒤에는 본인 데이터는 여전히 읽고 수정할 수 있는지도 함께 확인하세요.",
    ]),
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
    titleKo: "일반 계정의 관리자 기능 사용(BFLA)",
    summaryKo:
      "일반 계정으로 관리자 전용 기능을 쓸 수 있으면, 가입한 누구나 관리자만 해야 하는 작업을 할 수 있어요. 일반 테스트 계정으로 관리자 전용 기능(회원 목록, 권한 변경 등)을 불렀을 때 거부되는지 실제로 확인해요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "관리자 기능 API는 처리 전에 서버에서 로그인한 사람이 관리자인지 확인하세요. 화면에서 버튼을 숨기는 것만으로는 막을 수 없어요.",
    ]),
    verificationRequiredChecks: ["probe-bfla"],
  },

  {
    id: "WEB-016-C",
    family: "WEB-016",
    version: "1.0.0",
    title: "Mass assignment (active probe)",
    titleKo: "사용자가 바꾸면 안 되는 값까지 저장되는 처리(실제 확인)",
    summaryKo:
      "수정 요청에 role, is_admin, plan, credits 같은 값을 끼워 넣어 저장되면, 사용자가 스스로 권한이나 요금제를 바꿀 수 있어요. 테스트 계정 A가 자기 프로필을 수정할 때 이런 값을 끼워 넣어 반영되는지 확인하고, 점검 뒤 원래 값으로 되돌려요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "수정 요청에서 사용자가 바꿔도 되는 값(예: 이름, 소개)만 골라 저장하세요. 요청 내용을 통째로 저장하지 마세요.",
    ]),
    verificationRequiredChecks: ["probe-mass-assignment", "existing-functional-tests"],
  },

  {
    id: "WEB-019-C",
    family: "WEB-019",
    version: "1.0.0",
    title: "JWT tampering (active probe)",
    titleKo: "변조한 로그인 토큰(JWT) 허용(실제 확인)",
    summaryKo:
      "변조한 로그인 토큰이 통과하면, 누구나 다른 사용자인 척 요청할 수 있어요. 테스트 계정 A의 토큰을 alg=none으로 바꾸거나, 서명을 지우거나, 사용자 ID를 B로 바꿔 보냈을 때 모두 거부되는지 확인해요.",
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
    remediation: patch(APP_PATHS, "approval_required", [
      "토큰을 받을 때마다 서명을 확인하는 함수(verify)를 쓰고, 허용할 서명 방식(algorithms)과 만료 시간을 함께 확인하세요.",
      "서명을 확인하지 않은 decode 결과로 사용자를 판단하지 마세요.",
    ]),
    verificationRequiredChecks: ["jwt-alg-none", "jwt-signature-stripped", "jwt-subject-swapped"],
  },

  {
    id: "BAAS-001-C",
    family: "BAAS-001",
    version: "1.0.0",
    title: "Supabase cross-user RLS (active probe)",
    titleKo: "Supabase에서 다른 사용자 행 읽기·수정(실제 확인)",
    summaryKo:
      "테이블 접근 규칙(RLS)이 부족하면 로그인한 사용자가 다른 사람의 행을 읽거나 바꿀 수 있어요. 테스트 계정 A의 로그인 상태로 B가 가진 행을 조회·수정할 수 있는지 확인해요. 반드시 사용자 로그인 상태로만 점검하고 service_role 키는 쓰지 않아요.",
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
    remediation: patch(SUPABASE_PATHS, "approval_required", [
      "해당 테이블의 RLS 규칙에, 행의 주인과 로그인한 사용자가 같은지 확인하는 조건(예: auth.uid() = user_id)을 읽기와 수정 모두에 넣으세요.",
    ]),
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

/** 모드 A 규칙 + ASVS 5.0.0 자동화 가능 정적 신호 규칙(모두 PASSIVE). */
const MODE_A_WITH_ASVS: SecurityRule[] = [...MODE_A_RULES, ...ASVS5_RULES];

export const RULES: SecurityRule[] = [
  ...MODE_A_WITH_ASVS,
  ...MODE_B_RULES,
  ...MODE_C_RULES,
];

export const RULES_BY_MODE: Record<ScanMode, SecurityRule[]> = {
  A: MODE_A_WITH_ASVS,
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
