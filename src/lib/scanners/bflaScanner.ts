import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { safeFetch, SafeFetchError } from "@/lib/net/safeFetch";

/**
 * REAL active scanner (WEB-013 / 지식 베이스 A-2, BFLA).
 *
 * 일반 사용자 세션으로 관리자 전용 함수를 호출해 거부(401/403)되는지 확인한다.
 * 관리자 세션 호출은 대조군(허용 기대). 격리(ISOLATED_ACTIVE) 환경 전제.
 *
 * 세션 토큰은 ProjectContext에 주입되어야 한다(데모/합성 계정). 없으면
 * applicable=false → coverage_gap. 실제 사용자/운영 대상 금지.
 *
 * 비파괴 우선: 가능하면 조회형(GET) 관리자 함수로 확인한다. 여기서는 GET만 쓴다.
 */

// 흔한 관리자 함수 경로 후보.
const ADMIN_PATHS = ["/api/admin/users", "/api/admin", "/admin/api/users"];

interface Sessions {
  userToken?: string; // 일반 사용자 세션(쿠키/베어러)
  adminToken?: string; // 관리자 세션(대조군)
}

/** ProjectContext에서 세션 토큰을 읽는다(엔진이 격리 계정으로 주입). */
function readSessions(context: ProjectContext): Sessions {
  const g = context as unknown as { testSessions?: Sessions };
  return g.testSessions ?? {};
}

function toUrl(base: string, path: string): string | null {
  try {
    const u = new URL(base);
    return new URL(path, `${u.protocol}//${u.host}`).toString();
  } catch {
    return null;
  }
}

interface CallResult {
  status: number | null;
  note?: string;
}

async function callAs(url: string, token?: string): Promise<CallResult> {
  try {
    const res = await safeFetch(url, {
      timeoutMs: 4000,
      maxBytes: 4 * 1024,
      followRedirects: false,
      headers: token ? { authorization: `Bearer ${token}`, cookie: token } : undefined,
    });
    return { status: res.status };
  } catch (e) {
    return { status: null, note: e instanceof SafeFetchError ? e.code : "요청 실패" };
  }
}

async function findAdminUrl(base: string, adminToken?: string): Promise<string | null> {
  // 관리자 토큰으로 2xx/403이 나오는(=존재하는) 첫 관리자 경로.
  for (const p of ADMIN_PATHS) {
    const url = toUrl(base, p);
    if (!url) continue;
    const r = await callAs(url, adminToken);
    if (r.status !== null && r.status !== 404) return url;
  }
  return null;
}

function isAllowed(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300;
}

export class BflaScanner implements SecurityScanner {
  readonly name = "bfla-scanner";
  readonly displayName = "Function-level authorization probe";
  readonly step = "dynamic_testing" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    const s = readSessions(context);
    // 배포 URL + 일반/관리자 세션 둘 다 있어야 격리 재현 가능.
    return Boolean(context.deploymentUrl && s.userToken && s.adminToken);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    const { userToken, adminToken } = readSessions(context);
    if (!base || !userToken || !adminToken) return [];

    const url = await findAdminUrl(base, adminToken);
    if (!url) return []; // 관리자 함수 못 찾음 → coverage_gap

    // 일반 사용자로 호출(거부 기대) + 관리자로 호출(허용 대조군).
    const asUser = await callAs(url, userToken);
    const asAdmin = await callAs(url, adminToken);

    // 취약: 일반 사용자 호출이 허용됨. (관리자는 대조군)
    if (!isAllowed(asUser.status)) return [];

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_request",
        label: "관리자 기능에 보낸 요청",
        content: `GET ${url}\n- 일반 사용자 세션\n- 관리자 세션(대조군)`,
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "계정별 응답",
        content: `일반 사용자 → HTTP ${asUser.status} (허용됨 — 취약)\n관리자 → HTTP ${asAdmin.status}`,
      },
      {
        id: id("ev"),
        kind: "attack_reproduction",
        label: "재현 결과",
        content: "❌ 일반 사용자가 관리자 전용 함수를 실행할 수 있습니다.",
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: "일반 사용자도 관리자 전용 기능을 실행할 수 있어요",
        severity: "high",
        category: "Broken Function Level Authorization",
        owasp: "API5:2023 – Broken Function Level Authorization",
        cwe: "CWE-285",
        cvss: 8.1,
        description: `관리자 전용 함수(${url})가 일반 사용자 세션으로도 실행됐어요 (HTTP ${asUser.status}).`,
        humanReadableImpact:
          "관리자가 아닌 사람도 관리자만 써야 하는 기능을 실행할 수 있어요.",
        whyItMatters: `일반 사용자 테스트 계정으로 ${url}에 실제로 요청을 보냈더니 HTTP ${asUser.status} 응답으로 허용됐어요. 관리자 테스트 계정으로 보낸 요청은 HTTP ${asAdmin.status}였어요. 서버가 요청한 사람이 관리자인지 확인하지 않는 것으로 보여요.`,
        evidence,
        remediation:
          "관리자 전용 기능을 처리하기 전에 서버에서 요청한 사람이 관리자인지 확인하고, 아니면 403 응답으로 거절하도록 바꿔 주세요. 화면에서 버튼을 숨기는 것만으로는 막을 수 없어요.",
        status: "verified",
        simulated: false,
        verificationKey: `bfla:${context.projectId}`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const base = context.deploymentUrl;
    const { userToken, adminToken } = readSessions(context);
    const url = base && adminToken ? await findAdminUrl(base, adminToken) : null;

    const asUser = url ? await callAs(url, userToken) : { status: null };
    const asAdmin = url ? await callAs(url, adminToken) : { status: null };

    const userDenied = url !== null && !isAllowed(asUser.status);
    const adminAllowed = isAllowed(asAdmin.status);
    const securityPass = userDenied;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "함수 수준 권한 재점검",
      before: {
        label: "수정 전",
        request: "일반 사용자 → 관리자 함수",
        response: "허용됨(취약)",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: "일반 사용자 → 관리자 함수",
        response:
          url === null
            ? "관리자 함수 관측 불가 — 재검증 불가"
            : userDenied
              ? `차단됨 (HTTP ${asUser.status})`
              : `여전히 허용됨 (HTTP ${asUser.status})`,
        attackSucceeded: !userDenied,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "관리자 정상 기능 보존",
          expectation: "관리자 세션은 여전히 관리자 함수를 실행할 수 있어야 함",
          outcome: adminAllowed ? "pass" : "fail",
          detail: `관리자 → HTTP ${asAdmin.status}`,
        },
      ],
      outcome: adminAllowed ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
