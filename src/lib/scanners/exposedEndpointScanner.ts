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
 * REAL active scanner (WEB-008 / 지식 베이스 C-3).
 *
 * 배포 URL 기준으로 흔히 실수로 노출되는 민감 경로에 SSRF 안전 계층(safeFetch)을
 * 통해 읽기 전용 GET을 보내, 200으로 응답(노출)하는 경로를 찾는다.
 *
 * 안전 규칙(지식 베이스 §3):
 *   - safeFetch가 내부/메타데이터 대역을 차단하고 리다이렉트를 재검증한다.
 *   - 경로 목록은 고정(소수)이며 비파괴 GET만 보낸다(maxRequests 준수).
 *   - 배포 URL이 없으면 이 스캐너는 applicable=false → 규칙은 coverage_gap.
 *     (정적 대체 없음: 노출 여부는 관측 없이 단정하지 않는다.)
 */

// 흔한 민감/디버그 경로. 노출되면 4xx가 아니라 200이 온다.
const SENSITIVE_PATHS: { path: string; label: string }[] = [
  { path: "/.env", label: "환경변수 파일" },
  { path: "/.git/config", label: "git 설정" },
  { path: "/.git/HEAD", label: "git HEAD" },
  { path: "/config.json", label: "설정 파일" },
  { path: "/server-status", label: "서버 상태 페이지" },
  { path: "/debug", label: "디버그 라우트" },
];

/** 화면 설명용 쉬운 이름(근거에는 위 label을 그대로 쓴다). */
const PATH_PLAIN_KO: Record<string, string> = {
  "/.env": "비밀값이 담기는 환경변수 파일(.env)",
  "/.git/config": "코드 저장소 설정(.git)",
  "/.git/HEAD": "코드 저장소 정보(.git)",
  "/config.json": "설정 파일",
  "/server-status": "서버 상태 페이지",
  "/debug": "개발용 디버그 화면",
};

/** URL의 origin(스킴+호스트+포트)만 취해 경로를 붙인다. */
function toProbeUrl(base: string, path: string): string | null {
  try {
    const u = new URL(base);
    return new URL(path, `${u.protocol}//${u.host}`).toString();
  } catch {
    return null;
  }
}

interface ProbeOutcome {
  path: string;
  label: string;
  status: number | null; // null = 요청 실패/차단
  exposed: boolean; // 2xx = 노출로 간주
  note?: string;
}

async function probePath(
  base: string,
  entry: { path: string; label: string }
): Promise<ProbeOutcome> {
  const url = toProbeUrl(base, entry.path);
  if (!url) return { path: entry.path, label: entry.label, status: null, exposed: false, note: "URL 조립 실패" };
  try {
    const res = await safeFetch(url, { timeoutMs: 4000, maxBytes: 8 * 1024 });
    const exposed = res.status >= 200 && res.status < 300;
    return { path: entry.path, label: entry.label, status: res.status, exposed };
  } catch (e) {
    const note = e instanceof SafeFetchError ? e.code : "요청 실패";
    return { path: entry.path, label: entry.label, status: null, exposed: false, note };
  }
}

async function probeAll(base: string): Promise<ProbeOutcome[]> {
  return Promise.all(SENSITIVE_PATHS.map((p) => probePath(base, p)));
}

export class ExposedEndpointScanner implements SecurityScanner {
  readonly name = "exposed-endpoint-scanner";
  readonly displayName = "Exposed endpoint probe";
  readonly step = "deployment_check" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    // 배포 URL(테스트 대상)이 있어야만 능동 점검이 가능하다.
    return Boolean(context.deploymentUrl);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    if (!base) return [];

    const outcomes = await probeAll(base);
    const exposed = outcomes.filter((o) => o.exposed);
    if (exposed.length === 0) return [];

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_request",
        label: "요청한 주소",
        content: exposed
          .map((o) => `GET ${o.path}`)
          .join("\n"),
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "응답 상태",
        content: exposed
          .map((o) => `${o.path} → HTTP ${o.status} (${o.label})`)
          .join("\n"),
      },
      {
        id: id("ev"),
        kind: "scanner_output",
        label: "열려 있는 주소",
        content: `노출된 경로 ${exposed.length}개:\n- ${exposed
          .map((o) => `${o.path} (${o.label})`)
          .join("\n- ")}`,
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        // findingMerge의 문제 종류 분류가 바뀌지 않도록 "경로"라는 단어를 제목에 유지한다.
        title: "외부에서 열리면 안 되는 파일이나 관리용 경로가 열려 있어요",
        severity: "high",
        category: "Security Misconfiguration",
        owasp: "A05 – Security Misconfiguration",
        cwe: "CWE-489",
        cvss: 7.5,
        description: `외부에서 접근 가능한 민감 경로를 찾았어요: ${exposed
          .map((o) => o.path)
          .join(", ")}.`,
        humanReadableImpact: `누구나 이 주소로 들어가 ${[...new Set(exposed.map((o) => PATH_PLAIN_KO[o.path] ?? o.label))].join(", ")} 같은 내부 정보를 볼 수 있어요. 여기에 비밀값이나 서버 정보가 들어 있다면 다음 공격에 쓰일 수 있어요.`,
        whyItMatters: `배포된 사이트에 실제로 요청을 보내 확인했어요. 다음 주소가 정상 응답(2xx)을 돌려줬어요: ${exposed
          .map((o) => o.path)
          .join(", ")}. 응답 내용은 저장하지 않았으니, 실제로 민감한 내용이 보이는지는 직접 열어 확인해 주세요.`,
        evidence,
        remediation:
          "호스팅 설정이나 서버에서 이 주소들에 대한 요청을 거절하도록 막아 주세요. .env 파일이나 .git 폴더는 배포 파일에 넣지 말고, 디버그 기능은 운영 환경에서 꺼 주세요. 비밀값이 담긴 파일이 열려 있었다면 그 비밀값은 새로 발급해 주세요.",
        status: "verified", // 실제 관측으로 노출을 확인
        simulated: false,
        verificationKey: `exposed:${context.projectId}`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }

  /**
   * 재검증: 동일 경로를 다시 프로브해 모두 4xx로 차단됐는지 확인.
   * (배포에 반영된 수정 이후 실행되는 것을 전제로 한다.)
   */
  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const base = context.deploymentUrl;
    const outcomes = base ? await probeAll(base) : [];
    const stillExposed = outcomes.filter((o) => o.exposed);
    const securityPass = base !== undefined && stillExposed.length === 0;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "노출 경로 재점검",
      before: {
        label: "수정 전",
        request: "GET (민감 경로 목록)",
        response: "일부 경로가 200으로 노출됨",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: "GET (민감 경로 목록)",
        response:
          base === undefined
            ? "배포 URL 없음 — 재검증 불가"
            : stillExposed.length === 0
              ? "모든 경로가 차단됨(4xx)"
              : `여전히 노출: ${stillExposed.map((o) => o.path).join(", ")}`,
        attackSucceeded: stillExposed.length > 0,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "정상 경로 접근 유지",
          expectation: "루트 페이지(/)는 여전히 응답해야 함",
          outcome: await rootReachable(base),
          detail: base ? `GET ${base}` : "배포 URL 없음",
        },
      ],
      outcome: await rootReachable(base),
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}

async function rootReachable(base: string | undefined): Promise<"pass" | "fail"> {
  if (!base) return "fail";
  try {
    const res = await safeFetch(base, { timeoutMs: 4000, maxBytes: 4 * 1024 });
    return res.status < 500 ? "pass" : "fail";
  } catch {
    return "fail";
  }
}
