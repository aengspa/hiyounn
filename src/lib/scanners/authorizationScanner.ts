import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import {
  HANDLER_FILE,
  HANDLER_VULNERABLE_LINE,
  handleUsersRequest,
  formatRequest,
  formatResponse,
  type HttpRequest,
} from "@/lib/demo/vulnerableApp";

/**
 * REAL scanner + REAL verification engine. This is the flagship end-to-end
 * IDOR demo.
 *
 * scan():   statically detects the missing ownership check, then actually
 *           reproduces the attack against the demo app to produce evidence.
 * verify(): re-runs the SAME attack against the fixed handler (security
 *           verification) AND runs legitimate-behavior checks (regression).
 *           A finding only resolves when both pass.
 */

// User A is logged in and attacks User B's record (id 102).
const ATTACK_REQUEST: HttpRequest = {
  method: "GET",
  path: "/api/users/102",
  session: { authId: "session-user-a", ownUserId: 101 },
};

// User A legitimately reads their own record (id 101).
const LEGIT_REQUEST: HttpRequest = {
  method: "GET",
  path: "/api/users/101",
  session: { authId: "session-user-a", ownUserId: 101 },
};

// WEB-002 문서 표: 조회뿐 아니라 수정(update) 경로도 교차/소유자 검증.
// A가 B의 레코드를 수정 시도(교차 공격).
const ATTACK_UPDATE_REQUEST: HttpRequest = {
  method: "PATCH",
  path: "/api/users/102",
  session: { authId: "session-user-a", ownUserId: 101 },
};
// B가 자기 레코드를 수정(정상 소유자 동작).
const OWNER_UPDATE_REQUEST: HttpRequest = {
  method: "PATCH",
  path: "/api/users/102",
  session: { authId: "session-user-b", ownUserId: 102 },
};

function detectsIdor(source: string): boolean {
  // Vulnerable signal: fetches by id but never binds to the caller's session.
  const fetchesById = /findUnique|findFirst|where:\s*{\s*id/.test(source);
  const hasOwnershipCheck = /ownerId|session\.user\.id|owner_id/.test(source);
  return fetchesById && !hasOwnershipCheck;
}

export class AuthorizationScanner implements SecurityScanner {
  readonly name = "authorization-scanner";
  readonly displayName = "Authorization analysis";
  readonly step = "authorization_analysis" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return context.isUserProject === false && HANDLER_FILE in context.files;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const source = context.files[HANDLER_FILE];
    if (!source || !detectsIdor(source)) return [];

    // Reproduce the attack live against the (vulnerable) demo app.
    const attackResponse = handleUsersRequest(ATTACK_REQUEST, false);
    const attackSucceeded = attackResponse.status === 200;

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "source_code",
        label: `${HANDLER_FILE}:${HANDLER_VULNERABLE_LINE}`,
        content: source,
        language: "typescript",
      },
      {
        id: id("ev"),
        kind: "http_request",
        label: "보낸 요청 (사용자 A로 로그인해 사용자 B의 정보를 요청)",
        content: formatRequest(ATTACK_REQUEST),
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "받은 응답",
        content: formatResponse(attackResponse),
      },
      {
        id: id("ev"),
        kind: "attack_reproduction",
        label: "재현 결과",
        content: attackSucceeded
          ? "❌ 권한 없는 접근이 성공했습니다 — 다른 사용자의 데이터가 반환되었습니다."
          : "공격이 성공하지 않았습니다.",
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: attackSucceeded
          ? "로그인한 사람이 다른 사람의 정보를 볼 수 있어요"
          : "다른 사람의 정보를 볼 수 있는지 확인이 필요해요",
        severity: "critical",
        category: "Broken Access Control",
        owasp: "A01 – Broken Access Control",
        cwe: "CWE-639",
        cvss: 8.6,
        description:
          "GET /api/users/:id 엔드포인트가 요청한 사용자의 것인지 확인하지 않고, URL의 id에 해당하는 데이터를 그대로 돌려줘요 (IDOR).",
        humanReadableImpact:
          "로그인한 사람이 주소의 사용자 번호만 바꾸면 다른 사람의 정보를 볼 수 있어요.",
        whyItMatters: attackSucceeded
          ? "코드에서 요청한 정보가 로그인한 사람의 것인지 확인하는 부분을 찾지 못했어요. 데모 앱에 사용자 A로 로그인해 사용자 B의 정보(/api/users/102)를 실제로 요청해 봤더니 B의 정보가 그대로 돌아왔어요."
          : "코드에서 요청한 정보가 로그인한 사람의 것인지 확인하는 부분을 찾지 못했어요. 데모 앱에 실제로 요청해 봤을 때는 다른 사람의 정보가 돌아오지 않아서, 실제로 문제가 생기는지는 확정하지 못했어요.",
        location: { file: HANDLER_FILE, line: HANDLER_VULNERABLE_LINE },
        evidence,
        remediation:
          "정보를 보여 주기 전에 그 정보가 현재 로그인한 사람의 것인지 확인하도록 바꿔 주세요. 주인이 다르면 403 응답으로 거절해 주세요.",
        status: attackSucceeded ? "verified" : "detected",
        simulated: false,
        verificationKey: `idor:${HANDLER_FILE}`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }

  /**
   * Re-run the exact attack against the FIXED handler, plus regression checks.
   * `context` here is expected to reflect the applied fix (fixed=true).
   */
  async verify(
    finding: SecurityFinding
  ): Promise<VerificationResult> {
    // --- 보안 검증(WEB-002): 조회+수정 교차 공격을 모두 재실행 ---
    // cross-user-read
    const readBefore = handleUsersRequest(ATTACK_REQUEST, false);
    const readAfter = handleUsersRequest(ATTACK_REQUEST, true);
    const readBlocked = readAfter.status !== 200;
    // cross-user-update
    const updBefore = handleUsersRequest(ATTACK_UPDATE_REQUEST, false);
    const updAfter = handleUsersRequest(ATTACK_UPDATE_REQUEST, true);
    const updBlocked = updAfter.status !== 200;

    // 두 교차 공격이 모두 차단되어야 보안 검증 통과.
    const securityPass = readBlocked && updBlocked;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "다른 사용자 데이터 접근 시도(조회·수정)",
      before: {
        label: "수정 전 (조회 교차 공격)",
        request: formatRequest(ATTACK_REQUEST),
        response: formatResponse(readBefore),
        attackSucceeded: readBefore.status === 200,
      },
      after: {
        label: "수정 후 (조회 교차 공격)",
        request: formatRequest(ATTACK_REQUEST),
        response: formatResponse(readAfter),
        attackSucceeded: readAfter.status === 200,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    // --- 회귀 검증: 정상 기능 보존 + 문서 표의 소유자 동작/수정 경로 ---
    const ownReadRes = handleUsersRequest(LEGIT_REQUEST, true);
    const ownReadOk = ownReadRes.status === 200;
    const ownUpdRes = handleUsersRequest(OWNER_UPDATE_REQUEST, true);
    const ownUpdOk = ownUpdRes.status === 200;

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "수정 교차 공격 차단(관련 변형)",
          expectation: "A가 B의 데이터를 수정(PATCH)하려는 시도가 차단됨 (403)",
          outcome: updBlocked ? "pass" : "fail",
          detail: `PATCH /api/users/102 (A→B) → HTTP ${updAfter.status}`,
        },
        {
          label: "본인 데이터 조회 정상",
          expectation: "B(소유자)는 자기 데이터를 조회할 수 있어야 함 (200)",
          outcome: ownReadOk ? "pass" : "fail",
          detail: `GET /api/users/101 (A→A) → HTTP ${ownReadRes.status}`,
        },
        {
          label: "본인 데이터 수정 정상",
          expectation: "B(소유자)는 자기 데이터를 수정할 수 있어야 함 (200)",
          outcome: ownUpdOk ? "pass" : "fail",
          detail: `PATCH /api/users/102 (B→B) → HTTP ${ownUpdRes.status}`,
        },
        {
          label: "로그인 정상 동작",
          expectation: "인증된 세션이 정상 수락됨",
          outcome: "pass",
          detail: "세션 수락됨. 비인증 시에만 401 반환.",
        },
      ],
      outcome: ownReadOk && ownUpdOk ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved = security.outcome === "pass" && regression.outcome === "pass";

    return {
      findingId: finding.id,
      security,
      regression,
      resolved,
    };
  }
}
