/**
 * 규칙/스캐너 스모크 검증 스크립트.
 *
 * 목적: 새 SecurityRule을 추가한 뒤(지식 베이스 docs/security/scan-knowledge-base.md
 * 기준) 레지스트리가 규칙을 정상 적재하고, 데모 컨텍스트 스캔이 기대한 finding을
 * 만들어내며, 재검증(verify) 루프가 "신호가 사라져야만 resolved"로 동작하는지
 * 빠르게 확인한다.
 *
 * 실행: npm run verify:rules
 * (테스트 프레임워크가 없는 MVP에서 회귀를 막기 위한 경량 스모크 체크. 실패 시
 *  프로세스 종료 코드 1로 CI에서 잡을 수 있다.)
 */
import { getRules } from "../src/lib/rules/registry";
import { getTool } from "../src/lib/rules/toolCatalog";
import { SecurityOrchestrator } from "../src/lib/scanners/orchestrator";
import { StaticWebScanner } from "../src/lib/scanners/staticWebScanner";
import { buildDemoContext } from "../src/lib/demo/demoContext";
import type { ProjectContext } from "../src/lib/scanners/types";
import { isBlockedAddress, safeFetch, SafeFetchError } from "../src/lib/net/safeFetch";

let failures = 0;
function check(label: string, cond: boolean, detail = ""): void {
  const mark = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`[${mark}] ${label}${detail ? ` — ${detail}` : ""}`);
}

async function main(): Promise<void> {
  // 1) 레지스트리 적재 + 도구 등록
  const ids = getRules()
    .map((r) => r.id)
    .sort();
  const expected = [
    "BAAS-001",
    "SEC-001",
    "SEC-004",
    "WEB-001",
    "WEB-002",
    "WEB-003",
    "WEB-004",
    "WEB-005",
    "WEB-006",
    "WEB-007",
    "WEB-008",
    "WEB-009",
    "WEB-010",
    "WEB-011",
    "WEB-012",
    "WEB-013",
  ];
  check(
    "레지스트리가 기대한 규칙을 모두 적재",
    expected.every((e) => ids.includes(e)),
    ids.join(",")
  );
  check("static_web_analyzer 도구 등록됨", Boolean(getTool("static_web_analyzer")));
  check("exposed_path_probe 도구 등록됨", Boolean(getTool("exposed_path_probe")));

  // SSRF 안전 계층: 내부 대역 차단 + 라이브 요청 거부
  const blockedIps = ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fd00::1"];
  check(
    "SSRF 가드가 내부/메타데이터 대역 차단",
    blockedIps.every((ip) => isBlockedAddress(ip)) && !isBlockedAddress("8.8.8.8")
  );
  let ssrfBlocked = false;
  try {
    await safeFetch("http://169.254.169.254/latest/meta-data/", { timeoutMs: 2000 });
  } catch (e) {
    ssrfBlocked = e instanceof SafeFetchError && e.code === "PRIVATE_ADDRESS";
  }
  check("safeFetch가 메타데이터 IP 실제 요청 차단", ssrfBlocked);

  // 2) 데모 스캔 → 정적 규칙 finding 생성 + 규칙 메타 부착
  const ctx = buildDemoContext("proj_verify", {
    name: "verify",
    commitSha: "b72c42d",
  });
  const orch = new SecurityOrchestrator();
  const { findings, plan } = await orch.run(ctx);

  const byKind = (prefix: string) =>
    findings.filter((f) => (f.verificationKey ?? "").startsWith(prefix));

  check("XSS(WEB-003) 탐지", byKind("xss:").length >= 1);
  check("인젝션(WEB-004) 탐지(SQL+eval)", byKind("inj:").length >= 2);
  check("민감정보 노출(WEB-005) 탐지", byKind("expose:").length >= 1);
  check("경로 트래버설(WEB-006) 탐지", byKind("trav:").length >= 1);

  const xss = byKind("xss:")[0];
  check(
    "finding에 규칙 메타(ruleId/standards/tier) 부착",
    Boolean(xss?.ruleId && xss.standards?.length && xss.executionTier),
    `${xss?.ruleId} / ${xss?.standards?.join(";")} / ${xss?.executionTier}`
  );

  const plannedNew = plan.selectedChecks.filter((c) =>
    ["WEB-003", "WEB-004", "WEB-005", "WEB-006"].includes(c.ruleId)
  );
  check(
    "ScanPlan에 신규 규칙 검사 포함",
    plannedNew.length >= 5,
    plannedNew.map((c) => `${c.ruleId}/${c.checkId}`).join(",")
  );

  // 3) verify 루프: 수정 전 미해결 / 수정 후 해결
  const s = new StaticWebScanner();
  const unfixed = await s.verify(xss, ctx);
  check("수정 전 재검증은 미해결(정직한 fail)", unfixed.resolved === false);

  const fixedCtx: ProjectContext = {
    ...ctx,
    files: {
      ...ctx.files,
      "src/components/Comment.tsx":
        "export function Comment({ req }){ return <div>{req.query.text}</div>; }",
    },
  };
  const fixed = await s.verify(xss, fixedCtx);
  check(
    "수정 후 재검증은 해결(신호 사라짐 + 회귀 통과)",
    fixed.resolved === true,
    `sec=${fixed.security.outcome} reg=${fixed.regression.outcome}`
  );

  console.log(
    failures === 0
      ? "\n모든 검증 통과 ✅"
      : `\n${failures}개 검증 실패 ❌`
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
