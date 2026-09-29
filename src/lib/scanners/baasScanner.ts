import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * REAL scanner (BAAS-001). Supabase SQL(스키마/마이그레이션/정책)을 정적 분석해
 * 행 수준 보안(RLS) 미설정 테이블을 찾는다.
 *
 * 각 `create table public.X`에 대해:
 *   - `alter table public.X enable row level security`가 있는가?
 *   - RLS를 켠 테이블에 `create policy ... on public.X`가 하나 이상 있는가?
 * RLS 미설정(high) 또는 RLS만 켜고 정책 없음(medium)을 보고한다.
 *
 * 실제 SQL을 읽으므로 simulated:false. SQL 파일이 없으면 결과 없음(coverage_gap).
 * 재검증(verify): 수정 후 SQL에 RLS enable + 정책이 추가됐는지 재분석.
 *
 * 로드맵: 실서비스에서는 Supabase Management API로 배포된 RLS 상태를 조회하는
 * 확장이 가능(이 인터페이스는 그대로 유지).
 */

const SQL_FILE_RE = /^supabase\/.*\.sql$/;

interface TableRls {
  table: string; // 예: "public.profiles"
  rlsEnabled: boolean;
  hasPolicy: boolean;
  createLine: string;
}

/** 모든 supabase SQL 파일을 합쳐 테이블별 RLS 상태를 분석한다. */
function analyzeRls(files: Record<string, string>): TableRls[] {
  const sql = Object.entries(files)
    .filter(([path]) => SQL_FILE_RE.test(path))
    .map(([, content]) => content)
    .join("\n");
  if (!sql.trim()) return [];

  const tables = new Map<string, TableRls>();

  // create table [if not exists] public.NAME
  const createRe =
    /create\s+table\s+(?:if\s+not\s+exists\s+)?((?:public\.)?[A-Za-z_][\w]*)/gi;
  let m: RegExpExecArray | null;
  const lines = sql.split("\n");
  while ((m = createRe.exec(sql)) !== null) {
    const table = normalizeTable(m[1]);
    const lineNo = sql.slice(0, m.index).split("\n").length;
    if (!tables.has(table)) {
      tables.set(table, {
        table,
        rlsEnabled: false,
        hasPolicy: false,
        createLine: (lines[lineNo - 1] ?? "").trim(),
      });
    }
  }

  // alter table public.NAME enable row level security
  const enableRe =
    /alter\s+table\s+((?:public\.)?[A-Za-z_][\w]*)\s+enable\s+row\s+level\s+security/gi;
  while ((m = enableRe.exec(sql)) !== null) {
    const t = tables.get(normalizeTable(m[1]));
    if (t) t.rlsEnabled = true;
  }

  // create policy "..." on public.NAME
  const policyRe =
    /create\s+policy\s+[^\n]*?\s+on\s+((?:public\.)?[A-Za-z_][\w]*)/gi;
  while ((m = policyRe.exec(sql)) !== null) {
    const t = tables.get(normalizeTable(m[1]));
    if (t) t.hasPolicy = true;
  }

  return [...tables.values()];
}

function normalizeTable(raw: string): string {
  const t = raw.trim();
  return t.startsWith("public.") ? t : `public.${t}`;
}

/** 취약(RLS 없음 또는 정책 없음) 테이블만 반환. */
function vulnerableTables(rows: TableRls[]): TableRls[] {
  return rows.filter((r) => !r.rlsEnabled || !r.hasPolicy);
}

export class BaaSConfigScanner implements SecurityScanner {
  readonly name = "baas-config-scanner";
  readonly displayName = "BaaS configuration analysis";
  readonly step = "static_analysis" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    const isSupabase = (context.stack.baas ?? []).includes("supabase");
    const hasSql = Object.keys(context.files).some((p) => SQL_FILE_RE.test(p));
    return isSupabase && hasSql;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const rows = analyzeRls(context.files);
    if (rows.length === 0) return []; // SQL 없음 → coverage_gap

    const vulnerable = vulnerableTables(rows);
    if (vulnerable.length === 0) return [];

    const noRls = vulnerable.filter((v) => !v.rlsEnabled);
    const noPolicy = vulnerable.filter((v) => v.rlsEnabled && !v.hasPolicy);

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "configuration",
        label: "행 보호 규칙(RLS)이 꺼져 있거나 정책이 없는 테이블",
        content: vulnerable
          .map(
            (v) =>
              `${v.table}: RLS ${v.rlsEnabled ? "켜짐" : "꺼짐"}, 정책 ${
                v.hasPolicy ? "있음" : "없음"
              }`
          )
          .join("\n"),
      },
      {
        id: id("ev"),
        kind: "scanner_output",
        label: "SQL 파일 점검 결과",
        content: `분석한 테이블 ${rows.length}개 중 취약 ${vulnerable.length}개.\nRLS 꺼짐: ${
          noRls.map((v) => v.table).join(", ") || "없음"
        }\n정책 없음: ${noPolicy.map((v) => v.table).join(", ") || "없음"}`,
      },
    ];

    const severity: SecurityFinding["severity"] = noRls.length > 0 ? "high" : "medium";

    return [
      {
        id: id("finding"),
        scanId: "",
        title:
          noRls.length > 0
            ? "앱의 공개 키만 있으면 누구나 일부 테이블의 데이터를 읽거나 바꿀 수 있어요"
            : "일부 테이블에 누가 어떤 데이터를 볼 수 있는지 정한 규칙이 없어요",
        severity,
        category: "BaaS Misconfiguration",
        owasp: "A01 – Broken Access Control",
        cwe: "CWE-284",
        cvss: noRls.length > 0 ? 7.4 : 5.4,
        description: `Supabase SQL 정적 분석 결과, 다음 테이블에 접근 규칙이 부족해요: ${vulnerable
          .map((v) => v.table)
          .join(", ")}.`,
        humanReadableImpact:
          noRls.length > 0
            ? "Supabase의 공개(anon) 키는 누구나 브라우저에서 볼 수 있어요. 행 보호 규칙(RLS)이 꺼진 테이블은 이 키만 있으면 누구나 데이터를 읽거나 쓸 수 있어요."
            : "행 보호 규칙(RLS)은 켜져 있지만 누가 어떤 행을 볼 수 있는지 정한 정책이 없어요. 지금은 일반 사용자 요청이 막히지만, 앱에 필요한 접근 규칙이 코드에 정해져 있지 않은 상태예요.",
        whyItMatters: [
          "코드에서 확인했어요: supabase 폴더의 SQL 파일을 읽어 테이블마다 접근 규칙을 확인했어요.",
          noRls.length > 0 ? `RLS를 켜는 문장이 없는 테이블: ${noRls.map((v) => v.table).join(", ")}.` : "",
          noPolicy.length > 0 ? `RLS는 켰지만 정책(create policy)이 없는 테이블: ${noPolicy.map((v) => v.table).join(", ")}.` : "",
          "배포된 Supabase 프로젝트에 실제로 적용된 설정은 확인하지 않았어요.",
        ]
          .filter(Boolean)
          .join(" "),
        location: { file: "supabase/migrations", line: 1 },
        evidence,
        remediation:
          "테이블마다 `alter table 테이블이름 enable row level security` 문장을 추가해 주세요. 그리고 로그인한 사람이 자기 행만 보고 바꿀 수 있도록 auth.uid()로 주인을 비교하는 정책(create policy)을 만들어 주세요.",
        status: "detected",
        simulated: false,
        verificationKey: `rls:${noRls[0]?.table ?? vulnerable[0].table}`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }

  /** 재검증: 수정 후 SQL에 RLS enable + 정책이 추가됐는지 재분석(changed-code-scan). */
  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const rows = analyzeRls(context.files);
    const stillVulnerable = vulnerableTables(rows);
    const securityPass = rows.length > 0 && stillVulnerable.length === 0;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "RLS 정적 재분석(changed-code-scan)",
      before: {
        label: "수정 전",
        request: "SQL 정적 분석",
        response: "RLS 미설정/정책 없음 테이블 존재",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: "SQL 정적 분석",
        response:
          rows.length === 0
            ? "SQL 파일 없음 — 재분석 불가"
            : stillVulnerable.length === 0
              ? "모든 테이블 RLS+정책 확보"
              : `여전히 취약: ${stillVulnerable.map((v) => v.table).join(", ")}`,
        attackSucceeded: stillVulnerable.length > 0,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "스키마 정의 유지",
          expectation: "테이블 정의가 여전히 존재해야 함",
          outcome: rows.length > 0 ? "pass" : "fail",
          detail: `분석된 테이블 ${rows.length}개`,
        },
      ],
      outcome: rows.length > 0 ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
