import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding } from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * SIMULATED scanner. Models a Supabase RLS misconfiguration check. In
 * production this would query the project's Supabase policy state via the
 * Management API; here it returns a simulated "RLS disabled" finding when the
 * stack indicates Supabase.
 *
 * Every finding carries `simulated: true`.
 */
export class BaaSConfigScanner implements SecurityScanner {
  readonly name = "baas-config-scanner";
  readonly displayName = "BaaS configuration analysis";
  readonly step = "static_analysis" as const;
  readonly simulated = true;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return (context.stack.baas ?? []).includes("supabase");
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    // Simulated policy state: Row Level Security disabled on `profiles`.
    return [
      {
        id: id("finding"),
        scanId: "",
        title: "공개 키만 있으면 누구나 데이터베이스 테이블을 읽을 수 있습니다",
        severity: "high",
        category: "BaaS Misconfiguration",
        owasp: "A01 – Broken Access Control",
        cwe: "CWE-284",
        cvss: 7.4,
        description:
          "`profiles` 테이블에 행 수준 보안(RLS)이 꺼져 있는 것으로 보입니다 (시뮬레이션된 정책 상태).",
        humanReadableImpact:
          "데이터베이스 테이블에 접근 규칙이 없어서, 앱의 공개 키를 쓰는 사람이면 누구나 테이블의 모든 행을 읽을 수 있습니다.",
        whyItMatters:
          "Supabase의 공개 키는 브라우저에서 보입니다. RLS가 없으면 그 키만으로도 테이블 전체를 내려받을 수 있습니다.",
        evidence: [
          {
            id: id("ev"),
            kind: "configuration",
            label: "Supabase 정책 상태 (시뮬레이션)",
            content:
              "테이블: public.profiles\n행 수준 보안: 비활성화\n정책: 없음",
          },
          {
            id: id("ev"),
            kind: "scanner_output",
            label: "백엔드 설정 스캐너 출력 (시뮬레이션)",
            content: "1개 테이블에서 RLS 비활성화, 공개 읽기 노출.",
          },
        ],
        remediation:
          "테이블에 행 수준 보안(RLS)을 켜고, 각 행을 소유자에게만 제한하는 정책을 추가하세요.",
        status: "detected",
        simulated: true,
        verificationKey: `rls:profiles`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }
}
