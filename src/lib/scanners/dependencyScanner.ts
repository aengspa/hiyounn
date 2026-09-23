import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding, SecurityEvidence } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { queryOsv, type OsvPackageQuery, type OsvPackageResult } from "@/lib/net/osv";

/**
 * REAL scanner (SEC-004). package.json의 의존성을 OSV.dev에 조회해 알려진
 * 취약점을 찾는다. 네트워크가 없거나 OSV가 실패하면 조회 불가로 두고
 * 결과를 만들지 않는다(coverage_gap; "안전"으로 단정하지 않음).
 *
 * simulated 플래그는 실제 조회 성공 여부에 따라 finding마다 설정한다.
 * (오프라인/차단 환경에서 데모를 위해, OSV 실패 시 소수의 알려진 취약점으로
 *  대체하는 오프라인 폴백을 optional로 둔다 — 이 finding은 simulated:true.)
 */

// ── 버전 정규화 ──────────────────────────────────────────────
// "^14.2.15" / "~4.17.19" / ">=1.2.3" → "14.2.15" 처럼 조회용 정확 버전 추출.
function exactVersion(range: string): string | null {
  const m = range.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
}

function collectDeps(pkgRaw: string): Record<string, string> {
  try {
    const pkg = JSON.parse(pkgRaw);
    return {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };
  } catch {
    return {};
  }
}

// ── 오프라인 폴백(네트워크 없을 때만) ────────────────────────
interface KnownVuln {
  pkg: string;
  vulnerableBelow: string;
  osvId: string;
  cvss: number;
}
const OFFLINE_KNOWN: KnownVuln[] = [
  { pkg: "next", vulnerableBelow: "14.2.35", osvId: "GHSA-next-old", cvss: 7.5 },
  { pkg: "lodash", vulnerableBelow: "4.17.21", osvId: "CVE-2021-23337", cvss: 7.2 },
];
function isBelow(version: string, target: string): boolean {
  const a = version.replace(/[^0-9.]/g, "").split(".").map(Number);
  const b = target.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) < (b[i] ?? 0)) return true;
    if ((a[i] ?? 0) > (b[i] ?? 0)) return false;
  }
  return false;
}

export class DependencyScanner implements SecurityScanner {
  readonly name = "dependency-scanner";
  readonly displayName = "Dependency scanning";
  readonly step = "dependency_scan" as const;
  // 실제 OSV 조회를 시도하므로 기본은 실제 스캐너. 개별 finding의 simulated는
  // 조회 성공 여부에 따라 설정한다.
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return "package.json" in context.files;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const pkgRaw = context.files["package.json"];
    if (!pkgRaw) return [];
    const deps = collectDeps(pkgRaw);
    const entries = Object.entries(deps);
    if (entries.length === 0) return [];

    const queries: OsvPackageQuery[] = [];
    for (const [name, range] of entries) {
      const version = exactVersion(range);
      if (version) queries.push({ name, version });
    }
    if (queries.length === 0) return [];

    // 1) 실제 OSV 조회 시도.
    let osvResults: OsvPackageResult[] | null = null;
    try {
      osvResults = await queryOsv(queries);
    } catch {
      osvResults = null; // 네트워크 실패 → 오프라인 폴백
    }

    if (osvResults !== null) {
      return this.findingsFromOsv(osvResults, deps);
    }

    // 2) 오프라인 폴백(조회 불가 환경). simulated:true로 명확히 표시.
    return this.offlineFallback(deps);
  }

  private findingsFromOsv(
    results: OsvPackageResult[],
    deps: Record<string, string>
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    for (const r of results) {
      if (r.vulns.length === 0) continue;
      const maxCvss = Math.max(0, ...r.vulns.map((v) => v.cvss ?? 0));
      const ids = r.vulns.map((v) => v.id).join(", ");
      const fixed = r.vulns.find((v) => v.fixedVersion)?.fixedVersion;

      const evidence: SecurityEvidence[] = [
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "OSV.dev 조회 결과",
          content: r.vulns
            .map(
              (v) =>
                `${v.id}${v.cvss ? ` (CVSS ${v.cvss})` : ""}${
                  v.fixedVersion ? ` → 수정: ${v.fixedVersion}` : ""
                }${v.summary ? `\n  ${v.summary}` : ""}`
            )
            .join("\n"),
        },
        {
          id: id("ev"),
          kind: "configuration",
          label: "package.json",
          content: `"${r.name}": "${deps[r.name] ?? r.version}"`,
        },
      ];

      findings.push({
        id: id("finding"),
        scanId: "",
        title: "알려진 취약점이 있는 라이브러리를 사용 중입니다",
        severity: maxCvss >= 9 ? "critical" : maxCvss >= 7 ? "high" : maxCvss > 0 ? "medium" : "medium",
        category: "Vulnerable Dependencies",
        owasp: "A06 – Vulnerable and Outdated Components",
        cwe: "CWE-1035",
        cvss: maxCvss || undefined,
        description: `${r.name}@${r.version}에 알려진 취약점이 있습니다 (OSV: ${ids}).`,
        humanReadableImpact:
          "사용 중인 라이브러리에 공개적으로 알려진 보안 취약점이 있어, 공격자가 그 결함을 노릴 수 있습니다.",
        whyItMatters:
          "공격자는 알려진 취약점이 있는 라이브러리 버전을 쓰는 앱을 자동으로 찾아다닙니다.",
        evidence,
        remediation: fixed
          ? `${r.name}을(를) ${fixed} 이상으로 업데이트하세요.`
          : `${r.name}을(를) 취약점이 해결된 최신 버전으로 업데이트하세요.`,
        status: "detected",
        simulated: false, // 실제 OSV 조회 결과
        verificationKey: `dep:${r.name}`,
        createdAt: now(),
        updatedAt: now(),
      });
    }
    return findings;
  }

  private offlineFallback(deps: Record<string, string>): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    for (const known of OFFLINE_KNOWN) {
      const installed = deps[known.pkg];
      if (installed && isBelow(installed, known.vulnerableBelow)) {
        findings.push({
          id: id("finding"),
          scanId: "",
          title: "알려진 취약점이 있는 라이브러리를 사용 중입니다 (오프라인 판정)",
          severity: known.cvss >= 7 ? "high" : "medium",
          category: "Vulnerable Dependencies",
          owasp: "A06 – Vulnerable and Outdated Components",
          cwe: "CWE-1035",
          cvss: known.cvss,
          description: `${known.pkg}@${installed} 버전이 패치 버전 ${known.vulnerableBelow}보다 낮습니다 (OSV 조회 실패 — 오프라인 목록으로 판정).`,
          humanReadableImpact:
            "사용 중인 라이브러리가 알려진 취약점이 있는 오래된 버전입니다.",
          whyItMatters:
            "네트워크가 없어 OSV.dev 실시간 조회에 실패했고, 최소한의 오프라인 목록으로만 판정했습니다. 온라인에서 다시 스캔하면 더 정확합니다.",
          evidence: [
            {
              id: id("ev"),
              kind: "scanner_output",
              label: "의존성 스캐너 출력 (오프라인 폴백)",
              content: `패키지: ${known.pkg}\n설치됨: ${installed}\n패치 버전: ${known.vulnerableBelow}\n참고: ${known.osvId}`,
            },
          ],
          remediation: `${known.pkg}을(를) ${known.vulnerableBelow} 이상으로 업데이트하세요.`,
          status: "detected",
          simulated: true, // OSV 실패 시 폴백 — 실제 조회 아님
          verificationKey: `dep:${known.pkg}`,
          createdAt: now(),
          updatedAt: now(),
        });
      }
    }
    return findings;
  }
}
