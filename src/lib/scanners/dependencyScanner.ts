import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding } from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * SIMULATED scanner. Returns canned CVE results derived from the demo
 * package.json. This stands in for a real `npm audit` / OSV / Snyk integration.
 *
 * The `simulated: true` flag propagates to every finding so the UI can clearly
 * label these as mock results, keeping mock and real cleanly separated.
 */

interface KnownVuln {
  pkg: string;
  vulnerableBelow: string;
  cve: string;
  cvss: number;
  title: string;
  impact: string;
}

const KNOWN: KnownVuln[] = [
  {
    pkg: "next",
    vulnerableBelow: "14.0.0",
    cve: "CVE-2023-46298",
    cvss: 7.5,
    title: "오래된 프레임워크 버전에 알려진 보안 결함이 있습니다",
    impact:
      "핵심 구성요소 중 하나(Next.js)가 공개적으로 알려진 취약점이 있는 오래된 버전입니다.",
  },
  {
    pkg: "lodash",
    vulnerableBelow: "4.17.21",
    cve: "CVE-2021-23337",
    cvss: 7.2,
    title: "유틸리티 라이브러리 버전에 명령어 주입 취약점이 있습니다",
    impact:
      "널리 쓰이는 유틸리티 라이브러리(lodash)가 알려진 명령어 주입 결함이 있는 버전입니다.",
  },
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
  readonly simulated = true;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return "package.json" in context.files;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const pkgRaw = context.files["package.json"];
    if (!pkgRaw) return [];
    let deps: Record<string, string> = {};
    try {
      deps = JSON.parse(pkgRaw).dependencies ?? {};
    } catch {
      return [];
    }

    const findings: SecurityFinding[] = [];
    for (const known of KNOWN) {
      const installed = deps[known.pkg];
      if (installed && isBelow(installed, known.vulnerableBelow)) {
        findings.push({
          id: id("finding"),
          scanId: "",
          title: known.title,
          severity: known.cvss >= 7 ? "high" : "medium",
          category: "Vulnerable Dependencies",
          owasp: "A06 – Vulnerable and Outdated Components",
          cwe: "CWE-1035",
          cvss: known.cvss,
          description: `${known.pkg}@${installed} 버전이 패치된 버전 ${known.vulnerableBelow}보다 낮습니다 (${known.cve}).`,
          humanReadableImpact: known.impact,
          whyItMatters:
            "공격자는 알려진 취약점이 있는 라이브러리 버전을 쓰는 앱을 자동으로 찾아다닙니다.",
          evidence: [
            {
              id: id("ev"),
              kind: "scanner_output",
              label: "라이브러리 스캐너 출력 (시뮬레이션)",
              content: `패키지: ${known.pkg}\n설치됨: ${installed}\n패치 버전: ${known.vulnerableBelow}\n권고: ${known.cve}`,
            },
            {
              id: id("ev"),
              kind: "configuration",
              label: "package.json",
              content: `"${known.pkg}": "${installed}"`,
            },
          ],
          remediation: `${known.pkg}을(를) ${known.vulnerableBelow} 이상으로 업데이트하세요.`,
          status: "detected",
          simulated: true,
          verificationKey: `dep:${known.pkg}`,
          createdAt: now(),
          updatedAt: now(),
        });
      }
    }
    return findings;
  }
}
