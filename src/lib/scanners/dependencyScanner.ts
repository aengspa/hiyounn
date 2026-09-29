import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  RegressionTest,
  SecurityEvidence,
  SecurityFinding,
  VerificationResult,
  VerificationTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { queryOsv, type OsvPackageQuery, type OsvPackageResult } from "@/lib/net/osv";
import { VerificationUnavailableError } from "@/lib/store/errors";

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

type JsonRecord = Record<string, unknown>;

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const EXACT_VERSION =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** 각 의존성 항목에 package.json에서 그 패키지를 선언한 줄 위치와 그 줄을 붙인다. */
function withManifestLocations(findings: SecurityFinding[], pkgRaw: string): SecurityFinding[] {
  const lines = pkgRaw.split("\n");
  for (const f of findings) {
    const name = (f.verificationKey ?? "").slice(4);
    const idx = lines.findIndex((l) => l.includes(`"${name}"`));
    if (idx < 0) continue;
    f.location = { file: "package.json", line: idx + 1 };
    f.evidence.unshift({ id: id("ev"), kind: "source_code", label: `package.json:${idx + 1}`, content: lines[idx].trim(), language: "json" });
  }
  return findings;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unavailable(): never {
  throw new VerificationUnavailableError();
}

function verificationPackage(key: string | undefined): string {
  if (!key?.startsWith("dep:")) return unavailable();
  const name = key.slice(4);
  if (name.length === 0 || name.length > 214 || !PACKAGE_NAME.test(name)) {
    return unavailable();
  }
  return name;
}

interface VerifiedManifest {
  declared: boolean;
  spec?: string;
}

function verifyManifest(raw: string | undefined, name: string): VerifiedManifest {
  if (typeof raw !== "string" || raw.trim().length === 0) return unavailable();

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return unavailable();
  }
  if (!isRecord(parsed)) return unavailable();

  const declarations: string[] = [];
  for (const field of ["dependencies", "devDependencies"] as const) {
    const section = parsed[field];
    if (section === undefined) continue;
    if (!isRecord(section)) return unavailable();
    for (const value of Object.values(section)) {
      if (typeof value !== "string" || value.trim().length === 0) {
        return unavailable();
      }
    }
    if (Object.prototype.hasOwnProperty.call(section, name)) {
      declarations.push(section[name] as string);
    }
  }

  if (declarations.length === 0) return { declared: false };
  if (declarations.some((value) => value !== declarations[0])) return unavailable();
  return { declared: true, spec: declarations[0] };
}

function parseLock(raw: string | undefined): JsonRecord | undefined {
  if (raw === undefined) return undefined;
  if (raw.trim().length === 0) return unavailable();

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return unavailable();
  }
  if (!isRecord(parsed)) return unavailable();

  const lockfileVersion = parsed.lockfileVersion;
  if (lockfileVersion !== 1 && lockfileVersion !== 2 && lockfileVersion !== 3) {
    return unavailable();
  }
  const entries = lockfileVersion === 1 ? parsed.dependencies : parsed.packages;
  if (entries !== undefined && !isRecord(entries)) return unavailable();
  if ((lockfileVersion === 2 || lockfileVersion === 3) && entries === undefined) {
    return unavailable();
  }
  return parsed;
}

function lockContainsPackage(lock: JsonRecord | undefined, name: string): boolean {
  if (!lock) return false;
  const lockfileVersion = lock.lockfileVersion as 1 | 2 | 3;
  const entries = (lockfileVersion === 1 ? lock.dependencies : lock.packages) as
    | JsonRecord
    | undefined;
  const key = lockfileVersion === 1 ? name : `node_modules/${name}`;
  return Boolean(entries && Object.prototype.hasOwnProperty.call(entries, key));
}

interface ConcreteVersion {
  version: string;
  source: string;
}

function exactPinnedVersion(value: unknown, allowEquals: boolean): string | null {
  if (typeof value !== "string" || value !== value.trim()) return null;
  const normalized = allowEquals && value.startsWith("=") ? value.slice(1) : value;
  return EXACT_VERSION.test(normalized) ? normalized : null;
}

interface SemverCore {
  major: number;
  minor: number;
  patch: number;
}

function semverCore(version: string): SemverCore | null {
  if (!EXACT_VERSION.test(version) || version.includes("-") || version.includes("+")) {
    return null;
  }
  const [major, minor, patch] = version.split(".").map(Number);
  return { major, minor, patch };
}

function compareVersions(left: SemverCore, right: SemverCore): number {
  return left.major - right.major || left.minor - right.minor || left.patch - right.patch;
}

function versionMatchesSpec(version: string, spec: string): boolean {
  if (spec !== spec.trim()) return false;

  const exact = exactPinnedVersion(spec, true);
  if (exact) return exact === version;

  const current = semverCore(version);
  if (!current) return false;

  if (spec.startsWith("^") || spec.startsWith("~")) {
    const operator = spec[0];
    const base = semverCore(spec.slice(1));
    if (!base || compareVersions(current, base) < 0) return false;
    if (operator === "~") {
      return current.major === base.major && current.minor === base.minor;
    }
    if (base.major > 0) return current.major === base.major;
    if (base.minor > 0) {
      return current.major === 0 && current.minor === base.minor;
    }
    return current.major === 0 && current.minor === 0 && current.patch === base.patch;
  }

  const comparators = spec.split(/\s+/);
  if (comparators.length === 0) return false;
  return comparators.every((comparator) => {
    const match = comparator.match(/^(>=|<=|>|<)(.+)$/);
    if (!match) return false;
    const boundary = semverCore(match[2]);
    if (!boundary) return false;
    const compared = compareVersions(current, boundary);
    switch (match[1]) {
      case ">=":
        return compared >= 0;
      case "<=":
        return compared <= 0;
      case ">":
        return compared > 0;
      case "<":
        return compared < 0;
      default:
        return false;
    }
  });
}

function rootLockSpec(entries: JsonRecord, name: string): string {
  const root = entries[""];
  if (!isRecord(root)) return unavailable();

  const declarations: string[] = [];
  for (const field of ["dependencies", "devDependencies"] as const) {
    const section = root[field];
    if (section === undefined) continue;
    if (!isRecord(section)) return unavailable();
    if (Object.prototype.hasOwnProperty.call(section, name)) {
      const value = section[name];
      if (typeof value !== "string" || value.trim().length === 0) {
        return unavailable();
      }
      declarations.push(value);
    }
  }

  if (
    declarations.length === 0 ||
    declarations.some((value) => value !== declarations[0])
  ) {
    return unavailable();
  }
  return declarations[0];
}

function concreteVersion(
  lock: JsonRecord | undefined,
  name: string,
  manifestSpec: string
): ConcreteVersion {
  if (lock) {
    const lockfileVersion = lock.lockfileVersion as 1 | 2 | 3;
    const entries = (lockfileVersion === 1 ? lock.dependencies : lock.packages) as
      | JsonRecord
      | undefined;
    const key = lockfileVersion === 1 ? name : `node_modules/${name}`;

    if (entries && Object.prototype.hasOwnProperty.call(entries, key)) {
      if (
        lockfileVersion !== 1 &&
        rootLockSpec(entries, name) !== manifestSpec
      ) {
        return unavailable();
      }

      const entry = entries[key];
      if (!isRecord(entry)) return unavailable();
      const version = exactPinnedVersion(entry.version, false);
      if (!version || !versionMatchesSpec(version, manifestSpec)) {
        return unavailable();
      }
      return {
        version,
        source:
          lockfileVersion === 1
            ? "package-lock.json v1"
            : `package-lock.json v${lockfileVersion}`,
      };
    }
  }

  const version = exactPinnedVersion(manifestSpec, true);
  if (!version) return unavailable();
  return { version, source: "package.json의 정확한 고정 버전" };
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
      return withManifestLocations(this.findingsFromOsv(osvResults, deps), pkgRaw);
    }

    // 2) 오프라인 폴백(조회 불가 환경). simulated:true로 명확히 표시.
    return withManifestLocations(this.offlineFallback(deps), pkgRaw);
  }

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const packageName = verificationPackage(finding.verificationKey);
    const manifest = verifyManifest(context.files["package.json"], packageName);
    const lock = parseLock(context.files["package-lock.json"]);

    if (!manifest.declared) {
      // A package removed from direct declarations may still be installed as a
      // transitive dependency. Without resolving that lock entry's provenance,
      // do not claim that the vulnerable component disappeared.
      if (lockContainsPackage(lock, packageName)) return unavailable();

      const security: VerificationTest = {
        id: id("vtest"),
        findingId: finding.id,
        label: "대상 의존성 제거 재검증",
        before: {
          label: "수정 전",
          request: `최초 의존성 탐지 기록 확인: ${packageName}`,
          response: "알려진 취약점이 있는 대상 의존성이 탐지됨",
          attackSucceeded: true,
        },
        after: {
          label: "수정 후",
          request: `package.json 및 package-lock.json 대상 의존성 확인: ${packageName}`,
          response: "대상 의존성이 직접 선언과 잠금 파일에서 제거됨",
          attackSucceeded: false,
        },
        outcome: "pass",
        createdAt: now(),
      };
      const regression: RegressionTest = {
        id: id("rtest"),
        findingId: finding.id,
        checks: [
          {
            label: "의존성 메타데이터 무결성",
            expectation: "package.json이 유효하고 제거된 패키지가 잠금 파일에 남아 있지 않아야 함",
            outcome: "pass",
            detail: `${packageName}이 직접 선언과 잠금 파일에 존재하지 않습니다. 빌드·기능 실행은 별도 CI에서 확인해야 합니다.`,
          },
        ],
        outcome: "pass",
        createdAt: now(),
      };
      return {
        findingId: finding.id,
        security,
        regression,
        resolved: true,
      };
    }

    const current = concreteVersion(lock, packageName, manifest.spec!);
    let osvResult: OsvPackageResult;
    try {
      const rows = await queryOsv([
        { name: packageName, version: current.version, ecosystem: "npm" },
      ]);
      if (
        rows.length !== 1 ||
        rows[0].name !== packageName ||
        rows[0].version !== current.version ||
        !Array.isArray(rows[0].vulns)
      ) {
        return unavailable();
      }
      osvResult = rows[0];
    } catch {
      return unavailable();
    }

    const stillVulnerable = osvResult.vulns.length > 0;
    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "대상 의존성 OSV 재검증",
      before: {
        label: "수정 전",
        request: `최초 의존성 탐지 기록 확인: ${packageName}`,
        response: "알려진 취약점이 있는 대상 의존성이 탐지됨",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `OSV.dev 조회: ${packageName}@${current.version}`,
        response: stillVulnerable
          ? `현재 버전에서 OSV 취약점 ${osvResult.vulns.length}건 확인 (${osvResult.vulns
              .map((vuln) => vuln.id)
              .join(", ")})`
          : "현재 버전에서 OSV 취약점이 확인되지 않음",
        attackSucceeded: stillVulnerable,
      },
      outcome: stillVulnerable ? "fail" : "pass",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "package.json 구문 및 구조",
          expectation: "package.json이 유효한 JSON이며 의존성 필드 구조가 유효해야 함",
          outcome: "pass",
          detail: "package.json 구문과 의존성 필드를 확인함",
        },
        {
          label: "대상 의존성 선언 유지",
          expectation: `${packageName} 의존성이 계속 선언되어야 함`,
          outcome: "pass",
          detail: "대상 의존성 선언을 확인함",
        },
        {
          label: "구체적인 현재 버전 확인",
          expectation: "잠금 파일 또는 정확히 고정된 선언에서 현재 버전을 확정해야 함",
          outcome: "pass",
          detail: `${current.source}에서 ${packageName}@${current.version} 확인`,
        },
      ],
      outcome: "pass",
      createdAt: now(),
    };

    return {
      findingId: finding.id,
      security,
      regression,
      resolved: security.outcome === "pass" && regression.outcome === "pass",
    };
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
          label: "공개 보안 문제 목록(OSV.dev) 조회 결과",
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
        // 제목에 패키지 이름을 넣지 않는다(이름의 단어가 findingMerge의 문제 종류 분류를 바꿀 수 있음).
        title: "프로젝트에서 사용하는 외부 도구의 현재 버전에 알려진 보안 문제가 있어요",
        severity: maxCvss >= 9 ? "critical" : maxCvss >= 7 ? "high" : maxCvss > 0 ? "medium" : "medium",
        category: "Vulnerable Dependencies",
        owasp: "A06 – Vulnerable and Outdated Components",
        cwe: "CWE-1035",
        cvss: maxCvss || undefined,
        description: `${r.name}@${r.version}에 알려진 보안 문제가 있어요 (OSV: ${ids}).`,
        humanReadableImpact: `${r.name} ${r.version} 버전에 공개된 보안 문제가 ${r.vulns.length}건 있어요. 이 프로젝트가 문제가 된 기능을 쓰고 있다면, 누군가 이 알려진 문제를 노려 공격할 수 있어요.`,
        whyItMatters: `공개 보안 문제 목록(OSV.dev)을 조회해 ${r.name} ${r.version} 버전이 영향을 받는다고 확인했어요 (${ids}). 이 프로젝트 코드가 문제가 된 기능을 실제로 쓰는지, 실제로 악용될 수 있는지는 확인하지 않았어요.`,
        evidence,
        remediation: fixed
          ? `${r.name}을(를) ${fixed} 이상 버전으로 올린 뒤, 앱이 평소처럼 동작하는지 확인해 주세요.`
          : `${r.name}에 문제가 고쳐진 새 버전이 있는지 확인해 올려 주세요. 아직 고쳐진 버전이 없다면 다른 도구로 바꿀지 검토해 주세요.`,
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
          title: "프로젝트에서 사용하는 외부 도구의 현재 버전에 알려진 보안 문제가 있어요 (인터넷 조회 없이 판정)",
          severity: known.cvss >= 7 ? "high" : "medium",
          category: "Vulnerable Dependencies",
          owasp: "A06 – Vulnerable and Outdated Components",
          cwe: "CWE-1035",
          cvss: known.cvss,
          description: `${known.pkg}@${installed} 버전이 문제가 고쳐진 버전 ${known.vulnerableBelow}보다 낮아요 (OSV 조회 실패 — 내장 목록으로 판정).`,
          humanReadableImpact: `${known.pkg} ${installed} 버전은 보안 문제가 고쳐진 ${known.vulnerableBelow} 버전보다 낮아요. 이 프로젝트가 문제가 된 기능을 쓰고 있다면, 누군가 이 알려진 문제를 노려 공격할 수 있어요.`,
          whyItMatters:
            "공개 보안 문제 목록(OSV.dev)에 연결하지 못해, 미리 넣어 둔 짧은 목록과 버전만 비교했어요. 이 프로젝트에서 실제로 악용될 수 있는지는 확인하지 않았어요. 인터넷에 연결된 상태로 다시 점검하면 더 정확해요.",
          evidence: [
            {
              id: id("ev"),
              kind: "scanner_output",
              label: "버전 비교 결과 (인터넷 조회 없이 판정)",
              content: `패키지: ${known.pkg}\n설치됨: ${installed}\n패치 버전: ${known.vulnerableBelow}\n참고: ${known.osvId}`,
            },
          ],
          remediation: `${known.pkg}을(를) ${known.vulnerableBelow} 이상 버전으로 올린 뒤, 앱이 평소처럼 동작하는지 확인해 주세요.`,
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
