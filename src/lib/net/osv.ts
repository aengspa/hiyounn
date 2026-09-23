/**
 * OSV.dev 클라이언트 (SEC-004 실제 의존성 취약점 조회).
 *
 * OSV.dev는 Google이 운영하는 무료·무인증 오픈소스 취약점 데이터베이스다.
 *   - POST /v1/querybatch : {name, ecosystem, version} 배치 → 취약점 ID 목록
 *   - GET  /v1/vulns/{id} : 개별 취약점 상세(요약/심각도/수정 버전)
 *
 * 이 모듈은 우리(스캐너)가 신뢰하는 고정 엔드포인트로 나가는 아웃바운드 호출이므로
 * safeFetch(대상 앱 SSRF 가드)가 아니라 타임아웃만 두른 fetch를 쓴다. 대상 앱의
 * 코드/비밀은 전송하지 않고, 공개 패키지명·버전만 보낸다.
 *
 * 네트워크 실패/오프라인이면 예외를 던지고, 스캐너는 이를 coverage_gap으로 남긴다
 * (조회 못 했다고 "안전"으로 단정하지 않는다).
 */

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";

export interface OsvPackageQuery {
  name: string;
  version: string;
  ecosystem?: string; // 기본 npm
}

export interface OsvVulnSummary {
  id: string;
  summary?: string;
  /** CVSS 점수(있으면). severity 배열에서 추출. */
  cvss?: number;
  /** 이 패키지에서 취약점을 수정한 첫 버전(있으면). */
  fixedVersion?: string;
  aliases?: string[];
}

export interface OsvPackageResult {
  name: string;
  version: string;
  vulns: OsvVulnSummary[];
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<unknown> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

interface BatchResponse {
  results?: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
}

interface VulnDetail {
  id: string;
  summary?: string;
  aliases?: string[];
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

/**
 * OSV severity에서 CVSS base score를 뽑는다.
 * score가 숫자면 그대로, CVSS 벡터 문자열이면 v3.x base score를 계산한다.
 */
function parseCvss(detail: VulnDetail): number | undefined {
  const s = detail.severity?.find((x) => x.type?.startsWith("CVSS"));
  if (!s?.score) return undefined;
  const num = Number(s.score);
  if (Number.isFinite(num)) return num;
  if (/^CVSS:3\.[01]/.test(s.score)) return cvss3BaseScore(s.score);
  return undefined;
}

/** CVSS v3.0/3.1 벡터 → base score(간이 구현, 소수 첫째 자리 반올림 올림). */
function cvss3BaseScore(vector: string): number | undefined {
  const parts = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((kv) => kv.split(":") as [string, string])
  );
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const prChanged: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
  const prUnchanged: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };

  const scopeChanged = parts.S === "C";
  const av = AV[parts.AV];
  const ac = AC[parts.AC];
  const ui = UI[parts.UI];
  const pr = (scopeChanged ? prChanged : prUnchanged)[parts.PR];
  const c = CIA[parts.C];
  const i = CIA[parts.I];
  const a = CIA[parts.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return undefined;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return Math.ceil(raw * 10) / 10; // roundup to 1 decimal
}

/** affected에서 해당 패키지의 첫 fixed 버전을 찾는다. */
function firstFixed(detail: VulnDetail, pkg: string): string | undefined {
  for (const a of detail.affected ?? []) {
    if (a.package?.name && a.package.name !== pkg) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return undefined;
}

/**
 * 주어진 패키지 목록을 OSV에 배치 조회하고, 취약점이 있는 패키지의 상세를 채워 반환.
 * 네트워크 실패 시 예외를 던진다.
 */
export async function queryOsv(
  packages: OsvPackageQuery[],
  timeoutMs = 8000
): Promise<OsvPackageResult[]> {
  if (packages.length === 0) return [];

  const body = {
    queries: packages.map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem ?? "npm" },
      version: p.version,
    })),
  };

  const batch = (await fetchJson(
    OSV_BATCH_URL,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    },
    timeoutMs
  )) as BatchResponse;

  const results: OsvPackageResult[] = [];
  const detailCache = new Map<string, OsvVulnSummary>();

  const rows = batch.results ?? [];
  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const vulnRefs = rows[i]?.vulns ?? [];
    if (vulnRefs.length === 0) continue;

    const vulns: OsvVulnSummary[] = [];
    for (const ref of vulnRefs) {
      if (detailCache.has(ref.id)) {
        vulns.push(detailCache.get(ref.id)!);
        continue;
      }
      try {
        const detail = (await fetchJson(
          `${OSV_VULN_URL}${encodeURIComponent(ref.id)}`,
          { method: "GET" },
          timeoutMs
        )) as VulnDetail;
        const summary: OsvVulnSummary = {
          id: detail.id,
          summary: detail.summary,
          cvss: parseCvss(detail),
          fixedVersion: firstFixed(detail, pkg.name),
          aliases: detail.aliases,
        };
        detailCache.set(ref.id, summary);
        vulns.push(summary);
      } catch {
        // 상세 조회 실패해도 ID만이라도 보고.
        vulns.push({ id: ref.id });
      }
    }
    results.push({ name: pkg.name, version: pkg.version, vulns });
  }

  return results;
}
