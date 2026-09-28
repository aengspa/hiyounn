import type { Check } from "@/lib/rules/types";
import type { ProjectContext } from "@/lib/scanners/types";
import { isPublicBaasKey, jwtPayload } from "@/lib/scanners/deployedRuleTools";
import { RuleToolRuntime, gap, safeLabel, type ToolResult } from "@/lib/scanners/ruleToolRuntime";

type LinkedProject = NonNullable<ProjectContext["linkedBaasProjects"]>[number];
function validateLinked(project: LinkedProject): void {
  const url = new URL(project.url);
  if (url.protocol !== "https:" || url.username || url.password || url.port) throw new Error("BaaS 연결 URL이 유효하지 않습니다.");
  if (project.provider === "supabase") {
    if (!/^[a-z0-9-]+\.supabase\.co$/.test(url.hostname) || !project.publicKey || !isPublicBaasKey(project.publicKey)) {
      throw new Error("Supabase 공개 키(anon/publishable)와 소스 연결 증거가 필요합니다. 관리자 키는 사용할 수 없습니다.");
    }
  } else if (!/^[a-z0-9.-]+\.(?:firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname) &&
    !["firestore.googleapis.com", "firebasestorage.googleapis.com"].includes(url.hostname)) {
    throw new Error("허용된 Firebase 호스트가 아닙니다.");
  }
}

function baasHeaders(project: LinkedProject, token?: string): Record<string, string> {
  if (token && (jwtPayload(token)?.role === "service_role" || token.startsWith("sb_secret_"))) {
    throw new Error("관리자 자격증명은 테스트 세션으로 사용할 수 없습니다.");
  }
  return project.publicKey ? { apikey: project.publicKey, authorization: `Bearer ${token ?? project.publicKey}` } : {};
}

async function supabaseTables(runtime: RuleToolRuntime, project: LinkedProject): Promise<string[]> {
  const key = `tables:${project.url}`;
  if (runtime.cache.has(key)) return runtime.cache.get(key) as string[];
  let tables = project.tables ?? [];
  if (!tables.length) {
    const response = await runtime.request(new URL("/rest/v1/", project.url).toString(), { headers: baasHeaders(project), maxBytes: 256 * 1024 });
    if (response.status !== 200) throw new Error("Supabase 테이블 목록을 조회하지 못했습니다.");
    tables = Object.keys((JSON.parse(response.body) as { paths?: Record<string, unknown> }).paths ?? {}).map((path) => path.slice(1));
  }
  tables = [...new Set(tables)].filter((name) => /^[A-Za-z_][\w]*$/.test(name));
  runtime.cache.set(key, tables);
  return tables;
}

async function anonymousRead(runtime: RuleToolRuntime, check: Check, project: LinkedProject): Promise<ToolResult> {
  const findings: ToolResult["findings"] = [];
  if (check.id === "supabase-list-exposed-tables") {
    const tables = await supabaseTables(runtime, project);
    return tables.length ? { findings } : gap("점검할 Supabase 테이블을 찾지 못했습니다.");
  }
  if (check.id === "supabase-anon-select") {
    const tables = await supabaseTables(runtime, project);
    if (!tables.length) return gap("소스 또는 OpenAPI에서 테이블을 찾지 못했습니다.");
    for (const table of tables.slice(0, 20)) {
      const target = new URL(`/rest/v1/${encodeURIComponent(table)}`, project.url);
      target.searchParams.set("select", "*"); target.searchParams.set("limit", "1");
      const response = await runtime.request(target.toString(), { headers: baasHeaders(project), maxBytes: 32 * 1024 });
      if ([401, 403].includes(response.status)) continue;
      if (response.status !== 200) return { findings, gap: "일부 테이블을 조회하지 못했습니다." };
      const rows: unknown = JSON.parse(response.body);
      if (!Array.isArray(rows)) return { findings, gap: "예상한 Supabase 배열 응답이 아닙니다." };
      if (rows.length) findings.push(runtime.finding(check,
        "공개 키로 데이터 행을 읽을 수 있습니다. 의도적으로 공개한 데이터인지 확인하세요.",
        `Supabase table ${safeLabel(table)}: anonymous GET, HTTP 200; 행 값 생략`,
        { key: `tool:${runtime.rule.id}:${check.id}:${table}` }));
    }
    return { findings, gap: tables.length > 20 ? "테이블 상한으로 일부 테이블은 검사하지 못했습니다." : undefined };
  }
  if (check.id === "firebase-anon-read") {
    const host = new URL(project.url).hostname;
    if (host === "firebasestorage.googleapis.com") return gap("Firebase Storage 연결에는 DB 컬렉션 정보가 없습니다.");
    if (host === "firestore.googleapis.com") {
      if (!project.projectId || !project.collections?.length) return gap("Firestore 프로젝트 ID와 소스에서 확인된 컬렉션이 필요합니다.");
      for (const collection of project.collections.slice(0, 10)) {
        if (!/^[A-Za-z_][\w-]*$/.test(collection) || !/^[a-z0-9-]+$/.test(project.projectId)) return gap("Firestore 식별자가 유효하지 않습니다.");
        const target = `https://firestore.googleapis.com/v1/projects/${project.projectId}/databases/(default)/documents/${collection}?pageSize=1`;
        const response = await runtime.request(target, { maxBytes: 32 * 1024 });
        if ([401, 403].includes(response.status)) continue;
        if (response.status !== 200) return { findings, gap: "일부 Firestore 컬렉션을 조회하지 못했습니다." };
        const body = JSON.parse(response.body) as { documents?: unknown[] };
        if (body.documents?.length) findings.push(runtime.finding(check,
          "Firestore 컬렉션이 익명에게 데이터를 반환합니다. 공개 의도를 검토하세요.",
          `Firestore collection ${safeLabel(collection)}: anonymous HTTP 200; 문서 값 생략`));
      }
      return { findings };
    }
    const target = new URL("/.json", project.url); target.searchParams.set("shallow", "true");
    const response = await runtime.request(target.toString(), { maxBytes: 16 * 1024 });
    if ([401, 403].includes(response.status)) return { findings };
    if (response.status !== 200) return gap("Firebase Realtime DB 요청을 완료하지 못했습니다.");
    const body: unknown = JSON.parse(response.body);
    if (body !== null) findings.push(runtime.finding(check,
      "Realtime DB의 루트 구조를 익명으로 읽을 수 있습니다. 공개 의도를 검토하세요.",
      "Firebase anonymous shallow GET: HTTP 200; 키/값 생략"));
    return { findings };
  }
  if (check.id === "storage-anon-list") {
    if (project.provider === "supabase") {
      const response = await runtime.request(new URL("/storage/v1/bucket", project.url).toString(), { headers: baasHeaders(project), maxBytes: 32 * 1024 });
      if ([401, 403].includes(response.status)) return { findings };
      if (response.status !== 200) return gap("Storage 목록 요청을 완료하지 못했습니다.");
      const buckets: unknown = JSON.parse(response.body);
      if (Array.isArray(buckets) && buckets.length) findings.push(runtime.finding(check,
        "공개 자격증명으로 버킷 목록을 읽을 수 있습니다. 공개 의도를 검토하세요.", "Supabase bucket-list: anonymous HTTP 200; 버킷 값 생략"));
    } else {
      if (!project.buckets?.length) return gap("소스에서 확인된 Firebase Storage 버킷이 필요합니다.");
      for (const bucket of project.buckets.slice(0, Math.min(10, Number(check.params?.maxBuckets ?? 10)))) {
        if (!/^[a-z0-9._-]+$/.test(bucket)) return gap("버킷 이름이 유효하지 않습니다.");
        const target = `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}/o?maxResults=1`;
        const response = await runtime.request(target, { maxBytes: 32 * 1024 });
        if ([401, 403].includes(response.status)) continue;
        if (response.status !== 200) return { findings, gap: "Firebase Storage 목록 요청에 실패했습니다." };
        const body = JSON.parse(response.body) as { items?: unknown[]; prefixes?: unknown[] };
        if (body.items?.length || body.prefixes?.length) findings.push(runtime.finding(check,
          "Firebase Storage 목록이 익명에게 공개됩니다. 공개 의도를 검토하세요.", "Firebase Storage anonymous list: HTTP 200; 객체 이름 생략"));
      }
    }
    return { findings };
  }
  return gap(`지원하지 않는 익명 BaaS 체크: ${check.id}`);
}

async function crossUser(runtime: RuleToolRuntime, check: Check, project: LinkedProject): Promise<ToolResult> {
  const fixture = runtime.context.baasTestFixture;
  const sessions = runtime.context.testSessions;
  const a = sessions?.test_user_a, b = sessions?.test_user_b;
  if (!fixture?.testOnly || !a || !b || !/^[A-Za-z_][\w]*$/.test(fixture.table) || !/^[A-Za-z0-9_-]{1,128}$/.test(fixture.rowId)) return gap("격리된 B 소유 테스트 행과 A/B 세션이 필요합니다.");
  const target = new URL(`/rest/v1/${fixture.table}`, project.url);
  target.searchParams.set("id", `eq.${fixture.rowId}`); target.searchParams.set("limit", "1");
  const baseline = await runtime.request(target.toString(), { headers: baasHeaders(project, b.bearerToken), maxBytes: 16 * 1024 });
  if (baseline.status !== 200) return gap("B 소유자 대조 요청에 실패했습니다.");
  const baselineRows = JSON.parse(baseline.body) as Array<Record<string, unknown>>;
  if (!Array.isArray(baselineRows) || baselineRows.length !== 1 || String(baselineRows[0].id) !== fixture.rowId) return gap("B 테스트 행의 단일 객체 대조를 확인하지 못했습니다.");
  if (check.id === "rls-owner-read") return { findings: [] };
  if (check.id === "rls-cross-user-read") {
    const response = await runtime.request(target.toString(), { headers: baasHeaders(project, a.bearerToken), maxBytes: 16 * 1024 });
    if ([401, 403].includes(response.status)) return { findings: [] };
    if (response.status !== 200) return gap("교차 사용자 읽기 요청에 실패했습니다.");
    const rows: unknown = JSON.parse(response.body);
    if (!Array.isArray(rows)) return gap("교차 사용자 응답 형식이 유효하지 않습니다.");
    return { findings: rows.some((row) => String(row?.id) === fixture.rowId) ? [runtime.finding(check,
      "A 세션으로 B 소유 테스트 행을 읽을 수 있습니다.", "B 소유자 대조: 단일 테스트 행; A 교차 조회: 동일 행 반환(값 생략)", { confirmed: true })] : [] };
  }
  if (check.id !== "rls-cross-user-update") return gap(`지원하지 않는 RLS 체크: ${check.id}`);
  const fields = Object.keys(fixture.probeValues);
  if (!fields.length || fields.some((field) => !/^vsa_probe_[A-Za-z0-9_]+$/.test(field) || !(field in fixture.originalValues))) {
    return gap("변경 프로브는 원복 값이 준비된 vsa_probe_ 테스트 전용 필드만 허용합니다.");
  }
  const restoreValues = Object.fromEntries(fields.map((field) => [field, fixture.originalValues[field]]));
  if (fields.some((field) => baselineRows[0][field] !== restoreValues[field])) return gap("원복 값과 B 테스트 행의 현재 값이 일치하지 않습니다.");
  let changed = false;
  try {
    const response = await runtime.request(target.toString(), {
      method: "PATCH", allowUnsafeMethod: true, body: JSON.stringify(fixture.probeValues),
      headers: { ...baasHeaders(project, a.bearerToken), "content-type": "application/json", prefer: "return=representation" }, maxBytes: 16 * 1024,
    });
    if ([401, 403].includes(response.status)) return { findings: [] };
    if (response.status < 200 || response.status >= 300) return gap("교차 사용자 수정 요청에 실패했습니다.");
    const rows: unknown = JSON.parse(response.body || "[]");
    changed = Array.isArray(rows) && rows.some((row) => String(row?.id) === fixture.rowId && fields.every((field) => row[field] === fixture.probeValues[field]));
  } finally {
    // Always restore even after a timeout/parse error: the write may have reached the server.
    const restored = await runtime.restore(target.toString(), {
      method: "PATCH", allowUnsafeMethod: true, body: JSON.stringify(restoreValues),
      headers: { ...baasHeaders(project, b.bearerToken), "content-type": "application/json", prefer: "return=representation" }, maxBytes: 16 * 1024,
    });
    const restoredRows = JSON.parse(restored.body || "[]") as Array<Record<string, unknown>>;
    if (restored.status !== 200 || !Array.isArray(restoredRows) || restoredRows.length !== 1 || !fields.every((field) => restoredRows[0][field] === restoreValues[field])) {
      throw new Error("테스트 행 원복 확인 실패 — 즉시 수동 확인이 필요합니다.");
    }
  }
  return { findings: changed ? [runtime.finding(check,
    "A 세션이 B의 테스트 필드를 수정했습니다. B 세션으로 원복을 확인했습니다.", "교차 PATCH: 단일 테스트 행 변경; owner PATCH: 원복 확인(값 생략)", { confirmed: true })] : [] };
}

async function baasTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  const projects = (runtime.context.linkedBaasProjects ?? []).filter((project) =>
    runtime.rule.id.startsWith("BAAS-001") ? project.provider === "supabase" :
      runtime.rule.id.startsWith("BAAS-002") ? project.provider === "firebase" : true);
  if (!projects.length) return gap("검증된 소스/번들에서 연결된 BaaS 프로젝트를 찾지 못했습니다.");
  const findings: ToolResult["findings"] = [];
  const gaps: string[] = [];
  for (const project of projects) {
    validateLinked(project);
    const result = runtime.rule.mode === "C" ? await crossUser(runtime, check, project) : await anonymousRead(runtime, check, project);
    findings.push(...result.findings); if (result.gap) gaps.push(result.gap);
  }
  return { findings, gap: gaps.length ? gaps.join(" ") : undefined };
}

async function jwtTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  const a = runtime.context.testSessions?.test_user_a, b = runtime.context.testSessions?.test_user_b;
  if (!a || !b || a.bearerToken === b.bearerToken) return gap("서로 다른 테스트 사용자 A/B 세션이 필요합니다.");
  const target = runtime.targetUrl(a.probeUrl);
  const parts = a.bearerToken.split(".");
  if (parts.length !== 3) return gap("테스트 사용자 A의 토큰이 JWT 형식이 아닙니다.");
  const payload = jwtPayload(a.bearerToken);
  if (!payload || payload.role === "service_role" || jwtPayload(b.bearerToken)?.role === "service_role") return gap("일반 사용자 JWT만 점검할 수 있습니다.");
  if (!runtime.cache.has("jwt-controls")) {
    const anonymous = await runtime.request(target, { maxBytes: 32 * 1024 });
    const valid = await runtime.request(target, { headers: { authorization: `Bearer ${a.bearerToken}` }, maxBytes: 32 * 1024 });
    if (![401, 403].includes(anonymous.status) || valid.status !== 200 || !valid.body.trim()) return gap("익명 거부/정상 토큰 허용 대조가 성립하는 보호된 읽기 API가 필요합니다.");
    runtime.cache.set("jwt-controls", valid.body);
  }
  let token: string;
  if (check.id === "jwt-alg-none") {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    token = `${Buffer.from(JSON.stringify({ ...header, alg: "none" })).toString("base64url")}.${parts[1]}.`;
  } else if (check.id === "jwt-signature-stripped") token = `${parts[0]}.${parts[1]}.`;
  else if (check.id === "jwt-subject-swapped") {
    const subject = b.subject ?? jwtPayload(b.bearerToken)?.sub;
    if (typeof subject !== "string" || subject === payload.sub) return gap("서로 다른 테스트 사용자 subject가 필요합니다.");
    // Keep the original signature: any acceptance proves signature validation failure.
    token = `${parts[0]}.${Buffer.from(JSON.stringify({ ...payload, sub: subject })).toString("base64url")}.${parts[2]}`;
  } else return gap(`지원하지 않는 JWT 체크: ${check.id}`);
  const response = await runtime.request(target, { headers: { authorization: `Bearer ${token}` }, maxBytes: 32 * 1024 });
  if ([401, 403].includes(response.status)) return { findings: [] };
  if (response.status !== 200 || !response.body.trim()) return gap("변조 JWT 응답으로 인증 우회 여부를 판정하지 못했습니다.");
  // An HTTP 200 error document is not an accepted session. Require protected response parity.
  if (response.body !== runtime.cache.get("jwt-controls")) return gap("변조 응답이 정상 보호 데이터와 달라 자동 확정할 수 없습니다.");
  return { findings: [runtime.finding(check, "보호된 읽기 API가 서명 무효 JWT에 정상 토큰과 동일한 보호 응답을 반환했습니다.",
    `${check.id}: anonymous HTTP 401/403; valid JWT HTTP 200; invalid JWT HTTP 200 with protected-response parity (토큰/응답 값 생략)`, { confirmed: true })] };
}

export async function executeAccountTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  return check.toolId === "jwt_tamper_probe" ? jwtTool(runtime, check) : baasTool(runtime, check);
}
