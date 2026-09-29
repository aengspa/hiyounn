import type { Check } from "@/lib/rules/types";
import type { ProjectContext } from "@/lib/scanners/types";
import { isPublicBaasKey, jwtPayload } from "@/lib/scanners/deployedRuleTools";
import { RuleToolRuntime, gap, safeLabel, type ToolResult } from "@/lib/scanners/ruleToolRuntime";

type LinkedProject = NonNullable<ProjectContext["linkedBaasProjects"]>[number];
function validateLinked(project: LinkedProject): void {
  const url = new URL(project.url);
  if (url.protocol !== "https:" || url.username || url.password || url.port) throw new Error("데이터베이스 서비스(BaaS) 연결 주소가 올바르지 않아 확인하지 못했어요.");
  if (project.provider === "supabase") {
    if (!/^[a-z0-9-]+\.supabase\.co$/.test(url.hostname) || !project.publicKey || !isPublicBaasKey(project.publicKey)) {
      throw new Error("코드에서 Supabase 주소와 공개 키(anon/publishable)를 함께 찾지 못해 확인하지 못했어요. 관리자 키로는 시험하지 않아요.");
    }
  } else if (!/^[a-z0-9.-]+\.(?:firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname) &&
    !["firestore.googleapis.com", "firebasestorage.googleapis.com"].includes(url.hostname)) {
    throw new Error("Firebase 공식 주소가 아니라 요청을 보내지 않았어요.");
  }
}

function baasHeaders(project: LinkedProject, token?: string): Record<string, string> {
  if (token && (jwtPayload(token)?.role === "service_role" || token.startsWith("sb_secret_"))) {
    throw new Error("관리자 키는 시험용 로그인으로 쓸 수 없어 확인하지 않았어요.");
  }
  return project.publicKey ? { apikey: project.publicKey, authorization: `Bearer ${token ?? project.publicKey}` } : {};
}

async function supabaseTables(runtime: RuleToolRuntime, project: LinkedProject): Promise<string[]> {
  const key = `tables:${project.url}`;
  if (runtime.cache.has(key)) return runtime.cache.get(key) as string[];
  let tables = project.tables ?? [];
  if (!tables.length) {
    const response = await runtime.request(new URL("/rest/v1/", project.url).toString(), { headers: baasHeaders(project), maxBytes: 256 * 1024 });
    if (response.status !== 200) throw new Error("Supabase 테이블 목록을 가져오지 못해 확인하지 못했어요.");
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
    return tables.length ? { findings } : gap("확인할 Supabase 테이블을 찾지 못했어요.");
  }
  if (check.id === "supabase-anon-select") {
    const tables = await supabaseTables(runtime, project);
    if (!tables.length) return gap("코드나 Supabase 목록에서 테이블 이름을 찾지 못해 확인하지 못했어요.");
    for (const table of tables.slice(0, 20)) {
      const target = new URL(`/rest/v1/${encodeURIComponent(table)}`, project.url);
      target.searchParams.set("select", "*"); target.searchParams.set("limit", "1");
      const response = await runtime.request(target.toString(), { headers: baasHeaders(project), maxBytes: 32 * 1024 });
      if ([401, 403].includes(response.status)) continue;
      if (response.status !== 200) return { findings, gap: "일부 테이블은 응답을 받지 못해 확인하지 못했어요." };
      const rows: unknown = JSON.parse(response.body);
      if (!Array.isArray(rows)) return { findings, gap: "Supabase 응답 형식이 예상과 달라 판단하지 못했어요." };
      if (rows.length) findings.push(runtime.finding(check,
        `로그인하지 않고 앱의 공개 키만으로 ${safeLabel(table)} 테이블에 요청했더니 데이터가 돌아왔어요. 누구나 볼 수 있게 일부러 공개한 데이터가 아니라면 다른 사람의 정보가 보일 수 있어요.`,
        `Supabase table ${safeLabel(table)}: anonymous GET, HTTP 200; 행 값 생략`,
        { key: `tool:${runtime.rule.id}:${check.id}:${table}` }));
    }
    return { findings, gap: tables.length > 20 ? "한 번에 확인할 수 있는 수를 넘어 일부 테이블은 확인하지 못했어요." : undefined };
  }
  if (check.id === "firebase-anon-read") {
    const host = new URL(project.url).hostname;
    if (host === "firebasestorage.googleapis.com") return gap("Firebase 파일 저장소 연결이라 데이터베이스 읽기 검사는 하지 않았어요.");
    if (host === "firestore.googleapis.com") {
      if (!project.projectId || !project.collections?.length) return gap("코드에서 Firestore 프로젝트 ID와 컬렉션 이름을 찾지 못해 확인하지 못했어요.");
      for (const collection of project.collections.slice(0, 10)) {
        if (!/^[A-Za-z_][\w-]*$/.test(collection) || !/^[a-z0-9-]+$/.test(project.projectId)) return gap("Firestore 이름 형식이 올바르지 않아 요청을 보내지 않았어요.");
        const target = `https://firestore.googleapis.com/v1/projects/${project.projectId}/databases/(default)/documents/${collection}?pageSize=1`;
        const response = await runtime.request(target, { maxBytes: 32 * 1024 });
        if ([401, 403].includes(response.status)) continue;
        if (response.status !== 200) return { findings, gap: "일부 Firestore 컬렉션은 응답을 받지 못해 확인하지 못했어요." };
        const body = JSON.parse(response.body) as { documents?: unknown[] };
        if (body.documents?.length) findings.push(runtime.finding(check,
          `로그인하지 않고 Firestore의 ${safeLabel(collection)} 컬렉션에 요청했더니 데이터가 돌아왔어요. 누구나 볼 수 있게 일부러 공개한 데이터가 아니라면 다른 사람의 정보가 보일 수 있어요.`,
          `Firestore collection ${safeLabel(collection)}: anonymous HTTP 200; 문서 값 생략`));
      }
      return { findings };
    }
    const target = new URL("/.json", project.url); target.searchParams.set("shallow", "true");
    const response = await runtime.request(target.toString(), { maxBytes: 16 * 1024 });
    if ([401, 403].includes(response.status)) return { findings };
    if (response.status !== 200) return gap("Firebase Realtime DB에서 응답을 받지 못해 확인하지 못했어요.");
    const body: unknown = JSON.parse(response.body);
    if (body !== null) findings.push(runtime.finding(check,
      "로그인하지 않고 Firebase Realtime DB에 요청했더니 가장 위 단계의 데이터 목록이 보였어요. 일부러 공개한 것이 아니라면 누구나 데이터베이스 구조와 내용을 볼 수 있어요.",
      "Firebase anonymous shallow GET: HTTP 200; 키/값 생략"));
    return { findings };
  }
  if (check.id === "storage-anon-list") {
    if (project.provider === "supabase") {
      const response = await runtime.request(new URL("/storage/v1/bucket", project.url).toString(), { headers: baasHeaders(project), maxBytes: 32 * 1024 });
      if ([401, 403].includes(response.status)) return { findings };
      if (response.status !== 200) return gap("파일 저장소(Storage) 목록 요청에 응답을 받지 못해 확인하지 못했어요.");
      const buckets: unknown = JSON.parse(response.body);
      if (Array.isArray(buckets) && buckets.length) findings.push(runtime.finding(check,
        "로그인하지 않고 앱의 공개 키만으로 파일 저장소(Storage)의 폴더(버킷) 목록을 볼 수 있었어요. 일부러 공개한 것이 아니라면 저장된 파일이 드러날 수 있어요.", "Supabase bucket-list: anonymous HTTP 200; 버킷 값 생략"));
    } else {
      if (!project.buckets?.length) return gap("코드에서 Firebase 파일 저장소(버킷) 이름을 찾지 못해 확인하지 못했어요.");
      for (const bucket of project.buckets.slice(0, Math.min(10, Number(check.params?.maxBuckets ?? 10)))) {
        if (!/^[a-z0-9._-]+$/.test(bucket)) return gap("버킷 이름 형식이 올바르지 않아 요청을 보내지 않았어요.");
        const target = `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}/o?maxResults=1`;
        const response = await runtime.request(target, { maxBytes: 32 * 1024 });
        if ([401, 403].includes(response.status)) continue;
        if (response.status !== 200) return { findings, gap: "Firebase 파일 저장소 목록 요청에 응답을 받지 못해 확인하지 못했어요." };
        const body = JSON.parse(response.body) as { items?: unknown[]; prefixes?: unknown[] };
        if (body.items?.length || body.prefixes?.length) findings.push(runtime.finding(check,
          "로그인하지 않고 Firebase 파일 저장소에 요청했더니 파일 목록이 보였어요. 일부러 공개한 것이 아니라면 누구나 저장된 파일을 찾아볼 수 있어요.", "Firebase Storage anonymous list: HTTP 200; 객체 이름 생략"));
      }
    }
    return { findings };
  }
  return gap(`아직 지원하지 않는 로그인 없는 접근 검사라 하지 않았어요: ${check.id}`);
}

async function crossUser(runtime: RuleToolRuntime, check: Check, project: LinkedProject): Promise<ToolResult> {
  const fixture = runtime.context.baasTestFixture;
  const sessions = runtime.context.testSessions;
  const a = sessions?.test_user_a, b = sessions?.test_user_b;
  if (!fixture?.testOnly || !a || !b || !/^[A-Za-z_][\w]*$/.test(fixture.table) || !/^[A-Za-z0-9_-]{1,128}$/.test(fixture.rowId)) return gap("시험용 계정 A·B와 계정 B가 가진 시험용 데이터 한 줄이 준비되지 않아 이 검사는 하지 않았어요.");
  const target = new URL(`/rest/v1/${fixture.table}`, project.url);
  target.searchParams.set("id", `eq.${fixture.rowId}`); target.searchParams.set("limit", "1");
  const baseline = await runtime.request(target.toString(), { headers: baasHeaders(project, b.bearerToken), maxBytes: 16 * 1024 });
  if (baseline.status !== 200) return gap("계정 B로 자기 시험용 데이터를 읽는 요청이 실패해 비교 기준을 만들지 못했어요.");
  const baselineRows = JSON.parse(baseline.body) as Array<Record<string, unknown>>;
  if (!Array.isArray(baselineRows) || baselineRows.length !== 1 || String(baselineRows[0].id) !== fixture.rowId) return gap("계정 B의 시험용 데이터가 정확히 한 줄로 확인되지 않아 비교하지 못했어요.");
  if (check.id === "rls-owner-read") return { findings: [] };
  if (check.id === "rls-cross-user-read") {
    const response = await runtime.request(target.toString(), { headers: baasHeaders(project, a.bearerToken), maxBytes: 16 * 1024 });
    if ([401, 403].includes(response.status)) return { findings: [] };
    if (response.status !== 200) return gap("계정 A로 계정 B의 데이터를 읽는 요청에 응답을 받지 못해 확인하지 못했어요.");
    const rows: unknown = JSON.parse(response.body);
    if (!Array.isArray(rows)) return gap("계정 A로 보낸 요청의 응답 형식이 예상과 달라 판단하지 못했어요.");
    return { findings: rows.some((row) => String(row?.id) === fixture.rowId) ? [runtime.finding(check,
      "시험용 계정 A로 로그인해 계정 B의 시험용 데이터를 요청했더니 그 데이터가 그대로 돌아왔어요. 로그인한 사람이 다른 사람의 정보를 볼 수 있어요.", "B 소유자 대조: 단일 테스트 행; A 교차 조회: 동일 행 반환(값 생략)", { confirmed: true })] : [] };
  }
  if (check.id !== "rls-cross-user-update") return gap(`아직 지원하지 않는 데이터 보호 규칙(RLS) 검사라 하지 않았어요: ${check.id}`);
  const fields = Object.keys(fixture.probeValues);
  if (!fields.length || fields.some((field) => !/^vsa_probe_[A-Za-z0-9_]+$/.test(field) || !(field in fixture.originalValues))) {
    return gap("수정 시험은 원래 값이 준비된 시험 전용 칸(vsa_probe_로 시작)에서만 해요. 그런 칸이 없어 이 검사는 하지 않았어요.");
  }
  const restoreValues = Object.fromEntries(fields.map((field) => [field, fixture.originalValues[field]]));
  if (fields.some((field) => baselineRows[0][field] !== restoreValues[field])) return gap("되돌릴 원래 값과 계정 B 시험용 데이터의 현재 값이 달라, 안전하게 되돌릴 수 없어 이 검사는 하지 않았어요.");
  let changed = false;
  try {
    const response = await runtime.request(target.toString(), {
      method: "PATCH", allowUnsafeMethod: true, body: JSON.stringify(fixture.probeValues),
      headers: { ...baasHeaders(project, a.bearerToken), "content-type": "application/json", prefer: "return=representation" }, maxBytes: 16 * 1024,
    });
    if ([401, 403].includes(response.status)) return { findings: [] };
    if (response.status < 200 || response.status >= 300) return gap("계정 A로 계정 B의 데이터를 수정하는 요청에 응답을 받지 못해 확인하지 못했어요.");
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
      throw new Error("시험용 데이터를 원래 값으로 되돌렸는지 확인하지 못했어요. 계정 B의 시험용 데이터를 바로 직접 확인해 주세요.");
    }
  }
  return { findings: changed ? [runtime.finding(check,
    "시험용 계정 A로 계정 B의 시험 전용 칸을 수정해 봤더니 실제로 바뀌었어요. 로그인한 사람이 다른 사람의 정보를 바꿀 수 있어요. 바뀐 값은 계정 B로 원래대로 되돌렸고, 되돌린 것도 확인했어요.", "교차 PATCH: 단일 테스트 행 변경; owner PATCH: 원복 확인(값 생략)", { confirmed: true })] : [] };
}

async function baasTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  const projects = (runtime.context.linkedBaasProjects ?? []).filter((project) =>
    runtime.rule.id.startsWith("BAAS-001") ? project.provider === "supabase" :
      runtime.rule.id.startsWith("BAAS-002") ? project.provider === "firebase" : true);
  if (!projects.length) return gap("코드나 사이트 파일에서 연결된 데이터베이스 서비스(Supabase·Firebase) 정보를 찾지 못해 이 검사는 하지 않았어요.");
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
  if (!a || !b || a.bearerToken === b.bearerToken) return gap("서로 다른 시험용 계정 A·B의 로그인 정보가 없어 이 검사는 하지 않았어요.");
  const target = runtime.targetUrl(a.probeUrl);
  const parts = a.bearerToken.split(".");
  if (parts.length !== 3) return gap("계정 A의 로그인 토큰이 JWT 형식이 아니라 이 검사는 하지 않았어요.");
  const payload = jwtPayload(a.bearerToken);
  if (!payload || payload.role === "service_role" || jwtPayload(b.bearerToken)?.role === "service_role") return gap("일반 사용자 로그인 토큰(JWT)으로만 시험해요. 관리자 토큰이라 이 검사는 하지 않았어요.");
  if (!runtime.cache.has("jwt-controls")) {
    const anonymous = await runtime.request(target, { maxBytes: 32 * 1024 });
    const valid = await runtime.request(target, { headers: { authorization: `Bearer ${a.bearerToken}` }, maxBytes: 32 * 1024 });
    if (![401, 403].includes(anonymous.status) || valid.status !== 200 || !valid.body.trim()) return gap("로그인 없이 요청하면 거절하고 정상 토큰이면 허용하는 시험용 API 주소가 필요해요. 그런 주소를 찾지 못해 이 검사는 하지 않았어요.");
    runtime.cache.set("jwt-controls", valid.body);
  }
  let token: string;
  if (check.id === "jwt-alg-none") {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    token = `${Buffer.from(JSON.stringify({ ...header, alg: "none" })).toString("base64url")}.${parts[1]}.`;
  } else if (check.id === "jwt-signature-stripped") token = `${parts[0]}.${parts[1]}.`;
  else if (check.id === "jwt-subject-swapped") {
    const subject = b.subject ?? jwtPayload(b.bearerToken)?.sub;
    if (typeof subject !== "string" || subject === payload.sub) return gap("계정 A와 B의 사용자 식별값(subject)이 같거나 없어 이 검사는 하지 않았어요.");
    // Keep the original signature: any acceptance proves signature validation failure.
    token = `${parts[0]}.${Buffer.from(JSON.stringify({ ...payload, sub: subject })).toString("base64url")}.${parts[2]}`;
  } else return gap(`아직 지원하지 않는 로그인 토큰(JWT) 검사라 하지 않았어요: ${check.id}`);
  const response = await runtime.request(target, { headers: { authorization: `Bearer ${token}` }, maxBytes: 32 * 1024 });
  if ([401, 403].includes(response.status)) return { findings: [] };
  if (response.status !== 200 || !response.body.trim()) return gap("조작한 로그인 토큰에 대한 응답만으로는 로그인을 우회했는지 판단하지 못했어요.");
  // An HTTP 200 error document is not an accepted session. Require protected response parity.
  if (response.body !== runtime.cache.get("jwt-controls")) return gap("조작한 토큰의 응답이 정상 로그인 때 응답과 달라, 로그인 우회로 확정하지 않았어요.");
  return { findings: [runtime.finding(check, "서명이 맞지 않게 조작한 로그인 토큰(JWT)을 보냈는데, 정상 토큰을 보냈을 때와 똑같이 로그인한 사람만 볼 수 있는 응답이 돌아왔어요. 누군가 토큰을 직접 만들어 다른 사람으로 로그인할 수 있어요.",
    `${check.id}: anonymous HTTP 401/403; valid JWT HTTP 200; invalid JWT HTTP 200 with protected-response parity (토큰/응답 값 생략)`, { confirmed: true })] };
}

export async function executeAccountTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  return check.toolId === "jwt_tamper_probe" ? jwtTool(runtime, check) : baasTool(runtime, check);
}
