// Mock OpenAI-compatible gateway for end-to-end plumbing tests (no real model).
//
//   node scripts/e2e/mock-llm-gateway.mjs            # listens on 127.0.0.1:4010
//   LLM_PROVIDER=openai LLM_BASE_URL=http://localhost:4010/v1 LLM_AUTH_HEADER=api-key \
//   LLM_API_KEY=mock-gateway-key LLM_MODEL=mock npm run start
//
// It answers each app call (scan, adjudication, route table, fix, re-verify, exploit
// test, rule proposal, report) with deterministic, *valid* JSON derived from the
// request, so every AI-dependent path runs for real. It is not a security model:
// its answers are rule-of-thumb. Requests without the api-key header get 401.
import http from "node:http";

const PORT = Number(process.env.MOCK_GATEWAY_PORT || 4010);
const KEY = process.env.MOCK_GATEWAY_KEY || "mock-gateway-key";
const calls = [];

const lastJson = (text) => {
  const i = text.lastIndexOf("\n[");
  return i >= 0 ? JSON.parse(text.slice(i + 1)) : [];
};

function scanChunk(user) {
  const reviews = lastJson(user);
  // One AI-only finding the rules miss: a server-side fetch of a user-supplied URL.
  const findings = [];
  const ssrf = user.match(/\/\/ file: (\S+)\n[\s\S]*?(const r = await fetch\(target\);)/);
  if (ssrf) {
    findings.push({
      title: "사용자가 준 주소로 서버가 요청을 보내요 (SSRF)",
      severity: "high",
      category: "Server-Side Request Forgery",
      cwe: "CWE-918",
      humanReadableImpact: "공격자가 서버를 통해 내부 주소나 클라우드 메타데이터에 접근할 수 있어요.",
      whyItMatters: "내부망 정보가 새어 나갈 수 있어요.",
      file: ssrf[1],
      line: 0,
      codeSnippet: ssrf[2],
      remediation: "허용한 호스트만 요청하도록 제한하세요.",
    });
  }
  return {
    findings,
    ruleReviews: reviews.map((r) =>
      /process\.env|\{\s*ok:\s*true\s*\}/.test(r.code)
        ? { id: r.id, verdict: "likely_false_positive", reason: "서버 설정값이나 고정 응답만 쓰는 줄이에요." }
        : { id: r.id, verdict: "confirmed", reason: "사용자 입력이 위험한 동작에 그대로 들어가요." }
    ),
  };
}

function adjudicate(user) {
  const u = JSON.parse(user);
  return {
    results: u.findings.map((f) => ({
      id: f.id,
      verdict: "not_vulnerable",
      reason: "이 줄은 공격자가 바꿀 수 있는 값을 쓰지 않아요.",
      evidence: [{ file: u.file, snippet: f.code, explanation: "서버가 정한 값만 사용" }],
    })),
  };
}

function routeTable(user) {
  const u = JSON.parse(user);
  const routes = [];
  for (const f of u.files) {
    f.content.split("\n").forEach((line) => {
      const m = line.match(/\b(app|router)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/);
      if (!m) return;
      const method = m[2].toUpperCase();
      routes.push({
        method,
        path: m[3],
        file: f.path,
        snippet: line.trim(),
        auth: /requireLogin|requireAuth/.test(line) ? "required" : "unknown",
        admin: /admin/.test(f.path) ? (/requireAdmin/.test(line) ? "required" : "none") : "n/a",
        ownership: /:\w*[iI]d\b/.test(m[3]) ? "missing" : "n/a",
        mutates: method !== "GET",
      });
    });
  }
  return { routes };
}

// Rule-of-thumb patches for the shapes in the benchmark apps.
const FIXES = [
  { when: /SQL|쿼리/, re: /(db\.\w+\()\s*"([^"]*?)"\s*\+\s*(req\.[\w.]+)\s*\)/, to: (m) => `${m[1]}"${m[2]}?", [${m[3]}])`, what: "쿼리에 값을 붙이지 않고 바인딩으로 넘겨요." },
  { when: /명령|커맨드|command/i, re: /exec\("([^"]+?) "\s*\+\s*(req\.query\.\w+),/, to: (m) => `(typeof ${m[2]} === "string" && /^(?!-)[A-Za-z0-9.-]{1,253}$/.test(${m[2]})) && require("child_process").execFile(${JSON.stringify(m[1].split(" ")[0])}, [${m[1].split(" ").slice(1).map((a) => JSON.stringify(a)).join(", ")}, ${m[2]}],`, what: "셸 없이 인자 배열로 실행하고 호스트 형식을 확인해요." },
  { when: /XSS|스크립트/, re: /res\.send\("([^"]*<[^"]*)"\s*\+\s*(req\.query\.\w+)\s*\+/, to: (m) => `res.send("${m[1]}" + String(${m[2]} ?? "").replace(/[&<>"']/g, (c) => "&#" + c.charCodeAt(0) + ";") +`, what: "HTML에 넣기 전에 값을 이스케이프해요." },
  { when: /경로|traversal/i, re: /res\.sendFile\(__dirname \+ "\/uploads\/" \+ (req\.query\.\w+)\)/, to: (m) => `(/^[A-Za-z0-9._-]+$/.test(String(${m[1]})) ? res.sendFile(require("path").join(__dirname, "uploads", String(${m[1]}))) : res.sendStatus(400))`, what: "파일 이름을 허용 목록으로 제한해요." },
];

function fix(user) {
  const content = (user.split("<<<FILE\n")[1] || "").split("\nFILE>>>")[0];
  const title = (user.match(/^Title: (.*)$/m) || [])[1] || "";
  for (const line of content.split("\n")) {
    for (const f of FIXES.filter((x) => x.when.test(title))) {
      const m = line.match(f.re);
      if (m) return { canFix: true, summary: f.what, plainExplanation: f.what, edits: [{ before: line, after: line.replace(f.re, () => f.to(m)) }] };
    }
  }
  return { canFix: false, reason: "이 파일에서 안전하게 고칠 방법을 확정하지 못했어요." };
}

function reverify(user) {
  const u = JSON.parse(user);
  return {
    results: u.findings.map((f) => {
      const file = u.currentFiles.find((c) => c.file === f.reportedFile) || u.currentFiles[0];
      const original = (f.originalEvidence[0] || "").trim();
      const lines = (file?.content || "").split("\n").map((l) => l.trim()).filter((l) => l.length >= 8);
      if (f.question === "is_vulnerability") {
        const safe = lines.find((l) => original && l.includes(original.slice(0, 20))) || lines[0];
        return { findingId: f.id, verdict: "not_vulnerable", summary: "이 코드는 사용자 입력을 쓰지 않아 공격이 불가능해요.", evidence: [{ role: "safe_code", file: file.file, snippet: safe, explanation: "고정 값" }] };
      }
      const still = original && lines.includes(original);
      if (still) return { findingId: f.id, verdict: "still_present", summary: "원래 위험한 코드가 수정본에 그대로 있어요.", evidence: [{ role: "vulnerable_code", file: file.file, snippet: original, explanation: "그대로 남음" }] };
      const mitigation = lines.find((l) => /\?"|execFile|replace\(|test\(|sendStatus|process\.env/.test(l)) || lines[0];
      return { findingId: f.id, verdict: "fixed_in_source", summary: "위험했던 코드가 안전한 방식으로 바뀌었어요.", evidence: [{ role: "mitigation", file: file.file, snippet: mitigation, explanation: "완화 코드" }] };
    }),
  };
}

const EXPLOITS = [
  { when: /SQL|쿼리/, path: "/api/users/1 OR 1=1", code: `hoi.load(FILE); await hoi.request("GET", "/api/users/1 OR 1=1"); const q = hoi.callsTo("src/db", "")[0]; const sql = q ? String(q.args[0]) : ""; return { attackSucceeded: sql.includes("1 OR 1=1"), note: "SQL: " + sql };` },
  { when: /XSS|스크립트/, code: `hoi.load(FILE); const res = await hoi.request("GET", "/search?q=" + encodeURIComponent("<script>x</script>")); return { attackSucceeded: String(res.body).includes("<script>"), note: String(res.body).slice(0, 80) };` },
  { when: /명령|커맨드|command/i, code: `hoi.load(FILE); await hoi.request("GET", "/ping?host=" + encodeURIComponent("x;id")); const shell = hoi.callsTo("child_process", "exec").filter((c) => c.path === "exec" && String(c.args[0]).includes(";id")); const argv = hoi.callsTo("child_process", "execFile").filter((c) => JSON.stringify(c.args).includes("x;id")); return { attackSucceeded: shell.length + argv.length > 0, note: "shell " + shell.length + ", argv " + argv.length };` },
  { when: /경로|traversal/i, code: `hoi.load(FILE); const res = await hoi.request("GET", "/file?name=" + encodeURIComponent("../../etc/passwd")); const p = String(res.sentFile || ""); return { attackSucceeded: p.includes("../"), note: "status " + res.statusCode + " " + p };` },
];

function exploit(user) {
  const u = JSON.parse(user);
  const t = EXPLOITS.find((e) => e.when.test(u.finding.title));
  if (!t) return { testable: false, reason: "이 종류는 하네스로 재현하지 않았어요(모의 게이트웨이)." };
  return { testable: true, attack: "원래 공격 입력을 그대로 보내요.", code: `module.exports = async function exploit(hoi) { const FILE = ${JSON.stringify(u.finding.file)}; ${t.code} };` };
}

function answer(system, user) {
  if (system.includes("map every HTTP route")) return ["authz-table", routeTable(user)];
  if (system.includes("final reviewer for rule-based")) return ["adjudicate", adjudicate(user)];
  if (system.includes("fix one security finding")) return ["fix", fix(user)];
  if (system.includes("re-review security findings")) return ["reverify", reverify(user)];
  if (system.includes("exploit test")) return ["exploit", exploit(user)];
  if (system.includes("reusable detection rules")) {
    const u = JSON.parse(user);
    return ["propose", { proposals: u.findings.filter((f) => /fetch\(/.test(f.code)).map((f) => ({
      findingId: f.id, title: "변수로 받은 주소를 그대로 서버에서 요청해요", cwe: "CWE-918", severity: "high",
      pattern: "\\bfetch\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)", flags: "", rationale: "사용자 입력일 수 있는 변수를 검증 없이 fetch에 넘기는 줄을 잡아요.",
      remediation: "허용 목록으로 호스트를 제한하세요." })) }];
  }
  if (system.includes("시니어 애플리케이션 보안 엔지니어")) return ["scan", scanChunk(user)];
  return ["report", { summary: "모의 게이트웨이 요약입니다.", highlights: [], recommendation: "위험도가 높은 항목부터 고치세요." }];
}

http
  .createServer((req, res) => {
    if (req.method === "GET" && req.url === "/calls") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify(calls));
    }
    if (req.method !== "POST" || !req.url.endsWith("/chat/completions")) {
      res.writeHead(404);
      return res.end();
    }
    if (req.headers["api-key"] !== KEY) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: { message: "invalid gateway key", code: "invalid_api_key" } }));
    }
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const b = JSON.parse(body);
      const system = b.messages.find((m) => m.role === "system")?.content || "";
      const user = b.messages.find((m) => m.role === "user")?.content || "";
      const [purpose, out] = answer(system, user);
      calls.push({ purpose, model: b.model, temperature: b.temperature ?? null, auth: req.headers.authorization ? "bearer" : "api-key" });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: b.model, choices: [{ message: { role: "assistant", content: JSON.stringify(out) } }], usage: { prompt_tokens: Math.ceil(user.length / 4), completion_tokens: 50 } }));
    });
  })
  .listen(PORT, "127.0.0.1", () => console.log(`mock gateway on http://127.0.0.1:${PORT}/v1`));
