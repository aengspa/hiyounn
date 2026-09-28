import assert from "node:assert/strict";
import { RULES, selectRulesForMode } from "../src/lib/rules/definitions";
import { getRule, registryErrors } from "../src/lib/rules/registry";
import { getTool } from "../src/lib/rules/toolCatalog";
import { NEW_TOOL_CHECKS, executeNewToolCheck, supportsNewToolCheck } from "../src/lib/scanners/newRuleTools";
import { RuleToolRuntime, type ProbeFetch } from "../src/lib/scanners/ruleToolRuntime";
import { extractBaasProjects } from "../src/lib/scanners/deployedRuleTools";
import { SecurityOrchestrator } from "../src/lib/scanners/orchestrator";
import { groupFindingsForReport } from "../src/lib/reporting/reportGenerator";
import { allowedMaxTier, evaluatePrerequisites } from "../src/lib/rules/executionGate";
import { isBlockedAddress, safeFetch } from "../src/lib/net/safeFetch";
import { selectorMatches } from "../src/lib/rules/selectorEvaluation";
import { SCANNER_GUARDS, assertGuardsReady } from "../src/lib/scanners/definitions";
import { isScannableFile } from "../src/lib/demo/sourceFiles";
import type { ProjectContext } from "../src/lib/scanners/types";

let passed = 0;
function test(name: string, assertion: () => void) { assertion(); passed++; console.log(`[PASS] ${name}`); }
const base: ProjectContext = { projectId: "tools-test", name: "test", files: {},
  stack: { frameworks: ["react"], languages: ["typescript"], hasEnvFile: false },
  isUserProject: true, scanMode: "B", deploymentUrl: "https://app.test/", deploymentAuthorized: true };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (role: string, sub = "user-a") => `${encode({ alg: "HS256" })}.${encode({ role, sub })}.original-signature`;
const response = (url: string, body = "", status = 200, headers: Record<string, string> = {}) => ({ url, body, status, headers, truncated: false });
const denied: ProbeFetch = async (url) => response(url, "", 403);
const rule = (id: string) => { const result = getRule(id); assert.ok(result); return result; };
async function run(id: string, checkId: string, context: ProjectContext, fetcher: ProbeFetch = denied) {
  const r = rule(id), check = r.checks.find((c) => c.id === checkId); assert.ok(check);
  return executeNewToolCheck(new RuleToolRuntime(context, r, fetcher), check);
}

async function main() {
  test("46 definitions and every new tool check load without schema errors", () => {
    assert.equal(RULES.length, 46); assert.deepEqual(registryErrors(), []);
    for (const r of RULES) for (const check of r.checks) if (check.toolId in NEW_TOOL_CHECKS) {
      assert.ok(getTool(check.toolId)?.implementation); assert.ok(supportsNewToolCheck(check));
    }
  });
  test("recursive selectors and inherited mode selection", () => {
    assert.ok(selectorMatches({ all: [{ any: [{ field: "components.kind", op: "contains", value: "web" }] }] }, base));
    assert.ok(selectRulesForMode("C", { hasSource: true }).rules.some((r) => r.mode === "A"));
    assert.equal(selectRulesForMode("B", { hasSource: false }).rules.some((r) => r.mode === "A"), false);
  });
  test("real accounts never arise from a checkbox; demo conditions remain isolated", () => {
    assert.equal(allowedMaxTier(base), "PASSIVE");
    assert.ok(evaluatePrerequisites(rule("WEB-019-C"), base).missing.includes("test_user_a"));
  });
  test("IPv4-mapped IPv6, metadata, documentation and local ranges are blocked", () => {
    for (const address of ["127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "::ffff:7f00:1", "::1", "fc00::1", "fe90::1", "ff02::1", "2001:db8::1"]) assert.ok(isBlockedAddress(address), address);
    assert.equal(isBlockedAddress("2606:4700:4700::1111"), false);
  });
  await assert.rejects(() => safeFetch("http://[::ffff:7f00:1]/"), (error: unknown) => (error as { code: string }).code === "PRIVATE_ADDRESS");
  passed++; console.log("[PASS] normalized mapped IPv6 requests never connect");
  test("service identity and guard declarations are explicit", () => {
    const ownership = SCANNER_GUARDS.find((g) => g.id === "SCN-001")!;
    assert.equal(ownership.policy.dnsTxtRecordName, "_vibe-security-agent-verify");
    assert.throws(() => assertGuardsReady("B", new Set()), /가드가 비활성/);
    assert.ok(isScannableFile(".env.local") && isScannableFile("firestore.rules") && isScannableFile("pnpm-lock.yaml"));
  });
  const packageContext = { ...base, scanMode: "A" as const,
    files: { "package.json": JSON.stringify({ dependencies: { lodahs: "1.0.0" } }) } };
  const absent = await run("SEC-005", "registry-existence", packageContext, async (url) => response(url, "", 404));
  const similar = await run("SEC-005", "typosquat-similarity", packageContext);
  const hook = await run("SEC-005", "install-script-audit", packageContext, async (url) => response(url, JSON.stringify({ scripts: { postinstall: "echo hello" } })));
  const age = await run("SEC-005", "package-age-popularity", packageContext, async (url) => response(url,
    JSON.stringify(url.includes("api.npmjs.org") ? { downloads: 1 } : { time: { created: new Date().toISOString() } })));
  test("package existence, transposition, lifecycle and age/download checks execute", () => {
    assert.equal(absent.findings.length, 1); assert.equal(similar.findings.length, 1);
    assert.equal(hook.findings[0]?.status, "detected"); assert.equal(age.findings[0]?.status, "detected");
  });
  const registryFailure = await run("SEC-005", "registry-existence", packageContext, async () => { throw new Error("offline"); });
  test("registry failures surface as coverage gaps", () => { assert.ok(registryFailure.gap); assert.equal(registryFailure.findings.length, 0); });
  const secret = `sk-${"a".repeat(30)}`;
  const llmSources: Record<string, string> = {
    "prompt.ts": `import OpenAI from 'openai';\nconst systemPrompt = '${secret}';`,
    "sink.ts": `import OpenAI from 'openai';\nconst output = response.choices[0];\neval(output);`,
    "tools.ts": `import OpenAI from 'openai';\nconst tools = [{ name: 'shell_exec', execute: exec }];`,
    "html.tsx": `import OpenAI from 'openai';\nreturn <div dangerouslySetInnerHTML={{__html: response.output}} />;`,
  };
  const llmResults = await Promise.all(rule("LLM-001").checks.map((check) => run("LLM-001", check.id, { ...base, files: llmSources })));
  test("all four LLM integration checks detect risk and redact source content", () => {
    for (const result of llmResults) { assert.ok(result.findings.length); assert.ok(!JSON.stringify(result.findings).includes(secret)); }
  });
  const publicJwt = jwt("anon");
  const bundle = `const url='https://project.supabase.co'; const key='${publicJwt}'; client.from('profiles'); const secret='${secret}';`;
  const bundleFetch: ProbeFetch = async (url) => response(url, url.endsWith("app.js") ? bundle : '<script src="/app.js"></script><script src="https://other.test/remote.js"></script>');
  const bundleRuntime = new RuleToolRuntime(base, rule("SEC-002-B"), bundleFetch);
  const bundleResults = [];
  for (const check of rule("SEC-002-B").checks) bundleResults.push(await executeNewToolCheck(bundleRuntime, check));
  test("same-origin bundle scan masks keys and produces evidenced public BaaS linkage", () => {
    assert.equal(bundleResults[0].findings.length, 1); assert.ok(!JSON.stringify(bundleResults[0].findings).includes(secret));
    assert.equal(bundleResults[1].linkedBaasProjects?.[0].provider, "supabase");
    assert.deepEqual(bundleResults[1].linkedBaasProjects?.[0].tables, ["profiles"]);
    assert.equal(extractBaasProjects({ "app.js": bundle.replace(publicJwt, jwt("service_role")) }, "verified_bundle").length, 0);
  });
  const redirect = await run("WEB-022-B", "probe-open-redirect", base, async (url) => response(url, "", 302, { location: new URL(url).searchParams.get("next") ?? "/home" }));
  const safeRedirect = await run("WEB-022-B", "probe-open-redirect", base, async (url) => response(url, "", 302, { location: "/home" }));
  test("redirect requires an actual 3xx external Location and never follows it", () => { assert.equal(redirect.findings.length, 1); assert.equal(safeRedirect.findings.length, 0); });
  const missingErrorEndpoint = await run("WEB-023-B", "probe-error-leak", base);
  const error = await run("WEB-023-B", "probe-error-leak", { ...base, probeEndpoints: { invalidJson: ["/api/test"] } }, async (url) => response(url, "Error\n at route (/home/server/handler.js:10:2)", 500));
  test("error probes require a side-effect-free configured endpoint", () => { assert.ok(missingErrorEndpoint.gap); assert.equal(error.findings.length, 2); });
  let externalCalls = 0;
  const externalError = await run("WEB-023-B", "probe-error-leak", { ...base, probeEndpoints: { invalidJson: ["https://other.test/api"] } }, async (url) => { externalCalls++; return response(url); });
  test("cross-origin endpoint configurations are blocked before credentials/requests", () => { assert.equal(externalCalls, 0); assert.ok(externalError.gap); });
  const marker = "PRIVATE-SYSTEM-CANARY-123456";
  const promptContext = { ...base, llmProbeEndpoint: "/api/llm-test", llmPrivateMarkers: [marker] };
  const promptRefusal = await run("LLM-001-B", "probe-system-prompt-leak", promptContext, async (url) => response(url, "I cannot reveal the system prompt or hidden instructions."));
  const promptLeak = await run("LLM-001-B", "probe-system-prompt-leak", promptContext, async (url) => response(url, marker));
  test("prompt refusal/echo is not leakage; private canary leakage stays tentative", () => {
    assert.equal(promptRefusal.findings.length, 0); assert.equal(promptLeak.findings.length, 3); assert.equal(promptLeak.findings[0].status, "detected");
    assert.ok(!JSON.stringify(promptLeak.findings).includes(marker));
  });
  const linked = { provider: "supabase" as const, url: "https://project.supabase.co", publicKey: publicJwt,
    source: "verified_source" as const, tables: ["profiles"] };
  const baasContext = { ...base, linkedBaasProjects: [linked] };
  const anonRead = await run("BAAS-001-B", "supabase-anon-select", baasContext, async (url) => response(url, JSON.stringify([{ id: "private-row", email: "private@example.test" }])));
  const roleContext = { ...baasContext, linkedBaasProjects: [{ ...linked, publicKey: jwt("service_role") }] };
  let privilegedCalls = 0;
  const roleResult = await run("BAAS-001-B", "supabase-anon-select", roleContext, async (url) => { privilegedCalls++; return response(url); });
  test("BaaS public data needs review and admin credentials never leave the scanner", () => {
    assert.equal(anonRead.findings.length, 1); assert.equal(anonRead.findings[0].status, "detected");
    assert.ok(!JSON.stringify(anonRead.findings).includes("private@example.test")); assert.ok(roleResult.gap); assert.equal(privilegedCalls, 0);
  });
  const firebaseContext = { ...base, linkedBaasProjects: [{ provider: "firebase" as const, url: "https://project.firebaseio.com", source: "verified_source" as const }] };
  const firebase = await run("BAAS-002-B", "firebase-anon-read", firebaseContext, async (url) => response(url, '{"users":true}'));
  const storage = await run("BAAS-003-B", "storage-anon-list", baasContext, async (url) => response(url, '[{"name":"public"}]'));
  test("Firebase shallow read and storage list have executable handlers", () => { assert.equal(firebase.findings.length, 1); assert.equal(storage.findings.length, 1); });
  const tokenA = jwt("authenticated", "user-a"), tokenB = jwt("authenticated", "user-b");
  const sessionContext: ProjectContext = { ...baasContext, scanMode: "C", testObjects: { object_owned_by_b: "test-row" }, testSessions: {
    test_user_a: { bearerToken: tokenA, probeUrl: "/api/me", subject: "user-a" },
    test_user_b: { bearerToken: tokenB, probeUrl: "/api/me", subject: "user-b" },
  } };
  const jwtFetch: ProbeFetch = async (url, options) => response(url, options?.headers?.authorization ? '{"id":"user-a"}' : "", options?.headers?.authorization ? 200 : 401);
  const jwtRuntime = new RuleToolRuntime(sessionContext, rule("WEB-019-C"), jwtFetch);
  const jwtResults = [];
  for (const check of rule("WEB-019-C").checks) jwtResults.push(await executeNewToolCheck(jwtRuntime, check));
  const publicEndpoint = await run("WEB-019-C", "jwt-alg-none", sessionContext, async (url) => response(url, "public page"));
  test("JWT variants require anonymous-denied/valid-allowed controls and protected parity", () => {
    for (const result of jwtResults) assert.equal(result.findings.length, 1);
    assert.ok(publicEndpoint.gap); assert.equal(publicEndpoint.findings.length, 0);
    assert.ok(!JSON.stringify(jwtResults).includes(tokenA));
  });
  let row = { id: "test-row", vsa_probe_value: "original" };
  let restoreCalls = 0;
  const fixtureContext = { ...sessionContext, baasTestFixture: { table: "profiles", rowId: "test-row", testOnly: true as const,
    originalValues: { vsa_probe_value: "original" }, probeValues: { vsa_probe_value: "changed" } } };
  const mutationFetch: ProbeFetch = async (url, options) => {
    if (options?.method === "PATCH") {
      const values = JSON.parse(options.body!); row = { ...row, ...values };
      if (options.headers?.authorization === `Bearer ${tokenB}`) restoreCalls++;
    }
    return response(url, JSON.stringify([row]));
  };
  const mutation = await run("BAAS-001-C", "rls-cross-user-update", fixtureContext, mutationFetch);
  test("cross-user test mutation is restored with the owner session", () => {
    assert.equal(mutation.findings.length, 1); assert.equal(restoreCalls, 1); assert.equal(row.vsa_probe_value, "original");
  });
  const timeoutMutation = await run("BAAS-001-C", "rls-cross-user-update", fixtureContext, async (url, options) => {
    if (options?.method === "PATCH" && options.headers?.authorization === `Bearer ${tokenA}`) { row.vsa_probe_value = "changed"; throw new Error("timeout after send"); }
    return mutationFetch(url, options);
  });
  test("ambiguous write failures still restore and become coverage gaps", () => { assert.ok(timeoutMutation.gap); assert.equal(row.vsa_probe_value, "original"); });
  const limited = new RuleToolRuntime(base, { ...rule("WEB-022-B"), execution: { ...rule("WEB-022-B").execution, maxRequests: 1 } }, denied);
  await limited.request("https://app.test/"); await assert.rejects(() => limited.request("https://app.test/"), /상한/);
  passed++; console.log("[PASS] runtime enforces rule request budgets");
  const noProof = await new SecurityOrchestrator([], async () => { throw new Error("unexpected request"); }).run(base);
  test("consent-only projects cannot execute network checks", () => {
    assert.equal(noProof.plan.selectedChecks.filter((c) => c.tier !== "PASSIVE").length, 0);
    assert.ok(noProof.plan.coverageGaps.some((g) => g.ruleId === "SEC-002-B"));
  });
  const activeContext = { ...base, files: { "app.ts": "const React = true;" } };
  const calls: string[] = [];
  const discovered = await new SecurityOrchestrator([], async (url, options) => {
    calls.push(url);
    if (new URL(url).hostname === "project.supabase.co") return response(url, url.includes("/bucket") ? "[]" : '[{"id":"one"}]');
    if (url.endsWith("app.js")) return response(url, bundle);
    if (new URL(url).search) return response(url, "", 200);
    return response(url, '<script src="/app.js"></script>');
  }, async () => true).run(activeContext);
  test("bundle produces dynamically enable BaaS checks and attach correct rule metadata", () => {
    assert.ok(calls.some((url) => url.includes("project.supabase.co/rest/v1/profiles")));
    assert.ok(discovered.findings.some((f) => f.ruleId === "BAAS-001-B" && f.family === "BAAS-001"));
    assert.equal(groupFindingsForReport([{ ...bundleResults[0].findings[0], family: "SEC-002" },
      { ...bundleResults[0].findings[0], id: "second", family: "SEC-002" }]).length, 1);
  });
  console.log(`\n${passed} definition/tool regression checks passed.`);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
