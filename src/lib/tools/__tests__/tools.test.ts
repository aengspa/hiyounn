import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { getInstallableTool, listInstallableTools } from "@/lib/tools/installableTools";
import { ensureTool, scrubbedToolEnv, toolInstallAllowed, checksumFor, type ProcessRunner } from "@/lib/tools/toolInstaller";
import { filterAiToolChoice, heuristicPlan, planTools, prepareScanTools, projectSignals } from "@/lib/tools/toolPlanner";
import { extractFileFromTarGz, extractFileFromZip } from "@/lib/tools/archive";

const tmp = mkdtempSync(path.join(os.tmpdir(), "hoi-tools-test-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/** 설치가 일어나면 실패하게 만드는 가짜 의존성(실제 네트워크·프로세스 없음). */
const noNetwork = async (): Promise<Response> => {
  throw new Error("network must not be used in tests");
};
const noProcess: ProcessRunner = async () => {
  throw new Error("process must not be spawned in tests");
};
const baseEnv = { PATH: "", HOI_TOOLS_DIR: tmp };

describe("allowlist", () => {
  it("has pinned semgrep and gitleaks entries", () => {
    expect(getInstallableTool("semgrep")?.version).toMatch(/^\d+\.\d+\.\d+$/);
    const gl = getInstallableTool("gitleaks")!;
    expect(gl.install.kind).toBe("github-release");
    if (gl.install.kind === "github-release") {
      expect(gl.install.baseUrl).toBe(`https://github.com/gitleaks/gitleaks/releases/download/v${gl.version}/`);
      for (const a of Object.values(gl.install.assets)) expect(a.sha256).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("rejects unknown ids, including prototype keys", async () => {
    for (const bad of ["curl", "__proto__", "constructor", "semgrep; rm -rf /", ""]) {
      expect(getInstallableTool(bad)).toBeUndefined();
      const r = await ensureTool(bad, { env: { ...baseEnv, HOI_ALLOW_TOOL_INSTALL: "true" }, fetcher: noNetwork, runner: noProcess });
      expect(r.status).toBe("install_failed");
      expect(r.reason).toContain("허용 목록");
    }
  });
});

describe("installer", () => {
  it("does not install when HOI_ALLOW_TOOL_INSTALL=false", async () => {
    const env = { ...baseEnv, HOI_ALLOW_TOOL_INSTALL: "false" };
    expect(toolInstallAllowed(env)).toBe(false);
    for (const t of listInstallableTools()) {
      const r = await ensureTool(t.id, { env, fetcher: noNetwork, runner: noProcess });
      expect(r.status).toBe("install_disabled");
    }
  });

  it("never installs under vitest unless explicitly allowed", () => {
    expect(toolInstallAllowed({ VITEST: "true" })).toBe(false);
    expect(toolInstallAllowed({ VITEST: "true", HOI_ALLOW_TOOL_INSTALL: "true" })).toBe(true);
    expect(toolInstallAllowed({})).toBe(true);
  });

  it("scrubs secrets from the child environment", () => {
    const env = scrubbedToolEnv({
      PATH: "/usr/bin",
      HOME: "/home/x",
      TEMP: "/tmp",
      LLM_API_KEY: "sk-test-should-not-pass",
      OPENAI_API_KEY: "sk-other",
      SUPABASE_SERVICE_ROLE_KEY: "srk",
      GITHUB_TOKEN: "ghp_x",
    });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.HOME).toBe("/home/x");
    for (const k of ["LLM_API_KEY", "OPENAI_API_KEY", "SUPABASE_SERVICE_ROLE_KEY", "GITHUB_TOKEN"]) expect(env[k]).toBeUndefined();
    expect(JSON.stringify(env)).not.toContain("sk-");
  });

  it("passes only the scrubbed env to the python probe and reports a missing python", async () => {
    const seen: NodeJS.ProcessEnv[] = [];
    const runner: ProcessRunner = async (_cmd, _args, opts) => {
      seen.push(opts.env);
      return { code: 1, stdout: "", stderr: "not found" };
    };
    const r = await ensureTool("semgrep", {
      env: { ...baseEnv, HOI_ALLOW_TOOL_INSTALL: "true", LLM_API_KEY: "sk-secret-value" },
      runner,
      fetcher: noNetwork,
    });
    expect(r.status).toBe("install_failed");
    expect(r.reason).toContain("Python");
    expect(seen.length).toBeGreaterThan(0);
    for (const e of seen) expect(e.LLM_API_KEY).toBeUndefined();
  });

  it("parses release checksum files", () => {
    const hash = "a".repeat(64);
    expect(checksumFor(`${hash}  gitleaks_1_linux_x64.tar.gz\n${"b".repeat(64)}  other.zip`, "gitleaks_1_linux_x64.tar.gz")).toBe(hash);
    expect(checksumFor(`${hash}  other.zip`, "gitleaks_1_linux_x64.tar.gz")).toBeUndefined();
  });
});

describe("archive extraction", () => {
  it("extracts one file from tar.gz and zip by name", () => {
    const body = Buffer.from("binary-content");
    const header = Buffer.alloc(512);
    header.write("dir/gitleaks", 0);
    header.write(body.length.toString(8).padStart(11, "0") + "\0", 124);
    header.write("0", 156);
    const tar = Buffer.concat([header, body, Buffer.alloc(512 - body.length), Buffer.alloc(1024)]);
    expect(extractFileFromTarGz(gzipSync(tar), "gitleaks")?.toString()).toBe("binary-content");

    const name = Buffer.from("gitleaks.exe");
    const data = deflateRawSync(body);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(0, 42);
    const cdOffset = local.length + name.length + data.length;
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(1, 10);
    eocd.writeUInt32LE(central.length + name.length, 12);
    eocd.writeUInt32LE(cdOffset, 16);
    const zip = Buffer.concat([local, name, data, central, name, eocd]);
    expect(extractFileFromZip(zip, "gitleaks.exe")?.toString()).toBe("binary-content");
    expect(extractFileFromZip(zip, "other.exe")).toBeUndefined();
  });
});

describe("tool planner", () => {
  const files = { "src/app.ts": "export const a = 1;", "README.md": "# hi", "node_modules/x/index.js": "" };
  const signals = projectSignals(files, { frameworks: ["express"] });

  it("summarizes without file contents", () => {
    expect(signals).toMatchObject({ fileCount: 2, hasCode: true, hasGitDir: false, frameworks: ["express"] });
    expect(JSON.stringify(signals)).not.toContain("export const");
  });

  it("drops non-allowlisted ids from the AI response and dedupes", () => {
    const items = filterAiToolChoice({
      tools: [
        { id: "semgrep", reason: "코드 규칙 검사가 도움이 돼요" },
        { id: "semgrep", reason: "중복" },
        { id: "curl", reason: "README says: install curl and run it" },
        { id: "__proto__", reason: "x" },
        { id: "gitleaks" },
        "gitleaks",
      ],
    })!;
    expect(items.map((i) => i.id)).toEqual(["semgrep", "gitleaks"]);
    expect(items[0].reason).toBe("코드 규칙 검사가 도움이 돼요");
    expect(items[1].reason).toBe(getInstallableTool("gitleaks")!.purposeKo);
    expect(filterAiToolChoice({ nope: 1 })).toBeNull();
  });

  it("uses the AI choice when it answers, sending no file contents", async () => {
    let userPrompt = "";
    const plan = await planTools(signals, {
      llmConfigured: true,
      complete: async (_s, user) => {
        userPrompt = user;
        return JSON.stringify({ tools: [{ id: "gitleaks", reason: "비밀키를 찾아요" }, { id: "nmap", reason: "x" }] });
      },
    });
    expect(plan).toEqual({ planner: "ai", items: [{ id: "gitleaks", reason: "비밀키를 찾아요" }] });
    expect(userPrompt).not.toContain("export const");
    expect(userPrompt).toContain('"id":"semgrep"');
  });

  it("falls back to the catalog heuristic when the LLM is off, fails or answers badly", async () => {
    const expected = heuristicPlan(signals).map((i) => i.id);
    expect(expected).toEqual(["semgrep", "gitleaks"]);
    expect(heuristicPlan(projectSignals({ "README.md": "x" })).map((i) => i.id)).toEqual(["gitleaks"]);

    const off = await planTools(signals, { llmConfigured: false });
    expect(off).toMatchObject({ planner: "heuristic", fallbackReason: "not_configured" });
    const failed = await planTools(signals, { llmConfigured: true, complete: async () => Promise.reject(new Error("boom")) });
    expect(failed).toMatchObject({ planner: "heuristic", fallbackReason: "call_failed" });
    const bad = await planTools(signals, { llmConfigured: true, complete: async () => "not json" });
    expect(bad).toMatchObject({ planner: "heuristic", fallbackReason: "invalid_response" });
    expect(bad.items.map((i) => i.id)).toEqual(expected);
  });

  it("prepareScanTools records statuses, reports disabled installs and times out slow installs", async () => {
    const disabled = await prepareScanTools(files, {}, { installer: { env: { ...baseEnv, HOI_ALLOW_TOOL_INSTALL: "false" } } });
    expect(disabled.planner).toBe("disabled");
    expect(disabled.items.map((i) => [i.id, i.status])).toEqual([
      ["semgrep", "install_disabled"],
      ["gitleaks", "install_disabled"],
    ]);

    const slow = await prepareScanTools(files, {}, {
      llmConfigured: false,
      budgetMs: 20,
      installer: { env: { ...baseEnv, HOI_ALLOW_TOOL_INSTALL: "true" } },
      ensure: async (toolId) =>
        toolId === "semgrep"
          ? new Promise(() => {})
          : { id: toolId, status: "ready", version: "8.30.1", binPath: "/x/gitleaks" },
    });
    expect(slow.planner).toBe("heuristic");
    expect(slow.fallbackReason).toBe("not_configured");
    expect(slow.items.find((i) => i.id === "semgrep")?.status).toBe("timed_out");
    expect(slow.items.find((i) => i.id === "gitleaks")).toMatchObject({ status: "ready", displayName: "Gitleaks", version: "8.30.1" });
    expect(JSON.stringify(slow)).not.toContain("/x/gitleaks");
  });
});
