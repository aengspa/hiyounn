import { spawn } from "child_process";
import { createHash } from "crypto";
import { existsSync } from "fs";
import { chmod, mkdir, open, rm, stat, writeFile } from "fs/promises";
import path from "path";
import {
  INSTALL_MARKER,
  getInstallableTool,
  installDir,
  installedBin,
  installedBinPath,
  systemBin,
  toolsDir,
  type InstallableTool,
} from "@/lib/tools/installableTools";
import { extractFileFromTarGz, extractFileFromZip } from "@/lib/tools/archive";

/**
 * 허용 목록 도구 설치(서버 전용).
 *
 *  - 허용 목록의 id만 받는다. 버전은 목록에 고정돼 있다.
 *  - 서버에 이미 있는 실행 파일(SEMGREP_BIN·GITLEAKS_BIN·PATH)을 먼저 쓴다.
 *  - 설치 폴더: HOI_TOOLS_DIR, 없으면 os.tmpdir()/hoi-tools.
 *  - HOI_ALLOW_TOOL_INSTALL=false면 설치하지 않는다. 테스트(VITEST)에서는
 *    HOI_ALLOW_TOOL_INSTALL=true를 직접 주지 않는 한 설치하지 않는다.
 *  - 자식 프로세스에는 PATH·HOME·임시 폴더만 넘긴다(키·토큰 환경변수 없음).
 *    셸을 쓰지 않고 인자 배열로 실행한다.
 *  - 같은 도구를 동시에 설치하지 않도록 프로세스 안에서는 약속(promise)을
 *    공유하고, 프로세스끼리는 잠금 파일로 막는다.
 */

type Env = Record<string, string | undefined>;

export type EnsureStatus = "ready" | "already_installed" | "install_failed" | "install_disabled";

export interface EnsureResult {
  id: string;
  status: EnsureStatus;
  binPath?: string;
  version: string;
  /** 사용자에게 보여 줄 수 있는 짧은 이유(비밀값 없음). */
  reason?: string;
  source?: "system" | "tools_dir" | "installed";
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export type ProcessRunner = (cmd: string, args: string[], opts: { env: NodeJS.ProcessEnv; timeoutMs: number; cwd?: string }) => Promise<RunResult>;
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

export interface InstallerDeps {
  env?: Env;
  runner?: ProcessRunner;
  fetcher?: Fetcher;
}

export function toolInstallAllowed(env: Env = process.env): boolean {
  const flag = env.HOI_ALLOW_TOOL_INSTALL?.trim().toLowerCase();
  if (flag === "false") return false;
  if (env.VITEST && flag !== "true") return false;
  return true;
}

/** 외부 도구에 넘길 환경변수. 키·토큰이 든 변수는 넘기지 않는다. */
export function scrubbedToolEnv(env: Env = process.env, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const out: Record<string, string> = {};
  const pick = (name: string, value: string | undefined) => {
    if (value) out[name] = value;
  };
  pick("PATH", env.PATH ?? env.Path);
  pick("HOME", env.HOME);
  pick("USERPROFILE", env.USERPROFILE);
  pick("TEMP", env.TEMP);
  pick("TMP", env.TMP);
  pick("TMPDIR", env.TMPDIR);
  // Windows에서 Python·네트워크가 동작하려면 필요한 시스템 폴더 경로(비밀 아님).
  if (process.platform === "win32") pick("SystemRoot", env.SystemRoot ?? env.SYSTEMROOT);
  // NODE_ENV는 Next 타입에서 필수라 캐스트한다(자식 프로세스에는 넘기지 않음).
  return { ...out, ...extra } as unknown as NodeJS.ProcessEnv;
}

export function logToolEvent(entry: Record<string, unknown>): void {
  // 메타데이터만 한 줄로 남긴다(경로 안의 사용자 이름 등도 남기지 않음).
  console.info(`[tools] ${JSON.stringify(entry)}`);
}

export const defaultRunner: ProcessRunner = (cmd, args, opts) =>
  new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env: opts.env, cwd: opts.cwd, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs);
    child.stdout.on("data", (d: Buffer) => {
      if (stdout.length < 200_000) stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < 8000) stderr += d.toString("utf8");
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });

const inflight = new Map<string, Promise<EnsureResult>>();

/** 허용 목록의 도구를 쓸 수 있게 한다(있으면 그대로, 없으면 설치). */
export async function ensureTool(toolId: string, deps: InstallerDeps = {}): Promise<EnsureResult> {
  const env = deps.env ?? process.env;
  const tool = getInstallableTool(toolId);
  if (!tool) {
    logToolEvent({ event: "reject", id: String(toolId).slice(0, 40) });
    return { id: String(toolId).slice(0, 40), status: "install_failed", version: "", reason: "허용 목록에 없는 도구라 설치하지 않았어요." };
  }
  const existing = systemBin(tool, env);
  if (existing) return { id: tool.id, status: "already_installed", binPath: existing, version: "system", source: "system" };
  const ours = installedBin(tool.id, env);
  if (ours) return { id: tool.id, status: "already_installed", binPath: ours, version: tool.version, source: "tools_dir" };
  if (!toolInstallAllowed(env)) return { id: tool.id, status: "install_disabled", version: tool.version, reason: "서버 설정에서 도구 설치를 꺼 두었어요." };

  const key = `${toolsDir(env)}\u0000${tool.id}`;
  let p = inflight.get(key);
  if (!p) {
    p = install(tool, env, deps).finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
}

const LOCK_STALE_MS = 10 * 60_000;

async function install(tool: InstallableTool, env: Env, deps: InstallerDeps): Promise<EnsureResult> {
  const started = Date.now();
  const dir = installDir(tool, env);
  const lockPath = `${dir}.lock`;
  let result: EnsureResult;
  let locked = false;
  try {
    await mkdir(toolsDir(env), { recursive: true });
    locked = await acquireLock(lockPath);
    if (!locked) {
      result = { id: tool.id, status: "install_failed", version: tool.version, reason: "다른 점검에서 같은 도구를 설치하고 있어요. 잠시 뒤 다시 점검해 주세요." };
    } else {
      // 설치가 덜 끝난 폴더는 지우고 처음부터 한다.
      await rm(dir, { recursive: true, force: true });
      const runner = deps.runner ?? defaultRunner;
      if (tool.install.kind === "pip-venv") await installPipVenv(tool, dir, env, runner);
      else await installGitHubRelease(tool, dir, deps.fetcher ?? fetch);
      const bin = installedBinPath(tool, env);
      if (!existsSync(bin)) throw new InstallError("설치 후 실행 파일을 찾지 못했어요.");
      await writeFile(path.join(dir, INSTALL_MARKER), JSON.stringify({ id: tool.id, version: tool.version, installedAt: new Date().toISOString() }));
      result = { id: tool.id, status: "ready", binPath: bin, version: tool.version, source: "installed" };
    }
  } catch (e) {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
    result = { id: tool.id, status: "install_failed", version: tool.version, reason: e instanceof InstallError ? e.message : "설치 중 오류가 나서 이 도구는 쓰지 않았어요." };
  } finally {
    if (locked) await rm(lockPath, { force: true }).catch(() => {});
  }
  logToolEvent({ event: "install", id: tool.id, version: tool.version, status: result.status, ms: Date.now() - started, ...(result.reason ? { reason: result.reason } : {}) });
  return result;
}

class InstallError extends Error {}

async function acquireLock(lockPath: string): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fh = await open(lockPath, "wx");
      await fh.writeFile(String(process.pid));
      await fh.close();
      return true;
    } catch {
      const info = await stat(lockPath).catch(() => undefined);
      if (info && Date.now() - info.mtimeMs > LOCK_STALE_MS) {
        await rm(lockPath, { force: true }).catch(() => {});
        continue;
      }
      return false;
    }
  }
  return false;
}

// ── Semgrep: 전용 가상환경(venv)에 고정 버전 설치 ───────────────────────────

const PYTHON_CANDIDATES: Array<[string, string[]]> = [
  ["python3", []],
  ["python", []],
  ["py", ["-3"]],
];

export async function findPython(runner: ProcessRunner, env: NodeJS.ProcessEnv, min: [number, number]): Promise<[string, string[]] | undefined> {
  for (const [cmd, pre] of PYTHON_CANDIDATES) {
    try {
      const r = await runner(cmd, [...pre, "--version"], { env, timeoutMs: 15_000 });
      const m = `${r.stdout} ${r.stderr}`.match(/Python (\d+)\.(\d+)/);
      if (r.code === 0 && m && (Number(m[1]) > min[0] || (Number(m[1]) === min[0] && Number(m[2]) >= min[1]))) return [cmd, pre];
    } catch {
      // 다음 후보
    }
  }
  return undefined;
}

async function installPipVenv(tool: InstallableTool, dir: string, env: Env, runner: ProcessRunner): Promise<void> {
  if (tool.install.kind !== "pip-venv") return;
  const childEnv = scrubbedToolEnv(env, { PIP_DISABLE_PIP_VERSION_CHECK: "1", PIP_NO_INPUT: "1", PYTHONUTF8: "1" });
  const deadline = Date.now() + tool.installTimeoutMs;
  const left = () => Math.max(1_000, deadline - Date.now());
  const py = await findPython(runner, childEnv, tool.install.minPython);
  if (!py) throw new InstallError(`Python ${tool.install.minPython.join(".")} 이상을 찾지 못해 설치하지 않았어요.`);
  const venv = await runner(py[0], [...py[1], "-m", "venv", dir], { env: childEnv, timeoutMs: left() });
  if (venv.code !== 0) throw new InstallError("설치용 Python 환경을 만들지 못했어요.");
  const vpy = process.platform === "win32" ? path.join(dir, "Scripts", "python.exe") : path.join(dir, "bin", "python");
  const pip = await runner(
    vpy,
    ["-m", "pip", "install", "--no-input", "--disable-pip-version-check", "--prefer-binary", "--index-url", "https://pypi.org/simple", tool.install.pipSpec],
    { env: childEnv, timeoutMs: left() }
  );
  if (pip.code !== 0) throw new InstallError(pip.code === null ? "설치 시간이 너무 오래 걸려 멈췄어요." : "패키지 설치에 실패했어요.");
}

// ── Gitleaks: 고정 릴리스 파일 + SHA-256 확인 ───────────────────────────────

const RELEASE_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);

async function download(fetcher: Fetcher, url: string, maxBytes: number, signal: AbortSignal): Promise<Buffer> {
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const u = new URL(current);
    if (u.protocol !== "https:" || !RELEASE_HOSTS.has(u.hostname)) throw new InstallError("허용하지 않은 주소로 연결돼 내려받지 않았어요.");
    const res = await fetcher(current, { redirect: "manual", signal });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) throw new InstallError("내려받기 주소가 올바르지 않아요.");
      current = new URL(loc, current).toString();
      continue;
    }
    if (!res.ok) throw new InstallError(`내려받기에 실패했어요(HTTP ${res.status}).`);
    const len = Number(res.headers.get("content-length") ?? "0");
    if (len > maxBytes) throw new InstallError("내려받을 파일이 너무 커요.");
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxBytes) throw new InstallError("내려받을 파일이 너무 커요.");
    return buf;
  }
  throw new InstallError("연결 이동이 너무 많아 내려받지 않았어요.");
}

export function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** 체크섬 파일에서 파일 이름의 SHA-256을 찾는다. */
export function checksumFor(checksums: string, file: string): string | undefined {
  for (const line of checksums.split(/\r?\n/)) {
    const m = line.trim().match(/^([a-f0-9]{64})\s+\*?(\S+)$/i);
    if (m && m[2] === file) return m[1].toLowerCase();
  }
  return undefined;
}

async function installGitHubRelease(tool: InstallableTool, dir: string, fetcher: Fetcher): Promise<void> {
  if (tool.install.kind !== "github-release") return;
  const spec = tool.install;
  const asset = spec.assets[`${process.platform}-${process.arch}`];
  if (!asset) throw new InstallError("이 서버 환경(운영체제·CPU)에 맞는 설치 파일이 없어요.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), tool.installTimeoutMs);
  try {
    const sums = await download(fetcher, spec.baseUrl + spec.checksumsFile, 64 * 1024, controller.signal);
    if (sha256(sums) !== spec.checksumsSha256) throw new InstallError("체크섬 파일이 고정한 값과 달라 설치하지 않았어요.");
    const listed = checksumFor(sums.toString("utf8"), asset.file);
    if (!listed || listed !== asset.sha256) throw new InstallError("체크섬 파일의 값이 고정한 값과 달라 설치하지 않았어요.");
    const archive = await download(fetcher, spec.baseUrl + asset.file, 60 * 1024 * 1024, controller.signal);
    if (sha256(archive) !== listed) throw new InstallError("내려받은 파일의 SHA-256이 맞지 않아 설치하지 않았어요.");
    const exe = process.platform === "win32" ? `${tool.binName}.exe` : tool.binName;
    const bin = asset.file.endsWith(".zip") ? extractFileFromZip(archive, exe) : extractFileFromTarGz(archive, exe);
    if (!bin) throw new InstallError("압축 파일에서 실행 파일을 찾지 못했어요.");
    await mkdir(dir, { recursive: true });
    const target = path.join(dir, exe);
    await writeFile(target, bin);
    await chmod(target, 0o755);
  } catch (e) {
    if (e instanceof InstallError) throw e;
    throw new InstallError(controller.signal.aborted ? "설치 시간이 너무 오래 걸려 멈췄어요." : "내려받거나 푸는 중 오류가 났어요.");
  } finally {
    clearTimeout(timer);
  }
}
