import { existsSync } from "fs";
import os from "os";
import path from "path";

/**
 * 점검 시작 때 서버가 설치할 수 있는 외부 도구의 허용 목록(서버 전용).
 *
 * AI는 이 목록에서 고르기만 한다. 목록 밖의 이름은 AI 응답이든 저장소 내용이든
 * 무시한다. 버전은 고정이고, 받은 파일은 고정한 SHA-256과 대조한다.
 * (src/lib/rules/toolCatalog.ts는 규칙 실행 도구 목록으로, 이 파일과 별개다.)
 */

export type InstallableToolId = "semgrep" | "gitleaks";

/** 도구 선택에 쓰는 프로젝트 요약. 파일 내용은 담지 않는다. */
export interface ProjectSignals {
  fileCount: number;
  /** 확장자별 파일 수(예: { ".ts": 12 }). */
  extensions: Record<string, number>;
  frameworks: string[];
  languages: string[];
  /** 올린 파일에 .git 폴더가 실제로 들어 있는지. */
  hasGitDir: boolean;
  /** Semgrep이 보는 코드 파일이 있는지. */
  hasCode: boolean;
}

export interface GitHubReleaseAsset {
  file: string;
  /** GitHub 릴리스에 게시된 값(체크섬 파일의 값과도 같아야 함). */
  sha256: string;
}

export type InstallMethod =
  | { kind: "pip-venv"; pipSpec: string; minPython: [number, number] }
  | {
      kind: "github-release";
      /** 고정한 릴리스 다운로드 주소(끝에 /). 이 주소 밑의 파일만 받는다. */
      baseUrl: string;
      checksumsFile: string;
      checksumsSha256: string;
      /** `${process.platform}-${process.arch}` → 파일. */
      assets: Record<string, GitHubReleaseAsset>;
    };

export interface InstallableTool {
  id: InstallableToolId;
  displayName: string;
  /** 사용자에게 보여 줄 쉬운 설명(왜 도움이 되는지). */
  purposeKo: string;
  /** 어떤 프로젝트에서 쓸모 있는지(AI에게도 준다). */
  usefulWhenKo: string;
  version: string;
  /** 기존에 쓰던 실행 파일 지정 환경변수. */
  envVar: string;
  binName: string;
  installTimeoutMs: number;
  install: InstallMethod;
  /** AI를 못 쓸 때 쓰는 결정적 판단. */
  usefulFor(signals: ProjectSignals): boolean;
}

/** Semgrep이 보는 코드 확장자(semgrepScanner와 같은 범위). */
export const SEMGREP_CODE = /\.(?:m?[jt]sx?|cjs|py|go|java|rb|php)$/;

const GITLEAKS_VERSION = "8.30.1";

const ALLOWLIST: ReadonlyMap<string, InstallableTool> = new Map<string, InstallableTool>([
  [
    "semgrep",
    {
      id: "semgrep",
      displayName: "Semgrep",
      purposeKo:
        "공개된 보안 점검 규칙 모음으로 코드를 한 번 더 살펴봐요. SQL 인젝션, XSS 같은 흔한 실수를 기본 규칙과 다른 방식으로 찾아 줘서 놓친 문제를 줄여요.",
      usefulWhenKo: "JavaScript·TypeScript·Python·Go·Java·Ruby·PHP 코드가 있을 때",
      version: "1.178.0",
      envVar: "SEMGREP_BIN",
      binName: "semgrep",
      installTimeoutMs: 180_000,
      install: { kind: "pip-venv", pipSpec: "semgrep==1.178.0", minPython: [3, 10] },
      usefulFor: (s) => s.hasCode,
    },
  ],
  [
    "gitleaks",
    {
      id: "gitleaks",
      displayName: "Gitleaks",
      purposeKo:
        "코드와 설정 파일에 남은 비밀키·토큰을 수백 가지 서비스 형식으로 찾아요. 기본 비밀키 검사가 모르는 형식의 키도 잡아 주고, 코드 기록(.git)이 있으면 지운 줄 알았던 키도 찾아요.",
      usefulWhenKo: "모든 저장소(특히 .git 기록이 함께 있을 때)",
      version: GITLEAKS_VERSION,
      envVar: "GITLEAKS_BIN",
      binName: "gitleaks",
      installTimeoutMs: 120_000,
      install: {
        kind: "github-release",
        baseUrl: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/`,
        checksumsFile: `gitleaks_${GITLEAKS_VERSION}_checksums.txt`,
        checksumsSha256: "061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae",
        assets: {
          "linux-x64": { file: `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`, sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" },
          "linux-arm64": { file: `gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`, sha256: "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" },
          "darwin-x64": { file: `gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`, sha256: "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709" },
          "darwin-arm64": { file: `gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`, sha256: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5" },
          "win32-x64": { file: `gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`, sha256: "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e" },
          "win32-arm64": { file: `gitleaks_${GITLEAKS_VERSION}_windows_arm64.zip`, sha256: "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f" },
        },
      },
      usefulFor: (s) => s.fileCount > 0,
    },
  ],
]);

/** 허용 목록에 있는 id만 돌려준다(그 밖의 문자열은 undefined). */
export function getInstallableTool(toolId: unknown): InstallableTool | undefined {
  return typeof toolId === "string" ? ALLOWLIST.get(toolId) : undefined;
}

export function listInstallableTools(): InstallableTool[] {
  return [...ALLOWLIST.values()];
}

type Env = Record<string, string | undefined>;

export function toolsDir(env: Env = process.env): string {
  return env.HOI_TOOLS_DIR?.trim() || path.join(os.tmpdir(), "hoi-tools");
}

export function installDir(tool: InstallableTool, env: Env = process.env): string {
  return path.join(toolsDir(env), `${tool.id}-${tool.version}`);
}

/** 설치가 끝났을 때 쓰는 표시 파일(이 파일이 없으면 설치가 덜 된 것). */
export const INSTALL_MARKER = ".hoi-installed.json";

const IS_WIN = process.platform === "win32";

/** 우리 도구 폴더에 설치한 실행 파일 위치(설치 여부와 무관). */
export function installedBinPath(tool: InstallableTool, env: Env = process.env): string {
  const dir = installDir(tool, env);
  if (tool.install.kind === "pip-venv") return IS_WIN ? path.join(dir, "Scripts", `${tool.binName}.exe`) : path.join(dir, "bin", tool.binName);
  return path.join(dir, IS_WIN ? `${tool.binName}.exe` : tool.binName);
}

/** 도구 폴더에 설치가 끝난 실행 파일이 있으면 그 경로. */
export function installedBin(toolId: InstallableToolId, env: Env = process.env): string | undefined {
  const tool = ALLOWLIST.get(toolId);
  if (!tool) return undefined;
  const bin = installedBinPath(tool, env);
  return existsSync(bin) && existsSync(path.join(installDir(tool, env), INSTALL_MARKER)) ? bin : undefined;
}

/** 서버에 이미 있는 실행 파일(환경변수 지정 → PATH). */
export function systemBin(tool: InstallableTool, env: Env = process.env): string | undefined {
  const explicit = env[tool.envVar]?.trim();
  if (explicit) return existsSync(explicit) ? explicit : undefined;
  const names = IS_WIN ? [`${tool.binName}.exe`, tool.binName] : [tool.binName];
  for (const dir of (env.PATH ?? env.Path ?? "").split(path.delimiter)) {
    if (!dir) continue;
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}
