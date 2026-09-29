#!/usr/bin/env node
/**
 * 빌드 때 gitleaks(linux x64)를 받아 배포본에 함께 넣는다(Vercel 등 Linux 빌드 전용).
 *
 *  - 버전과 SHA-256은 src/lib/tools/installableTools.ts의 허용 목록에서 읽는다(값을 따로 적지 않음).
 *  - 받은 파일의 SHA-256이 다르면 실행 파일을 남기지 않는다.
 *  - 실패해도 빌드는 멈추지 않는다(exit 0). 이때는 점검 때 내려받아 설치하는 기존 방식이 쓰인다.
 *  - Linux가 아니면 조용히 건너뛴다. --force를 주면 운영체제와 상관없이 받는다(확인용).
 *
 * 결과: vendor-bin/gitleaks/gitleaks (0755). next.config.mjs의 outputFileTracingIncludes가
 * 점검을 돌리는 API 함수에 이 파일을 넣는다. Node 기본 모듈만 쓴다.
 */
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const ALLOWLIST_SOURCE = path.join(ROOT, "src", "lib", "tools", "installableTools.ts");
export const VENDOR_BIN = path.join(ROOT, "vendor-bin", "gitleaks", "gitleaks");

const RELEASE_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);
const MAX_BYTES = 60 * 1024 * 1024;
const TIMEOUT_MS = 90_000;

/** 허용 목록 소스에서 gitleaks 버전과 linux-x64 파일의 SHA-256을 읽는다. */
export function readPinned(source) {
  const version = source.match(/const GITLEAKS_VERSION = "(\d+\.\d+\.\d+)";/)?.[1];
  const sha = source.match(/"linux-x64":\s*\{\s*file:\s*`gitleaks_\$\{GITLEAKS_VERSION\}_linux_x64\.tar\.gz`,\s*sha256:\s*"([a-f0-9]{64})"/)?.[1];
  if (!version || !sha) return undefined;
  const file = `gitleaks_${version}_linux_x64.tar.gz`;
  return { version, file, sha256: sha, url: `https://github.com/gitleaks/gitleaks/releases/download/v${version}/${file}` };
}

export function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

/** tar.gz(ustar)에서 이름(basename)이 같은 일반 파일을 꺼낸다(src/lib/tools/archive.ts와 같은 방식). */
export function extractFromTarGz(tgz, fileName) {
  const tar = gunzipSync(tgz, { maxOutputLength: 200 * 1024 * 1024 });
  const field = (h, a, b) => h.subarray(a, b).toString("utf8").replace(/\0[\s\S]*$/, "");
  let p = 0;
  while (p + 512 <= tar.length) {
    const header = tar.subarray(p, p + 512);
    if (header.every((b) => b === 0)) break;
    const rawName = field(header, 0, 100);
    const prefix = field(header, 345, 500);
    const name = prefix ? `${prefix}/${rawName}` : rawName;
    const size = parseInt(field(header, 124, 136).trim() || "0", 8);
    const type = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    const start = p + 512;
    if (!Number.isFinite(size) || size < 0 || start + size > tar.length) throw new Error("tar: bad entry size");
    if (type === "0" && name.split(/[\\/]/).pop() === fileName) return Buffer.from(tar.subarray(start, start + size));
    p = start + Math.ceil(size / 512) * 512;
  }
  return undefined;
}

/** SHA-256 확인 → gitleaks 실행 파일만 꺼낸다. 맞지 않으면 예외. */
export function verifyAndExtract(archive, expectedSha) {
  const actual = sha256(archive);
  if (actual !== expectedSha) throw new Error(`SHA-256 mismatch (expected ${expectedSha}, got ${actual})`);
  const bin = extractFromTarGz(archive, "gitleaks");
  if (!bin || bin.length === 0) throw new Error("gitleaks binary not found in archive");
  return bin;
}

/** 확인한 압축 파일에서 실행 파일을 꺼내 target에 0755로 둔다. 실패하면 target을 남기지 않는다. */
export function installFromArchive(archive, expectedSha, target = VENDOR_BIN) {
  rmSync(target, { force: true });
  const bin = verifyAndExtract(archive, expectedSha);
  mkdirSync(path.dirname(target), { recursive: true });
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, bin);
    chmodSync(tmp, 0o755);
    renameSync(tmp, target);
  } finally {
    rmSync(tmp, { force: true });
  }
  return target;
}

async function download(url, signal) {
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const u = new URL(current);
    if (u.protocol !== "https:" || !RELEASE_HOSTS.has(u.hostname)) throw new Error(`refusing to download from ${u.hostname}`);
    const res = await fetch(current, { redirect: "manual", signal });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) throw new Error("redirect without location");
      current = new URL(loc, current).toString();
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (Number(res.headers.get("content-length") ?? "0") > MAX_BYTES) throw new Error("archive too large");
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_BYTES) throw new Error("archive too large");
    return buf;
  }
  throw new Error("too many redirects");
}

export async function main(argv = process.argv.slice(2)) {
  const force = argv.includes("--force");
  if (!force && (process.platform !== "linux" || process.arch !== "x64")) {
    // Windows·macOS 로컬 빌드는 조용히 건너뛴다.
    return 0;
  }
  // 이전 빌드에서 남은 파일은 먼저 지운다(실패하면 아무 파일도 남지 않게).
  rmSync(VENDOR_BIN, { force: true });
  try {
    const pinned = readPinned(readFileSync(ALLOWLIST_SOURCE, "utf8"));
    if (!pinned) throw new Error("could not read the pinned gitleaks version/SHA-256 from installableTools.ts");
    const archive = await download(pinned.url, AbortSignal.timeout(TIMEOUT_MS));
    const target = installFromArchive(archive, pinned.sha256);
    console.log(`[fetch-gitleaks] bundled gitleaks ${pinned.version} (linux x64) at ${path.relative(ROOT, target)}`);
  } catch (e) {
    rmSync(VENDOR_BIN, { force: true });
    console.warn(`[fetch-gitleaks] WARNING: gitleaks was not bundled (${e instanceof Error ? e.message : String(e)}). Scans will fall back to installing it at runtime.`);
  }
  return 0;
}

const invokedDirectly = Boolean(process.argv[1]) && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  main().then(
    () => process.exit(0),
    (e) => {
      console.warn(`[fetch-gitleaks] WARNING: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(0);
    }
  );
}
