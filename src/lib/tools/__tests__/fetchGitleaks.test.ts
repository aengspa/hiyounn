import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { getInstallableTool } from "@/lib/tools/installableTools";
import { ALLOWLIST_SOURCE, installFromArchive, readPinned, sha256 } from "../../../../scripts/fetch-gitleaks.mjs";

// 빌드 때 gitleaks를 받는 스크립트. 네트워크 없이 가짜 tar.gz로 확인한다.
const tmp = mkdtempSync(path.join(os.tmpdir(), "hoi-fetch-gitleaks-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function fakeTarGz(name: string, body: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0);
  header.write(body.length.toString(8).padStart(11, "0") + "\0", 124);
  header.write("0", 156);
  const pad = Buffer.alloc((512 - (body.length % 512)) % 512);
  return gzipSync(Buffer.concat([header, body, pad, Buffer.alloc(1024)]));
}

describe("fetch-gitleaks build script", () => {
  it("reads the same pinned version and linux-x64 SHA-256 as the allowlist", () => {
    const pinned = readPinned(readFileSync(ALLOWLIST_SOURCE, "utf8"));
    const gl = getInstallableTool("gitleaks")!;
    expect(gl.install.kind).toBe("github-release");
    if (gl.install.kind !== "github-release") return;
    const asset = gl.install.assets["linux-x64"];
    expect(pinned).toEqual({ version: gl.version, file: asset.file, sha256: asset.sha256, url: gl.install.baseUrl + asset.file });
    expect(readPinned("const X = 1;")).toBeUndefined();
  });

  it("extracts only the gitleaks binary with mode 755 when the hash matches", () => {
    const archive = fakeTarGz("gitleaks", Buffer.from("fake-gitleaks-binary"));
    const target = path.join(tmp, "ok", "gitleaks");
    expect(installFromArchive(archive, sha256(archive), target)).toBe(target);
    expect(readFileSync(target, "utf8")).toBe("fake-gitleaks-binary");
    if (process.platform !== "win32") expect(statSync(target).mode & 0o777).toBe(0o755);
  });

  it("never leaves a binary in place on hash mismatch or a missing binary", () => {
    const target = path.join(tmp, "bad", "gitleaks");
    const archive = fakeTarGz("gitleaks", Buffer.from("tampered"));
    const old = fakeTarGz("gitleaks", Buffer.from("old"));
    installFromArchive(old, sha256(old), target);
    expect(existsSync(target)).toBe(true);
    expect(() => installFromArchive(archive, "0".repeat(64), target)).toThrow(/SHA-256 mismatch/);
    expect(existsSync(target)).toBe(false);

    const noBin = fakeTarGz("README.md", Buffer.from("x"));
    writeFileSync(target, "stale");
    expect(() => installFromArchive(noBin, sha256(noBin), target)).toThrow(/not found/);
    expect(existsSync(target)).toBe(false);
  });
});
