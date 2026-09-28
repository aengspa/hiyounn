import { createHash } from "crypto";
import type { SourceVersion } from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * 파일 맵의 내용 해시. 경로 순서와 무관하게 같은 내용이면 같은 값이 나온다.
 * 경로와 내용 사이에 NUL 구분자를 넣어 경계를 섞어 만든 충돌을 막는다.
 */
export function hashFileMap(files: Record<string, string>): string {
  const h = createHash("sha256");
  for (const path of Object.keys(files).sort()) {
    h.update(path, "utf8");
    h.update("\u0000");
    h.update(files[path], "utf8");
    h.update("\u0000");
  }
  return h.digest("hex");
}

export function fileMapBytes(files: Record<string, string>): number {
  let total = 0;
  for (const content of Object.values(files)) total += Buffer.byteLength(content, "utf8");
  return total;
}

export function makeSourceVersion(input: {
  projectId: string;
  ownerId: string;
  kind: SourceVersion["kind"];
  files: Record<string, string>;
  parentVersionId?: string;
  fixJobId?: string;
}): SourceVersion {
  // 복사해서 저장한다. 호출부가 나중에 맵을 바꿔도 버전은 바뀌지 않는다.
  const files = { ...input.files };
  return {
    id: id("srcv"),
    projectId: input.projectId,
    ownerId: input.ownerId,
    kind: input.kind,
    parentVersionId: input.parentVersionId,
    fixJobId: input.fixJobId,
    files,
    fileCount: Object.keys(files).length,
    totalBytes: fileMapBytes(files),
    contentHash: hashFileMap(files),
    createdAt: now(),
  };
}
