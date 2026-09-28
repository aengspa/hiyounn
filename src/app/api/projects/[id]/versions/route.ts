import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { addSourceVersion, getCurrentSourceVersion } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import { parseSourceBlob, isScannableFile } from "@/lib/demo/sourceFiles";
import { unzipToFileMap, UnzipError } from "@/lib/net/unzip";
import { LIMITS } from "@/lib/config/limits";

/**
 * POST /api/projects/[id]/versions — 같은 프로젝트에 코드를 새로 올린다.
 * JSON { sourceCode } 또는 multipart { file: ZIP }. 새 버전이 현재 버전이 되고,
 * 다음 점검은 이전 점검과 비교해 바뀐 파일만 AI가 새로 본다.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const uid = await requireUserId();
    const previous = await getCurrentSourceVersion(params.id, uid);
    let files: Record<string, string>;
    let meta: { sourceKind: "zip" | "paste"; zipName?: string };

    if ((req.headers.get("content-type") ?? "").includes("multipart/form-data")) {
      const form = await req.formData().catch(() => null);
      const file = form?.get("file");
      if (!(file instanceof File)) return ok({ error: "source_required", message: "ZIP 파일을 올려 주세요." }, 400);
      if (file.size > LIMITS.uploadZipBytes) {
        return ok({ error: "file_too_large", message: `ZIP 파일은 ${Math.floor(LIMITS.uploadZipBytes / 1024 / 1024)}MB 이하로 올려 주세요.` }, 413);
      }
      let extracted: Record<string, string>;
      try {
        extracted = unzipToFileMap(Buffer.from(await file.arrayBuffer()));
      } catch (e) {
        if (e instanceof UnzipError) return ok({ error: "invalid_zip", message: e.message }, 400);
        throw e;
      }
      files = Object.fromEntries(Object.entries(extracted).filter(([p]) => isScannableFile(p)));
      meta = { sourceKind: "zip", zipName: file.name.split(/[\\/]/).pop()?.slice(0, 120) };
    } else {
      const body = await req.json().catch(() => ({}));
      const sourceCode = typeof body?.sourceCode === "string" ? body.sourceCode : "";
      if (!sourceCode.trim()) return ok({ error: "source_required", message: "코드를 붙여 넣어 주세요." }, 400);
      if (sourceCode.length > LIMITS.pastedSourceChars) {
        return ok({ error: "source_too_large", message: "붙여 넣은 코드가 너무 길어요. ZIP 파일로 올려 주세요." }, 413);
      }
      files = parseSourceBlob(sourceCode);
      meta = { sourceKind: "paste" };
    }
    if (Object.keys(files).length === 0) {
      return ok({ error: "source_required", message: "검사할 수 있는 소스 파일을 찾지 못했어요." }, 400);
    }

    const version = await addSourceVersion(params.id, uid, files, meta);
    const changedFiles = Object.keys(files).filter((p) => previous?.files[p] !== files[p]).sort();
    return ok({ version: { id: version.id, fileCount: version.fileCount, contentHash: version.contentHash }, changedFiles }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
