import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { createProject } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import {
  parseScanMode,
  parseTestAccounts,
  redactProject,
  validateScanModeInput,
  SCAN_MODE_ERROR_MESSAGE,
} from "@/lib/domain/scanMode";
import { unzipToFileMap, UnzipError, type UnzipSkipped } from "@/lib/net/unzip";
import { isScannableFile } from "@/lib/demo/sourceFiles";
import { LIMITS } from "@/lib/config/limits";

/**
 * Create a project from an uploaded ZIP of source files.
 *
 * The server extracts source/manifest files (skipping binaries, node_modules,
 * build output) and stores them as the project's immutable original source
 * version. Nothing inside the archive is executed. The scan then analyzes
 * ONLY these files — never the bundled demo fixture.
 */
export async function POST(req: NextRequest) {
  try {
    const uid = await requireUserId();

    const form = await req.formData().catch(() => null);
    if (!form) return ok({ error: "업로드 형식이 올바르지 않습니다." }, 400);

    const name = String(form.get("name") ?? "").trim();
    if (!name) return ok({ error: "프로젝트 이름을 입력해 주세요." }, 400);

    const file = form.get("file");
    if (!(file instanceof File)) {
      return ok(
        {
          error: "source_required",
          message: "점검할 코드가 필요해요. ZIP 파일을 올리거나 코드를 붙여 넣어 주세요.",
        },
        400
      );
    }
    if (file.size > LIMITS.uploadZipBytes) {
      const mb = Math.floor(LIMITS.uploadZipBytes / 1024 / 1024);
      return ok(
        {
          error: "file_too_large",
          message: `ZIP 파일은 ${mb}MB 이하로 올려 주세요.`,
          limit: LIMITS.uploadZipBytes,
        },
        413
      );
    }

    const repositoryUrl = validateUrl(form.get("repositoryUrl"));
    const deploymentUrl = validateUrl(form.get("deploymentUrl"));
    if (form.get("repositoryUrl") && repositoryUrl === null) {
      return ok({ error: "저장소 주소가 올바른 URL이 아닙니다." }, 400);
    }
    if (form.get("deploymentUrl") && deploymentUrl === null) {
      return ok({ error: "배포 주소가 올바른 URL이 아닙니다." }, 400);
    }

    const buf = Buffer.from(await file.arrayBuffer());

    const skipped: UnzipSkipped[] = [];
    let extracted: Record<string, string>;
    try {
      extracted = unzipToFileMap(buf, undefined, skipped);
    } catch (e) {
      if (e instanceof UnzipError) {
        return ok({ error: "invalid_zip", message: e.message }, 400);
      }
      throw e;
    }

    // Keep only scannable source/manifest files.
    const scannable: Record<string, string> = {};
    for (const [p, c] of Object.entries(extracted)) {
      if (isScannableFile(p)) scannable[p] = c;
    }
    const count = Object.keys(scannable).length;
    if (count === 0) {
      return ok(
        {
          error: "source_required",
          message: "압축 파일에서 검사할 수 있는 소스 파일을 찾지 못했어요.",
        },
        400
      );
    }

    const deploymentAuthorized =
      Boolean(deploymentUrl) && form.get("deploymentAuthorized") === "true";

    // 보안 스캔 방식(A/B/C). ZIP이 있으므로 소스 조건은 항상 충족된다.
    const rawMode = form.get("scanMode");
    const scanMode = rawMode == null || rawMode === "" ? null : parseScanMode(rawMode);
    // 공개 웹사이트 점검(safe_active)은 더 이상 새로 만들 수 없다.
    if ((rawMode && scanMode === null) || scanMode === "safe_active") {
      return ok({ error: "invalid_scan_mode" }, 400);
    }
    const testAccounts = parseTestAccounts(form.get("testAccounts"));
    if (testAccounts === null) {
      return ok({ error: "invalid_test_accounts" }, 400);
    }
    if (scanMode) {
      const invalid = validateScanModeInput(scanMode, {
        hasSource: true,
        deploymentUrl: deploymentUrl ?? undefined,
        deploymentAuthorized,
        testAccounts,
      });
      if (invalid) {
        return ok({ error: invalid, message: SCAN_MODE_ERROR_MESSAGE[invalid] }, 400);
      }
    }

    const project = await createProject(uid, {
      name,
      repositoryUrl: repositoryUrl ?? undefined,
      deploymentUrl: deploymentUrl ?? undefined,
      files: scannable,
      sourceKind: "zip",
      sourceZipName: safeZipName(file.name),
      deploymentAuthorized,
      scanMode: scanMode ?? undefined,
      testAccounts: scanMode === "isolated_active" ? testAccounts : undefined,
    });

    // 한도·형식 때문에 읽지 않은 파일은 숨기지 않고 알려 준다.
    const skippedTooLarge = skipped.filter((s) => s.reason === "too_large").length;
    return ok(
      {
        project: redactProject(project),
        fileCount: count,
        skippedFileCount: skipped.length,
        skippedTooLarge,
      },
      201
    );
  } catch (err) {
    return handleApiError(err);
  }
}

/** Display-only file name: base name, no control chars, bounded length. */
function safeZipName(raw: string): string | undefined {
  const base = raw.split(/[\\/]/).pop() ?? "";
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 120);
  return cleaned || undefined;
}

function validateUrl(value: unknown): string | null | undefined {
  if (value == null || value === "") return undefined;
  if (typeof value !== "string") return null;
  try {
    const u = new URL(value.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.toString();
  } catch {
    return null;
  }
}
