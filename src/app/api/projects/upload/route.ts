import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { createProject } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import {
  parseScanMode,
  parseTestAccounts,
  redactProject,
  validateScanModeInput,
  SCAN_MODE_ERROR_MESSAGE,
} from "@/lib/domain/scanMode";
import { unzipToFileMap, UnzipError } from "@/lib/net/unzip";
import { isScannableFile, serializeFileMap } from "@/lib/demo/sourceFiles";

/** Hard cap on the uploaded archive itself (compressed). */
const MAX_ZIP_BYTES = 8 * 1024 * 1024; // 8 MB

/**
 * Create a project from an uploaded ZIP of source files.
 *
 * The server extracts source/manifest files (skipping binaries, node_modules,
 * build output), stores them as the project's source (in the shared
 * `// file:`-delimited format), and the scan then analyzes ONLY these files —
 * never the bundled demo fixture.
 */
export async function POST(req: NextRequest) {
  try {
    const uid = await getCurrentUserId();

    const form = await req.formData().catch(() => null);
    if (!form) return ok({ error: "업로드 형식이 올바르지 않습니다." }, 400);

    const name = String(form.get("name") ?? "").trim();
    if (!name) return ok({ error: "프로젝트 이름을 입력해 주세요." }, 400);

    const file = form.get("file");
    if (!(file instanceof File)) {
      return ok({ error: "ZIP 파일을 첨부해 주세요." }, 400);
    }
    if (file.size > MAX_ZIP_BYTES) {
      return ok(
        { error: `ZIP 파일이 너무 큽니다 (최대 ${MAX_ZIP_BYTES / 1024 / 1024}MB).` },
        400
      );
    }

    const repositoryUrl = validateUrl(form.get("repositoryUrl"));
    const deploymentUrl = validateUrl(form.get("deploymentUrl"));
    if (form.get("deploymentUrl") && deploymentUrl === null) {
      return ok({ error: "배포 주소가 올바른 URL이 아닙니다." }, 400);
    }

    const buf = Buffer.from(await file.arrayBuffer());

    let extracted: Record<string, string>;
    try {
      extracted = unzipToFileMap(buf);
    } catch (e) {
      if (e instanceof UnzipError) return ok({ error: e.message }, 400);
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
        { error: "압축 파일에서 검사할 수 있는 소스 파일을 찾지 못했습니다." },
        400
      );
    }

    const deploymentAuthorized =
      Boolean(deploymentUrl) && form.get("deploymentAuthorized") === "true";

    // 보안 스캔 방식(A/B/C). ZIP이 있으므로 소스 조건은 항상 충족된다.
    const rawMode = form.get("scanMode");
    const scanMode = rawMode == null || rawMode === "" ? null : parseScanMode(rawMode);
    if (rawMode && scanMode === null) {
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
      sourceCode: serializeFileMap(scannable),
      deploymentAuthorized,
      scanMode: scanMode ?? undefined,
      testAccounts: scanMode === "isolated_active" ? testAccounts : undefined,
    });

    return ok({ project: redactProject(project), fileCount: count }, 201);
  } catch (err) {
    return handleApiError(err);
  }
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
