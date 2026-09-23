import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { listProjects, createProject } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export async function GET() {
  try {
    const uid = await getCurrentUserId();
    return ok({ projects: listProjects(uid) });
  } catch (err) {
    return handleApiError(err);
  }
}

const MAX_ZIP_BYTES = 25 * 1024 * 1024; // 25MB

export async function POST(req: NextRequest) {
  try {
    const uid = await getCurrentUserId();

    // JSON과 multipart/form-data(파일 업로드) 요청을 모두 지원.
    const contentType = req.headers.get("content-type") ?? "";
    let name = "";
    let rawDeploymentUrl: unknown;
    let sourceZipName: string | undefined;

    if (contentType.includes("multipart/form-data")) {
      const form = await req.formData();
      name = typeof form.get("name") === "string" ? String(form.get("name")).trim() : "";
      rawDeploymentUrl = form.get("deploymentUrl") ?? undefined;

      const zip = form.get("sourceZip");
      if (zip instanceof File && zip.size > 0) {
        const isZip =
          zip.name.toLowerCase().endsWith(".zip") ||
          zip.type === "application/zip" ||
          zip.type === "application/x-zip-compressed";
        if (!isZip) {
          return ok({ error: "zip 파일만 업로드할 수 있습니다." }, 400);
        }
        if (zip.size > MAX_ZIP_BYTES) {
          return ok({ error: "zip 파일은 25MB 이하여야 합니다." }, 400);
        }
        sourceZipName = zip.name;
        // NOTE: zip 압축 해제 및 코드 스캔 연동은 후속 단계에서 구현.
      }
    } else {
      const body = await req.json().catch(() => ({}));
      name = typeof body.name === "string" ? body.name.trim() : "";
      rawDeploymentUrl = body.deploymentUrl;
    }

    if (!name) {
      return ok({ error: "프로젝트 이름을 입력해 주세요." }, 400);
    }
    const deploymentUrl = validateUrl(rawDeploymentUrl);
    if (rawDeploymentUrl && deploymentUrl === null) {
      return ok({ error: "배포 주소가 올바른 URL이 아닙니다." }, 400);
    }

    const project = createProject(uid, {
      name,
      deploymentUrl: deploymentUrl ?? undefined,
      sourceZipName,
    });
    return ok({ project }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}

/** Returns the trimmed URL if valid http(s), "" if empty, null if invalid. */
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
