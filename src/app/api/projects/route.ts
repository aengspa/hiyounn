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

export async function POST(req: NextRequest) {
  try {
    const uid = await getCurrentUserId();
    const body = await req.json().catch(() => ({}));

    // 입력 검증.
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) {
      return ok({ error: "프로젝트 이름을 입력해 주세요." }, 400);
    }
    const repositoryUrl = validateUrl(body.repositoryUrl);
    const deploymentUrl = validateUrl(body.deploymentUrl);
    if (body.repositoryUrl && repositoryUrl === null) {
      return ok({ error: "저장소 주소가 올바른 URL이 아닙니다." }, 400);
    }
    if (body.deploymentUrl && deploymentUrl === null) {
      return ok({ error: "배포 주소가 올바른 URL이 아닙니다." }, 400);
    }

    // 붙여넣은 소스 코드(선택). 과도한 크기는 방지.
    const sourceCode =
      typeof body.sourceCode === "string"
        ? body.sourceCode.slice(0, 100000)
        : undefined;

    const project = createProject(uid, {
      name,
      repositoryUrl: repositoryUrl ?? undefined,
      deploymentUrl: deploymentUrl ?? undefined,
      sourceCode,
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
