import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { listProjects, createProject } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import {
  parseScanMode,
  parseTestAccounts,
  redactProject,
  validateScanModeInput,
  SCAN_MODE_ERROR_MESSAGE,
} from "@/lib/domain/scanMode";

export async function GET() {
  try {
    const uid = await getCurrentUserId();
    const projects = await listProjects(uid);
    return ok({ projects: projects.map(redactProject) });
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

    // 능동 검사는 사용자가 대상 소유/테스트 권한을 확인했을 때만 허용.
    const deploymentAuthorized =
      Boolean(deploymentUrl) && body.deploymentAuthorized === true;

    // 보안 스캔 방식(A/B/C). 없으면 기존 동작을 유지한다.
    const scanMode = body.scanMode == null ? null : parseScanMode(body.scanMode);
    if (body.scanMode != null && scanMode === null) {
      return ok({ error: "invalid_scan_mode" }, 400);
    }
    const testAccounts = parseTestAccounts(body.testAccounts);
    if (testAccounts === null) {
      return ok({ error: "invalid_test_accounts" }, 400);
    }
    if (scanMode) {
      const invalid = validateScanModeInput(scanMode, {
        hasSource: Boolean(sourceCode?.trim()),
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
      sourceCode,
      deploymentAuthorized,
      scanMode: scanMode ?? undefined,
      // 테스트 계정은 C(격리 동적 분석)에서만 보관한다.
      testAccounts: scanMode === "isolated_active" ? testAccounts : undefined,
    });
    return ok({ project: redactProject(project) }, 201);
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
