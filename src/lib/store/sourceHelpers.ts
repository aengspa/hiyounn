import type { Project } from "@/lib/domain/types";
import { parseSourceBlob } from "@/lib/demo/sourceFiles";
import { AppError } from "./errors";

/** Real projects must carry code. A repository URL alone is not code. */
export function assertHasSourceFiles(files: Record<string, string> | undefined): void {
  const count = files ? Object.keys(files).filter((p) => files[p].length > 0).length : 0;
  if (count === 0) {
    throw new AppError(
      400,
      "source_required",
      "점검할 코드가 필요해요. ZIP 파일을 올리거나 코드를 붙여 넣어 주세요."
    );
  }
}

export class SourceMissingError extends AppError {
  constructor() {
    super(
      409,
      "source_missing",
      "이 프로젝트에는 점검할 코드가 없어요. 코드를 올려 새 프로젝트로 등록해 주세요."
    );
    this.name = "SourceMissingError";
  }
}

/**
 * Projects created before source versions existed only have the serialized
 * `sourceCode` blob. Returns its file map so a version can be created lazily,
 * or undefined when there is no code at all.
 */
export function legacyFilesFromProject(project: Project): Record<string, string> | undefined {
  if (!project.sourceCode || !project.sourceCode.trim()) return undefined;
  const files = parseSourceBlob(project.sourceCode);
  return Object.keys(files).length > 0 ? files : undefined;
}
