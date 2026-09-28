import type { FixDiff } from "@/lib/domain/types";
import { isScannableFile } from "@/lib/demo/sourceFiles";

/**
 * 엄격한 패치 적용기.
 *
 * 수정안 한 개(= 여러 FixDiff)를 작업 복사본에 "전부 적용하거나 전혀 적용하지
 * 않는다". 다음은 성공으로 처리하지 않는다.
 *   - 프로젝트 밖 경로, 절대 경로, 상위 경로(..)
 *   - 존재하지 않는 파일(모델이 만들어 낸 경로 포함)
 *   - 원본에서 찾을 수 없는 변경 전 코드, 여러 곳에 겹치는 변경 전 코드
 *   - 앞선 수정이 이미 바꿔 버린 코드(충돌)
 *   - 변경 전·후가 같은 빈 diff, 삽입 위치를 알 수 없는 추가 전용 diff
 * 새 파일은 FixDiff.mode === "create"로 명시한 경우에만, 검사 대상 확장자이고
 * 아직 없는 경로일 때만 만든다.
 */

export type PatchFailure =
  | "unsafe_path"
  | "file_not_found"
  | "before_not_found"
  | "ambiguous_match"
  | "conflict"
  | "empty_diff"
  | "insertion_point_unknown"
  | "file_exists"
  | "disallowed_new_file";

export const PATCH_FAILURE_MESSAGE: Record<PatchFailure, string> = {
  unsafe_path: "프로젝트 밖의 경로를 바꾸려는 수정이라 적용하지 않았어요.",
  file_not_found: "수정하려는 파일이 업로드한 코드에 없어요.",
  before_not_found: "고칠 코드가 업로드한 파일 내용과 일치하지 않아 적용하지 않았어요.",
  ambiguous_match: "같은 코드가 여러 곳에 있어 어디를 고칠지 확정하지 못했어요.",
  conflict: "다른 항목의 수정과 같은 부분이 겹쳐 적용하지 않았어요.",
  empty_diff: "실제로 바뀌는 내용이 없는 수정안이라 적용하지 않았어요.",
  insertion_point_unknown: "코드를 어디에 넣을지 정할 수 없어 자동으로 적용하지 않았어요.",
  file_exists: "새로 만들려는 파일이 이미 있어서 덮어쓰지 않았어요.",
  disallowed_new_file: "허용되지 않은 종류의 새 파일이라 만들지 않았어요.",
};

export interface PatchOp {
  file: string;
  before: string;
  after: string;
  mode: "replace" | "create";
}

export type ApplyResult =
  | { ok: true; changedFiles: string[]; notes: string[] }
  | { ok: false; failure: PatchFailure; file: string };

/**
 * 사용자 입력 경로를 검사해 안전한 상대 경로를 돌려준다. 정규화 과정에서
 * 뭔가를 버려야 했다면(.., 절대 경로, 드라이브 문자) 안전하지 않은 것으로 본다.
 */
export function safeProjectPath(raw: string): string | null {
  const p = raw.trim().replace(/\\/g, "/");
  if (!p) return null;
  if (p.startsWith("/") || /^[a-zA-Z]:/.test(p)) return null;
  const parts = p.split("/");
  if (parts.some((seg) => seg === "..")) return null;
  if (/[\u0000-\u001f]/.test(p)) return null;
  const cleaned = parts.filter((seg) => seg && seg !== ".").join("/");
  return cleaned || null;
}

/** 표시용 patch 문자열에서 변경 전·후 텍스트를 만든다. 문맥 줄은 양쪽에 들어간다. */
export function textsFromPatch(patch: string): { before: string; after: string } {
  const before: string[] = [];
  const after: string[] = [];
  for (const line of patch.split("\n")) {
    if (line.startsWith("- ")) before.push(line.slice(2));
    else if (line.startsWith("-")) before.push(line.slice(1));
    else if (line.startsWith("+ ")) after.push(line.slice(2));
    else if (line.startsWith("+")) after.push(line.slice(1));
    else {
      const ctx = line.startsWith("  ") ? line.slice(2) : line;
      if (ctx.trim() === "") continue;
      before.push(ctx);
      after.push(ctx);
    }
  }
  return { before: before.join("\n"), after: after.join("\n") };
}

export function diffToOp(diff: FixDiff): { op: PatchOp } | { failure: PatchFailure; file: string } {
  const file = safeProjectPath(diff.file ?? "");
  if (!file) return { failure: "unsafe_path", file: diff.file ?? "" };

  const explicit = diff.beforeText !== undefined || diff.afterText !== undefined;
  const { before, after } = explicit
    ? { before: diff.beforeText ?? "", after: diff.afterText ?? "" }
    : textsFromPatch(diff.patch ?? "");
  const mode = diff.mode === "create" ? "create" : "replace";

  if (mode === "create") {
    if (!after.trim()) return { failure: "empty_diff", file };
    return { op: { file, before: "", after, mode } };
  }
  if (!before.trim()) return { failure: "insertion_point_unknown", file };
  if (before === after || before.trim() === after.trim()) return { failure: "empty_diff", file };
  return { op: { file, before, after, mode } };
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return count;
    count += 1;
    from = at + needle.length;
  }
}

function trimEmptyEdges(lines: string[]): string[] {
  let start = 0;
  let end = lines.length;
  while (start < end && lines[start].trim() === "") start += 1;
  while (end > start && lines[end - 1].trim() === "") end -= 1;
  return lines.slice(start, end);
}

function leadingWhitespace(s: string): string {
  return s.match(/^[ \t]*/)?.[0] ?? "";
}

/** 줄 앞뒤 공백을 무시하고 before 줄 묶음이 나타나는 시작 줄 목록. */
function findLineWindows(currentLines: string[], beforeLines: string[]): number[] {
  const hits: number[] = [];
  const target = beforeLines.map((l) => l.trim());
  if (target.length === 0) return hits;
  for (let i = 0; i + target.length <= currentLines.length; i++) {
    let match = true;
    for (let j = 0; j < target.length; j++) {
      if (currentLines[i + j].trim() !== target[j]) {
        match = false;
        break;
      }
    }
    if (match) hits.push(i);
  }
  return hits;
}

/** after 줄들을 찾은 위치의 들여쓰기에 맞춘다. */
function reindent(afterLines: string[], baseIndent: string): string[] {
  const indents = afterLines.filter((l) => l.trim()).map((l) => leadingWhitespace(l).length);
  const common = indents.length ? Math.min(...indents) : 0;
  return afterLines.map((l) => (l.trim() ? baseIndent + l.slice(common) : l));
}

type OpOutcome =
  | { ok: true; content: string; note?: string }
  | { ok: false; failure: PatchFailure };

function applyReplace(current: string, original: string | undefined, op: PatchOp): OpOutcome {
  const exact = countOccurrences(current, op.before);
  if (exact === 1) return { ok: true, content: current.replace(op.before, () => op.after) };
  if (exact > 1) return { ok: false, failure: "ambiguous_match" };

  const beforeLines = trimEmptyEdges(op.before.split("\n"));
  const currentLines = current.split("\n");
  const windows = findLineWindows(currentLines, beforeLines);
  if (windows.length === 1) {
    const at = windows[0];
    const afterLines = reindent(trimEmptyEdges(op.after.split("\n")), leadingWhitespace(currentLines[at]));
    const next = [...currentLines.slice(0, at), ...afterLines, ...currentLines.slice(at + beforeLines.length)];
    return { ok: true, content: next.join("\n") };
  }
  if (windows.length > 1) return { ok: false, failure: "ambiguous_match" };

  // 원본에는 있었는데 지금 없다면 앞선 수정이 이미 바꾼 것이다.
  const inOriginal =
    original !== undefined &&
    (countOccurrences(original, op.before) > 0 ||
      findLineWindows(original.split("\n"), beforeLines).length > 0);
  if (inOriginal) {
    // 앞선 항목이 똑같은 수정을 이미 적용했다면 같은 수정으로 함께 해결된 것이다.
    const afterLines = trimEmptyEdges(op.after.split("\n"));
    if (afterLines.length > 0 && findLineWindows(currentLines, afterLines).length > 0) {
      return { ok: true, content: current, note: "same_fix_already_applied" };
    }
    return { ok: false, failure: "conflict" };
  }
  return { ok: false, failure: "before_not_found" };
}

/**
 * 수정안 하나의 diff들을 `working`에 원자적으로 적용한다.
 * `original`은 이번 작업의 기준 버전(충돌 판별용)이며 바꾸지 않는다.
 * 실패하면 `working`은 그대로다.
 */
export function applyDiffsAtomically(
  working: Record<string, string>,
  original: Record<string, string>,
  diffs: FixDiff[]
): ApplyResult {
  if (diffs.length === 0) return { ok: false, failure: "empty_diff", file: "" };

  const staged: Record<string, string> = {};
  const notes: string[] = [];
  const read = (file: string) => (file in staged ? staged[file] : working[file]);

  for (const diff of diffs) {
    const converted = diffToOp(diff);
    if ("failure" in converted) return { ok: false, failure: converted.failure, file: converted.file };
    const op = converted.op;

    if (op.mode === "create") {
      if (read(op.file) !== undefined) return { ok: false, failure: "file_exists", file: op.file };
      if (!isScannableFile(op.file)) return { ok: false, failure: "disallowed_new_file", file: op.file };
      staged[op.file] = op.after;
      continue;
    }

    const current = read(op.file);
    if (current === undefined) return { ok: false, failure: "file_not_found", file: op.file };
    const outcome = applyReplace(current, original[op.file], op);
    if (!outcome.ok) return { ok: false, failure: outcome.failure, file: op.file };
    if (outcome.note) notes.push(outcome.note);
    staged[op.file] = outcome.content;
  }

  const changedFiles: string[] = [];
  for (const [file, content] of Object.entries(staged)) {
    if (working[file] !== content) {
      working[file] = content;
      changedFiles.push(file);
    }
  }
  return { ok: true, changedFiles, notes };
}
