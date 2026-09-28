import type { SecurityFinding } from "@/lib/domain/types";
import { findSecretMatches } from "@/lib/scanners/secretScanner";
import { maskSecret } from "@/lib/util";

/**
 * 화면에 보여 줄 코드 조각. 발견 위치의 줄(들)을 강조하고 위아래 몇 줄을 함께
 * 보여 준다. 비밀값은 항상 가린다(화면·응답·로그에 원문을 내보내지 않음).
 */
export interface CodeContext {
  file: string;
  /** lines[0]의 줄 번호(1부터). */
  startLine: number;
  lines: string[];
  /** 강조할 줄 번호들. */
  highlight: number[];
}

const MAX_LINE = 400;

/** 프로젝트에서 찾은 비밀값 목록(가림 처리용). 원문은 호출부 밖으로 내보내지 않는다. */
export function secretValues(files: Record<string, string>): string[] {
  return [...new Set(findSecretMatches(files).map((m) => m.raw))].sort((a, b) => b.length - a.length);
}

/** 글 속 비밀값을 가린다. 여러 줄짜리 키는 줄마다 가린 표시로 바꾼다. */
export function maskSecretValues(text: string, values: string[]): string {
  let out = text;
  for (const raw of values) {
    if (!out.includes(raw)) continue;
    const masked = raw.includes("\n")
      ? raw
          .split("\n")
          .map((l, i) => (i === 0 ? l : "•".repeat(Math.min(l.length, 16))))
          .join("\n")
      : maskSecret(raw);
    out = out.split(raw).join(masked);
  }
  return out;
}

function packageLine(content: string, name: string): number | undefined {
  const idx = content.split("\n").findIndex((l) => l.includes(`"${name}"`));
  return idx >= 0 ? idx + 1 : undefined;
}

export function codeContextFor(
  finding: SecurityFinding,
  files: Record<string, string>,
  secrets: string[],
  radius = 3
): CodeContext | undefined {
  let file = finding.location?.file;
  let line = finding.location?.line;
  const key = finding.verificationKey ?? "";
  if ((!file || !line) && key.startsWith("dep:") && files["package.json"] !== undefined) {
    file = "package.json";
    line = packageLine(files["package.json"], key.slice(4));
  }
  if (!file || !line || files[file] === undefined) return undefined;

  const all = maskSecretValues(files[file], secrets).split("\n");
  if (line < 1 || line > all.length) return undefined;

  // 근거 코드가 여러 줄이면 이어지는 줄까지 강조한다.
  const highlight = [line];
  const snippet = finding.evidence.find((e) => e.kind === "source_code")?.content ?? "";
  const snippetLines = snippet.split("\n").map((l) => l.trim()).filter(Boolean);
  for (let i = 1; i < snippetLines.length && line + i <= all.length; i++) {
    if (all[line - 1 + i].trim() === snippetLines[i]) highlight.push(line + i);
    else break;
  }

  const start = Math.max(1, line - radius);
  const end = Math.min(all.length, highlight[highlight.length - 1] + radius);
  return {
    file,
    startLine: start,
    lines: all.slice(start - 1, end).map((l) => (l.length > MAX_LINE ? `${l.slice(0, MAX_LINE)}…` : l)),
    highlight,
  };
}
