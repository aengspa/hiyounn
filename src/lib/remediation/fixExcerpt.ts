import type { SecurityEvidence } from "@/lib/domain/types";

/**
 * 긴 파일의 AI 수정용 발췌.
 *
 * 한 번의 AI 호출에 담을 수 있는 길이(LIMITS.llmFixWindowChars)보다 긴 파일은
 * 파일 전체 대신 문제 위치 주변만 보낸다. 발췌는 원본 파일의 연속된 줄(또는 아주
 * 긴 한 줄의 연속된 일부)을 그대로 잘라 낸 것이므로, 모델이 발췌에서 그대로
 * 옮긴 "before"는 원본 파일에서도 그대로 찾을 수 있다. 실제 적용은 언제나 전체
 * 파일에 patchEngine의 정확 일치 규칙으로 한다.
 */

export interface ExcerptPart {
  /** 전체 파일 기준 시작 줄(1부터). */
  startLine: number;
  /** 전체 파일 기준 끝 줄(포함). */
  endLine: number;
  /** 원본에서 그대로 잘라 낸 내용. */
  text: string;
  /** 한 줄이 너무 길어 그 줄의 일부만 담았으면 true. */
  partial?: boolean;
}

export interface FileExcerpt {
  totalLines: number;
  parts: ExcerptPart[];
}

/** 발췌에 담긴 파일 내용 글자 수(모델에 보내는 파일 내용의 양). */
export function excerptChars(ex: FileExcerpt): number {
  return ex.parts.reduce((n, p) => n + p.text.length, 0);
}

/** 머리말(import/require) 몫은 한도의 이 비율까지만 쓴다. */
const HEADER_SHARE = 0.25;
const HEADER_MAX_LINES = 200;
/** 둘러싼 함수·블록을 찾을 때 위아래로 볼 최대 줄 수. */
const BLOCK_SCAN_LINES = 2000;

const IMPORT_START = /^\s*import\b/;
const HEADER_LINE =
  /^\s*(?:export\s+(?:\*|\{[^}]*\}|type\s+\{[^}]*\})\s*from\b|["']use (?:client|server|strict)["'];?\s*$|(?:const|let|var)\s+[^=]+=\s*require\(|require\(|#!)/;
const COMMENT_OR_BLANK = /^\s*(?:$|\/\/|\/\*|\*|\*\/)/;

class Lines {
  readonly lines: string[];
  /** pre[i] = 앞의 i줄 길이 합 + 줄바꿈 수. */
  private readonly pre: number[];
  constructor(content: string) {
    this.lines = content.split("\n");
    this.pre = [0];
    for (const l of this.lines) this.pre.push(this.pre[this.pre.length - 1] + l.length + 1);
  }
  get count(): number {
    return this.lines.length;
  }
  /** a..b 줄(1부터, 포함)을 이어 붙인 글자 수. */
  cost(a: number, b: number): number {
    return b < a ? 0 : this.pre[b] - this.pre[a - 1] - 1;
  }
  text(a: number, b: number): string {
    return this.lines.slice(a - 1, b).join("\n");
  }
}

/** 파일 맨 앞의 import/require 머리말이 끝나는 줄(없으면 0). */
function headerEnd(L: Lines, maxChars: number): number {
  let end = 0;
  let inImport = false;
  for (let i = 1; i <= Math.min(L.count, HEADER_MAX_LINES); i++) {
    const line = L.lines[i - 1];
    let isHeader = false;
    if (inImport) {
      isHeader = true;
      if (/\bfrom\b|;\s*$|^\s*["']/.test(line)) inImport = false;
    } else if (IMPORT_START.test(line)) {
      isHeader = true;
      // 여러 줄 import: `import {` … `} from "x";`
      inImport = !/\bfrom\b|^\s*import\s*["']|^\s*import\s*\(|;\s*$/.test(line);
    } else if (HEADER_LINE.test(line)) {
      isHeader = true;
    } else if (!COMMENT_OR_BLANK.test(line)) {
      break;
    }
    if (isHeader) {
      if (L.cost(1, i) > maxChars) break;
      end = i;
    }
  }
  return end;
}

function indentOf(line: string): number {
  return line.match(/^[ \t]*/)?.[0].length ?? 0;
}

/**
 * 대상 줄을 감싸는 맨 바깥(들여쓰기 0) 문장·함수의 범위. 들여쓰기로만 판단하는
 * 가벼운 추정이며 못 찾으면 null.
 */
function enclosingBlock(L: Lines, line: number): [number, number] | null {
  let start = 0;
  for (let i = line; i >= Math.max(1, line - BLOCK_SCAN_LINES); i--) {
    const l = L.lines[i - 1];
    if (l.trim() && indentOf(l) === 0 && !/^[}\])]/.test(l)) {
      start = i;
      break;
    }
  }
  if (!start) return null;
  for (let i = Math.max(line, start) + 1; i <= Math.min(L.count, line + BLOCK_SCAN_LINES); i++) {
    const l = L.lines[i - 1];
    if (!l.trim() || indentOf(l) > 0) continue;
    return /^[}\])]/.test(l) ? [start, i] : [start, i - 1];
  }
  return [start, L.count];
}

/** 한 줄이 한도보다 길 때: 그 줄의 연속된 일부(가능하면 찾은 코드를 가운데로). */
function partialLine(L: Lines, line: number, budget: number, center?: number): ExcerptPart {
  const text = L.lines[line - 1];
  const mid = center === undefined ? 0 : center;
  const from = Math.max(0, Math.min(text.length - budget, mid - Math.floor(budget / 2)));
  return { startLine: line, endLine: line, text: text.slice(from, from + budget), partial: true };
}

/**
 * 대상 줄 주변 발췌. 감싸는 함수·블록이 한도 안에 들어오면 통째로 담고, 남는
 * 몫은 위아래로 고르게 넓힌다. 머리말(import/require)은 따로 앞에 붙인다.
 * 모든 조각의 글자 수 합은 `budget`을 넘지 않는다.
 *
 * @param column 대상 줄 안에서 문제 코드가 시작하는 위치(아주 긴 한 줄일 때만 쓴다).
 */
export function excerptAroundLine(content: string, line: number, budget: number, column?: number): FileExcerpt {
  const L = new Lines(content);
  const n = L.count;
  const target = Math.min(Math.max(1, Math.floor(line) || 1), n);
  if (L.lines[target - 1].length > budget) {
    return { totalLines: n, parts: [partialLine(L, target, budget, column)] };
  }

  let hdr = headerEnd(L, Math.floor(budget * HEADER_SHARE));
  const total = (a: number, b: number) => (a <= hdr + 1 ? L.cost(1, b) : L.cost(1, hdr) + L.cost(a, b));
  if (total(target, target) > budget) hdr = 0;

  let [a, b] = [target, target];
  const block = enclosingBlock(L, target);
  if (block && total(block[0], block[1]) <= budget) [a, b] = block;
  for (;;) {
    let grew = false;
    if (a > 1 && total(a - 1, b) <= budget) {
      a -= 1;
      grew = true;
    }
    if (b < n && total(a, b + 1) <= budget) {
      b += 1;
      grew = true;
    }
    if (!grew) break;
  }

  const parts: ExcerptPart[] =
    a <= hdr + 1
      ? [{ startLine: 1, endLine: b, text: L.text(1, b) }]
      : [
          ...(hdr > 0 ? [{ startLine: 1, endLine: hdr, text: L.text(1, hdr) }] : []),
          { startLine: a, endLine: b, text: L.text(a, b) },
        ];
  return { totalLines: n, parts };
}

/**
 * 파일 전체를 한도에 맞는 연속된 조각으로 나눈다(앞에서부터). 각 조각에는
 * 머리말(import/require)을 함께 붙인다. 한도보다 긴 한 줄은 글자 단위로 나눈다.
 */
export function chunkFile(content: string, budget: number): FileExcerpt[] {
  const L = new Lines(content);
  const n = L.count;
  const hdr = headerEnd(L, Math.floor(budget * HEADER_SHARE));
  const hdrPart: ExcerptPart | null = hdr > 0 ? { startLine: 1, endLine: hdr, text: L.text(1, hdr) } : null;
  const out: FileExcerpt[] = [];
  let a = 1;
  while (a <= n) {
    // 첫 조각은 머리말부터 이어서 담는다(따로 붙이지 않음).
    const withHdr = hdrPart !== null && a > hdr;
    const room = budget - (withHdr ? hdrPart!.text.length : 0);
    if (L.lines[a - 1].length > room) {
      const text = L.lines[a - 1];
      for (let from = 0; from < text.length; from += budget) {
        out.push({ totalLines: n, parts: [{ startLine: a, endLine: a, text: text.slice(from, from + budget), partial: true }] });
      }
      a += 1;
      continue;
    }
    let b = a;
    while (b < n && L.cost(a, b + 1) <= room) b += 1;
    out.push({
      totalLines: n,
      parts: [...(withHdr ? [hdrPart!] : []), { startLine: a, endLine: b, text: L.text(a, b) }],
    });
    a = b + 1;
  }
  return out;
}

/**
 * 근거 코드(source_code)가 파일의 어디에 있는지 찾는다. 근거 전체를 먼저 찾고,
 * 없으면 근거의 의미 있는 줄 하나씩 찾는다. 못 찾으면 null.
 */
export function findEvidenceLine(
  content: string,
  evidence: SecurityEvidence[]
): { line: number; column: number } | null {
  const at = (offset: number) => {
    const lineStart = content.lastIndexOf("\n", offset - 1) + 1;
    return { line: content.slice(0, offset).split("\n").length, column: offset - lineStart };
  };
  const snippets = evidence.filter((e) => e.kind === "source_code").map((e) => e.content.trim());
  for (const s of snippets) {
    if (s.length >= 4) {
      const i = content.indexOf(s);
      if (i >= 0) return at(i);
    }
  }
  for (const s of snippets) {
    for (const piece of s.split("\n").map((l) => l.trim())) {
      if (piece.length < 8) continue;
      const i = content.indexOf(piece);
      if (i >= 0) return at(i);
    }
  }
  return null;
}
