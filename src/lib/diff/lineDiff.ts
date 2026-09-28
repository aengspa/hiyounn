/**
 * 줄 단위 diff (수정 전후 비교 화면용).
 *
 * 앞뒤로 같은 줄을 먼저 떼어 내고, 가운데만 LCS로 비교한다. 가운데가 너무 크면
 * (줄 수 곱이 한도를 넘으면) 통째로 바뀐 것으로 보여 준다(느려지지 않게).
 */

export type DiffLine = { type: "ctx" | "del" | "add"; oldNo?: number; newNo?: number; text: string };

export interface DiffHunk {
  oldStart: number;
  newStart: number;
  lines: DiffLine[];
}

export interface FileDiff {
  hunks: DiffHunk[];
  added: number;
  removed: number;
  /** 너무 커서 가운데를 LCS로 비교하지 않았는지. */
  coarse: boolean;
}

const MAX_CELLS = 4_000_000;

export function diffLines(a: string[], b: string[]): { lines: DiffLine[]; coarse: boolean } {
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;

  const out: DiffLine[] = [];
  for (let i = 0; i < pre; i++) out.push({ type: "ctx", oldNo: i + 1, newNo: i + 1, text: a[i] });

  const am = a.slice(pre, a.length - suf);
  const bm = b.slice(pre, b.length - suf);
  let coarse = false;
  if (am.length * bm.length > MAX_CELLS) {
    coarse = true;
    am.forEach((t, i) => out.push({ type: "del", oldNo: pre + i + 1, text: t }));
    bm.forEach((t, j) => out.push({ type: "add", newNo: pre + j + 1, text: t }));
  } else {
    // LCS 길이 표(뒤에서부터).
    const n = am.length;
    const m = bm.length;
    const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i][j] = am[i] === bm[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && am[i] === bm[j]) {
        out.push({ type: "ctx", oldNo: pre + i + 1, newNo: pre + j + 1, text: am[i] });
        i++;
        j++;
      } else if (i < n && (j >= m || dp[i + 1][j] >= dp[i][j + 1])) {
        // 같은 길이면 지운 줄을 먼저 보여 준다(일반적인 diff 순서).
        out.push({ type: "del", oldNo: pre + i + 1, text: am[i] });
        i++;
      } else {
        out.push({ type: "add", newNo: pre + j + 1, text: bm[j] });
        j++;
      }
    }
  }

  const oldBase = a.length - suf;
  const newBase = b.length - suf;
  for (let k = 0; k < suf; k++) out.push({ type: "ctx", oldNo: oldBase + k + 1, newNo: newBase + k + 1, text: a[oldBase + k] });
  return { lines: out, coarse };
}

/** 바뀐 곳 주변 context줄만 남겨 덩어리(hunk)로 묶는다. */
export function toHunks(lines: DiffLine[], context = 3): DiffHunk[] {
  const changed = lines.map((l, i) => (l.type !== "ctx" ? i : -1)).filter((i) => i >= 0);
  if (changed.length === 0) return [];
  const hunks: DiffHunk[] = [];
  let start = Math.max(0, changed[0] - context);
  let end = Math.min(lines.length - 1, changed[0] + context);
  const flush = () => {
    const slice = lines.slice(start, end + 1);
    const firstOld = slice.find((l) => l.oldNo !== undefined)?.oldNo ?? 0;
    const firstNew = slice.find((l) => l.newNo !== undefined)?.newNo ?? 0;
    hunks.push({ oldStart: firstOld, newStart: firstNew, lines: slice });
  };
  for (const idx of changed.slice(1)) {
    if (idx - context <= end + 1) end = Math.min(lines.length - 1, idx + context);
    else {
      flush();
      start = Math.max(0, idx - context);
      end = Math.min(lines.length - 1, idx + context);
    }
  }
  flush();
  return hunks;
}

export function fileDiff(before: string, after: string, context = 3): FileDiff {
  const { lines, coarse } = diffLines(before.split("\n"), after.split("\n"));
  return {
    hunks: toHunks(lines, context),
    added: lines.filter((l) => l.type === "add").length,
    removed: lines.filter((l) => l.type === "del").length,
    coarse,
  };
}
