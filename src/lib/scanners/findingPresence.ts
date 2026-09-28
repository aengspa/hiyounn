/**
 * 규칙 재검사의 판단 단위는 "항목 하나"다.
 *
 * 예전에는 수정본 파일 어디에든 같은 종류의 신호가 남아 있으면 그 종류의 모든
 * 항목을 "남아 있음"으로 봤다. 그래서 한 줄의 오탐이 같은 파일의 다른 항목까지
 * 실패로 만들었다. 여기서는 원래 문제가 된 그 줄을 따라간다.
 *
 * 남아 있다고 보는 경우(보수적으로):
 *  1) 원래 문제가 된 줄이 수정본에도 그대로 있고, 같은 신호가 여전히 잡힘
 *  2) 같은 신호가 원본에 없던 새 줄에서 잡힘(수정이 같은 문제를 새로 만듦)
 *  3) 원본을 모를 때는 원래 줄 근처(±5줄)에서 같은 신호가 잡힘
 */

export interface SignalHit {
  line: number;
  text: string;
}

const NEAR_LINES = 5;

function norm(text: string): string {
  return text.trim().replace(/\s+/g, " ");
}

export function stillPresentAfterFix(input: {
  /** 수정본에서 같은 신호가 잡힌 곳. */
  hits: SignalHit[];
  /** 원래 발견의 줄 내용(근거). */
  originalLineText?: string;
  originalLine?: number;
  /** 수정 전 같은 파일 내용(재검증 때). */
  baselineContent?: string;
  /** 수정본 파일의 줄 수(줄 번호가 얼마나 밀렸는지 가늠할 때). */
  fixedLineCount?: number;
}): boolean {
  const { hits, originalLineText, originalLine, baselineContent, fixedLineCount } = input;
  if (hits.length === 0) return false;

  const original = originalLineText ? norm(originalLineText) : "";
  if (original && hits.some((h) => norm(h.text) === original)) return true;

  if (baselineContent !== undefined) {
    const baseline = baselineContent.split("\n");
    const baselineLines = new Set(baseline.map(norm));
    // 같은 파일의 다른 항목을 고치며 생긴 새 줄까지 이 항목 탓으로 돌리지 않도록,
    // 원래 줄 근처(수정으로 밀린 줄 수만큼 여유)의 새 줄만 본다.
    const shift = fixedLineCount === undefined ? 0 : Math.abs(fixedLineCount - baseline.length);
    return hits.some(
      (h) =>
        !baselineLines.has(norm(h.text)) &&
        (originalLine === undefined || Math.abs(h.line - originalLine) <= NEAR_LINES + shift)
    );
  }

  if (originalLine !== undefined) {
    return hits.some((h) => Math.abs(h.line - originalLine) <= NEAR_LINES);
  }
  // 원래 위치를 전혀 모르면 안전하다고 단정하지 않는다.
  return true;
}
