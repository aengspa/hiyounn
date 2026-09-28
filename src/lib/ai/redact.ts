import { findSecretMatches } from "@/lib/scanners/secretScanner";

/**
 * 외부 AI로 보내기 전에 코드에서 비밀값을 가린다.
 *
 * 비밀 스캐너와 같은 규칙으로 찾은 값을 `__HOI_REDACTED_SECRET_n__`으로 바꾼다.
 * 같은 값은 같은 자리표시자가 되므로 모델이 코드 구조를 그대로 볼 수 있다.
 * AI가 돌려준 수정안(before/after)은 restore()로 원래 값을 되돌린 뒤 실제
 * 파일과 대조한다. 원래 파일에 있던 값만 되돌리므로 새 비밀값이 생기지 않는다.
 */

const PLACEHOLDER = (n: number) => `__HOI_REDACTED_SECRET_${n}__`;
const PLACEHOLDER_RE = /__HOI_REDACTED_SECRET_(\d+)__/g;

export interface Redaction {
  /** 비밀값을 가린 파일들(입력과 같은 키). */
  files: Record<string, string>;
  /** 가린 서로 다른 값의 수. */
  count: number;
  /** 자리표시자를 원래 값으로 되돌린다. 모르는 자리표시자는 그대로 둔다. */
  restore(text: string): string;
  /** 파일 밖의 글(근거 문구 등)도 같은 규칙으로 가린다. */
  redactText(text: string): string;
}

export function redactSecrets(files: Record<string, string>): Redaction {
  // 긴 값부터 바꿔야 짧은 값이 긴 값의 일부를 먼저 망가뜨리지 않는다.
  const values = [...new Set(findSecretMatches(files).map((m) => m.raw))]
    .filter((v) => v.length >= 8)
    .sort((a, b) => b.length - a.length);
  const byPlaceholder = new Map<number, string>();
  const out: Record<string, string> = {};
  for (const [path, content] of Object.entries(files)) out[path] = content;

  values.forEach((raw, i) => {
    byPlaceholder.set(i + 1, raw);
    for (const path of Object.keys(out)) {
      if (out[path].includes(raw)) out[path] = out[path].split(raw).join(PLACEHOLDER(i + 1));
    }
  });

  return {
    files: out,
    count: values.length,
    restore: (text: string) =>
      text.replace(PLACEHOLDER_RE, (whole, n: string) => byPlaceholder.get(Number(n)) ?? whole),
    redactText: (text: string) => {
      let t = text;
      values.forEach((raw, i) => {
        if (t.includes(raw)) t = t.split(raw).join(PLACEHOLDER(i + 1));
      });
      return t;
    },
  };
}

/** 한 파일만 가릴 때의 편의 함수. */
export function redactFile(path: string, content: string): { content: string; restore: (t: string) => string } {
  const r = redactSecrets({ [path]: content });
  return { content: r.files[path], restore: r.restore };
}

/** 사람이 읽을 글(요약·설명)에 남은 자리표시자를 되돌리지 않고 "(비밀값)"으로 바꾼다. */
export function scrubPlaceholders(text: string): string {
  return text.replace(PLACEHOLDER_RE, "(비밀값)");
}
