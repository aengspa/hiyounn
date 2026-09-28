// Feature: hoi-warm-redesign — 요구사항 12.4 절대 보장 표현 차단
//
// `src/app`, `src/components`의 모든 `.tsx` 파일에서 사용자에게 보이는 문구
// (문자열 리터럴, 템플릿 문자열 텍스트, JSX 텍스트)를 뽑아 `containsGuaranteePhrase`가
// 모두 false인지 확인한다. 주석은 먼저 걷어내서 검사하지 않는다.
// `src/app/api/**`는 UI 문구가 아닌 API 라우트(Protected_Surface)라 검사 대상에서 뺀다.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { LIMIT_NOTICE, containsGuaranteePhrase } from "@/lib/ui/presentation";

const ROOT = process.cwd();
const SCAN_DIRS = [resolve(ROOT, "src", "app"), resolve(ROOT, "src", "components")];
const EXCLUDED_DIRS = [resolve(ROOT, "src", "app", "api")];

function isExcluded(path: string): boolean {
  return EXCLUDED_DIRS.some((dir) => path === dir || path.startsWith(dir + sep));
}

function collectTsxFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (isExcluded(full)) continue;
    if (statSync(full).isDirectory()) {
      collectTsxFiles(full, out);
    } else if (full.endsWith(".tsx")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * 소스를 한 번 훑어 주석을 공백으로 바꾼 코드와 문자열 리터럴 내용을 돌려준다.
 * 작은따옴표·큰따옴표 문자열은 줄을 넘지 않으므로 줄바꿈을 만나면 문자열이 아닌 것으로 본다
 * (JSX 텍스트 속 아포스트로피가 뒤쪽 코드를 삼키지 않게).
 */
function lex(source: string): { code: string; strings: string[] } {
  const strings: string[] = [];
  let code = "";
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];

    if (ch === "/" && next === "/") {
      const end = source.indexOf("\n", i);
      const stop = end === -1 ? source.length : end;
      code += " ".repeat(stop - i);
      i = stop;
      continue;
    }
    if (ch === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? source.length : end + 2;
      code += source.slice(i, stop).replace(/[^\n]/g, " ");
      i = stop;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      let j = i + 1;
      let text = "";
      let closed = false;
      while (j < source.length) {
        const c = source[j];
        if (c === "\\") {
          text += source.slice(j, j + 2);
          j += 2;
          continue;
        }
        if (c === ch) {
          closed = true;
          break;
        }
        if (c === "\n" && ch !== "`") break;
        text += c;
        j += 1;
      }
      if (closed) {
        // 템플릿의 `${...}` 표현식 부분은 문구가 아니므로 공백으로 바꾼다.
        strings.push(ch === "`" ? text.replace(/\$\{[^}]*\}/g, " ") : text);
        code += source.slice(i, j + 1);
        i = j + 1;
        continue;
      }
    }
    code += ch;
    i += 1;
  }
  return { code, strings };
}

/** 주석을 걷어낸 코드에서 `>`와 `<` 사이 JSX 텍스트를 뽑는다. */
function jsxTexts(code: string): string[] {
  const texts: string[] = [];
  for (const match of code.matchAll(/>([^<>{}]+)</g)) {
    const text = match[1].replace(/\s+/g, " ").trim();
    if (text.length > 0) texts.push(text);
  }
  return texts;
}

function extractUserFacingText(source: string): string[] {
  const { code, strings } = lex(source);
  return [...strings, ...jsxTexts(code)];
}

describe("정직한 문구 검사 (요구사항 12.4)", () => {
  it("검사기가 절대 보장 표현을 잡아내고 한계 고지는 통과시킨다", () => {
    expect(containsGuaranteePhrase("100% 안전해요")).toBe(true);
    expect(containsGuaranteePhrase(LIMIT_NOTICE)).toBe(false);
  });

  it("추출기가 주석은 건너뛰고 문자열·JSX 텍스트는 뽑는다", () => {
    const sample = [
      '// 100% 안전해요 주석은 검사하지 않아요',
      '/* 완벽해요 */',
      'const a = "문자열 문구";',
      "const b = `템플릿 ${value} 문구`;",
      "return <p>JSX 텍스트 문구</p>;",
    ].join("\n");
    const texts = extractUserFacingText(sample);
    expect(texts).toContain("문자열 문구");
    expect(texts.some((t) => t.startsWith("템플릿") && t.endsWith("문구"))).toBe(true);
    expect(texts).toContain("JSX 텍스트 문구");
    expect(texts.some((t) => containsGuaranteePhrase(t))).toBe(false);
  });

  it("src/app·src/components의 .tsx 문구에 절대 보장 표현이 없다", () => {
    const files = SCAN_DIRS.flatMap((dir) => collectTsxFiles(dir));
    expect(files.length).toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const text of extractUserFacingText(source)) {
        if (containsGuaranteePhrase(text)) {
          offenders.push(`${relative(ROOT, file)}: "${text}"`);
        }
      }
    }

    console.info(`[honest-copy] scanned ${files.length} .tsx files`);
    expect(offenders, `절대 보장 표현이 들어간 문구:\n${offenders.join("\n")}`).toEqual([]);
  });
});
