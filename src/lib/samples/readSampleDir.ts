import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/** 스크립트·테스트 전용(node:fs). 앱 번들에서는 쓰지 않는다. */
const SKIP = /(^|\/)(node_modules|package-lock\.json|\.DS_Store)($|\/)/;

/** samples/<name>/ 폴더를 { 상대경로: 내용 }으로 읽는다. */
export function readSampleDir(root: string, name: string): Record<string, string> {
  const base = path.join(root, "samples", name);
  const out: Record<string, string> = {};
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir).sort()) {
      const full = path.join(dir, entry);
      const rel = path.relative(base, full).split(path.sep).join("/");
      if (SKIP.test(rel)) continue;
      if (statSync(full).isDirectory()) walk(full);
      // Windows(core.autocrlf)에서 CRLF로 체크아웃돼도 같은 내용으로 읽도록 LF로 맞춘다.
      else out[rel] = readFileSync(full, "utf8").replace(/\r\n/g, "\n");
    }
  };
  walk(base);
  return out;
}
