import type { FixAttempt, SecurityFinding } from "@/lib/domain/types";
import { findSecretMatches, secretFingerprint } from "@/lib/scanners/secretScanner";
import { safeProjectPath } from "@/lib/remediation/patchEngine";
import { id, now } from "@/lib/util";

/**
 * 규칙 기반 수정 (실제 업로드 코드에 적용).
 *
 * 스캐너가 이미 정확히 무엇을 바꿔야 하는지 아는 항목만 다룬다.
 *  - secret: 코드에 적힌 비밀값 문자열 → process.env.<이름>. 비밀값은 AI로
 *    보내지 않는다(이 경로에서 못 고치면 사람에게 넘긴다).
 *  - dep: package.json의 버전 범위를 같은 주요 버전 안의 수정 버전으로 올린다.
 *
 * 안전하게 바꿀 수 없으면 추측하지 않고 이유와 함께 "unsupported"를 돌려준다.
 * 적용은 patchEngine이 원본과 정확히 대조해서 한다.
 */

export type DeterministicResult =
  | { kind: "fix"; fix: FixAttempt }
  | { kind: "unsupported"; reasonCode: string; reason: string };

/** 이 항목이 규칙 기반 수정 대상이면 결과를, 아니면 null을 돌려준다. */
export function deterministicFixFor(
  finding: SecurityFinding,
  files: Record<string, string>
): DeterministicResult | null {
  const key = finding.verificationKey ?? "";
  if (key.startsWith("secret:")) return secretFix(finding, files);
  if (key.startsWith("dep:")) return dependencyFix(finding, files);
  return null;
}

function unsupported(reasonCode: string, reason: string): DeterministicResult {
  return { kind: "unsupported", reasonCode, reason };
}

function attempt(finding: SecurityFinding, file: string, before: string, after: string, summary: string, plainExplanation: string): DeterministicResult {
  const fix: FixAttempt = {
    id: id("fix"),
    findingId: finding.id,
    source: "deterministic",
    summary,
    plainExplanation,
    diffs: [
      {
        file,
        patch: [...before.split("\n").map((l) => `- ${l}`), ...after.split("\n").map((l) => `+ ${l}`)].join("\n"),
        beforeText: before,
        afterText: after,
        mode: "replace",
      },
    ],
    applied: false,
    createdAt: now(),
  };
  return { kind: "fix", fix };
}

// ── Secrets ────────────────────────────────────────────────────

const JS_FILE = /\.(?:m?[jt]sx?|cjs)$/;
const GENERIC_NAMES = new Set(["key", "secret", "token", "password", "pass", "pwd", "value", "auth"]);

function isClientCode(file: string, content: string): boolean {
  return (
    /^\s*["']use client["']/m.test(content) ||
    /^(public|static|client|frontend)\//.test(file) ||
    /(^|\/)(public|static)\//.test(file)
  );
}

/** camelCase / kebab → UPPER_SNAKE. 이미 대문자 스네이크면 그대로. */
export function toEnvName(name: string): string {
  if (/^[A-Z][A-Z0-9_]*$/.test(name)) return name;
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}

/** 문자열 바로 앞의 대입 대상 이름으로 환경변수 이름을 정한다. */
export function envNameFor(prefix: string, fallback?: string): string {
  // 따옴표로 감싼 속성 이름('client-secret')도 받는다.
  const m = prefix.match(/(?:["']([A-Za-z_$][\w$.-]*)["']|([A-Za-z_$][\w$]*))\s*(?::\s*[\w<>[\]|, ]+)?\s*[:=]\s*$/);
  const name = m?.[1] ?? m?.[2];
  if (name && !GENERIC_NAMES.has(name.toLowerCase())) {
    const env = toEnvName(name);
    if (/^[A-Z][A-Z0-9_]{1,63}$/.test(env)) return env;
  }
  if (fallback) return fallback;
  if (name) {
    const env = `APP_${toEnvName(name)}`;
    if (/^[A-Z][A-Z0-9_]{1,63}$/.test(env)) return env;
  }
  return "APP_SECRET";
}

function secretFix(finding: SecurityFinding, files: Record<string, string>): DeterministicResult {
  const rawPath = finding.location?.file;
  const file = rawPath ? safeProjectPath(rawPath) : null;
  if (!file || files[file] === undefined || !finding.location) {
    return unsupported(
      "no_file_location",
      "비밀값이 있는 파일을 업로드한 코드에서 찾지 못해 자동으로 고치지 않았어요. 파일 이름이 바뀌었거나 업로드에서 빠졌을 수 있어요. 최신 코드로 다시 점검해 주세요."
    );
  }
  const base = file.split("/").pop() ?? file;
  if (/^\.env(\..+)?$/.test(base)) {
    return unsupported(
      "secret_in_env_file",
      ".env 파일은 비밀값을 모아 두는 설정 파일이라 코드로 고칠 수 없어요. 이 파일을 저장소와 업로드에서 빼 주세요(.gitignore에 추가). 값은 배포 서비스의 비밀 설정에 넣고, 이미 공개된 키는 새로 발급한 뒤 기존 키를 사용할 수 없게 해 주세요."
    );
  }
  if (!JS_FILE.test(file)) {
    return unsupported(
      "secret_language_unsupported",
      "이 파일 형식은 비밀값을 자동으로 옮기는 방법을 지원하지 않아요. 비밀값을 이 파일에서 지우고 서버 환경변수에서 읽도록 직접 바꿔 주세요. 이미 공개된 키는 새로 발급한 뒤 기존 키를 사용할 수 없게 해 주세요."
    );
  }
  const content = files[file];
  if (isClientCode(file, content)) {
    return unsupported(
      "secret_in_client_code",
      "이 코드는 사용자의 브라우저에서 실행돼서, 환경변수로 옮겨도 키가 그대로 보여요. 키를 쓰는 부분을 서버(API)로 옮겨야 해서 이 파일만으로는 자동으로 고치지 않았어요. 키는 새로 발급하고 기존 키를 사용할 수 없게 해 주세요."
    );
  }

  const line = finding.location.line;
  const match = findSecretMatches({ [file]: content }).find(
    (m) => m.lineNumber === line && (!finding.fingerprint || secretFingerprint(m.raw) === finding.fingerprint)
  );
  if (!match) {
    return unsupported(
      "secret_not_found",
      "점검 때 찾은 비밀값을 지금 파일에서 다시 찾지 못해 자동으로 고치지 않았어요. 그사이 파일 내용이 바뀌었을 수 있어요. 최신 코드로 다시 점검해 주세요."
    );
  }
  if (match.raw.includes("\n")) {
    return unsupported(
      "secret_block",
      "여러 줄로 된 키(개인 키 등)는 한 줄짜리 환경변수로 안전하게 옮기는 방법을 정할 수 없어 자동으로 고치지 않았어요. 키를 코드에서 빼고 배포 서비스의 비밀 설정에 넣어 주세요. 이미 공개된 키는 새로 발급해 주세요."
    );
  }

  const lines = content.split("\n");
  const lineText = lines[match.lineNumber - 1] ?? "";
  const col = lineText.indexOf(match.raw);
  const quote = lineText[col - 1];
  const closing = lineText[col + match.raw.length];
  if (col < 1 || quote !== closing || !(quote === '"' || quote === "'" || quote === "`")) {
    return unsupported(
      "secret_not_plain_literal",
      "비밀값이 다른 글자와 한 문자열 안에 섞여 있어(예: \"Bearer 키값\") 어디까지 바꿀지 정하지 못했어요. 비밀값 부분만 서버 환경변수에서 읽도록 직접 바꾸고, 키는 새로 발급해 주세요."
    );
  }

  const prefix = lineText.slice(0, col - 1);
  const envName = envNameFor(prefix, match.rule.envName);
  const typedString = /\.tsx?$/.test(file) && /:\s*string\s*=\s*$/.test(prefix);
  const expr = typedString ? `process.env.${envName} ?? ""` : `process.env.${envName}`;
  const after = `${prefix}${expr}${lineText.slice(col + match.raw.length + 1)}`;

  return attempt(
    finding,
    file,
    lineText,
    after,
    `코드에 직접 적힌 비밀값을 빼고, 서버 환경변수 ${envName}에서 읽도록 바꾸는 수정안이에요.`,
    `외부 서비스에 접속할 때 쓰는 비밀값이 코드에 직접 들어 있어요. 이 수정안은 그 값을 코드에서 지우고 서버 환경변수 ${envName}에서 읽게 해요. 기능이 전처럼 동작하려면 배포 서비스의 비밀 설정에 ${envName} 값을 넣어야 해요. 이미 공개된 키라면 코드만 바꿔서는 막을 수 없으니, 새 키를 발급해 넣고 기존 키는 사용할 수 없게 해 주세요. 적용한 뒤 이 값을 쓰는 기능이 정상으로 동작하는지 확인해 주세요.`
  );
}

// ── Dependencies ───────────────────────────────────────────────

interface Semver {
  major: number;
  minor: number;
  patch: number;
  pre: boolean;
  text: string;
}

function parseSemver(v: string): Semver | null {
  const m = v.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: Boolean(m[4]), text: `${m[1]}.${m[2]}.${m[3]}${m[4] ?? ""}` };
}

function compare(a: Semver, b: Semver): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch || Number(b.pre) - Number(a.pre);
}

/** 발견 근거에서 "수정된 버전" 후보를 모은다(OSV 결과, 오프라인 권고). */
function fixedVersionCandidates(finding: SecurityFinding): Semver[] {
  const texts = [...finding.evidence.map((e) => e.content), finding.remediation ?? ""];
  const out: Semver[] = [];
  for (const t of texts) {
    for (const m of t.matchAll(/→ 수정: ([0-9][0-9A-Za-z.+-]*)/g)) {
      const v = parseSemver(m[1]);
      if (v) out.push(v);
    }
    for (const m of t.matchAll(/(\d+\.\d+\.\d+)\s*이상/g)) {
      const v = parseSemver(m[1]);
      if (v) out.push(v);
    }
  }
  return out.filter((v) => !v.pre);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function dependencyFix(finding: SecurityFinding, files: Record<string, string>): DeterministicResult {
  const name = (finding.verificationKey ?? "").slice(4);
  const raw = files["package.json"];
  if (!name || raw === undefined) {
    return unsupported(
      "no_manifest",
      "사용하는 외부 도구 목록(package.json)을 찾지 못해 버전을 자동으로 올리지 못했어요. 업로드한 코드에 package.json이 들어 있는지 확인하고 다시 점검해 주세요."
    );
  }
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return unsupported(
      "manifest_invalid",
      "package.json의 형식이 올바르지 않아 읽을 수 없었어요. 그래서 버전을 자동으로 올리지 못했어요. 파일의 문법 오류(쉼표, 따옴표 등)를 고친 뒤 다시 점검해 주세요."
    );
  }
  const sections = (["dependencies", "devDependencies"] as const).filter((s) => {
    const deps = pkg[s];
    return typeof deps === "object" && deps !== null && typeof (deps as Record<string, unknown>)[name] === "string";
  });
  if (sections.length !== 1) {
    return unsupported(
      "dep_not_direct",
      `${name}은(는) package.json에 직접 적혀 있지 않거나 여러 곳에 적혀 있어, 어느 줄을 바꿀지 정하지 못했어요. 다른 도구가 함께 설치하는 경우가 많아요. 터미널에서 npm ls ${name}을 실행해 어떤 도구가 가져오는지 확인하고, 그 도구를 업데이트해 주세요.`
    );
  }
  const range = (pkg[sections[0]] as Record<string, string>)[name];
  const rm = range.trim().match(/^([\^~]?)v?(\d+\.\d+\.\d+)$/);
  const current = rm ? parseSemver(rm[2]) : null;
  if (!rm || !current) {
    return unsupported(
      "dep_range_unknown",
      `${name}의 버전 표기("${range}")가 단순한 형태가 아니라 자동으로 바꾸지 않았어요. package.json에서 ${name}을(를) 문제가 고쳐진 버전 이상으로 직접 올려 주세요.`
    );
  }

  const candidates = fixedVersionCandidates(finding).filter((v) => compare(v, current) > 0);
  if (candidates.length === 0) {
    return unsupported(
      "dep_no_fixed_version",
      `${name}의 문제가 고쳐진 버전 정보를 찾지 못해 자동으로 올리지 못했어요. 이 도구의 공식 보안 안내에서 고쳐진 버전을 확인한 뒤 직접 올려 주세요.`
    );
  }
  const sameMajor = candidates.filter((v) => v.major === current.major).sort(compare);
  if (sameMajor.length === 0) {
    const lowest = [...candidates].sort(compare)[0];
    return unsupported(
      "dep_major_bump",
      `${name}은(는) ${lowest.text} 이상으로 올려야 하는데, 주요 버전이 바뀌면 사용 방법이 달라질 수 있어 자동으로 올리지 않았어요. 이 도구의 변경 안내(릴리스 노트)를 확인하고 직접 올린 뒤, 앱의 주요 기능이 정상으로 동작하는지 확인해 주세요.`
    );
  }
  // 같은 주요 버전의 수정 버전 중 가장 높은 것(여러 취약점을 한 번에 덮기 위해).
  const target = sameMajor[sameMajor.length - 1];
  const nextRange = `${rm[1]}${target.text}`;

  const re = new RegExp(`("${escapeRe(name)}"\\s*:\\s*)"${escapeRe(range)}"`, "g");
  const hits = [...raw.matchAll(re)];
  if (hits.length !== 1) {
    return unsupported(
      "dep_edit_ambiguous",
      `package.json에서 ${name} 버전이 적힌 줄을 하나로 정하지 못해 자동으로 바꾸지 않았어요. package.json에서 ${name}의 버전을 직접 올려 주세요.`
    );
  }
  const before = hits[0][0];
  const after = `${hits[0][1]}"${nextRange}"`;

  const lockNote =
    files["package-lock.json"] !== undefined || files["pnpm-lock.yaml"] !== undefined || files["yarn.lock"] !== undefined
      ? " 잠금 파일(package-lock.json 등)은 이 수정본에 반영되지 않았어요. 받은 파일을 반영한 뒤 npm install을 실행해 주세요."
      : " 받은 파일을 반영한 뒤 npm install을 실행해 주세요.";

  return attempt(
    finding,
    "package.json",
    before,
    after,
    `${name}의 버전을 ${range}에서 ${nextRange}(으)로 올리는 수정안이에요.`,
    `프로젝트에서 사용하는 외부 도구 ${name}의 현재 버전(${range})에 알려진 보안 문제가 있어요. 이 수정안은 package.json에서 이 도구를 문제가 고쳐진 ${target.text}(으)로 올려요. 같은 주요 버전이라 사용 방법은 대부분 그대로지만, 적용한 뒤 앱의 주요 기능이 정상으로 동작하는지 확인해 주세요.${lockNote}`
  );
}
