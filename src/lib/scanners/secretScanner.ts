import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  RegressionTest,
  SecurityEvidence,
  SecurityFinding,
  VerificationResult,
  VerificationTest,
} from "@/lib/domain/types";
import { createHash } from "crypto";
import { id, now, maskSecret } from "@/lib/util";
import { VerificationUnavailableError } from "@/lib/store/errors";

/**
 * REAL scanner. Regex-based secret detection over the project's virtual files.
 * This mirrors what a tool like Gitleaks does; swapping in Gitleaks later just
 * means replacing the detection body while keeping this interface.
 */

export interface SecretRule {
  name: string;
  category: string;
  regex: RegExp;
  /** 코드에서 옮길 때 쓸 환경변수 이름(대입 대상 이름을 모를 때). */
  envName?: string;
}

export interface SecretMatch {
  file: string;
  content: string;
  lineNumber: number;
  /** 파일 안에서 비밀값(raw)이 시작하는 위치. */
  index: number;
  raw: string;
  rule: SecretRule;
}

// 제공자별 규칙이 일반 규칙보다 앞에 온다. 같은 위치를 여러 규칙이 잡으면
// 먼저 잡은(더 구체적인) 규칙 하나만 남긴다.
const RULES: SecretRule[] = [
  {
    name: "Stripe live secret key",
    category: "Secret Exposure",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g,
    envName: "STRIPE_SECRET_KEY",
  },
  {
    name: "OpenAI API key",
    category: "Secret Exposure",
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g,
    envName: "OPENAI_API_KEY",
  },
  {
    name: "AWS access key ID",
    category: "Secret Exposure",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    envName: "AWS_ACCESS_KEY_ID",
  },
  {
    name: "GitHub token",
    category: "Secret Exposure",
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    envName: "GITHUB_TOKEN",
  },
  {
    name: "Slack token",
    category: "Secret Exposure",
    regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    envName: "SLACK_TOKEN",
  },
  {
    name: "Google API key",
    category: "Secret Exposure",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    envName: "GOOGLE_API_KEY",
  },
  {
    name: "Private key block",
    category: "Secret Exposure",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    name: "Supabase service role / secret key",
    category: "Secret Exposure",
    regex: /sbp_live_[A-Za-z0-9]{20,}/g,
    envName: "SUPABASE_SERVICE_ROLE_KEY",
  },
  {
    name: "Hardcoded database password",
    category: "Secret Exposure",
    regex: /DATABASE_PASSWORD\s*=\s*([^\s"']+)/g,
  },
  {
    name: "Generic hardcoded credential",
    category: "Secret Exposure",
    // 이름 뒤 TypeScript 타입 표기(": string")가 있어도 잡는다.
    regex: /(?:api[_-]?key|secret|token)\s*(?::\s*[\w<>[\]|]+\s*)?[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/gi,
  },
];

/**
 * Shared by scan, verify, fix and AI redaction so none of them can drift from
 * the detection rules. Overlapping matches keep only the first (most specific)
 * rule, so one secret is one finding.
 */
export function findSecretMatches(files: Record<string, string>): SecretMatch[] {
  const matches: SecretMatch[] = [];

  for (const [file, content] of Object.entries(files)) {
    const taken: Array<[number, number]> = [];
    for (const rule of RULES) {
      // RULES are module-level global regexes. Reset for every file and again
      // after use so a previous scan can never affect the next one.
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(content)) !== null) {
        const raw = match[1] ?? match[0];
        const index = match.index + match[0].indexOf(raw);
        const end = index + raw.length;
        if (taken.some(([s, e]) => index < e && s < end)) continue;
        taken.push([index, end]);
        matches.push({
          file,
          content,
          lineNumber: content.slice(0, index).split("\n").length,
          index,
          raw,
          rule,
        });
      }
      rule.regex.lastIndex = 0;
    }
  }

  return matches;
}

/**
 * 프로젝트 어디에든 이 지문의 값이 남아 있는지. 탐지 규칙에 걸리지 않는 이름으로
 * 옮겨도(예: apiKey → key) 같은 값이면 찾도록, 규칙 일치와 모든 문자열 리터럴을 본다.
 */
export function projectContainsSecret(files: Record<string, string>, fingerprint: string): boolean {
  if (findSecretMatches(files).some((m) => secretFingerprint(m.raw) === fingerprint)) return true;
  const LITERAL = /(["'`])([^"'`\n]{8,})\1/g;
  for (const content of Object.values(files)) {
    LITERAL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = LITERAL.exec(content)) !== null) {
      if (secretFingerprint(m[2]) === fingerprint) return true;
    }
  }
  return false;
}

/** Non-reversible id for one secret value, so verify can follow that exact value. */
export function secretFingerprint(raw: string): string {
  return createHash("sha256").update(`hoi-secret:v1\u0000${raw}`).digest("hex").slice(0, 16);
}

/** Masked display that stays short even for multi-line key blocks. */
function shortMask(raw: string): string {
  const firstLine = raw.split("\n")[0];
  return maskSecret(firstLine).slice(0, 48);
}

export function ruleForFinding(finding: SecurityFinding): SecretRule | undefined {
  const scannerOutput = finding.evidence.find(
    (evidence) => evidence.kind === "scanner_output"
  )?.content;
  return RULES.find((rule) => scannerOutput?.includes(`규칙: ${rule.name}`));
}

/** 화면에 보여 줄 비밀값 종류(규칙 이름은 기술 정보로 근거에 그대로 남긴다). */
const SECRET_KIND_KO: Record<string, string> = {
  "Stripe live secret key": "Stripe 결제 비밀키",
  "OpenAI API key": "OpenAI API 키",
  "AWS access key ID": "AWS 접속 키",
  "GitHub token": "GitHub 접속 토큰",
  "Slack token": "Slack 접속 토큰",
  "Google API key": "Google API 키",
  "Private key block": "서명·암호화에 쓰는 개인 키",
  "Supabase service role / secret key": "Supabase 관리자 키",
  "Hardcoded database password": "데이터베이스 비밀번호",
  "Generic hardcoded credential": "비밀키나 토큰으로 보이는 값",
};

function secretTitle(ruleName: string, isEnvFile: boolean): string {
  if (isEnvFile) return "비밀값이 적힌 .env 파일이 코드와 함께 들어 있어요";
  if (ruleName === "Hardcoded database password") return "데이터베이스 비밀번호가 코드에 직접 들어 있어요";
  if (ruleName === "Private key block") return "서명·암호화에 쓰는 개인 키가 코드에 직접 들어 있어요";
  return "외부 서비스에 접속할 때 쓰는 비밀키가 코드에 직접 들어 있어요";
}

export class SecretScanner implements SecurityScanner {
  readonly name = "secret-scanner";
  readonly displayName = "Secret scanning";
  readonly step = "secret_scan" as const;
  readonly simulated = false;

  async isApplicable(): Promise<boolean> {
    return true; // always run secret scanning
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    for (const match of findSecretMatches(context.files)) {
      const { file, content, lineNumber, raw, rule } = match;

      // We store a MASKED version only — never the raw secret.
      const evidence: SecurityEvidence[] = [
        {
          id: id("ev"),
          kind: "source_code",
          label: `${file}:${lineNumber}`,
          content:
            content.split("\n")[lineNumber - 1]?.replace(raw, shortMask(raw)) ??
            "",
          masked: true,
          language: "typescript",
        },
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "비밀키 찾기 결과 (값은 가려서 보여 드려요)",
          content: `규칙: ${rule.name}\n파일: ${file}\n줄: ${lineNumber}\n일치: ${shortMask(raw)}`,
          masked: true,
        },
      ];

      const isEnvFile = file.endsWith(".env");
      const kind = SECRET_KIND_KO[rule.name] ?? "비밀값";

      findings.push({
        id: id("finding"),
        scanId: "",
        title: secretTitle(rule.name, isEnvFile),
        severity: "critical",
        category: rule.category,
        owasp: "A07 – Identification and Authentication Failures",
        cwe: "CWE-798",
        cvss: 9.1,
        description: `규칙 "${rule.name}"이(가) ${file} 파일 ${lineNumber}번째 줄에서 일치했어요.`,
        humanReadableImpact:
          "코드를 볼 수 있는 사람은 누구나 이 값을 복사해 쓸 수 있어요. 이 값으로 연결된 서비스에 이 프로젝트인 것처럼 접속해 데이터를 보거나 바꿀 수 있어요.",
        whyItMatters: `코드에서 확인했어요: ${file} ${lineNumber}번째 줄에 ${kind} 형식의 값이 직접 적혀 있어요. 이 값이 지금 실제로 쓰이는 키인지, 이미 밖으로 공개됐는지는 확인하지 않았어요.`,
        location: { file, line: lineNumber },
        evidence,
        remediation: isEnvFile
          ? "이 파일의 비밀값은 배포 서비스의 비밀 설정(환경변수)에 저장하고, .env 파일은 .gitignore에 넣어 코드와 함께 올리지 않도록 해 주세요. 이미 공개된 키라면 새 키를 발급하고 기존 키는 사용할 수 없게 해야 해요."
          : "비밀키를 코드에서 빼고 배포 서비스의 비밀 설정(환경변수)에 저장한 뒤, 코드에서는 그 설정을 읽어 쓰도록 바꿔 주세요. 이미 공개된 키라면 새 키를 발급하고 기존 키는 사용할 수 없게 해야 해요.",
        status: "detected",
        simulated: false,
        verificationKey: `secret:${file}:${lineNumber}`,
        fingerprint: secretFingerprint(raw),
        createdAt: now(),
        updatedAt: now(),
      });
    }

    return findings;
  }

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const file = finding.location?.file;
    const line = finding.location?.line;
    const key = finding.verificationKey ?? "";
    const rule = ruleForFinding(finding);
    const keyValid =
      file !== undefined &&
      line !== undefined &&
      key === `secret:${file}:${line}`;
    const snapshotAvailable = Object.values(context.files).some(
      (source) => source.trim().length > 0
    );

    if (!keyValid || !rule || !snapshotAvailable) {
      throw new VerificationUnavailableError();
    }

    const targetSource = context.files[file];
    // 지문이 있으면 "그 비밀값"이 프로젝트 어디에든 남았는지 본다(다른 파일로
    // 옮겨도 남은 것). 지문이 없는 예전 발견은 같은 파일·같은 규칙으로 본다.
    const remainingMatches = finding.fingerprint
      ? projectContainsSecret(context.files, finding.fingerprint)
        ? [finding.fingerprint]
        : []
      : findSecretMatches(context.files).filter((match) => match.file === file && match.rule.name === rule.name);
    const securityPass = remainingMatches.length === 0;
    const sourceState =
      targetSource === undefined
        ? "원본 파일이 현재 스냅샷에서 삭제되었습니다."
        : targetSource.trim().length === 0
          ? "원본 파일이 비어 있습니다."
          : "원본 파일을 현재 소스에서 다시 검사했습니다.";

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "하드코딩 비밀정보 소스 재검사",
      before: {
        label: "수정 전",
        request: `${rule.name} 규칙 검사: ${file}`,
        response: "최초 스캔에서 하드코딩된 비밀정보 패턴이 탐지되었습니다.",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `${rule.name} 규칙 재검사: ${file}`,
        response: securityPass
          ? `${sourceState} 동일 유형의 비밀정보 노출은 더 이상 탐지되지 않았습니다. 노출된 자격 증명의 폐기·재발급 여부는 별도로 확인해야 합니다.`
          : `${sourceState} 동일 유형의 비밀정보 패턴 ${remainingMatches.length}건이 남아 있습니다.`,
        attackSucceeded: !securityPass,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "프로젝트 소스 스냅샷 무결성",
          expectation: "재검사할 현재 프로젝트 소스가 비어 있지 않아야 함",
          outcome: "pass",
          detail: `현재 소스 파일 ${Object.keys(context.files).length}개를 확인했습니다.`,
        },
      ],
      outcome: "pass",
      createdAt: now(),
    };

    // Source removal is automatic evidence, but provider-side credential rotation
    // cannot be observed here. Keep the finding fixed-but-unverified until that
    // manual step can be attested by a future provider integration.
    return { findingId: finding.id, security, regression, resolved: false };
  }
}
