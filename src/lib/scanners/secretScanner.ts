import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  RegressionTest,
  SecurityEvidence,
  SecurityFinding,
  VerificationResult,
  VerificationTest,
} from "@/lib/domain/types";
import { id, now, maskSecret } from "@/lib/util";
import { VerificationUnavailableError } from "@/lib/store/errors";

/**
 * REAL scanner. Regex-based secret detection over the project's virtual files.
 * This mirrors what a tool like Gitleaks does; swapping in Gitleaks later just
 * means replacing the detection body while keeping this interface.
 */

interface SecretRule {
  name: string;
  category: string;
  regex: RegExp;
}

interface SecretMatch {
  file: string;
  content: string;
  lineNumber: number;
  raw: string;
  rule: SecretRule;
}

const RULES: SecretRule[] = [
  {
    name: "Supabase service role / secret key",
    category: "Secret Exposure",
    regex: /sbp_live_[A-Za-z0-9]{20,}/g,
  },
  {
    name: "Hardcoded database password",
    category: "Secret Exposure",
    regex: /DATABASE_PASSWORD\s*=\s*([^\s"']+)/g,
  },
  {
    name: "Generic hardcoded credential",
    category: "Secret Exposure",
    regex: /(?:api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/gi,
  },
];

/** Shared by scan and verify so verification cannot drift from detection rules. */
function findSecretMatches(files: Record<string, string>): SecretMatch[] {
  const matches: SecretMatch[] = [];

  for (const [file, content] of Object.entries(files)) {
    for (const rule of RULES) {
      // RULES are module-level global regexes. Reset for every file and again
      // after use so a previous scan can never affect the next one.
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(content)) !== null) {
        matches.push({
          file,
          content,
          lineNumber: content.slice(0, match.index).split("\n").length,
          raw: match[1] ?? match[0],
          rule,
        });
      }
      rule.regex.lastIndex = 0;
    }
  }

  return matches;
}

function ruleForFinding(finding: SecurityFinding): SecretRule | undefined {
  const scannerOutput = finding.evidence.find(
    (evidence) => evidence.kind === "scanner_output"
  )?.content;
  return RULES.find((rule) => scannerOutput?.includes(`규칙: ${rule.name}`));
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
            content.split("\n")[lineNumber - 1]?.replace(raw, maskSecret(raw)) ??
            "",
          masked: true,
          language: "typescript",
        },
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "비밀정보 스캐너 출력",
          content: `규칙: ${rule.name}\n파일: ${file}\n줄: ${lineNumber}\n일치: ${maskSecret(raw)}`,
          masked: true,
        },
      ];

      const isEnvFile = file.endsWith(".env");

      findings.push({
        id: id("finding"),
        scanId: "",
        title: isEnvFile
          ? "비밀번호가 커밋된 파일에 저장되어 있습니다"
          : "비밀 키가 코드에 직접 적혀 있습니다",
        severity: "critical",
        category: rule.category,
        owasp: "A07 – Identification and Authentication Failures",
        cwe: "CWE-798",
        cvss: 9.1,
        description: `규칙 "${rule.name}"이(가) ${file} 파일 ${lineNumber}번째 줄에서 일치했습니다.`,
        humanReadableImpact:
          "데이터베이스나 백엔드를 여는 비밀 값이, 코드를 볼 수 있는 사람이면 누구나 읽을 수 있는 곳에 적혀 있습니다.",
        whyItMatters:
          "이 파일을 보는 사람(동료, 유출된 저장소, 브라우저 번들 등) 누구나 이 비밀 값으로 모든 데이터를 읽거나 바꿀 수 있습니다.",
        location: { file, line: lineNumber },
        evidence,
        remediation:
          "비밀 값을 서버에서만 접근 가능한 환경변수로 옮기고, 노출된 값은 재발급(rotate)하세요.",
        status: "detected",
        simulated: false,
        verificationKey: `secret:${file}:${lineNumber}`,
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
    const remainingMatches = findSecretMatches(context.files).filter(
      (match) => match.file === file && match.rule.name === rule.name
    );
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
