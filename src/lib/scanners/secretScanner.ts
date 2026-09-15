import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding, SecurityEvidence } from "@/lib/domain/types";
import { id, now, maskSecret } from "@/lib/util";

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

    for (const [file, content] of Object.entries(context.files)) {
      for (const rule of RULES) {
        rule.regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.regex.exec(content)) !== null) {
          const raw = match[1] ?? match[0];
          const lineNumber = content.slice(0, match.index).split("\n").length;

          // We store a MASKED version only — never the raw secret.
          const evidence: SecurityEvidence[] = [
            {
              id: id("ev"),
              kind: "source_code",
              label: `${file}:${lineNumber}`,
              content: content
                .split("\n")
                [lineNumber - 1]?.replace(raw, maskSecret(raw)) ?? "",
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
      }
    }

    return findings;
  }
}
