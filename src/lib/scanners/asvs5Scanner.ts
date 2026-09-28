import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  RegressionTest,
  SecurityEvidence,
  SecurityFinding,
  VerificationResult,
  VerificationTest,
} from "@/lib/domain/types";
import {
  ASVS5_STATIC_SIGNALS,
  ASVS_VERSION,
  type AsvsStaticSignal,
} from "@/lib/rules/asvs5Catalog";
import { id, now } from "@/lib/util";

const ANALYZABLE_FILE =
  /(?:^|\/)(?:\.env(?:\.[^/]+)?|[^/]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|java|cs|sql|html|vue|svelte|json|ya?ml|toml|ini|conf|properties|xml))$/i;
const GENERATED_OR_LOCK =
  /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|.*\.min\.(?:js|css))$/i;

interface Match {
  line: number;
  lineText: string;
}

function test(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  return regex.test(value);
}

function isAnalyzableFile(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  return ANALYZABLE_FILE.test(normalized) && !GENERATED_OR_LOCK.test(normalized);
}

function languageFor(file: string): string {
  const ext = file.split(".").pop()?.toLowerCase();
  const names: Record<string, string> = {
    ts: "typescript",
    tsx: "typescript",
    js: "javascript",
    jsx: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    py: "python",
    go: "go",
    rb: "ruby",
    php: "php",
    java: "java",
    cs: "csharp",
    sql: "sql",
    html: "html",
    vue: "vue",
    svelte: "svelte",
    json: "json",
    yaml: "yaml",
    yml: "yaml",
  };
  return names[ext ?? ""] ?? "text";
}

function lineAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function findSignalMatches(
  file: string,
  content: string,
  signal: AsvsStaticSignal
): Match[] {
  if (signal.filePattern && !test(signal.filePattern, file)) return [];
  if (signal.requiresContent && !test(signal.requiresContent, content)) return [];
  if (signal.safeContentPattern && test(signal.safeContentPattern, content)) return [];

  const flags = signal.pattern.flags.includes("g")
    ? signal.pattern.flags
    : `${signal.pattern.flags}g`;
  const regex = new RegExp(signal.pattern.source, flags);
  const lines = content.split("\n");
  const matches: Match[] = [];
  let match: RegExpExecArray | null;

  while ((match = regex.exec(content)) !== null) {
    const line = lineAt(content, match.index);
    const lineText = lines[line - 1] ?? "";
    const before = signal.windowBefore ?? 2;
    const after = signal.windowAfter ?? 2;
    const windowText = lines
      .slice(Math.max(0, line - 1 - before), Math.min(lines.length, line + after))
      .join("\n");

    if (signal.excludeLinePattern && test(signal.excludeLinePattern, lineText)) {
      if (match[0].length === 0) regex.lastIndex++;
      continue;
    }
    if (signal.safeWindowPattern && test(signal.safeWindowPattern, windowText)) {
      if (match[0].length === 0) regex.lastIndex++;
      continue;
    }

    matches.push({ line, lineText });
    break; // 동일 파일·동일 규칙은 대표 근거 1건만 보고해 소음을 제한한다.
  }

  return matches;
}

function findingFromMatch(
  file: string,
  signal: AsvsStaticSignal,
  match: Match
): SecurityFinding {
  const sections = signal.asvsSections.join(", ");
  const evidence: SecurityEvidence[] = [
    {
      id: id("ev"),
      kind: "source_code",
      label: `${file}:${match.line}`,
      content: match.lineText.trim().slice(0, 500),
      language: languageFor(file),
    },
    {
      id: id("ev"),
      kind: "scanner_output",
      label: "OWASP ASVS 5.0 정적 분석",
      content: `규칙: ${signal.ruleId}\nASVS: ${sections}\n파일: ${file}\n줄: ${match.line}`,
    },
  ];

  return {
    id: id("finding"),
    scanId: "",
    title: signal.title,
    severity: signal.severity,
    category: signal.category,
    owasp: `OWASP ASVS ${ASVS_VERSION} ${sections}`,
    cwe: signal.cwe,
    cvss: signal.cvss,
    description: `${signal.titleKo} 위험 신호가 ${file} ${match.line}번째 줄에서 발견되었습니다. 정적 신호이므로 주변 데이터 흐름을 함께 검토해야 합니다.`,
    humanReadableImpact: signal.impact,
    whyItMatters: signal.impact,
    location: { file, line: match.line },
    evidence,
    remediation: signal.remediation,
    status: "detected",
    simulated: false,
    verificationKey: `asvs5:${signal.key}:${encodeURIComponent(file)}:${match.line}`,
    createdAt: now(),
    updatedAt: now(),
  };
}

export class Asvs5Scanner implements SecurityScanner {
  readonly name = "asvs5-static-scanner";
  readonly displayName = "OWASP ASVS 5.0 static analysis";
  readonly step = "static_analysis" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Object.keys(context.files).some(isAnalyzableFile);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    for (const [file, content] of Object.entries(context.files)) {
      if (!isAnalyzableFile(file)) continue;
      for (const signal of ASVS5_STATIC_SIGNALS) {
        for (const match of findSignalMatches(file, content, signal)) {
          findings.push(findingFromMatch(file, signal, match));
        }
      }
    }
    return findings;
  }

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const key = finding.verificationKey ?? "";
    const signalKey = key.startsWith("asvs5:") ? key.split(":", 3)[1] : "";
    const signal = ASVS5_STATIC_SIGNALS.find((item) => item.key === signalKey);
    const file = finding.location?.file;
    const source = file ? context.files[file] : undefined;
    const vulnerable = Boolean(
      signal && file && source !== undefined && findSignalMatches(file, source, signal).length
    );
    const securityPass = Boolean(signal && source !== undefined && !vulnerable);

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "OWASP ASVS 5.0 수정 후 정적 재검사",
      before: {
        label: "수정 전",
        request: `SAST re-scan: ${file ?? "(unknown)"}`,
        response: "ASVS 위험 신호 존재",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `SAST re-scan: ${file ?? "(unknown)"}`,
        response:
          source === undefined
            ? "수정 반영 소스가 없어 재검사할 수 없음"
            : vulnerable
              ? "동일한 위험 신호가 남아 있음"
              : "동일한 위험 신호가 사라짐",
        attackSucceeded: vulnerable,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const sourcePresent = Boolean(source?.trim());
    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "수정 파일 유지",
          expectation: "수정된 파일이 존재하고 비어 있지 않아야 함",
          outcome: sourcePresent ? "pass" : "fail",
          detail: file ? `${file} 길이 ${source?.length ?? 0}` : "파일 위치 불명",
        },
      ],
      outcome: sourcePresent ? "pass" : "fail",
      createdAt: now(),
    };

    return {
      findingId: finding.id,
      security,
      regression,
      resolved: security.outcome === "pass" && regression.outcome === "pass",
    };
  }
}
