import type { SecurityFinding, FixAttempt, FixDiff } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import {
  VULNERABLE_HANDLER_SOURCE,
  FIXED_HANDLER_SOURCE,
  HANDLER_FILE,
} from "@/lib/demo/vulnerableApp";

/**
 * Fix generator.
 *
 * The "generation Agent" and the "verification Agent" are logically separate:
 * this module ONLY proposes a fix. It never marks anything resolved — that is
 * the verification engine's job, and only after re-running the attack.
 *
 * In the MVP this uses deterministic, rule-based patches keyed off the
 * finding's verificationKey. When LLM_PROVIDER is configured, callLlmFix()
 * would be swapped in behind the same interface (source: "llm").
 */

function unifiedDiff(before: string, after: string): string {
  const beforeLines = before.split("\n").map((l) => `- ${l}`);
  const afterLines = after.split("\n").map((l) => `+ ${l}`);
  return [...beforeLines, ...afterLines].join("\n");
}

export function generateFix(finding: SecurityFinding): FixAttempt {
  const key = finding.verificationKey ?? "";

  if (key.startsWith("idor:")) {
    const diffs: FixDiff[] = [
      {
        file: HANDLER_FILE,
        patch: unifiedDiff(VULNERABLE_HANDLER_SOURCE, FIXED_HANDLER_SOURCE),
      },
    ];
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary:
        "Add an ownership check so the query only returns the record when it belongs to the logged-in user.",
      plainExplanation:
        "This change adds an authorization check that confirms the requested data belongs to the currently logged-in user. If it doesn't, the app now returns 'Forbidden' instead of the other person's data.",
      diffs,
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("secret:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Move the secret to a server-only environment variable and rotate it.",
      plainExplanation:
        "This change removes the secret from your code and reads it from a server-only setting instead, so it is never exposed. You should also regenerate the old value so the leaked one stops working.",
      diffs: [
        {
          file: finding.location?.file ?? "src/lib/db.ts",
          patch: [
            `- const SUPABASE_SERVICE_KEY = "sbp_live_••••••••••••••••••••";`,
            `+ const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("headers:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Add standard security headers in next.config.js.",
      plainExplanation:
        "This change tells browsers how to protect your users by adding standard security headers to every response.",
      diffs: [
        {
          file: "next.config.js",
          patch: [
            `-     return []; // BUG: no security headers configured`,
            `+     return [{`,
            `+       source: "/(.*)",`,
            `+       headers: [`,
            `+         { key: "X-Frame-Options", value: "DENY" },`,
            `+         { key: "X-Content-Type-Options", value: "nosniff" },`,
            `+         { key: "Strict-Transport-Security", value: "max-age=63072000" },`,
            `+         { key: "Content-Security-Policy", value: "default-src 'self'" },`,
            `+       ],`,
            `+     }];`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("rls:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Enable RLS and add an owner-only policy on the table.",
      plainExplanation:
        "This change turns on access rules for your database table so each person can only see their own rows.",
      diffs: [
        {
          file: "supabase/policies.sql",
          patch: [
            `+ alter table public.profiles enable row level security;`,
            `+ create policy "own rows" on public.profiles`,
            `+   for select using (auth.uid() = user_id);`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  // Generic fallback.
  return {
    id: id("fix"),
    findingId: finding.id,
    source: "deterministic",
    summary: finding.remediation ?? "Apply the recommended remediation.",
    plainExplanation:
      finding.remediation ??
      "Follow the recommended remediation steps for this finding.",
    diffs: [],
    applied: false,
    createdAt: now(),
  };
}


// ─────────────────────────────────────────────────────────────
// AI 기반 수정안 생성 (LLM 설정 시)
// ─────────────────────────────────────────────────────────────

import { isConfigured, completeJson } from "@/lib/ai/llmClient";

const FIX_SYSTEM_PROMPT = `당신은 시니어 보안 엔지니어입니다.
주어진 취약점에 대한 코드 수정안을 제안합니다.
반드시 아래 JSON 하나만 출력하세요.

{
  "summary": "무엇을 어떻게 고치는지 한 문장(한국어)",
  "plainExplanation": "코드를 모르는 사용자를 위한 쉬운 설명(한국어)",
  "file": "수정할 파일 경로",
  "before": "수정 전 코드(문제되는 부분)",
  "after": "수정 후 코드"
}

규칙: 최소한의 변경만 제안하고, 실제 동작하는 코드를 제시하세요.`;

interface AiFixRaw {
  summary?: string;
  plainExplanation?: string;
  file?: string;
  before?: string;
  after?: string;
}

/**
 * 수정안 생성 진입점.
 * - LLM이 설정되어 있으면 AI로 수정안 생성 시도 (source: "llm").
 * - 실패하거나 미설정이면 규칙 기반 generateFix()로 fallback.
 *
 * 생성 Agent와 검증 Agent는 분리되어 있습니다. 이 함수는 수정안을 "제안"만
 * 하며, 해결 여부는 검증 엔진이 결정합니다.
 */
export async function generateFixSmart(
  finding: SecurityFinding
): Promise<FixAttempt> {
  const key = finding.verificationKey ?? "";
  const deterministicKnown =
    key.startsWith("idor:") ||
    key.startsWith("secret:") ||
    key.startsWith("headers:") ||
    key.startsWith("rls:");

  // 결정적으로 잘 아는 취약점은 규칙 기반이 더 정확 → 그대로 사용.
  if (deterministicKnown || !isConfigured()) {
    return generateFix(finding);
  }

  // 그 외(주로 AI가 찾은 항목)는 AI에게 수정안을 요청.
  try {
    const evidenceText = finding.evidence
      .map((e) => `[${e.kind}] ${e.label}\n${e.content}`)
      .join("\n\n");
    const raw = await completeJson(
      FIX_SYSTEM_PROMPT,
      `취약점: ${finding.title}\n영향: ${finding.humanReadableImpact}\n\n근거:\n${evidenceText}\n\nJSON으로만 답하세요.`
    );
    const parsed = JSON.parse(stripFence(raw)) as AiFixRaw;
    const before = parsed.before ?? "";
    const after = parsed.after ?? "";
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "llm",
      summary: parsed.summary || finding.remediation || "AI가 제안한 수정안입니다.",
      plainExplanation:
        parsed.plainExplanation ||
        "이 변경은 발견된 보안 문제를 해결하기 위한 것입니다.",
      diffs:
        before || after
          ? [{ file: parsed.file || "붙여넣은 코드", patch: unifiedDiff(before, after) }]
          : [],
      applied: false,
      createdAt: now(),
    };
  } catch {
    // AI 실패 시 규칙 기반으로 안전하게 fallback.
    return generateFix(finding);
  }
}

function stripFence(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const b = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (b >= 0 && e > b) return text.slice(b, e + 1);
  return text.trim();
}
