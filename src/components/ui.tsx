import type { Severity, FindingStatus } from "@/lib/domain/types";

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-yellow-50 text-yellow-700 border-yellow-200",
  low: "bg-cyan-50 text-cyan-700 border-cyan-200",
};

export const SEV_LABEL: Record<Severity, string> = {
  critical: "심각",
  high: "높음",
  medium: "보통",
  low: "낮음",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold tracking-wide ${SEV_STYLE[severity]}`}
    >
      {SEV_LABEL[severity]}
    </span>
  );
}

export const STATUS_LABEL: Record<FindingStatus, string> = {
  detected: "발견됨",
  verified: "공격 재현됨",
  fixing: "수정 중",
  fixed: "수정 적용됨",
  verification_failed: "재검증 실패",
  regression_failed: "기능 회귀 실패",
  resolved: "수정 검증 완료",
};

const STATUS_STYLE: Record<FindingStatus, string> = {
  detected: "bg-slate-100 text-slate-700",
  verified: "bg-amber-100 text-amber-800",
  fixing: "bg-blue-100 text-blue-800",
  fixed: "bg-blue-100 text-blue-800",
  verification_failed: "bg-red-100 text-red-800",
  regression_failed: "bg-red-100 text-red-800",
  resolved: "bg-emerald-100 text-emerald-800",
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLE[status]}`}
    >
      {STATUS_LABEL[status]}
    </span>
  );
}

export function Evidence({
  label,
  content,
  tone = "default",
}: {
  label?: string;
  content: string;
  tone?: "default" | "danger" | "success";
}) {
  const border =
    tone === "danger"
      ? "border-red-200"
      : tone === "success"
        ? "border-emerald-200"
        : "border-slate-200";
  const head =
    tone === "danger"
      ? "text-red-600"
      : tone === "success"
        ? "text-emerald-600"
        : "text-slate-500";
  return (
    <div className={`overflow-hidden rounded-lg border ${border} bg-slate-900`}>
      {label && (
        <div
          className={`border-b border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium ${head} bg-opacity-100`}
        >
          <span className="text-slate-300">{label}</span>
        </div>
      )}
      <pre className="evidence overflow-x-auto p-3 text-slate-100">{content}</pre>
    </div>
  );
}

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border border-slate-200 bg-white shadow-sm ${className}`}
    >
      {children}
    </div>
  );
}

export function SimulatedTag() {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-violet-50 px-1.5 py-0.5 text-[11px] font-medium text-violet-700 border border-violet-200">
      시뮬레이션 결과
    </span>
  );
}

export function AiTag() {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-sky-50 px-1.5 py-0.5 text-[11px] font-medium text-sky-700 border border-sky-200">
      AI 분석
    </span>
  );
}


/** 스캐너 카테고리 영문 → 한국어 표시 매핑. 미정의 값은 원문 그대로 노출. */
export const CATEGORY_LABEL: Record<string, string> = {
  "Secret Exposure": "비밀정보 노출",
  "Broken Access Control": "접근 권한 통제 미흡",
  "Security Headers": "보안 헤더 누락",
  CORS: "CORS 설정 오류",
  "Vulnerable Dependencies": "취약한 라이브러리",
  "BaaS Misconfiguration": "백엔드 서비스 설정 오류",
  "AI Detected": "AI 분석 발견",
  // 스캔 범위(미테스트) 카테고리
  "Complex Business Logic": "복잡한 비즈니스 로직",
  "Social Engineering": "사회공학적 공격",
  DDoS: "디도스(DDoS)",
  "Internal Infrastructure": "내부 인프라",
  "Advanced Supply Chain Attacks": "고급 공급망 공격",
};

export function categoryLabel(c: string): string {
  return CATEGORY_LABEL[c] ?? c;
}
