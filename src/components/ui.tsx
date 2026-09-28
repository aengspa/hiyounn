import type {
  ButtonHTMLAttributes,
  DetailsHTMLAttributes,
  HTMLAttributes,
  ReactNode,
} from "react";
import type {
  ExecutionTier,
  FindingStatus,
  Severity,
  TestStatus,
} from "@/lib/domain/types";

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: "border border-brand-600 bg-brand-600 text-white hover:bg-brand-700",
  secondary: "border border-line-strong bg-white text-ink hover:bg-surface-warm",
  ghost: "border border-transparent bg-transparent text-ink-subtle hover:bg-primary-soft/60 hover:text-ink",
  danger: "border border-red-600 bg-red-600 text-white hover:bg-red-700",
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "px-3 py-2 text-sm",
  md: "px-4 py-2.5 text-sm",
  lg: "px-5 py-3 text-base",
};

/** Link에도 같은 버튼 외형을 적용할 수 있는 class helper. */
export function buttonClassName({
  variant = "primary",
  size = "md",
  className = "",
}: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  className?: string;
} = {}) {
  return cx(
    "hoi-button-3d inline-flex items-center justify-center gap-2 rounded-xl font-semibold leading-tight disabled:cursor-not-allowed disabled:opacity-55",
    BUTTON_VARIANTS[variant],
    BUTTON_SIZES[size],
    className,
  );
}


export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export function Button({
  variant = "primary",
  size = "md",
  className = "",
  type = "button",
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={buttonClassName({ variant, size, className })}
      {...props}
    />
  );
}

export type CardVariant = "default" | "warm" | "raised" | "flat" | "danger";

const CARD_VARIANTS: Record<CardVariant, string> = {
  default: "border-line bg-white shadow-warm",
  warm: "border-line bg-surface-warm shadow-warm",
  raised: "hoi-card-3d",
  flat: "border-line bg-white",
  danger: "border-red-200 bg-danger-soft shadow-warm",
};

export function Card({
  children,
  className = "",
  variant = "default",
  ...props
}: HTMLAttributes<HTMLDivElement> & {
  children: ReactNode;
  variant?: CardVariant;
}) {
  return (
    <div
      className={cx(
        "rounded-2xl border",
        CARD_VARIANTS[variant],
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export type BadgeTone =
  | "neutral"
  | "primary"
  | "info"
  | "success"
  | "warning"
  | "danger";

const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: "border-line bg-surface-warm text-ink-subtle",
  primary: "border-blue-200 bg-primary-soft text-brand-900",
  info: "border-blue-200 bg-info-soft text-info",
  success: "border-green-200 bg-success-soft text-success",
  warning: "border-amber-200 bg-warning-soft text-warning",
  danger: "border-red-200 bg-danger-soft text-danger",
};

export function Badge({
  children,
  tone = "neutral",
  className = "",
  ...props
}: HTMLAttributes<HTMLSpanElement> & {
  children: ReactNode;
  tone?: BadgeTone;
}) {
  return (
    <span
      className={cx(
        "inline-flex min-h-6 items-center rounded-full border px-2.5 py-0.5 text-xs font-bold leading-5",
        BADGE_TONES[tone],
        className,
      )}
      {...props}
    >
      {children}
    </span>
  );
}

const SEV_STYLE: Record<Severity, string> = {
  critical: "border-red-300 bg-danger-soft text-red-800",
  high: "border-orange-300 bg-orange-50 text-orange-800",
  medium: "border-amber-300 bg-warning-soft text-amber-800",
  low: "border-blue-200 bg-info-soft text-blue-800",
};

export const SEV_LABEL: Record<Severity, string> = {
  critical: "매우 급해요",
  high: "우선 확인해요",
  medium: "살펴보면 좋아요",
  low: "여유 있게 확인해요",
};

export function SeverityBadge({
  severity,
  className = "",
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cx(
        "inline-flex min-h-6 items-center rounded-full border px-2.5 py-0.5 text-xs font-bold tracking-tight",
        SEV_STYLE[severity],
        className,
      )}
    >
      {SEV_LABEL[severity]}
    </span>
  );
}

export const STATUS_LABEL: Record<FindingStatus, string> = {
  detected: "고치면 좋은 부분을 찾았어요",
  verified: "문제가 실제 생기는 것을 확인했어요",
  fixing: "고치는 중이에요",
  fixed: "수정 내용을 적용했어요",
  verification_failed: "아직 완전히 막히지 않았어요",
  regression_failed: "기존 기능 하나를 다시 확인해야 해요",
  resolved: "고친 내용이 잘 막히는지 확인했어요",
};

const STATUS_TONE: Record<FindingStatus, BadgeTone> = {
  detected: "neutral",
  verified: "warning",
  fixing: "info",
  fixed: "info",
  verification_failed: "danger",
  regression_failed: "danger",
  resolved: "success",
};

export function StatusBadge({
  status,
  className = "",
}: {
  status: FindingStatus;
  className?: string;
}) {
  return (
    <Badge tone={STATUS_TONE[status]} className={className}>
      {STATUS_LABEL[status]}
    </Badge>
  );
}

export const TEST_STATUS_LABEL: Record<TestStatus, string> = {
  CONFIRMED: "문제가 생기는 것을 확인했어요",
  SUSPECTED: "조금 더 확인이 필요해요",
  NOT_DETECTED: "이번 점검에서는 찾지 못했어요",
  NOT_APPLICABLE: "이 프로젝트에는 해당하지 않아요",
  NOT_TESTED: "아직 확인하지 않았어요",
  TEST_FAILED: "점검을 마치지 못했어요",
  FIXED_VERIFIED: "수정 후 잘 막히는 것을 확인했어요",
  REGRESSION_FAILED: "기존 기능을 다시 확인해야 해요",
};

const TEST_STATUS_TONE: Record<TestStatus, BadgeTone> = {
  CONFIRMED: "warning",
  SUSPECTED: "neutral",
  NOT_DETECTED: "neutral",
  NOT_APPLICABLE: "neutral",
  NOT_TESTED: "neutral",
  TEST_FAILED: "danger",
  FIXED_VERIFIED: "success",
  REGRESSION_FAILED: "danger",
};

export function TestStatusBadge({
  status,
  className = "",
}: {
  status: TestStatus;
  className?: string;
}) {
  return (
    <Badge tone={TEST_STATUS_TONE[status]} className={className}>
      {TEST_STATUS_LABEL[status]}
    </Badge>
  );
}

export interface CodeEvidenceProps {
  label?: string;
  content: string;
  tone?: "default" | "danger" | "success";
  className?: string;
}

export function CodeEvidence({
  label,
  content,
  tone = "default",
  className = "",
}: CodeEvidenceProps) {
  const border =
    tone === "danger"
      ? "border-red-400"
      : tone === "success"
        ? "border-green-500"
        : "border-[#5b4d44]";
  const marker =
    tone === "danger"
      ? "text-red-200"
      : tone === "success"
        ? "text-green-200"
        : "text-[#ead9ca]";

  return (
    <div
      className={cx(
        "overflow-hidden rounded-2xl border bg-code text-[#fffaf2] shadow-sm",
        border,
        className,
      )}
    >
      {label && (
        <div className="border-b border-white/15 bg-white/[0.06] px-4 py-2">
          <span className={cx("text-xs font-bold", marker)}>{label}</span>
        </div>
      )}
      <pre className="evidence overflow-x-auto p-4 text-[#fffaf2]">{content}</pre>
    </div>
  );
}

/** 기존 Evidence API를 그대로 유지하는 호환 래퍼. */
export function Evidence(props: CodeEvidenceProps) {
  return <CodeEvidence {...props} />;
}

export function Disclosure({
  summary,
  children,
  className = "",
  ...props
}: DetailsHTMLAttributes<HTMLDetailsElement> & {
  summary: ReactNode;
  children: ReactNode;
}) {
  return (
    <details
      className={cx(
        "group rounded-2xl border border-line bg-white px-4 py-3 open:shadow-warm",
        className,
      )}
      {...props}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 font-bold text-ink marker:content-none">
        <span>{summary}</span>
        <span
          aria-hidden="true"
          className="text-xl leading-none text-brand-700 transition-transform group-open:rotate-45"
        >
          +
        </span>
      </summary>
      <div className="border-t border-line pt-4 text-ink-subtle">{children}</div>
    </details>
  );
}

export function TechnicalDetails({
  children,
  summary = "전문가용 정보 펼쳐보기",
  className = "",
  ...props
}: Omit<DetailsHTMLAttributes<HTMLDetailsElement>, "children"> & {
  children: ReactNode;
  summary?: ReactNode;
}) {
  return (
    <Disclosure summary={summary} className={className} {...props}>
      {children}
    </Disclosure>
  );
}

export function EmptyState({
  title,
  description,
  action,
  illustration,
  className = "",
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  illustration?: ReactNode;
  className?: string;
}) {
  return (
    <Card
      variant="warm"
      className={cx("hoi-decoration px-5 py-10 text-center sm:px-8", className)}
    >
      {illustration && <div className="mb-4 flex justify-center">{illustration}</div>}
      <h2 className="text-xl font-semibold text-ink">{title}</h2>
      {description && (
        <div className="mx-auto mt-2 max-w-xl text-sm text-ink-subtle sm:text-base">
          {description}
        </div>
      )}
      {action && <div className="mt-6 flex justify-center">{action}</div>}
    </Card>
  );
}

export function FriendlyError({
  title = "앗, 요청을 마치지 못했어요",
  description,
  action,
  className = "",
}: {
  title?: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cx(
        "rounded-2xl border border-red-200 bg-danger-soft p-5 text-danger",
        className,
      )}
    >
      <p className="font-semibold">{title}</p>
      {description && <div className="mt-1 text-sm text-red-800">{description}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function SectionHeader({
  eyebrow,
  title,
  description,
  action,
  className = "",
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cx(
        "flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between",
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow && (
          <p className="mb-1 text-sm font-semibold text-brand-700">{eyebrow}</p>
        )}
        <h2 className="text-2xl font-bold tracking-tight text-ink">{title}</h2>
        {description && <div className="mt-1 text-ink-subtle">{description}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  hint,
  tone = "neutral",
  className = "",
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  tone?: BadgeTone;
  className?: string;
}) {
  const accent: Record<BadgeTone, string> = {
    neutral: "bg-surface-warm",
    primary: "bg-primary-soft",
    info: "bg-info-soft",
    success: "bg-success-soft",
    warning: "bg-warning-soft",
    danger: "bg-danger-soft",
  };

  return (
    <Card variant="raised" className={cx("overflow-hidden p-0", className)}>
      <div className={cx("h-2", accent[tone])} aria-hidden="true" />
      <div className="p-5">
        <p className="text-sm font-bold text-ink-subtle">{label}</p>
        <div className="mt-1 text-3xl font-bold tracking-tight text-ink">{value}</div>
        {hint && <div className="mt-2 text-sm text-ink-muted">{hint}</div>}
      </div>
    </Card>
  );
}

export function SimulatedTag({ className = "" }: { className?: string } = {}) {
  return (
    <Badge tone="primary" className={className} title="허용된 격리 범위에서 확인한 결과예요">
      격리 시뮬레이션
    </Badge>
  );
}

export function AiTag({ className = "" }: { className?: string } = {}) {
  return (
    <Badge tone="info" className={className} title="AI가 분석한 내용이에요">
      AI가 살펴봤어요
    </Badge>
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
  "Complex Business Logic": "복잡한 비즈니스 로직",
  "Social Engineering": "사회공학적 공격",
  DDoS: "디도스(DDoS)",
  "Internal Infrastructure": "내부 인프라",
  "Advanced Supply Chain Attacks": "고급 공급망 공격",
};

export function categoryLabel(c: string): string {
  return CATEGORY_LABEL[c] ?? c;
}

export const TIER_LABEL: Record<ExecutionTier, string> = {
  PASSIVE: "코드와 설정만 살펴봐요",
  SAFE_ACTIVE: "서비스에 무리 없이 확인해요",
  ISOLATED_ACTIVE: "격리된 곳에서 문제를 재현해요",
  PATCH: "고칠 내용을 만들어요",
  PRIVILEGED_CHANGE: "승인 후 운영 환경에 반영해요",
};

export function tierLabel(t: ExecutionTier): string {
  return TIER_LABEL[t];
}
