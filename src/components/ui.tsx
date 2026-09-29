import type {
  ButtonHTMLAttributes,
  DetailsHTMLAttributes,
  HTMLAttributes,
  ReactNode,
  SVGProps,
} from "react";
import type {
  ExecutionTier,
  FindingStatus,
  Severity,
  TestStatus,
} from "@/lib/domain/types";
import {
  severityDisplay,
  statusLabel,
  testStatusLabel,
  type SeverityIconShape,
} from "@/lib/ui/presentation";

// 라벨 맵·조회 함수의 원본은 presentation.ts다. 기존 import 경로를 유지하려고 다시 내보낸다(설계 2-3).
export {
  SEV_LABEL,
  SEV_EXPERT_LABEL,
  STATUS_LABEL,
  TEST_STATUS_LABEL,
  severityLabel,
  statusLabel,
  testStatusLabel,
} from "@/lib/ui/presentation";
export type { SeverityIconShape } from "@/lib/ui/presentation";

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

/** `value`가 `map`의 자기 키일 때만 값을 돌려준다. `"toString"` 같은 프로토타입 키는 거른다. */
function ownValue<V>(map: Record<string, V>, value: unknown): V | undefined {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(map, value)
    ? map[value]
    : undefined;
}

// ─────────────────────────────────────────────────────────────
// 버튼 (설계 2-1)
// ─────────────────────────────────────────────────────────────

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

// 움직임(hover 2px 위, active 2px 아래)과 disabled 표현은 globals.css `.hoi-button-3d`가 맡는다.
const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  // 주황 배경 + 진한 갈색 글자(5.54:1). hover·active 배경과 깊이는 `.is-primary` CSS 규칙.
  primary: "is-primary border-0 bg-brand-500 text-ink",
  // 흰 표면 + 3:1 이상 입력 경계 + 하단 깊이(`.is-secondary`).
  secondary:
    "is-secondary border-2 border-line-input bg-surface text-ink hover:border-brand-700 hover:bg-surface-warm",
  // bg-primary-soft 위에서는 text-ink-subtle 대비가 부족하므로 hover 때 text-ink로 바꾼다.
  ghost:
    "border-2 border-transparent bg-transparent text-ink-subtle hover:bg-primary-soft hover:text-ink",
  danger: "is-danger border-0 bg-danger text-white",
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "min-h-11 px-4 text-sm",
  md: "min-h-12 px-6 text-base",
  lg: "min-h-14 px-7 text-lg",
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
    "hoi-button-3d inline-flex items-center justify-center gap-2 rounded-2xl font-extrabold leading-tight",
    BUTTON_VARIANTS[variant] ?? BUTTON_VARIANTS.primary,
    BUTTON_SIZES[size] ?? BUTTON_SIZES.md,
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

// ─────────────────────────────────────────────────────────────
// 카드 (설계 2-2)
// ─────────────────────────────────────────────────────────────

export type CardVariant = "default" | "warm" | "raised" | "flat" | "danger";

const CARD_VARIANTS: Record<CardVariant, string> = {
  default: "rounded-3xl border-2 border-line bg-surface shadow-warm",
  warm: "rounded-3xl border-2 border-line bg-surface-warm shadow-warm",
  // rounded-3xl, 테두리, 하단 깊이는 globals.css `.hoi-card-3d`.
  raised: "hoi-card-3d",
  flat: "rounded-2xl border-2 border-line bg-surface",
  danger: "rounded-3xl border-2 border-[#f3c4bd] bg-danger-soft",
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
      className={cx(CARD_VARIANTS[variant] ?? CARD_VARIANTS.default, className)}
      {...props}
    >
      {children}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 배지 (설계 2-3)
// ─────────────────────────────────────────────────────────────

export type BadgeTone =
  | "neutral"
  | "primary"
  | "info"
  | "success"
  | "warning"
  | "danger";

const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: "border-line-strong bg-surface-warm text-ink-subtle",
  // bg-primary-soft 위 글자는 text-ink-subtle 대신 진한 브랜드색을 쓴다.
  primary: "border-brand-300 bg-primary-soft text-brand-900",
  info: "border-[#c9def3] bg-info-soft text-info",
  success: "border-[#bfe0c8] bg-success-soft text-success",
  warning: "border-[#f0d9a6] bg-warning-soft text-warning",
  danger: "border-[#f3c4bd] bg-danger-soft text-danger",
};

const BADGE_BASE =
  "inline-flex min-h-7 items-center gap-1.5 rounded-full border-2 px-3 py-0.5 text-[13px] font-bold leading-5";

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
      className={cx(BADGE_BASE, BADGE_TONES[tone] ?? BADGE_TONES.neutral, className)}
      {...props}
    >
      {children}
    </span>
  );
}

/**
 * 심각도 아이콘. 모양만으로 4개 심각도를 구분한다(요구사항 4.4).
 * 장식이므로 항상 aria-hidden이며, 색은 배지 글자색(currentColor)을 따른다.
 */
export function SeverityIcon({
  shape,
  className = "",
  ...props
}: Omit<SVGProps<SVGSVGElement>, "children"> & { shape: SeverityIconShape }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="12"
      height="12"
      data-shape={shape}
      className={cx("shrink-0", className)}
      {...props}
      aria-hidden="true"
      focusable="false"
    >
      {shape === "octagon" && (
        <>
          <polygon points="5,1 11,1 15,5 15,11 11,15 5,15 1,11 1,5" fill="currentColor" />
          <rect x="7.1" y="3.8" width="1.8" height="5.4" rx="0.9" fill="#ffffff" />
          <circle cx="8" cy="11.6" r="1.1" fill="#ffffff" />
        </>
      )}
      {shape === "triangle" && <polygon points="8,1.5 15,14.5 1,14.5" fill="currentColor" />}
      {shape === "diamond" && <polygon points="8,1 15,8 8,15 1,8" fill="currentColor" />}
      {shape === "circle" && (
        <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="2.5" />
      )}
      {shape === "dot" && <circle cx="8" cy="8" r="3" fill="currentColor" />}
    </svg>
  );
}

// 텍스트 브랜드색은 brand-800만 쓴다(500/600/700 금지). critical에는 animation 클래스를 붙이지 않는다.
const SEV_STYLE: Record<Severity, string> = {
  critical: "border-[#f3c4bd] bg-danger-soft text-danger",
  high: "border-brand-300 bg-primary-soft text-brand-800",
  medium: "border-[#f0d9a6] bg-warning-soft text-warning",
  low: "border-[#c9def3] bg-info-soft text-info",
};

const SEV_STYLE_FALLBACK = "border-line-strong bg-surface-warm text-ink-subtle";

export function SeverityBadge({
  severity,
  className = "",
}: {
  severity: Severity;
  className?: string;
}) {
  const { label, icon } = severityDisplay(severity);
  return (
    <span
      data-severity={severity}
      className={cx(
        BADGE_BASE,
        "tracking-tight",
        ownValue(SEV_STYLE, severity) ?? SEV_STYLE_FALLBACK,
        className,
      )}
    >
      <SeverityIcon shape={icon} />
      {label}
    </span>
  );
}

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
    <Badge tone={ownValue(STATUS_TONE, status) ?? "neutral"} className={className}>
      {statusLabel(status)}
    </Badge>
  );
}

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
    <Badge tone={ownValue(TEST_STATUS_TONE, status) ?? "neutral"} className={className}>
      {testStatusLabel(status)}
    </Badge>
  );
}

// ─────────────────────────────────────────────────────────────
// 코드 근거 (설계 2-4)
// ─────────────────────────────────────────────────────────────

export interface CodeEvidenceProps {
  label?: string;
  content: string;
  tone?: "default" | "danger" | "success";
  className?: string;
}

const CODE_BORDER: Record<NonNullable<CodeEvidenceProps["tone"]>, string> = {
  default: "border-[#5b4d44]",
  danger: "border-[#e38b80]",
  success: "border-[#7fbf8e]",
};

/** 전달받은 문자열을 가공 없이 그대로 출력한다(마스킹 보존, 요구사항 8.10). */
export function CodeEvidence({
  label,
  content,
  tone = "default",
  className = "",
}: CodeEvidenceProps) {
  return (
    <div
      className={cx(
        "overflow-hidden rounded-2xl border bg-code text-code-text shadow-warm",
        CODE_BORDER[tone] ?? CODE_BORDER.default,
        className,
      )}
    >
      {label && (
        <div className="border-b border-white/15 bg-white/[0.06] px-4 py-2">
          <span className="text-xs font-bold text-code-muted">{label}</span>
        </div>
      )}
      <pre className="evidence overflow-x-auto p-4 text-code-text">{content}</pre>
    </div>
  );
}

/** 기존 Evidence API를 그대로 유지하는 호환 래퍼. */
export function Evidence(props: CodeEvidenceProps) {
  return <CodeEvidence {...props} />;
}

// ─────────────────────────────────────────────────────────────
// 펼침 (설계 2-4) — 네이티브 <details>/<summary>가 Enter/Space 토글과 펼침 상태를 제공한다.
// ─────────────────────────────────────────────────────────────

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
        "group rounded-2xl border-2 border-line bg-surface px-4 py-2 transition-colors open:border-line-strong open:bg-surface-warm open:shadow-warm motion-reduce:transition-none",
        className,
      )}
      {...props}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 rounded-xl font-bold text-ink marker:content-none hover:text-brand-800 [&::-webkit-details-marker]:hidden">
        <span>{summary}</span>
        <span
          aria-hidden="true"
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 border-brand-300 bg-primary-soft text-lg font-bold leading-none text-brand-900 transition-transform group-open:rotate-45 motion-reduce:transition-none"
        >
          +
        </span>
      </summary>
      <div className="mb-2 mt-2 border-t-2 border-dashed border-line pt-4 text-ink-subtle">{children}</div>
    </details>
  );
}

export function TechnicalDetails({
  children,
  summary = "기술 정보 보기",
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

// ─────────────────────────────────────────────────────────────
// 상태 화면
// ─────────────────────────────────────────────────────────────

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
      className={cx("hoi-decoration border-dashed px-5 py-10 text-center sm:px-8 sm:py-12", className)}
    >
      {illustration && <div className="mb-4 flex justify-center">{illustration}</div>}
      <h2 className="text-xl font-extrabold text-ink sm:text-2xl">{title}</h2>
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
        "flex gap-3 rounded-3xl border-2 border-[#f3c4bd] bg-danger-soft p-5 text-danger",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-danger text-base font-extrabold text-white"
      >
        !
      </span>
      <div className="min-w-0">
        <p className="font-bold">{title}</p>
        {description && <div className="mt-1 text-sm leading-relaxed text-ink">{description}</div>}
        {action && <div className="mt-4">{action}</div>}
      </div>
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
          <p className="mb-2 inline-flex rounded-full bg-primary-soft px-3 py-0.5 text-sm font-bold text-brand-900">{eyebrow}</p>
        )}
        <h2 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h2>
        {description && <div className="mt-1 text-ink-subtle">{description}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

const METRIC_ACCENT: Record<BadgeTone, string> = {
  neutral: "bg-line-strong",
  primary: "bg-brand-500",
  info: "bg-info",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
};

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
  return (
    <Card variant="raised" className={cx("overflow-hidden p-0", className)}>
      <div className={cx("h-2", METRIC_ACCENT[tone] ?? METRIC_ACCENT.neutral)} aria-hidden="true" />
      <div className="p-5">
        <p className="text-sm font-bold text-ink-subtle">{label}</p>
        <div className="mt-1 text-3xl font-extrabold tracking-tight text-ink">{value}</div>
        {hint && <div className="mt-2 text-sm text-ink-muted">{hint}</div>}
      </div>
    </Card>
  );
}

// 1회성 작은 컨페티(장식). 부모는 position: relative여야 한다. 동작 줄이기 설정이면 CSS가 숨긴다.
const CONFETTI_PIECES = [6, 14, 23, 31, 42, 50, 58, 67, 75, 84, 92];

export function Confetti({ className = "" }: { className?: string } = {}) {
  return (
    <div aria-hidden="true" className={cx("hoi-confetti", className)}>
      {CONFETTI_PIECES.map((left, i) => (
        <span key={left} style={{ left: `${left}%`, animationDelay: `${(i % 4) * 90}ms` }} />
      ))}
    </div>
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
