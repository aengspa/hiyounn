import Link from "next/link";
import { buttonClassName } from "@/components/ui";

interface Props {
  title: string;
  subtitle?: string;
  backHref?: string;
  backLabel?: string;
  action?: { href: string; label: string };
  children?: React.ReactNode;
}

/** 기존 props 계약을 유지하는 반응형 페이지 헤더. */
export function PageHeader({
  title,
  subtitle,
  backHref,
  backLabel,
  action,
  children,
}: Props) {
  return (
    <header className="border-b-2 border-line bg-gradient-to-b from-canvas-soft to-surface-warm">
      <div className="mx-auto max-w-6xl px-4 py-4 sm:px-6 sm:py-6">
        {backHref && (
          <Link
            href={backHref}
            className="mb-2 inline-flex min-h-11 items-center gap-1 rounded-full border-2 border-line bg-surface px-3 text-sm font-bold text-brand-800 hover:border-brand-300 hover:text-brand-900"
            aria-label="이전 화면으로 이동"
          >
            <span aria-hidden="true">←</span>&nbsp;{backLabel ?? "이전"}
          </Link>
        )}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
          <div className="min-w-0">
            <h1 className="break-words text-2xl font-extrabold tracking-tight text-ink sm:text-3xl">
              {title}
            </h1>
            {subtitle && (
              <p className="mt-1 max-w-3xl text-sm leading-relaxed text-ink-subtle sm:text-base">
                {subtitle}
              </p>
            )}
          </div>
          {(children || action) && (
            <div className="flex flex-wrap items-center gap-2 sm:shrink-0 sm:justify-end">
              {children}
              {action && (
                <Link
                  href={action.href}
                  className={buttonClassName({ size: "sm" })}
                >
                  {action.label}
                </Link>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
