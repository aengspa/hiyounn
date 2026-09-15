import Link from "next/link";

interface Props {
  title: string;
  subtitle?: string;
  backHref?: string;
  backLabel?: string;
  action?: { href: string; label: string };
  children?: React.ReactNode;
}

/** 앱 상단바 느낌의 페이지 헤더. 사이드바 레이아웃과 함께 사용. */
export function PageHeader({
  title,
  subtitle,
  backHref,
  backLabel,
  action,
  children,
}: Props) {
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/85 backdrop-blur">
      <div className="mx-auto max-w-6xl px-6 py-4">
        {backHref && (
          <Link
            href={backHref}
            className="mb-1 inline-block text-sm text-brand-600 hover:underline"
          >
            ← {backLabel ?? "뒤로"}
          </Link>
        )}
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900">{title}</h1>
            {subtitle && (
              <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            {children}
            {action && (
              <Link
                href={action.href}
                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
              >
                {action.label}
              </Link>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
