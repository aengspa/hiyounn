import type { SVGProps } from "react";

export interface IconProps extends SVGProps<SVGSVGElement> {
  title?: string;
}

function iconA11y(title?: string) {
  return title
    ? { role: "img" as const, "aria-label": title }
    : { "aria-hidden": true as const };
}

export function ShieldIcon({
  className = "h-5 w-5 text-brand-600",
  title,
  ...props
}: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      focusable="false"
      {...iconA11y(title)}
      {...props}
    >
      {title && <title>{title}</title>}
      <path
        d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function GridIcon({ className = "h-5 w-5", title, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className={className} focusable="false" {...iconA11y(title)} {...props}>
      {title && <title>{title}</title>}
      <rect x="2.5" y="2.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11.5" y="2.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="2.5" y="11.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11.5" y="11.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export function PlusIcon({ className = "h-5 w-5", title, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className={className} focusable="false" {...iconA11y(title)} {...props}>
      {title && <title>{title}</title>}
      <path d="M10 4v12M4 10h12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

export function SearchIcon({ className = "h-5 w-5", title, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className={className} focusable="false" {...iconA11y(title)} {...props}>
      {title && <title>{title}</title>}
      <circle cx="8.5" cy="8.5" r="5.5" stroke="currentColor" strokeWidth="1.7" />
      <path d="M12.5 12.5L17 17" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}
