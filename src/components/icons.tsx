import type React from "react";
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

export function ChatIcon({ className = "h-5 w-5", title, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} focusable="false" {...iconA11y(title)} {...props}>
      {title && <title>{title}</title>}
      <path
        d="M5 5h14a2 2 0 012 2v8a2 2 0 01-2 2h-7l-4.5 3.5V17H5a2 2 0 01-2-2V7a2 2 0 012-2z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M8 10h8M8 13h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function StrokeIcon({ className = "h-5 w-5", title, children, ...props }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      focusable="false"
      {...iconA11y(title)}
      {...props}
    >
      {title && <title>{title}</title>}
      {children}
    </svg>
  );
}

export function WrenchIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M14.5 5.5a4 4 0 00-5 5L4 16a2.1 2.1 0 003 3l5.5-5.5a4 4 0 005-5l-2.5 2.5-2.5-.5-.5-2.5 2.5-2.5z" />
    </StrokeIcon>
  );
}

export function RefreshIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M19.5 12a7.5 7.5 0 01-13.2 4.9M4.5 12a7.5 7.5 0 0113.2-4.9" />
      <path d="M17.8 3.5v3.6h-3.6M6.2 20.5v-3.6h3.6" />
    </StrokeIcon>
  );
}

export function ArrowRightIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </StrokeIcon>
  );
}

export function ArchiveIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M14 3.5H7a2 2 0 00-2 2v13a2 2 0 002 2h10a2 2 0 002-2V8.5l-5-5z" />
      <path d="M14 3.5v5h5M10.5 7h1M10.5 10h1M10.5 13h1M9.5 16h3v2.5h-3z" />
    </StrokeIcon>
  );
}

export function BookCheckIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M5 4.5A1.5 1.5 0 016.5 3H19v15H6.5A1.5 1.5 0 005 19.5v-15z" />
      <path d="M5 19.5A1.5 1.5 0 006.5 21H19M9 10.5l2 2 4-4" />
    </StrokeIcon>
  );
}

export function BookOpenIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M12 6.5C10 5 7.5 4.5 4 4.5v13c3.5 0 6 .5 8 2 2-1.5 4.5-2 8-2v-13c-3.5 0-6 .5-8 2z" />
      <path d="M12 6.5v13" />
    </StrokeIcon>
  );
}

export function SparkleIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M11 3.5l1.6 4.4 4.4 1.6-4.4 1.6L11 15.5l-1.6-4.4L5 9.5l4.4-1.6L11 3.5z" />
      <path d="M17.5 14.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
    </StrokeIcon>
  );
}

export function TagIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M3.5 12.2V4.5a1 1 0 011-1h7.7l8.3 8.3a1.4 1.4 0 010 2l-6.7 6.7a1.4 1.4 0 01-2 0L3.5 12.2z" />
      <circle cx="8" cy="8" r="1.4" />
    </StrokeIcon>
  );
}

export function ClockIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </StrokeIcon>
  );
}

export function InfoIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5M12 8h.01" />
    </StrokeIcon>
  );
}

export function ExternalLinkIcon(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M14 4.5h5.5V10M19.5 4.5L11 13M17 14v4.5a1 1 0 01-1 1H5.5a1 1 0 01-1-1V8a1 1 0 011-1H10" />
    </StrokeIcon>
  );
}
