import type { ReactNode } from "react";
import { Hoi, type HoiMood, type HoiSize } from "./Hoi";

export interface HoiSceneProps {
  mood?: HoiMood;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  size?: HoiSize;
  headingLevel?: "h1" | "h2";
  className?: string;
}

/** 빈 상태·완료·오류 안내에 재사용하는 호이 중심 장면. */
export function HoiScene({
  mood = "guide",
  title,
  description,
  action,
  size = "lg",
  headingLevel = "h2",
  className = "",
}: HoiSceneProps) {
  const Heading = headingLevel;

  return (
    <section
      className={`hoi-decoration flex flex-col items-center gap-5 rounded-3xl border border-line bg-surface-warm px-5 py-9 text-center shadow-warm sm:px-8 ${className}`}
    >
      <Hoi mood={mood} size={size} />
      <div className="min-w-0 max-w-xl">
        <Heading className="break-keep text-2xl font-black tracking-tight text-ink">{title}</Heading>
        {description && (
          <div className="mt-2 break-words text-ink-subtle">{description}</div>
        )}
        {action && <div className="mt-6 flex flex-wrap justify-center gap-2">{action}</div>}
      </div>
    </section>
  );
}
