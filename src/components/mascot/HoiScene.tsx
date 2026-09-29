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
      className={`hoi-decoration hoi-card-3d flex flex-col items-center gap-5 !bg-surface-warm px-5 py-10 text-center sm:px-10 ${className}`}
    >
      <Hoi mood={mood} size={size} />
      <div className="min-w-0 max-w-xl">
        <Heading className="break-keep text-2xl font-extrabold tracking-tight text-ink sm:text-3xl">{title}</Heading>
        {description && (
          <div className="mt-3 break-words leading-relaxed text-ink-subtle">{description}</div>
        )}
        {action && <div className="mt-6 flex flex-wrap justify-center gap-2">{action}</div>}
      </div>
    </section>
  );
}
