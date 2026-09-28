import type { HTMLAttributes, ReactNode } from "react";
import { Hoi, type HoiMood, type HoiSize } from "./Hoi";

export interface HoiSpeechProps extends HTMLAttributes<HTMLDivElement> {
  mood?: HoiMood;
  size?: Extract<HoiSize, "sm" | "md" | "lg">;
  children: ReactNode;
  hideMascot?: boolean;
}

export function HoiSpeech({
  mood = "guide",
  size = "md",
  children,
  hideMascot = false,
  className = "",
  ...props
}: HoiSpeechProps) {
  return (
    <div
      className={`flex items-end gap-3 ${className}`}
      aria-label="호이의 안내"
      {...props}
    >
      {!hideMascot && <Hoi mood={mood} size={size} decorative />}
      <div className="relative mb-2 min-w-0 rounded-3xl rounded-bl-md border border-line bg-white px-5 py-4 font-bold leading-relaxed text-ink shadow-warm">
        <span
          aria-hidden="true"
          className="absolute -left-2 bottom-4 h-4 w-4 rotate-45 border-b border-l border-line bg-white"
        />
        {children}
      </div>
    </div>
  );
}
