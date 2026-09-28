"use client";

import { useState, type ReactNode } from "react";

export interface HoiImageProps {
  /** `resolveHoiImageSrc`로 검증된 내부 PNG 경로(`/hoi/*.png`) */
  src: string;
  /** decorative가 아닐 때 쓰는 대체 텍스트(Mood 라벨) */
  alt: string;
  /** true면 alt=""와 aria-hidden="true"로 보조 기술에서 숨긴다 */
  decorative?: boolean;
  /** 크기 클래스 등. SVG 폴백과 같은 값을 넘긴다 */
  className?: string;
  /** 이미지 로드에 실패하면 대신 그릴 노드(같은 크기·접근성의 SVG 호이) */
  fallback: ReactNode;
}

/**
 * 호이 PNG를 그리고, 로드에 실패하면 깨진 이미지 대신 `fallback`을 보여 준다.
 */
export function HoiImage({ src, alt, decorative = false, className = "", fallback }: HoiImageProps) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return <>{fallback}</>;
  }

  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={src}
      alt={decorative ? "" : alt}
      aria-hidden={decorative ? "true" : undefined}
      className={className}
      onError={() => setFailed(true)}
    />
  );
}
