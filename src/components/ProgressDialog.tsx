"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Hoi } from "@/components/mascot/Hoi";

/**
 * 오래 걸리는 요청(점검·전체 수정·재검증) 동안 보여 주는 가운데 모달.
 *
 * - document.body로 Portal 렌더링: 부모의 overflow·transform·sticky 영향으로
 *   잘리거나 치우치지 않게 한다.
 * - role="dialog" + aria-modal, 제목·설명 연결, 열릴 때 포커스 이동, Tab 순환,
 *   닫힐 때 이전 포커스로 복귀, 배경 스크롤 잠금.
 * - 요청이 진행 중이라 닫기 버튼은 없다. Esc를 누르면 닫을 수 없는 이유를 알린다.
 */
export function ProgressDialog({
  open,
  title,
  description,
  liveMessage,
  children,
}: {
  open: boolean;
  title: string;
  description: string;
  /** 스크린리더에 알릴 현재 상태. */
  liveMessage?: string;
  children?: ReactNode;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    if (!open) {
      setNotice(null);
      return;
    }
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    // Portal이 붙은 다음 프레임에 포커스한다.
    const raf = requestAnimationFrame(() => dialogRef.current?.focus());

    function onKey(event: KeyboardEvent) {
      const dialog = dialogRef.current;
      if (!dialog) return;
      if (event.key === "Escape") {
        event.preventDefault();
        setNotice("작업이 진행 중이라 이 창을 닫을 수 없어요. 끝나면 자동으로 닫혀요.");
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    function onFocusIn(event: FocusEvent) {
      const dialog = dialogRef.current;
      if (dialog && event.target instanceof Node && !dialog.contains(event.target)) dialog.focus();
    }

    document.addEventListener("keydown", onKey);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("focusin", onFocusIn);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [open]);

  if (!open || !mounted) return null;

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-[#192638]/45 p-4 backdrop-blur-sm">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-busy="true"
        aria-labelledby="progress-dialog-title"
        aria-describedby="progress-dialog-description"
        tabIndex={-1}
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-3xl border border-line bg-surface p-6 text-center shadow-2xl outline-none sm:p-8"
      >
        <div className="flex justify-center">
          <Hoi mood="searching" size="md" decorative />
        </div>
        <h2 id="progress-dialog-title" className="mt-4 text-xl font-bold text-ink">
          {title}
        </h2>
        <p id="progress-dialog-description" className="mt-2 text-sm leading-relaxed text-ink-subtle">
          {description}
        </p>
        <div className="mx-auto mt-5 h-2 w-40 overflow-hidden rounded-full bg-primary-soft" aria-hidden="true">
          <div className="h-full w-1/3 animate-pulse rounded-full bg-brand-500 motion-reduce:animate-none" />
        </div>
        {children && <div className="mt-5 text-left">{children}</div>}
        <div className="sr-only" aria-live="polite" aria-atomic="true">
          {liveMessage ?? title}
          {notice ? ` ${notice}` : ""}
        </div>
        {notice && (
          <p role="status" className="mt-4 rounded-2xl bg-warning-soft p-3 text-sm text-warning">
            {notice}
          </p>
        )}
      </div>
    </div>,
    document.body
  );
}
