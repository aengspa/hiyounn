"use client";

import { useState } from "react";

type Item = { title: string; body: string };

const ITEMS: Item[] = [
  {
    title: "근거",
    body: "모든 발견은 실제 근거로 뒷받침됩니다. 정확한 코드, HTTP 요청과 응답, 그리고 재현된 공격까지 — AI의 짐작이 아닙니다.",
  },
  {
    title: "검증",
    body: "수정 후 똑같은 공격을 다시 실행합니다. 공격이 막히고 정상 기능도 그대로 동작할 때에만 '검증 완료'로 표시합니다.",
  },
  {
    title: "쉬운 설명",
    body: "전문 용어(CWE, OWASP)를 보여주기 전에, 당신과 사용자에게 실제로 어떤 피해가 생길 수 있는지 먼저 설명합니다.",
  },
];

export function FeatureCards() {
  const [active, setActive] = useState<number | null>(null);

  return (
    <div className="relative">
      {/* Dimming overlay — appears when any card is hovered */}
      <div
        className={`pointer-events-none fixed inset-0 z-20 bg-slate-900 transition-opacity duration-500 ease-out ${
          active !== null ? "opacity-10" : "opacity-0"
        }`}
      />

      <section className="mx-auto grid max-w-4xl gap-10 pb-20 md:grid-cols-3">
        {ITEMS.map((item, i) => {
          const isActive = active === i;
          return (
            // Fixed-height slot: reserves layout space so the page never shifts.
            <div key={item.title} className="relative h-24">
              <div
                onMouseEnter={() => setActive(i)}
                onMouseLeave={() => setActive(null)}
                className={`absolute left-0 top-0 flex w-full origin-center flex-col items-center justify-center rounded-xl border bg-white px-5 py-6 text-center transition-all duration-300 ease-out ${
                  isActive
                    ? "z-30 scale-125 border-slate-400 shadow-2xl"
                    : "z-0 scale-100 border-slate-200 shadow-sm"
                }`}
              >
                <h3
                  className={`text-xl font-bold transition ${
                    isActive ? "text-slate-700" : "text-slate-900"
                  }`}
                >
                  {item.title}
                </h3>
                <p
                  className={`overflow-hidden text-sm text-slate-600 transition-all duration-300 ${
                    isActive ? "mt-3 max-h-40 opacity-100" : "max-h-0 opacity-0"
                  }`}
                >
                  {item.body}
                </p>
              </div>
            </div>
          );
        })}
      </section>
    </div>
  );
}
