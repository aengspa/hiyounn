import Link from "next/link";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Badge, Card, buttonClassName } from "@/components/ui";
import { ScanScopeMeter } from "@/components/ScanScopeMeter";
import { SCAN_MODES, SCAN_MODE_INFO, type ScanMode } from "@/lib/domain/scanMode";

/**
 * 새 프로젝트 1단계: 보안 스캔 방식(A/B/C) 선택.
 * A < B < C 순으로 스캔 범위가 넓어진다는 것을 먼저 보여주고, 사용자가 고르면
 * 해당 방식에 맞는 입력 폼(/dashboard/new/setup?mode=...)으로 이동한다.
 */
export default function ChooseScanModePage() {
  return (
    <>
      <PageHeader
        title="어떤 방식으로 점검할까요?"
        subtitle="준비할 수 있는 자료에 맞춰 보안 스캔 방식을 골라 주세요."
        backHref="/dashboard"
        backLabel="내 프로젝트"
      />
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
        <HoiSpeech mood="guide" size="md">
          A → B → C 로 갈수록 호이가 살펴보는 범위가 넓어져요. 대신 준비할 것도 늘어나고,
          C는 실제 공격에 가까운 요청을 보내니 꼭 격리된 테스트 서버에서 사용해 주세요.
        </HoiSpeech>

        <ScopeOverview />

        <div className="mt-8 grid gap-5 lg:grid-cols-3" role="list" aria-label="보안 스캔 방식">
          {SCAN_MODES.map((mode) => (
            <ModeCard key={mode} mode={mode} />
          ))}
        </div>

        <p className="mt-6 text-sm leading-relaxed text-ink-muted">
          어떤 방식을 골라도 자동 점검만으로 모든 위험을 찾을 수는 없어요. 선택한 범위를 넘는 검사는
          서버에서 실행하지 않고 &lsquo;확인하지 못한 항목&rsquo;으로 따로 알려드려요.
        </p>
      </div>
    </>
  );
}

/** A ⊂ B ⊂ C 포함 관계를 한눈에 보여주는 겹친 상자. */
function ScopeOverview() {
  const a = SCAN_MODE_INFO.static;
  const b = SCAN_MODE_INFO.safe_active;
  const c = SCAN_MODE_INFO.isolated_active;
  return (
    <Card variant="warm" className="mt-6 p-5 sm:p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-black text-ink">스캔 범위 한눈에 보기</h2>
        <p className="text-sm font-bold text-ink-subtle">A &lt; B &lt; C</p>
      </div>
      <div
        className="mt-4 rounded-3xl border-2 border-dashed border-red-300 bg-danger-soft p-3 sm:p-4"
        aria-label={`C ${c.title}: B의 범위에 격리 서버 공격 재현이 더해져요`}
      >
        <ScopeLabel letter="C" title={c.title} extra="+ 테스트 계정으로 공격 재현" tone="text-red-800" />
        <div className="mt-3 rounded-2xl border-2 border-dashed border-amber-300 bg-warning-soft p-3 sm:p-4">
          <ScopeLabel letter="B" title={b.title} extra="+ 배포 URL 비파괴 요청" tone="text-amber-900" />
          <div className="mt-3 rounded-2xl border-2 border-green-300 bg-success-soft p-3 sm:p-4">
            <ScopeLabel letter="A" title={a.title} extra="소스 코드 정적 분석" tone="text-green-900" />
          </div>
        </div>
      </div>
    </Card>
  );
}

function ScopeLabel({
  letter,
  title,
  extra,
  tone,
}: {
  letter: string;
  title: string;
  extra: string;
  tone: string;
}) {
  return (
    <p className={`flex flex-wrap items-center gap-x-2 gap-y-1 text-sm ${tone}`}>
      <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-white text-sm font-black shadow-sm">
        {letter}
      </span>
      <span className="font-extrabold">{title}</span>
      <span className="opacity-80">{extra}</span>
    </p>
  );
}

const MODE_TONE: Record<ScanMode, { badge: "success" | "warning" | "danger"; risk: string }> = {
  static: { badge: "success", risk: "위험도 낮음" },
  safe_active: { badge: "warning", risk: "위험도 보통" },
  isolated_active: { badge: "danger", risk: "위험도 높음 · 격리 필수" },
};

function ModeCard({ mode }: { mode: ScanMode }) {
  const info = SCAN_MODE_INFO[mode];
  const tone = MODE_TONE[mode];
  return (
    <Card variant="raised" className="flex flex-col p-5 sm:p-6" role="listitem">
      <div className="flex items-start justify-between gap-3">
        <span
          className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-primary-soft text-2xl font-black text-brand-900"
          aria-hidden="true"
        >
          {info.letter}
        </span>
        <Badge tone={tone.badge}>{tone.risk}</Badge>
      </div>

      <h2 className="mt-4 text-xl font-black text-ink">
        <span className="sr-only">{info.letter} 방식: </span>
        {info.title}
      </h2>
      <p className="mt-1 text-sm font-bold text-ink-subtle">{info.tagline}</p>

      <ScanScopeMeter scope={info.scope} className="mt-4" />

      <h3 className="mt-5 text-sm font-extrabold text-ink">준비할 것</h3>
      <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-ink-subtle">
        {info.needs.map((n) => (
          <li key={n} className="flex gap-2">
            <span aria-hidden="true">•</span>
            <span>{n}</span>
          </li>
        ))}
      </ul>

      <h3 className="mt-5 text-sm font-extrabold text-ink">확인하는 것</h3>
      <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-ink-subtle">
        {info.covers.map((c) => (
          <li key={c} className="flex gap-2">
            <span aria-hidden="true" className="text-success">✓</span>
            <span>{c}</span>
          </li>
        ))}
      </ul>

      <p
        className={`mt-5 rounded-2xl border p-3 text-sm leading-relaxed ${
          mode === "isolated_active"
            ? "border-red-200 bg-danger-soft text-red-800"
            : "border-line bg-surface-warm text-ink-subtle"
        }`}
      >
        {info.caution}
      </p>

      <div className="mt-auto pt-5">
        <Link
          href={`/dashboard/new/setup?mode=${mode}`}
          className={buttonClassName({
            variant: mode === "static" ? "primary" : "secondary",
            size: "lg",
            className: "w-full",
          })}
        >
          {info.letter} 방식으로 시작하기
        </Link>
      </div>
    </Card>
  );
}
