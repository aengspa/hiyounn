import Link from "next/link";
import { SampleProjectCard } from "@/components/SampleProjectCard";
import { SAMPLE_APPS } from "@/lib/samples";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Card, buttonClassName } from "@/components/ui";

/**
 * 프로젝트 등록 1단계: 코드와 파일로 점검을 시작하거나, 샘플 앱으로 먼저 체험한다.
 * 공개 웹사이트 점검(safe_active)은 제공하지 않는다(setup 경로와 API에서도 막는다).
 */
export default function ChooseScanModePage() {
  return (
    <>
      <PageHeader
        title="호이에게 프로젝트를 소개해 주세요"
        subtitle="가지고 있는 자료에 맞는 방법을 골라 주세요."
        backHref="/dashboard"
        backLabel="이전"
      />
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
        {/* 문장이 끝날 때만 줄을 바꾼다 */}
        <HoiSpeech mood="guide" size="md">
          <span className="block">코드 또는 파일을 업로드해주시면 제가 안전하게 스캔할게요.</span>
          <span className="block">안전을 위해, 깃허브 주소를 통해서는 스캔하지 않아요.</span>
        </HoiSpeech>

        <div className="mt-8 grid gap-4 sm:grid-cols-2">
          <ModeCard
            title="코드와 파일 확인"
            description="프로젝트 파일이나 코드를 읽어 보안 문제를 찾아요."
            actionLabel="코드와 파일로 시작하기"
          />
          <SampleProjectCard sample={SAMPLE_APPS[0]} className="h-full" />
        </div>
      </div>
    </>
  );
}

function ModeCard({
  title,
  description,
  actionLabel,
}: {
  title: string;
  description: string;
  actionLabel: string;
}) {
  return (
    <Card
      variant="raised"
      className="hoi-card-link flex flex-col rounded-3xl p-6 hover:border-brand-300 focus-within:border-brand-500 sm:p-7"
    >
      <h2 className="text-xl font-extrabold text-ink">{title}</h2>
      <p className="mt-2 text-sm leading-relaxed text-ink-subtle">{description}</p>
      <div className="mt-auto pt-6">
        <Link
          href="/dashboard/new/setup?mode=static"
          className={buttonClassName({ variant: "primary", size: "lg", className: "w-full" })}
        >
          {actionLabel}
        </Link>
      </div>
    </Card>
  );
}
