import Link from "next/link";
import { PageHeader } from "@/components/PageHeader";
import { Badge, Card, Disclosure, buttonClassName } from "@/components/ui";

/**
 * 프로젝트 등록 1단계: 어떤 자료로 점검할지 고른다.
 * 기본 노출은 코드/파일과 공개 웹사이트 두 가지. 격리 서버 심층 점검은
 * "추가 점검 옵션" 안에만 노출해 초보자에게 실행 위험을 먼저 보여주지 않는다.
 * 내부적으로는 기존 static/safe_active/isolated_active 모드를 그대로 쓴다.
 */
export default function ChooseScanModePage() {
  return (
    <>
      <PageHeader
        title="어떤 자료를 확인할까요?"
        subtitle="가지고 있는 자료에 맞는 방법을 골라 주세요."
        backHref="/dashboard"
        backLabel="내 프로젝트"
      />
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <ModeCard
            mode="static"
            title="코드와 파일 확인"
            description="프로젝트 파일이나 코드를 읽어 보안 문제를 찾아요."
            actionLabel="코드와 파일로 시작하기"
            recommended
          />
          <ModeCard
            mode="safe_active"
            title="공개한 웹사이트도 확인"
            description="내 웹사이트에 접속해 공개된 설정과 응답을 확인해요."
            note="내 사이트라는 확인이 필요해요. 데이터를 바꾸는 검사는 진행하지 않아요."
            actionLabel="웹사이트도 함께 확인하기"
          />
        </div>

        <Disclosure summary="추가 점검 옵션 · 테스트 환경에서 더 자세히 점검하기" className="mt-6">
          <div className="rounded-xl border border-amber-200 bg-warning-soft p-4">
            <p className="font-semibold text-ink">테스트 사이트에서 추가 확인</p>
            <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
              테스트 계정 두 개로 다른 사람의 정보에 접근할 수 있는지 확인해요.
            </p>
            <p className="mt-3 rounded-lg bg-white p-3 text-sm font-semibold text-danger">
              실제 서비스와 분리된 테스트 사이트에서만 사용하세요. 점검 중 데이터가 바뀔 수 있어요.
            </p>
            <Link
              href="/dashboard/new/setup?mode=isolated_active"
              className={buttonClassName({ variant: "secondary", size: "md", className: "mt-4" })}
            >
              테스트 사이트로 시작하기
            </Link>
          </div>
        </Disclosure>

        <p className="mt-6 text-sm leading-relaxed text-ink-muted">
          어떤 방법을 골라도 자동 점검만으로 모든 위험을 찾을 수는 없어요. 선택한 범위를 넘는 검사는
          실행하지 않고 확인하지 못한 항목으로 따로 알려드려요.
        </p>
      </div>
    </>
  );
}

function ModeCard({
  mode,
  title,
  description,
  note,
  actionLabel,
  recommended = false,
}: {
  mode: "static" | "safe_active";
  title: string;
  description: string;
  note?: string;
  actionLabel: string;
  recommended?: boolean;
}) {
  return (
    <Card variant="default" className="flex flex-col p-6">
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-lg font-bold text-ink">{title}</h2>
        {recommended && <Badge tone="primary">추천</Badge>}
      </div>
      <p className="mt-2 text-sm leading-relaxed text-ink-subtle">{description}</p>
      {note && <p className="mt-3 text-sm leading-relaxed text-ink-muted">{note}</p>}
      <div className="mt-auto pt-6">
        <Link
          href={`/dashboard/new/setup?mode=${mode}`}
          className={buttonClassName({ size: "lg", className: "w-full" })}
        >
          {actionLabel}
        </Link>
      </div>
    </Card>
  );
}
