/**
 * 메인 페이지 서비스 소개 섹션: 보안 점검이 어떤 순서로 진행되는지 알려 준다.
 *
 * - 서버 컴포넌트다(클라이언트 JS 없음). 펼침 영역은 네이티브 <details>(Disclosure)를 쓴다.
 * - 규칙·출처 수치는 @/lib/rules/sources 에서 RULES를 읽어 계산하므로, 규칙을 바꾸면 소개글 숫자도 함께 바뀐다.
 * - 아이콘은 @/components/icons, 스타일은 프로젝트 Tailwind 토큰(globals.css)을 쓴다. 새 패키지 없음.
 * - 단계 설명은 실제 동작과 맞춘다(오탐 판정은 따로 모아 표시, 수정은 요청할 때만, 원본은 그대로).
 */
import type { ComponentType, ReactNode } from "react";
import Link from "next/link";
import {
  ArchiveIcon,
  BookCheckIcon,
  BookOpenIcon,
  ChatIcon,
  ClockIcon,
  ExternalLinkIcon,
  InfoIcon,
  RefreshIcon,
  ShieldIcon,
  SparkleIcon,
  TagIcon,
  WrenchIcon,
  type IconProps,
} from "@/components/icons";
import { Disclosure, SeverityBadge, buttonClassName } from "@/components/ui";
import { RULES } from "@/lib/rules/definitions";
import {
  CITED_SOURCES,
  KIND_LABEL_KO,
  REFERENCE_SOURCES,
  frameworkStats,
  introStats,
  standardLabel,
  standardUrl,
} from "@/lib/rules/sources";

type Icon = ComponentType<IconProps>;

export interface ServiceIntroProps {
  /** "점검 시작하기" 버튼이 가는 경로 */
  startHref?: string;
  className?: string;
}

// ─────────────────────────────────────────────────────────────
// 작은 부품
// ─────────────────────────────────────────────────────────────

function ExtLink({ href, className = "", children }: { href: string; className?: string; children: ReactNode }) {
  return (
    <a
      className={`inline-flex items-center gap-1 font-bold text-brand-800 underline-offset-4 hover:underline ${className}`}
      href={href}
      target="_blank"
      rel="noopener noreferrer"
    >
      {children}
      <ExternalLinkIcon className="h-3.5 w-3.5 shrink-0" />
      <span className="sr-only">(새 창에서 열려요)</span>
    </a>
  );
}

// ─────────────────────────────────────────────────────────────
// 2단계: 근거 출처 패널
// ─────────────────────────────────────────────────────────────

const TRUST_POINTS: Array<{ icon: Icon; title: string; body: string }> = [
  {
    icon: BookOpenIcon,
    title: "누구나 볼 수 있는 기준이에요",
    body: "사용한 기준은 모두 공개된 문서예요. 아래 링크에서 직접 확인해 보실 수 있어요.",
  },
  {
    icon: TagIcon,
    title: "규칙마다 근거가 붙어요",
    body: "점검 규칙에는 CWE-639 같은 근거 번호가 연결돼 있어요. 왜 문제로 봤는지 원문을 따라가며 확인할 수 있어요.",
  },
  {
    icon: ClockIcon,
    title: "기준의 버전을 함께 적어요",
    body: "보안 기준은 시간이 지나며 바뀌어요. 어느 시점의 기준을 썼는지 버전을 남겨 둬요.",
  },
];

function SourcesPanel() {
  const stats = frameworkStats();
  return (
    <div className="space-y-5">
      <div>
        <h5 className="text-base font-extrabold text-ink">왜 믿고 맡길 수 있나요?</h5>
        <ul className="mt-3 grid gap-3 md:grid-cols-3">
          {TRUST_POINTS.map(({ icon: TrustIcon, title, body }) => (
            <li key={title} className="flex gap-3 rounded-2xl border-2 border-line bg-surface p-4">
              <span aria-hidden="true" className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-sun-soft text-brand-900">
                <TrustIcon className="h-5 w-5" />
              </span>
              <div className="min-w-0">
                <strong className="block text-sm font-extrabold text-ink">{title}</strong>
                <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">{body}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h5 className="text-base font-extrabold text-ink">규칙이 근거로 삼는 공개 기준</h5>
        <ul className="mt-3 grid gap-3 sm:grid-cols-2">
          {CITED_SOURCES.map((s) => {
            const st = s.framework ? stats.get(s.framework) : undefined;
            return (
              <li key={s.id} className="min-w-0 rounded-2xl border-2 border-line bg-surface p-4">
                <p className="text-[13px] font-semibold text-ink-muted">
                  {s.publisher}
                  {s.version ? ` · ${s.version}` : ""}
                </p>
                <p className="mt-1 break-words text-sm">
                  {s.url ? <ExtLink href={s.url}>{s.name}</ExtLink> : <span className="font-bold text-ink">{s.name}</span>}
                </p>
                {s.whatKo && <p className="mt-2 break-keep text-sm leading-relaxed text-ink">{s.whatKo}</p>}
                <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">{s.usedForKo}</p>
                {st ? (
                  <p className="mt-3 inline-flex rounded-full bg-primary-soft px-3 py-0.5 text-[13px] font-bold text-brand-900">
                    점검 항목 {st.items}개에서 인용 · 근거 번호 {st.distinctIds}종
                  </p>
                ) : null}
              </li>
            );
          })}
        </ul>
      </div>

      <Disclosure summary={`점검 기준을 세울 때 함께 참고한 문서 ${REFERENCE_SOURCES.length}개 보기`}>
        <ul className="space-y-3">
          {REFERENCE_SOURCES.map((s) => (
            <li key={s.id} className="rounded-2xl border-2 border-line bg-surface p-4">
              <p className="text-sm">
                {s.url ? <ExtLink href={s.url}>{s.name}</ExtLink> : <span className="font-bold text-ink">{s.name}</span>}
              </p>
              <p className="mt-1 text-[13px] font-semibold text-ink-muted">
                {KIND_LABEL_KO[s.kind]} · {s.publisher}
                {s.version ? ` · ${s.version}` : ""}
              </p>
              <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">{s.usedForKo}</p>
            </li>
          ))}
        </ul>
      </Disclosure>

      <p className="break-keep text-[13px] leading-relaxed text-ink-muted">
        위 기관들이 이 서비스를 보증하거나 제휴한 것은 아니에요. 공개된 기준을 저희가 해석해 규칙으로 옮긴 것이라,
        해석이 원문과 다를 수 있어요. CWE™, CAPEC™, ATT&amp;CK®, ATLAS™는 MITRE의 상표예요.
      </p>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 4단계: 결과 예시
// ─────────────────────────────────────────────────────────────

function SampleFinding() {
  // 예시는 실제 규칙(WEB-014)의 근거를 그대로 써서, 규칙이 바뀌어도 어긋나지 않게 한다.
  const rule = RULES.find((r) => r.id === "WEB-014");
  const refs = (rule?.standards ?? []).filter((s) => s.framework !== "MITRE_ATTACK");

  const rows: Array<{ label: string; body: ReactNode }> = [
    {
      label: "어디가",
      body: (
        <>
          <code className="rounded-lg bg-surface-warm px-1.5 py-0.5 font-mono text-[13px] text-ink">app/api/orders/[id]/route.ts</code>{" "}
          12번째 줄 근처
        </>
      ),
    },
    {
      label: "어떻게",
      body: "주문 번호(id)만으로 데이터베이스에서 주문을 꺼내고, 요청한 사람이 그 주문의 주인인지는 확인하지 않아요.",
    },
    {
      label: "왜 문제인가요",
      body: "주소 끝의 번호만 바꿔도 다른 사람의 주문 정보를 볼 수 있어요. 개인정보 유출로 이어질 수 있어요.",
    },
    {
      label: "이렇게 고쳐요",
      body: "주문을 조회할 때 “로그인한 사용자의 주문인지”를 함께 확인하고, 아니라면 접근을 거부해 주세요.",
    },
  ];

  return (
    <figure aria-label="점검 결과 예시" className="overflow-hidden rounded-3xl border-2 border-line bg-surface shadow-warm">
      <figcaption className="flex flex-wrap items-center gap-2 border-b-2 border-line bg-surface-warm px-4 py-3 sm:px-5">
        <span className="inline-flex rounded-full bg-ink px-2.5 py-0.5 text-[13px] font-bold text-surface">예시</span>
        <strong className="text-base font-extrabold text-ink">다른 사람의 데이터에 접근할 수 있어요</strong>
        {rule ? <SeverityBadge severity={rule.severity} /> : null}
        {rule ? <span className="w-full text-[13px] text-ink-muted">{rule.titleKo}</span> : null}
      </figcaption>

      <dl className="divide-y-2 divide-line">
        {rows.map((row) => (
          <div key={row.label} className="grid gap-1 px-4 py-3 sm:grid-cols-[8rem_1fr] sm:gap-4 sm:px-5">
            <dt className="text-sm font-extrabold text-brand-800">{row.label}</dt>
            <dd className="break-keep text-sm leading-relaxed text-ink">{row.body}</dd>
          </div>
        ))}
      </dl>

      {refs.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 border-t-2 border-line px-4 py-3 sm:px-5">
          <span className="text-[13px] font-bold text-ink-subtle">근거</span>
          <ul className="flex flex-wrap gap-2">
            {refs.map((r) => {
              const href = standardUrl(r);
              const label = standardLabel(r);
              return (
                <li key={`${r.framework}-${r.id}`}>
                  {href ? (
                    <ExtLink
                      href={href}
                      className="min-h-7 rounded-full border-2 border-line bg-surface-warm px-3 py-0.5 text-[13px] no-underline hover:border-brand-300"
                    >
                      {label}
                    </ExtLink>
                  ) : (
                    <span className="inline-flex min-h-7 items-center rounded-full border-2 border-line bg-surface-warm px-3 py-0.5 text-[13px] font-bold text-ink">
                      {label}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      <p className="border-t-2 border-dashed border-line px-4 py-2.5 text-[13px] text-ink-muted sm:px-5">
        예시 화면이에요. 실제 결과의 문구와 내용은 서비스에 따라 달라요.
      </p>
    </figure>
  );
}

// ─────────────────────────────────────────────────────────────
// 단계 정의
// ─────────────────────────────────────────────────────────────

interface Step {
  icon: Icon;
  title: string;
  body: string;
  extra?: "sources" | "sample";
}

const STEPS: Step[] = [
  {
    icon: ArchiveIcon,
    title: "올린 파일에서 설정과 코드를 살펴봐요",
    body: "프로젝트를 zip 파일로 올리거나 코드를 붙여 넣으면, 소스 코드와 설정 파일(환경변수 파일, 프레임워크 설정, 사용 중인 라이브러리 목록 등)을 읽어서 어떤 구조로 만들어졌는지 먼저 파악해요. 이 단계에서는 올린 코드를 실행하지 않고, 파일을 읽기만 해요.",
  },
  {
    icon: BookCheckIcon,
    title: "공개된 보안 기준으로 만든 규칙으로 1차 점검해요",
    body: "OWASP, MITRE처럼 신뢰받는 기관이 공개한 보안 가이드라인을 바탕으로 만든 점검 규칙을 코드와 설정에 적용해요. 저희가 임의로 정한 기준이 아니에요. 어떤 기준에 근거했는지 출처를 함께 남겨 둬요. 아래를 펼치면 기준 목록과 원문 링크를 볼 수 있어요.",
    extra: "sources",
  },
  {
    icon: SparkleIcon,
    title: "AI가 한 번 더 살펴봐요",
    body: "규칙만으로는 잡기 어려운 부분, 예를 들어 “이 API가 로그인한 본인의 데이터만 돌려주는지” 같은 코드의 흐름과 맥락은 연결된 AI가 2차로 읽어보고 점검해요. AI가 규칙 결과를 지우지는 않아요. 오탐으로 보이는 항목은 근거와 함께 따로 모아 보여드리고, 기록은 그대로 남겨요. AI도 틀릴 수 있기 때문이에요.",
  },
  {
    icon: ChatIcon,
    title: "어디가, 어떻게, 왜 잘못됐는지 쉽게 알려드려요",
    body: "찾아낸 문제는 어려운 보안 용어 대신, 어느 파일의 어디가 문제인지, 어떤 식으로 잘못됐는지, 그대로 두면 어떤 일이 생길 수 있는지를 차근차근 풀어서 정리해요. 아래를 펼치면 결과 화면 예시를 볼 수 있어요.",
    extra: "sample",
  },
  {
    icon: WrenchIcon,
    title: "원하시면 취약점을 고쳐 드려요",
    body: "오탐으로 판정된 항목을 뺀 나머지를 대상으로, 사용자가 요청하실 때만 수정안을 만들어요. 원본 코드는 그대로 두고, 고친 파일을 따로 내려받을 수 있게 드려요.",
  },
  {
    icon: ShieldIcon,
    title: "고친 코드를 다시 검토해요",
    body: "수정본 코드에 같은 규칙 검사를 다시 돌려서 원래 문제가 정말 막혔는지 확인해요. 규칙으로 확인하기 어려운 항목은 AI가 함께 살펴보고, 가능한 항목은 격리된 환경에서 같은 방식으로 다시 시도해 봐요.",
  },
  {
    icon: RefreshIcon,
    title: "같은 프로젝트에 다시 올려 다시 점검해요",
    body: "직접 코드를 고쳤거나 기능을 추가했다면, 프로젝트 안에서 코드를 다시 올려 언제든 재점검할 수 있어요. 점검과 수정을 반복하면서 조금씩 더 튼튼하게 만들어 가요.",
  },
];

// ─────────────────────────────────────────────────────────────
// 본문
// ─────────────────────────────────────────────────────────────

export function ServiceIntro({ startHref = "/dashboard", className = "" }: ServiceIntroProps) {
  const stats = introStats();
  const statItems = [
    { value: stats.items, label: "점검 항목" },
    { value: stats.frameworks, label: "근거 삼은 공개 기준" },
    { value: stats.cweIds, label: "연결된 결함 유형(CWE)" },
  ];

  return (
    <section
      id="service-intro"
      aria-labelledby="intro-title"
      className={`border-y-2 border-line bg-surface-warm px-4 py-16 sm:px-6 ${className}`}
    >
      <div className="mx-auto max-w-4xl">
        {/* 서비스 개념 */}
        <header className="text-center">
          <p className="inline-flex items-center gap-2 rounded-full border-2 border-brand-300 bg-surface px-4 py-1 text-sm font-bold text-brand-900 shadow-[0_3px_0_var(--border-strong)]">
            <ShieldIcon className="h-4 w-4 text-brand-800" />
            배포 전 보안 점검
          </p>
          <h2 id="intro-title" className="mt-5 break-keep text-2xl font-extrabold leading-snug tracking-tight text-ink sm:text-4xl">
            바이브코딩한 서비스,
            <br />
            공개하기 전에 한 번만 더 확인해요
          </h2>
          <p className="mx-auto mt-4 max-w-2xl break-keep text-base leading-relaxed text-ink-subtle sm:text-lg">
            AI와 함께 빠르게 만든 결과물은 잘 돌아가는 것처럼 보여도, 눈에 띄지 않는 곳에 보안 구멍이 남아 있을 수
            있어요. 호이는 서비스를 공유하거나 배포하기 전에, 사용해 줄 분들의 안전을 위해 코드와 설정을 미리 살펴보고
            무엇을 어떻게 고치면 좋을지 알려드려요.
          </p>
          <div className="mt-7 flex flex-col items-stretch justify-center gap-3 sm:flex-row sm:items-center">
            <Link href={startHref} className={buttonClassName({ variant: "primary", size: "lg" })}>
              점검 시작하기
            </Link>
            <a href="#how-it-works" className={buttonClassName({ variant: "secondary", size: "lg" })}>
              어떻게 동작하나요?
            </a>
          </div>

          <ul aria-label="서비스 규모" className="mx-auto mt-10 grid max-w-2xl grid-cols-3 gap-3">
            {statItems.map((s) => (
              <li key={s.label} className="hoi-card-3d flex flex-col items-center px-2 py-4 sm:py-5">
                <span className="text-2xl font-extrabold tabular-nums text-ink sm:text-4xl">{s.value}</span>
                <span className="mt-1 break-keep text-[13px] font-bold text-ink-subtle sm:text-sm">{s.label}</span>
              </li>
            ))}
          </ul>
        </header>

        {/* 7단계 */}
        <div id="how-it-works" className="mt-16 scroll-mt-24">
          <h3 className="text-center text-2xl font-extrabold tracking-tight text-ink sm:text-3xl">이렇게 점검해요</h3>
          <p className="mt-2 text-center text-ink-subtle">
            파일을 올리는 것부터 다시 확인하는 것까지, 일곱 단계로 진행돼요.
          </p>

          <ol className="mt-10 space-y-6">
            {STEPS.map(({ icon: StepIcon, title, body, extra }, i) => {
              const isLast = i === STEPS.length - 1;
              return (
                <li key={title} className="relative flex gap-4 sm:gap-5">
                  {/* 왼쪽 길: 아이콘 배지 + 다음 단계까지 이어지는 점선 */}
                  <div aria-hidden="true" className="relative flex w-12 shrink-0 flex-col items-center sm:w-14">
                    <span className="relative z-10 flex h-12 w-12 items-center justify-center rounded-2xl border-2 border-brand-300 bg-sun-soft text-brand-900 shadow-[0_4px_0_var(--border-strong)] sm:h-14 sm:w-14">
                      <StepIcon className="h-6 w-6 sm:h-7 sm:w-7" />
                    </span>
                    {!isLast && (
                      <span className="absolute -bottom-6 top-14 w-0 border-l-[3px] border-dashed border-brand-300 sm:top-16" />
                    )}
                  </div>
                  <div className="hoi-card-3d min-w-0 flex-1 p-5 sm:p-6">
                    <p className="text-sm font-extrabold text-brand-800">{i + 1}단계</p>
                    <h4 className="mt-1 break-keep text-lg font-extrabold text-ink sm:text-xl">{title}</h4>
                    <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{body}</p>
                    {/* 세부 내용은 기본으로 접어 두고, 필요할 때 펼쳐 본다(네이티브 details: Enter/Space로 여닫기) */}
                    {extra === "sources" ? (
                      <Disclosure summary="근거로 삼은 공개 기준 자세히 보기" className="mt-5">
                        <SourcesPanel />
                      </Disclosure>
                    ) : null}
                    {extra === "sample" ? (
                      <Disclosure summary="결과 화면 예시 보기" className="mt-5">
                        <SampleFinding />
                      </Disclosure>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        {/* 유의사항 */}
        <aside
          aria-labelledby="notice-title"
          className="mt-14 flex gap-4 rounded-3xl border-2 border-[#f0d9a6] bg-warning-soft p-5 sm:p-6"
        >
          <InfoIcon className="mt-0.5 h-6 w-6 shrink-0 text-warning" />
          <div className="min-w-0 space-y-2 break-keep leading-relaxed text-ink">
            <h3 id="notice-title" className="text-lg font-extrabold text-ink">
              함께 알아두시면 좋아요
            </h3>
            <p>
              호이는 배포 전에 빠르게 살펴보는 ‘안전 점검표’ 같은 도구예요. 서비스에 존재하는 모든 취약점과 보안 위험을
              다 찾아내지는 못하고, 점검을 통과했다고 해서 위험이 하나도 없다는 뜻도 아니에요. 또 실제로는 문제가 아닌데
              문제로 표시되는 경우(오탐)도 있을 수 있어요.
            </p>
            <p>
              결과는 ‘함께 살펴볼 후보’로 봐주세요. 결제나 개인정보처럼 민감한 정보를 다루는 서비스라면, 전문가의 점검도
              함께 받아보시길 권해요.
            </p>
          </div>
        </aside>

        <div className="mt-10 flex flex-col items-center gap-4 rounded-3xl border-2 border-brand-300 bg-sun-soft p-6 text-center sm:flex-row sm:justify-between sm:text-left">
          <p className="break-keep text-lg font-extrabold text-ink">배포 전에, 한 번만 더 확인해 보세요.</p>
          <Link href={startHref} className={buttonClassName({ variant: "primary", size: "lg", className: "w-full sm:w-auto" })}>
            점검 시작하기
          </Link>
        </div>
      </div>
    </section>
  );
}
