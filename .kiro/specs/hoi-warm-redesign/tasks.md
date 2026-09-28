# Implementation Plan: hoi-warm-redesign

## Overview

따뜻한 호이 시각 언어로 UI를 되돌리는 작업을 TypeScript(Next.js 14 App Router + Tailwind)로 구현한다. 순서는 도구 설정 → 순수 표현 모듈(`tokens.ts`, `presentation.ts`) → CSS 토큰 → 공용 컴포넌트(`ui.tsx`, 호이) → 내비게이션 → 화면 → 문구 검사와 최종 확인이다. 각 화면은 앞 단계에서 만든 순수 함수와 공용 컴포넌트를 그대로 가져다 쓰므로 고립된 코드가 남지 않는다.

공통 제약:
- Protected_Surface(`src/app/api/**`, `src/lib/domain/types.ts`, `src/lib/domain/scanMode.ts`, `src/lib/auth-core.ts`, `src/lib/authActions.ts`)는 수정하지 않는다.
- `package.json`의 `dependencies`는 바꾸지 않는다. devDependencies만 정확한 버전으로 추가한다.
- npm은 `& "$env:ProgramFiles\nodejs\npm.cmd"` 형태로 호출한다(`npm.ps1` 차단). 테스트는 `vitest --run`으로 한 번만 실행한다.
- 기존 fetch 경로·HTTP 메서드·요청 본문 필드는 그대로 둔다.

## Tasks

- [x] 1. 테스트·린트 도구 설정
  - [x] 1.1 devDependencies와 설정 파일 추가
    - `package.json` devDependencies에 `vitest@2.1.9`, `fast-check@3.23.2`, `eslint@8.57.0`, `eslint-config-next@14.2.35`를 정확한 버전으로 추가하고 `& "$env:ProgramFiles\nodejs\npm.cmd" install` 실행
    - scripts에 `"test": "vitest --run"` 추가. `dependencies`는 변경하지 않음
    - `vitest.config.mts` 생성(esbuild `jsx: "automatic"`, `@` → `./src` 별칭, `environment: "node"`, `include: ["src/**/*.test.{ts,tsx}"]`)
    - `.eslintrc.json` 생성(`{ "extends": "next/core-web-vitals" }`)
    - `npm run lint`가 대화형 설정 없이 실행되는지 확인
    - _Requirements: 12.7, 12.8_

- [x] 2. 디자인 토큰 순수 모듈
  - [x] 2.1 `src/lib/ui/tokens.ts` 구현
    - 설계 1-1 표의 최종값(기준 25개 + `--primary-depth`, `--primary-text`, `--border-input`, `--code`, `--code-text`, `--code-muted`, `--code-focus`)으로 `WARM_TOKENS` 정의
    - WCAG 2.1 상대 휘도 공식으로 `relativeLuminance`, `contrastRatio` 구현
    - 설계 1-3에 나열된 조합으로 `CONTRAST_PAIRS`(`fg`, `bg`, `min`, `use`) 정의
    - _Requirements: 1.1, 1.2, 1.8, 1.9, 1.10, 2.2, 2.7_

  - [ ]* 2.2 Property 1 속성 테스트 작성 (`src/lib/ui/__tests__/tokens.property.test.ts`)
    - **Property 1: 대비 계산의 기본 성질**
    - hex 생성기 `fc.integer({ min: 0, max: 0xffffff })`, 대칭성·범위 1~21·자기 대비 1 확인
    - **Validates: Requirements 1.2**

  - [ ]* 2.3 Property 2 속성 테스트 작성 (`src/lib/ui/__tests__/contrast-pairs.property.test.ts`)
    - **Property 2: 선언된 모든 텍스트·배경 조합이 최소 대비를 충족**
    - **Validates: Requirements 1.2, 1.8, 1.9, 1.10, 2.2, 2.7**

- [x] 3. 표현 로직 모듈 `src/lib/ui/presentation.ts`
  - [x] 3.1 라벨·정렬·요약·다음 행동·금지 표현 함수 구현
    - `HoiMood` 타입 정의(Hoi.tsx가 re-export), 도메인 타입은 `import type`으로만 참조
    - `SEV_LABEL`, `SEV_EXPERT_LABEL`, `STATUS_LABEL`, `TEST_STATUS_LABEL`, `UNKNOWN_STATUS_LABEL`을 요구사항 4 문구 그대로 정의
    - `severityLabel`, `statusLabel`, `testStatusLabel`, `severityDisplay`(`hasOwnProperty.call`로 프로토타입 키 방어, 아이콘 octagon/triangle/diamond/circle, 대체 `dot`)
    - `SEVERITY_RANK`, `sortBySeverity`(안정 정렬, 새 배열), `countSeverities`
    - `NO_FINDINGS_MESSAGE`, `LIMIT_NOTICE`, `summarizeResult`, `summarizeFinding`(설계 4-1 규칙, 80자 이하)
    - `primaryActionForFinding`, `primaryActionForScan`(설계 4-1 첫 일치 규칙)
    - `FORBIDDEN_GUARANTEE_PATTERNS`, `containsGuaranteePhrase`
    - _Requirements: 3.6, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 8.1, 8.2, 8.3, 8.4, 8.7, 12.4, 12.5_

  - [ ]* 3.2 Property 6 속성 테스트 작성 (`src/lib/ui/__tests__/labels.property.test.ts`)
    - **Property 6: 라벨 조회는 모든 입력에 대해 정의됨**
    - enum 값, 임의 문자열, `"toString"`·`"__proto__"`, 숫자, `undefined` 조합
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.5, 4.8**

  - [ ]* 3.3 Property 14 속성 테스트 작성 (`src/lib/ui/__tests__/summary.property.test.ts`)
    - **Property 14: 결과 요약 규칙**
    - **Validates: Requirements 8.1, 8.2, 8.3, 12.5**

  - [ ]* 3.4 Property 15 속성 테스트 작성 (`src/lib/ui/__tests__/sort.property.test.ts`)
    - **Property 15: 심각도 정렬은 안정적인 순열**
    - **Validates: Requirements 8.2**

  - [ ]* 3.5 Property 16 속성 테스트 작성 (`src/lib/ui/__tests__/finding-action.property.test.ts`)
    - **Property 16: 발견 상세의 Mood와 단일 다음 행동**
    - **Validates: Requirements 8.4, 8.7**

  - [ ]* 3.6 Property 17 속성 테스트 작성 (`src/lib/ui/__tests__/scan-action.property.test.ts`)
    - **Property 17: 스캔 결과의 단일 다음 행동**
    - **Validates: Requirements 8.7**

  - [x] 3.7 입력 검증·폼·탭·대시보드 함수 구현
    - `MAX_SOURCE_CHARS`, `formatCharCount`(`toLocaleString("en-US")`), `isOverSourceLimit`, `isQuickCheckSubmitDisabled`, `validateQuickCheckSource`(전각 공백 포함 공백 판정)
    - `QuickCheckErrorKind`, `classifyQuickCheckError`, `QUICK_CHECK_ERROR_COPY`(설계 Error Handling 표 문구, 다음 행동 문장 포함)
    - `MAX_ZIP_BYTES`, `validateProjectDraft`(이름 → ZIP 크기 순), `projectEndpoint`
    - `nextTabIndex`(ArrowLeft/ArrowRight/Home/End, `n ≤ 0`이면 0)
    - `DashboardRowInput`, `DashboardMetrics`, `computeDashboardMetrics`
    - _Requirements: 6.2, 6.3, 6.5, 6.6, 6.7, 6.8, 7.4, 7.9, 7.10, 7.11, 9.6, 9.7, 9.8_

  - [ ]* 3.8 Property 8 속성 테스트 작성 (`src/lib/ui/__tests__/char-count.property.test.ts`)
    - **Property 8: 글자 수 표시 형식 왕복**
    - **Validates: Requirements 6.2**

  - [ ]* 3.9 Property 9 속성 테스트 작성 (`src/lib/ui/__tests__/source-limit.property.test.ts`)
    - **Property 9: 글자 수 초과와 제출 비활성화의 동치**
    - 길이 99,999~100,002 경계 포함
    - **Validates: Requirements 6.3, 6.7, 6.8**

  - [ ]* 3.10 Property 10 속성 테스트 작성 (`src/lib/ui/__tests__/empty-source.property.test.ts`)
    - **Property 10: 빈 코드 제출 차단**
    - **Validates: Requirements 6.5**

  - [ ]* 3.11 Property 11 속성 테스트 작성 (`src/lib/ui/__tests__/quick-check-error.property.test.ts`)
    - **Property 11: 빠른 점검 오류 분류**
    - **Validates: Requirements 6.6**

  - [ ]* 3.12 Property 12 속성 테스트 작성 (`src/lib/ui/__tests__/tab-index.property.test.ts`)
    - **Property 12: 탭 이동 인덱스**
    - **Validates: Requirements 7.4**

  - [ ]* 3.13 Property 13 속성 테스트 작성 (`src/lib/ui/__tests__/project-draft.property.test.ts`)
    - **Property 13: 프로젝트 입력 검증**
    - ZIP 크기 8,388,607~8,388,609 경계 포함
    - **Validates: Requirements 7.9, 7.10**

  - [ ]* 3.14 Property 20 속성 테스트 작성 (`src/lib/ui/__tests__/dashboard-metrics.property.test.ts`)
    - **Property 20: 대시보드 지표는 데이터에서만 계산**
    - **Validates: Requirements 9.6, 9.7, 9.8**

  - [ ]* 3.15 Property 22 속성 테스트 작성 (`src/lib/ui/__tests__/guarantee-phrase.property.test.ts`)
    - **Property 22: 절대 보장 표현 차단**
    - **Validates: Requirements 12.4**

- [x] 4. Checkpoint - 순수 모듈 확인
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. 전역 CSS 토큰과 Tailwind 확장
  - [x] 5.1 `src/app/globals.css` 교체
    - `:root`에 `WARM_TOKENS`와 같은 값 정의, 조정한 토큰은 `기준값 → 조정값 (측정 대비)` 주석 기록
    - `--shadow-sm`, `--shadow-lg`(갈색·주황 rgba만)
    - `.hoi-button-3d`(`.is-primary` 깊이 3px, hover -2px/깊이 4px, active +2px/깊이 1px, 150ms, disabled opacity .5), `.hoi-card-3d`, `.hoi-page-decor`(opacity .3, `pointer-events: none`, `z-index: -1`)
    - `:focus-visible` 3px `--focus` + `outline-offset: 2px`, `.bg-code :focus-visible`는 `--code-focus`
    - `hoi-enter`(220ms 1회), `hoi-search`(1.6s 반복, 3px·6°) keyframes, `prefers-reduced-motion` 블록
    - _Requirements: 1.1, 1.2, 1.4, 1.6, 1.8, 1.10, 2.1, 2.3, 2.4, 2.5, 2.6, 2.8, 2.9, 2.10, 2.11, 2.13, 11.3_

  - [x] 5.2 `tailwind.config.ts` 수정
    - `brand` 10단계(설계 1-2 값, 500 = primary, 600 = primary-hover)
    - `boxShadow`의 `warm`, `warm-lg`, `press`, `sev` 장식 색, 표면·텍스트·상태 색 유틸리티(`bg-surface`, `text-ink` 등 ui.tsx가 쓰는 이름)
    - _Requirements: 1.3, 1.4, 1.5_

  - [ ]* 5.3 토큰 동기화 단위 테스트 작성 (`src/lib/ui/__tests__/tokens-sync.test.ts`)
    - `globals.css` `:root` 값 = `WARM_TOKENS`, brand 500/600 일치, brand 명도 단조 감소·색상각 15°~40°, 그림자 rgba가 갈색·주황 계열
    - `.hoi-button-3d` 이동 값·전환 시간, reduced-motion 블록, `.hoi-page-decor` opacity ≤ 0.35, `:focus-visible` 3px
    - _Requirements: 1.1, 1.3, 1.4, 1.6, 2.3, 2.4, 2.5, 11.3_

  - [x] 5.4 루트 `src/app/layout.tsx`에 배경 장식 추가
    - `<body>` 첫 자식으로 `<div className="hoi-page-decor" aria-hidden="true" />` 하나만 배치
    - _Requirements: 1.6, 1.7_

- [x] 6. 공용 UI 컴포넌트
  - [x] 6.1 `src/components/ui.tsx` 수정
    - 기존 export 이름과 prop 시그니처 유지
    - 버튼 변형(primary 주황 + `text-ink` + `.hoi-button-3d is-primary`, secondary, ghost, danger)과 크기(`min-h-11`/`12`/`14`, `rounded-2xl`)
    - 카드 변형(default/warm `rounded-3xl`, raised `.hoi-card-3d`, flat `rounded-2xl`, danger)
    - 라벨 맵을 `presentation.ts`에서 re-export, `SeverityBadge`에 `SeverityIcon`(aria-hidden) + 라벨, `StatusBadge`·`TestStatusBadge`는 조회 함수 사용
    - `TechnicalDetails` 기본 summary "기술 정보 보기", `Disclosure` 네이티브 `<details>` 유지
    - `FriendlyError`(`role="alert"`), `MetricCard`(raised), `CodeEvidence`(`bg-code`, 전달 문자열 그대로 출력)
    - critical 항목에 애니메이션 클래스를 붙이지 않음
    - _Requirements: 1.5, 1.8, 2.1, 2.2, 2.5, 2.6, 2.7, 2.8, 2.12, 2.13, 4.1, 4.2, 4.3, 4.4, 4.7, 4.8, 8.5, 8.10, 11.4, 11.5, 11.6_

  - [ ]* 6.2 Property 7 속성 테스트 작성 (`src/components/__tests__/severity-badge.property.test.tsx`)
    - **Property 7: 심각도 배지는 색 없이도 구분됨**
    - **Validates: Requirements 4.4, 2.12**

  - [ ]* 6.3 Property 18 속성 테스트 작성 (`src/components/__tests__/code-evidence.property.test.tsx`)
    - **Property 18: 근거 표시는 저장된 문자열 그대로**
    - **Validates: Requirements 8.10**

  - [ ]* 6.4 공용 컴포넌트 단위 테스트 작성 (`src/components/__tests__/ui.test.tsx`)
    - `Button` disabled 마크업, 변형별 클래스, `Card` 반경 클래스, `TechnicalDetails` 기본 제목
    - `SeverityStrip`에 `counts`가 없으면 안내 문구가 나오고 숫자 0이 나오지 않음
    - _Requirements: 1.5, 2.6, 2.7, 8.5, 8.12_

  - [x] 6.5 `src/components/SeverityStrip.tsx` 수정
    - `counts?: SeverityCounts | null`, 없으면 "발견 수를 불러오지 못했어요"
    - `SEV_LABEL`과 `SeverityIcon` 사용, 받은 정수만 표시, 점수·백분율 없음
    - _Requirements: 4.1, 8.11, 8.12, 12.3_

  - [ ]* 6.6 Property 19 속성 테스트 작성 (`src/components/__tests__/severity-strip.property.test.tsx`)
    - **Property 19: 심각도 요약 막대는 받은 수만 표시**
    - **Validates: Requirements 8.11**

- [x] 7. 호이 마스코트 다시 그리기
  - [x] 7.1 `src/components/mascot/HoiImage.tsx` 생성
    - `"use client"`, `useState(failed)` + `<img onError>`, 실패 시 `fallback` 렌더링
    - 크기 클래스·`alt`(decorative면 `""`)를 SVG와 동일하게 적용
    - _Requirements: 3.4, 3.5_

  - [x] 7.2 `src/components/mascot/Hoi.tsx` 재작성
    - props API(`mood`, `size`, `title`, `decorative`, `className`) 유지, 선택 `src` 추가, 기본값 `welcome`/`md`
    - `HoiMood`를 `presentation.ts`에서 re-export, `HOI_SIZE_CLASS`(48/96/160/224px), `HOI_MOOD_LABEL`, `MOOD_POSE` export
    - viewBox `0 0 200 200` 공용 레이어(`tail`, `ears`, `body`, `belly`, `stripes`, `legs`, `arms`, `eyes`, `nose`, `mouth`)와 Mood별 오버레이(`brows`, `fangs`, `prop-*`)에 `data-part` 부여, 설계 3-2 표의 자세 반영
    - `resolveHoiImageSrc`(`/hoi/`로 시작·`.png`로 끝·`//`·`..`·`:` 없음)일 때만 `HoiImage` 사용
    - 접근성: decorative면 `aria-hidden="true"`만, 아니면 `role="img"` + `aria-label`/`<title>` = `title ?? HOI_MOOD_LABEL[mood]`
    - 루트에 `hoi-enter`, `searching`의 돋보기 그룹에만 `hoi-search-prop`
    - _Requirements: 2.9, 2.10, 2.11, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.14, 3.15, 3.16, 3.17, 3.18_

  - [ ]* 7.3 Property 3 속성 테스트 작성 (`src/components/__tests__/hoi-pose.property.test.tsx`)
    - **Property 3: 호이 렌더링은 포즈 테이블과 일치**
    - **Validates: Requirements 2.10, 3.1, 3.2, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.14, 3.15, 3.16**

  - [ ]* 7.4 Property 4 속성 테스트 작성 (`src/components/__tests__/hoi-a11y.property.test.tsx`)
    - **Property 4: 호이 접근성 속성**
    - **Validates: Requirements 3.17, 3.18**

  - [ ]* 7.5 Property 5 속성 테스트 작성 (`src/components/__tests__/hoi-src.property.test.tsx`)
    - **Property 5: 호이 이미지 경로는 내부 PNG로 제한**
    - **Validates: Requirements 3.3, 3.5**

  - [x] 7.6 `HoiSpeech.tsx`, `HoiScene.tsx` 수정
    - `HoiSpeech`: `flex flex-col items-center gap-3 sm:flex-row sm:items-end`, 말풍선 꼬리 `aria-hidden`, 호이 decorative, 선택 `footer` prop
    - `HoiScene`: `rounded-3xl bg-surface-warm`, 호이 `lg`, 제목 레벨 prop 유지
    - _Requirements: 3.19, 8.3_

  - [ ]* 7.7 호이 보조 컴포넌트 단위 테스트 작성 (`src/components/__tests__/hoi-speech.test.tsx`)
    - `HoiSpeech` 반응형 클래스와 `footer` 렌더링, `HoiImage` 유효 `src`의 `<img>`·`alt`, decorative일 때 `alt=""`
    - _Requirements: 3.4, 3.19, 8.3_

  - [x] 7.8 `public/hoi/SOURCES.md` 갱신
    - 설계 3-4 표 형식으로 에셋별 제작 방식, 외부 출처 URL("없음"), 이용 조건, 확인 날짜(YYYY-MM-DD) 기록
    - _Requirements: 3.20_

- [x] 8. Checkpoint - 공용 컴포넌트 확인
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. 내비게이션
  - [x] 9.1 `src/components/Sidebar.tsx` 수정
    - 로고 링크 `/dashboard` + 작은 호이(`sm`, decorative) + "호이 보안 코치"
    - "내 프로젝트"·"빠른 점검" 링크, "프로젝트 추가" Primary 링크, 활성 항목 `aria-current="page"` + 배경·왼쪽 막대
    - 768px 미만: 상단 바(로고, 프로젝트 추가, 로그아웃) + `grid grid-cols-2` 메뉴, 항목 `min-h-11`, 로고 텍스트 `truncate` + 전체 이름 제공
    - 기존 `logoutAction` 폼 유지
    - _Requirements: 9.1, 9.2, 9.3, 11.4, 11.8, 12.2_

  - [x] 9.2 `src/components/TopNav.tsx` 수정
    - 로고 `/`, 기능 소개/사용 방법 앵커, 로그인 여부에 따른 "내 프로젝트"/"로그인" 링크를 secondary 스타일로 표시
    - _Requirements: 5.5, 11.4, 11.6_

- [x] 10. 랜딩과 대시보드
  - [x] 10.1 `src/app/page.tsx` 재작성
    - 히어로: 아이브로우, 유일한 H1, `HoiSpeech`(`welcome`, `lg`) 중앙 정렬, Primary 링크 "코드만 빠르게 확인하기" → `/dashboard/quick-check`, secondary 링크 "내 프로젝트 점검하기" → `/dashboard/new`
    - 5단계 `<ol>`(`lg:grid-cols-5`, 그 미만 세로 타임라인), 가치 카드 3개(순서 고정), 아래에 `LIMIT_NOTICE`
    - 코드 입력 요소와 기존 "결과 예시" 섹션 제거
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10_

  - [ ]* 10.2 랜딩 정적 마크업 단위 테스트 작성 (`src/app/__tests__/landing.test.tsx`)
    - H1 1개와 문구, 아이브로우, 두 CTA `href`, textarea 없음, 5단계 순서, 가치 카드 순서, `LIMIT_NOTICE` 원문
    - TopNav가 서버 전용 모듈을 쓰면 `vi.mock`으로 대체
    - _Requirements: 5.1, 5.3, 5.4, 5.6, 5.7, 5.8, 5.9, 5.10_

  - [x] 10.3 `src/app/dashboard/page.tsx` 수정
    - 제목 "어떤 서비스를 튼튼하게 만들어 볼까요?", 헤더 아래 `HoiSpeech` 요약
    - `computeDashboardMetrics`로 기존 MetricCard 값 계산, "최근 점검"이 없으면 "아직 없어요"
    - 프로젝트 0개면 EmptyState(`rest`/`welcome` 호이, "아직 호이에게 소개한 프로젝트가 없어요", "첫 프로젝트 데려오기")
    - 화면 Primary는 헤더 버튼 1개, 프로젝트 카드 CTA는 secondary
    - 로드 실패는 `dashboard/error.tsx` 경계가 처리
    - _Requirements: 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 12.4_

- [x] 11. 빠른 점검 화면
  - [x] 11.1 `src/app/dashboard/quick-check/page.tsx` 수정
    - 제목 "이 코드, 호이가 빠르게 살펴볼게요", `label htmlFor="source"`, 밝은 textarea
    - `formatCharCount` 카운터(`id="source-count"`, `aria-describedby`), 초과 안내 `aria-live`, `isQuickCheckSubmitDisabled`로 버튼 제어
    - `// file:` 도움말을 접힌 Disclosure로
    - 빈 입력은 fetch 없이 `role="alert"` 안내, 오류는 `classifyQuickCheckError` + `QUICK_CHECK_ERROR_COPY` FriendlyError, 입력 유지, `finally`에서 버튼 재활성
    - 진행 중 `HoiSpeech`(`searching`) + "줄마다 꼼꼼히 읽고 있어요…"(`role="status"`, 퍼센트 없음)
    - 결과 영역: 입력 카드 아래, 포커스 이동, `summarizeResult` 요약(0건이면 `footer`에 `LIMIT_NOTICE`), `sortBySeverity` 목록, 기술 필드는 "기술 정보 보기" 안, AI 고지·`SimulatedTag`
    - `POST /api/quick-check`, `{ source }` 유지
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 8.1, 8.2, 8.3, 8.5, 8.6, 8.8, 8.9, 11.10, 12.3_

- [x] 12. 새 프로젝트 흐름
  - [x] 12.1 `src/app/dashboard/new/page.tsx` 수정
    - 제목 "호이에게 프로젝트를 소개해 주세요", 추천(static) ModeCard만 Primary, safe_active는 secondary
    - `isolated_active`는 접힌 "추가 점검 옵션" Disclosure 안, A/B/C 다이어그램 없음, 모드 선택 로직 유지
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 12.2 `src/app/dashboard/new/setup/NewProjectForm.tsx` 수정
    - "ZIP 파일"(기본)·"코드 붙여넣기" 탭: `role="tablist"/"tab"/"tabpanel"`, roving tabindex, `nextTabIndex`로 방향키 이동, 비선택 패널은 `hidden`으로 값 유지
    - 모든 입력에 hint 한 문장 + `aria-describedby`, 오류 시 `aria-invalid`와 오류 id 연결
    - GitHub 입력 label "참고용 GitHub 주소(선택)", Disclosure 밖에 항상 표시
    - 제출: `validateProjectDraft` → 실패 시 fetch 없이 제출 버튼 위 FriendlyError와 첫 오류 필드 포커스, ZIP 초과면 파일 선택 해제 → 기존 `validateScanModeInput`
    - `projectEndpoint(Boolean(zipFile))`로 기존 경로·본문 유지, 버튼 "프로젝트 만들기"/"프로젝트를 만들고 있어요…" + `disabled`, 실패 시 기존 `friendlyProjectError`로 입력 유지
    - _Requirements: 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 7.10, 7.11, 11.9, 11.10, 12.2_

- [x] 13. Checkpoint - 입력 화면 확인
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. 결과 화면
  - [x] 14.1 `src/app/dashboard/scans/[id]/page.tsx`와 `src/components/ScanReportPanel.tsx` 수정
    - 설계 5-6의 DOM 순서: 제목 → `HoiSpeech`(summarizeResult, 0건이면 한계 고지 footer) → "가장 먼저 할 일" Primary 1개(`primaryActionForScan`) → 심각도 MetricCard → ScanReportPanel(내부 버튼 secondary) → `sortBySeverity` 목록 → 점검 범위와 한계 → "기술 정보 보기"
    - `scan.report?.summary`는 기술 정보 쪽으로 이동, 기존 필드 모두 유지
    - _Requirements: 8.1, 8.2, 8.3, 8.5, 8.6, 8.7, 8.9, 8.11, 12.3, 12.5_

  - [x] 14.2 `src/app/dashboard/findings/[id]/page.tsx` 수정
    - 제목 아래 `HoiSpeech`(summarizeFinding), `resolved`면 `celebrate` + "잘 막았어요! 한 단계 더 튼튼해졌어요"
    - 배지 줄, AI 고지(Disclosure 밖), 설계 5-7 섹션 순서, "기술 정보 보기"에 CWE·OWASP·CVSS·ruleId·tier·`SEV_EXPERT_LABEL`·원문 근거 등 기존 필드 모두
    - 원문 근거는 저장된 `content`를 그대로 `CodeEvidence`에 전달, 복사 시 같은 문자열만 사용
    - _Requirements: 4.6, 8.1, 8.4, 8.5, 8.6, 8.8, 8.9, 8.10_

  - [x] 14.3 `src/components/FindingActions.tsx` 수정
    - `primaryActionForFinding`이 가리키는 버튼만 `variant="primary"`, 나머지 secondary, 운영 반영 확인 버튼은 danger
    - 승인 체크박스·확인 단계 순서·`PRIVILEGED_CHANGE` 흐름, fetch 경로·메서드·본문, `aria-live` 진행 상태, 기존 `mapError` 오류 정보 유지
    - _Requirements: 8.7, 11.10, 12.2, 12.6, 12.9_

- [x] 15. 인증·오류·로딩 화면
  - [x] 15.1 `src/app/login/page.tsx`, `src/app/signup/page.tsx`, `src/components/AuthForm.tsx` 수정
    - 로그인 h1 "다시 만나서 반가워요!" + `Hoi mood="welcome" size="lg"` 1개, 회원가입 h1 "호이와 첫 점검을 시작해요"
    - 보이는 label + `htmlFor` 유지, 폼 상단 `role="alert" aria-live="assertive"`에 `state.error` 원문 + 다음 행동 문장
    - 진행 중 버튼 비활성 + "잠시만요, 확인하고 있어요…", `useFormState`·server action 구조 유지
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 11.9_

  - [x] 15.2 상태 화면 수정 (`src/app/error.tsx`, `src/app/dashboard/error.tsx`, `src/app/not-found.tsx`, `src/app/loading.tsx`, `src/app/dashboard/loading.tsx`)
    - 오류: `concerned` 호이, h1 "잠시 문제가 생겼어요", 설명, "다시 시도하기"(`reset`), `error.message`·`digest` 미출력
    - not-found: `thinking` 호이, h1 "호이가 이 페이지를 찾지 못했어요.", 홈 링크 Primary
    - 로딩: `role="status"` 안에 `searching` 호이 + "호이가 화면을 준비하고 있어요…"
    - _Requirements: 10.7, 10.8, 10.9, 10.10_

  - [ ]* 15.3 Property 21 속성 테스트 작성 (`src/app/__tests__/error-boundary.property.test.tsx`)
    - **Property 21: 오류 화면은 오류 원문을 노출하지 않음**
    - 오류 원문은 `fc.uuid().map((u) => "ERRTOKEN-" + u)`로 생성
    - **Validates: Requirements 10.8**

  - [ ]* 15.4 not-found·loading 단위 테스트 작성 (`src/app/__tests__/state-pages.test.tsx`)
    - Mood, h1 문구, 홈 링크 `href="/"`, `role="status"`
    - _Requirements: 10.9, 10.10_

- [x] 16. 정직한 문구 검사와 최종 확인
  - [x] 16.1 절대 보장 표현 저장소 스캔 테스트 작성 (`src/lib/ui/__tests__/honest-copy.test.ts`)
    - `src/app`, `src/components`의 `.tsx` 파일 문자열 리터럴·JSX 텍스트를 읽어 `containsGuaranteePhrase`가 모두 false인지 확인
    - 걸리는 문구가 있으면 해당 화면 문구 수정
    - _Requirements: 12.4_

  - [x] 16.2 최종 검증 실행
    - `npm.cmd`로 `run build`, `run lint`, `test`, `run verify:rules`, `run verify:definitions` 모두 오류 없이 통과
    - `git diff --stat -- src/app/api src/lib/domain src/lib/auth-core.ts src/lib/authActions.ts` 결과가 비어 있는지 확인
    - `package.json`의 `dependencies`가 변경 전과 같은지 확인
    - _Requirements: 12.1, 12.7, 12.8_

- [x] 17. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- `*`가 붙은 하위 작업은 선택 사항이며 빠른 MVP를 위해 건너뛸 수 있다. 16.1 문구 스캔 테스트는 요구사항 12.4를 저장소 전체에 적용하는 유일한 자동 검사라서 필수로 둔다.
- 속성 테스트는 설계의 `__tests__` 위치를 따르되, 병렬 실행 충돌을 피하려고 속성마다 파일을 나눴다. 각 테스트 위에 `// Feature: hoi-warm-redesign, Property {번호}: {속성 문장}` 주석을 달고 `numRuns: 100` 이상으로 실행한다.
- 컴포넌트 테스트는 `react-dom/server`의 `renderToStaticMarkup`으로 마크업을 검사한다. 서버 전용 모듈을 import하는 페이지는 속성 테스트 대상에서 뺀다.
- 브라우저 폭별 가로 스크롤, 첫 화면 노출, 키보드·스크린리더 흐름, reduced-motion 확인(요구사항 11.1~11.8 등)은 자동 작업에 포함하지 않았다. WCAG 준수를 완전히 검증하려면 보조기기를 사용한 수동 테스트와 접근성 전문가 검토가 필요하다.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1", "7.1", "7.8"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "5.1", "5.2"] },
    { "id": 3, "tasks": ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "5.3", "5.4", "6.1", "7.2"] },
    { "id": 4, "tasks": ["6.2", "6.3", "6.5", "7.3", "7.4", "7.5", "7.6", "9.1", "9.2"] },
    { "id": 5, "tasks": ["6.4", "6.6", "7.7", "10.1", "10.3", "11.1", "12.1", "12.2", "14.1", "14.2", "14.3", "15.1", "15.2"] },
    { "id": 6, "tasks": ["10.2", "15.3", "15.4", "16.1"] },
    { "id": 7, "tasks": ["16.2"] }
  ]
}
```
