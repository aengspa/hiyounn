# Requirements Document

## Introduction

"호이 보안 코치(Vibe Coding Security Agent)"의 UI를 다시 디자인한다. 최근 적용된 크림/파랑 계열의 미니멀 스타일과 기존 호이 SVG는 사용자가 받아들이지 않았다. 이번 개편은 최초 디자인 프롬프트(`HOI_UI_REDESIGN_PROMPT.md`)의 따뜻한 호이 시각 언어(크림·주황·노랑 팔레트, 3D 버튼, 둥근 카드, 호이 안내자)로 돌아간다. 호이 마스코트는 사용자 레퍼런스 이미지에 맞게 새로 그린다. 두 번째 명세의 흐름 규칙(홈 → 스캔 시작하기 → 바로 코드 입력 → 쉬운 결과, 단순해진 프로젝트 등록, 쉬운 요약 우선 결과 화면)은 그대로 유지한다.

API 라우트, 도메인 enum, 인증, 스캔 모드 로직(`src/lib/domain/scanMode.ts`)은 바꾸지 않는다. 사용자에게 보이는 스타일, 레이아웃, 문구만 바꾼다.

## Glossary

- **Web_App**: `c:\Users\user\kor_aws`의 Next.js 14 App Router 기반 웹 애플리케이션 전체
- **Design_Tokens**: `src/app/globals.css`의 CSS 변수와 `tailwind.config.ts`의 색상·반경·그림자·애니메이션 확장 값
- **Warm_Palette**: 이 문서 요구사항 1에 정의된 크림·주황·노랑·크림슨 중심 색상 값 집합
- **UI_Kit**: `src/components/ui.tsx`의 공용 컴포넌트(Button, Card, Badge, SeverityBadge, StatusBadge, TestStatusBadge, Disclosure, TechnicalDetails, EmptyState, FriendlyError, SectionHeader, MetricCard, CodeEvidence)와 표시 라벨 맵(SEV_LABEL, STATUS_LABEL, TEST_STATUS_LABEL 등)
- **Primary_Button**: UI_Kit의 Button 중 `variant="primary"`이거나 `buttonClassName({ variant: "primary" })`를 쓰는 링크
- **Hoi**: 고려대학교 마스코트 호이를 표현하는 `src/components/mascot/Hoi.tsx` 컴포넌트
- **Hoi_Speech**: 호이와 말풍선을 함께 표시하는 `src/components/mascot/HoiSpeech.tsx` 컴포넌트
- **Hoi_Scene**: 호이와 배경 장식을 함께 표시하는 `src/components/mascot/HoiScene.tsx` 컴포넌트
- **Mood**: Hoi의 표정·자세 상태. `welcome`, `guide`, `searching`, `thinking`, `concerned`, `cheer`, `celebrate`, `rest` 8가지
- **Landing_Page**: `src/app/page.tsx`
- **Quick_Check_Page**: `src/app/dashboard/quick-check/page.tsx`
- **New_Project_Page**: `src/app/dashboard/new/page.tsx`
- **Project_Setup_Form**: `src/app/dashboard/new/setup/NewProjectForm.tsx`
- **Result_Pages**: 스캔 결과(`dashboard/scans/[id]`), 발견 상세(`dashboard/findings/[id]`), 빠른 점검 결과 영역(Quick_Check_Page 내부)
- **Auth_Pages**: `src/app/login/page.tsx`, `src/app/signup/page.tsx`, `src/components/AuthForm.tsx`
- **State_Pages**: `src/app/error.tsx`, `src/app/not-found.tsx`, `src/app/loading.tsx`, `src/app/dashboard/error.tsx`, `src/app/dashboard/loading.tsx`
- **Navigation**: `src/components/TopNav.tsx`, `src/components/Sidebar.tsx`
- **Protected_Surface**: API 라우트(`src/app/api/**`), 도메인 타입과 enum(`src/lib/domain/types.ts`), 인증 로직, 스캔 모드 로직(`src/lib/domain/scanMode.ts`)
- **Source_Limit**: 빠른 점검 코드 입력의 최대 글자 수 100,000자
- **Reduced_Motion**: 사용자 환경의 `prefers-reduced-motion: reduce` 설정
- **AA_Contrast**: WCAG 2.1 AA 기준. 일반 텍스트 4.5:1 이상, 18.66px 굵은 글씨 또는 24px 이상 큰 텍스트와 UI 구성 요소 경계 3:1 이상

## Requirements

### Requirement 1: 따뜻한 디자인 토큰

**User Story:** 바이브 코더로서, 따뜻하고 편안한 색감의 화면을 보고 싶어요. 그래야 보안 점검이 무섭지 않게 느껴져요.

#### Acceptance Criteria

1. THE Design_Tokens SHALL `globals.css`의 `:root`에 다음 CSS 변수 25개를 Warm_Palette 기준값으로 정의한다: `--background:#fff8ed`, `--background-soft:#fff1cf`, `--surface:#ffffff`, `--surface-warm:#fffaf2`, `--primary:#f58a36`, `--primary-hover:#df7022`, `--primary-soft:#ffdfb8`, `--sun:#ffc857`, `--sun-soft:#fff0b8`, `--crimson:#9e1b32`, `--crimson-soft:#f9e7eb`, `--success:#3fae5a`, `--success-soft:#e8f7eb`, `--danger:#df4d4d`, `--danger-soft:#fff0ee`, `--warning:#e99b22`, `--warning-soft:#fff5d9`, `--info:#4a89c7`, `--info-soft:#edf6ff`, `--text:#3a2b20`, `--text-subtle:#756354`, `--text-muted:#9a8879`, `--border:#eadbc8`, `--border-strong:#d6bea3`, `--focus:#9e1b32`. 기준값은 AC 2에 따라 조정된 경우에만 달라질 수 있다.
2. IF 텍스트 전경색 토큰(`--text`, `--text-subtle`, `--text-muted`, 그리고 텍스트로 쓰이는 `--primary`, `--crimson`, `--success`, `--danger`, `--warning`, `--info`)과 해당 텍스트가 놓이는 배경 토큰(`--background`, `--background-soft`, `--surface`, `--surface-warm` 및 짝이 되는 `-soft` 토큰)의 조합이 AA_Contrast(일반 텍스트 4.5:1, 18pt 이상 또는 14pt 이상 굵은 텍스트 3:1)를 충족하지 못하면, THEN THE Design_Tokens SHALL 해당 전경색 또는 배경색 값을 AA_Contrast를 충족하는 값으로 조정하고, 변경 전 값·변경 후 값·측정 대비율을 `globals.css` 주석에 기록한다.
3. THE Design_Tokens SHALL `tailwind.config.ts`의 `brand` 팔레트에 50, 100, 200, 300, 400, 500, 600, 700, 800, 900의 10단계를 정의하되, `brand-500`은 `--primary` 값, `brand-600`은 `--primary-hover` 값과 같게 하고, 50에서 900으로 갈수록 명도가 단조 감소하는 주황 계열(HSL 색상각 15°~40°) 색상으로 구성한다.
4. THE Design_Tokens SHALL 그림자 색상으로 검정·회색 대신 `--text` 또는 `--primary` 기반의 반투명 갈색·주황 계열만 사용하는 그림자 토큰을 최소 2단계(작은 카드용, 큰 카드용) 제공한다.
5. THE Design_Tokens SHALL 큰 카드·패널에는 `rounded-3xl`, 입력 필드·버튼·작은 카드에는 `rounded-2xl` 반경을 적용하는 규칙을 제공한다.
6. THE Web_App SHALL 모든 페이지 배경을 `--background` 크림색 위에 불투명도 0.35 이하의 옅은 주황·노랑 방사형 그라디언트 장식으로 표시하고, 장식 요소는 본문 콘텐츠보다 뒤쪽에 배치되어 클릭·입력을 가로막지 않는다.
7. THE Web_App SHALL 배경 장식 요소에 `aria-hidden="true"`를 지정한다.
8. THE Web_App SHALL 짙은 코드 패널 배경을 코드 스니펫, 수정 제안 diff, 스캔 로그 영역에만 사용하고 그 밖의 모든 카드·패널·페이지 영역은 `--background`, `--background-soft`, `--surface`, `--surface-warm` 중 하나를 표면색으로 사용하며, 코드 패널 안의 텍스트는 코드 패널 배경 대비 AA_Contrast를 충족한다.
9. THE Web_App SHALL 노랑(`--sun`, `--sun-soft`) 배경 위 텍스트를 `--text` 값으로 표시하고 흰색 또는 `--text-muted` 텍스트를 사용하지 않는다.
10. WHEN 키보드 포커스가 인터랙티브 요소로 이동하면, THE Web_App SHALL `--focus` 색상의 포커스 표시를 보여주며, 이 포커스 표시는 인접 배경색 대비 3:1 이상의 대비율을 가진다.

### Requirement 2: 3D 버튼, 카드, 움직임

**User Story:** 바이브 코더로서, 누르는 느낌이 있는 크고 둥근 버튼을 쓰고 싶어요. 그래야 다음에 뭘 눌러야 할지 바로 알 수 있어요.

#### Acceptance Criteria

1. THE Primary_Button SHALL Warm_Palette의 주황색 배경, 배경보다 더 진한 주황색의 2px 이상 4px 이하 하단 테두리 또는 하단 그림자, 최소 44px 높이, 8px 이상의 모서리 둥글기로 표시된다.
2. THE Primary_Button SHALL 기본, hover, pressed 상태 모두에서 버튼 텍스트와 배경 사이 대비를 AA_Contrast 이상으로 유지한다.
3. WHEN 사용자가 Primary_Button 위에 포인터를 올리면, THE Primary_Button SHALL 100ms 이상 200ms 이하의 전환 시간 동안 1px에서 2px 위로 이동하고, 포인터가 벗어나면 같은 전환 시간 안에 원래 위치로 돌아온다.
4. WHEN 사용자가 Primary_Button을 누르면, THE Primary_Button SHALL 1px에서 2px 아래로 이동하고 하단 깊이를 0px 이상 1px 이하로 줄이며, 누름이 해제되면 원래 위치와 깊이로 돌아온다.
5. WHILE Reduced_Motion이 활성화된 상태에서, THE UI_Kit SHALL 버튼과 카드의 위치 이동 효과(0px 이동)를 제거하고 hover와 pressed 상태를 배경색 또는 테두리 색 변화로만 표시한다.
6. WHILE 버튼이 disabled 상태인 동안, THE UI_Kit SHALL 버튼을 40% 이상 60% 이하의 불투명도와 `cursor-not-allowed`로 표시하고, 이동 효과를 적용하지 않으며, 클릭 시 연결된 동작을 실행하지 않는다.
7. THE UI_Kit SHALL secondary, ghost, danger 버튼 변형을 Warm_Palette 색상으로 표시하고, danger 변형은 Primary_Button과 다른 빨강 계열 배경 또는 테두리로 구분하며, 모든 변형의 텍스트 대비를 AA_Contrast 이상으로 유지한다.
8. THE UI_Kit SHALL `raised` 카드 변형을 Warm_Palette의 테두리 색과 2px 이상 4px 이하의 하단 깊이로 표시한다.
9. WHEN Hoi가 화면에 나타나면, THE Hoi SHALL 150ms 이상 300ms 이하의 페이드 또는 8px 이하 이동의 바운스 등장 애니메이션을 1회 재생한다.
10. WHILE Mood가 `searching`인 동안, THE Hoi SHALL 1회 주기가 1초 이상이고 이동 폭 4px 이하 또는 회전 10도 이하인 반복 애니메이션(돋보기 이동 또는 꼬리 흔들림)을 재생하고, Mood가 `searching`에서 다른 값으로 바뀌면 반복 애니메이션을 중지한다.
11. WHILE Reduced_Motion이 활성화된 상태에서, THE Hoi SHALL 등장 애니메이션과 반복 애니메이션을 재생하지 않고 최종 정지 상태로 즉시 표시한다.
12. THE Web_App SHALL 심각도가 `critical`인 항목을 흔들림, 점멸, 반복 애니메이션 없이 정적 스타일로 표시한다.
13. WHEN 사용자가 키보드로 버튼에 포커스를 이동하면, THE UI_Kit SHALL 버튼 외곽에 2px 이상 두께의 포커스 표시를 배경과 구분되는 색으로 표시한다.

### Requirement 3: 호이 마스코트 다시 그리기

**User Story:** 사용자로서, 제가 보여준 레퍼런스 이미지와 같은 호이를 보고 싶어요. 그래야 이 서비스만의 캐릭터로 느껴져요.

#### Acceptance Criteria

1. THE Hoi SHALL 직접 작성한 인라인 SVG로 8가지 Mood 모두에서 다음 특징을 모두 표현한다: 금빛 노랑 몸, 머리와 몸이 이어진 둥근 실루엣, 작고 둥근 양쪽 귀, 몸 전체를 끊김 없이 두르는 짙은 갈색 외곽선, 이마 중앙의 줄무늬, 양 볼·몸 옆·꼬리의 검은 줄무늬, 작은 검은 점 눈(`rest`에서는 감은 눈으로 대체), 짙은 코, 흰색 타원형 배, 짧고 통통한 팔다리, 분홍·붉은 발바닥.
2. WHEN Hoi가 `welcome`, `cheer`, `celebrate` Mood로 렌더링되면, THE Hoi SHALL 붉은 입 안과 작고 흰 송곳니 2개가 보이는 열린 입으로 표시된다.
3. WHEN Hoi가 렌더링되면, THE Hoi SHALL 외부 도메인으로 이미지 요청을 한 건도 보내지 않고, 권리가 확인되지 않은 웹 이미지를 사용하지 않는다.
4. WHERE `public/hoi/` 아래에 사용자가 제공한 호이 PNG 파일이 존재하고 Hoi에 해당 이미지 사용 옵션이 지정되면, THE Hoi SHALL 해당 PNG를 기준 8의 크기 규칙으로 표시하고, `decorative`가 false일 때는 기준 18의 한국어 라벨과 같은 대체 텍스트를, true일 때는 빈 대체 텍스트를 제공한다.
5. IF PNG 이미지 사용 옵션이 지정되었지만 해당 파일이 없거나 불러오기에 실패하면, THEN THE Hoi SHALL 같은 Mood·크기·접근성 속성을 가진 인라인 SVG 호이를 대신 표시하고 깨진 이미지 아이콘을 표시하지 않는다.
6. THE Hoi SHALL 기존 props API(`mood`, `size`, `title`, `decorative`, `className`)와 8가지 Mood 값(`welcome`, `guide`, `searching`, `thinking`, `concerned`, `cheer`, `celebrate`, `rest`)을 이름과 타입 변경 없이 유지한다.
7. WHEN Hoi가 `mood` 또는 `size` 없이 렌더링되면, THE Hoi SHALL 각각 `welcome`과 `md`를 기본값으로 사용한다.
8. WHEN Hoi가 렌더링되면, THE Hoi SHALL `size` 값에 따라 정확히 `sm` 48px(h-12), `md` 96px(h-24), `lg` 160px(h-40), `xl` 224px(h-56) 높이와 같은 너비의 정사각형 영역으로 표시된다.
9. WHEN Hoi가 `welcome` Mood로 렌더링되면, THE Hoi SHALL 한쪽 팔을 머리 높이 이상으로 들어 손을 흔드는 자세와 웃는 입으로 표시된다.
10. WHEN Hoi가 `guide` Mood로 렌더링되면, THE Hoi SHALL 한쪽 팔을 몸 옆으로 수평에 가깝게 뻗어 가리키는 자세로 표시된다.
11. WHEN Hoi가 `searching` Mood로 렌더링되면, THE Hoi SHALL 한 손에 돋보기를 든 자세로 표시되고, 돋보기는 다른 Mood에서는 표시되지 않는다.
12. WHEN Hoi가 `thinking` Mood로 렌더링되면, THE Hoi SHALL 머리 옆에 생각 기호(점 3개 이하 또는 말풍선 점)와 다문 입으로 표시된다.
13. WHEN Hoi가 `concerned` Mood로 렌더링되면, THE Hoi SHALL 진지한 눈썹과 다문 입으로 표시되고, 눈물·드러난 송곳니·찡그린 이빨 표현을 포함하지 않는다.
14. WHEN Hoi가 `cheer` Mood로 렌더링되면, THE Hoi SHALL 주먹을 든 자세 또는 별 기호 1개 이상과 함께 응원하는 자세로 표시된다.
15. WHEN Hoi가 `celebrate` Mood로 렌더링되면, THE Hoi SHALL 두 팔을 모두 머리 위로 든 자세와 축하 기호(별·반짝이·색종이 중 1개 이상)로 표시된다.
16. WHEN Hoi가 `rest` Mood로 렌더링되면, THE Hoi SHALL 감은 눈(곡선)과 팔을 몸 쪽에 내린 자세로 표시된다.
17. WHEN Hoi가 `decorative`가 true로 렌더링되면, THE Hoi SHALL `aria-hidden="true"`로 렌더링되고 `role="img"`, `aria-label`, `title` 요소를 생략한다.
18. WHEN Hoi가 `decorative`가 false로 렌더링되면, THE Hoi SHALL `role="img"`와 한국어 `aria-label`을 제공하며, `title` prop이 있으면 그 값을, 없으면 해당 Mood 전용 한국어 라벨을 사용한다.
19. WHEN Hoi_Speech가 렌더링되면, THE Hoi_Speech SHALL 뷰포트 너비 640px 이상에서는 Hoi와 말풍선을 가로로 나란히, 640px 미만에서는 Hoi를 위·말풍선을 아래로 세로 배치한다.
20. THE Web_App SHALL `public/hoi/SOURCES.md`에 호이 에셋별 제작 방식(직접 작성 SVG 또는 사용자 제공 PNG), 외부 출처 URL 유무(없으면 "없음"으로 명시), 확인한 이용 조건, 확인 날짜(YYYY-MM-DD 형식)를 기록한다.

### Requirement 4: 표시 라벨

**User Story:** 초보 개발자로서, 어려운 보안 용어 대신 쉬운 말로 된 상태 라벨을 보고 싶어요. 그래야 겁먹지 않고 우선순위를 이해할 수 있어요.

#### Acceptance Criteria

1. THE UI_Kit SHALL 심각도(`Severity`) 표시 라벨을 `critical` "지금 확인해요", `high` "먼저 고쳐요", `medium` "다듬어 봐요", `low` "여유 있을 때"로 정의하고, 심각도가 표시되는 모든 화면에서 이 라벨만 사용한다.
2. THE UI_Kit SHALL 발견 상태(`FindingStatus`) 표시 라벨을 `detected` "확인이 필요해요", `verified` "실제로 문제가 생기는 걸 확인했어요", `fixing` "고치는 중이에요", `fixed` "수정을 적용했어요", `verification_failed` "아직 완전히 막히지 않았어요", `regression_failed` "기존 기능을 다시 봐야 해요", `resolved` "잘 해결했어요"로 정의하고, 발견 상태가 표시되는 모든 화면에서 이 라벨만 사용한다.
3. THE UI_Kit SHALL 검사 상태(`TestStatus`) 표시 라벨을 `CONFIRMED` "문제를 확인했어요", `SUSPECTED` "가능성이 있어요", `NOT_DETECTED` "이번에는 보이지 않았어요", `NOT_APPLICABLE` "이 프로젝트에는 해당하지 않아요", `NOT_TESTED` "아직 확인하지 않았어요", `TEST_FAILED` "확인 과정이 끝나지 않았어요", `FIXED_VERIFIED` "고친 뒤 잘 막히는 걸 확인했어요", `REGRESSION_FAILED` "기존 기능을 다시 봐야 해요"로 정의하고, 검사 상태가 표시되는 모든 화면에서 이 라벨만 사용한다.
4. THE SeverityBadge SHALL 색상 외에 기준 1의 텍스트 라벨과 4개 심각도마다 서로 다른 아이콘 또는 형태 표시를 함께 렌더링하여, 색상 정보 없이 텍스트와 아이콘/형태만으로 4개 심각도를 서로 구분할 수 있게 한다.
5. THE UI_Kit SHALL `Severity`(4개), `FindingStatus`(7개), `TestStatus`(8개) enum의 모든 값에 대해 공백만으로 이루어지지 않은 한국어 표시 라벨을 1개씩 제공한다.
6. THE Result_Pages SHALL "기술 정보 보기" Disclosure 안에 원래 심각도 의미를 `critical` "심각(Critical)", `high` "높음(High)", `medium` "보통(Medium)", `low` "낮음(Low)" 형식으로 쉬운 라벨과 함께 표시한다.
7. THE UI_Kit SHALL 표시 라벨을 화면 표시에만 적용하고, 저장·API 요청·응답에 쓰이는 `Severity`, `FindingStatus`, `TestStatus` enum 값은 기존 값 그대로 유지한다.
8. IF 표시할 값이 기준 1~3의 라벨 목록에 없는 경우, THEN THE UI_Kit SHALL 빈 칸이나 오류 대신 해당 상태를 아직 알 수 없다는 뜻의 대체 라벨을 표시하고, 페이지의 나머지 내용은 정상적으로 렌더링한다.

### Requirement 5: 랜딩 페이지

**User Story:** 처음 방문한 바이브 코더로서, 5초 안에 이 서비스가 무엇인지 알고 바로 점검을 시작하고 싶어요.

#### Acceptance Criteria

1. THE Landing_Page SHALL 아이브로우 "바이브 코더를 위한 보안 친구"와 H1 "내 서비스, 호이와 함께 튼튼하게 만들어요"를 첫 화면(스크롤 없이 보이는 초기 뷰포트, 데스크톱 1280×720 및 모바일 375×667 기준)에 표시하며, 페이지 내 H1은 1개만 존재한다.
2. THE Landing_Page SHALL 첫 화면 안에 `welcome` Mood의 `lg` 이상 크기 Hoi와 말풍선을 가로 방향 중앙 정렬로 표시한다.
3. THE Landing_Page SHALL "코드만 빠르게 확인하기" 문구의 Primary_Button을 첫 화면 안에 가로 방향 중앙 정렬로 표시한다.
4. WHEN 사용자가 첫 화면의 Primary_Button을 클릭하거나 키보드 포커스 상태에서 Enter 키로 활성화하면, THE Landing_Page SHALL 같은 탭에서 사용자를 `/dashboard/quick-check`로 이동시킨다.
5. THE Landing_Page SHALL "내 프로젝트 점검하기" 보조 버튼을 첫 화면 안에 Primary_Button보다 시각적 우선순위가 낮은 스타일로 표시한다.
6. WHEN 사용자가 "내 프로젝트 점검하기" 보조 버튼을 클릭하거나 키보드 포커스 상태에서 Enter 키로 활성화하면, THE Landing_Page SHALL 같은 탭에서 사용자를 `/dashboard/new`로 이동시킨다.
7. THE Landing_Page SHALL 코드 입력 요소(textarea 또는 코드 입력 폼)를 페이지 어느 위치에도 포함하지 않는다.
8. THE Landing_Page SHALL "찾아봐요", "확인해요", "고쳐봐요", "다시 봐요", "튼튼해졌어요" 5단계 흐름을 이 순서대로, 뷰포트 너비 1024px 이상에서는 가로 스텝으로, 1024px 미만에서는 세로 타임라인으로 표시한다.
9. THE Landing_Page SHALL "쉬운 말로 알려드려요", "근거를 함께 보여드려요", "고친 뒤 한 번 더 확인해요" 가치 카드를 정확히 3개, 이 순서대로 표시한다.
10. THE Landing_Page SHALL "호이가 열심히 살펴보지만 자동 점검만으로 모든 위험을 찾을 수는 없어요. 중요한 서비스는 보안 전문가의 검토도 함께 받아보세요." 고지를 가치 카드 영역 아래에 문구 변경 없이 표시한다.

### Requirement 6: 빠른 점검 흐름

**User Story:** 바이브 코더로서, 코드를 붙여 넣고 바로 쉬운 결과를 보고 싶어요. 그래야 복잡한 설정 없이 점검할 수 있어요.

#### Acceptance Criteria

1. THE Quick_Check_Page SHALL 첫 화면(스크롤 전 영역)에 제목 "이 코드, 호이가 빠르게 살펴볼게요"와 `for`/`id`로 연결된 label을 가진 코드 입력 영역을 표시한다.
2. WHEN 코드 입력 영역의 내용이 바뀌면, THE Quick_Check_Page SHALL 서버와 같은 기준(입력 문자열 길이)으로 센 현재 글자 수를 천 단위 쉼표를 넣어 "N / 100,000자" 형식으로 갱신한다. 입력이 비어 있으면 "0 / 100,000자"를 표시한다.
3. WHILE 입력된 글자 수가 Source_Limit(100,000자)를 넘는 동안(100,001자 이상), THE Quick_Check_Page SHALL 초과 안내 문구를 `aria-live` 영역에 표시하고 제출 버튼을 비활성화한다. 글자 수가 100,000자 이하로 돌아오면 안내 문구를 없애고 제출 버튼을 다시 활성화한다.
4. THE Quick_Check_Page SHALL `// file:` 다중 파일 입력 도움말을 페이지 로드 시 접힌 상태의 Disclosure 안에 표시한다.
5. IF 코드 입력이 비어 있거나 공백 문자만 있는 상태에서 제출되면, THEN THE Quick_Check_Page SHALL 서버에 요청을 보내지 않고 "확인할 코드를 먼저 붙여 넣어 주세요." 안내를 `role="alert"` 영역에 표시한다.
6. IF 서버가 오류 응답을 반환하거나 네트워크 오류로 요청이 실패하면, THEN THE Quick_Check_Page SHALL 오류 종류(`source_too_large`, 서버 내부 오류, 연결 실패, 그 밖의 오류)별로 해결 행동을 담은 FriendlyError를 표시하고, 사용자가 입력한 코드를 한 글자도 바꾸지 않고 입력 영역에 유지하며, 제출 버튼을 다시 활성화한다.
7. WHILE 점검 요청이 진행 중인 동안, THE Quick_Check_Page SHALL `searching` Mood의 Hoi와 "줄마다 꼼꼼히 읽고 있어요…" 문구를 표시하고, 제출 버튼을 비활성화해 중복 요청을 막으며, 퍼센트 진행률을 표시하지 않는다.
8. IF 요청 본문의 코드가 Source_Limit를 넘으면(100,001자 이상), THEN THE Web_App SHALL 기존 서버 동작대로 점검을 실행하지 않고 `source_too_large` 오류를 반환한다. 정확히 100,000자인 코드는 정상 처리한다.
9. WHEN 점검 요청이 성공하면, THE Quick_Check_Page SHALL 진행 중 표시를 없애고 결과 영역을 입력 카드 아래에 표시한 뒤 키보드 포커스를 결과 영역으로 옮긴다.

### Requirement 7: 새 프로젝트 흐름

**User Story:** 바이브 코더로서, 필요한 것만 묻는 간단한 화면으로 프로젝트를 등록하고 싶어요.

#### Acceptance Criteria

1. THE New_Project_Page SHALL 제목 "호이에게 프로젝트를 소개해 주세요"를 표시하고, 화면 전체에 Primary_Button을 정확히 1개만 표시한다.
2. THE New_Project_Page SHALL A/B/C 구조 다이어그램(점검 방식 간 구조를 도식으로 비교하는 그림)을 포함하지 않는다.
3. THE New_Project_Page SHALL `isolated_active` 옵션을 "추가 점검 옵션" 제목의 Disclosure 안에 표시하고, 페이지 최초 로드 시 해당 Disclosure를 접힌 상태로 표시하며, Disclosure 제목에 키보드 포커스가 있을 때 Enter 또는 Space 키로 펼치고 접을 수 있게 한다(`static`, `safe_active`, `isolated_active`의 점검 방식 선택 로직은 변경하지 않는다).
4. THE Project_Setup_Form SHALL "ZIP 파일"과 "코드 붙여넣기" 2개의 탭을 표시하고, 기본 선택 탭을 "ZIP 파일"로 하며, 탭에 키보드 포커스가 있을 때 좌/우 방향키 또는 Enter/Space 키로 탭을 전환할 수 있게 하고, 선택된 탭을 보조기술이 인식할 수 있는 선택 상태로 노출하며, 탭을 전환해도 다른 탭에 입력한 값을 지우지 않는다.
5. THE Project_Setup_Form SHALL GitHub URL 입력의 label을 "참고용 GitHub 주소(선택)"로 표시하고, 해당 입력이 비어 있어도 제출을 막지 않는다.
6. THE Project_Setup_Form SHALL 제출 버튼 문구를 "프로젝트 만들기"로 표시한다.
7. THE Project_Setup_Form SHALL 화면에 표시된 각 입력(프로젝트 이름, ZIP 파일, 코드 붙여넣기, GitHub 주소, 그리고 점검 방식에 따라 표시되는 서비스 주소·테스트 계정) 바로 아래에 해당 정보가 필요한 이유를 한 문장으로 표시하고, 그 문장을 해당 입력의 설명으로 프로그래밍 방식으로 연결한다.
8. IF 프로젝트 생성 요청이 실패하면(서버가 성공이 아닌 응답을 반환하거나, 응답을 해석할 수 없거나, 네트워크 연결이 끊긴 경우), THEN THE Project_Setup_Form SHALL 페이지를 이동하지 않고, 실패 원인과 사용자가 취할 다음 행동을 담은 FriendlyError를 제출 버튼 위에 표시하여 보조기술에 즉시 알리며, 사용자가 입력한 모든 값을 유지하고, 제출 버튼을 다시 활성화한다.
9. IF 사용자가 8MB(8,388,608바이트)를 초과하는 ZIP 파일을 선택하거나 제출하면, THEN THE Project_Setup_Form SHALL 서버로 요청을 보내지 않고, 파일 선택을 해제하며, 8MB 이하 파일을 선택하라는 FriendlyError를 표시하고, 다른 입력값은 유지한다.
10. IF 프로젝트 이름이 비어 있거나 공백만으로 이루어진 상태에서 사용자가 제출하면, THEN THE Project_Setup_Form SHALL 서버로 요청을 보내지 않고, 프로젝트 이름 입력을 요청하는 FriendlyError를 표시하며, 입력한 다른 값은 유지한다.
11. WHEN 사용자가 유효한 입력으로 "프로젝트 만들기" 버튼을 누르면, THE Project_Setup_Form SHALL 응답을 받을 때까지 제출 버튼을 비활성화하고 진행 중 문구로 바꿔 중복 제출을 막으며, ZIP 파일이 선택된 경우 `/api/projects/upload`로, 그렇지 않은 경우 `/api/projects`로 요청을 보내고, 요청이 성공하면 생성된 프로젝트의 상세 페이지로 이동한다.

### Requirement 8: 결과 화면

**User Story:** 초보 개발자로서, 결과 화면에서 쉬운 요약을 먼저 보고 필요할 때만 기술 정보를 펼치고 싶어요.

#### Acceptance Criteria

1. WHEN Result_Pages(dashboard/scans/[id], dashboard/findings/[id], quick-check 결과 영역)가 렌더링되면, THE Result_Pages SHALL 페이지 제목 바로 아래, 모든 기술 정보보다 DOM 순서와 시각 순서 모두 앞에 Hoi_Speech 형태의 쉬운 요약 1문장(공백 포함 80자 이하)을 표시한다.
2. IF 스캔 결과 또는 quick-check 결과에 `critical` 발견이 1개 이상 있으면, THEN THE Result_Pages SHALL `concerned` Mood의 Hoi와 `critical` 발견부터 해결하도록 안내하는 요약을 표시하고, 발견 목록을 `Severity` enum의 4개 값 기준 `critical` → `high` → `medium` → `low` 순서로 정렬해 표시한다.
3. IF 스캔 결과 또는 quick-check 결과의 발견 수가 0개이면, THEN THE Result_Pages SHALL "이번에 확인한 범위에서는 큰 문제가 보이지 않았어요." 요약과 검사 범위 한계 고지를 같은 Hoi_Speech 영역 안에 함께 표시한다.
4. IF dashboard/findings/[id]의 발견 상태가 `resolved`이면, THEN THE Result_Pages SHALL `concerned` Mood 대신 `celebrate` Mood의 Hoi와 "잘 막았어요! 한 단계 더 튼튼해졌어요" 제목을 표시한다.
5. WHEN Result_Pages가 처음 로드되면, THE Result_Pages SHALL OWASP, CWE, CVSS, ruleId, 실행 등급, 원본 로그·HTTP 근거를 "기술 정보 보기" 제목의 Disclosure 안에 접힌 상태로 표시하고, 사용자가 Disclosure 제목을 클릭하거나 키보드 포커스 상태에서 Enter 또는 Space를 누르면 펼침/접힘을 전환하며 현재 상태를 보조기술에 펼침 여부로 노출한다.
6. THE Result_Pages SHALL 리디자인 이전 해당 페이지에 표시되던 모든 데이터 필드를 요약 영역 또는 "기술 정보 보기" Disclosure 중 한 곳에 표시하며, 어떤 필드도 화면에서 제거하지 않는다.
7. THE Result_Pages SHALL 한 화면에 Primary_Button 스타일 버튼을 정확히 1개만 표시하고(스캔 결과: 가장 높은 심각도 발견 보기 또는 다시 검사, 발견 상세: 수정안 생성·적용·검증 중 현재 상태의 다음 단계 1개), 그 외 모든 동작은 보조 버튼 스타일로 표시한다.
8. WHERE 발견이 AI 분석 결과이면, THE Result_Pages SHALL 해당 발견의 요약 영역 안, "기술 정보 보기" Disclosure 바깥에 AI 결과 고지("호이가 AI로 코드를 읽고 찾은 내용이에요. 놓치거나 잘못 짚을 수 있어요…" 취지)를 접히지 않은 상태로 표시한다.
9. WHERE 결과가 격리 시뮬레이션 결과이면, THE Result_Pages SHALL 해당 결과의 요약 영역 안에 시뮬레이션 결과임을 텍스트로 알리는 배지를 표시한다.
10. THE Result_Pages SHALL 민감정보 마스킹이 적용된 근거를 화면 표시와 복사 동작 모두에서 마스킹된 값 그대로 사용하며, 복사된 클립보드 내용에 마스킹 전 원본 값을 포함하지 않는다.
11. THE SeverityStrip SHALL 백엔드가 제공한 심각도별 실제 발견 수만 정수로 표시하고, 백엔드 응답에 없는 점수·등급·백분율을 계산하거나 표시하지 않는다.
12. IF 백엔드가 심각도별 발견 수를 제공하지 않거나 결과 데이터 로드에 실패하면, THEN THE SeverityStrip SHALL 0이나 추정값을 표시하지 않고 발견 수를 불러오지 못했음을 알리는 안내 문구를 표시한다.

### Requirement 9: 대시보드와 내비게이션

**User Story:** 사용자로서, 대시보드에서 오늘 무엇을 점검하거나 해결할지 바로 알고 싶어요.

#### Acceptance Criteria

1. THE Navigation SHALL 모든 대시보드 화면에서 왼쪽 영역(모바일 레이아웃에서는 상단 영역)에 작은 Hoi와 서비스 이름 "호이 보안 코치"를 표시하고, 서비스 이름을 선택하면 대시보드로 이동한다.
2. THE Navigation SHALL "내 프로젝트"(대시보드로 이동), "빠른 점검"(빠른 점검 화면으로 이동) 메뉴와 "프로젝트 추가"(새 프로젝트 화면으로 이동) 버튼을 표시하고, 현재 화면에 해당하는 메뉴를 선택된 상태로 시각적으로 구분하며 보조기기에 현재 페이지로 알린다.
3. WHILE 화면 너비가 768px 미만인 동안, THE Navigation SHALL "내 프로젝트", "빠른 점검", "프로젝트 추가"를 모두 최대 1번의 추가 탭(메뉴 열기) 이내에 도달할 수 있는 모바일 레이아웃을 표시하고, 너비 320px에서도 가로 스크롤 없이 모든 항목을 표시한다.
4. THE Web_App SHALL 대시보드(`src/app/dashboard/page.tsx`) 헤더에 "어떤 서비스를 튼튼하게 만들어 볼까요?" 제목을 표시한다.
5. IF 현재 사용자에게 등록된 프로젝트가 0개이면, THEN THE Web_App SHALL 대시보드에 MetricCard와 프로젝트 목록 대신 `rest` 또는 `welcome` Mood의 Hoi, "아직 호이에게 소개한 프로젝트가 없어요" 제목, 새 프로젝트 화면으로 이동하는 "첫 프로젝트 데려오기" 버튼을 가진 EmptyState를 표시한다.
6. THE Web_App SHALL 대시보드에 기존 MetricCard 지표만 유지해 표시하고(새 지표 추가 없음), 각 MetricCard 값을 현재 사용자의 저장된 프로젝트·스캔·발견 데이터에서 계산한 값으로만 채우며, 예시·고정·추정 값을 표시하지 않는다.
7. IF 개수형 MetricCard의 계산 대상 항목이 0개이면, THEN THE Web_App SHALL 해당 MetricCard에 0을 표시하고, 예시·고정·추정 값을 표시하지 않는다.
8. IF 점검 기록이 하나도 없으면, THEN THE Web_App SHALL "최근 점검" MetricCard에 "아직 없어요"를 표시하고, 예시·고정·추정 값을 표시하지 않는다.
9. IF 대시보드 데이터를 불러오지 못하면, THEN THE Web_App SHALL MetricCard와 프로젝트 목록을 표시하지 않고 불러오기 실패를 알리는 오류 상태와 다시 시도 동작을 표시한다.

### Requirement 10: 인증, 오류, 로딩 화면

**User Story:** 사용자로서, 로그인하거나 오류를 만났을 때도 호이가 친절하게 다음 행동을 알려줬으면 해요.

#### Acceptance Criteria

1. WHEN 사용자가 로그인 화면에 진입하면, THE Auth_Pages SHALL "다시 만나서 반가워요!" 문구를 페이지의 h1 제목으로 표시하고, 같은 화면에 `welcome` Mood의 Hoi를 1개 표시한다.
2. WHEN 사용자가 회원가입 화면에 진입하면, THE Auth_Pages SHALL "호이와 첫 점검을 시작해요" 문구를 페이지의 h1 제목으로 표시한다.
3. THE Auth_Pages SHALL 로그인·회원가입 화면의 모든 입력 필드에 항상 화면에 보이는 한국어 텍스트 label을 표시하고, label을 입력 필드와 프로그래밍적으로 연결하여 label 클릭 시 해당 입력 필드로 포커스가 이동하게 한다(placeholder만으로 label을 대신하지 않는다).
4. IF 인증 요청(입력값 검증 실패, 자격 증명 불일치, 가입 실패 포함)이 실패하면, THEN THE Auth_Pages SHALL 화면을 이동하지 않고 같은 인증 화면에 머무르며, 인증 로직이 반환한 한국어 오류 문장과 사용자가 취할 다음 행동 1가지 이상을 폼 상단의 `aria-live` 영역에 표시한다.
5. IF 로그인이 자격 증명 불일치로 실패하면, THEN THE Auth_Pages SHALL 등록되지 않은 이메일과 틀린 비밀번호를 구분하지 않는 기존 단일 오류 문장을 그대로 표시하며, 이메일 등록 여부를 드러내는 문구를 새로 추가하지 않는다.
6. WHILE 인증 요청이 처리 중인 동안, THE Auth_Pages SHALL 제출 버튼을 비활성화하여 중복 제출을 막고, 버튼 문구를 처리 중임을 알리는 한국어 문장으로 바꿔 표시한다.
7. WHEN 렌더링 오류가 발생하면, THE State_Pages SHALL `concerned` Mood의 Hoi, "잠시 문제가 생겼어요" 취지의 h1 제목과 설명 문장, 키보드로 조작할 수 있는 "다시 시도하기" 버튼을 표시하고, 버튼을 누르면 오류가 난 화면을 다시 렌더링한다.
8. THE State_Pages SHALL 오류 원문 메시지, 오류 식별자(digest), 스택 트레이스를 사용자 화면과 스크린리더에 노출되는 텍스트 어디에도 표시하지 않는다.
9. WHEN 사용자가 존재하지 않는 경로로 접속하면, THE State_Pages SHALL `thinking` 또는 `concerned` Mood의 Hoi, "호이가 이 페이지를 찾지 못했어요." 문구의 h1 제목, 누르면 홈 경로("/")로 이동하는 버튼 1개 이상을 표시한다.
10. WHILE 페이지가 로딩 중인 동안, THE State_Pages SHALL `searching` 또는 `thinking` Mood의 Hoi 1개와 로딩 중임을 알리는 한국어 텍스트를 스크린리더가 읽을 수 있는 상태 알림(status) 영역 안에 표시한다.

### Requirement 11: 접근성과 반응형

**User Story:** 키보드나 스크린리더를 쓰는 사용자로서, 모든 흐름을 마우스 없이 끝까지 진행하고 싶어요.

#### Acceptance Criteria

1. THE Web_App SHALL 모든 버튼, 링크, 입력, Disclosure summary를 화면에 보이는 위에서 아래, 왼쪽에서 오른쪽 순서와 같은 Tab 순서로 접근 가능하게 제공하고, 포커스가 한 요소 안에 갇혀 Tab 또는 Shift+Tab으로 빠져나올 수 없는 상태를 만들지 않는다.
2. WHEN 버튼 또는 Disclosure summary가 키보드 포커스를 가진 상태에서 사용자가 Enter 또는 Space 키를 누르면, THE Web_App SHALL 마우스 클릭과 같은 동작을 실행한다.
3. WHEN 상호작용 요소가 키보드 포커스를 받으면, THE Web_App SHALL `--focus` 색상의 3px 이상 포커스 링을 요소 테두리 바깥에 표시하고, 이 포커스 링이 부모 요소에 의해 잘리거나 가려지지 않게 한다.
4. THE Web_App SHALL 상호작용 요소의 터치 영역을 최소 44px × 44px로 제공한다(본문 문장 안의 인라인 텍스트 링크 제외).
5. THE Web_App SHALL 본문 텍스트를 16px 이상, 부가 정보(날짜·시간, 캡션, 메타 라벨, 배지 텍스트)를 13px 이상으로 표시한다.
6. THE Web_App SHALL 아이콘만 있는 버튼에 그 버튼의 동작을 설명하는 한국어 접근 가능한 이름을 제공하고, 장식용 아이콘과 장식용 호이 마스코트 일러스트는 스크린리더가 읽지 않도록 숨긴다.
7. THE Web_App SHALL 랜딩, 로그인, 회원가입, 대시보드, 새 프로젝트, 프로젝트 상세, 스캔 상세, 발견 항목 상세, 빠른 점검 화면을 320px 너비부터 1440px 너비까지 가로 스크롤 없이 표시한다(코드 블록 내부 스크롤 제외).
8. THE Web_App SHALL 긴 프로젝트명, URL, 파일 경로를 줄바꿈 또는 말줄임 처리해 레이아웃 밖으로 넘치지 않게 표시하고, 말줄임 처리된 경우에도 스크린리더에는 전체 텍스트를 제공한다.
9. IF 폼 제출 시 입력값 검증이 실패하면, THEN THE Web_App SHALL 사용자가 입력한 값을 유지한 채 오류 메시지를 해당 입력 필드에 프로그래밍적으로 연결하고, 오류가 있는 첫 번째 입력 필드로 키보드 포커스를 옮긴다.
10. WHEN 스캔 진행 상태, 수정안 생성·적용·검증 결과, 요청 실패 같은 비동기 상태 메시지가 화면에 나타나면, THE Web_App SHALL 사용자가 포커스를 옮기지 않아도 스크린리더가 해당 메시지를 읽도록 알린다.

### Requirement 12: 비회귀와 정직한 안내

**User Story:** 제품 운영자로서, UI만 바뀌고 보안 기능과 결과의 정확성은 그대로 유지되길 원해요.

#### Acceptance Criteria

1. THE Web_App SHALL Protected_Surface 파일의 동작과 공개 계약(요청·응답 형태, enum 값, 인증 흐름, 스캔 모드 판정)을 리디자인 전과 동일하게 유지하며, 리디자인 변경 내역에 Protected_Surface 파일의 로직 변경이 0건이어야 한다.
2. WHEN 사용자가 스캔 시작, 수정안 생성, 수정 적용, 재검증, 로그아웃, 프로젝트 생성 버튼 중 하나를 누르면, THE Web_App SHALL 리디자인 전과 같은 대상 경로, 같은 요청 방식, 같은 요청 본문 필드로 API를 1회 호출한다.
3. THE Web_App SHALL 백엔드 응답에 포함되지 않은 진행률 퍼센트, 진행 단계, 보안 점수를 숫자·막대·단계 표시 등 어떤 형태로도 표시하지 않는다.
4. THE Web_App SHALL 위험이 전혀 없음을 보장하는 표현("100% 안전", "완벽해요", "완벽히 보호" 및 같은 뜻의 절대 보장 표현)을 사용자에게 보이는 모든 문구(본문, 버튼, 호이 말풍선, 페이지 제목)에 포함하지 않는다.
5. IF 화면이 "안전" 또는 "문제없어요" 취지의 결과를 표시하면, THEN THE Web_App SHALL 그 결과 문구와 같은 카드 또는 섹션 안에, 추가 클릭이나 펼치기 없이 보이는 형태로 자동 검사 범위의 한계 고지를 함께 표시한다.
6. WHEN 운영 반영(`PRIVILEGED_CHANGE`) 단계에 도달하면, THE Web_App SHALL 사용자의 명시적 승인 동작 전에는 반영 요청을 보내지 않으며, 승인 단계의 개수와 순서를 리디자인 전과 동일하게 유지한다.
7. THE Web_App SHALL `package.json`의 `dependencies` 항목을 리디자인 전과 동일하게 유지한 상태로 구현된다(새 런타임 의존성 추가 0건).
8. WHEN 리디자인이 완료되면, THE Web_App SHALL `npm run build`, `npm run lint`, `npm run verify:rules`, `npm run verify:definitions`를 모두 오류 없이 통과한다.
9. IF 버튼 동작의 API 호출이 실패 응답을 반환하면, THEN THE Web_App SHALL 성공이나 "안전" 취지의 문구 대신 작업이 실패했음을 알리는 안내를 표시하고, 리디자인 전 화면이 제공하던 오류 정보를 빠짐없이 표시한다.
