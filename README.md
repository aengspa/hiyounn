# 코치코치 호이 — 바이브 코더를 위한 보안 점검

> 호이가 약한 곳을 찾아 쉽게 설명해 드리고, 고친 뒤 잘 막혔는지 한 번 더 확인해요.

- 서비스 주소: https://hiyounn.vercel.app
- 저장소: https://github.com/aengspa/hiyounn

AI와 함께 빠르게 만든 서비스는 잘 돌아가는 것처럼 보여도 눈에 띄지 않는 곳에 보안 구멍이 남아 있을 수 있어요.
코치코치 호이는 서비스를 공개하기 전에 코드와 설정을 살펴보고, 무엇이 문제인지와 어떻게 고치면 되는지를 쉬운 말로 알려 줘요.
고친 코드는 같은 기준으로 다시 확인해서, 문제가 실제로 막혔는지까지 보여 줘요.

---

## 이렇게 동작해요

1. **올린 코드를 살펴봐요.** ZIP 파일이나 붙여 넣은 코드에서 소스와 설정 파일을 읽어요. 이 단계에서는 코드를 실행하지 않아요.
2. **공개된 보안 기준으로 만든 규칙으로 1차 점검해요.** 규칙마다 CWE 같은 근거 번호가 연결돼 있어요.
3. **AI가 한 번 더 살펴봐요.** 규칙으로 잡기 어려운 권한 확인 누락 같은 로직 문제를 찾고, 규칙 결과에 의견을 달아요. AI는 규칙 결과를 지우지 않아요. 오탐으로 판정한 항목은 근거와 함께 따로 모아 보여 줘요.
4. **어디가, 어떻게, 왜 문제인지 쉽게 알려 줘요.** 문제가 된 코드 줄(비밀값은 가림)과 함께, 그대로 두면 생길 수 있는 일과 고치는 방법을 정리해요.
5. **요청하면 한 번에 고쳐 드려요.** 오탐으로 판정된 항목을 뺀 나머지를 고친 사본을 만들어요. 올린 원본은 그대로 두고, 바뀐 파일은 ZIP으로 내려받아요.
6. **고친 코드를 다시 확인해요.** 수정본에 같은 규칙 검사를 다시 돌리고, 규칙으로 판단하기 어려운 항목은 AI가 함께 봐요. 가능한 항목은 격리된 환경에서 같은 공격을 다시 시도해 막혔는지 확인해요.
7. **코드를 다시 올려 언제든 재점검해요.** 새로 올리면 바뀐 파일만 AI가 새로 보고, 나머지는 이전 결과를 이어서 보여 줘요.

---

## 주요 기능

| 기능 | 설명 | 코드 위치 |
|---|---|---|
| 규칙 기반 점검 | 비밀정보 노출, XSS·인젝션·경로 조작, 객체 권한 확인 누락(IDOR), 보안 헤더·CORS, OWASP ASVS 5.0 정적 신호 등 | `src/lib/rules/`, `src/lib/scanners/` |
| 취약한 라이브러리 확인 | 사용 중인 패키지 버전을 OSV.dev에서 조회해요 | `src/lib/scanners/dependencyScanner.ts` |
| AI 코드 분석 | 위험해 보이는 파일부터 나눠 읽고, 규칙이 놓친 로직 문제를 찾아요(`LLM_*` 설정 필요) | `src/lib/scanners/aiCodeScanner.ts` |
| 라우트 권한 표 | 라우트마다 로그인·관리자·소유자 확인이 있는지 정리하고, 빈틈을 발견 항목으로 만들어요 | `src/lib/scanners/authzMatrix.ts` |
| 외부 도구 연동 | Semgrep 규칙 검사와 Gitleaks 비밀키 검사를 함께 돌려요(허용 목록의 고정 버전만 설치) | `src/lib/tools/`, `src/lib/scanners/` |
| 한 번에 고치기 | 비밀값·라이브러리는 규칙으로, 나머지는 AI 수정안으로 고친 사본을 만들어요. 비밀값은 AI에 보내지 않아요 | `src/lib/fixjobs/`, `src/lib/remediation/` |
| 재검증 | 규칙 재검사를 기준으로, AI 판단과 격리 환경의 공격 재현 테스트로 해결 여부를 확인해요 | `src/lib/fixjobs/reverifyService.ts`, `src/lib/exploit/` |
| AI 제안 규칙 | AI만 찾은 문제를 다음부터 규칙으로도 잡을 수 있게 제안하고, 사람이 승인하면 규칙으로 써요 | `src/lib/rules/customRules.ts` |
| 빠른 점검 | 코드 조각을 붙여 넣어 바로 확인해요. 프로젝트나 점검 결과로 저장하지 않아요 | `/dashboard/quick-check` |
| 샘플 앱 체험 | 일부러 취약하게 만든 메모 보드 앱으로 점검·수정·재검증을 바로 해 볼 수 있어요 | `samples/memo-board/` |

## 점검 근거로 삼은 공개 기준

- **1차 근거:** CWE(결함 분류), CAPEC 3.9(공격 패턴)
- **보조 근거:** OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP ASVS 5.0.0, OWASP Top 10 for LLM Applications:2025, MITRE ATT&CK(Enterprise), MITRE ATLAS

규칙 정의는 `src/lib/rules/definitions.ts`, `src/lib/rules/asvs5Catalog.ts`에 있어요.
메인 페이지의 기준 목록과 숫자는 `src/lib/rules/sources.ts`가 규칙에서 직접 계산해요.
위 기관들이 이 서비스를 보증하거나 제휴한 것은 아니에요.

## 이런 원칙을 지켜요

- **보장 표현을 쓰지 않아요.** "100% 안전" 같은 문구는 테스트(`src/lib/ui/__tests__/honest-copy.test.ts`)로 막아요. 확인한 범위와 확인하지 못한 범위를 함께 보여 줘요.
- **수정과 검증을 나눠요.** 수정안을 만든 것만으로는 해결로 보지 않아요. 재검증에서 확인해야 해결로 표시해요.
- **비밀값을 가려요.** 결과 화면과 AI에 보내는 코드에서 비밀값을 가려요.
- **내 데이터만 봐요.** 모든 저장소 접근은 소유자를 확인하고, Supabase 스키마는 모든 테이블에 RLS를 켜요.
- **원본을 건드리지 않아요.** 수정은 새 소스 버전과 바뀐 파일 ZIP으로만 제공해요.

---

## 기술 스택

- Next.js 14(App Router), React 18, TypeScript, Tailwind CSS
- 데이터 저장: Supabase(Postgres) 또는 메모리(로컬 개발용)
- AI: OpenAI·Anthropic·Gemini 중 선택(OpenAI 호환 게이트웨이 지원)
- 테스트: Vitest, fast-check

## 로컬에서 실행하기

Node.js 22 이상을 권장해요.
공격 재현 샌드박스는 Node 20.16 이상, 샘플 앱은 Node 22.13 이상이 필요해요.

```bash
cp .env.example .env.local   # 로컬 개발은 기본값(DATA_STORE=memory)으로도 동작해요
npm install
npm run dev                  # http://localhost:3000
```

회원가입 후 "새 프로젝트 데려오기"에서 코드를 올리거나, "샘플 앱으로 먼저 체험하기"로 메모 보드 샘플을 추가해 점검을 시작해 보세요.
메모리 저장소는 서버를 다시 켜면 데이터가 사라져요.

| 명령 | 하는 일 |
|---|---|
| `npm run dev` | 개발 서버 |
| `npm run build` | 프로덕션 빌드(Linux에서는 Gitleaks 실행 파일을 먼저 받아 함께 넣어요) |
| `npm run start` | 빌드한 서버 실행 |
| `npm run lint` | ESLint |
| `npm test` | Vitest 테스트 |
| `npm run verify:rules`, `npm run verify:definitions` | 규칙·도구 정의 검증 |
| `npm run samples` | 샘플 앱 폴더에서 생성 모듈과 ZIP을 다시 만들어요 |

## 환경변수

`.env.example`을 참고하세요. `NEXT_PUBLIC_`으로 시작하는 값만 브라우저에 노출돼요.
나머지 키는 서버 전용이라 코드나 저장소에 넣지 말고 `.env.local` 또는 배포 서비스 설정에만 두세요.

| 이름 | 필요할 때 | 설명 |
|---|---|---|
| `AUTH_SECRET` | 운영 필수 | 로그인 세션 서명 키. 없으면 운영 환경에서 로그인·세션 처리가 오류로 멈춰요. `openssl rand -hex 32`로 만들어요. |
| `DATA_STORE` | 항상(기본 `memory`) | 로컬은 `memory`, 배포는 `supabase` |
| `NEXT_PUBLIC_SUPABASE_URL` | `DATA_STORE=supabase` | Supabase 프로젝트 주소 |
| `SUPABASE_SERVICE_ROLE_KEY` | `DATA_STORE=supabase` | 서버 전용 키(RLS를 우회하므로 절대 노출 금지) |
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL` | 선택 | AI 분석·수정·재검증. 없으면 규칙 기반으로만 동작해요. |
| `LLM_BASE_URL`, `LLM_AUTH_HEADER`, `LLM_EXTRA_HEADERS`, `LLM_REQUIRE_GATEWAY` | 선택 | OpenAI 호환 게이트웨이를 쓸 때 |
| `SEMGREP_BIN`, `SEMGREP_CONFIG`, `GITLEAKS_BIN` | 선택 | 서버에 이미 설치된 도구를 쓸 때 |
| `HOI_ALLOW_TOOL_INSTALL` | 선택 | `false`면 점검 중 도구를 내려받아 설치하지 않아요 |
| `LIMIT_*` | 선택 | 업로드 크기, AI 점검 분량·시간, 동시 실행 수 등 한도(`src/lib/config/limits.ts`) |

## 배포하기(Vercel)

메모리 저장소는 서버리스 함수마다 데이터가 따로 있어서, 배포 환경에서는 점검 결과가 사라질 수 있어요.
배포할 때는 Supabase 저장소를 쓰세요.

1. Supabase 프로젝트를 만들고 SQL 편집기에서 `supabase/schema.sql`을 실행해요. 이어서 `supabase/migrations/`의 파일을 날짜 순서대로 실행해요.
2. Vercel 프로젝트 설정에 `DATA_STORE=supabase`, `NEXT_PUBLIC_SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AUTH_SECRET`을 넣어요. AI를 쓰려면 `LLM_*` 값도 넣어요.
3. 다시 배포해요.

## 샘플 앱(메모 보드)

`samples/memo-board/`는 Express와 `node:sqlite`로 만든 작은 메모 앱이에요.
점검 연습용으로 SQL 인젝션, IDOR, XSS, SSRF, 관리자 확인 누락, 예측 가능한 세션 토큰 같은 문제를 일부러 넣었어요.
실제 서비스나 인터넷에 공개된 곳에서 실행하지 마세요.

새 프로젝트 화면의 "샘플 앱으로 먼저 체험하기"는 이 소스로 일반 프로젝트를 만들어요.
점검·수정·재검증은 미리 만든 결과 없이 매번 실제로 실행돼요.
폴더를 고친 뒤에는 `npm run samples`로 생성 모듈과 ZIP을 다시 만들어 주세요. 둘이 어긋나면 테스트가 실패해요.

## 폴더 구조

```text
src/
  app/                    화면(메인, 로그인, 대시보드, 새 프로젝트, 점검 결과, 빠른 점검)과 API 라우트
  components/             화면 부품(호이 캐릭터, 사이드바, 수정·재검증 패널 등)
  lib/
    rules/                점검 규칙과 근거 기준
    scanners/             규칙·AI·외부 도구 스캐너
    fixjobs/              한 번에 고치기와 재검증
    remediation/          수정안 생성과 적용, 바뀐 파일 ZIP
    exploit/              공격 재현 테스트 샌드박스
    tools/                Semgrep·Gitleaks 허용 목록 설치
    store/                저장소(메모리·Supabase, 소유자 확인)
    ui/                   화면 표시용 라벨과 상태 계산
supabase/                 Postgres 스키마와 마이그레이션(RLS 포함)
samples/memo-board/       점검 연습용 샘플 앱
scripts/                  규칙 검증, 샘플 생성, 빌드용 도구 받기, E2E 벤치마크
docs/security/            규칙 정의 연동 메모, 수정 후 설정 안내
```

## 알아두면 좋아요

- 자동 점검만으로 모든 취약점을 찾을 수는 없어요. 결제나 개인정보를 다루는 서비스라면 전문가 검토도 함께 받아 보세요.
- 재검증의 "해결"은 수정본 코드 기준이에요. 받은 파일을 반영하고 다시 배포해야 실제 사이트에 적용돼요.
- 공격 재현 테스트는 `node --permission`과 모듈 가짜화로 격리하지만, 컨테이너 수준의 격리는 아니에요.
- 수정 때문에 새 환경변수가 필요해지면(예: `JWT_SECRET`), 결과 화면과 ZIP에 목록을 함께 보여 줘요. 설정 방법은 [docs/security/fix-configuration.md](docs/security/fix-configuration.md)에 있어요.

---

호이 캐릭터에 관한 권리는 고려대학교에 귀속돼요. 캐릭터 에셋 출처와 확인 내용은 `public/hoi/SOURCES.md`에 있어요.
