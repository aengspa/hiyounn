# 스캔 지식 베이스 (ASVS / WSTG → 검사 규칙 참조)

> **이 문서는 VSA(Vibe Coding Security Agent)가 _다른 웹사이트_ 를 스캔할 때 참조하는 검사 카탈로그입니다.**
> VSA 자체를 점검하는 문서가 아닙니다.
>
> **⚠ 이 문서는 SecurityRule의 source of truth 입니다.**
> `SecurityRule`을 추가·수정할 때는 반드시 이 카탈로그의 **표준 ID · 적용 조건(selector/appliesTo) · 실행 tier · prerequisites · evidence · expectedResult** 를 기준으로 구현한다. 코드와 이 문서가 어긋나면 이 문서가 우선이며, 코드를 문서에 맞춘다.
>
> 목적: OWASP ASVS 4.0.3 · WSTG v4.2의 검사 항목을 이 엔진의 **규칙 스키마**(`src/lib/rules/types.ts`)에 그대로 옮길 수 있는 형태로 정리한다. 개발자는 이 문서를 보고 `src/lib/rules/definitions.ts`에 규칙을 추가하고, 필요한 도구를 `src/lib/rules/toolCatalog.ts`에 등록하면 된다.
>
> 참조 표준: [OWASP ASVS 4.0.3](https://owasp.org/www-project-application-security-verification-standard/) · [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/)

---

## 0. 이 문서와 코드의 관계

VSA의 검사 흐름(대상 웹사이트 기준):

```
ProjectManifest(대상 앱 무엇으로 구성?)  ─selector─▶  적용 규칙 선별
      │                                                    │
      ▼                                                    ▼
capabilities/environment                       ScanPlan(selectedChecks + coverageGaps)
      │                                                    │
      └──────────── executionGate(tier/tool/prereq) ───────┘
                                 │
                                 ▼
                        스캐너 실행(도구) → Finding(+standards/tier/testStatus)
                                 │
                                 ▼
                     수정안 → 재검증(공격 재현) → resolved
```

- **규칙 스키마**: `src/lib/rules/types.ts` (`SecurityRule`)
- **현재 등록된 규칙**: `src/lib/rules/definitions.ts` (SEC-001, SEC-004, WEB-001, WEB-002, WEB-007, BAAS-001)
- **도구 카탈로그**: `src/lib/rules/toolCatalog.ts` (등록된 tool_id만 실행 가능)
- **실행 게이트**: `src/lib/rules/executionGate.ts` (tier·prereq·비파괴 강제)

**이 지식 베이스는 위 규칙 집합의 _상위 집합_(로드맵)이다.** 현재 구현된 것은 `[구현됨]`, 아직 안 된 것은 `[미구현]`으로 표시한다.

---

## 1. 규칙 작성에 쓰는 공통 어휘 (이 엔진 고유)

각 검사 항목을 규칙으로 옮길 때 아래 필드를 채운다. 값은 반드시 엔진이 아는 열거값이어야 한다(임의 문자열 금지 — `registry.ts`가 검증).

| 필드 | 의미 | 허용값 (`domain/types.ts`, `rules/types.ts`) |
|---|---|---|
| `appliesTo` | 적용 구성요소 | `web` · `api` · `baas` |
| `methods` | 검사 방법 | `SAST`(정적) · `CONFIG`(설정) · `DAST`(동적) · `TEST`(시나리오 재현) |
| `execution.tier` | 실행 위험 등급 | `PASSIVE`(읽기전용) · `SAFE_ACTIVE`(비파괴 HTTP) · `ISOLATED_ACTIVE`(격리 공격 재현) · `PATCH` · `PRIVILEGED_CHANGE` |
| `prerequisites` | 방법별 선행조건 | `source_checkout` · `authorized_test_deployment` · `test_user_a` · `test_user_b` · `object_owned_by_a` · `object_owned_by_b` … |
| `expected` (check) | 기대 결과 | `allowed` · `denied` |
| `testStatus` (결과) | 검사 판정 | `CONFIRMED` · `SUSPECTED` · `NOT_DETECTED` · `NOT_APPLICABLE` · `NOT_TESTED` · `TEST_FAILED` · `FIXED_VERIFIED` · `REGRESSION_FAILED` |

**핵심 원칙 (이미 코드가 강제하는 것, 규칙 추가 시 반드시 지킬 것):**
1. **미실행 ≠ 실패 ≠ 통과.** 못 검사했으면 `NOT_TESTED`/`coverage_gap`으로 남긴다(안전하다고 하지 않는다).
2. **tier 승격은 서버만.** 배포 URL(테스트 대상)이 없으면 `PASSIVE`까지만 자동 허용(`allowedMaxTier`).
3. **파괴적 작업 금지.** `execution.destructiveOperations`는 반드시 `false`.
4. **비밀·레포 내용은 증거로만, 마스킹.** 지시로 취급하지 않는다.
5. **재검증 없는 resolved 금지.** `verificationRequiredChecks`에 "공격 차단 + 정상 기능 보존"을 모두 넣는다.

---

## 2. 검사 카탈로그 (WSTG/ASVS → 규칙)

각 항목 형식:
- **검사 대상 / 탐지 방법 / 실행 등급 / 선행조건 / 기대결과 / 증거 / 재검증 / 수정 경로**

우선순위(P0=먼저 구현)는 "AI로 만든 웹앱에서 가장 흔하고 파급 큰 취약점" 기준.

---

### A. 접근 제어 (Access Control)

#### A-1. 사용자 간 객체 접근 (IDOR / BOLA) — `[구현됨: WEB-002]`
- **표준**: OWASP API1:2023 · ASVS 4.2.1 · WSTG-ATHZ-04 · CWE-639
- **appliesTo**: `api`, `web`, `baas` / **methods**: `SAST` + `TEST`
- **selector**: `components.kind contains api` AND `capabilities.authentication = detected` AND `capabilities.user_owned_data = detected`
- **탐지**:
  - SAST: 라우트 핸들러가 URL/파라미터의 id로만 객체를 조회하고 소유권 조건(`ownerId`/`session.user.id`)이 없는지. (현재 휴리스틱: `authorizationScanner.detectsIdor`)
  - TEST(`ISOLATED_ACTIVE`): 사용자 A 세션으로 B 소유 객체를 `read`/`update` → **denied(403) 기대**. 소유자 본인 접근 → **allowed(200) 기대**.
- **선행조건(TEST)**: `authorized_test_deployment`, `test_user_a`, `test_user_b`, `object_owned_by_a`, `object_owned_by_b`
- **증거**: 취약 소스, 교차 접근 HTTP 요청/응답, 재현 결과(attack_reproduction)
- **재검증**: `cross-user-read`·`cross-user-update` 차단 + `owner-read`·`owner-update` 정상 + 기존 기능 테스트 통과
- **수정 경로**: `app/**`, `src/**`, `supabase/migrations/**` (branch_only)
- **확장 아이디어**: 리스트 엔드포인트의 대량 노출(BOLA on collection), 순차 id 열거.

#### A-2. 함수/권한 상승 (BFLA / 관리자 기능 노출) — `[구현됨: WEB-013]`
- **표준**: OWASP API5:2023 · ASVS 4.1.3/4.3.1 · WSTG-ATHZ-02 · CWE-285
- **appliesTo**: `api`, `web` / **methods**: `TEST` (`ISOLATED_ACTIVE`)
- **selector**: `environment.testOrigin exists` AND `capabilities.authentication = detected` AND `capabilities.admin_functions = detected`
- **탐지**: 일반 사용자 세션으로 관리자 전용 함수(예: `/api/admin/*`, 역할 변경, 다른 사용자 삭제)를 호출한다. **denied(401/403) 기대**. 200/2xx로 수행되면 함수 수준 권한(BFLA) 취약.
- **expectedResult**: 일반 사용자의 관리자 함수 호출은 거부(denied). 관리자 세션은 허용(대조군).
- **선행조건(TEST)**: `authorized_test_deployment`, `test_user_a`(일반), `admin_session`(관리자), 관리자 엔드포인트 목록. 하나라도 없으면 `coverage_gap`.
- **실행 등급**: `ISOLATED_ACTIVE` — 상태 변경 가능성이 있어 **격리 환경에서만**. 배포 URL 없으면 tier 미승인 → coverage_gap. `PRIVILEGED_CHANGE` 절대 금지.
- **비파괴 우선**: 가능하면 조회형 관리자 함수(목록/상세)로 확인. 상태 변경형은 격리 인스턴스에서만, 요청 상한 준수.
- **증거**: 권한별(일반 vs 관리자) 요청/응답 매트릭스, 스캐너 출력.
- **재검증**: `probe-bfla` — 수정 후 일반 사용자 호출이 denied, 관리자 호출은 여전히 allowed(정상 기능 보존).
- **수정 경로**: `app/**`, `src/**`. `productionChange: approval_required`.

#### A-3. 경로/디렉터리 접근 우회 (Path Traversal) — `[구현됨(SAST): WEB-006]`
- **표준**: ASVS 4.3.2 · WSTG-ATHZ-01 · CWE-22
- **appliesTo**: `web`, `api` / **methods**: `SAST` (`PASSIVE`) — (동적 `../` 재현은 향후 SAFE_ACTIVE 확장)
- **selector**: `components.kind contains api` OR `components.kind contains web`
- **탐지**: 파일 시스템 API(`fs.readFile`/`readFileSync`/`createReadStream`/`res.sendFile`/`path.join`)의 인자에 사용자 제어 값(`req.`/`params`/`query`/`body`/`searchParams`)이 정규화·화이트리스트 없이 들어가는지. SAST 신호: `readFile(path.join(dir, req.query.name))` 처럼 입력이 경로로 흐르고 인근에 `path.normalize`/`path.resolve` + 기준 디렉터리 검사(`startsWith(baseDir)`)나 확장자/파일명 화이트리스트가 없음.
- **expectedResult**: 사용자 입력이 경로 검증(정규화 + 기준 디렉터리 봉쇄) 없이 파일 접근에 쓰이지 않아야 함(취약 신호 없음).
- **선행조건(SAST)**: `source_checkout`
- **증거**: 취약 라인 소스, 스캐너 출력(입력→파일 API 흐름).
- **재검증**: `changed-code-scan` — 수정 후 소스에서 동일 신호가 사라짐(정규화·봉쇄 추가).
- **수정 경로**: `app/**`, `src/**` (branch_only). `productionChange: not_applicable`.

---

### B. 인증 (Authentication)

#### B-1. 보호된 API의 무인증 접근 — `[구현됨: WEB-001]`
- **표준**: OWASP API2:2023 · ASVS 2.1/4.1.1 · WSTG-ATHN-* · CWE-306
- **appliesTo**: `api`, `web` / **methods**: `TEST` (`SAFE_ACTIVE`)
- **selector**: `components.kind contains api` AND `capabilities.authentication = detected`
- **탐지**: 인증 헤더/쿠키 없이 보호 엔드포인트 호출 → **denied(401/403) 기대**. 200이면 취약.
- **선행조건**: `authorized_test_deployment`
- **재검증**: `anonymous-access` denied + 기존 기능 테스트.

#### B-2. 취약한 로그인 정책 (무차별 대입 / 계정 잠금) — `[구현됨: WEB-011]`
- **표준**: OWASP A07:2021 · ASVS 2.2.1 · WSTG-ATHN-03 · CWE-307
- **appliesTo**: `web`, `api` / **methods**: `TEST` (`SAFE_ACTIVE`)
- **selector**: `environment.testOrigin exists` AND `capabilities.authentication = detected`
- **탐지**: 하나의 합성 계정에 **잘못된 비밀번호로 소수 회(기본 6회)** 연속 로그인 시도. 모든 시도가 동일하게 처리되고(레이트 리밋/잠금/CAPTCHA 신호 없이 계속 401/400) 응답 시간도 늘지 않으면 무차별 대입 방어가 없는 것으로 본다. 방어가 있으면 429(Too Many Requests)·잠금 메시지·지연 증가 등이 관측된다.
- **expectedResult**: 연속 실패 시 차단(429/잠금)이 나타나야 함.
- **선행조건**: `authorized_test_deployment`, 로그인 엔드포인트. 없으면 `coverage_gap`.
- **비파괴·저빈도**: 잘못된 비밀번호로만(로그인 성공 없음), `maxRequests` 낮게, 짧은 간격이되 총 시도 수 제한. **실제 사용자 계정 금지 — 합성 이메일만**. DoS로 오인되지 않게 소량.
- **증거**: 시도별 상태코드·시간 시퀀스, 스캐너 출력(차단 신호 유무).
- **재검증**: `probe-bruteforce` — 수정 후 연속 실패가 429/잠금으로 차단됨.
- **수정 경로**: `app/**`, `src/**`, 미들웨어. `productionChange: approval_required`.

#### B-3. 사용자 열거 — `[구현됨: WEB-010]`
- **표준**: OWASP A07:2021 · ASVS 2.2.2 · WSTG-ATHN-03 · CWE-204
- **appliesTo**: `web`, `api` / **methods**: `TEST` (`SAFE_ACTIVE`)
- **selector**: `environment.testOrigin exists` AND `capabilities.authentication = detected`
- **탐지**: 로그인(또는 비밀번호 찾기) 엔드포인트에 **두 가지 프로브**를 보낸다 — (a) 존재하지 않는 임의 이메일 + 잘못된 비밀번호, (b) 존재할 법한/등록 이메일 + 잘못된 비밀번호. 두 응답의 **상태코드·본문 메시지·응답 시간**이 유의미하게 다르면 계정 존재가 노출됨(열거 가능).
- **expectedResult**: 두 프로브의 응답이 사실상 동일(계정 존재를 구분 불가)해야 함.
- **선행조건**: `authorized_test_deployment`, 로그인 엔드포인트 경로. 없으면 `coverage_gap`.
- **비파괴 근거**: 잘못된 비밀번호로만 시도하므로 로그인에 성공하지 않는다(상태 변경 없음). 요청 수 상한(2~4회)·저빈도로 무차별 대입과 구분.
- **증거**: 두 프로브의 요청/응답(상태·메시지 차이·시간차), 스캐너 출력(판정 근거).
- **재검증**: `probe-user-enumeration` — 수정 후 두 응답이 동일(일반 메시지·균일 타이밍)해짐.
- **수정 경로**: `app/**`, `src/**`. `productionChange: approval_required`.
- **⚠ 주의**: 반드시 등록·검증된 대상에만. 실제 사용자 계정 대상 반복 시도 금지(테스트 계정/합성 이메일). `safeFetch`의 POST 프로브 옵트인(`allowUnsafeMethod`)으로만 전송하고 SSRF 가드를 유지한다.

#### B-4. 세션 토큰/쿠키 속성 — `[구현됨: WEB-012]`
- **표준**: OWASP A05:2021 · ASVS 3.4 · WSTG-SESS-02 · CWE-614/1004/1275
- **appliesTo**: `web`, `api` / **methods**: `CONFIG` (`SAFE_ACTIVE`)
- **selector**: `environment.testOrigin exists`
- **탐지**: 배포 origin에 읽기 전용 GET(`safeFetch`)을 보내 응답의 `Set-Cookie` 헤더를 관측한다. 쿠키에 `HttpOnly`·`Secure`·`SameSite` 속성이 빠졌으면 각각 신호. (세션 고정=로그인 후 토큰 미회전은 로그인 흐름이 필요해 향후 확장.)
- **expectedResult**: 세션성 쿠키에 `HttpOnly` + `Secure` + `SameSite`(Lax/Strict) 모두 존재.
- **선행조건**: `authorized_test_deployment`. `Set-Cookie`가 없으면 관측 불가 → `coverage_gap`.
- **실행**: 비파괴 GET 1~2회. `safeFetch` 사용.
- **증거**: 관측된 `Set-Cookie` 값(값 자체는 마스킹), 누락 속성 목록.
- **재검증**: `probe-cookie-flags` — 수정 후 쿠키에 세 속성이 모두 존재.
- **수정 경로**: `app/**`, `src/**`(쿠키 설정 코드). `productionChange: approval_required`.
- **⚠ 마스킹**: 쿠키 값은 세션 토큰이므로 저장·표시 전 마스킹(`maskSecret`).

---

### C. 설정 · 전송 (Configuration & Transport)

#### C-1. 보안 헤더 & CORS — `[구현됨: WEB-007]`
- **표준**: OWASP A05:2021 · ASVS 14.4/14.5 · WSTG-CONF-07/CLNT · CWE-693/942
- **appliesTo**: `web`, `api` / **methods**: `CONFIG` (`SAFE_ACTIVE`, 배포 URL 없으면 정적 설정으로 대체)
- **탐지**:
  - 필수 헤더 부재: CSP, X-Frame-Options, X-Content-Type-Options, HSTS. (현재 `headerScanner`의 `REQUIRED_HEADERS`)
  - 위험한 CORS: `Access-Control-Allow-Origin: *` + `Allow-Credentials: true`.
- **증거**: 실제 HTTP 응답 헤더(읽기전용 GET) 또는 `next.config` 정적 설정.
- **수정 경로**: `next.config.js`/`next.config.mjs`, `src/**`.
- **⚠ SSRF 주의(도구 구현 시)**: 대상 URL로 요청 보내기 전 **사설/링크로컬/루프백 대역 차단**(127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1). 리다이렉트는 `manual`로 받고 재검증. URL 소유권 검증 선행. → §3 참조.

#### C-2. 평문 HTTP / TLS 미강제 — `[구현됨: WEB-009]`
- **표준**: OWASP A05:2021 · ASVS 9.1/9.2 · WSTG-CONF-* · CWE-319
- **appliesTo**: `web`, `api` / **methods**: `CONFIG` (`SAFE_ACTIVE`)
- **selector**: `environment.testOrigin exists` (배포 URL 필요)
- **탐지**: 배포 origin을 http로 시도했을 때 https로 **리다이렉트되지 않으면**(평문 허용) 취약. 또한 https 응답에 **HSTS(Strict-Transport-Security) 헤더가 없으면** 취약. 둘을 별개 신호로 관측한다.
- **expectedResult**: http→https 리다이렉트 존재 + HSTS 헤더 존재.
- **선행조건(CONFIG)**: `authorized_test_deployment`. 없으면 `coverage_gap`(정적 대체 없음).
- **실행**: `safeFetch`로 읽기 전용 GET(리다이렉트 수동 관측). 요청 상한 낮게.
- **증거**: http 요청·응답(리다이렉트 여부/Location), https 응답 헤더(HSTS 유무).
- **재검증**: `probe-tls` — 수정 후 http→https 리다이렉트 + HSTS 존재.
- **수정 경로**: `next.config.js`/`next.config.mjs`, 호스팅 설정. `productionChange: approval_required`.
- **⚠ 주의**: `safeFetch`가 http 스킴도 SSRF 검사 후 허용하므로 내부 대역은 자동 차단됨. `maxRedirects`를 1~2로 두어 리다이렉트 체인 관측만 한다.

#### C-3. 노출된 관리/디버그 엔드포인트 — `[구현됨: WEB-008]`
- **표준**: OWASP A05:2021 · ASVS 14.3 · WSTG-CONF-05 · CWE-489
- **appliesTo**: `web`, `api` / **methods**: `CONFIG` (`SAFE_ACTIVE`)
- **selector**: `environment.testOrigin exists` (배포 URL이 있어야 능동 점검)
- **탐지**: 배포 URL 기준으로 흔히 노출되는 민감 경로에 **읽기 전용 GET**(SSRF 안전 계층 경유)을 보내 200으로 응답하는지 확인: `/.env`, `/.git/config`, `/.git/HEAD`, `/config.json`, `/.next/`, `.map`(소스맵), `/server-status`, `/debug` 등.
- **expectedResult**: 위 경로는 접근 불가(4xx)여야 함. 200/노출이면 취약(denied 기대인데 allowed로 관측됨).
- **선행조건(CONFIG)**: `authorized_test_deployment`(배포 URL). 없으면 `coverage_gap`(정적 대체 없음 — "안전" 오판 금지).
- **실행 상한**: `maxRequests` 낮게(경로 목록만), `timeoutSeconds` 짧게, 비파괴.
- **증거**: 노출 경로별 요청/응답(상태코드), 스캐너 출력(노출 경로 목록). 응답 본문은 마스킹·소량만.
- **재검증**: `probe-exposed-paths` — 수정 후 동일 경로가 4xx로 차단됨(현재 MVP는 관측 기반).
- **⚠ 안전**: 반드시 `safeFetch`(SSRF 차단·리다이렉트 재검증·상한) 사용. 임의 URL·내부 대역 금지.
- **수정 경로**: `next.config.js`/`next.config.mjs`, 배포/호스팅 설정. `productionChange: approval_required`.

---

### D. 비밀정보 · 데이터 보호

#### D-1. 하드코딩된 비밀정보 — `[구현됨: SEC-001]`
- **표준**: OWASP A07:2021 · ASVS 6.4/14.1 · WSTG-* · CWE-798
- **appliesTo**: `web`, `api`, `baas` / **methods**: `SAST` (`PASSIVE`)
- **탐지**: 소스/설정에서 시크릿 패턴(서비스 롤 키, DB 비밀번호, `api_key/secret/token` 리터럴).
- **증거**: **반드시 마스킹**(`maskSecret`). 원문 저장 금지.
- **수정 경로**: `app/**`, `src/**`, `.env*`. **운영 반영은 approval_required**(노출 키 폐기·교체는 사람이).
- **확장**: git 히스토리 스캔(Gitleaks), 커밋 diff 스캔(`changed-code-scan`).

#### D-2. 민감정보 응답 과다 노출 — `[구현됨: WEB-005]`
- **표준**: OWASP API3:2023 · ASVS 8.1 · WSTG-* · CWE-213
- **appliesTo**: `api`, `web` / **methods**: `SAST` (`PASSIVE`)
- **selector**: `components.kind contains api`
- **탐지**: API 라우트가 사용자/DB 레코드를 응답에 반환하면서 민감 필드(`password`, `passwordHash`, `password_hash`, `ssn`, `secret`, `token`)를 화이트리스트로 걸러내지 않고 그대로 직렬화하는지. SAST 신호: `res.json(user)`/`return ... user` 처럼 전체 객체를 반환하고, 인근에 `select`/필드 화이트리스트/`delete user.password` 같은 정제가 없음.
- **expectedResult**: 응답 본문에 민감 필드가 **포함되지 않아야** 함(denied).
- **선행조건(SAST)**: `source_checkout`
- **증거**: 취약 라우트 소스(민감 필드 반환 라인), 스캐너 출력(탐지 필드 목록).
- **재검증**: `changed-code-scan` — 수정 후 소스에서 동일 민감 필드 반환 신호가 사라짐.
- **수정 경로**: `app/**`, `src/**` (branch_only).

---

### E. 의존성 · 공급망

#### E-1. 취약한 의존성 (SCA) — `[구현됨(실제 OSV.dev): SEC-004]`
- **표준**: OWASP A06:2021 · ASVS 14.2 · CWE-1035/1104
- **appliesTo**: `web`, `api`, `baas` / **methods**: `CONFIG` (`PASSIVE`)
- **selector**: `capabilities.lockfile = detected`
- **탐지**: `package.json`의 dependencies/devDependencies를 **OSV.dev `/v1/querybatch`** 에 배치 조회하고, 취약점이 있는 패키지의 상세(`/v1/vulns/{id}`)로 CVSS·수정 버전을 채운다. 구현: `src/lib/net/osv.ts` + `dependencyScanner.ts`.
- **네트워크 실패 시**: 실시간 조회 불가로 두고, 최소 오프라인 목록으로만 판정한다(그 finding은 `simulated:true`로 명시). 조회 못 했다고 "안전"으로 단정하지 않는다.
- **전송 데이터**: 공개 패키지명·버전만. 대상 앱의 코드·비밀은 전송하지 않는다.
- **증거**: OSV 취약점 ID·CVSS·수정 버전, package.json 라인.
- **수정 경로**: `package.json`, `package-lock.json` (branch_only).

---

### F. 입력 검증 (Injection)

#### F-1. SQL/NoSQL 인젝션 — `[구현됨(SAST): WEB-004]`
- **표준**: OWASP A03:2021 · ASVS 5.3.4 · WSTG-INPV-05 · CWE-89
- **appliesTo**: `web`, `api` / **methods**: `SAST` (`PASSIVE`) — (TEST 격리 재현은 향후 확장)
- **selector**: `components.kind contains api` OR `components.kind contains web`
- **탐지**: 문자열 연결/템플릿 리터럴로 조립된 쿼리(`query(\`... ${..} ...\`)`, `"SELECT ... " + var`)나 미파라미터화 실행.
- **expectedResult**: 쿼리는 파라미터 바인딩을 사용해야 함(취약 신호 없음 = allowed).
- **선행조건(SAST)**: `source_checkout`. 증거: 취약 라인 소스 + 스캐너 출력. 재검증: `changed-code-scan`.

#### F-2. XSS (DOM/저장) — `[구현됨(SAST): WEB-003]`
- **표준**: OWASP A03:2021 · ASVS 5.3.3 · WSTG-INPV-01/02 · CWE-79
- **appliesTo**: `web` / **methods**: `SAST` (`PASSIVE`) — (동적 반사 확인은 향후 SAFE_ACTIVE 확장)
- **selector**: `components.kind contains web`
- **탐지**: `dangerouslySetInnerHTML`, `element.innerHTML =`, `document.write(` 에 정적 상수가 아닌 값이 들어가는지.
- **expectedResult**: 사용자 제어 값이 인코딩 없이 DOM에 들어가지 않아야 함(취약 신호 없음).
- **선행조건(SAST)**: `source_checkout`. 증거: 취약 라인 소스 + 스캐너 출력. 재검증: `changed-code-scan`.

#### F-3. 커맨드/역직렬화 인젝션 — `[구현됨(SAST): WEB-004]`
- **표준**: ASVS 5.2/5.5 · WSTG-INPV-* · CWE-77/94/502
- **appliesTo**: `web`, `api` / **methods**: `SAST` (`PASSIVE`)
- **탐지**: `eval(`, `new Function(`, `child_process`의 `exec(`에 변수 삽입. WEB-004 규칙의 checks에 함께 포함.
- **expectedResult/선행조건/증거/재검증**: F-1과 동일(WEB-004로 통합).

---

### G. BaaS / 클라우드 설정

#### G-1. Supabase RLS(행 수준 보안) — `[구현됨(정적 SQL 분석): BAAS-001]`
- **표준**: OWASP A01:2021 · ASVS 4.2 · CWE-284
- **appliesTo**: `baas` / **methods**: `CONFIG` (`PASSIVE`)
- **selector**: `components.kind contains baas`
- **탐지**: 프로젝트의 Supabase SQL(`supabase/schema.sql`, `supabase/migrations/**`, `supabase/policies.sql`)을 정적 분석한다. 각 `create table public.X`에 대해 (1) `alter table public.X enable row level security`가 있는지, (2) RLS를 켠 테이블에 `create policy ... on public.X`가 하나 이상 있는지 확인. RLS 미설정 테이블(high) 또는 RLS만 켜고 정책이 없는 테이블(정책 없으면 기본 거부지만 설계 미완으로 medium)을 보고.
- **expectedResult**: 모든 사용자 데이터 테이블에 RLS 활성 + 소유자 제한 정책 존재.
- **선행조건(CONFIG)**: `source_checkout`(SQL 파일). SQL 파일이 없으면 `coverage_gap`.
- **증거**: 취약 테이블 목록, 해당 `create table` SQL 라인, 스캐너 출력.
- **재검증**: `changed-code-scan` — 수정 후 SQL에 RLS enable + 정책이 추가됨.
- **수정 경로**: `supabase/migrations/**`, `supabase/policies.sql`. 운영 반영 approval_required.
- **참고(로드맵)**: 실서비스에서는 Supabase Management API로 **실제 배포된** RLS 상태를 조회하고, 사용자 세션(anon/authenticated, 서비스 롤 아님)으로 교차 접근을 TEST로 재현하는 확장이 가능.

---

## 3. 도구 구현 시 안전 규칙 (능동 검사 공통)

WSTG를 이 엔진에서 "실제로 돌릴 때" 반드시 지킬 것 (`executionGate.ts`/README "Safe DAST note"와 일치):

1. **읽기 전용·비파괴 우선.** `SAFE_ACTIVE`는 상태를 바꾸지 않는 GET/HEAD 위주. 상태 변경(`update`/`delete`) 재현은 `ISOLATED_ACTIVE`(격리 환경)에서만.
2. **대상 소유권 검증.** 등록·검증된 배포 도메인만. 임의 URL로 스캔 금지.
3. **요청 상한.** 규칙의 `maxRequests`/`timeoutSeconds` 준수(DoS·무차별 대입 방지).
4. **SSRF 차단.** 대상 URL 해석 후 내부/메타데이터 대역 차단, 리다이렉트 수동 처리. → **`src/lib/net/safeFetch.ts`가 이 규칙을 코드로 강제한다**(사설/루프백/링크로컬/유니크로컬/메타데이터 차단, DNS 해석 후 검사, 홉마다 재검증, GET/HEAD만, 타임아웃·본문 크기 상한). 능동 검사 스캐너는 반드시 `safeFetch`만 사용한다.
5. **tier 승격 금지.** 배포 URL 없으면 정적(`PASSIVE`)까지만. `PATCH`/`PRIVILEGED_CHANGE`는 별도 승인 흐름.
6. **증거 마스킹.** 시크릿·PII는 저장·표시 전 마스킹.
7. **미검사 정직성.** 선행조건 부족·도구 실패는 `coverage_gap`/`NOT_TESTED`. 절대 "통과/안전"으로 표시하지 않는다.

---

## 4. 새 규칙 추가 체크리스트 (개발자용)

`src/lib/rules/definitions.ts`에 규칙 하나를 추가할 때:

- [ ] `id`(전역 유일, 예 `WEB-003`) + `version` 부여
- [ ] `standards`에 정확한 표준 id(예 `API3:2023`) — **임의 생성 금지**(registry가 검증)
- [ ] `appliesTo` / `selector`(엔진이 아는 연산자 `equals`·`contains`·`in`·`exists`만)
- [ ] `methods`와 `checks[].method` 일치
- [ ] `checks[].toolId`가 `toolCatalog.ts`에 등록됨 (없으면 도구 먼저 등록)
- [ ] `execution.tier`가 검사 위험도에 맞고 `destructiveOperations: false`
- [ ] `prerequisites`에 방법별 선행조건 명시(부족 시 자동 coverage_gap)
- [ ] `verificationRequiredChecks`에 **공격 차단 + 정상 기능 보존** 검사 모두 포함
- [ ] `remediation.allowedPaths`와 `productionChange`(approval_required/not_applicable)
- [ ] 스캐너 구현을 `scannerBinding.ts`의 `SCANNER_TO_RULE` + `ruleIdForVerificationKey`에 연결

검증 실패한 규칙은 레지스트리에 **적재되지 않는다**(`registry.ts` — 개발 중 콘솔 경고).

---

## 5. 커버리지 현황 요약

| 카테고리 | 검사 항목 | 상태 |
|---|---|---|
| 접근제어 | IDOR/BOLA (A-1) | ✅ WEB-002 구현(실제 재현+재검증) |
| 접근제어 | 경로 트래버설 (A-3) | ✅ WEB-006 구현(SAST+재스캔 검증) |
| 접근제어 | BFLA (A-2) | ✅ WEB-013 구현(ISOLATED_ACTIVE, 권한별 대조) |
| 인증 | 무인증 API (B-1) | ✅ WEB-001 규칙 존재 |
| 인증 | 사용자 열거 (B-3) | ✅ WEB-010 구현(SAFE_ACTIVE, 비파괴 로그인 프로브) |
| 인증 | 무차별대입 방어 (B-2) | ✅ WEB-011 구현(SAFE_ACTIVE, 저빈도 프로브) |
| 인증 | 세션 쿠키 속성 (B-4) | ✅ WEB-012 구현(SAFE_ACTIVE, Set-Cookie 관측) |
| 설정 | 헤더·CORS (C-1) | ✅ WEB-007 구현(실제 GET) |
| 설정 | 노출 엔드포인트 (C-3) | ✅ WEB-008 구현(SAFE_ACTIVE, SSRF 안전 fetch) |
| 설정 | TLS 미강제 (C-2) | ✅ WEB-009 구현(SAFE_ACTIVE, http→https/HSTS 관측) |
| 비밀정보 | 하드코딩 시크릿 (D-1) | ✅ SEC-001 구현 |
| 비밀정보 | 응답 과다노출 (D-2) | ✅ WEB-005 구현(SAST+재스캔 검증) |
| 공급망 | 취약 의존성 (E-1) | ✅ SEC-004 실제 OSV.dev 조회(오프라인 폴백) |
| BaaS | Supabase RLS (G-1) | ✅ BAAS-001 실제 정적 SQL 분석(RLS/정책) |
| 입력검증 | XSS (F-2) | ✅ WEB-003 구현(SAST+재스캔 검증) |
| 입력검증 | SQL·커맨드·eval 인젝션 (F-1/F-3) | ✅ WEB-004 구현(SAST+재스캔 검증) |


> 참고: WEB-003/004/005/006은 정적(PASSIVE SAST) 신호 기반이다. `testStatus`는 재현 전 `SUSPECTED`이며, 동적 재현(SAFE_ACTIVE/ISOLATED_ACTIVE)은 향후 확장 항목이다. 스캐너 구현은 `src/lib/scanners/staticWebScanner.ts`, 규칙은 `src/lib/rules/definitions.ts`.

---

_출처: 항목 번호·구조는 OWASP ASVS 4.0.3 및 WSTG v4.2를 참조했으며, 설명은 본 엔진의 규칙 스키마에 맞게 재구성했습니다(라이선스 준수를 위해 원문을 그대로 옮기지 않고 재서술)._
