# 보안 규칙 v2 통합

`definitions_scan.ts`의 46개 규칙은 `src/lib/rules/definitions.ts`,
`definitions_scanner.ts`의 14개 가드는 `src/lib/scanners/definitions.ts`에 통합했다.
공유 타입은 `src/lib/rules/types.ts` 한 곳에 둔다. 기존 `RuleCheck`,
`RuleExecution`, `RuleRemediation`, `ScanMethod` 이름은 호환용으로 유지한다.

추가 필드는 `mode`, `family`, `summaryKo`, `produces`, `coverageGap`,
`check.when/params/confidence`, `remediation.manualStepsKo`, BaaS 대상 및 신규 표준 참조다.
중첩 selector와 `not_equals`도 검증·평가한다. 첨부 규칙의 `BAAS-003`,
`WEB-002`는 SAST 체크를 선언했지만 methods에서 누락했으므로 methods/prerequisites를 보완했다.
규칙 다이제스트는 전체 선언의 SHA-256으로 계산한다.

## 새 도구

| toolId | 실제 검사 | 구현 |
| --- | --- | --- |
| `package_provenance_checker` | npm 존재 여부, 이름 유사성, 설치 스크립트, 생성 시점·주간 다운로드 | `sourceRuleTools.ts` |
| `llm_integration_analyzer` | 프롬프트 주변 비밀, 출력→실행, 도구 권한, HTML 렌더링 정적 신호 | `sourceRuleTools.ts` |
| `bundle_secret_scanner` | 같은 origin의 HTML/JS 비밀 패턴과 공개 BaaS 연결 추출 | `deployedRuleTools.ts` |
| `redirect_probe` | 예약 `.invalid` canary에 대한 3xx Location 관측 | `deployedRuleTools.ts` |
| `error_probe` | 지정한 검증 API에 깨진 JSON/타입 입력 후 내부 오류 신호 확인 | `deployedRuleTools.ts` |
| `llm_prompt_probe` | 전용 LLM 테스트 API에 최대 3개 요청, 비공개 canary/비밀 패턴 확인 | `deployedRuleTools.ts` |
| `baas_access_probe` | Supabase 익명 조회/버킷 목록, Firebase DB/Storage 조회, 테스트 행 교차 접근·원복 | `accountRuleTools.ts` |
| `jwt_tamper_probe` | 익명·정상 토큰 대조 후 alg-none, 서명 제거, subject 변경 | `accountRuleTools.ts` |

`newRuleTools.ts`는 명시적으로 지원하는 체크를 실제 핸들러에 연결한다.
도구 실패, 응답 상한, 누락된 입력, 기존 스캐너가 아직 지원하지 않는 추가 체크는
`coverageGaps`에 남긴다. `selectedChecks`는 실행 가능한 체크를 나타내며 안전 인증이 아니다.
소스/배포 변형은 `family`로 리포트 요약에서 묶되 개별 finding과 증거는 보존한다.
새 finding은 별도 기능 회귀 계약이 없으므로 자동으로 최종 해결 상태로 바꾸지 않는다.

## 서버 입력과 실행 제약

기존 웹 폼의 동의 체크박스만으로 능동 검사를 승인하지 않는다.
실제 대상은 서버의 `ProjectContext.ownershipProof`가 필요하다. 서버가 발급한
32바이트 이상의 토큰, 정확한 hostname, 유효한 만료 시각, `dns_txt` 또는
`well_known_file` 방식으로 구성하고 스캔 직전에 증명을 재확인한다.
현재 웹 폼/저장소는 증명 발급·계정 입력 UI를 제공하지 않는다. 서버 호출부에서
아래 입력을 연결하기 전에는 관련 검사가 coverage gap으로 남는 것이 정상이다.
`ownershipVerified`나 `linkedBaasProjects`를 클라이언트 요청의 값으로 신뢰해서는 안 된다.

- `scanMode`: A/B/C. 생략 시 소스 전용 A, URL이 있으면 B, 내부 데모는 C.
- `ownershipProof`: 서버가 발급·보관한 정확한 호스트/토큰/만료/검증 방식.
- `testSessions`: C 모드 테스트 전용 A/B 세션과 보호된 읽기 전용 `probeUrl`.
- `testObjects`: A/B 소유 테스트 객체 식별자.
- `probeEndpoints.redirect`: 검증된 origin 안의 실제 리다이렉트 경로. 생략 시 입력 URL만 검사한다.
- `probeEndpoints.invalidJson`: 입력 검증이 비즈니스 부작용보다 먼저 실행되는 테스트 API.
- `llmProbeEndpoint`, `llmPrivateMarkers`: 비용 상한을 갖춘 전용 LLM API와 비공개 canary.
- `baasTestFixture`: B 소유의 폐기 가능한 행. 수정은 `vsa_probe_` 테스트 필드만 허용한다.
  원복 값과 현재 행이 일치해야 하며 B 세션으로 원복을 확인한다. 원복에는 독립된 시간 예산을 예약한다.

세션·행 값·모델 응답·비밀 키 원문은 새 도구의 finding 증거에 저장하지 않는다.
공개 BaaS 데이터와 정적 LLM 신호는 공개 의도/안전한 코드일 수 있어 `SUSPECTED`로 보고한다.
JWT는 익명 거부와 정상 토큰 허용이 성립하고 변조 응답이 정상 보호 응답과 같은 경우만 확정한다.
일반 HTTP 200 페이지는 인증 우회로 간주하지 않는다.

새 능동 요청은 규칙별 요청/시간 상한, 같은 origin 확인, 리다이렉트 미추적을 적용한다.
공통 `safeFetch`는 검증한 DNS 주소로 연결을 고정하고 응답 읽기에도 시간 상한을 적용한다.
IPv4-mapped IPv6/사설/메타데이터 주소를 차단한다.
14개 가드 전체가 구현됐다는 뜻은 아니다. 워커 격리·서비스 전체 속도/동시성 제한,
자격증명 암호화 보관·삭제, 감사/보존 정책 등은 플랫폼 통합이 필요하다.
`assertGuardsReady`에는 실제로 강제·검증한 가드만 등록해야 한다.

## 서비스 식별자와 CAPEC 확인

서비스 이름 Vibe Security Agent와 실제 저장소 주소를 사용한다.
배포된 서비스 정보 페이지 주소는 저장소에서 확인할 수 없어 주소를 만들어 넣지 않았다.

- User-Agent: `VibeSecurityAgent/0.2 (+https://github.com/aengspa/hiyounn)`
- DNS TXT: `_vibe-security-agent-verify.<target-host>`
- 파일 검증: `/.well-known/vibe-security-agent-verification.txt`

2026-09-28에 MITRE 공식 페이지에서 확인했으며 CAPEC 참조는 **3.9**로 고정했다.
[CAPEC-178](https://capec.mitre.org/data/definitions/178.html)은 `Cross-Site Flashing`이라는
**Detailed** 패턴이다. CWE-601을 관련 약점으로 연결하지만 범용 오픈 리다이렉트의
상위 패턴은 아니므로 WEB-022/B에서 기술 특화된 **간접 매핑**임을 명시한다.
[CAPEC-116](https://capec.mitre.org/data/definitions/116.html)은 `Excavation`이라는 **Meta** 패턴이며,
상세 오류/응답을 통해 정보를 수집하는 공격을 설명하고 과다 출력 최소화를 완화책으로 제시한다.
WEB-005의 과다 응답 노출에는 이 메타 패턴을 사용한다.

## 검증

`npm run verify:rules`, `npm run verify:definitions`, `npx tsc --noEmit`, `npm run build`.
새 도구 회귀 테스트는 주입한 응답을 사용하므로 실제 사용자 대상에 점검 요청을 보내지 않는다.
패키지 설치 시 기존 고정 의존성 Next.js/PostCSS의 npm audit 경고가 관측됐다.
이 변경에서 프레임워크 메이저 버전 업그레이드는 수행하지 않았다.
