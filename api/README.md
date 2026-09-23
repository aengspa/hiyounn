# 서버리스 함수 (`/api`)

Vercel 배포 환경에서 동작하는 서버리스 함수 폴더입니다. 이 폴더의 각 파일은
`https://<도메인>/api/<파일명>` 경로의 함수로 배포됩니다.

## `chat.js` — 챗 프록시

제공자 무관 LLM 챗 프록시입니다. API 키는 **코드에 두지 않고** 환경변수로만
읽습니다.

### 요청

```
POST /api/chat
Content-Type: application/json

{
  "system": "선택. 시스템 프롬프트",
  "messages": [
    { "role": "user", "content": "안녕" }
  ]
}
```

### 응답

```json
{ "reply": "..." }
```

## 환경변수 (Vercel Project → Settings → Environment Variables)

| 이름 | 필수 | 설명 |
|---|---|---|
| `LLM_API_KEY` | 예 | 제공자 API 키 (절대 코드/깃에 넣지 말 것) |
| `LLM_PROVIDER` | 아니오 | `openai`(기본) \| `anthropic` \| `gemini` |
| `LLM_MODEL` | 아니오 | 모델명. 미지정 시 제공자별 기본값 사용 |
| `ALLOWED_ORIGIN` | 아니오 | CORS 허용 오리진. 미지정 시 `*` (배포 시 사이트 URL로 제한 권장) |

## 주의

- 로컬 `npm run dev`(Next.js)에서는 이 함수가 실행되지 않습니다.
  로컬에서 테스트하려면 `vercel dev`를 사용하세요.
- 실제 키는 `.env.local`(깃 제외)이나 Vercel 대시보드에만 두고,
  저장소에는 절대 커밋하지 마세요.
