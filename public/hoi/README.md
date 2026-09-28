# HOI assets

호이는 외부 이미지 파일 대신 `src/components/mascot/Hoi.tsx`의 직접 작성한 인라인 SVG로 제공됩니다. `welcome`, `guide`, `searching`, `thinking`, `concerned`, `cheer`, `celebrate`, `rest` 상태를 같은 캐릭터 구조로 재사용할 수 있습니다.

접근성 사용법:

```tsx
<Hoi mood="welcome" size="lg" />
<Hoi mood="rest" decorative />
```

의미를 전달하는 경우 기본 `aria-label`/`title`을 사용하고, 주변 텍스트와 의미가 중복되는 장식용 이미지는 `decorative`를 지정하세요. 출처와 권리 확인 메모는 `SOURCES.md`를 확인하세요.
