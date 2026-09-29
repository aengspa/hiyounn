import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "코치코치 호이 — 같이 튼튼하게 만들어요",
    template: "%s | 코치코치 호이",
  },
  description:
    "호이가 코드의 약한 곳을 쉬운 말로 알려드리고, 고친 뒤 잘 막혔는지 한 번 더 확인해요.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // body의 `isolate`: body를 쌓임 맥락으로 만들어 z-index:-1 배경 장식(.hoi-page-decor)이
  // globals.css의 불투명한 body 배경 뒤로 숨지 않고 그 위(본문 아래)에 보이게 한다.
  return (
    <html lang="ko">
      <head>
        {/* Pretendard(버전 고정). 불러오지 못하면 globals.css의 시스템 한글 글꼴로 대체된다. */}
        <link rel="preconnect" href="https://cdn.jsdelivr.net" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css"
          crossOrigin="anonymous"
        />
      </head>
      <body className="isolate">
        <div className="hoi-page-decor" aria-hidden="true" />
        <a href="#main-content" className="skip-link">
          본문으로 바로가기
        </a>
        {children}
      </body>
    </html>
  );
}
