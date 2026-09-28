import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "호이 보안 코치 — 같이 튼튼하게 만들어요",
    template: "%s | 호이 보안 코치",
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
