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
  return (
    <html lang="ko">
      <body>
        <a href="#main-content" className="skip-link">
          본문으로 바로가기
        </a>
        {children}
      </body>
    </html>
  );
}
