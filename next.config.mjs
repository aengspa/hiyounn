/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // 빌드 때 받은 gitleaks(scripts/fetch-gitleaks.mjs)를 점검·재검증을 돌리는 함수에 넣는다.
    // 파일이 없으면(Windows·macOS 빌드, 받기 실패) 아무것도 넣지 않는다.
    outputFileTracingIncludes: {
      "/api/projects/*/scan": ["./vendor-bin/gitleaks/**"],
      "/api/findings/*/verify": ["./vendor-bin/gitleaks/**"],
      "/api/fix-jobs/*/verify": ["./vendor-bin/gitleaks/**"],
    },
  },
};

export default nextConfig;
