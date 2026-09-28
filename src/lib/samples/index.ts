import { MEMO_BOARD_FILES } from "@/lib/samples/memo-board.generated";

/**
 * 제품에 들어 있는 체험용 샘플 앱. 소스 코드만 담는다: 점검 결과·수정안을 미리 만들어
 * 두지 않으므로, 샘플을 추가하면 보통 프로젝트처럼 점검·수정·재검증이 매번 실제로 돈다.
 * 원본은 samples/<id>/ 폴더이고 `npm run samples`로 이 모듈과 ZIP을 다시 만든다.
 */
export interface SampleApp {
  id: string;
  name: string;
  description: string;
  zipPath: string;
  files: Record<string, string>;
}

export const SAMPLE_APPS: SampleApp[] = [
  {
    id: "memo-board",
    name: "메모 보드 (샘플)",
    description: "로그인·메모 검색·링크 미리보기가 있는 작은 Express 앱이에요. 연습용으로 일부러 취약하게 만들었어요.",
    zipPath: "/samples/memo-board-sample.zip",
    files: MEMO_BOARD_FILES,
  },
];

export function getSampleApp(id: string): SampleApp | undefined {
  return SAMPLE_APPS.find((s) => s.id === id);
}
