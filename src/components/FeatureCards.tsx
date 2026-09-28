import { Card } from "@/components/ui";

type Item = { title: string; body: string };

const ITEMS: Item[] = [
  {
    title: "확인한 근거",
    body: "확인 가능한 코드와 요청·응답 기록을 결과와 함께 보여드려요. 자동 분석의 판단은 근거와 점검 범위를 함께 살펴봐 주세요.",
  },
  {
    title: "고친 뒤 다시 확인",
    body: "같은 문제가 다시 나타나는지와 확인 가능한 기본 기능이 그대로 동작하는지 살펴봐요. 확인하지 못한 범위도 함께 알려드려요.",
  },
  {
    title: "쉬운 설명부터",
    body: "전문 용어보다 내 서비스와 사용자에게 어떤 영향이 있는지 먼저 설명하고, 기술 정보는 필요할 때 펼쳐볼 수 있어요.",
  },
];

export function FeatureCards() {
  return (
    <section aria-label="호이의 점검 원칙" className="mx-auto grid max-w-4xl gap-4 pb-20 md:grid-cols-3">
      {ITEMS.map((item) => (
        <Card key={item.title} variant="raised" className="min-w-0 p-5 text-center sm:p-6">
          <h3 className="break-keep text-xl font-black text-ink">{item.title}</h3>
          <p className="mt-3 break-keep text-sm leading-relaxed text-ink-subtle">{item.body}</p>
        </Card>
      ))}
    </section>
  );
}
