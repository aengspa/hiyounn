"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceCode, setSourceCode] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [deploymentAuthorized, setDeploymentAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      // ZIP 업로드가 있으면 multipart로, 아니면 붙여넣은 소스로 생성.
      const authorized = !!deploymentUrl.trim() && deploymentAuthorized;
      const res = zipFile
        ? await fetch("/api/projects/upload", {
            method: "POST",
            body: buildUploadForm({
              name,
              repositoryUrl,
              deploymentUrl,
              zipFile,
              deploymentAuthorized: authorized,
            }),
          })
        : await fetch("/api/projects", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name,
              repositoryUrl,
              deploymentUrl,
              sourceCode,
              deploymentAuthorized: authorized,
            }),
          });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.error) {
        setError(data?.error ?? "프로젝트를 만들 수 없습니다.");
        setSubmitting(false);
        return;
      }
      router.push(`/dashboard/projects/${data.project.id}`);
    } catch {
      setError("네트워크 오류입니다. 다시 시도해 주세요.");
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        title="프로젝트 추가"
        subtitle="저장소와 배포 주소를 연결하면 에이전트가 무엇을 점검할지 파악합니다."
        backHref="/dashboard"
        backLabel="프로젝트"
      />
      <main className="mx-auto max-w-2xl px-6 py-8">
        <form
          onSubmit={submit}
          className="space-y-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm"
        >
          <Field label="프로젝트 이름" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="예: 내 노트 앱"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <p className="text-sm font-medium text-slate-700">
              소스 코드 제공 방법 (둘 중 하나)
            </p>
            <p className="mt-1 text-xs text-slate-500">
              정적 분석(IDOR·XSS·인젝션·시크릿)은 <strong>제공된 소스 파일만</strong>{" "}
              검사합니다. ZIP 업로드가 붙여넣기보다 정확합니다(여러 파일·경로 유지).
            </p>
          </div>

          <Field
            label="프로젝트 ZIP 업로드 (권장)"
            hint="프로젝트 폴더를 zip으로 올리면 소스 파일을 추출해 검사합니다. node_modules·빌드 산출물·바이너리는 자동 제외됩니다."
          >
            <input
              type="file"
              accept=".zip,application/zip"
              onChange={(e) => setZipFile(e.target.files?.[0] ?? null)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm file:mr-3 file:rounded file:border-0 file:bg-brand-600 file:px-3 file:py-1.5 file:text-white outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
            {zipFile && (
              <span className="mt-1 block text-xs text-emerald-700">
                선택됨: {zipFile.name} · 붙여넣기 대신 ZIP을 사용합니다.
              </span>
            )}
          </Field>

          <Field
            label="또는 소스 코드 붙여넣기"
            hint="ZIP이 없을 때 사용하세요. 여러 파일은 '// file: 경로' 주석으로 구분하면 파일별로 분리해 검사합니다."
          >
            <textarea
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              rows={8}
              disabled={!!zipFile}
              placeholder={`// file: src/api/todos/[id].ts\nexport async function GET(req, { params }) {\n  const todo = await db.todos.findUnique({ where: { id: params.id } });\n  return Response.json(todo); // 소유자 확인 없음 → IDOR\n}`}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100 disabled:bg-slate-100 disabled:text-slate-400"
            />
          </Field>

          <Field
            label="GitHub 저장소 주소 (선택)"
            hint="아직 저장소 자동 연결(clone)은 지원하지 않습니다. 지금은 참고용 링크로만 기록되며, 코드 검사는 위의 ZIP/붙여넣기로 합니다."
          >
            <input
              value={repositoryUrl}
              onChange={(e) => setRepositoryUrl(e.target.value)}
              placeholder="https://github.com/내계정/내저장소"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <Field
            label="배포된 앱 주소 (선택)"
            hint="본인이 소유한 대상만 입력하세요. 입력하면 배포 환경에 대한 읽기 전용 헤더/CORS 점검을 함께 수행합니다."
          >
            <input
              value={deploymentUrl}
              onChange={(e) => setDeploymentUrl(e.target.value)}
              placeholder="https://내앱.example.com"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          {deploymentUrl.trim() && (
            <label className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
              <input
                type="checkbox"
                checked={deploymentAuthorized}
                onChange={(e) => setDeploymentAuthorized(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                이 배포 주소를 <strong>본인이 소유</strong>하거나 능동 보안 테스트
                권한이 있음을 확인합니다. 확인하지 않으면 배포 환경에 대한 능동
                점검(헤더/CORS 등)은 실행되지 않고 소스 정적 분석만 수행합니다.
              </span>
            </label>
          )}

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-brand-600 px-4 py-2.5 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
          >
            {submitting ? "생성 중…" : "프로젝트 만들기"}
          </button>
        </form>
      </main>
    </>
  );
}

function buildUploadForm(input: {
  name: string;
  repositoryUrl: string;
  deploymentUrl: string;
  zipFile: File;
  deploymentAuthorized: boolean;
}): FormData {
  const fd = new FormData();
  fd.set("name", input.name);
  fd.set("repositoryUrl", input.repositoryUrl);
  fd.set("deploymentUrl", input.deploymentUrl);
  fd.set("file", input.zipFile);
  fd.set("deploymentAuthorized", String(input.deploymentAuthorized));
  return fd;
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-700">
        {label} {required && <span className="text-red-500">*</span>}
      </span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}
