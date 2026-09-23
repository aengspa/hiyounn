"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";

const MAX_ZIP_BYTES = 25 * 1024 * 1024; // 25MB

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceZip, setSourceZip] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function onZipChange(e: React.ChangeEvent<HTMLInputElement>) {
    setError(null);
    const file = e.target.files?.[0] ?? null;
    if (file) {
      const isZip =
        file.name.toLowerCase().endsWith(".zip") ||
        file.type === "application/zip" ||
        file.type === "application/x-zip-compressed";
      if (!isZip) {
        setError("zip 파일만 업로드할 수 있습니다.");
        setSourceZip(null);
        e.target.value = "";
        return;
      }
      if (file.size > MAX_ZIP_BYTES) {
        setError("zip 파일은 25MB 이하여야 합니다.");
        setSourceZip(null);
        e.target.value = "";
        return;
      }
    }
    setSourceZip(file);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const form = new FormData();
      form.append("name", name);
      form.append("deploymentUrl", deploymentUrl);
      if (sourceZip) form.append("sourceZip", sourceZip);

      const res = await fetch("/api/projects", {
        method: "POST",
        body: form,
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error ?? "프로젝트를 만들 수 없습니다.");
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
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-slate-500 focus:ring-2 focus:ring-slate-200"
            />
          </Field>

          <Field
            label="테스트 배포 주소"
            hint="본인이 소유한 테스트 환경만 입력하세요. 읽기 전용 헤더/CORS 점검에 사용됩니다."
          >
            <input
              value={deploymentUrl}
              onChange={(e) => setDeploymentUrl(e.target.value)}
              placeholder="https://test.내앱.example.com"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-slate-500 focus:ring-2 focus:ring-slate-200"
            />
          </Field>

          <Field
            label="소스 코드 (zip 파일)"
            hint="프로젝트 소스 코드를 zip으로 압축해 업로드하세요. 최대 25MB."
          >
            <label className="flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-dashed border-slate-300 px-3 py-3 text-sm transition hover:border-slate-400 hover:bg-slate-50">
              <span className="truncate text-slate-600">
                {sourceZip ? (
                  <span className="font-medium text-slate-800">
                    {sourceZip.name}{" "}
                    <span className="font-normal text-slate-400">
                      ({(sourceZip.size / 1024 / 1024).toFixed(1)}MB)
                    </span>
                  </span>
                ) : (
                  "클릭해서 zip 파일 선택"
                )}
              </span>
              <span className="shrink-0 rounded-md bg-slate-100 px-3 py-1 text-slate-600">
                파일 선택
              </span>
              <input
                type="file"
                accept=".zip,application/zip,application/x-zip-compressed"
                onChange={onZipChange}
                className="hidden"
              />
            </label>
          </Field>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-slate-800 px-4 py-2.5 font-medium text-white hover:bg-slate-900 disabled:opacity-60"
          >
            {submitting ? "생성 중…" : "프로젝트 만들기"}
          </button>
        </form>
      </main>
    </>
  );
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
