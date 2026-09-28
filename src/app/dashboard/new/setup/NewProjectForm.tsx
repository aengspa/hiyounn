"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { ScanScopeMeter } from "@/components/ScanScopeMeter";
import { Button, Card, Disclosure } from "@/components/ui";
import {
  REQUIRED_TEST_ACCOUNTS,
  SCAN_MODE_ERROR_MESSAGE,
  SCAN_MODE_INFO,
  validateScanModeInput,
  type ScanMode,
  type ScanModeValidationError,
} from "@/lib/domain/scanMode";

const MAX_ZIP_SIZE = 8 * 1024 * 1024;
const inputClassName =
  "min-h-12 w-full rounded-2xl border border-line-strong bg-white px-4 py-3 text-base text-ink shadow-sm outline-none transition-colors hover:border-brand-500 focus:border-brand-700 focus:ring-2 focus:ring-primary-soft disabled:cursor-not-allowed disabled:bg-surface-warm disabled:text-ink-muted";

interface AccountInput {
  username: string;
  password: string;
}

const HOI_GUIDE: Record<ScanMode, string> = {
  static:
    "ZIP 파일만 있으면 돼요. 서비스에는 요청을 보내지 않고 코드와 설정만 꼼꼼히 읽어볼게요.",
  safe_active:
    "배포된 주소에 조회 요청만 보내서 헤더·쿠키·노출된 경로를 확인해요. ZIP도 올리면 코드까지 함께 봐요.",
  isolated_active:
    "테스트 계정 두 개로 ‘A가 B의 데이터를 볼 수 있는지’ 같은 공격을 직접 재현해요. 운영 서버가 아닌 격리된 테스트 서버 주소를 넣어 주세요.",
};

export function NewProjectForm({ mode }: { mode: ScanMode }) {
  const info = SCAN_MODE_INFO[mode];
  const dynamic = mode !== "static";
  const isolated = mode === "isolated_active";

  const router = useRouter();
  const [name, setName] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceCode, setSourceCode] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [deploymentAuthorized, setDeploymentAuthorized] = useState(false);
  const [accounts, setAccounts] = useState<AccountInput[]>(
    Array.from({ length: REQUIRED_TEST_ACCOUNTS }, () => ({ username: "", password: "" })),
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function updateAccount(index: number, patch: Partial<AccountInput>) {
    setAccounts((prev) => prev.map((a, i) => (i === index ? { ...a, ...patch } : a)));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError("프로젝트 이름을 입력해 주세요.");
      return;
    }
    if (zipFile && zipFile.size > MAX_ZIP_SIZE) {
      setError("ZIP 파일은 8MB 이하로 선택해 주세요.");
      return;
    }

    const testAccounts = isolated
      ? accounts.map((a, i) => ({
          label: `계정 ${String.fromCharCode(65 + i)}`,
          username: a.username.trim(),
          password: a.password,
        }))
      : [];
    if (isolated && testAccounts.some((a) => !a.username || !a.password)) {
      setError(SCAN_MODE_ERROR_MESSAGE.test_accounts_required);
      return;
    }

    const url = dynamic ? deploymentUrl.trim() : "";
    const authorized = Boolean(url) && deploymentAuthorized;
    const invalid = validateScanModeInput(mode, {
      hasSource: Boolean(zipFile) || Boolean(sourceCode.trim()),
      deploymentUrl: url || undefined,
      deploymentAuthorized: authorized,
      testAccounts,
    });
    if (invalid) {
      setError(SCAN_MODE_ERROR_MESSAGE[invalid]);
      return;
    }

    setSubmitting(true);
    try {
      const res = zipFile
        ? await fetch("/api/projects/upload", {
            method: "POST",
            body: buildUploadForm({
              name,
              repositoryUrl,
              deploymentUrl: url,
              zipFile,
              deploymentAuthorized: authorized,
              scanMode: mode,
              testAccounts,
            }),
          })
        : await fetch("/api/projects", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name,
              repositoryUrl,
              deploymentUrl: url,
              sourceCode,
              deploymentAuthorized: authorized,
              scanMode: mode,
              testAccounts,
            }),
          });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.error) {
        setError(friendlyProjectError(data?.error, data?.message));
        setSubmitting(false);
        return;
      }
      router.push(`/dashboard/projects/${data.project.id}`);
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
      setSubmitting(false);
    }
  }

  function chooseZip(file: File | null, input: HTMLInputElement) {
    setError(null);
    if (file && file.size > MAX_ZIP_SIZE) {
      input.value = "";
      setZipFile(null);
      setError("ZIP 파일은 8MB 이하로 선택해 주세요.");
      return;
    }
    setZipFile(file);
  }

  let step = 0;
  const next = () => String(++step);

  return (
    <>
      <PageHeader
        title={`${info.letter} · ${info.title}`}
        subtitle={info.tagline}
        backHref="/dashboard/new"
        backLabel="스캔 방식 다시 고르기"
      />
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
        <HoiSpeech mood="guide" size="md">
          {HOI_GUIDE[mode]}
        </HoiSpeech>

        <Card variant="warm" className="mt-6 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm font-extrabold text-ink">
              선택한 방식: <span className="text-brand-800">{info.letter} · {info.title}</span>
            </p>
            <Link
              href="/dashboard/new"
              className="inline-flex min-h-11 items-center text-sm font-bold text-brand-700 hover:text-brand-900 hover:underline"
            >
              방식 바꾸기
            </Link>
          </div>
          <ScanScopeMeter scope={info.scope} className="mt-3" />
        </Card>

        <form
          onSubmit={submit}
          className="mt-6 space-y-5"
          aria-busy={submitting}
          aria-describedby={error ? "project-form-error" : undefined}
        >
          <StepCard number={next()} title="프로젝트 이름" description="목록에서 알아보기 쉬운 이름을 적어 주세요.">
            <Field id="name" label="프로젝트 이름" required>
              <input
                id="name"
                name="name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (error === "프로젝트 이름을 입력해 주세요.") setError(null);
                }}
                required
                autoComplete="off"
                placeholder="예: 우리 동네 일정 앱"
                className={inputClassName}
              />
            </Field>
          </StepCard>

          <StepCard
            number={next()}
            title={dynamic ? "코드 (선택)" : "코드가 있는 곳"}
            description={
              dynamic
                ? "ZIP을 함께 올리면 A 방식의 정적 분석도 같이 진행해요. 없어도 괜찮아요."
                : "ZIP을 우선 사용하고, 없다면 코드를 직접 붙여 넣을 수 있어요."
            }
          >
            <Field
              id="file"
              label="프로젝트 ZIP"
              required={!dynamic && !sourceCode.trim()}
              hint="8MB 이하의 .zip 파일을 올려 주세요. node_modules, 빌드 결과물, 바이너리는 자동으로 제외해요."
            >
              <input
                id="file"
                name="file"
                type="file"
                accept=".zip,application/zip"
                onChange={(e) => chooseZip(e.target.files?.[0] ?? null, e.currentTarget)}
                aria-describedby="file-hint"
                className={`${inputClassName} p-2 text-sm file:mr-3 file:min-h-10 file:rounded-xl file:border-0 file:bg-primary-soft file:px-4 file:font-extrabold file:text-brand-900`}
              />
            </Field>
            {zipFile && (
              <p className="mt-3 break-all rounded-2xl border border-green-200 bg-success-soft px-4 py-3 text-sm font-bold text-success" role="status">
                {zipFile.name}을 선택했어요. 붙여 넣은 코드보다 이 ZIP을 먼저 사용해요.
              </p>
            )}

            <Disclosure summary="다른 코드 제공 방법과 저장소 링크" className="mt-4">
              <div className="space-y-5">
                <Field
                  id="sourceCode"
                  label="소스 코드 직접 붙여넣기"
                  hint="ZIP이 없을 때만 사용해요. 여러 파일은 ‘// file: 경로’로 구분해 주세요. 서버는 입력의 앞 100,000자까지 검사해요."
                >
                  <textarea
                    id="sourceCode"
                    name="sourceCode"
                    value={sourceCode}
                    onChange={(e) => setSourceCode(e.target.value)}
                    rows={9}
                    disabled={Boolean(zipFile)}
                    aria-describedby="sourceCode-hint"
                    placeholder={`// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}`}
                    className={`${inputClassName} min-h-52 resize-y font-mono text-sm`}
                  />
                </Field>
                <Field
                  id="repositoryUrl"
                  label="GitHub 저장소 주소"
                  hint="선택 · 지금은 참고 링크로만 기록하며, 저장소를 자동으로 내려받지는 않아요."
                >
                  <input
                    id="repositoryUrl"
                    name="repositoryUrl"
                    type="url"
                    value={repositoryUrl}
                    onChange={(e) => setRepositoryUrl(e.target.value)}
                    placeholder="https://github.com/example/project"
                    aria-describedby="repositoryUrl-hint"
                    className={inputClassName}
                  />
                </Field>
              </div>
            </Disclosure>
          </StepCard>

          {dynamic && (
            <StepCard
              number={next()}
              title={isolated ? "격리된 테스트 서버 주소" : "배포된 서비스 주소"}
              description={
                isolated
                  ? "운영 서버와 데이터베이스가 분리된 스테이징/테스트 서버 주소를 입력해 주세요."
                  : "실제로 접속할 수 있는 서비스 주소예요. 조회 요청만 보내요."
              }
            >
              <Field
                id="deploymentUrl"
                label={isolated ? "테스트 서버 주소" : "서비스 주소"}
                required
                hint="본인이 소유하거나 점검 권한이 있는 http(s) 주소만 입력해 주세요."
              >
                <input
                  id="deploymentUrl"
                  name="deploymentUrl"
                  type="url"
                  required
                  value={deploymentUrl}
                  onChange={(e) => setDeploymentUrl(e.target.value)}
                  placeholder={isolated ? "https://staging.example.com" : "https://app.example.com"}
                  aria-describedby="deploymentUrl-hint"
                  className={inputClassName}
                />
              </Field>
            </StepCard>
          )}

          {isolated && (
            <StepCard
              number={next()}
              title="테스트 계정 2개"
              description="서로 다른 일반 사용자 계정 두 개가 필요해요. 계정 A로 계정 B의 데이터에 접근할 수 있는지 확인해요."
            >
              <div className="grid gap-4 sm:grid-cols-2">
                {accounts.map((acc, i) => {
                  const letter = String.fromCharCode(65 + i);
                  return (
                    <fieldset key={letter} className="rounded-2xl border border-line bg-white p-4">
                      <legend className="px-1 text-base font-extrabold text-ink">계정 {letter}</legend>
                      <div className="space-y-3">
                        <Field id={`account-${i}-username`} label="아이디 또는 이메일" required>
                          <input
                            id={`account-${i}-username`}
                            value={acc.username}
                            onChange={(e) => updateAccount(i, { username: e.target.value })}
                            required
                            autoComplete="off"
                            placeholder={`tester-${letter.toLowerCase()}@example.com`}
                            className={inputClassName}
                          />
                        </Field>
                        <Field id={`account-${i}-password`} label="비밀번호" required>
                          <input
                            id={`account-${i}-password`}
                            type="password"
                            value={acc.password}
                            onChange={(e) => updateAccount(i, { password: e.target.value })}
                            required
                            autoComplete="new-password"
                            className={inputClassName}
                          />
                        </Field>
                      </div>
                    </fieldset>
                  );
                })}
              </div>
              <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                실제 사용자 계정이 아닌 테스트 전용 계정을 사용해 주세요. 비밀번호는 점검에만 쓰고 화면이나 API 응답에는 다시 보여주지 않아요.
              </p>
            </StepCard>
          )}

          <StepCard number={next()} title="검사 범위를 확인해요" description={`${info.letter} 방식에서 호이가 하는 일과 하지 않는 일이에요.`}>
            <ul className="space-y-2 text-sm leading-relaxed text-ink-subtle">
              {info.covers.map((c) => (
                <li key={c}>• {c}</li>
              ))}
              {mode === "static" && <li>• 서비스에는 네트워크 요청을 보내지 않아요.</li>}
              {mode === "safe_active" && <li>• 데이터를 바꾸거나 계정을 만드는 요청은 보내지 않아요.</li>}
              <li>• 자동 점검만으로 모든 위험을 찾을 수는 없어요.</li>
            </ul>

            {dynamic && (
              <label
                className={`mt-4 flex min-h-11 cursor-pointer items-start gap-3 rounded-2xl border p-4 text-sm leading-relaxed text-ink ${
                  isolated ? "border-red-300 bg-danger-soft" : "border-amber-300 bg-warning-soft"
                }`}
              >
                <input
                  name="deploymentAuthorized"
                  type="checkbox"
                  checked={deploymentAuthorized}
                  onChange={(e) => setDeploymentAuthorized(e.target.checked)}
                  className="mt-1 h-5 w-5 shrink-0 accent-brand-700"
                />
                <span>
                  이 주소를 <strong>본인이 소유</strong>하거나 능동 보안 테스트 권한이 있음을 확인해요.
                  {isolated && (
                    <>
                      {" "}또한 이 서버가 <strong>운영 환경과 격리</strong>되어 있고, 점검 중 데이터가 바뀌어도 괜찮음을 확인해요.
                    </>
                  )}
                </span>
              </label>
            )}
            {dynamic && (
              <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                권한 확인과 별개로, 실제 요청을 보내기 전에 DNS TXT 레코드나 파일 토큰으로 URL 소유권을 인증해요.
                인증이 끝나기 전에는 동적 점검 항목이 &lsquo;확인하지 못한 항목&rsquo;으로 표시돼요.
              </p>
            )}
          </StepCard>

          <Card variant="raised" className="p-5 sm:p-6">
            <div className="flex items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-soft text-sm font-black text-brand-900">{next()}</span>
              <div>
                <h2 className="text-xl font-black text-ink">준비되면 연결해요</h2>
                <p className="mt-1 text-sm text-ink-subtle">연결이 끝나면 프로젝트 화면으로 이동해 첫 점검을 준비해요.</p>
              </div>
            </div>

            {error && (
              <div id="project-form-error" role="alert" aria-live="assertive" className="mt-5 rounded-2xl border border-red-200 bg-danger-soft p-4 text-sm text-danger">
                <p className="font-extrabold">입력한 내용을 한 번만 확인해 주세요</p>
                <p className="mt-1">{error}</p>
              </div>
            )}

            <Button type="submit" size="lg" disabled={submitting} aria-busy={submitting} className="mt-5 w-full">
              <span aria-live="polite">
                {submitting ? "프로젝트를 연결하고 있어요…" : `${info.letter} 방식으로 프로젝트 연결하기`}
              </span>
            </Button>
          </Card>
        </form>
      </div>
    </>
  );
}

function buildUploadForm(input: {
  name: string;
  repositoryUrl: string;
  deploymentUrl: string;
  zipFile: File;
  deploymentAuthorized: boolean;
  scanMode: ScanMode;
  testAccounts: { label: string; username: string; password: string }[];
}): FormData {
  const fd = new FormData();
  fd.set("name", input.name);
  fd.set("repositoryUrl", input.repositoryUrl);
  fd.set("deploymentUrl", input.deploymentUrl);
  fd.set("file", input.zipFile);
  fd.set("deploymentAuthorized", String(input.deploymentAuthorized));
  fd.set("scanMode", input.scanMode);
  if (input.testAccounts.length) fd.set("testAccounts", JSON.stringify(input.testAccounts));
  return fd;
}

function friendlyProjectError(error: unknown, message?: unknown) {
  if (typeof error === "string" && error in SCAN_MODE_ERROR_MESSAGE) {
    return SCAN_MODE_ERROR_MESSAGE[error as ScanModeValidationError];
  }
  if (error === "invalid_test_accounts") return "테스트 계정은 아이디와 비밀번호를 모두 입력해 주세요.";
  if (error === "invalid_scan_mode") return "스캔 방식을 다시 선택해 주세요.";
  if (error === "forbidden") return "이 프로젝트를 만들 권한을 확인할 수 없어요. 로그인 상태를 확인해 주세요.";
  if (error === "invalid_url") return "입력한 주소 형식을 확인해 주세요. http 또는 https 주소를 사용할 수 있어요.";
  if (error === "file_too_large") return "ZIP 파일은 8MB 이하로 선택해 주세요.";
  if (error === "internal_error") return "지금은 프로젝트를 연결하기 어려워요. 잠시 후 다시 시도해 주세요.";
  if (typeof message === "string" && message) return message;
  if (typeof error === "string" && /[가-힣]/.test(error)) return error;
  return "프로젝트를 연결할 수 없어요. 입력한 주소와 파일을 확인한 뒤 다시 시도해 주세요.";
}

function StepCard({
  number,
  title,
  description,
  children,
}: {
  number: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card variant="raised" className="p-5 sm:p-6">
      <div className="flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-soft text-sm font-black text-brand-900">{number}</span>
        <div className="min-w-0">
          <h2 className="text-xl font-black text-ink">{title}</h2>
          <p className="mt-1 text-sm leading-relaxed text-ink-subtle">{description}</p>
        </div>
      </div>
      <div className="mt-5">{children}</div>
    </Card>
  );
}

function Field({
  id,
  label,
  hint,
  required,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-2 block text-base font-extrabold text-ink">
        {label} {required && <span className="text-danger">(필수)</span>}
      </label>
      {children}
      {hint && <p id={`${id}-hint`} className="mt-2 text-sm leading-relaxed text-ink-muted">{hint}</p>}
    </div>
  );
}
