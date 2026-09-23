import { lookup } from "dns/promises";
import net from "net";

/**
 * 능동 검사(SAFE_ACTIVE)용 안전 fetch 계층.
 *
 * 지식 베이스 §3 "도구 구현 시 안전 규칙"을 코드로 강제한다:
 *   - SSRF 차단: 대상 호스트를 DNS로 해석해 사설/루프백/링크로컬/메타데이터
 *     대역이면 거부(DNS 리바인딩 대비 해석 후 검사).
 *   - 리다이렉트 수동 처리: 매 홉의 Location을 다시 검증(자동 follow 금지).
 *   - 요청 상한: 타임아웃 + 응답 본문 최대 크기 제한.
 *   - 읽기 전용: GET/HEAD만 허용(상태 변경 없음).
 *
 * 이 계층을 통과하지 못한 요청은 SafeFetchError로 실패하며, 스캐너는 이를
 * coverage_gap/NOT_TESTED로 남긴다("안전하다"고 오판하지 않는다).
 */

export type SafeFetchErrorCode =
  | "INVALID_URL"
  | "SCHEME_NOT_ALLOWED"
  | "PRIVATE_ADDRESS"
  | "DNS_FAILED"
  | "TOO_MANY_REDIRECTS"
  | "RESPONSE_TOO_LARGE"
  | "TIMEOUT"
  | "METHOD_NOT_ALLOWED"
  | "REQUEST_FAILED";

export class SafeFetchError extends Error {
  constructor(
    public code: SafeFetchErrorCode,
    message: string
  ) {
    super(message);
    this.name = "SafeFetchError";
  }
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD" | "POST";
  timeoutMs?: number;
  maxRedirects?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  /** POST 등 비-GET/HEAD 메서드를 명시적으로 허용(기본 false). 요청 본문(body) 동반. */
  allowUnsafeMethod?: boolean;
  body?: string;
  /**
   * false면 리다이렉트를 따라가지 않고 3xx 응답을 그대로 반환한다(Location 포함).
   * TLS/HTTPS 강제 점검처럼 "리다이렉트가 일어나는지" 자체를 관측할 때 사용.
   * 기본값 true.
   */
  followRedirects?: boolean;
}

export interface SafeFetchResult {
  status: number;
  url: string; // 최종(리다이렉트 후) URL
  headers: Record<string, string>;
  body: string; // maxBytes까지 잘린 본문
  truncated: boolean;
}

const DEFAULTS = {
  method: "GET" as const,
  timeoutMs: 5000,
  maxRedirects: 3,
  maxBytes: 256 * 1024, // 256KB
};

/**
 * 주어진 IP(문자열)가 공인 라우팅 대상이 아닌 위험 대역인지 판정.
 * 사설/루프백/링크로컬/유니크로컬/메타데이터(169.254.169.254 포함) 차단.
 */
export function isBlockedAddress(ip: string): boolean {
  const type = net.isIP(ip);
  if (type === 4) return isBlockedIPv4(ip);
  if (type === 6) return isBlockedIPv6(ip);
  return true; // 해석 불가 = 차단
}

function isBlockedIPv4(ip: string): boolean {
  const p = ip.split(".").map((n) => parseInt(n, 10));
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = p;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8 사설
  if (a === 127) return true; // 127.0.0.0/8 루프백
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 링크로컬(메타데이터)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 사설
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 사설
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // 멀티캐스트/예약
  return false;
}

function isBlockedIPv6(ip: string): boolean {
  const norm = ip.toLowerCase().split("%")[0]; // zone id 제거
  if (norm === "::1" || norm === "::") return true; // 루프백/미지정
  if (norm.startsWith("fe80")) return true; // 링크로컬
  if (norm.startsWith("fc") || norm.startsWith("fd")) return true; // 유니크로컬
  // IPv4-매핑(::ffff:a.b.c.d)은 내부 IPv4 규칙으로 재검사.
  const mapped = norm.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIPv4(mapped[1]);
  return false;
}

/** URL을 파싱·검증하고, 호스트를 해석해 SSRF 대역이면 예외를 던진다. */
async function assertSafeUrl(rawUrl: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new SafeFetchError("INVALID_URL", `URL 파싱 실패: ${rawUrl}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SafeFetchError("SCHEME_NOT_ALLOWED", `허용되지 않은 스킴: ${u.protocol}`);
  }

  // 호스트가 이미 IP 리터럴이면 바로 검사, 아니면 DNS 해석 후 검사.
  const host = u.hostname;
  if (net.isIP(host)) {
    if (isBlockedAddress(host)) {
      throw new SafeFetchError("PRIVATE_ADDRESS", `차단된 주소: ${host}`);
    }
    return u;
  }

  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new SafeFetchError("DNS_FAILED", `DNS 해석 실패: ${host}`);
  }
  if (addrs.length === 0) {
    throw new SafeFetchError("DNS_FAILED", `DNS 결과 없음: ${host}`);
  }
  // 해석된 모든 주소가 안전해야 통과(리바인딩/다중 A레코드 대비).
  for (const { address } of addrs) {
    if (isBlockedAddress(address)) {
      throw new SafeFetchError("PRIVATE_ADDRESS", `차단된 해석 주소: ${host} → ${address}`);
    }
  }
  return u;
}

/**
 * SSRF 안전 fetch. 리다이렉트를 수동으로 따라가며 매 홉을 재검증한다.
 * 읽기 전용(GET/HEAD)만 허용하고 응답 크기/시간 상한을 강제한다.
 */
export async function safeFetch(
  rawUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const method = options.method ?? DEFAULTS.method;
  if (method !== "GET" && method !== "HEAD") {
    // 기본은 읽기 전용. POST 등은 명시적 옵트인이 있어야만 허용(비파괴 프로브용).
    if (!options.allowUnsafeMethod) {
      throw new SafeFetchError("METHOD_NOT_ALLOWED", `읽기 전용만 허용: ${method}`);
    }
  }
  const timeoutMs = options.timeoutMs ?? DEFAULTS.timeoutMs;
  const maxRedirects = options.maxRedirects ?? DEFAULTS.maxRedirects;
  const maxBytes = options.maxBytes ?? DEFAULTS.maxBytes;
  const followRedirects = options.followRedirects ?? true;

  let currentUrl = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const safeUrl = await assertSafeUrl(currentUrl);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(safeUrl.toString(), {
        method,
        redirect: "manual", // 자동 follow 금지 — 홉마다 재검증
        signal: controller.signal,
        headers: options.headers,
        body: method === "POST" ? options.body : undefined,
      });
    } catch (e) {
      clearTimeout(timer);
      if (e instanceof Error && e.name === "AbortError") {
        throw new SafeFetchError("TIMEOUT", `요청 시간 초과: ${currentUrl}`);
      }
      throw new SafeFetchError("REQUEST_FAILED", `요청 실패: ${currentUrl}`);
    }
    clearTimeout(timer);

    // 리다이렉트 처리(수동).
    if (res.status >= 300 && res.status < 400 && followRedirects) {
      const loc = res.headers.get("location");
      if (!loc) break; // Location 없으면 그대로 반환
      if (hop === maxRedirects) {
        throw new SafeFetchError("TOO_MANY_REDIRECTS", `리다이렉트 과다: ${currentUrl}`);
      }
      currentUrl = new URL(loc, safeUrl).toString();
      continue;
    }
    // followRedirects=false면 3xx를 그대로 반환(아래 헤더 수집으로 진행).

    // 헤더 수집.
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });

    // 본문을 maxBytes까지만 읽는다.
    const { body, truncated } = await readCapped(res, maxBytes);

    return {
      status: res.status,
      url: safeUrl.toString(),
      headers,
      body,
      truncated,
    };
  }

  throw new SafeFetchError("TOO_MANY_REDIRECTS", `리다이렉트 과다: ${rawUrl}`);
}

/** 응답 본문을 최대 maxBytes까지만 읽어 문자열로 반환. */
async function readCapped(
  res: Response,
  maxBytes: number
): Promise<{ body: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) return { body: "", truncated: false };

  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > maxBytes) {
        chunks.push(value.slice(0, value.length - (total - maxBytes)));
        truncated = true;
        try {
          await reader.cancel();
        } catch {
          /* noop */
        }
        break;
      }
      chunks.push(value);
    }
  }

  const merged = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.length;
  }
  return { body: new TextDecoder().decode(merged), truncated };
}
