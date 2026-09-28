import { lookup } from "dns/promises";
import http from "http";
import https from "https";
import net from "net";

export type SafeFetchErrorCode =
  | "INVALID_URL" | "SCHEME_NOT_ALLOWED" | "PRIVATE_ADDRESS" | "DNS_FAILED"
  | "TOO_MANY_REDIRECTS" | "RESPONSE_TOO_LARGE" | "TIMEOUT"
  | "METHOD_NOT_ALLOWED" | "REQUEST_FAILED";

export class SafeFetchError extends Error {
  constructor(public code: SafeFetchErrorCode, message: string) {
    super(message);
    this.name = "SafeFetchError";
  }
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD" | "POST" | "PATCH";
  timeoutMs?: number;
  maxRedirects?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  allowUnsafeMethod?: boolean;
  body?: string;
  followRedirects?: boolean;
}

export interface SafeFetchResult {
  status: number;
  url: string;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

/** Deny non-public ranges, including normalized hexadecimal IPv4-mapped IPv6. */
export function isBlockedAddress(raw: string): boolean {
  const ip = raw.replace(/^\[|\]$/g, "");
  const family = net.isIP(ip);
  if (family === 4) {
    const [a, b, c] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
      (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113);
  }
  if (family !== 6 || ip.includes("%")) return true;
  const normalized = new URL(`http://[${ip}]/`).hostname.slice(1, -1).toLowerCase();
  const mapped = normalized.match(/^::ffff:([\da-f]+):([\da-f]+)$/);
  if (mapped) {
    const high = parseInt(mapped[1], 16);
    const low = parseInt(mapped[2], 16);
    return isBlockedAddress(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  // Public unicast currently lives in 2000::/3; default deny other address space.
  return !/^[23][\da-f]{3}:/.test(normalized) || normalized.startsWith("2001:db8:");
}

async function safeDestination(raw: string, remaining: number): Promise<{ url: URL; address: string; family: number }> {
  let url: URL;
  try { url = new URL(raw); }
  catch { throw new SafeFetchError("INVALID_URL", "URL 파싱 실패"); }
  if (!["http:", "https:"].includes(url.protocol)) throw new SafeFetchError("SCHEME_NOT_ALLOWED", "HTTP(S)만 허용합니다.");
  if (url.username || url.password) throw new SafeFetchError("INVALID_URL", "URL 자격증명은 허용하지 않습니다.");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const literalFamily = net.isIP(hostname);
  if (literalFamily) {
    if (isBlockedAddress(hostname)) throw new SafeFetchError("PRIVATE_ADDRESS", "차단된 주소");
    return { url, address: hostname, family: literalFamily };
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const addresses = await Promise.race([
      lookup(hostname, { all: true }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new SafeFetchError("TIMEOUT", "DNS 시간 초과")), remaining); }),
    ]);
    if (!addresses.length) throw new SafeFetchError("DNS_FAILED", "DNS 결과 없음");
    if (addresses.some(({ address }) => isBlockedAddress(address))) throw new SafeFetchError("PRIVATE_ADDRESS", "차단된 DNS 해석 주소");
    return { url, address: addresses[0].address, family: addresses[0].family };
  } catch (error) {
    if (error instanceof SafeFetchError) throw error;
    throw new SafeFetchError("DNS_FAILED", "DNS 해석 실패");
  } finally { clearTimeout(timer); }
}

/** Connect only to the address just validated, while retaining hostname for Host/TLS. */
function requestPinned(
  destination: { url: URL; address: string; family: number },
  options: SafeFetchOptions,
  remaining: number
): Promise<SafeFetchResult> {
  return new Promise((resolve, reject) => {
    const { url, address, family } = destination;
    const requestOptions: http.RequestOptions & { autoSelectFamily: boolean } = {
      method: options.method ?? "GET",
      headers: { "user-agent": "VibeSecurityAgent/0.2 (+https://github.com/aengspa/hiyounn)", "accept-encoding": "identity", ...options.headers },
      autoSelectFamily: false,
      // DNS is not consulted again between validation and connection (rebinding).
      lookup: (_hostname, _opts, callback) => callback(null, address, family),
    };
    const request = (url.protocol === "https:" ? https : http).request(url, requestOptions);
    const timer = setTimeout(() => request.destroy(new SafeFetchError("TIMEOUT", "요청/응답 읽기 시간 초과")), remaining);
    const finish = (result: SafeFetchResult) => { clearTimeout(timer); resolve(result); };
    request.on("error", (error) => {
      clearTimeout(timer);
      reject(error instanceof SafeFetchError ? error : new SafeFetchError("REQUEST_FAILED", "요청 실패"));
    });
    request.on("response", (response) => {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(response.headers)) {
        if (value !== undefined) headers[key] = Array.isArray(value) ? value.join(",") : value;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      const maxBytes = options.maxBytes ?? 256 * 1024;
      const result = (truncated: boolean): SafeFetchResult => ({
        status: response.statusCode ?? 0, url: url.toString(), headers,
        body: Buffer.concat(chunks).toString("utf8"), truncated,
      });
      // Redirect bodies are irrelevant; release the connection before the next hop.
      if ((response.statusCode ?? 0) >= 300 && (response.statusCode ?? 0) < 400 && headers.location && options.followRedirects !== false) {
        finish(result(false)); response.destroy(); return;
      }
      response.on("data", (chunk: Buffer) => {
        const available = maxBytes - bytes;
        if (chunk.length > available) {
          chunks.push(chunk.subarray(0, available));
          finish(result(true)); response.destroy(); return;
        }
        chunks.push(chunk); bytes += chunk.length;
      });
      response.on("end", () => finish(result(false)));
      response.on("error", () => { clearTimeout(timer); reject(new SafeFetchError("REQUEST_FAILED", "응답 읽기 실패")); });
    });
    request.end(options.body);
  });
}

/** Bounded HTTP with pinned DNS, per-hop validation and no cross-origin credentials. */
export async function safeFetch(rawUrl: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  if (!["GET", "HEAD"].includes(options.method ?? "GET") && !options.allowUnsafeMethod) {
    throw new SafeFetchError("METHOD_NOT_ALLOWED", "읽기 전용만 허용합니다.");
  }
  const deadline = Date.now() + Math.min(60_000, Math.max(1, options.timeoutMs ?? 5000));
  let current = rawUrl;
  const initialOrigin = (() => { try { return new URL(rawUrl).origin; } catch { return ""; } })();
  const maxRedirects = Math.min(5, Math.max(0, options.maxRedirects ?? 3));
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new SafeFetchError("TIMEOUT", "요청 시간 초과");
    const destination = await safeDestination(current, remaining);
    const result = await requestPinned(destination, options, Math.max(1, deadline - Date.now()));
    if (result.status < 300 || result.status >= 400 || !result.headers.location || options.followRedirects === false) return result;
    if (hop === maxRedirects) throw new SafeFetchError("TOO_MANY_REDIRECTS", "리다이렉트 상한 초과");
    const next = new URL(result.headers.location, current);
    // Ownership and credentials apply only to the approved origin.
    const hasCredentials = Object.keys(options.headers ?? {}).some((name) => ["authorization", "cookie", "apikey"].includes(name.toLowerCase()));
    if (next.origin !== initialOrigin && (hasCredentials || !["GET", "HEAD"].includes(options.method ?? "GET"))) {
      throw new SafeFetchError("REQUEST_FAILED", "자격증명/쓰기 요청의 다른 origin 리다이렉트 차단");
    }
    current = next.toString();
  }
  throw new SafeFetchError("TOO_MANY_REDIRECTS", "리다이렉트 상한 초과");
}
