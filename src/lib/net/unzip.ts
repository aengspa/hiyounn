import { inflateRawSync } from "node:zlib";

/**
 * Minimal, dependency-free ZIP reader (server-only).
 *
 * Parses the ZIP central directory and inflates each entry with Node's built-in
 * zlib. No third-party package — consistent with the rest of the codebase
 * (fetch-based Supabase/LLM clients). Only what we need to turn an uploaded
 * archive into a { path: content } map for scanning.
 *
 * Hardened against the classic archive attacks:
 *   - path traversal / absolute paths / drive letters are rejected
 *   - symlink entries (unix mode) are skipped
 *   - per-file and total uncompressed size caps (zip-bomb guard)
 *   - entry count cap
 *   - only STORE (0) and DEFLATE (8) compression are supported
 */

export interface UnzipLimits {
  maxEntries: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}

export const DEFAULT_UNZIP_LIMITS: UnzipLimits = {
  maxEntries: 2000,
  maxFileBytes: 2 * 1024 * 1024, // 2 MB per file
  maxTotalBytes: 20 * 1024 * 1024, // 20 MB total uncompressed
};

export class UnzipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnzipError";
  }
}

// End of Central Directory record signature.
const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

function findEocd(buf: Buffer): number {
  // EOCD is at the end; scan backwards (comment can be up to 64KB).
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new UnzipError("유효한 ZIP 파일이 아닙니다 (EOCD를 찾을 수 없음).");
}

/** Reject traversal, absolute, and drive-letter paths; normalize separators. */
function safeEntryPath(raw: string): string | null {
  const p = raw.replace(/\\/g, "/");
  if (p.startsWith("/") || /^[a-zA-Z]:/.test(p)) return null;
  const parts = p.split("/");
  if (parts.some((seg) => seg === "..")) return null;
  const cleaned = parts.filter((seg) => seg && seg !== ".").join("/");
  return cleaned || null;
}

/**
 * Extract a ZIP archive into a { path: content } text map.
 * Binary-looking entries and directories are skipped.
 */
export function unzipToFileMap(
  buf: Buffer,
  limits: UnzipLimits = DEFAULT_UNZIP_LIMITS
): Record<string, string> {
  const eocd = findEocd(buf);
  const entryCount = buf.readUInt16LE(eocd + 10);
  let cenOffset = buf.readUInt32LE(eocd + 16);

  if (entryCount > limits.maxEntries) {
    throw new UnzipError(
      `압축 파일 항목이 너무 많습니다 (${entryCount} > ${limits.maxEntries}).`
    );
  }

  const files: Record<string, string> = {};
  let totalBytes = 0;

  for (let i = 0; i < entryCount; i++) {
    if (cenOffset + 46 > buf.length || buf.readUInt32LE(cenOffset) !== CEN_SIG) {
      break;
    }
    const method = buf.readUInt16LE(cenOffset + 10);
    const compSize = buf.readUInt32LE(cenOffset + 20);
    const uncompSize = buf.readUInt32LE(cenOffset + 24);
    const nameLen = buf.readUInt16LE(cenOffset + 28);
    const extraLen = buf.readUInt16LE(cenOffset + 30);
    const commentLen = buf.readUInt16LE(cenOffset + 32);
    const externalAttrs = buf.readUInt32LE(cenOffset + 38);
    const localOffset = buf.readUInt32LE(cenOffset + 42);
    const nameStart = cenOffset + 46;
    const rawName = buf.toString("utf8", nameStart, nameStart + nameLen);

    cenOffset = nameStart + nameLen + extraLen + commentLen;

    // Skip directories.
    if (rawName.endsWith("/")) continue;

    // Skip unix symlinks (mode 0xA000 in high 16 bits of external attrs).
    const unixMode = externalAttrs >>> 16;
    if ((unixMode & 0xf000) === 0xa000) continue;

    const safe = safeEntryPath(rawName);
    if (!safe) continue; // traversal/absolute — skip silently

    if (uncompSize > limits.maxFileBytes) continue; // oversized single file
    totalBytes += uncompSize;
    if (totalBytes > limits.maxTotalBytes) {
      throw new UnzipError("압축 해제 크기가 상한을 초과했습니다 (zip bomb 방지).");
    }

    // Read the local file header to find the data start.
    if (buf.readUInt32LE(localOffset) !== LOC_SIG) continue;
    const locNameLen = buf.readUInt16LE(localOffset + 26);
    const locExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + locNameLen + locExtraLen;
    const compData = buf.subarray(dataStart, dataStart + compSize);

    let content: Buffer;
    try {
      if (method === 0) content = Buffer.from(compData); // STORE
      else if (method === 8) content = inflateRawSync(compData); // DEFLATE
      else continue; // unsupported compression
    } catch {
      continue; // corrupt entry — skip
    }

    // Skip binary content (NUL byte in the first chunk).
    const sample = content.subarray(0, 8000);
    if (sample.includes(0)) continue;

    files[safe] = content.toString("utf8");
  }

  return files;
}
