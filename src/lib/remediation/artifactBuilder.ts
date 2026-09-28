import { createHash } from "crypto";
import { deflateRawSync } from "zlib";
import { Buffer } from "buffer";
import type { FixAttempt, FixDiff } from "@/lib/domain/types";
import { parseSourceBlob, sanitizeRelPath } from "@/lib/demo/sourceFiles";

/**
 * Builds a downloadable, modified COPY of a project's source with selected
 * fixes applied. The original upload (Project.sourceCode) is never mutated —
 * we parse it into a file map, deep-copy that map, apply fixes to the copy,
 * and package the copy as a ZIP.
 *
 * Dependency-free: the ZIP is assembled by hand (store method, stored + no
 * compression for maximum compatibility) using only Node built-ins.
 */

export interface AppliedChange {
  file: string;
  applied: boolean;
  reason?: string;
}

export interface BuiltArtifact {
  /** ZIP bytes. */
  zip: Buffer;
  sha256: string;
  size: number;
  /** Files in the copy, with a changed flag. */
  files: { path: string; changed: boolean }[];
  /** Per-diff application result (for verification / reporting). */
  changes: AppliedChange[];
}

export interface FixedFileMap {
  /** Preserved original file map (never mutated). */
  original: Record<string, string>;
  /** Working copy with fixes applied. */
  copy: Record<string, string>;
  /** Per-diff application result. */
  changes: AppliedChange[];
  /** Paths that differ from the original. */
  changedPaths: string[];
}

/**
 * Derive (beforeText, afterText) for a diff. Prefers the explicit fields; if
 * absent, reconstructs them from the display patch (lines starting with "- "
 * are the original, "+ " are the replacement). Context lines (no prefix) are
 * ignored for matching.
 */
function diffTexts(diff: FixDiff): { before: string; after: string } {
  if (diff.beforeText !== undefined || diff.afterText !== undefined) {
    return { before: diff.beforeText ?? "", after: diff.afterText ?? "" };
  }
  const before: string[] = [];
  const after: string[] = [];
  for (const line of diff.patch.split("\n")) {
    if (line.startsWith("- ")) before.push(line.slice(2));
    else if (line.startsWith("+ ")) after.push(line.slice(2));
    else if (line.startsWith("-")) before.push(line.slice(1));
    else if (line.startsWith("+")) after.push(line.slice(1));
  }
  return { before: before.join("\n"), after: after.join("\n") };
}

/** Apply one diff to a file map (the working copy). Returns whether it changed. */
function applyDiff(
  files: Record<string, string>,
  diff: FixDiff
): AppliedChange {
  const path = sanitizeRelPath(diff.file);
  const { before, after } = diffTexts(diff);

  // New file (no before text): create it if it doesn't exist.
  if (!before.trim()) {
    if (files[path] === undefined) {
      files[path] = after;
      return { file: path, applied: true, reason: "new_file" };
    }
    // File exists but we only have "after": append as a clearly marked block
    // rather than overwrite, to avoid destroying original content.
    files[path] = `${files[path]}\n\n// --- security fix applied ---\n${after}`;
    return { file: path, applied: true, reason: "appended" };
  }

  const current = files[path];
  if (current === undefined) {
    return { file: path, applied: false, reason: "file_not_found" };
  }

  // Try exact match first, then whitespace-normalized match.
  if (current.includes(before)) {
    files[path] = current.replace(before, after);
    return { file: path, applied: true, reason: "replaced" };
  }
  const normalize = (s: string) => s.replace(/\s+/g, " ").trim();
  const normBefore = normalize(before);
  const lines = current.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (normalize(lines[i]).includes(normBefore) && normBefore.length > 0) {
      lines[i] = after;
      files[path] = lines.join("\n");
      return { file: path, applied: true, reason: "replaced_line" };
    }
  }
  return { file: path, applied: false, reason: "before_text_not_found" };
}

/**
 * Apply fixes to a COPY of the preserved original source and return both maps.
 * This is the SAME transformation buildFixArtifact packages into a ZIP, so
 * re-verification can scan exactly the fixed copy (not the original). The
 * original is never mutated.
 */
export function buildFixedFileMap(
  sourceBlob: string | undefined,
  fixes: FixAttempt[]
): FixedFileMap {
  const original = sourceBlob ? parseSourceBlob(sourceBlob) : {};
  const copy: Record<string, string> = { ...original };

  const changes: AppliedChange[] = [];
  for (const fix of fixes) {
    for (const diff of fix.diffs) {
      changes.push(applyDiff(copy, diff));
    }
  }

  const changedPaths = Object.keys(copy).filter(
    (path) => copy[path] !== original[path]
  );
  return { original, copy, changes, changedPaths };
}

/**
 * Build the modified copy + ZIP from a source blob and a set of fixes.
 * `sourceBlob` is the preserved original (Project.sourceCode); it is not
 * mutated. `projectName` seeds the ZIP file name.
 */
export function buildFixArtifact(
  sourceBlob: string | undefined,
  fixes: FixAttempt[],
  projectName: string,
  version: number
): BuiltArtifact {
  const { original, copy, changes } = buildFixedFileMap(sourceBlob, fixes);

  const files = Object.keys(copy)
    .sort()
    .map((path) => ({ path, changed: copy[path] !== original[path] }));

  const zip = makeZip(copy);
  const sha256 = createHash("sha256").update(zip).digest("hex");

  return { zip, sha256, size: zip.length, files, changes };
}

// ─────────────────────────────────────────────────────────────
// Minimal ZIP writer (store + deflate), Node built-ins only.
// ─────────────────────────────────────────────────────────────

function dosDateTime(d = new Date()): { time: number; date: number } {
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

// CRC-32 (ZIP standard) — dependency-free.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** General-purpose flag bit 11: file names are UTF-8 (needed for 한글 paths). */
const UTF8_FLAG = 0x0800;

/**
 * ZIP of ONLY the given files (e.g. the files a fix job changed), each at its
 * original relative path, plus a summary text file. Returns bytes + SHA-256.
 * The summary name never overwrites a project file.
 */
export function buildChangedFilesZip(
  changed: Record<string, string>,
  summary: { text: string; baseName?: string }
): { zip: Buffer; sha256: string; size: number; summaryPath: string } {
  const base = summary.baseName ?? "HOI-SECURITY-FIX-SUMMARY";
  let summaryPath = `${base}.md`;
  for (let n = 2; summaryPath in changed; n++) summaryPath = `${base}-${n}.md`;

  const entries: Record<string, string> = {};
  for (const path of Object.keys(changed).sort()) entries[path] = changed[path];
  entries[summaryPath] = summary.text;

  const zip = makeZip(entries);
  const sha256 = createHash("sha256").update(zip).digest("hex");
  return { zip, sha256, size: zip.length, summaryPath };
}

export function makeZip(files: Record<string, string>): Buffer {
  const { time, date } = dosDateTime();
  const entries: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const [name, content] of Object.entries(files)) {
    const nameBuf = Buffer.from(name, "utf8");
    const data = Buffer.from(content, "utf8");
    const crc = crc32(data) >>> 0;
    const compressed = deflateRawSync(data);
    const useDeflate = compressed.length < data.length;
    const stored = useDeflate ? compressed : data;
    const method = useDeflate ? 8 : 0;

    // Local file header
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(UTF8_FLAG, 6); // flags
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    entries.push(local, nameBuf, stored);

    // Central directory header
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(UTF8_FLAG, 8);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt16LE(time, 12);
    cen.writeUInt16LE(date, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(stored.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt16LE(0, 30);
    cen.writeUInt16LE(0, 32);
    cen.writeUInt16LE(0, 34);
    cen.writeUInt16LE(0, 36);
    cen.writeUInt32LE(0, 38);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, nameBuf);

    offset += local.length + nameBuf.length + stored.length;
  }

  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...entries, centralBuf, end]);
}
