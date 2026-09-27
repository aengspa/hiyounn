import type { ProjectContext } from "@/lib/scanners/types";

/**
 * Turn a user's source input into a virtual file map + detected stack, so real
 * projects are scanned from THEIR OWN files only — never the bundled demo
 * fixture.
 *
 * Two input shapes are supported:
 *   1. A pasted blob, optionally split into multiple files with `// file: <path>`
 *      markers (also accepts `# file:` and `/* file: ... *&#47;`).
 *   2. An already-split file map (e.g. from a ZIP upload).
 */

const FILE_MARKER =
  /^\s*(?:\/\/|#|;|--|\/\*)\s*file:\s*(.+?)\s*(?:\*\/)?\s*$/i;

/**
 * Parse a pasted source blob into { path: content }. When no `// file:` marker
 * is present the whole blob becomes a single file whose name is guessed from
 * its content.
 */
export function parseSourceBlob(blob: string): Record<string, string> {
  const text = blob.replace(/\r\n/g, "\n");
  const lines = text.split("\n");

  // Find marker lines.
  const markers: { line: number; path: string }[] = [];
  lines.forEach((l, i) => {
    const m = l.match(FILE_MARKER);
    if (m) markers.push({ line: i, path: sanitizeRelPath(m[1]) });
  });

  if (markers.length === 0) {
    const name = guessSingleFileName(text);
    return { [name]: text.trim() };
  }

  const files: Record<string, string> = {};
  for (let i = 0; i < markers.length; i++) {
    const start = markers[i].line + 1;
    const end = i + 1 < markers.length ? markers[i + 1].line : lines.length;
    const content = lines.slice(start, end).join("\n").trim();
    if (content) files[markers[i].path] = content;
  }
  return files;
}

/**
 * Serialize a file map back into a `// file:`-delimited blob, so uploaded
 * projects and pasted projects share one storage format (Project.sourceCode).
 */
export function serializeFileMap(files: Record<string, string>): string {
  return Object.entries(files)
    .map(([path, content]) => `// file: ${path}\n${content}`)
    .join("\n\n");
}

/** Guess a filename for an unmarked paste from its syntax. */
function guessSingleFileName(text: string): string {
  if (/dangerouslySetInnerHTML|from\s+["']react["']|<\w+[\s/>]/.test(text))
    return "pasted.tsx";
  if (/\bdef\s+\w+\(|\bimport\s+\w+\b|print\(/.test(text)) return "pasted.py";
  if (/^\s*package\s+main|func\s+\w+\(/m.test(text)) return "pasted.go";
  return "pasted.ts";
}

/**
 * Prevent path traversal / absolute paths in user-supplied file names. Returns
 * a safe relative path.
 */
export function sanitizeRelPath(raw: string): string {
  let p = raw.trim().replace(/\\/g, "/");
  p = p.replace(/^([a-zA-Z]:)?\/+/, ""); // strip drive + leading slashes
  const parts = p
    .split("/")
    .filter((seg) => seg && seg !== "." && seg !== "..");
  const safe = parts.join("/");
  return safe || "pasted.txt";
}

// Which files are worth scanning (source + manifests). Everything else (images,
// lockfiles beyond manifests, node_modules, build output) is skipped.
const SOURCE_EXT =
  /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|java|cs|sql|html|vue|svelte|json)$/i;
const SKIP_DIR = /(^|\/)(node_modules|\.git|\.next|dist|build|vendor|coverage)\//;

export function isScannableFile(path: string): boolean {
  if (SKIP_DIR.test("/" + path)) return false;
  return SOURCE_EXT.test(path);
}

/** Detect a lightweight stack from the file map (paths + package.json). */
export function detectStack(files: Record<string, string>): ProjectContext["stack"] {
  const paths = Object.keys(files);
  const frameworks = new Set<string>();
  const languages = new Set<string>();
  const baas = new Set<string>();

  if (paths.some((p) => /\.tsx?$/.test(p))) languages.add("typescript");
  if (paths.some((p) => /\.jsx?$/.test(p) || /\.mjs$/.test(p)))
    languages.add("javascript");
  if (paths.some((p) => /\.py$/.test(p))) languages.add("python");
  if (paths.some((p) => /\.go$/.test(p))) languages.add("go");

  const pkg = files["package.json"];
  const allText = pkg ?? "";
  if (/\bnext\b/.test(allText) || paths.some((p) => /next\.config\./.test(p)))
    frameworks.add("next.js");
  if (/\breact\b/.test(allText) || paths.some((p) => /\.tsx$|\.jsx$/.test(p)))
    frameworks.add("react");
  if (/\bexpress\b/.test(allText)) frameworks.add("express");
  if (/@supabase\/supabase-js|supabase/i.test(allText + paths.join(" ")))
    baas.add("supabase");
  if (/firebase/i.test(allText)) baas.add("firebase");

  const hasEnvFile = paths.some((p) => /(^|\/)\.env(\.|$)/.test(p));

  return {
    frameworks: [...frameworks],
    languages: languages.size ? [...languages] : ["unknown"],
    baas: baas.size ? [...baas] : undefined,
    hasEnvFile,
  };
}

/**
 * Build a ProjectContext for a REAL user project from its own files only.
 * No bundled demo vulnerabilities are added.
 */
export function buildProjectContext(
  projectId: string,
  opts: {
    name: string;
    repositoryUrl?: string;
    deploymentUrl?: string;
    commitSha?: string;
    /** Pre-split file map (ZIP upload). Takes precedence over `sourceBlob`. */
    files?: Record<string, string>;
    /** Pasted source blob (parsed with `// file:` markers). */
    sourceBlob?: string;
    /** User confirmed ownership of deploymentUrl (gates active DAST). */
    deploymentAuthorized?: boolean;
  }
): ProjectContext {
  let files: Record<string, string> = {};
  if (opts.files && Object.keys(opts.files).length > 0) {
    files = opts.files;
  } else if (opts.sourceBlob && opts.sourceBlob.trim()) {
    files = parseSourceBlob(opts.sourceBlob);
  }

  // Keep only scannable files (skip binaries/build output). If a paste guessed
  // a single non-standard name, keep it anyway so nothing silently vanishes.
  const filtered: Record<string, string> = {};
  for (const [p, c] of Object.entries(files)) {
    if (isScannableFile(p) || Object.keys(files).length === 1) filtered[p] = c;
  }

  return {
    projectId,
    name: opts.name,
    repositoryUrl: opts.repositoryUrl,
    deploymentUrl: opts.deploymentUrl,
    commitSha: opts.commitSha,
    stack: detectStack(filtered),
    files: filtered,
    isUserProject: true,
    deploymentAuthorized: opts.deploymentAuthorized ?? false,
  };
}
