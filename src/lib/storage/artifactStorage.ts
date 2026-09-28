import { storageDownload, storageUpload } from "@/lib/store/supabaseClient";

/**
 * Where fix-job ZIP bytes live. Metadata (size, SHA-256, changed files) stays
 * in the store; only the bytes go here, so a missing object is detectable.
 *
 *   DATA_STORE=memory   → process memory (local dev / tests only; not shared
 *                         across serverless invocations)
 *   DATA_STORE=supabase → private Supabase Storage bucket (ARTIFACT_BUCKET,
 *                         default "fix-artifacts"). The bucket must be created
 *                         by the migration; this code never creates it or
 *                         makes it public.
 *
 * Keys are built from server-generated ids only (see artifactKey), never from
 * user input.
 */
export interface ArtifactStorage {
  readonly kind: "memory" | "supabase";
  put(key: string, bytes: Uint8Array, contentType: string): Promise<void>;
  get(key: string): Promise<Uint8Array | undefined>;
}

export const DEFAULT_ARTIFACT_BUCKET = "fix-artifacts";

const SAFE_SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;

/** `${ownerId}/${projectId}/${jobId}/${artifactId}.zip`, with id validation. */
export function artifactKey(parts: {
  ownerId: string;
  projectId: string;
  jobId: string;
  artifactId: string;
}): string {
  const segs = [parts.ownerId, parts.projectId, parts.jobId, parts.artifactId];
  for (const s of segs) {
    if (!SAFE_SEGMENT.test(s)) throw new Error("invalid artifact key segment");
  }
  return `${segs.join("/")}.zip`;
}

class MemoryArtifactStorage implements ArtifactStorage {
  readonly kind = "memory" as const;
  private get objects(): Map<string, Uint8Array> {
    const g = globalThis as unknown as { __vsa_artifacts?: Map<string, Uint8Array> };
    g.__vsa_artifacts ??= new Map();
    return g.__vsa_artifacts;
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    if (this.objects.has(key)) throw new Error("artifact already exists");
    this.objects.set(key, new Uint8Array(bytes));
  }
  async get(key: string): Promise<Uint8Array | undefined> {
    const b = this.objects.get(key);
    return b ? new Uint8Array(b) : undefined;
  }
}

class SupabaseArtifactStorage implements ArtifactStorage {
  readonly kind = "supabase" as const;
  constructor(private bucket: string) {}
  put(key: string, bytes: Uint8Array, contentType: string): Promise<void> {
    return storageUpload(this.bucket, key, bytes, contentType);
  }
  get(key: string): Promise<Uint8Array | undefined> {
    return storageDownload(this.bucket, key);
  }
}

export function getArtifactStorage(): ArtifactStorage {
  const mode = (process.env.DATA_STORE ?? "memory").toLowerCase();
  if (mode === "supabase") {
    const bucket = process.env.ARTIFACT_BUCKET?.trim() || DEFAULT_ARTIFACT_BUCKET;
    return new SupabaseArtifactStorage(bucket);
  }
  return new MemoryArtifactStorage();
}
