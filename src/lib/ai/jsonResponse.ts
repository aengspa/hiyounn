/**
 * Parse the single JSON object an LLM was asked to return. Accepts a bare
 * object or one wrapped in a ``` fence. Returns undefined (never throws) when
 * the text is not a JSON object — callers must treat that as a failed call.
 */
export function parseJsonObject(text: string): Record<string, unknown> | undefined {
  const candidates: string[] = [text.trim()];
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) candidates.push(fenced[1].trim());
  const b = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (b >= 0 && e > b) candidates.push(text.slice(b, e + 1));
  for (const c of candidates) {
    try {
      const v = JSON.parse(c) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
    } catch {
      // try the next candidate
    }
  }
  return undefined;
}

export function str(v: unknown, max: number): string | undefined {
  return typeof v === "string" && v.length <= max ? v : undefined;
}
