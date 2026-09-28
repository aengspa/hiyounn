import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_LIMITS, readLimits } from "@/lib/config/limits";

const saved = { ...process.env };
afterEach(() => {
  process.env = { ...saved };
});

describe("readLimits", () => {
  it("uses defaults (8MB ZIP, 20 items)", () => {
    delete process.env.LIMIT_UPLOAD_ZIP_BYTES;
    delete process.env.LIMIT_FIX_ALL_MAX_ITEMS;
    const l = readLimits();
    expect(l.uploadZipBytes).toBe(8 * 1024 * 1024);
    expect(l.fixAllMaxItems).toBe(DEFAULT_LIMITS.fixAllMaxItems);
  });

  it("reads valid env overrides", () => {
    process.env.LIMIT_FIX_ALL_MAX_ITEMS = "5";
    expect(readLimits().fixAllMaxItems).toBe(5);
  });

  it("ignores invalid values and clamps out-of-range ones", () => {
    process.env.LIMIT_FIX_ALL_MAX_ITEMS = "abc";
    expect(readLimits().fixAllMaxItems).toBe(DEFAULT_LIMITS.fixAllMaxItems);
    process.env.LIMIT_FIX_ALL_MAX_ITEMS = "100000";
    expect(readLimits().fixAllMaxItems).toBe(200);
  });

  it("keeps the fix-all budget under the route maxDuration (120s)", () => {
    const l = readLimits();
    expect(l.fixAllTimeBudgetMs + 5_000).toBeLessThan(120_000);
  });
});
