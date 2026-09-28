import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { unzipToFileMap } from "@/lib/net/unzip";
import { readSampleDir } from "@/lib/samples/readSampleDir";
import { SAMPLE_APPS } from "@/lib/samples";

const ROOT = process.cwd();

describe("bundled sample apps", () => {
  for (const sample of SAMPLE_APPS) {
    it(`${sample.id}: generated module matches samples/${sample.id}/ (run npm run samples)`, () => {
      expect(sample.files).toEqual(readSampleDir(ROOT, sample.id));
    });

    it(`${sample.id}: downloadable ZIPs hold the same files`, () => {
      const expected = readSampleDir(ROOT, sample.id);
      for (const zip of [path.join("public", sample.zipPath), `${sample.id}-sample.zip`]) {
        expect(unzipToFileMap(readFileSync(path.join(ROOT, zip)))).toEqual(expected);
      }
    });

    it(`${sample.id}: ships source only, no scan results or fixes`, () => {
      const paths = Object.keys(sample.files);
      expect(paths.some((p) => /HOI-SECURITY|finding|\.fixed\./i.test(p))).toBe(false);
    });
  }
});
