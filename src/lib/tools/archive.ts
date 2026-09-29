import { gunzipSync, inflateRawSync } from "zlib";

/**
 * 릴리스 압축 파일에서 실행 파일 하나만 꺼낸다(Node 기본 모듈만 사용).
 * 경로는 쓰지 않고 이름(basename)으로만 찾으므로 압축 파일 안의 경로 조작
 * (../ 같은)이 디스크에 영향을 주지 않는다.
 */

const MAX_ENTRY_BYTES = 200 * 1024 * 1024;

function basename(name: string): string {
  return name.split(/[\\/]/).pop() ?? name;
}

/** zip(저장 또는 deflate)에서 이름이 같은 파일을 꺼낸다. */
export function extractFileFromZip(zip: Buffer, fileName: string): Buffer | undefined {
  // End of central directory: 뒤에서부터 찾는다(주석 최대 64KB).
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 0xffff); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip: end of central directory not found");
  const entries = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < entries; n++) {
    if (p + 46 > zip.length || zip.readUInt32LE(p) !== 0x02014b50) throw new Error("zip: bad central directory");
    const method = zip.readUInt16LE(p + 10);
    const compSize = zip.readUInt32LE(p + 20);
    const size = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const localOffset = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/") || basename(name) !== fileName) continue;
    if (size > MAX_ENTRY_BYTES) throw new Error("zip: entry too large");
    if (zip.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("zip: bad local header");
    const start = localOffset + 30 + zip.readUInt16LE(localOffset + 26) + zip.readUInt16LE(localOffset + 28);
    const data = zip.subarray(start, start + compSize);
    if (method === 0) return Buffer.from(data);
    if (method === 8) return inflateRawSync(data, { maxOutputLength: MAX_ENTRY_BYTES });
    throw new Error(`zip: unsupported compression ${method}`);
  }
  return undefined;
}

/** tar.gz(ustar)에서 이름이 같은 일반 파일을 꺼낸다. */
export function extractFileFromTarGz(tgz: Buffer, fileName: string): Buffer | undefined {
  const tar = gunzipSync(tgz, { maxOutputLength: MAX_ENTRY_BYTES });
  const field = (header: Buffer, a: number, b: number) => header.subarray(a, b).toString("utf8").replace(/\0[\s\S]*$/, "");
  let p = 0;
  while (p + 512 <= tar.length) {
    const header = tar.subarray(p, p + 512);
    if (header.every((b) => b === 0)) break;
    const rawName = field(header, 0, 100);
    const prefix = field(header, 345, 500);
    const name = prefix ? `${prefix}/${rawName}` : rawName;
    const size = parseInt(field(header, 124, 136).trim() || "0", 8);
    // 0 또는 NUL = 일반 파일.
    const type = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    const start = p + 512;
    if (!Number.isFinite(size) || size < 0 || start + size > tar.length) throw new Error("tar: bad entry size");
    if (type === "0" && basename(name) === fileName) return Buffer.from(tar.subarray(start, start + size));
    p = start + Math.ceil(size / 512) * 512;
  }
  return undefined;
}
