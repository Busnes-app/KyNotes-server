import { describe, expect, it } from "vitest";
import { crc32, zip } from "./zip";

/** Reads a stored zip back through its central directory, checking each local header and CRC. */
function unzip(bytes: Uint8Array): Array<{ path: string; data: Uint8Array }> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = bytes.length - 22;
  expect(view.getUint32(end, true)).toBe(0x06054b50);
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const out = [];
  for (let i = 0; i < count; i += 1) {
    expect(view.getUint32(at, true)).toBe(0x02014b50);
    expect(view.getUint16(at + 8, true) & 0x0800).toBe(0x0800);
    expect(view.getUint16(at + 10, true)).toBe(0); // stored
    const crc = view.getUint32(at + 16, true), size = view.getUint32(at + 20, true), nameLength = view.getUint16(at + 28, true);
    const local = view.getUint32(at + 42, true);
    const path = decoder.decode(bytes.subarray(at + 46, at + 46 + nameLength));
    expect(view.getUint32(local, true)).toBe(0x04034b50);
    expect(decoder.decode(bytes.subarray(local + 30, local + 30 + nameLength))).toBe(path);
    const data = bytes.subarray(local + 30 + nameLength, local + 30 + nameLength + size);
    expect(crc32(data)).toBe(crc);
    out.push({ path, data });
    at += 46 + nameLength;
  }
  return out;
}

describe("zip", () => {
  it("computes the standard CRC-32", () => {
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
    expect(crc32(new Uint8Array())).toBe(0);
  });

  it("writes stored entries with UTF-8 names that read back byte for byte", async () => {
    const files = [
      { path: "Notebook/manifest.json", data: new TextEncoder().encode("{}") },
      { path: "Notebook/Sektion ü/001 Café ☕.md", data: new TextEncoder().encode("# Café\n") },
      { path: "Notebook/attachments/a/empty.bin", data: new Uint8Array() },
      { path: "Notebook/attachments/b/bytes.bin", data: Uint8Array.from({ length: 300 }, (_, i) => i % 256) },
    ];
    const blob = zip(files, new Date(2026, 9, 17, 12, 30, 10));
    expect(blob.type).toBe("application/zip");
    const read = unzip(new Uint8Array(await blob.arrayBuffer()));
    expect(read.map((entry) => entry.path)).toEqual(files.map((entry) => entry.path));
    read.forEach((entry, i) => expect(Array.from(entry.data)).toEqual(Array.from(files[i].data)));
  });

  it("writes an empty archive", async () => {
    expect(unzip(new Uint8Array(await zip([]).arrayBuffer()))).toEqual([]);
  });
});
