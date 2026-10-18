export type ZipEntry = { path: string; data: Uint8Array };

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * A stored (uncompressed) zip with UTF-8 names. ponytail: no compression and no zip64, so at most
 * 65 535 entries and 4 GiB; deflate via CompressionStream("deflate-raw") is the upgrade path.
 */
export function zip(entries: ZipEntry[], when = new Date()): Blob {
  if (entries.length > 0xffff) throw new Error("Too many files for one zip");
  const time = (when.getHours() << 11) | (when.getMinutes() << 5) | (when.getSeconds() >> 1);
  const date = (Math.max(0, when.getFullYear() - 1980) << 9) | ((when.getMonth() + 1) << 5) | when.getDate();
  const encoder = new TextEncoder();
  const parts: BlobPart[] = [];
  const central: Uint8Array<ArrayBuffer>[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = encoder.encode(entry.path);
    const crc = crc32(entry.data);
    const size = entry.data.length;
    if (offset + 30 + name.length + size > 0xffffffff) throw new Error("Export is larger than 4 GiB");
    const local = new Uint8Array(30 + name.length);
    const l = new DataView(local.buffer);
    l.setUint32(0, 0x04034b50, true);
    l.setUint16(4, 20, true);
    l.setUint16(6, 0x0800, true); // names are UTF-8
    l.setUint16(10, time, true); l.setUint16(12, date, true);
    l.setUint32(14, crc, true); l.setUint32(18, size, true); l.setUint32(22, size, true);
    l.setUint16(26, name.length, true);
    local.set(name, 30);
    const header = new Uint8Array(46 + name.length);
    const c = new DataView(header.buffer);
    c.setUint32(0, 0x02014b50, true);
    c.setUint16(4, 20, true); c.setUint16(6, 20, true);
    c.setUint16(8, 0x0800, true);
    c.setUint16(12, time, true); c.setUint16(14, date, true);
    c.setUint32(16, crc, true); c.setUint32(20, size, true); c.setUint32(24, size, true);
    c.setUint16(28, name.length, true);
    c.setUint32(42, offset, true);
    header.set(name, 46);
    central.push(header);
    parts.push(local, entry.data.slice().buffer as ArrayBuffer);
    offset += local.length + size;
  }
  const centralSize = central.reduce((sum, header) => sum + header.length, 0);
  const end = new Uint8Array(22);
  const e = new DataView(end.buffer);
  e.setUint32(0, 0x06054b50, true);
  e.setUint16(8, entries.length, true); e.setUint16(10, entries.length, true);
  e.setUint32(12, centralSize, true); e.setUint32(16, offset, true);
  return new Blob([...parts, ...central, end], { type: "application/zip" });
}
