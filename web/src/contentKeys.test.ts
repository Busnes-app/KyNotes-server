import { describe, expect, it } from "vitest";
import { asContentKey, decryptObject, encryptNote } from "./crypto";
import { ownCopyKeys, readKeys, WAITING_GENERATION } from "./keyring";

/** Every non-test source file under web/src, vendored ky-ui excluded. */
const all = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
const sources = Object.entries(all).map(([file, text]) => ({ file: file.slice(2), text }));
const using = (pattern: RegExp) => sources.filter(({ text }) => pattern.test(text)).map(({ file }) => file).sort();

/**
 * Casts that can push raw bytes past the KeyRef brand: as KeyRef, <KeyRef>, as never, as any, as unknown as,
 * as Parameters<…>, or an alias of KeyRef. Each allowed line is named with its file; none of them carries a key.
 */
const BYPASS = /\bas\s+(?:KeyRef|never|any|unknown\s+as|Parameters\s*<)|(?<![\w.])<\s*KeyRef\s*>|\btype\s+\w+\s*=\s*KeyRef\b/;
const ALLOWED_CASTS = new Set([
  "crypto.ts: return bytes as KeyRef;", // asContentKey: the one brand-minting function
  "crypto.ts: crypto.getRandomValues(buffer as any);", // a nonce buffer
  "document.ts: case \"paragraph\": return [{ type: \"paragraph\", content: content as never }];", // editor JSON
  "document.ts: case \"heading\": return [{ type: \"heading\", props: { level: Number(node.attrs?.level) || 1 }, content: content as never }];",
  "knowledge.ts: blocks.forEach((block) => visit(block as Parameters<typeof visit>[0]));", // plaintext text projection
  "api.ts: body: bytes as unknown as BodyInit,", // ciphertext request bodies
  "api.ts: export function uploadChunk(uploadID: string, index: number, bytes: Uint8Array) { return request<{ receivedBytes: number; nextChunk: number }>(`/api/v1/uploads/${encodeURIComponent(uploadID)}`, { method: \"PATCH\", body: bytes as unknown as BodyInit, headers: { \"Content-Type\": \"application/octet-stream\", \"X-Kynotes-Chunk-Index\": String(index) } }); }",
]);
const bypasses = (files: Array<{ file: string; text: string }>) => files.flatMap(({ file, text }) =>
  text.split("\n").filter((line) => BYPASS.test(line)).map((line) => `${file}: ${line.trim()}`).filter((entry) => !ALLOWED_CASTS.has(entry)));

describe("content keys", () => {
  it("only keyring.ts makes content keys, and nothing casts to one", () => {
    expect(sources.map(({ file }) => file)).toEqual(expect.arrayContaining(["main.tsx", "keyring.ts", "crypto.ts"]));
    expect(using(/asContentKey\(/)).toEqual(["crypto.ts", "keyring.ts"]); // crypto.ts: the definition
    expect(using(/as KeyRef\b/)).toEqual(["crypto.ts"]);
  });

  it("no cast can push raw bytes past the brand", () => {
    expect(bypasses(sources)).toEqual([]);
    // Every allowed line still exists, so the list cannot keep a stale exception.
    const present = new Set(sources.flatMap(({ file, text }) => text.split("\n").map((line) => `${file}: ${line.trim()}`)));
    for (const entry of ALLOWED_CASTS) expect(present, entry).toContain(entry);
    // A planted bypass of each kind fails.
    for (const planted of ["encryptNote(secret as never, id, note);", "decryptObject(<KeyRef>bytes, id, body);", "const k = bytes as any;", "const k = bytes as unknown as Uint8Array;", "const k = bytes as KeyRef;", "type K = KeyRef;", "encryptNote(bytes as Parameters<typeof encryptNote>[0], id, note);"])
      expect(bypasses([{ file: "main.tsx", text: planted }]), planted).toHaveLength(1);
    expect(bypasses([{ file: "keyring.ts", text: "const ring = new Map<number, KeyRef>(); const keys: Promise<KeyRef> = p;" }])).toEqual([]);
  });

  it("no login-derived content key or legacy read path exists", () => {
    expect(using(/legacyKeyRef|legacyKeys|legacyRow|localReadKeys|copyableConflicts|movesLabelledSubpage|unverified|UNVERIFIED|hexBytes\(auth/)).toEqual([]);
  });

  it("authSecret appears only where it does login work, never on a line with content crypto", () => {
    const allowed = ["api.ts", "components/AdminConsole.tsx", "components/RecoveryCode.tsx", "crypto.ts", "identity.ts", "main.tsx", "recovery.ts", "stepup.ts", "storage.ts"];
    for (const file of using(/authsecret/i)) expect(allowed).toContain(file);
    for (const { file, text } of sources.filter(({ text }) => /authsecret/i.test(text))) {
      for (const line of text.split("\n").filter((value) => /authsecret/i.test(value))) {
        expect(line, file).not.toMatch(/encrypt(Note|Comment|Attachment|ContainerMeta)|decrypt(Object|Note|Comment|Attachment|ContainerMeta)|KeyRef|readKeys|ownCopyKeys|openFirst/);
      }
    }
  });

  it("server rows are read with readKeysFor; only this browser's own copies may use the waiting key", () => {
    const main = all["./main.tsx"];
    const calls = main.split("\n").filter((line) => line.includes("ownCopyKeysFor(") && !line.includes("const ownCopyKeysFor"));
    expect(calls.length).toBeGreaterThan(0);
    for (const line of calls) expect(line).toMatch(/cached|item\./);
    // The waiting key reaches only ownCopyKeys, and only ownCopyKeysFor calls it; readKeysFor never sees it.
    expect(main.match(/\bownCopyKeys\(/g)).toHaveLength(1);
    const readFor = main.slice(main.indexOf("  const readKeysFor"), main.indexOf("\n  };", main.indexOf("  const readKeysFor")));
    expect(readFor).toMatch(/\breadKeys\(container, ringsRef\.current\[container\.id\] \?\? noKeys, generation, floor\)/);
    expect(readFor).not.toMatch(/waiting|ownCopyKeys\(/);
  });

  it("pending uploads are read, cleared and sent only for this account", () => {
    const main = all["./main.tsx"];
    expect(main.match(/\bpendingUploads\(/g)?.length).toBe(main.match(/\bpendingUploads\(auth\.user\.id\)/g)?.length);
    expect(main.match(/\bclearUpload\(/g)?.length).toBe(main.match(/\bclearUpload\(auth\.user\.id, /g)?.length);
    expect(main).toContain("const job = { uploadId: upload.uploadId, owner: auth.user.id,");
    // An upload that is not this account's is never re-sealed or sent, whatever list it came from.
    const pending = main.slice(main.indexOf("  async function uploadPending("));
    expect(pending.indexOf("if (job.owner !== auth.user.id) throw")).toBeGreaterThan(-1);
    expect(pending.indexOf("if (job.owner !== auth.user.id) throw")).toBeLessThan(pending.indexOf("attachmentStep("));
  });

  it("every read of the queue in a session keeps only this account's entries", () => {
    for (const [file, text] of Object.entries(all)) {
      for (const line of text.split("\n").filter((value) => /\bpendingSaves\(\)/.test(value) && !/export async function/.test(value)))
        expect(line, file).toMatch(/\.filter\(\(item\) => item\.owner === (?:auth\.user\.id|userID)\)|unsentEdits\(.*, userID\);$/);
    }
  });
});

describe("readKeys", () => {
  const k2 = asContentKey(new Uint8Array(32).fill(2));
  const ring = new Map([[2, k2]]);
  it("opens a row only with its own generation's container key", () => {
    expect(readKeys({ sharedGeneration: 2 }, ring, 2, {})).toEqual([k2]);
    for (const generation of [undefined, 0, 1, 1.5, 3, -1]) expect(readKeys({ sharedGeneration: 2 }, ring, generation, {})).toEqual([]);
  });
  it("an unkeyed container has no read key for any generation, and the floor wins over a lower report", () => {
    expect(readKeys({ sharedGeneration: 0 }, ring, 2, {})).toEqual([]);
    expect(readKeys({ sharedGeneration: 0 }, ring, 2, { shared: 3 })).toEqual([]);
  });
  it("a waiting copy opens only with the waiting key, and only through ownCopyKeys", () => {
    const waiting = asContentKey(new Uint8Array(32).fill(7));
    expect(readKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {})).toEqual([]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {}, waiting)).toEqual([waiting]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {})).toEqual([]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, 2, {}, waiting)).toEqual([k2]);
  });
  it("content crypto takes only a branded content key, never raw bytes (checked by tsc)", () => {
    const raw = new Uint8Array(32);
    // @ts-expect-error raw bytes, such as a login-derived secret, are not a content key
    const seal = () => encryptNote(raw, "cnt_x", { title: "", body: "" });
    // @ts-expect-error nor can they open content
    const open = () => decryptObject(raw, "cnt_x", raw);
    expect([seal, open]).toHaveLength(2);
  });
  it("refuses a content key that is not 32 bytes", () => {
    expect(() => asContentKey(new Uint8Array(31))).toThrow();
  });
});
