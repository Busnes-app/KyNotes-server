import { describe, expect, it } from "vitest";
import { asContentKey, decryptObject, encryptNote } from "./crypto";
import { ownCopyKeys, readKeys, WAITING_GENERATION } from "./keyring";

/** Every non-test source file under web/src, vendored ky-ui excluded. */
const all = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
const sources = Object.entries(all).map(([file, text]) => ({ file: file.slice(2), text }));
const using = (pattern: RegExp) => sources.filter(({ text }) => pattern.test(text)).map(({ file }) => file).sort();

describe("content keys", () => {
  it("only keyring.ts makes content keys, and nothing casts to one", () => {
    expect(sources.map(({ file }) => file)).toEqual(expect.arrayContaining(["main.tsx", "keyring.ts", "crypto.ts"]));
    expect(using(/asContentKey\(/)).toEqual(["crypto.ts", "keyring.ts"]); // crypto.ts: the definition
    expect(using(/as KeyRef\b/)).toEqual(["crypto.ts"]);
  });

  it("no login-derived content key or legacy read path exists", () => {
    expect(using(/legacyKeyRef|legacyKeys|legacyRow|localReadKeys|copyableConflicts|movesLabelledSubpage|unverified|UNVERIFIED|hexBytes\(auth/)).toEqual([]);
  });

  it("authSecret appears only where it does login work, never on a line with content crypto", () => {
    const allowed = ["api.ts", "components/RecoveryCode.tsx", "crypto.ts", "identity.ts", "main.tsx", "recovery.ts", "stepup.ts", "storage.ts"];
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
