import { describe, expect, it } from "vitest";
import { legacyKeyRef, fromBase64, decryptContainerMeta, decryptNote, decryptObject, decryptSharePayload, deriveAuthSecret, encryptContainerMeta, encryptNote, encryptSharePayload } from "./crypto";

describe("browser crypto", () => {
  it("matches the server auth fixture", async () => {
    await expect(deriveAuthSecret("correct horse battery staple", "MDEyMzQ1Njc4OWFiY2RlZg==", 100000)).resolves.toBe(
      "b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d",
    );
  });

  it("round-trips encrypted note content", async () => {
    const secret = legacyKeyRef("b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d");
    const note = { title: "Private", body: "Only the browser sees this.\n\n![pixel](data:image/png;base64,AA==)" };
    const ciphertext = await encryptNote(secret, "cnt_test", note);
    expect(new TextDecoder().decode(ciphertext)).not.toContain(note.body);
    await expect(decryptNote(secret, "cnt_test", ciphertext)).resolves.toEqual(note);
  });

  it("round-trips workspace names without exposing plaintext", async () => {
    const secret = legacyKeyRef("b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d");
    const ciphertext = await encryptContainerMeta(secret, "cnt_test", "Research");
    expect(new TextDecoder().decode(ciphertext)).not.toContain("Research");
    await expect(decryptContainerMeta(secret, "cnt_test", ciphertext)).resolves.toEqual({ name: "Research" });
  });

  it("seals a share with a separate URL-fragment key", async () => {
    const note = { title: "Shared", body: "Ciphertext only" };
    const sealed = await encryptSharePayload(note);
    expect(sealed.key).not.toContain("=");
    expect(new TextDecoder().decode(sealed.ciphertext)).not.toContain(note.body);
    await expect(decryptSharePayload(sealed.ciphertext, sealed.key)).resolves.toEqual(note);
  });
});

describe("object payloads", () => {
  const secret = legacyKeyRef("b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d");
  const cnt = "cnt_test";
  it("round-trips a placed page and a section through the object key", async () => {
    const page = { type: "page" as const, title: "T", body: "b", section: `obj_${"b".repeat(26)}`, order: "i" };
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, page))).toEqual(page);
    const section = { type: "section" as const, title: "S", color: "teal" as const, order: "r" };
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, section))).toEqual(section);
  });
  it("returns undefined for a payload that decrypts but is not an object payload", async () => {
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, [] as never))).toBeUndefined();
  });
});

describe("content keys", () => {
  // Ciphertext produced by the pre-P3 encryptNote("5a"×32, "cnt_legacyfixture", …): legacy rows must still open.
  const LEGACY_NOTE = "rSmf1huCgm2R/XQ9P8xstlQUmhhtrDyMHSVLtqGStWeMMUQfiWjT8DyXkU++Hdsmu5W+e8C+j7yGvElvE6ECcyGFADwleuCMbA==";
  it("opens legacy ciphertext through legacyKeyRef", async () => {
    await expect(decryptNote(legacyKeyRef("5a".repeat(32)), "cnt_legacyfixture", fromBase64(LEGACY_NOTE))).resolves.toEqual({ title: "Legacy", body: "written before P3" });
  });
  it("keys content by the container key, never across keys or containers", async () => {
    const ck = new Uint8Array(32).fill(7);
    const sealed = await encryptNote(ck, "cnt_a", { title: "T", body: "B" });
    await expect(decryptNote(ck, "cnt_a", sealed)).resolves.toEqual({ title: "T", body: "B" });
    await expect(decryptNote(new Uint8Array(32).fill(8), "cnt_a", sealed)).rejects.toThrow();
    await expect(decryptNote(ck, "cnt_b", sealed)).rejects.toThrow();
  });
  it("refuses a key that is not 32 bytes", async () => {
    await expect(encryptNote(new Uint8Array(16), "cnt_a", { title: "", body: "" })).rejects.toThrow("invalid content key");
  });
});
