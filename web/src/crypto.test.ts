import { describe, expect, it, vi } from "vitest";
import { asContentKey, fromBase64, decryptAttachment, decryptAttachmentMetadata, decryptComment, decryptContainerMeta, decryptNote, decryptObject, decryptSharePayload, deriveAuthSecret, digestSha256Hex, encryptAttachment, encryptAttachmentMetadata, encryptComment, encryptContainerMeta, encryptNote, encryptSharePayload, hkdfSha256, legacyChildOpens, LEGACY_LOGIN_ITERATIONS, LOGIN_ITERATIONS, NEEDS_HTTPS, openObject, randomLoginSalt, type KeyRef } from "./crypto";

describe("browser crypto", () => {
  it("matches the server auth fixture", async () => {
    await expect(deriveAuthSecret("correct horse battery staple", "MDEyMzQ1Njc4OWFiY2RlZg==", 100000, LEGACY_LOGIN_ITERATIONS)).resolves.toBe(
      "b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d",
    );
  });

  it("round-trips encrypted note content", async () => {
    const secret = asContentKey(new Uint8Array(32).fill(9));
    const note = { title: "Private", body: "Only the browser sees this.\n\n![pixel](data:image/png;base64,AA==)" };
    const ciphertext = await encryptNote(secret, "cnt_test", "obj_a", note);
    expect(new TextDecoder().decode(ciphertext)).not.toContain(note.body);
    await expect(decryptNote(secret, "cnt_test", "obj_a", ciphertext, false)).resolves.toEqual(note);
  });

  it("round-trips workspace names without exposing plaintext", async () => {
    const secret = asContentKey(new Uint8Array(32).fill(9));
    const ciphertext = await encryptContainerMeta(secret, "cnt_test", "Research");
    expect(new TextDecoder().decode(ciphertext)).not.toContain("Research");
    await expect(decryptContainerMeta(secret, "cnt_test", ciphertext, false)).resolves.toEqual({ name: "Research" });
    await expect(decryptContainerMeta(secret, "cnt_test", await encryptContainerMeta(secret, "cnt_test", "Research", true), false)).resolves.toEqual({ name: "Research", objects: 2 });
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
  const secret = asContentKey(new Uint8Array(32).fill(9));
  const cnt = "cnt_test";
  it("round-trips a placed page and a section through the object key", async () => {
    const page = { type: "page" as const, title: "T", body: "b", section: `obj_${"b".repeat(26)}`, order: "i" };
    expect(await decryptObject(secret, cnt, "obj_p", await encryptNote(secret, cnt, "obj_p", page), false)).toEqual(page);
    const section = { type: "section" as const, title: "S", color: "teal" as const, order: "r" };
    expect(await decryptObject(secret, cnt, "obj_s", await encryptNote(secret, cnt, "obj_s", section), false)).toEqual(section);
  });
  it("returns undefined for a payload that decrypts but is not an object payload", async () => {
    expect(await decryptObject(secret, cnt, "obj_p", await encryptNote(secret, cnt, "obj_p", [] as never), false)).toBeUndefined();
  });
});

describe("content keys", () => {
  // A fixed vector: encryptNote(0x5a×32, "cnt_legacyfixture", …). The content format does not drift.
  const VECTOR = "rSmf1huCgm2R/XQ9P8xstlQUmhhtrDyMHSVLtqGStWeMMUQfiWjT8DyXkU++Hdsmu5W+e8C+j7yGvElvE6ECcyGFADwleuCMbA==";
  it("opens a known ciphertext vector", async () => {
    await expect(decryptNote(asContentKey(new Uint8Array(32).fill(0x5a)), "cnt_legacyfixture", "obj_any", fromBase64(VECTOR), true)).resolves.toEqual({ title: "Legacy", body: "written before P3" });
  });
  it("keys content by the container key, never across keys or containers", async () => {
    const ck = asContentKey(new Uint8Array(32).fill(7));
    const sealed = await encryptNote(ck, "cnt_a", "obj_a", { title: "T", body: "B" });
    await expect(decryptNote(ck, "cnt_a", "obj_a", sealed, true)).resolves.toEqual({ title: "T", body: "B" });
    await expect(decryptNote(asContentKey(new Uint8Array(32).fill(8)), "cnt_a", "obj_a", sealed, true)).rejects.toThrow();
    await expect(decryptNote(ck, "cnt_b", "obj_a", sealed, true)).rejects.toThrow();
  });
  it("refuses a key that is not 32 bytes", async () => {
    await expect(encryptNote(new Uint8Array(16) as never, "cnt_a", "obj_a", { title: "", body: "" })).rejects.toThrow("invalid content key");
  });
  it("refuses fewer login iterations than new accounts use, whatever the server sends", async () => {
    for (const iterations of [1, LEGACY_LOGIN_ITERATIONS, LOGIN_ITERATIONS - 1, Number.NaN, 1e300]) {
      await expect(deriveAuthSecret("pw", "MDEyMzQ1Njc4OWFiY2RlZg==", iterations), String(iterations)).rejects.toThrow(/too few password iterations/);
    }
    await expect(deriveAuthSecret("pw", "MDEyMzQ1Njc4OWFiY2RlZg==", LEGACY_LOGIN_ITERATIONS - 1, LEGACY_LOGIN_ITERATIONS)).rejects.toThrow(/too few password iterations/);
  });
  it("needs WebCrypto: no fallback cipher and no Math.random", async () => {
    const random = vi.spyOn(Math, "random");
    vi.stubGlobal("crypto", undefined);
    try {
      expect(() => randomLoginSalt()).toThrow(NEEDS_HTTPS);
      await expect(encryptNote(asContentKey(new Uint8Array(32).fill(7)), "cnt_a", "obj_a", { title: "T", body: "B" })).rejects.toThrow(NEEDS_HTTPS);
      expect(random).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
      random.mockRestore();
    }
  });
});

/** The v1 form older builds wrote: nonce(12) ‖ AES-256-GCM(HKDF(key, containerID, label)), no AAD. */
async function sealV1(key: KeyRef, containerID: string, label: string, plaintext: Uint8Array, nonce = crypto.getRandomValues(new Uint8Array(12))) {
  const subkey = await crypto.subtle.importKey("raw", hkdfSha256(key, 32, new TextEncoder().encode(containerID), new TextEncoder().encode(label)).slice().buffer as ArrayBuffer, "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, subkey, plaintext.slice().buffer as ArrayBuffer));
  return new Uint8Array([...nonce, ...sealed]);
}

describe("content v2 binding", () => {
  const key = asContentKey(new Uint8Array(32).fill(3));
  const cnt = "cnt_a";
  const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const page = { type: "page" as const, title: "A", body: "[]", legacy: {} };

  it("refuses a ciphertext swapped between two objects", async () => {
    const a = await encryptNote(key, cnt, "obj_a", page);
    expect(a[0]).toBe(2);
    await expect(decryptObject(key, cnt, "obj_b", a, false)).rejects.toThrow();
    await expect(decryptObject(key, cnt, "obj_b", a, true)).rejects.toThrow();
  });

  it("refuses a ciphertext served as another kind, even bound to the same page", async () => {
    const asObject = (bytes: Uint8Array) => decryptObject(key, cnt, "obj_a", bytes, true);
    await expect(asObject(await encryptComment(key, cnt, "obj_a", "hi"))).rejects.toThrow();
    await expect(asObject(await encryptAttachment(key, cnt, "obj_a", json(page)))).rejects.toThrow();
    await expect(asObject(await encryptAttachmentMetadata(key, cnt, "obj_a", { name: "n", type: "t", size: 1 }))).rejects.toThrow();
    await expect(decryptObject(key, cnt, cnt, await encryptContainerMeta(key, cnt, "N", true), true)).rejects.toThrow();
    const object = await encryptNote(key, cnt, "obj_a", page);
    await expect(decryptComment(key, cnt, "obj_a", object, true)).rejects.toThrow();
    await expect(decryptAttachment(key, cnt, "obj_a", object, true)).rejects.toThrow();
    await expect(decryptAttachmentMetadata(key, cnt, "obj_a", object, true)).rejects.toThrow();
    await expect(decryptContainerMeta(key, cnt, object, true)).rejects.toThrow();
    // A comment bound to page A is refused on page B.
    await expect(decryptComment(key, cnt, "obj_b", await encryptComment(key, cnt, "obj_a", "hi"), false)).rejects.toThrow();
  });

  it("reads v1 only while allowed, including a v1 nonce starting with the v2 byte", async () => {
    for (const nonce of [new Uint8Array(12), new Uint8Array(12).fill(2)]) {
      const old = await sealV1(key, cnt, "kynotes/object/v1", json({ type: "page", title: "Old", body: "" }), nonce);
      await expect(openObject(key, cnt, "obj_a", old, true)).resolves.toEqual({ payload: { type: "page", title: "Old", body: "" }, v1: true });
      await expect(openObject(key, cnt, "obj_a", old, false)).rejects.toThrow();
    }
    await expect(openObject(key, cnt, "obj_a", await encryptNote(key, cnt, "obj_a", page), true)).resolves.toEqual({ payload: page, v1: false });
    // A v1 meta's marker never counts, and after the marker a v1 meta is refused.
    const oldMeta = await sealV1(key, cnt, "kynotes/container-meta/v1", json({ name: "N", objects: 2 }));
    await expect(decryptContainerMeta(key, cnt, oldMeta, true)).resolves.toEqual({ name: "N" });
    await expect(decryptContainerMeta(key, cnt, oldMeta, false)).rejects.toThrow();
  });

  it("accepts a v1 child only before legacy pins exist, or when pinned by its digest", async () => {
    const comment = await sealV1(key, cnt, "kynotes/comment/v1", json({ body: "old", section: "" }));
    const pinned = { legacy: { cmt_x: await digestSha256Hex(comment) } };
    expect(await legacyChildOpens({}, false, "cmt_x", comment)).toBe(true);
    expect(await legacyChildOpens({}, true, "cmt_x", comment)).toBe(false);
    expect(await legacyChildOpens({ legacy: {} }, false, "cmt_x", comment)).toBe(false);
    expect(await legacyChildOpens(pinned, true, "cmt_x", comment)).toBe(true);
    expect(await legacyChildOpens(pinned, true, "cmt_y", comment)).toBe(false);
    expect(await legacyChildOpens(pinned, true, "cmt_x", await sealV1(key, cnt, "kynotes/comment/v1", json({ body: "swapped" })))).toBe(false);
    expect(await legacyChildOpens(pinned, true, "constructor")).toBe(false);
    expect(await legacyChildOpens(undefined, false, "cmt_x", comment)).toBe(false);
    const allowed = await legacyChildOpens(pinned, true, "cmt_x", comment);
    await expect(decryptComment(key, cnt, "obj_a", comment, allowed)).resolves.toEqual({ body: "old", section: "" });
    await expect(decryptComment(key, cnt, "obj_a", comment, false)).rejects.toThrow();
  });
});
