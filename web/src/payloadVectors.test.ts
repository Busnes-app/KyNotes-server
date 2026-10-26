import { afterEach, describe, expect, it, vi } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import vectors from "../../testdata/protocol/payload_vectors.json";
import {
  asContentKey,
  decryptAttachment,
  decryptAttachmentMetadata,
  decryptComment,
  decryptContainerMeta,
  decryptObject,
  encryptAttachment,
  encryptAttachmentMetadata,
  encryptComment,
  encryptContainerMeta,
  encryptNote,
  hkdfSha256,
} from "./crypto";

/** The next nonce crypto.ts draws is the vector's, so its output must equal Go's bytes. */
function withNonce(hex: string) {
  vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((array) => {
    (array as Uint8Array).set(h(hex));
    return array;
  });
}

afterEach(() => vi.restoreAllMocks());

const json = (hex: string) => JSON.parse(new TextDecoder().decode(h(hex)));
type V2 = (typeof vectors.v2)[number];
/** Each kind through its public crypto.ts pair: open (v1 refused) and seal. */
const kinds: Record<string, { open: (v: V2) => Promise<unknown>; seal: (v: V2) => Promise<Uint8Array>; want: (v: V2) => unknown }> = {
  object: { open: (v) => decryptObject(asContentKey(h(v.key)), v.containerId, v.boundId, h(v.sealed), false), seal: (v) => encryptNote(asContentKey(h(v.key)), v.containerId, v.boundId, json(v.plaintext)), want: (v) => json(v.plaintext) },
  comment: { open: (v) => decryptComment(asContentKey(h(v.key)), v.containerId, v.boundId, h(v.sealed), false), seal: (v) => encryptComment(asContentKey(h(v.key)), v.containerId, v.boundId, json(v.plaintext).body, json(v.plaintext).section), want: (v) => json(v.plaintext) },
  attachment: { open: async (v) => bytesToHex(await decryptAttachment(asContentKey(h(v.key)), v.containerId, v.boundId, h(v.sealed), false)), seal: (v) => encryptAttachment(asContentKey(h(v.key)), v.containerId, v.boundId, h(v.plaintext)), want: (v) => v.plaintext },
  "attachment-meta": { open: (v) => decryptAttachmentMetadata(asContentKey(h(v.key)), v.containerId, v.boundId, h(v.sealed), false), seal: (v) => encryptAttachmentMetadata(asContentKey(h(v.key)), v.containerId, v.boundId, json(v.plaintext)), want: (v) => json(v.plaintext) },
  "container-meta": { open: (v) => decryptContainerMeta(asContentKey(h(v.key)), v.containerId, h(v.sealed), false), seal: (v) => encryptContainerMeta(asContentKey(h(v.key)), v.containerId, json(v.plaintext).name, json(v.plaintext).objects === 2), want: (v) => json(v.plaintext) },
};

describe("internal/notecrypto vectors (testdata/protocol/payload_vectors.json)", () => {
  it("opens what Go sealed in v1, only while v1 is allowed", async () => {
    for (const v of vectors.objects) {
      expect(await decryptObject(asContentKey(h(v.key)), v.containerId, "obj_any", h(v.sealed), true)).toEqual(v.payload);
      await expect(decryptObject(asContentKey(h(v.key)), v.containerId, "obj_any", h(v.sealed), false)).rejects.toThrow();
    }
    for (const v of vectors.containerNames) expect(await decryptContainerMeta(asContentKey(h(v.key)), v.containerId, h(v.sealed), true)).toEqual({ name: v.name });
    for (const v of vectors.attachmentMeta) expect(await decryptAttachmentMetadata(asContentKey(h(v.key)), v.containerId, "obj_any", h(v.sealed), true)).toEqual(v.meta);
    for (const v of vectors.attachments) expect(bytesToHex(await decryptAttachment(asContentKey(h(v.key)), v.containerId, "obj_any", h(v.sealed), true))).toBe(v.plaintext);
  });

  it("opens every v2 kind Go sealed, and seals exactly the bytes Go opens", async () => {
    expect(new Set(vectors.v2.map((v) => v.kind))).toEqual(new Set(Object.keys(kinds)));
    for (const v of vectors.v2) {
      expect(await kinds[v.kind].open(v), v.kind).toEqual(kinds[v.kind].want(v));
      withNonce(v.nonce);
      expect(bytesToHex(await kinds[v.kind].seal(v)), v.kind).toBe(v.sealed);
    }
  });

  it("binds each v2 vector to exactly its AAD", async () => {
    for (const v of vectors.v2) {
      const subkey = hkdfSha256(h(v.key), 32, new TextEncoder().encode(v.containerId), new TextEncoder().encode("kynotes/content/v2"));
      const key = await crypto.subtle.importKey("raw", subkey.slice().buffer as ArrayBuffer, "AES-GCM", false, ["decrypt"]);
      const sealed = h(v.sealed);
      const open = (aad: Uint8Array) => crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(1, 13), additionalData: aad.slice().buffer as ArrayBuffer }, key, sealed.slice(13));
      expect(sealed[0]).toBe(2);
      await expect(open(h(v.aad))).resolves.toBeInstanceOf(ArrayBuffer);
      await expect(open(new Uint8Array(0))).rejects.toThrow();
    }
  });

  it("refuses a vector under another container, bound ID or with a flipped byte", async () => {
    const v = vectors.v2[0];
    const key = asContentKey(h(v.key));
    await expect(decryptObject(key, vectors.v2[1].containerId, v.boundId, h(v.sealed), false)).rejects.toThrow();
    await expect(decryptObject(key, v.containerId, vectors.v2[1].boundId, h(v.sealed), false)).rejects.toThrow();
    const bad = h(v.sealed);
    bad[bad.length - 1] ^= 1;
    await expect(decryptObject(key, v.containerId, v.boundId, bad, false)).rejects.toThrow();
  });
});
