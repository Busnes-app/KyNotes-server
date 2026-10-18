import { afterEach, describe, expect, it, vi } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import vectors from "../../testdata/protocol/payload_vectors.json";
import {
  asContentKey,
  decryptAttachment,
  decryptAttachmentMetadata,
  decryptContainerMeta,
  decryptObject,
  encryptAttachment,
  encryptAttachmentMetadata,
  encryptContainerMeta,
  encryptNote,
} from "./crypto";

/** The next nonce crypto.ts draws is the vector's, so its output must equal Go's bytes. */
function withNonce(hex: string) {
  vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((array) => {
    (array as Uint8Array).set(h(hex));
    return array;
  });
}

afterEach(() => vi.restoreAllMocks());

describe("internal/notecrypto vectors (testdata/protocol/payload_vectors.json)", () => {
  it("opens what Go sealed", async () => {
    for (const v of vectors.objects) expect(await decryptObject(asContentKey(h(v.key)), v.containerId, h(v.sealed))).toEqual(v.payload);
    for (const v of vectors.containerNames) expect(await decryptContainerMeta(asContentKey(h(v.key)), v.containerId, h(v.sealed))).toEqual({ name: v.name });
    for (const v of vectors.attachmentMeta) expect(await decryptAttachmentMetadata(asContentKey(h(v.key)), v.containerId, h(v.sealed))).toEqual(v.meta);
    for (const v of vectors.attachments) expect(bytesToHex(await decryptAttachment(asContentKey(h(v.key)), v.containerId, h(v.sealed)))).toBe(v.plaintext);
  });

  it("seals exactly the bytes Go opens", async () => {
    for (const v of vectors.objects) {
      withNonce(v.nonce);
      expect(bytesToHex(await encryptNote(asContentKey(h(v.key)), v.containerId, JSON.parse(v.plaintext)))).toBe(v.sealed);
    }
    for (const v of vectors.containerNames) {
      withNonce(v.nonce);
      expect(bytesToHex(await encryptContainerMeta(asContentKey(h(v.key)), v.containerId, v.name))).toBe(v.sealed);
    }
    for (const v of vectors.attachmentMeta) {
      withNonce(v.nonce);
      expect(bytesToHex(await encryptAttachmentMetadata(asContentKey(h(v.key)), v.containerId, v.meta))).toBe(v.sealed);
    }
    for (const v of vectors.attachments) {
      withNonce(v.nonce);
      expect(bytesToHex(await encryptAttachment(asContentKey(h(v.key)), v.containerId, h(v.plaintext)))).toBe(v.sealed);
    }
  });

  it("refuses a vector under another container or with a flipped byte", async () => {
    const v = vectors.objects[0];
    const key = asContentKey(h(v.key));
    await expect(decryptObject(key, vectors.objects[1].containerId, h(v.sealed))).rejects.toThrow();
    const bad = h(v.sealed);
    bad[bad.length - 1] ^= 1;
    await expect(decryptObject(key, v.containerId, bad)).rejects.toThrow();
  });
});
