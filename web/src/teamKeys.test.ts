import { afterEach, describe, expect, it, vi } from "vitest";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import vectors from "../../testdata/protocol/envelope_vectors.json";
import authVectors from "../../testdata/protocol/auth_vectors.json";
import { deriveLoginKeys } from "./crypto";
import { ENVELOPE_BYTES, envelopeAAD, envelopeSender, generateIdentity, unwrapEnvelope, unwrapIdentity, wrapEnvelope, wrapEnvelopeForVector, wrapIdentityForVector, WRAPPED_IDENTITY_BYTES } from "./teamKeys";

const h = hexToBytes;

describe("primitive vectors", () => {
  it("matches RFC 7748 §5.2 and §6.1", () => {
    expect(bytesToHex(x25519.getSharedSecret(
      h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
      h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ))).toBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    const alice = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bob = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    expect(bytesToHex(x25519.getPublicKey(alice))).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect(bytesToHex(x25519.getPublicKey(bob))).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    expect(bytesToHex(x25519.getSharedSecret(alice, x25519.getPublicKey(bob)))).toBe("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  });

  it("matches RFC 8439 §2.8.2", () => {
    const plaintext = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    const sealed = chacha20poly1305(
      h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
      h("070000004041424344454647"),
      h("50515253c0c1c2c3c4c5c6c7"),
    ).encrypt(plaintext);
    expect(bytesToHex(sealed.subarray(0, 16))).toBe("d31a8d34648e60db7b86afbc53ef7ec2");
    expect(bytesToHex(sealed.subarray(-16))).toBe("1ae10b594f09e26a7e902ecbd0600691");
  });

  it("refuses an all-zero shared secret", () => {
    expect(() => x25519.getSharedSecret(generateIdentity().privateKey, new Uint8Array(32))).toThrow();
  });
});

describe("Go cross-implementation vectors", () => {
  it("derives authSecret and userKEK from one PBKDF2 pass", async () => {
    for (const v of vectors.login) {
      const keys = await deriveLoginKeys(v.password, v.loginSalt, v.iterations);
      expect(keys.authSecret).toBe(v.authSecret);
      expect(bytesToHex(keys.userKEK)).toBe(v.userKEK);
    }
  });

  it("pins authSecret to auth_vectors.json", () => {
    expect(vectors.login[0].authSecret).toBe(authVectors[0].authSecret);
  });

  describe("without WebCrypto", () => {
    afterEach(() => vi.unstubAllGlobals());
    it("pure-JS fallback derives the same keys", async () => {
      vi.stubGlobal("crypto", {});
      const v = vectors.login[0];
      const keys = await deriveLoginKeys(v.password, v.loginSalt, v.iterations);
      expect(keys.authSecret).toBe(v.authSecret);
      expect(bytesToHex(keys.userKEK)).toBe(v.userKEK);
    });
  });

  it("wraps and unwraps the identity exactly like Go", () => {
    for (const v of vectors.identity) {
      const wrapped = wrapIdentityForVector(h(v.userKEK), h(v.privateKey), v.userId, h(v.nonce));
      expect(bytesToHex(wrapped)).toBe(v.wrapped);
      expect(wrapped.length).toBe(WRAPPED_IDENTITY_BYTES);
      const back = unwrapIdentity(h(v.userKEK), h(v.wrapped), v.userId);
      expect(bytesToHex(back.privateKey)).toBe(v.privateKey);
      expect(bytesToHex(back.publicKey)).toBe(v.publicKey);
    }
  });

  it("seals and opens envelopes exactly like Go", () => {
    for (const v of vectors.envelopes) {
      const sender = { deviceId: v.senderDeviceId, privateKey: h(v.senderPrivateKey) };
      const sealed = wrapEnvelopeForVector(h(v.contentKey), h(v.recipientPublicKey), v.containerId, v.keyGeneration, v.recipientDeviceId, sender, h(v.ephemeralPrivateKey), h(v.nonce));
      expect(bytesToHex(sealed)).toBe(v.envelope);
      expect(sealed.length).toBe(ENVELOPE_BYTES);
      expect(envelopeSender(h(v.envelope))).toBe(v.senderDeviceId);
      expect(bytesToHex(unwrapEnvelope(h(v.envelope), h(v.recipientPrivateKey), v.containerId, v.keyGeneration, v.recipientDeviceId, h(v.senderPublicKey)))).toBe(v.contentKey);
    }
  });
});

describe("binding", () => {
  const v = vectors.envelopes[0];
  const open = (envelope: Uint8Array, container = v.containerId, generation = v.keyGeneration, device = v.recipientDeviceId, sender: Uint8Array = h(v.senderPublicKey)) =>
    unwrapEnvelope(envelope, h(v.recipientPrivateKey), container, generation, device, sender);

  it("refuses an envelope replayed into another container, generation or recipient", () => {
    expect(() => open(h(v.envelope), "cnt_00000000000000000000000001")).toThrow();
    expect(() => open(h(v.envelope), v.containerId, v.keyGeneration + 1)).toThrow();
    expect(() => open(h(v.envelope), v.containerId, v.keyGeneration, "dev_00000000000000000000000001")).toThrow();
  });

  it("authenticates the sender: another identity key, a relabelled sender or a zero shared secret fail", () => {
    expect(() => open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, generateIdentity().publicKey)).toThrow();
    expect(() => open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, new Uint8Array(32))).toThrow();
    const relabelled = h(v.envelope);
    relabelled.set(new TextEncoder().encode("dev_00000000000000000000000009"), 1);
    expect(envelopeSender(relabelled)).toBe("dev_00000000000000000000000009");
    expect(() => open(relabelled)).toThrow();
  });

  it("refuses an envelope sealed by anyone but the claimed sender, even for the right recipient", () => {
    // Someone holding only the recipient's public key (a server) cannot impersonate the sender.
    const forger = generateIdentity();
    const forged = wrapEnvelope(h(v.contentKey), h(v.recipientPublicKey), v.containerId, v.keyGeneration, v.recipientDeviceId, { deviceId: v.senderDeviceId, privateKey: forger.privateKey });
    expect(envelopeSender(forged)).toBe(v.senderDeviceId);
    expect(() => open(forged)).toThrow();
  });

  it("refuses tampered, truncated, v1 or malformed-sender envelopes", () => {
    for (const at of [0, 1, 30, 31, 62, 63, 75, ENVELOPE_BYTES - 1]) {
      const bad = h(v.envelope);
      bad[at] ^= 1;
      expect(() => open(bad)).toThrow();
    }
    expect(() => open(h(v.envelope).subarray(0, ENVELOPE_BYTES - 1))).toThrow();
    const v1 = h(v.envelope);
    v1[0] = 0x01;
    expect(() => envelopeSender(v1)).toThrow();
    const badSender = h(v.envelope);
    badSender.set(new TextEncoder().encode("usr_"), 1);
    expect(() => envelopeSender(badSender)).toThrow();
    expect(() => open(badSender)).toThrow();
  });

  it("refuses an identity bound to another user or KEK", () => {
    const id = vectors.identity[0];
    expect(() => unwrapIdentity(h(id.userKEK), h(id.wrapped), "usr_0123456789abcdefghjkmnpqrt")).toThrow();
    expect(() => unwrapIdentity(new Uint8Array(32), h(id.wrapped), id.userId)).toThrow();
  });

  it("rejects malformed IDs and generations before building AAD", () => {
    const s = v.senderDeviceId;
    expect(() => envelopeAAD("cnt_x", 1, v.recipientDeviceId, s)).toThrow();
    expect(() => envelopeAAD(v.containerId, 1, "usr_00000000000000000000000000", s)).toThrow();
    expect(() => envelopeAAD(v.containerId, 1, v.recipientDeviceId, "dev_short")).toThrow();
    expect(() => envelopeAAD(v.containerId, 0, v.recipientDeviceId, s)).toThrow();
    expect(() => envelopeAAD(v.containerId, 2 ** 32, v.recipientDeviceId, s)).toThrow();
  });

  it("generates distinct random identities and envelopes", () => {
    const a = generateIdentity();
    const b = generateIdentity();
    expect(bytesToHex(a.privateKey)).not.toBe(bytesToHex(b.privateKey));
    const ck = new Uint8Array(32).fill(7);
    const sender = { deviceId: v.senderDeviceId, privateKey: b.privateKey };
    const one = wrapEnvelope(ck, a.publicKey, v.containerId, 1, v.recipientDeviceId, sender);
    const two = wrapEnvelope(ck, a.publicKey, v.containerId, 1, v.recipientDeviceId, sender);
    expect(bytesToHex(one)).not.toBe(bytesToHex(two));
    expect(bytesToHex(unwrapEnvelope(one, a.privateKey, v.containerId, 1, v.recipientDeviceId, b.publicKey))).toBe(bytesToHex(ck));
  });
});

describe("vector-only exports", () => {
  it("are imported by tests only (caller-chosen nonces and ephemeral keys)", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./teamKeys.ts", "!./recovery.ts", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toContain("./main.tsx");
    expect(Object.entries(sources).filter(([, text]) => text.includes("ForVector")).map(([name]) => name)).toEqual([]);
  });
});
