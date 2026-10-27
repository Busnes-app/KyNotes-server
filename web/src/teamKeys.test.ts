import { afterEach, describe, expect, it, vi } from "vitest";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import vectors from "../../testdata/protocol/envelope_vectors.json";
import authVectors from "../../testdata/protocol/auth_vectors.json";
// RFC 9180 Appendix A.2.3 (https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.3): DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256, ChaCha20Poly1305, mode_auth; the same entry as the CFRG draft-irtf-cfrg-hpke test-vectors.json.
import rfc from "../../testdata/protocol/rfc9180_a2_3_auth.json";
import { deriveLoginKeys, LEGACY_LOGIN_ITERATIONS, NEEDS_HTTPS } from "./crypto";
import { ENVELOPE_ALG, ENVELOPE_BYTES, envelopeInfo, envelopeSender, envelopeSuite, generateIdentity, LEGACY_ENVELOPE_ALG, LEGACY_ENVELOPE_BYTES, unwrapEnvelope, unwrapIdentity, wrapEnvelope, wrapEnvelopeForVector, wrapIdentityForVector, WRAPPED_IDENTITY_BYTES } from "./teamKeys";

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

describe("RFC 9180 A.2.3 (the envelope v3 suite in mode_auth)", () => {
  const kem = envelopeSuite.kem;
  const hex = (b: ArrayBuffer) => bytesToHex(new Uint8Array(b));

  it("is that suite and mode", () => {
    expect([rfc.mode, rfc.kem_id, rfc.kdf_id, rfc.aead_id]).toEqual([2, 0x20, 0x01, 0x03]);
    expect([envelopeSuite.kem.id, envelopeSuite.kdf.id, envelopeSuite.aead.id]).toEqual([0x20, 0x01, 0x03]);
    expect(rfc.encryptions.map((e) => e.sequence)).toEqual([0, 1, 2, 4, 255, 256]);
  });

  it("derives the key pairs, enc, exports and every printed ciphertext", async () => {
    const pairs = await Promise.all([rfc.ikmE, rfc.ikmR, rfc.ikmS].map((ikm) => kem.deriveKeyPair(h(ikm))));
    const serialized = await Promise.all(pairs.flatMap((p) => [kem.serializePrivateKey(p.privateKey), kem.serializePublicKey(p.publicKey)]));
    expect(serialized.map(hex)).toEqual([rfc.skEm, rfc.pkEm, rfc.skRm, rfc.pkRm, rfc.skSm, rfc.pkSm]);
    const [, recipient, sender] = pairs;
    const sealer = await envelopeSuite.createSenderContext({ recipientPublicKey: recipient.publicKey, senderKey: sender, info: h(rfc.info), ekm: h(rfc.ikmE) });
    expect(hex(sealer.enc)).toBe(rfc.enc);
    const opener = await envelopeSuite.createRecipientContext({ recipientKey: recipient, enc: sealer.enc, senderPublicKey: sender.publicKey, info: h(rfc.info) });
    // The exporter secret pins the key schedule (shared_secret, secret).
    for (const e of rfc.exports) {
      expect(hex(await sealer.export(h(e.exporter_context), e.L))).toBe(e.exported_value);
      expect(hex(await opener.export(h(e.exporter_context), e.L))).toBe(e.exported_value);
    }
    const printed = new Map(rfc.encryptions.map((e) => [e.sequence, e]));
    for (let seq = 0; seq <= 256; seq++) {
      const e = printed.get(seq);
      const ct = await sealer.seal(e ? h(e.pt) : new Uint8Array(0), e ? h(e.aad) : undefined);
      if (e) expect(hex(ct), `seq ${seq}`).toBe(e.ct);
      await opener.open(ct, e ? h(e.aad) : undefined);
    }
  });

  it("single-shot seal (the envelope path) gives the same enc and first ciphertext", async () => {
    const [recipient, sender] = await Promise.all([kem.deriveKeyPair(h(rfc.ikmR)), kem.deriveKeyPair(h(rfc.ikmS))]);
    const first = rfc.encryptions[0];
    const { enc, ct } = await envelopeSuite.seal({ recipientPublicKey: recipient.publicKey, senderKey: sender, info: h(rfc.info), ekm: h(rfc.ikmE) }, h(first.pt), h(first.aad));
    expect([hex(enc), hex(ct)]).toEqual([rfc.enc, first.ct]);
    const pt = await envelopeSuite.open({ recipientKey: recipient, enc, senderPublicKey: sender.publicKey, info: h(rfc.info) }, ct, h(first.aad));
    expect(hex(pt)).toBe(first.pt);
  });
});

describe("Go cross-implementation vectors", () => {
  it("derives authSecret and userKEK from one PBKDF2 pass", async () => {
    for (const v of vectors.login) {
      const keys = await deriveLoginKeys(v.password, v.loginSalt, v.iterations, LEGACY_LOGIN_ITERATIONS);
      expect(keys.authSecret).toBe(v.authSecret);
      expect(bytesToHex(keys.userKEK)).toBe(v.userKEK);
    }
  });

  it("pins authSecret to auth_vectors.json", () => {
    expect(vectors.login[0].authSecret).toBe(authVectors[0].authSecret);
  });

  describe("without WebCrypto", () => {
    afterEach(() => vi.unstubAllGlobals());
    it("refuses to derive keys (plain HTTP) instead of falling back", async () => {
      vi.stubGlobal("crypto", {});
      const v = vectors.login[0];
      await expect(deriveLoginKeys(v.password, v.loginSalt, v.iterations, LEGACY_LOGIN_ITERATIONS)).rejects.toThrow(NEEDS_HTTPS);
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

  it("seals and opens v3 envelopes exactly like Go", async () => {
    expect(vectors.hpkeEnvelopes.length).toBe(2);
    for (const v of vectors.hpkeEnvelopes) {
      expect(bytesToHex(envelopeInfo(v.containerId, v.keyGeneration, v.recipientDeviceId, v.senderDeviceId))).toBe(v.info);
      const sender = { deviceId: v.senderDeviceId, privateKey: h(v.senderPrivateKey) };
      const sealed = await wrapEnvelopeForVector(h(v.contentKey), h(v.recipientPublicKey), v.containerId, v.keyGeneration, v.recipientDeviceId, sender, h(v.ephemeralSeed));
      expect(bytesToHex(sealed)).toBe(v.envelope);
      expect(sealed.length).toBe(ENVELOPE_BYTES);
      expect(envelopeSender(ENVELOPE_ALG, h(v.envelope))).toBe(v.senderDeviceId);
      expect(bytesToHex(await unwrapEnvelope(ENVELOPE_ALG, h(v.envelope), h(v.recipientPrivateKey), v.containerId, v.keyGeneration, v.recipientDeviceId, h(v.senderPublicKey)))).toBe(v.contentKey);
    }
  });

  it("opens stored v2 envelopes, only as v2", async () => {
    expect(vectors.envelopes.length).toBe(2);
    for (const v of vectors.envelopes) {
      expect(h(v.envelope).length).toBe(LEGACY_ENVELOPE_BYTES);
      expect(envelopeSender(LEGACY_ENVELOPE_ALG, h(v.envelope))).toBe(v.senderDeviceId);
      const open = (alg: string, sender = h(v.senderPublicKey), generation = v.keyGeneration) =>
        unwrapEnvelope(alg, h(v.envelope), h(v.recipientPrivateKey), v.containerId, generation, v.recipientDeviceId, sender);
      expect(bytesToHex(await open(LEGACY_ENVELOPE_ALG))).toBe(v.contentKey);
      await expect(open(ENVELOPE_ALG)).rejects.toThrow();
      await expect(open(LEGACY_ENVELOPE_ALG, h(v.recipientPublicKey))).rejects.toThrow();
      await expect(open(LEGACY_ENVELOPE_ALG, new Uint8Array(32))).rejects.toThrow();
      await expect(open(LEGACY_ENVELOPE_ALG, h(v.senderPublicKey), v.keyGeneration ^ 2)).rejects.toThrow();
    }
  });
});

describe("v3 binding and sender authentication", () => {
  const v = vectors.hpkeEnvelopes[0];
  const open = (envelope: Uint8Array, container = v.containerId, generation = v.keyGeneration, device = v.recipientDeviceId, sender: Uint8Array = h(v.senderPublicKey), alg = ENVELOPE_ALG) =>
    unwrapEnvelope(alg, envelope, h(v.recipientPrivateKey), container, generation, device, sender);

  it("refuses an envelope replayed into another container, generation or recipient", async () => {
    await expect(open(h(v.envelope), "cnt_00000000000000000000000001")).rejects.toThrow();
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration + 1)).rejects.toThrow();
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration, "dev_00000000000000000000000001")).rejects.toThrow();
  });

  it("authenticates the sender: another identity key, a relabelled sender or a zero key fail", async () => {
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, generateIdentity().publicKey)).rejects.toThrow();
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, new Uint8Array(32))).rejects.toThrow();
    const relabelled = h(v.envelope);
    relabelled.set(new TextEncoder().encode("dev_00000000000000000000000009"), 1);
    expect(envelopeSender(ENVELOPE_ALG, relabelled)).toBe("dev_00000000000000000000000009");
    await expect(open(relabelled)).rejects.toThrow();
  });

  it("refuses an envelope sealed by anyone but the claimed sender, even for the right recipient", async () => {
    // Someone holding only the recipient's public key (a server) cannot impersonate the sender.
    const forger = generateIdentity();
    const forged = await wrapEnvelope(h(v.contentKey), h(v.recipientPublicKey), v.containerId, v.keyGeneration, v.recipientDeviceId, { deviceId: v.senderDeviceId, privateKey: forger.privateKey });
    expect(envelopeSender(ENVELOPE_ALG, forged)).toBe(v.senderDeviceId);
    await expect(open(forged)).rejects.toThrow();
  });

  it("refuses a swapped alg or version byte, tampering, truncation and malformed senders", async () => {
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, h(v.senderPublicKey), LEGACY_ENVELOPE_ALG)).rejects.toThrow();
    await expect(open(h(v.envelope), v.containerId, v.keyGeneration, v.recipientDeviceId, h(v.senderPublicKey), "hpke-base-x25519-hkdfsha256-chacha20poly1305")).rejects.toThrow();
    for (const at of [0, 1, 30, 31, 62, 63, ENVELOPE_BYTES - 1]) {
      const bad = h(v.envelope);
      bad[at] ^= 1;
      await expect(open(bad), `byte ${at}`).rejects.toThrow();
    }
    await expect(open(h(v.envelope).subarray(0, ENVELOPE_BYTES - 1))).rejects.toThrow();
    for (const version of [0x01, 0x02]) {
      const other = h(v.envelope);
      other[0] = version;
      expect(() => envelopeSender(ENVELOPE_ALG, other)).toThrow();
    }
    const badSender = h(v.envelope);
    badSender.set(new TextEncoder().encode("usr_"), 1);
    expect(() => envelopeSender(ENVELOPE_ALG, badSender)).toThrow();
    await expect(open(badSender)).rejects.toThrow();
  });

  it("refuses an identity bound to another user or KEK", () => {
    const id = vectors.identity[0];
    expect(() => unwrapIdentity(h(id.userKEK), h(id.wrapped), "usr_0123456789abcdefghjkmnpqrt")).toThrow();
    expect(() => unwrapIdentity(new Uint8Array(32), h(id.wrapped), id.userId)).toThrow();
  });

  it("rejects malformed IDs and generations before building the context", () => {
    const s = v.senderDeviceId;
    expect(() => envelopeInfo("cnt_x", 1, v.recipientDeviceId, s)).toThrow();
    expect(() => envelopeInfo(v.containerId, 1, "usr_00000000000000000000000000", s)).toThrow();
    expect(() => envelopeInfo(v.containerId, 1, v.recipientDeviceId, "dev_short")).toThrow();
    expect(() => envelopeInfo(v.containerId, 0, v.recipientDeviceId, s)).toThrow();
    expect(() => envelopeInfo(v.containerId, 2 ** 32, v.recipientDeviceId, s)).toThrow();
  });

  it("generates distinct random identities and envelopes", async () => {
    const a = generateIdentity();
    const b = generateIdentity();
    expect(bytesToHex(a.privateKey)).not.toBe(bytesToHex(b.privateKey));
    const ck = new Uint8Array(32).fill(7);
    const sender = { deviceId: v.senderDeviceId, privateKey: b.privateKey };
    const one = await wrapEnvelope(ck, a.publicKey, v.containerId, 1, v.recipientDeviceId, sender);
    const two = await wrapEnvelope(ck, a.publicKey, v.containerId, 1, v.recipientDeviceId, sender);
    expect(one[0]).toBe(0x03);
    expect(bytesToHex(one)).not.toBe(bytesToHex(two));
    expect(bytesToHex(await unwrapEnvelope(ENVELOPE_ALG, one, a.privateKey, v.containerId, 1, v.recipientDeviceId, b.publicKey))).toBe(bytesToHex(ck));
  });
});

describe("vector-only exports", () => {
  it("are imported by tests only (caller-chosen nonces and ephemeral keys)", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./teamKeys.ts", "!./recovery.ts", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toContain("./main.tsx");
    expect(Object.entries(sources).filter(([, text]) => text.includes("ForVector")).map(([name]) => name)).toEqual([]);
  });
});
