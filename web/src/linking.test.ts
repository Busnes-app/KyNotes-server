import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import vectors from "../../testdata/protocol/link_vectors.json";
import { checkCode, confirmCheckCode, isCheckCodeConfirmation, LINK_BUNDLE_BYTES, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, type LinkContext } from "./linking";
import { sameBytes } from "./teamKeys";

const keysOf = (v: (typeof vectors.links)[number]) => ({
  approver: { privateKey: h(v.approverPrivateKey), publicKey: h(v.approverPublicKey) },
  newcomer: { privateKey: h(v.newcomerPrivateKey), publicKey: h(v.newcomerPublicKey) },
});
const contextOf = (v: (typeof vectors.links)[number]): LinkContext => ({ userID: v.userId, requestID: v.requestId, identityDeviceID: v.identityDeviceId, approverKey: h(v.approverPublicKey), newcomerKey: h(v.newcomerPublicKey) });

describe("device link protocol", () => {
  it("matches the Go vectors: commitment, check code and bundle", () => {
    for (const v of vectors.links) {
      const { approver, newcomer } = keysOf(v);
      expect(bytesToHex(linkCommitment(newcomer.publicKey))).toBe(v.commitment);
      expect(checkCode(v.userId, v.requestId, approver.publicKey, newcomer.publicKey)).toBe(v.checkCode);
      const bundle = sealLinkBundle(h(v.identityPrivateKey), approver, contextOf(v), h(v.nonce));
      expect(bundle.length).toBe(LINK_BUNDLE_BYTES);
      expect(bytesToHex(bundle)).toBe(v.bundle);
      expect(bytesToHex(openLinkBundle(bundle, newcomer, contextOf(v)))).toBe(v.identityPrivateKey);
    }
  });

  it("refuses every Go reject vector for the reason it names", () => {
    const lowOrder = ["zero", "one", "order8-a", "order8-b", "p-minus-1", "p", "p-plus-1"].map((n) => `low-order-approver-key-${n}`);
    expect(vectors.rejects.map((r) => r.case)).toEqual([
      "tampered-ciphertext", "tampered-tag", "tampered-nonce", "wrong-version", "truncated", "swapped-keys", "keys-reversed-in-binding",
      "wrong-approver-key", ...lowOrder, "wrong-request", "wrong-user", "wrong-identity-device", "commitment-mismatch",
    ]);
    for (const r of vectors.rejects) {
      const newcomer = { privateKey: h(r.newcomerPrivateKey), publicKey: x25519.getPublicKey(h(r.newcomerPrivateKey)) };
      const context: LinkContext = { userID: r.userId, requestID: r.requestId, identityDeviceID: r.identityDeviceId, approverKey: h(r.approverPublicKey), newcomerKey: h(r.newcomerPublicKey) };
      const committed = sameBytes(linkCommitment(context.newcomerKey), h(r.commitment));
      if (r.reason === "commitment") {
        expect(committed, r.case).toBe(false);
        // The relay's key opens its own bundle: the commitment is the only defence here.
        expect(() => openLinkBundle(h(r.bundle), newcomer, context), r.case).not.toThrow();
      } else {
        expect(committed, r.case).toBe(r.case === "swapped-keys" ? false : true);
        expect(() => openLinkBundle(h(r.bundle), newcomer, context), r.case).toThrow(`link bundle refused: ${r.reason}`);
      }
    }
  });

  it("opens nothing bound to another user, request, identity or approver key, or a flipped byte", () => {
    const v = vectors.links[0];
    const { newcomer } = keysOf(v);
    const bundle = h(v.bundle);
    const context = contextOf(v);
    for (const changed of [
      { ...context, userID: `usr_${"z".repeat(26)}` },
      { ...context, requestID: `lnk_${"z".repeat(26)}` },
      { ...context, identityDeviceID: `dev_${"z".repeat(26)}` },
      { ...context, approverKey: newLinkKey().publicKey },
    ]) expect(() => openLinkBundle(bundle, newcomer, changed)).toThrow();
    const flipped = bundle.slice();
    flipped[20] ^= 1;
    expect(() => openLinkBundle(flipped, newcomer, context)).toThrow();
    expect(() => openLinkBundle(bundle.subarray(0, 60), newcomer, context)).toThrow();
  });

  it("refuses low-order and malformed one-time keys on both sides", () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const context = contextOf(v);
    // u = 0, 1, both order-8 points, p-1, p and p+1: every agreement with them is all zeros.
    const lowOrder = vectors.rejects.filter((r) => r.reason === "low-order").map((r) => h(r.approverPublicKey));
    expect(lowOrder).toHaveLength(7);
    for (const bad of lowOrder) {
      expect(() => sealLinkBundle(h(v.identityPrivateKey), approver, { ...context, newcomerKey: bad }, h(v.nonce))).toThrow();
      expect(() => openLinkBundle(h(v.bundle), newcomer, { ...context, approverKey: bad })).toThrow("link bundle refused: low-order");
    }
    expect(() => linkCommitment(new Uint8Array(31))).toThrow();
    expect(() => checkCode(v.userId, v.requestId, new Uint8Array(33), newcomer.publicKey)).toThrow();
    expect(() => checkCode(v.userId, "dev_00000000000000000000000000", approver.publicKey, newcomer.publicKey)).toThrow();
  });

  it("changes the check code when either one-time key changes", () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const code = checkCode(v.userId, v.requestId, approver.publicKey, newcomer.publicKey);
    expect(code).toMatch(/^\d{3} \d{3}$/);
    expect(checkCode(v.userId, v.requestId, newLinkKey().publicKey, newcomer.publicKey)).not.toBe(code);
    expect(checkCode(v.userId, v.requestId, approver.publicKey, newLinkKey().publicKey)).not.toBe(code);
    expect(checkCode(v.userId, v.requestId, newcomer.publicKey, approver.publicKey)).not.toBe(code);
    expect(checkCode(vectors.links[1].userId, v.requestId, approver.publicKey, newcomer.publicKey)).not.toBe(code);
    expect(checkCode(v.userId, vectors.links[1].requestId, approver.publicKey, newcomer.publicKey)).not.toBe(code);
  });

  it("zero-pads the check code exactly as Go does", () => {
    const padded = vectors.links.filter((v) => v.checkCode.startsWith("0"));
    expect(padded.length).toBeGreaterThan(0);
    for (const v of padded) expect(checkCode(v.userId, v.requestId, h(v.approverPublicKey), h(v.newcomerPublicKey))).toBe(v.checkCode);
  });

  it("accepts only a confirmCheckCode result, for its own request", () => {
    const id = vectors.links[0].requestId;
    const confirmed = confirmCheckCode(id);
    expect(isCheckCodeConfirmation(confirmed, id)).toBe(true);
    expect(isCheckCodeConfirmation(confirmed, vectors.links[1].requestId)).toBe(false);
    expect(isCheckCodeConfirmation({ requestID: id }, id)).toBe(false);
    expect(isCheckCodeConfirmation(Object.create(Object.getPrototypeOf(confirmed)), id)).toBe(false);
  });
});

describe("sameBytes", () => {
  it("compares length and every byte", () => {
    expect(sameBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
    expect(sameBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
    expect(sameBytes(Uint8Array.of(0, 2, 3), Uint8Array.of(1, 2, 3))).toBe(false);
    expect(sameBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
  });
});
