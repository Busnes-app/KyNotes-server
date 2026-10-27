import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import vectors from "../../testdata/protocol/link_vectors.json";
import { checkCode, confirmCheckCode, confirmTypedCheckCode, isCheckCodeConfirmation, LINK_BUNDLE_BYTES, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, sealLinkBundleForVector, type LinkContext } from "./linking";
import { sameBytes } from "./teamKeys";

const keysOf = (v: (typeof vectors.links)[number]) => ({
  approver: { privateKey: h(v.approverPrivateKey), publicKey: h(v.approverPublicKey) },
  newcomer: { privateKey: h(v.newcomerPrivateKey), publicKey: h(v.newcomerPublicKey) },
});
const contextOf = (v: (typeof vectors.links)[number]): LinkContext => ({ userID: v.userId, requestID: v.requestId, identityDeviceID: v.identityDeviceId, approverKey: h(v.approverPublicKey), newcomerKey: h(v.newcomerPublicKey) });

describe("device link protocol", () => {
  it("matches the Go vectors: commitment, check code and an HPKE bundle Go opens, and opens Go's", async () => {
    for (const v of vectors.links) {
      const { approver, newcomer } = keysOf(v);
      expect(bytesToHex(linkCommitment(newcomer.publicKey))).toBe(v.commitment);
      expect(checkCode(v.userId, v.requestId, approver.publicKey, newcomer.publicKey)).toBe(v.checkCode);
      // Byte-identical to circl's seal for the same ikmE, so Go's openLink opens what this seals.
      const bundle = await sealLinkBundleForVector(h(v.identityPrivateKey), approver, contextOf(v), h(v.ephemeralSeed));
      expect(bundle.length).toBe(LINK_BUNDLE_BYTES);
      expect(bytesToHex(bundle)).toBe(v.bundle);
      expect(bytesToHex(await openLinkBundle(h(v.bundle), newcomer, contextOf(v)))).toBe(v.identityPrivateKey);
    }
  });

  it("round-trips with a fresh ephemeral key", async () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const bundle = await sealLinkBundle(h(v.identityPrivateKey), approver, contextOf(v));
    expect(bundle.length).toBe(LINK_BUNDLE_BYTES);
    expect(bytesToHex(bundle)).not.toBe(v.bundle);
    expect(bytesToHex(await openLinkBundle(bundle, newcomer, contextOf(v)))).toBe(v.identityPrivateKey);
  });

  it("refuses every Go reject vector for the reason it names", async () => {
    const lowOrder = ["zero", "one", "order8-a", "order8-b", "p-minus-1", "p", "p-plus-1"].map((n) => `low-order-approver-key-${n}`);
    expect(vectors.rejects.map((r) => r.case)).toEqual([
      "tampered-ciphertext", "tampered-tag", "tampered-enc", "wrong-version", "v1-version-v2-length", "v1-bundle", "v2-version-v1-length", "truncated",
      "swapped-keys", "wrong-newcomer-key", "wrong-newcomer-private-key", "bundle-for-another-newcomer", "keys-reversed-in-binding", "label-only-info",
      "unauthenticated-sender", "wrong-sender", "wrong-approver-key", ...lowOrder, "wrong-request", "wrong-user", "wrong-identity-device", "commitment-mismatch",
    ]);
    for (const r of vectors.rejects) {
      const newcomer = { privateKey: h(r.newcomerPrivateKey), publicKey: x25519.getPublicKey(h(r.newcomerPrivateKey)) };
      const context: LinkContext = { userID: r.userId, requestID: r.requestId, identityDeviceID: r.identityDeviceId, approverKey: h(r.approverPublicKey), newcomerKey: h(r.newcomerPublicKey) };
      if (r.reason === "commitment") {
        expect(sameBytes(linkCommitment(context.newcomerKey), h(r.commitment)), r.case).toBe(false);
        // The relay's key opens its own bundle: the commitment is the only defence here.
        await expect(openLinkBundle(h(r.bundle), newcomer, context), r.case).resolves.toBeInstanceOf(Uint8Array);
      } else {
        await expect(openLinkBundle(h(r.bundle), newcomer, context), r.case).rejects.toThrow(`link bundle refused: ${r.reason}`);
      }
    }
  });

  it("opens nothing bound to another user, request, identity, approver or newcomer key, or a changed byte", async () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const context = contextOf(v);
    // Sealed here, so this holds for whatever linking.ts binds, not only for Go's bytes.
    const bundle = await sealLinkBundle(h(v.identityPrivateKey), approver, context);
    await expect(openLinkBundle(bundle, newcomer, context)).resolves.toBeInstanceOf(Uint8Array);
    const stranger = newLinkKey();
    for (const [name, changed, key] of [
      ["user", { ...context, userID: `usr_${"z".repeat(26)}` }, newcomer],
      ["request", { ...context, requestID: `lnk_${"z".repeat(26)}` }, newcomer],
      ["identity device", { ...context, identityDeviceID: `dev_${"z".repeat(26)}` }, newcomer],
      ["approver key", { ...context, approverKey: newLinkKey().publicKey }, newcomer],
      ["newcomer key", { ...context, newcomerKey: stranger.publicKey }, newcomer],
      ["newcomer private key", { ...context, newcomerKey: stranger.publicKey }, stranger],
    ] as const) await expect(openLinkBundle(bundle, key, changed), name).rejects.toThrow();
    for (const at of [0, 1, 40, 80]) {
      const flipped = bundle.slice();
      flipped[at] ^= 1;
      await expect(openLinkBundle(flipped, newcomer, context), `byte ${at}`).rejects.toThrow();
    }
    await expect(openLinkBundle(bundle.subarray(0, LINK_BUNDLE_BYTES - 1), newcomer, context)).rejects.toThrow("format");
    await expect(openLinkBundle(h(vectors.rejects.find((r) => r.case === "v1-bundle")!.bundle), newcomer, context)).rejects.toThrow("format");
  });

  it("refuses low-order and malformed one-time keys on both sides", async () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const context = contextOf(v);
    // u = 0, 1, both order-8 points, p-1, p and p+1: every agreement with them is all zeros.
    const lowOrder = vectors.rejects.filter((r) => r.reason === "low-order").map((r) => h(r.approverPublicKey));
    expect(lowOrder).toHaveLength(7);
    for (const bad of lowOrder) {
      await expect(sealLinkBundle(h(v.identityPrivateKey), approver, { ...context, newcomerKey: bad })).rejects.toThrow();
      await expect(openLinkBundle(h(v.bundle), newcomer, { ...context, approverKey: bad })).rejects.toThrow("link bundle refused: low-order");
    }
    await expect(sealLinkBundle(h(v.identityPrivateKey), newcomer, context), "approver key must be the context's").rejects.toThrow();
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
    const confirmed = confirmCheckCode(id, "123 456");
    expect(isCheckCodeConfirmation(confirmed, id)).toBe(true);
    expect(isCheckCodeConfirmation(confirmed, vectors.links[1].requestId)).toBe(false);
    expect(isCheckCodeConfirmation({ requestID: id }, id)).toBe(false);
    expect(isCheckCodeConfirmation(Object.create(Object.getPrototypeOf(confirmed)), id)).toBe(false);
  });

  it("freezes confirmations so they cannot be re-targeted at another request or code", () => {
    const id = vectors.links[0].requestId;
    const other = vectors.links[1].requestId;
    for (const confirmed of [confirmCheckCode(id, "123 456"), confirmTypedCheckCode(id, "123 456", "123456")]) {
      expect(Object.isFrozen(confirmed)).toBe(true);
      const writable = confirmed as unknown as { requestID: string; code: string };
      expect(() => { writable.requestID = other; }).toThrow(TypeError);
      expect(() => { writable.code = "000 000"; }).toThrow(TypeError);
      expect(isCheckCodeConfirmation(confirmed, other)).toBe(false);
      expect(confirmed.code).toBe("123 456");
    }
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
