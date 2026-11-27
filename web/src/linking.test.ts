import { describe, expect, it } from "vitest";
import { generatePQIdentityReady } from "./pqIdentity";
import { checkCode, confirmCheckCode, confirmTypedCheckCode, isCheckCodeConfirmation, LINK_BUNDLE_BYTES, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, type LinkContext } from "./linking";
import { sameBytes } from "./teamKeys";
import pqVectors from "../../testdata/protocol/pq_vectors.json";
import { hexToBytes } from "@noble/ciphers/utils.js";
import vectors from "../../testdata/protocol/link_vectors.json";
const userID = `usr_${"a".repeat(26)}`, requestID = `lnk_${"b".repeat(26)}`, identityDeviceID = `dev_${"c".repeat(26)}`;
describe("X-Wing linking", () => {
  it("round trips both PQ and legacy identities, and authenticates sender, full context and framing", async () => {
    const approver = newLinkKey(), newcomer = newLinkKey();
    const context: LinkContext = { userID, requestID, identityDeviceID, approverKey: approver.publicKey, newcomerKey: newcomer.publicKey };
    for (const privateKey of [generatePQIdentityReady().privateKey,new Uint8Array(32).fill(7)]) {
      const bundle = await sealLinkBundle(privateKey,approver,context);
      expect(bundle.length).toBe(privateKey.length+1+1137+3389);
      expect(await openLinkBundle(bundle,newcomer,context)).toEqual(privateKey);
      for (const changed of [{...context,userID:`usr_${"z".repeat(26)}`},{...context,requestID:`lnk_${"z".repeat(26)}`},{...context,identityDeviceID:`dev_${"z".repeat(26)}`},{...context,approverKey:newLinkKey().publicKey}]) await expect(openLinkBundle(bundle,newcomer,changed)).rejects.toThrow();
      for (const at of [0,1,100,1138,bundle.length-65,bundle.length-1]) {const changed=bundle.slice();changed[at]^=1;await expect(openLinkBundle(changed,newcomer,context)).rejects.toThrow();}
      await expect(openLinkBundle(bundle.subarray(0,bundle.length-1),newcomer,context)).rejects.toThrow("format");
      await expect(openLinkBundle(bundle,newLinkKey(),context)).rejects.toThrow("newcomer-key");
      const forged = await sealLinkBundle(privateKey,newLinkKey(),{...context,approverKey: newLinkKey().publicKey}).catch(()=>undefined);
      expect(forged).toBeUndefined();
    }
    expect(LINK_BUNDLE_BYTES).toBe(1+1137+generatePQIdentityReady().privateKey.length+3389);
  });
  it("covers every byte of both X-Wing public keys in the six-digit SAS and commitment", () => {
    // Fixed keys make this reproducible. Six decimal digits inevitably permit collisions;
    // this proves every one-byte flip in these full 1216-byte fixtures affects the SAS.
    const a = hexToBytes(pqVectors.SenderPublic), b = hexToBytes(pqVectors.RecipientPublic);
    const code = checkCode(userID,requestID,a,b), commitment=linkCommitment(b);
    expect(code).toMatch(/^\d{3} \d{3}$/);
    for (let i=33;i<33+1216;i++) {
      const changedA=a.slice(),changedB=b.slice();changedA[i]^=1;changedB[i]^=1;
      expect(checkCode(userID,requestID,changedA,b),`approver byte ${i-33}`).not.toBe(code);
      expect(checkCode(userID,requestID,a,changedB),`newcomer byte ${i-33}`).not.toBe(code);
      expect(linkCommitment(changedB)).not.toEqual(commitment);
    }
    expect(()=>linkCommitment(new Uint8Array(32))).toThrow();
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
