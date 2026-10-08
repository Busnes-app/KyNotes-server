import { afterEach, describe, expect, it, vi } from "vitest";
import { base64, fromBase64 } from "./crypto";
import { APIRequestError, type LinkRequestRow, type LinkState } from "./api";
import type { HeldIdentity } from "./identity";
import { approveLink, claimLink, confirmTypedCode, endLink, finishNewcomerLink, LinkEndedError, linkRefusal, LinkStorageError, LinkTamperedError, pollNewcomerLink, revealedLink, startNewcomerLink, type NewcomerLink } from "./linkFlow";
import { confirmCheckCode, isLiveLinkKey, linkCommitment, newLinkKey, sealLinkBundle, type CheckCodeConfirmation } from "./linking";
import { generateIdentity, type Identity } from "./teamKeys";

const me = `usr_${"a".repeat(26)}`;
const other = `usr_${"z".repeat(26)}`;
const dev = `dev_${"b".repeat(26)}`;
const identity = { ...generateIdentity(), deviceId: dev };
const live = { deviceId: dev, publicKey: base64(identity.publicKey), fingerprint: "" };

/** An honest relay in memory, recording both sides' calls in order. */
function relay() {
  const calls: string[] = [];
  let row: LinkRequestRow | undefined;
  let state: LinkState = { state: "pending", expiresAt: "" };
  const newcomer = {
    create: async (commitment: string) => { calls.push("create"); row = { id: `lnk_${"c".repeat(26)}`, commitment, createdAt: "", expiresAt: "", claimed: false, newcomerKey: "" }; return { id: row.id, expiresAt: "" }; },
    collect: async (_key: Identity, _id: string) => { calls.push("collect"); return state; },
    reveal: vi.fn(async (_id: string, key: string) => { calls.push("reveal"); row = { ...row!, newcomerKey: key }; state = { ...state, state: "revealed" }; }),
    myIdentity: async () => live,
  };
  const approver = { claim: vi.fn(async (_id: string, key: string) => { calls.push("claim"); row = { ...row!, claimed: true }; state = { state: "claimed", approverKey: key, expiresAt: "" }; }) };
  const send = vi.fn(async (_c: CheckCodeConfirmation, _id: string, bundle: Uint8Array) => { calls.push("send"); state = { ...state, state: "approved", bundle: base64(bundle) }; });
  return { calls, newcomer, approver, send, row: () => row!, setRow: (next: LinkRequestRow) => { row = next; }, setApproverKey: (key: string) => { state = { ...state, approverKey: key }; } };
}
const stepUp = (calls: string[]) => async () => { calls.push("step-up"); };
/** This browser's vault: compare-and-swap like storeIdentityKey. */
function vault(initial?: HeldIdentity, keeps = true) {
  let held = initial;
  return {
    load: async () => held,
    save: vi.fn(async (next: HeldIdentity, expected?: HeldIdentity | null) => {
      if (!keeps || expected === undefined) return false;
      if ((expected === null) !== (held === undefined) || (expected && held && base64(expected.publicKey) !== base64(held.publicKey))) return false;
      held = next;
      return true;
    }),
    held: () => held,
    replace: (next?: HeldIdentity) => { held = next; },
  };
}
/** Both sides up to the moment the codes are shown. */
async function shown(r = relay()) {
  let link = await startNewcomerLink(r.newcomer, async () => true, me);
  let approver = await claimLink(r.approver, r.row(), me);
  ({ link } = await pollNewcomerLink(r.newcomer, link, me));
  approver = revealedLink(approver, r.row(), me);
  return { r, link, approver };
}
const confirmed = (link: NewcomerLink) => confirmCheckCode(link.id, link.code!);

describe("device linking", () => {
  it("shows one code on both sides; the key moves only after both users confirmed", async () => {
    const { r, link, approver } = await shown();
    const store = vault();
    expect(link.code).toMatch(/^\d{3} \d{3}$/);
    expect(approver.code).toBe(link.code);
    await approveLink(approver, confirmTypedCode(approver, link.code!), identity, me, stepUp(r.calls), r.send);
    const { bundle } = await pollNewcomerLink(r.newcomer, link, me);
    await expect(finishNewcomerLink(link, bundle!, undefined as never, me, r.newcomer, store)).rejects.toThrow();
    expect(store.save).not.toHaveBeenCalled();
    const held = await finishNewcomerLink(link, bundle!, confirmed(link), me, r.newcomer, store);
    expect(held).toEqual(identity);
    expect(store.held()).toEqual(identity);
    expect(r.calls).toEqual(["create", "claim", "collect", "reveal", "step-up", "send", "collect"]);
  });

  it("shows different codes when the relay swaps the approver's key", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true, me);
    let approver = await claimLink(r.approver, r.row(), me);
    r.setApproverKey(base64(newLinkKey().publicKey));
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    approver = revealedLink(approver, r.row(), me);
    expect(link.code).not.toBe(approver.code);
  });

  it("refuses an approver key that changes after the code was shown, and ends the attempt", async () => {
    const { r, link } = await shown();
    r.setApproverKey(base64(newLinkKey().publicKey));
    await expect(pollNewcomerLink(r.newcomer, link, me)).rejects.toBeInstanceOf(LinkTamperedError);
    expect(isLiveLinkKey(link.key)).toBe(false);
  });

  it("reveals the newcomer key only after the approver's key arrived", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true, me);
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    expect(r.calls).toEqual(["create", "collect"]);
    expect(link.code).toBeUndefined();
    await claimLink(r.approver, r.row(), me);
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    expect(r.calls).toEqual(["create", "collect", "claim", "collect", "reveal"]);
  });

  it("pins the approver key before revealing; a failed reveal ends the attempt, never revealed against another key", async () => {
    const r = relay();
    const link = await startNewcomerLink(r.newcomer, async () => true, me);
    await claimLink(r.approver, r.row(), me);
    const first = r.calls.length;
    // The relay records the newcomer key, answers 500, then serves a key it picked knowing it.
    r.newcomer.reveal.mockImplementationOnce(async () => { r.calls.push("reveal"); throw new Error("500"); });
    const pinned = await pollNewcomerLink(r.newcomer, link, me).catch((error: unknown) => error);
    expect(pinned).toBeInstanceOf(Error);
    expect(link.approverKey).toBeDefined();
    r.setApproverKey(base64(newLinkKey().publicKey));
    const code = link.code;
    await expect(pollNewcomerLink(r.newcomer, link, me)).rejects.toBeInstanceOf(LinkEndedError);
    // Even a caller holding a copy taken before the poll cannot start over with the same key.
    await expect(pollNewcomerLink(r.newcomer, { ...link, approverKey: undefined, code: undefined }, me)).rejects.toBeInstanceOf(LinkEndedError);
    expect(r.calls.slice(first)).toEqual(["collect", "reveal"]);
    expect(link.code).toBe(code);
    expect(isLiveLinkKey(link.key)).toBe(false);
    expect(link.key.privateKey.every((byte) => byte === 0)).toBe(true);
  });

  it("refuses a newcomer key that does not match the commitment seen before claiming", async () => {
    const r = relay();
    await startNewcomerLink(r.newcomer, async () => true, me);
    const approver = await claimLink(r.approver, r.row(), me);
    const forged = newLinkKey();
    // A relay that rewrote the commitment after the claim, to match its own key: still refused.
    r.setRow({ ...r.row(), commitment: base64(linkCommitment(forged.publicKey)), newcomerKey: base64(forged.publicKey) });
    expect(() => revealedLink(approver, r.row(), me)).toThrow(LinkTamperedError);
    expect(isLiveLinkKey(approver.key)).toBe(false);
  });

  it("fixes the account at start and at claim; another account aborts", async () => {
    const r = relay();
    const link = await startNewcomerLink(r.newcomer, async () => true, me);
    const approver = await claimLink(r.approver, r.row(), me);
    await expect(pollNewcomerLink(r.newcomer, link, other)).rejects.toThrow(/account changed/);
    expect(r.calls).toEqual(["create", "claim"]);
    expect(isLiveLinkKey(link.key)).toBe(false);
    expect(() => revealedLink(approver, r.row(), other)).toThrow(/account changed/);
    expect(isLiveLinkKey(approver.key)).toBe(false);
  });

  it("never retries with a fresh one-time key: a failed create or claim surfaces once", async () => {
    const r = relay();
    const create = vi.fn(async () => { throw new Error("offline"); });
    await expect(startNewcomerLink({ create }, async () => true, me)).rejects.toThrow("offline");
    expect(create).toHaveBeenCalledOnce();
    await startNewcomerLink(r.newcomer, async () => true, me);
    r.approver.claim.mockImplementationOnce(async () => { throw new Error("offline"); });
    await expect(claimLink(r.approver, r.row(), me)).rejects.toThrow("offline");
    expect(r.approver.claim).toHaveBeenCalledOnce();
  });

  it("creates no request when this browser cannot keep the key", async () => {
    const r = relay();
    await expect(startNewcomerLink(r.newcomer, async () => false, me)).rejects.toBeInstanceOf(LinkStorageError);
    expect(r.calls).toEqual([]);
  });

  it("refuses a bundle holding another key than the account's identity", async () => {
    const { r, link, approver } = await shown();
    const forged = sealLinkBundle(generateIdentity().privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    const store = vault();
    await expect(finishNewcomerLink(link, forged, confirmed(link), me, r.newcomer, store)).rejects.toThrow(/not your account's encryption key/);
    expect(store.save).not.toHaveBeenCalled();
    expect(isLiveLinkKey(link.key)).toBe(false);
  });

  it("keeps the identity with compare-and-swap: a key another tab kept meanwhile is never overwritten", async () => {
    const { r, link, approver } = await shown();
    const honest = sealLinkBundle(identity.privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    const pending = { ...generateIdentity(), deviceId: "" };
    const store = vault(pending);
    // Another tab replaces the vault copy between this run's read and its write.
    const load = store.load;
    store.load = async () => { const seen = await load(); store.replace({ ...generateIdentity(), deviceId: "" }); return seen; };
    await expect(finishNewcomerLink(link, honest, confirmed(link), me, r.newcomer, store)).rejects.toBeInstanceOf(LinkStorageError);
    expect(store.save).toHaveBeenCalledWith(expect.objectContaining({ deviceId: dev }), pending);
    expect(store.held()?.deviceId).toBe("");
  });

  it("reports a browser that could not keep the linked key", async () => {
    const { r, link, approver } = await shown();
    const honest = sealLinkBundle(identity.privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    await expect(finishNewcomerLink(link, honest, confirmed(link), me, r.newcomer, vault(undefined, false))).rejects.toBeInstanceOf(LinkStorageError);
  });

  it("opens the bundle only with a confirmation of the code this browser showed", async () => {
    const { r, link, approver } = await shown();
    const honest = sealLinkBundle(identity.privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    const store = vault();
    await expect(finishNewcomerLink(link, honest, confirmCheckCode(link.id, "000 000"), me, r.newcomer, store)).rejects.toThrow(/check codes/);
    expect(store.save).not.toHaveBeenCalled();
    expect(isLiveLinkKey(link.key)).toBe(true);
  });

  it("sends nothing, and asks for no step-up, without a confirmation for this request", async () => {
    const { r, link, approver } = await shown();
    await expect(approveLink(approver, confirmCheckCode(`lnk_${"z".repeat(26)}`, link.code!), identity, me, stepUp(r.calls), r.send)).rejects.toThrow();
    expect(r.calls).not.toContain("step-up");
    expect(r.send).not.toHaveBeenCalled();
    expect(fromBase64(r.row().newcomerKey)).toEqual(link.key.publicKey);
  });

  it("approves only after the user typed the newcomer's code; a click-style confirmation is not enough", async () => {
    const { r, link, approver } = await shown();
    const wrong = link.code === "000 000" ? "000 001" : "000 000";
    expect(() => confirmTypedCode(approver, wrong)).toThrow(/not the code/);
    expect(() => confirmTypedCode(approver, "")).toThrow(/not the code/);
    await expect(approveLink(approver, confirmCheckCode(approver.id, approver.code!), identity, me, stepUp(r.calls), r.send)).rejects.toThrow(/Type the code/);
    expect(r.send).not.toHaveBeenCalled();
    await approveLink(approver, confirmTypedCode(approver, link.code!.replace(" ", "")), identity, me, stepUp(r.calls), r.send);
    expect(r.send).toHaveBeenCalledOnce();
    // The approver's one-time key is gone once the bundle left.
    expect(isLiveLinkKey(approver.key)).toBe(false);
  });

  it("keeps one-time keys in memory only, discarded when the attempt ends", async () => {
    const { link, approver } = await shown();
    expect(isLiveLinkKey(link.key)).toBe(true);
    endLink(link);
    endLink(approver);
    for (const key of [link.key, approver.key]) {
      expect(isLiveLinkKey(key)).toBe(false);
      expect(key.privateKey.every((byte) => byte === 0)).toBe(true);
    }
  });
});

describe("link refusals", () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  const refused = (code: string, challenge?: string) => new APIRequestError("refused", { error: { code, message: "server text", challenge } }, 409);

  it("offers to cancel an open KySignOn confirmation by its challenge ID", async () => {
    const challenge = `rea_${"d".repeat(26)}`;
    const calls: Array<[string, RequestInit | undefined]> = [];
    vi.stubGlobal("document", { cookie: "csrf_token=t" });
    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => { calls.push([path, init]); return new Response(null, { status: 204 }); }));
    const shown = linkRefusal(refused("step_up_pending", challenge));
    expect(shown.message).toMatch(/KySignOn confirmation is still open/);
    await shown.cancel!();
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe(`/api/v1/auth/oidc/step-up/${challenge}`);
    expect(calls[0][1]?.method).toBe("DELETE");
    expect(new Headers(calls[0][1]?.headers).get("X-CSRF-Token")).toBe("t");
    expect(linkRefusal(refused("step_up_pending")).cancel).toBeUndefined();
  });

  it("names the way out of a session that cannot link", () => {
    expect(linkRefusal(refused("sso_sign_in_required")).message).toMatch(/^Sign in with KySignOn/);
    expect(linkRefusal(refused("password_change_required")).message).toMatch(/administrator set.*change your password/i);
    expect(linkRefusal(refused("password_change_required")).cancel).toBeUndefined();
    expect(linkRefusal(new Error("offline")).message).toBe("offline");
  });
});
