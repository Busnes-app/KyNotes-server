import { x25519 } from "@noble/curves/ed25519.js";
import { base64, fromBase64 } from "./crypto";
import { APIRequestError, cancelSSOStepUp, type LinkRequestRow, type LinkState } from "./api";
import type { HeldIdentity, IdentityStore, PublicIdentity } from "./identity";
import { checkCode, confirmTypedCheckCode, discardLinkKey, isCheckCodeConfirmation, isLiveLinkKey, isTypedCheckCodeConfirmation, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, type CheckCodeConfirmation } from "./linking";
import { sendLinkBundle } from "./outbound";
import { publicKeyBytes } from "./pins";
import { sameBytes, type Identity } from "./teamKeys";

export class LinkStorageError extends Error {
  constructor() { super("This browser cannot keep an encryption key (site storage is blocked or unavailable), so it cannot be linked."); this.name = "LinkStorageError"; }
}
export class LinkTamperedError extends Error {
  constructor() { super("The other browser's key changed while linking. Nothing was linked; start again on both browsers."); this.name = "LinkTamperedError"; }
}
export class LinkEndedError extends Error {
  constructor() { super("This link attempt ended. Nothing was linked; start again on both browsers."); this.name = "LinkEndedError"; }
}

/**
 * Every attempt fixes its account and request ID when it starts (newcomer) or claims (approver),
 * and owns one one-time key. Nothing here retries with a fresh key: a new attempt is a new user action.
 */
type Attempt = { readonly id: string; readonly userID: string; readonly key: Identity };

/** Discards the attempt's one-time private key. Call on cancel, "codes differ" and any error the UI shows. */
export const endLink = (link: Attempt): void => discardLinkKey(link.key);

/** Throws unless the attempt is still live and for the account it started with; another account ends it. */
function live(link: Attempt, userID: string): void {
  if (!isLiveLinkKey(link.key)) throw new LinkEndedError();
  if (userID !== link.userID) {
    endLink(link);
    throw new Error("The signed-in account changed while linking. Nothing was linked; start again on both browsers.");
  }
}

/** Runs step and ends the attempt when it throws. */
async function orEnd<T>(link: Attempt, step: () => Promise<T>): Promise<T> {
  try { return await step(); } catch (error) { endLink(link); throw error; }
}

export type NewcomerAPI = {
  create: (commitment: string) => Promise<{ id: string; expiresAt: string }>;
  /** outbound.ts collectLinkBundle: refuses once the one-time key is discarded. */
  collect: (key: Identity, id: string) => Promise<LinkState>;
  reveal: (id: string, newcomerKey: string) => Promise<void>;
  myIdentity: () => Promise<PublicIdentity | undefined>;
};
/**
 * One attempt on the browser being linked. Its one-time key lives only here, in memory.
 * approverKey and code are a view of the pin pollNewcomerLink keeps for the one-time key.
 */
export type NewcomerLink = Attempt & { readonly expiresAt: string; readonly approverKey?: Uint8Array; readonly code?: string };
type Pin = { approverKey: Uint8Array; code: string };
/**
 * The approver key each one-time key was revealed against, keyed by its private key bytes: every
 * copy of a NewcomerLink shares one pin and one reveal for the key's lifetime.
 */
const pins = new WeakMap<Uint8Array, Pin>();

export const OTHER_COPY = "This browser holds another copy of your key. Use Forget this device first.";
/**
 * True when this browser holds a key other than the one the server lists for the account (or the
 * account lists none). Checked before starting, so the user is not sent through the ceremony only
 * for finishNewcomerLink to refuse after collect deleted the bundle.
 */
export async function otherCopyHeld(api: Pick<NewcomerAPI, "myIdentity">, store: Pick<IdentityStore, "load">): Promise<boolean> {
  const local = await store.load();
  if (!local) return false;
  const listed = await api.myIdentity();
  return !listed || !sameBytes(local.publicKey, publicKeyBytes(listed.publicKey));
}

/** Starts a link; refuses before any request when this browser could not keep the identity. */
export async function startNewcomerLink(api: Pick<NewcomerAPI, "create">, canKeep: () => Promise<boolean>, userID: string): Promise<NewcomerLink> {
  if (!(await canKeep())) throw new LinkStorageError();
  const key = newLinkKey();
  const { id, expiresAt } = await orEnd({ id: "", userID, key }, () => api.create(base64(linkCommitment(key.publicKey))));
  return { id, userID, key, expiresAt };
}

/**
 * One poll. When the approver's key first arrives, it and the check code are pinned to the one-time
 * key, then this browser reveals its own key (committed to at start). A failed reveal ends the
 * attempt; once pinned, the key is never revealed again, and a different approver key is refused.
 * bundle: once the approver sent it. It is opened only by finishNewcomerLink.
 */
export async function pollNewcomerLink(api: Pick<NewcomerAPI, "collect" | "reveal">, link: NewcomerLink, userID: string): Promise<{ link: NewcomerLink; bundle?: Uint8Array }> {
  live(link, userID);
  const state = await api.collect(link.key, link.id);
  const pinned = pins.get(link.key.privateKey);
  if (pinned) {
    if (state.approverKey && !sameBytes(publicKeyBytes(state.approverKey), pinned.approverKey)) {
      endLink(link);
      throw new LinkTamperedError();
    }
    return { link: { ...link, ...pinned }, bundle: state.bundle ? fromBase64(state.bundle) : undefined };
  }
  if (!state.approverKey) return { link };
  const pin = await orEnd(link, async () => {
    const approverKey = publicKeyBytes(state.approverKey!);
    const next = { approverKey, code: checkCode(link.userID, link.id, approverKey, link.key.publicKey) };
    pins.set(link.key.privateKey, next);
    await api.reveal(link.id, base64(link.key.publicKey));
    return next;
  });
  return { link: { ...link, ...pin } };
}

/**
 * Opens the bundle only after this browser's own user confirmed the code it shows, only when it
 * carries the identity the server lists for the account. It never replaces another copy this
 * browser holds (pending, orphaned or older), and keeps the key with a compare-and-swap against
 * the copy read here. Past the confirmation check, the attempt ends whatever happens (the server
 * deleted the bundle at collect).
 */
export async function finishNewcomerLink(link: NewcomerLink, bundle: Uint8Array, confirmation: CheckCodeConfirmation, userID: string, api: Pick<NewcomerAPI, "myIdentity">, store: IdentityStore): Promise<HeldIdentity> {
  live(link, userID);
  const pin = pins.get(link.key.privateKey);
  if (!pin || !isCheckCodeConfirmation(confirmation, link.id) || confirmation.code !== pin.code) throw new Error("Compare the check codes on both screens first.");
  try {
    const listed = await api.myIdentity();
    if (!listed) throw new Error("Your account has no encryption key to link.");
    const privateKey = openLinkBundle(bundle, link.key, { userID: link.userID, requestID: link.id, identityDeviceID: listed.deviceId, approverKey: pin.approverKey, newcomerKey: link.key.publicKey });
    const publicKey = x25519.getPublicKey(privateKey);
    if (!sameBytes(publicKey, publicKeyBytes(listed.publicKey))) throw new Error("The key sent is not your account's encryption key. Nothing was linked.");
    const identity = { deviceId: listed.deviceId, publicKey, privateKey };
    const current = await store.load();
    if (current && !sameBytes(current.publicKey, publicKey)) throw new Error(OTHER_COPY);
    if (current?.deviceId === identity.deviceId) return current;
    if (!(await store.save(identity, current ?? null))) throw new LinkStorageError();
    return identity;
  } finally {
    endLink(link);
  }
}

/** One attempt on the trusted browser. commitment is the one listed before this browser's key was sent. */
export type ApproverLink = Attempt & { readonly commitment: Uint8Array; readonly newcomerKey?: Uint8Array; readonly code?: string };

export async function claimLink(api: { claim: (id: string, approverKey: string) => Promise<void> }, row: LinkRequestRow, userID: string): Promise<ApproverLink> {
  const commitment = fromBase64(row.commitment);
  if (commitment.length !== 32) throw new LinkTamperedError();
  const link = { id: row.id, userID, key: newLinkKey(), commitment };
  await orEnd(link, () => api.claim(row.id, base64(link.key.publicKey)));
  return link;
}

/** Takes the newcomer's revealed key, only if it matches the commitment seen before claiming. */
export function revealedLink(link: ApproverLink, row: LinkRequestRow | undefined, userID: string): ApproverLink {
  live(link, userID);
  if (link.newcomerKey || row?.id !== link.id || !row.newcomerKey) return link;
  let newcomerKey: Uint8Array;
  try { newcomerKey = publicKeyBytes(row.newcomerKey); } catch { newcomerKey = new Uint8Array(); }
  if (newcomerKey.length !== 32 || !sameBytes(linkCommitment(newcomerKey), link.commitment)) {
    endLink(link);
    throw new LinkTamperedError();
  }
  return { ...link, newcomerKey, code: checkCode(link.userID, link.id, link.key.publicKey, newcomerKey) };
}

/** The approver's only confirmation: the code typed from the other browser (see confirmTypedCheckCode). */
export const confirmTypedCode = (link: ApproverLink, entered: string): CheckCodeConfirmation => confirmTypedCheckCode(link.id, link.code ?? "", entered);

/** Seals the identity to the newcomer and sends it, after the user typed the matching code and a fresh step-up. */
export async function approveLink(link: ApproverLink, confirmation: CheckCodeConfirmation, identity: HeldIdentity, userID: string, stepUp: () => Promise<void>, send: typeof sendLinkBundle = sendLinkBundle): Promise<void> {
  live(link, userID);
  if (!link.newcomerKey || !link.code) throw new Error("The other browser has not answered yet.");
  if (!isTypedCheckCodeConfirmation(confirmation, link.id) || confirmation.code !== link.code) throw new Error("Type the code the other browser shows first.");
  const bundle = sealLinkBundle(identity.privateKey, link.key, { userID: link.userID, requestID: link.id, identityDeviceID: identity.deviceId, approverKey: link.key.publicKey, newcomerKey: link.newcomerKey });
  // A failed step-up or send keeps the attempt: approving again re-seals to the same keys.
  await stepUp();
  await send(confirmation, link.id, bundle);
  endLink(link);
}

/** What the UI shows for a refused link step; cancel, when set, closes the open KySignOn confirmation. */
export function linkRefusal(error: unknown): { message: string; cancel?: () => Promise<void> } {
  const code = error instanceof APIRequestError ? error.code : undefined;
  if (code === "step_up_pending") {
    const challenge = (error as APIRequestError).challenge;
    return { message: "A KySignOn confirmation is still open for this account. Finish it in its window, or cancel it and try again.", cancel: challenge ? () => cancelSSOStepUp(challenge) : undefined };
  }
  if (code === "sso_sign_in_required") return { message: "Sign in with KySignOn to continue. This session signed in with a password an administrator set, so it cannot link browsers." };
  if (code === "password_change_required") return { message: "An administrator set this account's password. Change your password before linking a browser." };
  return { message: error instanceof Error ? error.message : "Linking failed." };
}
