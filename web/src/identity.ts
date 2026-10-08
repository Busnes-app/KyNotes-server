import { base64, fromBase64, type LoginKeys } from "./crypto";
import { generateIdentity, IDENTITY_WRAP_ALG, sameBytes, unwrapIdentity, wrapIdentity, type Identity } from "./teamKeys";

/** The password-wrapped identity; only local login and step-up responses carry it. */
export type IdentityRecord = { deviceId: string; publicKey: string; fingerprint: string; wrapAlg: string; wrappedPrivateKey: string };
/** wrapAlg of an identity created from a single sign-on session: no server copy (P5 adds a recovery code). */
export const DEVICE_ONLY_WRAP = "none";
export type PublicIdentity = { deviceId: string; publicKey: string; fingerprint: string; wrapAlg?: string };
export type IdentityUpload = { publicKey: string; wrapAlg: string; wrappedPrivateKey: string };
export type HeldIdentity = Identity & { deviceId: string };
export type IdentityAPI = {
  myIdentity: () => Promise<PublicIdentity | undefined>;
  putMyIdentity: (input: IdentityUpload) => Promise<{ deviceId: string }>;
  /** Proves the password and returns the wrapped identity, if the session may receive it. */
  stepUp: (authSecret: string) => Promise<IdentityRecord | undefined>;
};

/** Unlocks the server copy and refuses a public key the private key does not produce. */
export function openIdentity(record: IdentityRecord, userKEK: Uint8Array, userID: string): HeldIdentity {
  if (record.wrapAlg !== IDENTITY_WRAP_ALG) throw new Error("unsupported identity wrap");
  const identity = unwrapIdentity(userKEK, fromBase64(record.wrappedPrivateKey), userID);
  if (!sameBytes(identity.publicKey, fromBase64(record.publicKey))) throw new Error("identity public key mismatch");
  return { ...identity, deviceId: record.deviceId };
}

const unlock = (record: IdentityRecord, keys: LoginKeys, userID: string) => (record.wrapAlg === DEVICE_ONLY_WRAP ? undefined : openIdentity(record, keys.userKEK, userID));

/**
 * Opens the identity from the login response, or creates it on first password sign-in.
 * PUT needs a fresh step-up, which also returns an identity another tab created meanwhile.
 * Never replaces an identity it cannot open. Undefined while an administrator knows the
 * password: the user's own password change creates it. Undefined for a device-only identity: this
 * browser must be linked.
 */
export async function ensureIdentity(api: IdentityAPI, userID: string, keys: LoginKeys, fromLogin: IdentityRecord | undefined): Promise<HeldIdentity | undefined> {
  if (fromLogin) return unlock(fromLogin, keys, userID);
  const existing = await api.stepUp(keys.authSecret);
  if (existing) return unlock(existing, keys, userID);
  const identity = generateIdentity();
  const upload = { publicKey: base64(identity.publicKey), wrapAlg: IDENTITY_WRAP_ALG, wrappedPrivateKey: base64(wrapIdentity(keys.userKEK, identity.privateKey, userID)) };
  try {
    const { deviceId } = await api.putMyIdentity(upload);
    return { ...identity, deviceId };
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === "password_change_required") return undefined;
    // Another tab won the create race: use its identity, not ours.
    const winner = code === "identity_exists" ? await api.stepUp(keys.authSecret) : undefined;
    if (!winner) throw error;
    return unlock(winner, keys, userID);
  }
}

/**
 * The password-change payload: the same private key under the new userKEK, bound to its device ID.
 * Undefined when no identity exists. SSO step-ups withhold the wrapped key, so the vault copy is
 * used only when it matches the server's current identity.
 */
export async function rewrapIdentity(api: Pick<IdentityAPI, "myIdentity" | "stepUp">, userID: string, current: LoginKeys, newKEK: Uint8Array, cached: HeldIdentity | undefined): Promise<{ identity: HeldIdentity; identityDeviceId: string; wrappedIdentityKey: string } | undefined> {
  const live = await api.myIdentity();
  if (!live) return undefined;
  if (live.wrapAlg === DEVICE_ONLY_WRAP) return undefined; // nothing on the server is wrapped under the password
  const record = await api.stepUp(current.authSecret);
  const identity = record ? openIdentity(record, current.userKEK, userID)
    : cached && cached.deviceId === live.deviceId && sameBytes(cached.publicKey, fromBase64(live.publicKey)) ? cached
    : undefined;
  if (!identity) throw new Error("Sign in with your password on this device before changing it");
  return { identity, identityDeviceId: identity.deviceId, wrappedIdentityKey: base64(wrapIdentity(newKEK, identity.privateKey, userID)) };
}

export type DeviceOnlyAPI = Pick<IdentityAPI, "myIdentity"> & { putDeviceOnlyIdentity: (publicKey: string) => Promise<{ deviceId: string }> };
/**
 * This browser's vault copy: load includes a pending one (deviceId "") and throws when unreadable.
 * save is false when nothing was kept; with expected it writes only while the vault still holds
 * that identity (null: none), so two tabs never overwrite each other's key.
 */
export type IdentityStore = { load: () => Promise<HeldIdentity | undefined>; save: (identity: HeldIdentity, expected?: HeldIdentity | null) => Promise<boolean> };
export type Settled = { kind: "held"; identity: HeldIdentity } | { kind: "link" } | { kind: "orphaned" } | { kind: "unsaved" };

/**
 * Creates a single sign-on account's identity on this browser (device-only), or finishes one an
 * interrupted run created. The key is kept here, pending, before the server learns it, so a lost
 * response never leaves an identity no browser holds. A held identity the server no longer lists is
 * replaced only with replace (the user's explicit choice); another browser's identity means linking.
 * Server refusals (step_up_pending, sso_sign_in_required, password_change_required, a cancelled
 * KySignOn confirmation) are thrown unchanged and leave the pending key for the next run.
 */
export async function settleSSOIdentity(api: DeviceOnlyAPI, store: IdentityStore, replace = false, retried = false): Promise<Settled> {
  const local = await store.load();
  const live = await api.myIdentity();
  if (live) {
    if (!local || !sameBytes(local.publicKey, fromBase64(live.publicKey))) return { kind: "link" };
    const identity = { ...local, deviceId: live.deviceId };
    // A save that fails leaves the pending copy, which the next run finishes.
    if (local.deviceId !== live.deviceId) await store.save(identity, local);
    return { kind: "held", identity };
  }
  if (local?.deviceId && !replace) return { kind: "orphaned" };
  const pending = local && !local.deviceId ? local : { ...generateIdentity(), deviceId: "" };
  // Compare-and-swap against what this run read: a key another tab kept meanwhile is never overwritten.
  if (pending !== local && !(await store.save(pending, local ?? null))) return retried ? { kind: "unsaved" } : settleSSOIdentity(api, store, false, true);
  try {
    const { deviceId } = await api.putDeviceOnlyIdentity(base64(pending.publicKey));
    const identity = { ...pending, deviceId };
    await store.save(identity, pending);
    return { kind: "held", identity };
  } catch (error) {
    // Another tab of this browser created one meanwhile: settle against it once.
    if ((error as { code?: string }).code === "identity_exists" && !retried) return settleSSOIdentity(api, store, false, true);
    throw error;
  }
}

export type IdentityStatus = "held" | "link" | "create" | "orphaned";
/** What this browser can do: use its copy, be linked, create (or finish) one, or replace an orphan. */
export function identityStatus(local: HeldIdentity | undefined, live: PublicIdentity | undefined): IdentityStatus {
  if (!live) return local?.deviceId ? "orphaned" : "create";
  if (!local || !sameBytes(local.publicKey, fromBase64(live.publicKey))) return "link";
  return local.deviceId === live.deviceId ? "held" : "create";
}

/** The vault copy may seal and open keys only while the server lists it as this account's identity, or cannot be reached. */
export function currentCopy(local: HeldIdentity | undefined, live: PublicIdentity | undefined | "unreachable"): HeldIdentity | undefined {
  if (!local?.deviceId) return undefined;
  if (live === "unreachable") return local;
  return identityStatus(local, live) === "held" ? local : undefined;
}
