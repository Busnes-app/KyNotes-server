import { base64, fromBase64, type LoginKeys } from "./crypto";
import { generateIdentity, IDENTITY_WRAP_ALG, sameBytes, unwrapIdentity, wrapIdentity, type Identity } from "./teamKeys";

/** The password-wrapped identity; only local login and step-up responses carry it. */
export type IdentityRecord = { deviceId: string; publicKey: string; fingerprint: string; wrapAlg: string; wrappedPrivateKey: string };
export type PublicIdentity = { deviceId: string; publicKey: string; fingerprint: string };
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

/**
 * Opens the identity from the login response, or creates it on first password sign-in.
 * PUT needs a fresh step-up, which also returns an identity another tab created meanwhile.
 * Never replaces an identity it cannot open. Undefined while an administrator knows the
 * password: the user's own password change creates it.
 */
export async function ensureIdentity(api: IdentityAPI, userID: string, keys: LoginKeys, fromLogin: IdentityRecord | undefined): Promise<HeldIdentity | undefined> {
  if (fromLogin) return openIdentity(fromLogin, keys.userKEK, userID);
  const existing = await api.stepUp(keys.authSecret);
  if (existing) return openIdentity(existing, keys.userKEK, userID);
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
    return openIdentity(winner, keys.userKEK, userID);
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
  const record = await api.stepUp(current.authSecret);
  const identity = record ? openIdentity(record, current.userKEK, userID)
    : cached && cached.deviceId === live.deviceId && sameBytes(cached.publicKey, fromBase64(live.publicKey)) ? cached
    : undefined;
  if (!identity) throw new Error("Sign in with your password on this device before changing it");
  return { identity, identityDeviceId: identity.deviceId, wrappedIdentityKey: base64(wrapIdentity(newKEK, identity.privateKey, userID)) };
}
