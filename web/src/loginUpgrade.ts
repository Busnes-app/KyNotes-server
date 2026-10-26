import { base64, deriveLoginKeys, LEGACY_LOGIN_ITERATIONS, LOGIN_ITERATIONS, randomLoginSalt, type LoginKeys } from "./crypto";
import { openIdentity, type IdentityRecord } from "./identity";
import { IDENTITY_WRAP_ALG, wrapIdentity } from "./teamKeys";

const PINS = "kynotes.login-pins.v1";
const normal = (username: string) => username.trim().toLowerCase();

/** Usernames this browser has signed in to at LOGIN_ITERATIONS: a server never takes them lower again. */
function pinned(): string[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(PINS) ?? "[]");
    return Array.isArray(value) ? value.filter((name): name is string => typeof name === "string") : [];
  } catch {
    return [];
  }
}

/** The fewest iterations this browser derives at for username; LEGACY only until the account is pinned. */
export const loginFloor = (username: string) => (pinned().includes(normal(username)) ? LOGIN_ITERATIONS : LEGACY_LOGIN_ITERATIONS);

export function pinLogin(username: string): void {
  const list = pinned();
  if (list.includes(normal(username))) return;
  try { localStorage.setItem(PINS, JSON.stringify([...list, normal(username)])); } catch { /* storage disabled: the floor stays legacy here */ }
}

export type LoginUpgrade = { currentAuthSecret: string; newAuthSecret: string; newLoginSalt: string; iterations: number; identityDeviceId?: string; wrappedIdentityKey?: string };

/**
 * Re-derives an older account's keys at LOGIN_ITERATIONS under a fresh salt and sends the new verifier with
 * the identity's password copy re-wrapped, which the server swaps in one transaction. Interrupted, nothing
 * changed or everything did: the next sign-in sees the old count and runs it again, or the new one.
 * Returns the new keys and the login identity as the server now holds it.
 */
export async function upgradeLogin(send: (input: LoginUpgrade) => Promise<void>, userID: string, password: string, current: LoginKeys, identity?: IdentityRecord): Promise<{ keys: LoginKeys; identity?: IdentityRecord }> {
  const newLoginSalt = randomLoginSalt();
  const keys = await deriveLoginKeys(password, newLoginSalt, LOGIN_ITERATIONS);
  let rewrap: { identityDeviceId: string; wrappedIdentityKey: string } | undefined;
  if (identity?.wrapAlg === IDENTITY_WRAP_ALG) {
    const held = openIdentity(identity, current.userKEK, userID);
    rewrap = { identityDeviceId: held.deviceId, wrappedIdentityKey: base64(wrapIdentity(keys.userKEK, held.privateKey, userID)) };
  }
  await send({ currentAuthSecret: current.authSecret, newAuthSecret: keys.authSecret, newLoginSalt, iterations: LOGIN_ITERATIONS, ...rewrap });
  return { keys, identity: identity && rewrap ? { ...identity, wrappedPrivateKey: rewrap.wrappedIdentityKey } : identity };
}
