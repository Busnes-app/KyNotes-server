import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { APIRequestError } from "./api";
import { base64, deriveRecoveryKEK, fromBase64, type LoginKeys } from "./crypto";
import { sha256 } from "./fallbackCrypto";
import { DEVICE_ONLY_WRAP, type HeldIdentity, type IdentityStore, type PublicIdentity } from "./identity";
import { linkRefusal, LinkStorageError, OTHER_COPY } from "./linkFlow";
import { publicKeyBytes } from "./pins";
import { concat, IDENTITY_WRAP_ALG, idBytes, sameBytes, wrapIdentity, type Identity } from "./teamKeys";

/** The recovery-code copy: salt(16) | nonce(12) | AES-256-GCM(KEK, privateKey(32)) | tag(16). */
export const RECOVERY_ALG = "pbkdf2-sha256-600000/aes-256-gcm";
export const RECOVERY_BYTES = 76;
const SECRET_BYTES = 16;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const SYMBOLS = 28;
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
const CODE_LABEL = "kynotes/recovery-code/v1";
const WRAP_LABEL = "kynotes/identity-recovery/v1";
const encoder = new TextEncoder();

export const RECOVERY_TYPO = "Check the recovery code: a character is wrong or missing.";
export const RECOVERY_WRONG = "This recovery code does not open your key. Check it and try again.";
export const RECOVERY_NONE = "Your account has no recovery code. Link this browser from one that holds your key, or reset your encryption key.";

export class RecoveryCodeError extends Error {
  constructor(message = RECOVERY_TYPO) {
    super(message);
    this.name = "RecoveryCodeError";
  }
}

/**
 * First 10 bits of SHA-256(label | secret): a typo is caught here, before any request or KDF. It is
 * part of the displayed code and never stored or sent, and is checked only on the user's own input,
 * so it leaks nothing beyond its own 10 bits and has no remote timing oracle.
 */
const checksum = (secret: Uint8Array) => {
  const sum = sha256(concat(encoder.encode(CODE_LABEL), secret));
  return BigInt((sum[0] << 2) | (sum[1] >> 6));
};

/** secret << 10 | checksum as 28 big-endian Crockford symbols in seven groups of four. */
export function formatRecoveryCode(secret: Uint8Array): string {
  if (secret.length !== SECRET_BYTES) throw new Error("invalid recovery secret");
  let value = (secret.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n) << 10n) | checksum(secret);
  const symbols: string[] = [];
  for (let i = 0; i < SYMBOLS; i++) {
    symbols.unshift(ALPHABET[Number(value & 31n)]);
    value >>= 5n;
  }
  return symbols.join("").match(/.{4}/g)!.join("-");
}

/**
 * NFKC, any case, spaces and dashes ignored, I/L read as 1 and O as 0. Throws RecoveryCodeError otherwise.
 * The returned bytes belong to the caller: zero them with fill(0) once used. ponytail: JS strings and
 * BigInts holding the code cannot be wiped; only the byte arrays can.
 */
export function parseRecoveryCode(input: string): Uint8Array {
  const symbols = input.normalize("NFKC").toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  if (symbols.length !== SYMBOLS) throw new RecoveryCodeError();
  let value = 0n;
  for (const symbol of symbols) {
    const digit = ALPHABET.indexOf(symbol);
    if (digit < 0) throw new RecoveryCodeError();
    value = (value << 5n) | BigInt(digit);
  }
  if (value >> 138n) throw new RecoveryCodeError();
  const secret = new Uint8Array(SECRET_BYTES);
  let body = value >> 10n;
  for (let i = SECRET_BYTES - 1; i >= 0; i--) {
    secret[i] = Number(body & 255n);
    body >>= 8n;
  }
  if (checksum(secret) !== (value & 1023n)) throw new RecoveryCodeError();
  return secret;
}

/** 128 CSPRNG bits (noble throws rather than fall back). Show code once; zero secret with fill(0) after sealing. */
export function newRecoveryCode(): { code: string; secret: Uint8Array } {
  const secret = randomBytes(SECRET_BYTES);
  return { code: formatRecoveryCode(secret), secret };
}

/** A server-listed public key as 32 bytes, or undefined when malformed. */
const keyOrUndefined = (value: string): Uint8Array | undefined => { try { return publicKeyBytes(value); } catch { return undefined; } };

/** AAD binds the account and the exact public key (a reset mints the device ID with the copy, so it cannot be bound). */
const aad = (userID: string, publicKey: Uint8Array) => concat(encoder.encode(WRAP_LABEL), idBytes("usr", userID), publicKey);

/** Test-only: fixed salt and nonce for testdata/protocol/recovery_vectors.json. */
export async function sealRecoveryForVector(secret: Uint8Array, privateKey: Uint8Array, userID: string, salt: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  if (secret.length !== SECRET_BYTES || privateKey.length !== 32 || salt.length !== SALT_BYTES || nonce.length !== NONCE_BYTES) throw new Error("invalid recovery input");
  const kek = await deriveRecoveryKEK(secret, salt);
  try {
    return concat(salt, nonce, gcm(kek, nonce, aad(userID, x25519.getPublicKey(privateKey))).encrypt(privateKey));
  } finally {
    kek.fill(0);
  }
}

/** A fresh random salt and nonce per seal. */
export const sealRecovery = (secret: Uint8Array, identity: Identity, userID: string) =>
  sealRecoveryForVector(secret, identity.privateKey, userID, randomBytes(SALT_BYTES), randomBytes(NONCE_BYTES));

/**
 * Opens the server's copy; anything but this code, user and listed public key is RECOVERY_WRONG.
 * The label and length are checked before the KDF and never parsed: the iterations and salt size are
 * this client's, so a server cannot downgrade them.
 */
export async function openRecovery(secret: Uint8Array, wrapped: Uint8Array, userID: string, listed: { deviceId: string; publicKey: string; wrapAlg: string }): Promise<HeldIdentity> {
  const publicKey = keyOrUndefined(listed.publicKey);
  if (!publicKey || listed.wrapAlg !== RECOVERY_ALG || wrapped.length !== RECOVERY_BYTES || secret.length !== SECRET_BYTES) throw new RecoveryCodeError(RECOVERY_WRONG);
  const kek = await deriveRecoveryKEK(secret, wrapped.subarray(0, SALT_BYTES));
  let privateKey: Uint8Array;
  try {
    privateKey = gcm(kek, wrapped.subarray(SALT_BYTES, SALT_BYTES + NONCE_BYTES), aad(userID, publicKey)).decrypt(wrapped.subarray(SALT_BYTES + NONCE_BYTES));
  } catch {
    throw new RecoveryCodeError(RECOVERY_WRONG);
  } finally {
    kek.fill(0);
  }
  if (!sameBytes(x25519.getPublicKey(privateKey), publicKey)) {
    privateKey.fill(0);
    throw new RecoveryCodeError(RECOVERY_WRONG);
  }
  return { deviceId: listed.deviceId, publicKey, privateKey };
}

export type RecoveryCopy = { deviceId: string; publicKey: string; recoveryId: string; wrapAlg: string; wrappedKey: string };
/** The reset body: a password copy for a password session (spec §8), device-only otherwise. */
export type ReplaceInput = { publicKey: string; wrapAlg: string; wrappedPrivateKey?: string; expectedDeviceId: string; recovery: { wrapAlg: string; wrappedKey: string } };
export type RecoveryAPI = {
  myIdentity: () => Promise<PublicIdentity | undefined>;
  putRecovery: (input: { deviceId: string; expectedRecoveryId: string; wrapAlg: string; wrappedKey: string }) => Promise<{ recoveryId: string }>;
  fetchRecovery: () => Promise<RecoveryCopy | undefined>;
  replaceIdentity: (input: ReplaceInput) => Promise<{ deviceId: string }>;
};

export const CONFIRM_FIRST = "Type the asked group of your saved recovery code first.";
export const RECOVERY_MOVED = "Your recovery code was changed in another tab or browser, so this one was not saved. Make a new code here only if you no longer have that one.";
export const RECOVERY_STALE = "The server's recovery copy is not for your account's current key. Reload and try again.";
export const RECOVERY_NEWER = "This recovery code was saved by a newer version of KyNotes. Update this browser's page and try again.";
export const RECOVERY_RATE_LIMITED = "Too many attempts. Wait a few minutes and try again.";
export const RESET_PHRASE = "RESET";
export const RESET_CONFIRM = `Reset your encryption key? Your personal notebooks become unreadable for good, on every browser, and so does any team notebook whose keys no other owner or admin holds. Unsent edits waiting for a notebook's keys are never sent afterwards: export them first. Team owners must share each team's keys with you again, and colleagues are asked to trust your new key. Type ${RESET_PHRASE} to continue.`;
export const RESET_UNCONFIRMED = `Type ${RESET_PHRASE} to confirm the reset.`;
export const resetConfirmed = (typed: string | null | undefined) => typed?.trim() === RESET_PHRASE;
/** The type-back prompt: the group is named only once the code is hidden. */
export const recoveryTypeBack = (group: number) => `Type group ${group} of 7 from your saved copy`;

export const RESET_UNCERTAIN = "The connection failed, so this browser cannot tell whether the reset finished. Keep the code you saved and try again: the retry sends the same new key.";
/** The reset request and the re-read after it both failed: it may have committed. Keep the prepared key and code. */
export class ResetUncertainError extends Error {
  constructor(readonly cause: unknown) {
    super(RESET_UNCERTAIN);
    this.name = "ResetUncertainError";
  }
}

/** A compare-and-swap lost to another tab or browser; live is the server's identity re-read after it. */
export class RecoveryMovedError extends Error {
  readonly code = "already_exists";
  constructor(readonly live: PublicIdentity | undefined) {
    super(RECOVERY_MOVED);
    this.name = "RecoveryMovedError";
  }
}

/**
 * A new code and the copy of identity it seals: shown once, held only in memory, never stored. check: the
 * group (1–7) to type back. The code's bytes are zeroed once sealed; ponytail: the code string cannot be.
 */
export type PreparedRecovery = { readonly code: string; readonly check: number; readonly identity: Identity; readonly userID: string; readonly wrappedKey: string };
/** Prepared codes the user typed back from a saved copy; consumed by the one upload they allow. */
const kept = new WeakSet<PreparedRecovery>();

/** A group 1–7 by rejection sampling over one CSPRNG byte (252 = 36 * 7: every group equally likely), never exclude. */
function pickGroup(exclude?: number): number {
  for (;;) {
    const byte = randomBytes(1)[0];
    if (byte >= 252) continue;
    const group = (byte % 7) + 1;
    if (group !== exclude) return group;
  }
}

export async function prepareRecovery(identity: Identity, userID: string): Promise<PreparedRecovery> {
  const { code, secret } = newRecoveryCode();
  try {
    return Object.freeze({ code, check: pickGroup(), identity, userID, wrappedKey: base64(await sealRecovery(secret, identity, userID)) });
  } finally {
    secret.fill(0);
  }
}

/**
 * The same code, asked back by a different random group: for "Show the code again", so the group the
 * user just read is never the one asked (I1). Unconfirmed: only its own type-back allows an upload.
 */
export const recheck = (prepared: PreparedRecovery): PreparedRecovery => Object.freeze({ ...prepared, check: pickGroup(prepared.check) });

/** True when typed is the asked group (prepared.check): a random group, named only after the code is hidden, shows the user kept the whole code. */
export function confirmRecoverySaved(prepared: PreparedRecovery, typed: string): boolean {
  const fold = (value: string) => value.normalize("NFKC").toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  const ok = fold(typed) === prepared.code.split("-")[prepared.check - 1];
  if (ok) kept.add(prepared);
  return ok;
}

const lostRace = (error: unknown) => error instanceof APIRequestError && error.code === "already_exists";

/**
 * Sets or replaces the account's copy: compare-and-swap on expectedRecoveryId ("" for the first). A lost
 * race re-reads the server and throws RecoveryMovedError; that code is spent, so nothing is overwritten
 * without a new code the user confirms. Returns the new copy's ID.
 */
export async function saveRecovery(api: Pick<RecoveryAPI, "putRecovery" | "myIdentity">, prepared: PreparedRecovery, held: HeldIdentity, expectedRecoveryId: string): Promise<string> {
  if (!kept.has(prepared)) throw new Error(CONFIRM_FIRST);
  if (!sameBytes(prepared.identity.publicKey, held.publicKey)) throw new Error("This recovery code was made for another key. Start again.");
  try {
    const { recoveryId } = await api.putRecovery({ deviceId: held.deviceId, expectedRecoveryId, wrapAlg: RECOVERY_ALG, wrappedKey: prepared.wrappedKey });
    kept.delete(prepared);
    return recoveryId;
  } catch (error) {
    if (!lostRace(error)) throw error;
    kept.delete(prepared);
    throw new RecoveryMovedError(await api.myIdentity().catch(() => undefined));
  }
}

/**
 * Gets the identity back on a browser that does not hold it, from the server's copy and the typed code.
 * A typo fails before the step-up and any request. The copy must be for the identity GET /me/identity
 * lists; it opens only for this user and that public key. Kept by compare-and-swap against the vault as
 * read first: never over a different key (OTHER_COPY). Makes no link requests.
 */
export async function restoreIdentity(api: Pick<RecoveryAPI, "fetchRecovery" | "myIdentity">, store: IdentityStore, userID: string, input: string, stepUp: () => Promise<void>): Promise<HeldIdentity> {
  const secret = parseRecoveryCode(input);
  try {
    // Settled before the step-up, the audited fetch and the KDF: a browser holding another key stops here.
    const before = await store.load();
    const live = await api.myIdentity();
    const listed = live && keyOrUndefined(live.publicKey);
    if (!live || !listed) throw new Error(RECOVERY_NONE);
    if (before && !sameBytes(before.publicKey, listed)) throw new Error(OTHER_COPY);
    if (before?.deviceId === live.deviceId) return before;
    await stepUp();
    const copy = await api.fetchRecovery();
    if (!copy) throw new Error(RECOVERY_NONE);
    if (copy.wrapAlg !== RECOVERY_ALG) throw new Error(RECOVERY_NEWER);
    if (live.deviceId !== copy.deviceId || !sameBytes(listed, keyOrUndefined(copy.publicKey) ?? new Uint8Array())) throw new RecoveryCodeError(RECOVERY_STALE);
    let wrapped: Uint8Array;
    try { wrapped = fromBase64(copy.wrappedKey); } catch { throw new RecoveryCodeError(RECOVERY_WRONG); }
    const identity = await openRecovery(secret, wrapped, userID, { deviceId: live.deviceId, publicKey: live.publicKey, wrapAlg: copy.wrapAlg });
    let saved = false;
    try {
      if (await store.save(identity, before ?? null)) {
        saved = true;
        return identity;
      }
      // Another tab changed the vault meanwhile: its copy of this key is as good; any other key wins.
      const now = await store.load();
      if (now && sameBytes(now.publicKey, identity.publicKey)) return now;
      if (now) throw new Error(OTHER_COPY);
      throw new LinkStorageError();
    } finally {
      if (!saved) identity.privateKey.fill(0);
    }
  } finally {
    secret.fill(0);
  }
}

/**
 * The self-service reset (spec §8 item 5): a new identity and its recovery copy replace the one the browser
 * saw listed (expectedDeviceId, "" for none; the server refuses any other, 409) in one request. typed is
 * what the user typed in answer to RESET_CONFIRM; anything but RESET_PHRASE sends nothing. A password
 * session passes password: keys from one deriveLoginKeys of the typed password; its authSecret is the
 * step-up here, so the password copy is wrapped under the userKEK of the password the server just
 * verified. Without it the identity is device-only (the caller steps up), and so it is for an account
 * linked to KySignOn, which the server refuses a password copy (device_only_required). Before sending,
 * the new public key is noted in the vault (store.noteReset), so a lost answer is explained on the next
 * load. A lost response is finished only when the server lists this new key. The reset replaces whatever
 * this browser held: no compare-and-swap.
 * ponytail: personal notebooks are lost even when this browser still holds the old key. Upgrade: an
 * identity rotation that re-wraps held container keys to the new identity before the swap.
 */
export async function resetIdentity(api: Pick<RecoveryAPI, "replaceIdentity" | "myIdentity">, store: IdentityStore, prepared: PreparedRecovery, expectedDeviceId: string, typed: string, password?: { keys: LoginKeys; stepUp: (authSecret: string) => Promise<unknown> }): Promise<{ identity: HeldIdentity; kept: boolean }> {
  if (!resetConfirmed(typed)) throw new Error(RESET_UNCONFIRMED);
  if (!kept.has(prepared)) throw new Error(CONFIRM_FIRST);
  let wrap: { wrapAlg: string; wrappedPrivateKey?: string } = { wrapAlg: DEVICE_ONLY_WRAP };
  if (password) {
    await password.stepUp(password.keys.authSecret);
    wrap = { wrapAlg: IDENTITY_WRAP_ALG, wrappedPrivateKey: base64(wrapIdentity(password.keys.userKEK, prepared.identity.privateKey, prepared.userID)) };
  }
  let deviceId: string;
  await store.noteReset?.(prepared.identity.publicKey).catch(() => undefined);
  const replace = (with_: typeof wrap) => api.replaceIdentity({ publicKey: base64(prepared.identity.publicKey), ...with_, expectedDeviceId, recovery: { wrapAlg: RECOVERY_ALG, wrappedKey: prepared.wrappedKey } });
  try {
    ({ deviceId } = await replace(wrap).catch((error) => {
      if (!(error instanceof APIRequestError && error.code === "device_only_required")) throw error;
      return replace({ wrapAlg: DEVICE_ONLY_WRAP });
    }));
  } catch (error) {
    // The prepared key stays confirmed (kept) on every failure, so a retry re-sends this same key and copy.
    let live: PublicIdentity | undefined;
    try { live = await api.myIdentity(); } catch { throw new ResetUncertainError(error); }
    const listed = live && keyOrUndefined(live.publicKey);
    if (!live || !listed || !sameBytes(listed, prepared.identity.publicKey)) throw error;
    deviceId = live.deviceId;
  }
  kept.delete(prepared);
  const identity = { ...prepared.identity, deviceId };
  return { identity, kept: await store.save(identity) };
}

/**
 * What the UI shows for a refused recovery step; action names it ("restore your key"…). cancel closes an
 * open KySignOn confirmation. A server refusal is always mapped: its raw message is never shown.
 */
export function recoveryRefusal(error: unknown, action: string): { message: string; cancel?: () => Promise<void> } {
  if (error instanceof APIRequestError) {
    if (error.status === 429 || error.code === "rate_limited") return { message: RECOVERY_RATE_LIMITED };
    if (error.code === "sso_step_up_required") return { message: `Confirm with KySignOn to ${action}. The confirmation window did not finish; allow pop-ups for this site and try again.` };
    if (error.code === "step_up_required") return { message: `Confirm your password to ${action}.` };
    if (error.code === "already_exists") return { message: "Your encryption key changed in another tab or browser. Reload and check before trying again." };
    if (error.code === "identity_exists") return { message: "Start the reset again: a new key is needed." };
    if (error.code === "unauthenticated") return { message: "Your session ended or the password was wrong. Sign in again." };
    if (error.code === "step_up_pending" || error.code === "sso_sign_in_required" || error.code === "password_change_required") return linkRefusal(error, action);
    return { message: `Could not ${action}. Try again.` };
  }
  if (error instanceof TypeError) return { message: `Could not reach KyNotes to ${action}. Check the connection and try again.` };
  if (!(error instanceof Error)) return { message: `Could not ${action}.` };
  return { message: error.message };
}
