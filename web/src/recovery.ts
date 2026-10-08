import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { deriveRecoveryKEK } from "./crypto";
import { sha256 } from "./fallbackCrypto";
import type { HeldIdentity } from "./identity";
import { publicKeyBytes } from "./pins";
import { concat, idBytes, sameBytes, type Identity } from "./teamKeys";

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
  if (listed.wrapAlg !== RECOVERY_ALG || wrapped.length !== RECOVERY_BYTES || secret.length !== SECRET_BYTES) throw new RecoveryCodeError(RECOVERY_WRONG);
  const publicKey = publicKeyBytes(listed.publicKey);
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
