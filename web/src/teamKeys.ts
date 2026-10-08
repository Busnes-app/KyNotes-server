import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdfSha256 } from "./fallbackCrypto";

export const ENVELOPE_ALG = "x25519-hkdf-sha256-chacha20poly1305";
export const IDENTITY_WRAP_ALG = "aes-256-gcm";
/** 0x02 | senderDeviceID(30) | ephPub(32) | nonce(12) | ChaCha20-Poly1305(CK)(48). */
export const ENVELOPE_BYTES = 123;
export const WRAPPED_IDENTITY_BYTES = 60;
const ENVELOPE_LABEL = "kynotes/envelope/v2";
const IDENTITY_LABEL = "kynotes/identity/v1";
const ENVELOPE_VERSION = 0x02;
const ID_BYTES = 30;
const ID = /^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$/;
const encoder = new TextEncoder();

export type Identity = { publicKey: Uint8Array; privateKey: Uint8Array };
/** The sealing identity: its device row ID and private key. */
export type Sender = { deviceId: string; privateKey: Uint8Array };

function idBytes(prefix: "cnt" | "dev" | "usr", value: string): Uint8Array {
  if (!value.startsWith(`${prefix}_`) || !ID.test(value)) throw new Error(`invalid ${prefix} id`);
  return encoder.encode(value);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export function generateIdentity(): Identity {
  const { secretKey, publicKey } = x25519.keygen();
  return { privateKey: secretKey, publicKey };
}

export function envelopeAAD(containerID: string, keyGeneration: number, recipientDeviceID: string, senderDeviceID: string): Uint8Array {
  if (!Number.isInteger(keyGeneration) || keyGeneration < 1 || keyGeneration > 0xffffffff) throw new Error("invalid key generation");
  const generation = new Uint8Array(4);
  new DataView(generation.buffer).setUint32(0, keyGeneration);
  return concat(encoder.encode(ENVELOPE_LABEL), idBytes("cnt", containerID), generation, idBytes("dev", recipientDeviceID), idBytes("dev", senderDeviceID));
}

/** ikm = ephemeral agreement || sender identity agreement, so only the sender (or the recipient) can seal. */
function envelopeKey(ephemeralShared: Uint8Array, staticShared: Uint8Array, ephemeralPublic: Uint8Array, recipientPublic: Uint8Array, senderPublic: Uint8Array): Uint8Array {
  return hkdfSha256(concat(ephemeralShared, staticShared), 32, concat(ephemeralPublic, recipientPublic, senderPublic), encoder.encode(ENVELOPE_LABEL));
}

function sealEnvelope(
  contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string,
  sender: Sender, ephemeralPrivateKey: Uint8Array, nonce: Uint8Array,
): Uint8Array {
  if (contentKey.length !== 32 || recipientPublicKey.length !== 32 || nonce.length !== 12) throw new Error("invalid envelope input");
  const aad = envelopeAAD(containerID, keyGeneration, recipientDeviceID, sender.deviceId);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivateKey);
  // noble's getSharedSecret throws on an all-zero result (low-order point).
  const key = envelopeKey(
    x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey), x25519.getSharedSecret(sender.privateKey, recipientPublicKey),
    ephemeralPublic, recipientPublicKey, x25519.getPublicKey(sender.privateKey),
  );
  const sealed = chacha20poly1305(key, nonce, aad).encrypt(contentKey);
  return concat(Uint8Array.of(ENVELOPE_VERSION), encoder.encode(sender.deviceId), ephemeralPublic, nonce, sealed);
}

export function wrapEnvelope(contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string, sender: Sender): Uint8Array {
  return sealEnvelope(contentKey, recipientPublicKey, containerID, keyGeneration, recipientDeviceID, sender, x25519.utils.randomSecretKey(), randomBytes(12));
}

/** Test-only: fixed ephemeral key and nonce for cross-implementation vectors. */
export const wrapEnvelopeForVector = sealEnvelope;

/** The sender device ID an envelope claims; unauthenticated until unwrapEnvelope succeeds with that sender's key. */
export function envelopeSender(envelope: Uint8Array): string {
  if (envelope.length !== ENVELOPE_BYTES || envelope[0] !== ENVELOPE_VERSION) throw new Error("unsupported envelope");
  const sender = new TextDecoder().decode(envelope.subarray(1, 1 + ID_BYTES));
  idBytes("dev", sender);
  return sender;
}

/** Opens an envelope; senderPublicKey is the identity key the caller resolved for envelopeSender(envelope). */
export function unwrapEnvelope(envelope: Uint8Array, recipientPrivateKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string, senderPublicKey: Uint8Array): Uint8Array {
  const aad = envelopeAAD(containerID, keyGeneration, recipientDeviceID, envelopeSender(envelope));
  if (senderPublicKey.length !== 32) throw new Error("invalid sender key");
  const ephemeralPublic = envelope.subarray(31, 63);
  const nonce = envelope.subarray(63, 75);
  const key = envelopeKey(
    x25519.getSharedSecret(recipientPrivateKey, ephemeralPublic), x25519.getSharedSecret(recipientPrivateKey, senderPublicKey),
    ephemeralPublic, x25519.getPublicKey(recipientPrivateKey), senderPublicKey,
  );
  return chacha20poly1305(key, nonce, aad).decrypt(envelope.subarray(75));
}

function identityAAD(userID: string): Uint8Array {
  return concat(encoder.encode(IDENTITY_LABEL), idBytes("usr", userID));
}

function sealIdentity(userKEK: Uint8Array, privateKey: Uint8Array, userID: string, nonce: Uint8Array): Uint8Array {
  if (userKEK.length !== 32 || privateKey.length !== 32 || nonce.length !== 12) throw new Error("invalid identity input");
  return concat(nonce, gcm(userKEK, nonce, identityAAD(userID)).encrypt(privateKey));
}

export function wrapIdentity(userKEK: Uint8Array, privateKey: Uint8Array, userID: string): Uint8Array {
  return sealIdentity(userKEK, privateKey, userID, randomBytes(12));
}

/** Test-only: fixed nonce for cross-implementation vectors. */
export const wrapIdentityForVector = sealIdentity;

export function unwrapIdentity(userKEK: Uint8Array, wrapped: Uint8Array, userID: string): Identity {
  if (userKEK.length !== 32 || wrapped.length !== WRAPPED_IDENTITY_BYTES) throw new Error("invalid wrapped identity");
  const privateKey = gcm(userKEK, wrapped.subarray(0, 12), identityAAD(userID)).decrypt(wrapped.subarray(12));
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}
