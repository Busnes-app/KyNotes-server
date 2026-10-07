import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdfSha256 } from "./fallbackCrypto";

export const ENVELOPE_ALG = "x25519-hkdf-sha256-chacha20poly1305";
export const IDENTITY_WRAP_ALG = "aes-256-gcm";
export const ENVELOPE_BYTES = 93;
export const WRAPPED_IDENTITY_BYTES = 60;
const ENVELOPE_LABEL = "kynotes/envelope/v1";
const IDENTITY_LABEL = "kynotes/identity/v1";
const ENVELOPE_VERSION = 0x01;
const ID = /^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$/;
const encoder = new TextEncoder();

export type Identity = { publicKey: Uint8Array; privateKey: Uint8Array };

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

export function envelopeAAD(containerID: string, keyGeneration: number, recipientDeviceID: string): Uint8Array {
  if (!Number.isInteger(keyGeneration) || keyGeneration < 1 || keyGeneration > 0xffffffff) throw new Error("invalid key generation");
  const generation = new Uint8Array(4);
  new DataView(generation.buffer).setUint32(0, keyGeneration);
  return concat(encoder.encode(ENVELOPE_LABEL), idBytes("cnt", containerID), generation, idBytes("dev", recipientDeviceID));
}

function envelopeKey(ephemeralPrivate: Uint8Array, peerPublic: Uint8Array, ephemeralPublic: Uint8Array, recipientPublic: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(ephemeralPrivate, peerPublic);
  return hkdfSha256(shared, 32, concat(ephemeralPublic, recipientPublic), encoder.encode(ENVELOPE_LABEL));
}

function sealEnvelope(
  contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string,
  ephemeralPrivateKey: Uint8Array, nonce: Uint8Array,
): Uint8Array {
  if (contentKey.length !== 32 || recipientPublicKey.length !== 32 || nonce.length !== 12) throw new Error("invalid envelope input");
  const aad = envelopeAAD(containerID, keyGeneration, recipientDeviceID);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivateKey);
  const key = envelopeKey(ephemeralPrivateKey, recipientPublicKey, ephemeralPublic, recipientPublicKey);
  const sealed = chacha20poly1305(key, nonce, aad).encrypt(contentKey);
  return concat(Uint8Array.of(ENVELOPE_VERSION), ephemeralPublic, nonce, sealed);
}

export function wrapEnvelope(contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string): Uint8Array {
  return sealEnvelope(contentKey, recipientPublicKey, containerID, keyGeneration, recipientDeviceID, x25519.utils.randomSecretKey(), randomBytes(12));
}

/** Test-only: fixed ephemeral key and nonce for cross-implementation vectors. */
export const wrapEnvelopeForVector = sealEnvelope;

export function unwrapEnvelope(envelope: Uint8Array, recipientPrivateKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string): Uint8Array {
  if (envelope.length !== ENVELOPE_BYTES || envelope[0] !== ENVELOPE_VERSION) throw new Error("unsupported envelope");
  const aad = envelopeAAD(containerID, keyGeneration, recipientDeviceID);
  const ephemeralPublic = envelope.subarray(1, 33);
  const nonce = envelope.subarray(33, 45);
  const recipientPublic = x25519.getPublicKey(recipientPrivateKey);
  const key = envelopeKey(recipientPrivateKey, ephemeralPublic, ephemeralPublic, recipientPublic);
  return chacha20poly1305(key, nonce, aad).decrypt(envelope.subarray(45));
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
