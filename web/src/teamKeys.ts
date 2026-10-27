import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { hkdfSha256 } from "./crypto";

/** Envelope v3: RFC 9180 HPKE mode_auth, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305. Every new envelope is v3. */
export const ENVELOPE_ALG = "hpke-auth-x25519-hkdfsha256-chacha20poly1305";
/** 0x03 | senderDeviceID(30) | enc(32) | ChaCha20-Poly1305(CK)(48). */
export const ENVELOPE_BYTES = 111;
/** Envelope v2, the earlier custom construction: opened for stored rows, never sealed. */
export const LEGACY_ENVELOPE_ALG = "x25519-hkdf-sha256-chacha20poly1305";
/** 0x02 | senderDeviceID(30) | ephPub(32) | nonce(12) | ChaCha20-Poly1305(CK)(48). */
export const LEGACY_ENVELOPE_BYTES = 123;
export const IDENTITY_WRAP_ALG = "aes-256-gcm";
export const WRAPPED_IDENTITY_BYTES = 60;
const ENVELOPE_LABEL = "kynotes/envelope/v3";
const LEGACY_ENVELOPE_LABEL = "kynotes/envelope/v2";
const IDENTITY_LABEL = "kynotes/identity/v1";
const ID_BYTES = 30;
const ID = /^(cnt|dev|usr|lnk)_[0-9a-hjkmnp-tv-z]{26}$/;
const encoder = new TextEncoder();
/** The envelope v3 suite; exported for the RFC 9180 vector test. */
export const envelopeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

export type Identity = { publicKey: Uint8Array; privateKey: Uint8Array };
/** The sealing identity: its device row ID and private key. */
export type Sender = { deviceId: string; privateKey: Uint8Array };

export function idBytes(prefix: "cnt" | "dev" | "usr" | "lnk", value: string): Uint8Array {
  if (!value.startsWith(`${prefix}_`) || !ID.test(value)) throw new Error(`invalid ${prefix} id`);
  return encoder.encode(value);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** Same length and bytes, with no early exit, so commitments and keys compare without a timing oracle. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function generateIdentity(): Identity {
  const { secretKey, publicKey } = x25519.keygen();
  return { privateKey: secretKey, publicKey };
}

function envelopeContext(label: string, containerID: string, keyGeneration: number, recipientDeviceID: string, senderDeviceID: string): Uint8Array {
  if (!Number.isInteger(keyGeneration) || keyGeneration < 1 || keyGeneration > 0xffffffff) throw new Error("invalid key generation");
  const generation = new Uint8Array(4);
  new DataView(generation.buffer).setUint32(0, keyGeneration);
  return concat(encoder.encode(label), idBytes("cnt", containerID), generation, idBytes("dev", recipientDeviceID), idBytes("dev", senderDeviceID));
}

/**
 * The v3 HPKE info: label | containerID | generation (u32 BE) | recipientDeviceID | senderDeviceID.
 * Context goes in info so it enters the key schedule; the single message needs no aad.
 */
export const envelopeInfo = (containerID: string, keyGeneration: number, recipientDeviceID: string, senderDeviceID: string) =>
  envelopeContext(ENVELOPE_LABEL, containerID, keyGeneration, recipientDeviceID, senderDeviceID);

async function keyPair(privateKey: Uint8Array): Promise<CryptoKeyPair> {
  return { privateKey: await envelopeSuite.kem.deserializePrivateKey(privateKey), publicKey: await envelopeSuite.kem.deserializePublicKey(x25519.getPublicKey(privateKey)) };
}

/** ephemeralSeed is the HPKE ikmE (test vectors only); omitted, the library draws a fresh ephemeral key. */
async function sealEnvelope(
  contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string,
  sender: Sender, ephemeralSeed?: Uint8Array,
): Promise<Uint8Array> {
  if (contentKey.length !== 32 || recipientPublicKey.length !== 32) throw new Error("invalid envelope input");
  const info = envelopeInfo(containerID, keyGeneration, recipientDeviceID, sender.deviceId);
  const params = { recipientPublicKey: await envelopeSuite.kem.deserializePublicKey(recipientPublicKey), senderKey: await keyPair(sender.privateKey), info };
  const { enc, ct } = await envelopeSuite.seal(ephemeralSeed ? { ...params, ekm: ephemeralSeed } : params, contentKey);
  return concat(Uint8Array.of(0x03), encoder.encode(sender.deviceId), new Uint8Array(enc), new Uint8Array(ct));
}

export function wrapEnvelope(contentKey: Uint8Array, recipientPublicKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string, sender: Sender): Promise<Uint8Array> {
  return sealEnvelope(contentKey, recipientPublicKey, containerID, keyGeneration, recipientDeviceID, sender);
}

/** Test-only: fixed HPKE ephemeral seed for cross-implementation vectors. */
export const wrapEnvelopeForVector = sealEnvelope;

/** The sender device ID an envelope of alg claims; unauthenticated until unwrapEnvelope succeeds with that sender's key. Alg, version and length must agree. */
export function envelopeSender(alg: string, envelope: Uint8Array): string {
  const [version, size] = alg === ENVELOPE_ALG ? [0x03, ENVELOPE_BYTES] : alg === LEGACY_ENVELOPE_ALG ? [0x02, LEGACY_ENVELOPE_BYTES] : [-1, -1];
  if (envelope.length !== size || envelope[0] !== version) throw new Error("unsupported envelope");
  const sender = new TextDecoder().decode(envelope.subarray(1, 1 + ID_BYTES));
  idBytes("dev", sender);
  return sender;
}

/** Opens a v3 or stored v2 envelope, selected by alg; senderPublicKey is the identity key the caller resolved for envelopeSender. */
export async function unwrapEnvelope(alg: string, envelope: Uint8Array, recipientPrivateKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string, senderPublicKey: Uint8Array): Promise<Uint8Array> {
  const sender = envelopeSender(alg, envelope);
  if (senderPublicKey.length !== 32) throw new Error("invalid sender key");
  if (alg === LEGACY_ENVELOPE_ALG) return unwrapLegacyEnvelope(envelope, recipientPrivateKey, containerID, keyGeneration, recipientDeviceID, sender, senderPublicKey);
  const opened = await envelopeSuite.open({
    recipientKey: await keyPair(recipientPrivateKey),
    senderPublicKey: await envelopeSuite.kem.deserializePublicKey(senderPublicKey),
    enc: envelope.subarray(1 + ID_BYTES, 1 + ID_BYTES + 32),
    info: envelopeInfo(containerID, keyGeneration, recipientDeviceID, sender),
  }, envelope.subarray(1 + ID_BYTES + 32));
  return new Uint8Array(opened);
}

/**
 * v2: key = HKDF-SHA256(DH(eph,R) || DH(senderStatic,R), salt = ephPub || recipientPub || senderPub, info = v2 label),
 * AAD = the v2 context. Unchanged so stored envelopes keep opening.
 */
function unwrapLegacyEnvelope(envelope: Uint8Array, recipientPrivateKey: Uint8Array, containerID: string, keyGeneration: number, recipientDeviceID: string, sender: string, senderPublicKey: Uint8Array): Uint8Array {
  const aad = envelopeContext(LEGACY_ENVELOPE_LABEL, containerID, keyGeneration, recipientDeviceID, sender);
  const ephemeralPublic = envelope.subarray(31, 63);
  const nonce = envelope.subarray(63, 75);
  // noble's getSharedSecret throws on an all-zero result (low-order point).
  const ikm = concat(x25519.getSharedSecret(recipientPrivateKey, ephemeralPublic), x25519.getSharedSecret(recipientPrivateKey, senderPublicKey));
  const key = hkdfSha256(ikm, 32, concat(ephemeralPublic, x25519.getPublicKey(recipientPrivateKey), senderPublicKey), encoder.encode(LEGACY_ENVELOPE_LABEL));
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
