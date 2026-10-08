import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdfSha256, sha256 } from "./fallbackCrypto";
import { concat, generateIdentity, idBytes, sameBytes, type Identity } from "./teamKeys";

const LINK_LABEL = "kynotes/link/v1";
const COMMIT_LABEL = "kynotes/link-commit/v1";
const CHECK_LABEL = "kynotes/link-check/v1";
const LINK_VERSION = 0x01;
/** 0x01 | nonce(12) | ChaCha20-Poly1305(identity private key)(48). */
export const LINK_BUNDLE_BYTES = 61;
const encoder = new TextEncoder();

/** What both sides bind: the account, the request, the identity row, and both one-time keys. */
export type LinkContext = { userID: string; requestID: string; identityDeviceID: string; approverKey: Uint8Array; newcomerKey: Uint8Array };

function key32(key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("invalid link key");
  return key;
}

/** A one-time X25519 key for one link attempt; it lives in memory only. */
export const newLinkKey = (): Identity => generateIdentity();

/** Posted before the approver's key exists, so no one can pick a key to fit a check code later. */
export const linkCommitment = (newcomerKey: Uint8Array): Uint8Array => sha256(concat(encoder.encode(COMMIT_LABEL), key32(newcomerKey)));

/** Six digits over the account, the request and both one-time keys, shown as "123 456" on both screens. */
export function checkCode(userID: string, requestID: string, approverKey: Uint8Array, newcomerKey: Uint8Array): string {
  const digest = sha256(concat(encoder.encode(CHECK_LABEL), idBytes("usr", userID), idBytes("lnk", requestID), key32(approverKey), key32(newcomerKey)));
  const digits = String(new DataView(digest.buffer, digest.byteOffset, 4).getUint32(0) % 1_000_000).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

const aad = (c: LinkContext) => concat(encoder.encode(LINK_LABEL), idBytes("usr", c.userID), idBytes("lnk", c.requestID), idBytes("dev", c.identityDeviceID), key32(c.approverKey), key32(c.newcomerKey));
const bundleKey = (shared: Uint8Array, c: LinkContext) => hkdfSha256(shared, 32, concat(c.approverKey, c.newcomerKey), encoder.encode(LINK_LABEL));

/** Approver: seals this account's identity private key to the newcomer's one-time key. */
export function sealLinkBundle(identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext, nonce: Uint8Array = randomBytes(12)): Uint8Array {
  if (identityPrivateKey.length !== 32 || nonce.length !== 12 || !sameBytes(approver.publicKey, context.approverKey)) throw new Error("invalid link input");
  // noble's getSharedSecret throws on an all-zero result (low-order point).
  const key = bundleKey(x25519.getSharedSecret(approver.privateKey, key32(context.newcomerKey)), context);
  return concat(Uint8Array.of(LINK_VERSION), nonce, chacha20poly1305(key, nonce, aad(context)).encrypt(identityPrivateKey));
}

/** Refusal reasons match the Go reference (`openLink`) and `link_vectors.json` rejects. */
export type LinkRefusal = "format" | "newcomer-key" | "low-order" | "aead";
const refused = (reason: LinkRefusal) => new Error(`link bundle refused: ${reason}`);
function as<T>(reason: LinkRefusal, run: () => T): T {
  try { return run(); } catch { throw refused(reason); }
}

/** Newcomer: the identity private key, or a throw naming the check that refused the bytes, binding or key. */
export function openLinkBundle(bundle: Uint8Array, newcomer: Identity, context: LinkContext): Uint8Array {
  if (bundle.length !== LINK_BUNDLE_BYTES || bundle[0] !== LINK_VERSION) throw refused("format");
  if (!sameBytes(newcomer.publicKey, context.newcomerKey)) throw refused("newcomer-key");
  const ad = aad(context);
  const shared = as("low-order", () => x25519.getSharedSecret(newcomer.privateKey, context.approverKey));
  const key = bundleKey(shared, context);
  return as("aead", () => chacha20poly1305(key, bundle.subarray(1, 13), ad).decrypt(bundle.subarray(13)));
}

const confirmations = new WeakSet<CheckCodeConfirmation>();
let mint: (requestID: string) => CheckCodeConfirmation;
/** Proof the user saw one check code on both screens for this request; only confirmCheckCode makes one. */
export class CheckCodeConfirmation {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mint = (requestID) => {
      const confirmation = new CheckCodeConfirmation(requestID);
      confirmations.add(confirmation);
      return confirmation;
    };
  }
  private constructor(readonly requestID: string) {}
}
/** Call only from the user's own "Codes match" click. */
export const confirmCheckCode = (requestID: string): CheckCodeConfirmation => mint(requestID);
export const isCheckCodeConfirmation = (value: unknown, requestID: string): value is CheckCodeConfirmation =>
  typeof value === "object" && value !== null && confirmations.has(value as CheckCodeConfirmation) && (value as CheckCodeConfirmation).requestID === requestID;
