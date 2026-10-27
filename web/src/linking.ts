import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "./crypto";
import { concat, envelopeSuite, generateIdentity, hpkeKeyPair, idBytes, sameBytes, type Identity } from "./teamKeys";

const LINK_LABEL = "kynotes/link/v2";
const COMMIT_LABEL = "kynotes/link-commit/v1";
const CHECK_LABEL = "kynotes/link-check/v1";
const LINK_VERSION = 0x02;
/** 0x02 | enc(32) | ChaCha20-Poly1305(identity private key)(48): RFC 9180 HPKE mode_auth, the envelope v3 suite. */
export const LINK_BUNDLE_BYTES = 81;
const encoder = new TextEncoder();

/** What both sides bind: the account, the request, the identity row, and both one-time keys. */
export type LinkContext = { userID: string; requestID: string; identityDeviceID: string; approverKey: Uint8Array; newcomerKey: Uint8Array };

function key32(key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("invalid link key");
  return key;
}

const liveKeys = new WeakSet<Identity>();
/** A one-time X25519 key for one link attempt; it lives in memory only, until discardLinkKey. */
export function newLinkKey(): Identity {
  const key = generateIdentity();
  liveKeys.add(key);
  return key;
}
/** Ends an attempt: zeroes the one-time private key; nothing can open a bundle sealed to it after this. */
export function discardLinkKey(key: Identity): void {
  key.privateKey.fill(0);
  liveKeys.delete(key);
}
export const isLiveLinkKey = (key: Identity): boolean => liveKeys.has(key);

/** Posted before the approver's key exists, so no one can pick a key to fit a check code later. */
export const linkCommitment = (newcomerKey: Uint8Array): Uint8Array => sha256(concat(encoder.encode(COMMIT_LABEL), key32(newcomerKey)));

/** Six digits over the account, the request and both one-time keys, shown as "123 456" on both screens. */
export function checkCode(userID: string, requestID: string, approverKey: Uint8Array, newcomerKey: Uint8Array): string {
  const digest = sha256(concat(encoder.encode(CHECK_LABEL), idBytes("usr", userID), idBytes("lnk", requestID), key32(approverKey), key32(newcomerKey)));
  const digits = String(new DataView(digest.buffer, digest.byteOffset, 4).getUint32(0) % 1_000_000).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

/** HPKE info: v2 label | userID | requestID | identityDeviceID | approverKey | newcomerKey. */
const linkInfo = (c: LinkContext) => concat(encoder.encode(LINK_LABEL), idBytes("usr", c.userID), idBytes("lnk", c.requestID), idBytes("dev", c.identityDeviceID), key32(c.approverKey), key32(c.newcomerKey));

/**
 * Approver: seals this account's identity private key to the newcomer's one-time key, authenticated by
 * the approver's one-time key (the key the check code covers). ephemeralSeed is the HPKE ikmE, vectors only.
 */
async function seal(identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext, ephemeralSeed?: Uint8Array): Promise<Uint8Array> {
  if (identityPrivateKey.length !== 32 || !sameBytes(approver.publicKey, context.approverKey)) throw new Error("invalid link input");
  const params = { recipientPublicKey: await envelopeSuite.kem.deserializePublicKey(key32(context.newcomerKey)), senderKey: await hpkeKeyPair(approver.privateKey), info: linkInfo(context) };
  const { enc, ct } = await envelopeSuite.seal(ephemeralSeed ? { ...params, ekm: ephemeralSeed } : params, identityPrivateKey);
  return concat(Uint8Array.of(LINK_VERSION), new Uint8Array(enc), new Uint8Array(ct));
}
export const sealLinkBundle = (identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext): Promise<Uint8Array> => seal(identityPrivateKey, approver, context);
/** Test-only: fixed HPKE ephemeral seed for cross-implementation vectors. */
export const sealLinkBundleForVector = seal;

/** Refusal reasons match the Go reference (`openLink`) and `link_vectors.json` rejects. */
export type LinkRefusal = "format" | "newcomer-key" | "low-order" | "aead";
const refused = (reason: LinkRefusal) => new Error(`link bundle refused: ${reason}`);

/** Newcomer: the identity private key, or a throw naming the check that refused the bytes, binding or key. */
export async function openLinkBundle(bundle: Uint8Array, newcomer: Identity, context: LinkContext): Promise<Uint8Array> {
  if (bundle.length !== LINK_BUNDLE_BYTES || bundle[0] !== LINK_VERSION || context.approverKey.length !== 32) throw refused("format");
  if (!sameBytes(newcomer.publicKey, context.newcomerKey)) throw refused("newcomer-key");
  // HPKE refuses an all-zero agreement too; this names it. noble throws on a low-order point.
  try { x25519.getSharedSecret(newcomer.privateKey, context.approverKey); } catch { throw refused("low-order"); }
  try {
    return new Uint8Array(await envelopeSuite.open({
      recipientKey: await hpkeKeyPair(newcomer.privateKey),
      senderPublicKey: await envelopeSuite.kem.deserializePublicKey(context.approverKey),
      enc: bundle.subarray(1, 33),
      info: linkInfo(context),
    }, bundle.subarray(33)));
  } catch { throw refused("aead"); }
}

const confirmations = new WeakSet<CheckCodeConfirmation>();
let mint: (requestID: string, code: string) => CheckCodeConfirmation;
/** Proof the user saw this check code on both screens for this request; only confirmCheckCode makes one. */
export class CheckCodeConfirmation {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mint = (requestID, code) => {
      // Frozen: a holder cannot re-target it at another request or code.
      const confirmation = new CheckCodeConfirmation(requestID, code);
      Object.freeze(confirmation);
      confirmations.add(confirmation);
      return confirmation;
    };
  }
  private constructor(readonly requestID: string, readonly code: string) {}
}
/** Call only from the user's own confirmation of the code this screen shows (linkFlow.ts). */
export const confirmCheckCode = (requestID: string, code: string): CheckCodeConfirmation => mint(requestID, code);
export const isCheckCodeConfirmation = (value: unknown, requestID: string): value is CheckCodeConfirmation =>
  typeof value === "object" && value !== null && confirmations.has(value as CheckCodeConfirmation) && (value as CheckCodeConfirmation).requestID === requestID;

const typed = new WeakSet<CheckCodeConfirmation>();
const digits = (code: string) => code.normalize("NFKC").replace(/\s/g, "");
/**
 * The approver's only confirmation: the user typed the code the other browser shows (entered), and it
 * equals this screen's code (shown) after NFKC and with spaces ignored. There is no "codes match" button.
 */
export function confirmTypedCheckCode(requestID: string, shown: string, entered: string): CheckCodeConfirmation {
  if (!shown || digits(entered) !== digits(shown)) throw new Error("That is not the code the other browser shows. Type it again; if the codes differ, cancel.");
  const confirmation = mint(requestID, shown);
  typed.add(confirmation);
  return confirmation;
}
export const isTypedCheckCodeConfirmation = (value: unknown, requestID: string): value is CheckCodeConfirmation =>
  isCheckCodeConfirmation(value, requestID) && typed.has(value);
