import { sha256 } from "./crypto";
import { concat, idBytes, sameBytes, type Identity } from "./teamKeys";
import { generatePQIdentityReady, isPQPublic } from "./pqIdentity";
import { loadPQ, result, HYBRID_SIGNATURE_BYTES, PQ_PRIVATE_BYTES, XWING_PUBLIC_BYTES } from "./pq";

const LINK_LABEL = "kynotes/link/v3";
const COMMIT_LABEL = "kynotes/link-commit/v2";
const CHECK_LABEL = "kynotes/link-check/v2";
const SIGN_LABEL = "kynotes/link/v3/sender";
const LINK_VERSION = 3;
/** v3 | xwing.Seal(identity encoding) | HybridSig; both classical and PQ identities can be linked. */
export const LINK_BUNDLE_BYTES = 1 + 1137 + PQ_PRIVATE_BYTES + HYBRID_SIGNATURE_BYTES;
const encoder = new TextEncoder();
export type LinkContext = { userID: string; requestID: string; identityDeviceID: string; approverKey: Uint8Array; newcomerKey: Uint8Array };
function linkKey(key: Uint8Array): Uint8Array {
  if (!isPQPublic(key)) throw new Error("invalid link key");
  return key;
}
const liveKeys = new WeakSet<Identity>();
/** A fresh one-time X-Wing and HybridSig pair, held only until discardLinkKey. */
export function newLinkKey(): Identity {
  const key = generatePQIdentityReady(); liveKeys.add(key); return key;
}
export function discardLinkKey(key: Identity): void { key.privateKey.fill(0); liveKeys.delete(key); }
export const isLiveLinkKey = (key: Identity): boolean => liveKeys.has(key);
export const linkCommitment = (newcomerKey: Uint8Array): Uint8Array => sha256(concat(encoder.encode(COMMIT_LABEL),linkKey(newcomerKey)));
/** Full keys, including every byte of both X-Wing keys and the sender verification key. */
export function checkCode(userID: string, requestID: string, approverKey: Uint8Array, newcomerKey: Uint8Array): string {
  const digest = sha256(concat(encoder.encode(CHECK_LABEL),idBytes("usr",userID),idBytes("lnk",requestID),linkKey(approverKey),linkKey(newcomerKey)));
  const digits = String(new DataView(digest.buffer,digest.byteOffset,4).getUint32(0) % 1_000_000).padStart(6,"0");
  return `${digits.slice(0,3)} ${digits.slice(3)}`;
}
const linkInfo = (c: LinkContext) => concat(encoder.encode(LINK_LABEL),idBytes("usr",c.userID),idBytes("lnk",c.requestID),idBytes("dev",c.identityDeviceID),linkKey(c.approverKey),linkKey(c.newcomerKey));
export async function sealLinkBundle(identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext): Promise<Uint8Array> {
  if ((identityPrivateKey.length !== 32 && identityPrivateKey.length !== PQ_PRIVATE_BYTES) || !sameBytes(approver.publicKey,context.approverKey)) throw new Error("invalid link input");
  const pq = await loadPQ(), ctx = linkInfo(context);
  const sealed = result(pq.xwingSeal(context.newcomerKey.subarray(33,33+XWING_PUBLIC_BYTES),ctx,ctx,identityPrivateKey));
  const unsigned = concat(Uint8Array.of(LINK_VERSION),sealed);
  const sig = result(pq.hybridsigSign(approver.privateKey.subarray(65,97),approver.privateKey.subarray(97,129),SIGN_LABEL,concat(ctx,unsigned)));
  return concat(unsigned,sig);
}
export type LinkRefusal = "format" | "newcomer-key" | "aead";
const refused = (reason: LinkRefusal) => new Error(`link bundle refused: ${reason}`);
export async function openLinkBundle(bundle: Uint8Array, newcomer: Identity, context: LinkContext): Promise<Uint8Array> {
  const legacySize = LINK_BUNDLE_BYTES - PQ_PRIVATE_BYTES + 32;
  if ((bundle.length !== LINK_BUNDLE_BYTES && bundle.length !== legacySize) || bundle[0] !== LINK_VERSION || !isPQPublic(context.approverKey)) throw refused("format");
  if (!sameBytes(newcomer.publicKey,context.newcomerKey)) throw refused("newcomer-key");
  const pq = await loadPQ(), ctx = linkInfo(context), unsigned = bundle.subarray(0,bundle.length-HYBRID_SIGNATURE_BYTES);
  try {
    result(pq.hybridsigVerify(context.approverKey.subarray(33+XWING_PUBLIC_BYTES),SIGN_LABEL,concat(ctx,unsigned),bundle.subarray(unsigned.length)));
    return result(pq.xwingOpen(newcomer.privateKey.subarray(33,65),ctx,ctx,unsigned.subarray(1)));
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
