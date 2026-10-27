import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseObjectPayload, type Legacy, type ObjectPayload } from "./pages";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export { sha256 };
/** HKDF-SHA256 (RFC 5869), synchronous for derivations that cannot await WebCrypto. */
export const hkdfSha256 = (ikm: Uint8Array, length: number, salt: Uint8Array, info: Uint8Array) => hkdf(sha256, ikm, salt, info, length);

export const NEEDS_HTTPS = "KyNotes needs a secure connection. Open it over HTTPS, or on localhost.";
/** WebCrypto exists only in secure contexts (HTTPS, localhost); there is no fallback. */
export const hasWebCrypto = () => typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function" && typeof crypto.subtle?.importKey === "function";
function subtle(): SubtleCrypto {
  if (!hasWebCrypto()) throw new Error(NEEDS_HTTPS);
  return crypto.subtle;
}

function getRandomValues(buffer: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  if (!hasWebCrypto()) throw new Error(NEEDS_HTTPS);
  return crypto.getRandomValues(buffer);
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
export { fromBase64, base64 };

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

export async function digestSha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", buffer(data)));
}

export async function digestSha256Hex(data: Uint8Array): Promise<string> {
  const hash = await digestSha256(data);
  return [...hash].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export type LoginKeys = { authSecret: string; userKEK: Uint8Array };

/** PBKDF2-HMAC-SHA256 to 32 bytes. */
async function pbkdf2Bits(input: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await subtle().importKey("raw", buffer(input), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "PBKDF2", salt: buffer(salt), iterations, hash: "SHA-256" }, key, 256));
}

const stretchPassword = (password: string, salt: string, iterations: number) => pbkdf2Bits(encoder.encode(password), fromBase64(salt), iterations);

/** Fixed, never read from the server: a copy labelled with fewer iterations is refused, not opened. */
export const RECOVERY_ITERATIONS = 600_000;
const RECOVERY_KEK_LABEL = encoder.encode("kynotes/recovery-kek/v1");
/** The recovery code's KEK: PBKDF2 over the code's 16 random bytes (recovery.ts), salt = label ‖ salt(16). */
export function deriveRecoveryKEK(secret: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const labelled = new Uint8Array(RECOVERY_KEK_LABEL.length + salt.length);
  labelled.set(RECOVERY_KEK_LABEL);
  labelled.set(salt, RECOVERY_KEK_LABEL.length);
  return pbkdf2Bits(secret, labelled, RECOVERY_ITERATIONS);
}

/** What every password write uses, and the default floor: fewer, from a malicious server, are refused. */
export const LOGIN_ITERATIONS = 600_000;
/** The server's MinLoginIterations: only an account this browser has not pinned may sign in at it, to be upgraded (loginUpgrade.ts). */
export const LEGACY_LOGIN_ITERATIONS = 100_000;

/** One PBKDF2 pass, two HKDF labels: the server sees authSecret, never userKEK. */
export async function deriveLoginKeys(password: string, salt: string, iterations: number, floor = LOGIN_ITERATIONS): Promise<LoginKeys> {
  if (!Number.isSafeInteger(iterations) || iterations < floor) throw new Error("The server asked for too few password iterations; refusing to sign in.");
  const stretched = await stretchPassword(password, salt, iterations);
  const label = (info: string) => hkdfSha256(stretched, 32, new Uint8Array(0), encoder.encode(info));
  const authSecret = [...label("kynotes/auth/v1")].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return { authSecret, userKEK: label("kynotes/user-kek/v1") };
}

export async function deriveAuthSecret(password: string, salt: string, iterations: number, floor = LOGIN_ITERATIONS): Promise<string> {
  return (await deriveLoginKeys(password, salt, iterations, floor)).authSecret;
}

export function randomLoginSalt(): string {
  const bytes = getRandomValues(new Uint8Array(16));
  return base64(bytes);
}

const V2 = 2;
const CONTENT_V2 = "kynotes/content/v2";

/** WebCrypto takes 16- and 24-byte AES keys too; every KyNotes key is AES-256. */
function importAES256(keyBytes: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (keyBytes.byteLength !== 32) throw new Error("Refusing a content key that is not 256 bits");
  return subtle().importKey("raw", buffer(keyBytes), "AES-GCM", false, [usage]);
}

/** nonce(12) ‖ AES-256-GCM; with aad, the v2 form 0x02 ‖ nonce(12) ‖ AES-256-GCM(…, aad). */
async function encryptWithKey(keyBytes: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const iv = getRandomValues(new Uint8Array(12));
  const key = await importAES256(keyBytes, "encrypt");
  const ciphertext = await subtle().encrypt({ name: "AES-GCM", iv: buffer(iv), ...(aad && { additionalData: buffer(aad) }) }, key, buffer(plaintext));
  const head = aad ? 1 : 0;
  const result = new Uint8Array(head + iv.byteLength + ciphertext.byteLength);
  if (aad) result[0] = V2;
  result.set(iv, head);
  result.set(new Uint8Array(ciphertext), head + iv.byteLength);
  return result;
}

async function decryptWithKey(keyBytes: Uint8Array, bytes: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const head = aad ? 1 : 0;
  if (bytes.byteLength < head + 28) throw new Error("Ciphertext too short");
  const key = await importAES256(keyBytes, "decrypt");
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: buffer(bytes.slice(head, head + 12)), ...(aad && { additionalData: buffer(aad) }) }, key, buffer(bytes.slice(head + 12))));
  } catch (e) {
    if (e instanceof DOMException && e.name === "OperationError") throw new Error("Unable to decrypt: invalid key or tampered ciphertext");
    throw e;
  }
}

declare const contentKey: unique symbol;
/** A container key, or the identity's waiting key: the only input content subkeys derive from. Made only in keyring.ts. */
export type KeyRef = Uint8Array & { readonly [contentKey]: true };
export function asContentKey(bytes: Uint8Array): KeyRef {
  if (bytes.length !== 32) throw new Error("invalid content key");
  return bytes as KeyRef;
}

function deriveObjectKeyBytes(key: KeyRef, containerID: string, info: string): Uint8Array {
  if (key.length !== 32) throw new Error("invalid content key");
  return hkdfSha256(key, 32, encoder.encode(containerID), encoder.encode(info));
}

/**
 * Content v2: 0x02 ‖ nonce(12) ‖ AES-256-GCM(HKDF(key, containerID, "kynotes/content/v2"), AAD).
 * The bound ID is the object for objects, the page for comments and attachments, the container for its meta.
 */
type ContentKind = "object" | "comment" | "attachment" | "attachment-meta" | "container-meta";
/** Each field as uint16 big-endian length ‖ UTF-8 bytes: label, container, bound ID, kind. */
function contentAAD(containerID: string, boundID: string, kind: ContentKind): Uint8Array {
  if (!boundID) throw new Error("content needs the ID it is bound to");
  const fields = [CONTENT_V2, containerID, boundID, kind].map((field) => encoder.encode(field));
  const aad = new Uint8Array(fields.reduce((length, field) => length + 2 + field.length, 0));
  let at = 0;
  for (const field of fields) {
    if (field.length > 0xffff) throw new Error("content ID too long");
    new DataView(aad.buffer).setUint16(at, field.length);
    aad.set(field, at + 2);
    at += 2 + field.length;
  }
  return aad;
}

const sealContent = (key: KeyRef, containerID: string, boundID: string, kind: ContentKind, plaintext: Uint8Array) =>
  encryptWithKey(deriveObjectKeyBytes(key, containerID, CONTENT_V2), plaintext, contentAAD(containerID, boundID, kind));

/**
 * Opens v2 bound to (containerID, boundID, kind). The unbound v1 form under v1Label is tried only when v1
 * allows it (before the notebook's migration marker; local copies), also after a failed v2 try: a v1
 * blob's random first byte may be 0x02.
 */
async function openContent(key: KeyRef, containerID: string, boundID: string, kind: ContentKind, v1Label: string, bytes: Uint8Array, v1: boolean): Promise<{ plaintext: Uint8Array; v1: boolean }> {
  if (bytes[0] === V2) {
    try {
      return { plaintext: await decryptWithKey(deriveObjectKeyBytes(key, containerID, CONTENT_V2), bytes, contentAAD(containerID, boundID, kind)), v1: false };
    } catch (error) {
      if (!v1) throw error;
    }
  }
  if (!v1) throw new Error("Unable to decrypt: an older format this notebook no longer accepts, or tampered ciphertext");
  return { plaintext: await decryptWithKey(deriveObjectKeyBytes(key, containerID, v1Label), bytes), v1: true };
}

const openJSON = async (...args: Parameters<typeof openContent>): Promise<unknown> => JSON.parse(decoder.decode((await openContent(...args)).plaintext));

/** objects: 2 is the migration marker: every object is v2, and v1 is refused from then on. */
export async function encryptContainerMeta(key: KeyRef, containerID: string, name: string, migrated = false): Promise<Uint8Array> {
  return sealContent(key, containerID, containerID, "container-meta", encoder.encode(JSON.stringify(migrated ? { name, objects: 2 } : { name })));
}

/** objects is 2 only for a v2 meta carrying the marker. */
export async function decryptContainerMeta(key: KeyRef, containerID: string, bytes: Uint8Array, v1: boolean): Promise<{ name: string; objects?: 2 }> {
  if (bytes.byteLength < 13) throw new Error("Encrypted workspace metadata is too short");
  const opened = await openContent(key, containerID, containerID, "container-meta", "kynotes/container-meta/v1", bytes, v1);
  const result = JSON.parse(decoder.decode(opened.plaintext)) as { name?: unknown; objects?: unknown };
  if (typeof result.name !== "string") throw new Error("Invalid workspace metadata");
  return !opened.v1 && result.objects === 2 ? { name: result.name, objects: 2 } : { name: result.name };
}

/** Comments are bound to the page they are on (their IDs are minted after sealing). */
export const encryptComment = (key: KeyRef, containerID: string, pageID: string, body: string, section = "") =>
  sealContent(key, containerID, pageID, "comment", encoder.encode(JSON.stringify({ body, section })));

export async function decryptComment(key: KeyRef, containerID: string, pageID: string, bytes: Uint8Array, v1: boolean): Promise<{ body: string; section?: string }> {
  return openJSON(key, containerID, pageID, "comment", "kynotes/comment/v1", bytes, v1) as Promise<{ body: string; section?: string }>;
}

/** Attachments are bound to the page they are uploaded for (PendingUpload.objectID). */
export const encryptAttachmentMetadata = (key: KeyRef, containerID: string, pageID: string, metadata: { name: string; type: string; size: number }) =>
  sealContent(key, containerID, pageID, "attachment-meta", encoder.encode(JSON.stringify(metadata)));

export async function decryptAttachmentMetadata(key: KeyRef, containerID: string, pageID: string, bytes: Uint8Array, v1: boolean): Promise<{ name: string; type: string; size: number }> {
  return openJSON(key, containerID, pageID, "attachment-meta", "kynotes/attachment-meta/v1", bytes, v1) as Promise<{ name: string; type: string; size: number }>;
}

export const encryptAttachment = (key: KeyRef, containerID: string, pageID: string, plaintext: Uint8Array) =>
  sealContent(key, containerID, pageID, "attachment", plaintext);

export async function decryptAttachment(key: KeyRef, containerID: string, pageID: string, bytes: Uint8Array, v1: boolean): Promise<Uint8Array> {
  // v1 attachment bytes shared the object label.
  return (await openContent(key, containerID, pageID, "attachment", "kynotes/object/v1", bytes, v1)).plaintext;
}

export type NotePayload = { title: string; body: string };

/** Pages, sections and groups are bound to their object ID (minted before anything is sealed). */
export async function encryptNote(key: KeyRef, containerID: string, objectID: string, note: NotePayload | ObjectPayload): Promise<Uint8Array> {
  return sealContent(key, containerID, objectID, "object", encoder.encode(JSON.stringify(note)));
}

export async function decryptNote(key: KeyRef, containerID: string, objectID: string, bytes: Uint8Array, v1: boolean): Promise<NotePayload> {
  if (bytes.byteLength < 13) throw new Error("Encrypted note is too short");
  return openJSON(key, containerID, objectID, "object", "kynotes/object/v1", bytes, v1) as Promise<NotePayload>;
}

/** Any object (page, section or group): payload undefined when not a valid one; v1 when it was read in the older form. */
export async function openObject(key: KeyRef, containerID: string, objectID: string, bytes: Uint8Array, v1: boolean): Promise<{ payload: ObjectPayload | undefined; v1: boolean }> {
  if (bytes.byteLength < 13) throw new Error("Encrypted data is too short");
  const opened = await openContent(key, containerID, objectID, "object", "kynotes/object/v1", bytes, v1);
  return { payload: parseObjectPayload(JSON.parse(decoder.decode(opened.plaintext))), v1: opened.v1 };
}

export const decryptObject = async (...args: Parameters<typeof openObject>) => (await openObject(...args)).payload;

/** The pin ID of an attachment's metadata; the attachment's own ID pins its bytes. */
export const metaPin = (attachmentID: string) => `${attachmentID}/meta`;

/**
 * Whether a v1 child (comment, attachment bytes, attachment metadata under metaPin) of page may open:
 * before the marker, while the page has no legacy field; otherwise only a child pinned there by the
 * SHA-256 of its ciphertext. A page this read does not know accepts none.
 */
export async function legacyChildOpens(page: { legacy?: Legacy } | undefined, migrated: boolean, childID: string, ciphertext: Uint8Array): Promise<boolean> {
  if (!page) return false;
  if (!page.legacy) return !migrated;
  return Object.hasOwn(page.legacy, childID) && page.legacy[childID] === (await digestSha256Hex(ciphertext));
}

export async function encryptSharePayload(note: NotePayload): Promise<{ ciphertext: Uint8Array; key: string }> {
  const rawKey = getRandomValues(new Uint8Array(32));
  const sealed = await encryptWithKey(rawKey, encoder.encode(JSON.stringify(note)));
  return { ciphertext: sealed, key: base64url(rawKey) };
}

export async function decryptSharePayload(bytes: Uint8Array, encodedKey: string): Promise<NotePayload> {
  const keyBytes = base64urlDecode(encodedKey);
  const plaintext = await decryptWithKey(keyBytes, bytes);
  return JSON.parse(decoder.decode(plaintext)) as NotePayload;
}

function base64url(bytes: Uint8Array): string {
  return base64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64urlDecode(value: string): Uint8Array {
  return fromBase64(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4));
}
