import { parseObjectPayload, type ObjectPayload } from "./pages";
import {
  aes256GcmDecrypt,
  aes256GcmEncrypt,
  hkdfSha256,
  pbkdf2Sha256,
  sha256,
} from "./fallbackCrypto";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function getRandomValues(buffer: Uint8Array): Uint8Array {
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(buffer as any);
    return buffer;
  }
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }
  return buffer;
}

function hasNativeSubtle(): boolean {
  return (
    typeof crypto !== "undefined" &&
    typeof crypto.subtle !== "undefined" &&
    typeof crypto.subtle.importKey === "function"
  );
}

function hexBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return bytes;
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
  if (hasNativeSubtle()) {
    try {
      const res = await crypto.subtle.digest("SHA-256", buffer(data));
      return new Uint8Array(res);
    } catch {
      // Fall through to fallback
    }
  }
  return sha256(data);
}

export async function digestSha256Hex(data: Uint8Array): Promise<string> {
  const hash = await digestSha256(data);
  return [...hash].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export type LoginKeys = { authSecret: string; userKEK: Uint8Array };

/** PBKDF2-HMAC-SHA256 to 32 bytes: WebCrypto where it exists, the pure fallback on plain-HTTP origins. */
async function pbkdf2Bits(input: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  if (hasNativeSubtle()) {
    try {
      const key = await crypto.subtle.importKey("raw", buffer(input), "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: buffer(salt), iterations, hash: "SHA-256" }, key, 256));
    } catch {
      // Fall through to fallback
    }
  }
  return pbkdf2Sha256(input, salt, iterations, 32);
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

/** One PBKDF2 pass, two HKDF labels: the server sees authSecret, never userKEK. */
export async function deriveLoginKeys(password: string, salt: string, iterations: number): Promise<LoginKeys> {
  const stretched = await stretchPassword(password, salt, iterations);
  const label = (info: string) => hkdfSha256(stretched, 32, new Uint8Array(0), encoder.encode(info));
  const authSecret = [...label("kynotes/auth/v1")].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return { authSecret, userKEK: label("kynotes/user-kek/v1") };
}

export async function deriveAuthSecret(password: string, salt: string, iterations: number): Promise<string> {
  return (await deriveLoginKeys(password, salt, iterations)).authSecret;
}

export function randomLoginSalt(): string {
  const bytes = getRandomValues(new Uint8Array(16));
  return base64(bytes);
}

async function encryptWithKey(keyBytes: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = getRandomValues(new Uint8Array(12));
  if (hasNativeSubtle()) {
    try {
      const key = await crypto.subtle.importKey("raw", buffer(keyBytes), "AES-GCM", false, ["encrypt"]);
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, key, buffer(plaintext));
      const result = new Uint8Array(iv.byteLength + ciphertext.byteLength);
      result.set(iv);
      result.set(new Uint8Array(ciphertext), iv.byteLength);
      return result;
    } catch {
      // Fall through to fallback
    }
  }
  const ciphertextAndTag = aes256GcmEncrypt(keyBytes, iv, plaintext);
  const result = new Uint8Array(iv.byteLength + ciphertextAndTag.byteLength);
  result.set(iv);
  result.set(ciphertextAndTag, iv.byteLength);
  return result;
}

async function decryptWithKey(keyBytes: Uint8Array, bytes: Uint8Array): Promise<Uint8Array> {
  if (bytes.byteLength < 28) throw new Error("Ciphertext too short");
  const iv = bytes.slice(0, 12);
  const ciphertextAndTag = bytes.slice(12);

  if (hasNativeSubtle()) {
    try {
      const key = await crypto.subtle.importKey("raw", buffer(keyBytes), "AES-GCM", false, ["decrypt"]);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(iv) }, key, buffer(ciphertextAndTag));
      return new Uint8Array(plaintext);
    } catch (e) {
      if (e instanceof DOMException && e.name === "OperationError") {
        throw new Error("Unable to decrypt: invalid key or tampered ciphertext");
      }
      // Fall through to fallback if subtle failed unexpectedly
    }
  }

  return aes256GcmDecrypt(keyBytes, iv, ciphertextAndTag);
}

/** HKDF input for content subkeys: a container key (CK) or, for legacy rows, the login secret's bytes. */
export type KeyRef = Uint8Array;

/** The pre-team-keys content key input. Only legacy reads and personal notebooks use it. */
export const legacyKeyRef = (authSecret: string): KeyRef => hexBytes(authSecret);

function deriveObjectKeyBytes(key: KeyRef, containerID: string, info: string): Uint8Array {
  if (key.length !== 32) throw new Error("invalid content key");
  return hkdfSha256(key, 32, encoder.encode(containerID), encoder.encode(info));
}

export async function encryptContainerMeta(key: KeyRef, containerID: string, name: string): Promise<Uint8Array> {
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/container-meta/v1");
  return encryptWithKey(subkey, encoder.encode(JSON.stringify({ name })));
}

export async function decryptContainerMeta(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<{ name: string }> {
  if (bytes.byteLength < 13) throw new Error("Encrypted workspace metadata is too short");
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/container-meta/v1");
  const plaintext = await decryptWithKey(subkey, bytes);
  const result = JSON.parse(decoder.decode(plaintext)) as { name?: unknown };
  if (typeof result.name !== "string") throw new Error("Invalid workspace metadata");
  return { name: result.name };
}

export const encryptComment = (key: KeyRef, containerID: string, body: string, section = "") =>
  encryptWithInfo(key, containerID, "kynotes/comment/v1", { body, section });

export async function decryptComment(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<{ body: string; section?: string }> {
  return decryptWithInfo(key, containerID, "kynotes/comment/v1", bytes) as Promise<{ body: string; section?: string }>;
}

export const encryptAttachmentMetadata = (key: KeyRef, containerID: string, metadata: { name: string; type: string; size: number }) =>
  encryptWithInfo(key, containerID, "kynotes/attachment-meta/v1", metadata);

export async function decryptAttachmentMetadata(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<{ name: string; type: string; size: number }> {
  return decryptWithInfo(key, containerID, "kynotes/attachment-meta/v1", bytes) as Promise<{ name: string; type: string; size: number }>;
}

export async function encryptAttachment(key: KeyRef, containerID: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/object/v1");
  return encryptWithKey(subkey, plaintext);
}

export async function decryptAttachment(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<Uint8Array> {
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/object/v1");
  return decryptWithKey(subkey, bytes);
}

async function encryptWithInfo(key: KeyRef, containerID: string, info: string, value: unknown): Promise<Uint8Array> {
  const subkey = deriveObjectKeyBytes(key, containerID, info);
  return encryptWithKey(subkey, encoder.encode(JSON.stringify(value)));
}

async function decryptWithInfo(key: KeyRef, containerID: string, info: string, bytes: Uint8Array): Promise<unknown> {
  if (bytes.byteLength < 13) throw new Error("Encrypted data is too short");
  const subkey = deriveObjectKeyBytes(key, containerID, info);
  const plaintext = await decryptWithKey(subkey, bytes);
  return JSON.parse(decoder.decode(plaintext));
}

export type NotePayload = { title: string; body: string };

export async function encryptNote(key: KeyRef, containerID: string, note: NotePayload | ObjectPayload): Promise<Uint8Array> {
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/object/v1");
  return encryptWithKey(subkey, encoder.encode(JSON.stringify(note)));
}

export async function decryptNote(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<NotePayload> {
  if (bytes.byteLength < 13) throw new Error("Encrypted note is too short");
  const subkey = deriveObjectKeyBytes(key, containerID, "kynotes/object/v1");
  const plaintext = await decryptWithKey(subkey, bytes);
  return JSON.parse(decoder.decode(plaintext)) as NotePayload;
}

/** Decrypts any object (page or section); undefined when the plaintext is not a valid payload. */
export async function decryptObject(key: KeyRef, containerID: string, bytes: Uint8Array): Promise<ObjectPayload | undefined> {
  return parseObjectPayload(await decryptWithInfo(key, containerID, "kynotes/object/v1", bytes));
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
