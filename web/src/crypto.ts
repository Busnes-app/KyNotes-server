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

async function stretchPassword(password: string, salt: string, iterations: number): Promise<Uint8Array> {
  const rawSalt = fromBase64(salt);
  if (hasNativeSubtle()) {
    try {
      const passwordKey = await crypto.subtle.importKey("raw", buffer(encoder.encode(password)), "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: buffer(rawSalt), iterations, hash: "SHA-256" }, passwordKey, 256));
    } catch {
      // Fall through to fallback
    }
  }
  return pbkdf2Sha256(encoder.encode(password), rawSalt, iterations, 32);
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

function deriveObjectKeyBytes(authSecret: string, containerID: string, info: string): Uint8Array {
  const ikm = hexBytes(authSecret);
  const salt = encoder.encode(containerID);
  return hkdfSha256(ikm, 32, salt, encoder.encode(info));
}

export async function encryptContainerMeta(authSecret: string, containerID: string, name: string): Promise<Uint8Array> {
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/container-meta/v1");
  return encryptWithKey(key, encoder.encode(JSON.stringify({ name })));
}

export async function decryptContainerMeta(authSecret: string, containerID: string, bytes: Uint8Array): Promise<{ name: string }> {
  if (bytes.byteLength < 13) throw new Error("Encrypted workspace metadata is too short");
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/container-meta/v1");
  const plaintext = await decryptWithKey(key, bytes);
  const result = JSON.parse(decoder.decode(plaintext)) as { name?: unknown };
  if (typeof result.name !== "string") throw new Error("Invalid workspace metadata");
  return { name: result.name };
}

export const encryptComment = (authSecret: string, containerID: string, body: string, section = "") =>
  encryptWithInfo(authSecret, containerID, "kynotes/comment/v1", { body, section });

export async function decryptComment(authSecret: string, containerID: string, bytes: Uint8Array): Promise<{ body: string; section?: string }> {
  return decryptWithInfo(authSecret, containerID, "kynotes/comment/v1", bytes) as Promise<{ body: string; section?: string }>;
}

export const encryptAttachmentMetadata = (authSecret: string, containerID: string, metadata: { name: string; type: string; size: number }) =>
  encryptWithInfo(authSecret, containerID, "kynotes/attachment-meta/v1", metadata);

export async function decryptAttachmentMetadata(authSecret: string, containerID: string, bytes: Uint8Array): Promise<{ name: string; type: string; size: number }> {
  return decryptWithInfo(authSecret, containerID, "kynotes/attachment-meta/v1", bytes) as Promise<{ name: string; type: string; size: number }>;
}

export async function encryptAttachment(authSecret: string, containerID: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/object/v1");
  return encryptWithKey(key, plaintext);
}

export async function decryptAttachment(authSecret: string, containerID: string, bytes: Uint8Array): Promise<Uint8Array> {
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/object/v1");
  return decryptWithKey(key, bytes);
}

async function encryptWithInfo(authSecret: string, containerID: string, info: string, value: unknown): Promise<Uint8Array> {
  const key = deriveObjectKeyBytes(authSecret, containerID, info);
  return encryptWithKey(key, encoder.encode(JSON.stringify(value)));
}

async function decryptWithInfo(authSecret: string, containerID: string, info: string, bytes: Uint8Array): Promise<unknown> {
  if (bytes.byteLength < 13) throw new Error("Encrypted data is too short");
  const key = deriveObjectKeyBytes(authSecret, containerID, info);
  const plaintext = await decryptWithKey(key, bytes);
  return JSON.parse(decoder.decode(plaintext));
}

export type NotePayload = { title: string; body: string };

export async function encryptNote(authSecret: string, containerID: string, note: NotePayload | ObjectPayload): Promise<Uint8Array> {
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/object/v1");
  return encryptWithKey(key, encoder.encode(JSON.stringify(note)));
}

export async function decryptNote(authSecret: string, containerID: string, bytes: Uint8Array): Promise<NotePayload> {
  if (bytes.byteLength < 13) throw new Error("Encrypted note is too short");
  const key = deriveObjectKeyBytes(authSecret, containerID, "kynotes/object/v1");
  const plaintext = await decryptWithKey(key, bytes);
  return JSON.parse(decoder.decode(plaintext)) as NotePayload;
}

/** Decrypts any object (page or section); undefined when the plaintext is not a valid payload. */
export async function decryptObject(authSecret: string, containerID: string, bytes: Uint8Array): Promise<ObjectPayload | undefined> {
  return parseObjectPayload(await decryptWithInfo(authSecret, containerID, "kynotes/object/v1", bytes));
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
