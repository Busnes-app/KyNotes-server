import { base64, decryptAttachment, decryptAttachmentMetadata, decryptObject, encryptAttachment, encryptAttachmentMetadata, encryptNote, fromBase64, type KeyRef } from "./crypto";
import { legacyRow, openFirst, readKeys, WAITING_GENERATION, type KeyedContainer, type KeyFloor, type Keyring, type WriteKey } from "./keyring";
import type { PendingSave, PendingUpload } from "./storage";

/**
 * What the queue drain may do with an entry sealed at generation: send it only when it is sealed
 * for the current write key (same generation, and never a legacy row of a container this device has
 * seen shared); otherwise re-seal it under write, or wait while there is no write key.
 */
export function queuedSaveStep(container: Pick<KeyedContainer, "sharedGeneration">, floor: KeyFloor | undefined, generation: number | undefined, write: WriteKey | undefined): "send" | "reseal" | "wait" {
  if (!write || !floor) return "wait";
  return generation === write.generation && generation !== WAITING_GENERATION && !legacyRow(container, generation, floor) ? "send" : "reseal";
}

/**
 * The queued save as it may be uploaded now: itself, a copy re-sealed under write (opened with its
 * own generation's key), or undefined to keep it queued. Stale ciphertext is never returned.
 * write is the caller's writeKeyFor(container); floor its current tab-wide floor.
 */
export async function readyToSend(item: PendingSave, container: KeyedContainer, floor: KeyFloor | undefined, write: WriteKey | undefined, ring: Keyring, legacy: KeyRef): Promise<PendingSave | undefined> {
  const step = queuedSaveStep(container, floor, item.keyGeneration, write);
  if (step !== "reseal") return step === "send" ? item : undefined;
  const payload = await openFirst(readKeys(container, ring, legacy, item.keyGeneration, floor!), (key) => decryptObject(key, item.containerID, item.payload));
  if (!payload) return undefined;
  return { ...item, payload: await encryptNote(write!.key, item.containerID, payload), keyGeneration: write!.generation };
}

export type AttachmentFile = { name: string; type: string; size: number };
/** An attachment sealed for write: its payload, encrypted metadata and generation. */
export async function sealAttachment(write: WriteKey, containerID: string, plaintext: Uint8Array, file: AttachmentFile) {
  return { payload: await encryptAttachment(write.key, containerID, plaintext), metadataCiphertext: base64(await encryptAttachmentMetadata(write.key, containerID, file)), keyGeneration: write.generation };
}

/**
 * What resuming a pending attachment may do before any chunk leaves: stream it as sealed, re-seal
 * it (payload and metadata, opened with its own generation's key) into a new upload, or wait.
 */
export async function attachmentStep(job: PendingUpload, container: KeyedContainer, floor: KeyFloor | undefined, write: WriteKey | undefined, ring: Keyring, legacy: KeyRef): Promise<{ kind: "send" } | { kind: "wait" } | { kind: "reseal"; plaintext: Uint8Array; file: AttachmentFile }> {
  const step = queuedSaveStep(container, floor, job.keyGeneration, write);
  if (step !== "reseal") return { kind: step };
  const keys = readKeys(container, ring, legacy, job.keyGeneration, floor!);
  const plaintext = await openFirst(keys, (key) => decryptAttachment(key, job.containerID, job.payload));
  const file = await openFirst(keys, (key) => decryptAttachmentMetadata(key, job.containerID, fromBase64(job.metadataCiphertext)));
  return { kind: "reseal", plaintext, file };
}
