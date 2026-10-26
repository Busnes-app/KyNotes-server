import { base64, decryptAttachment, decryptAttachmentMetadata, encryptAttachment, encryptAttachmentMetadata, encryptNote, fromBase64, openObject, type KeyRef } from "./crypto";
import { openFirst, ownCopyKeys, type KeyedContainer, type KeyFloor, type Keyring, type WriteKey } from "./keyring";
import type { PendingSave, PendingUpload } from "./storage";

/** What the queue drain may do with an entry sealed at generation: send it only when it is sealed for the current write key; otherwise re-seal it under write, or wait while there is no write key. */
export function queuedSaveStep(floor: KeyFloor | undefined, generation: number | undefined, write: WriteKey | undefined): "send" | "reseal" | "wait" {
  if (!write || !floor) return "wait";
  return generation === write.generation ? "send" : "reseal";
}

/**
 * The queued save as it may be uploaded now: itself, a copy re-sealed under write, or undefined to keep it
 * queued. Stale ciphertext is never returned, nor the v1 form an older build queued (re-sealed as v2).
 * The entry opens with ownCopyKeys: its own generation's key, or the waiting key for a waiting edit.
 * The server cannot write the queue, so v1 is accepted here.
 */
export async function readyToSend(item: PendingSave, container: KeyedContainer, floor: KeyFloor | undefined, write: WriteKey | undefined, ring: Keyring, waiting?: KeyRef): Promise<PendingSave | undefined> {
  const step = queuedSaveStep(floor, item.keyGeneration, write);
  if (step === "wait") return undefined;
  const opened = await openFirst(ownCopyKeys(container, ring, item.keyGeneration, floor!, waiting), (key) => openObject(key, item.containerID, item.id, item.payload, true));
  if (step === "send" && !opened.v1) return item;
  if (!opened.payload) return undefined;
  return { ...item, payload: await encryptNote(write!.key, item.containerID, item.id, opened.payload), keyGeneration: write!.generation };
}

export type AttachmentFile = { name: string; type: string; size: number };
/** An attachment for pageID sealed for write: its payload, encrypted metadata and generation. */
export async function sealAttachment(write: WriteKey, containerID: string, pageID: string, plaintext: Uint8Array, file: AttachmentFile) {
  return { payload: await encryptAttachment(write.key, containerID, pageID, plaintext), metadataCiphertext: base64(await encryptAttachmentMetadata(write.key, containerID, pageID, file)), keyGeneration: write.generation };
}

/**
 * What resuming a pending attachment may do before any chunk leaves: stream it as sealed, re-seal
 * it (payload and metadata, opened with ownCopyKeys: this browser wrote it, from a file the user
 * picked) into a new upload, or wait. An older build's v1 upload is re-sealed as v2 too.
 */
export async function attachmentStep(job: PendingUpload, container: KeyedContainer, floor: KeyFloor | undefined, write: WriteKey | undefined, ring: Keyring, waiting?: KeyRef): Promise<{ kind: "send" } | { kind: "wait" } | { kind: "reseal"; plaintext: Uint8Array; file: AttachmentFile }> {
  const step = queuedSaveStep(floor, job.keyGeneration, write);
  if (step === "wait") return { kind: step };
  const keys = ownCopyKeys(container, ring, job.keyGeneration, floor!, waiting);
  // Opened v2-only first: a send needs no plaintext, only the proof it is not v1.
  const v2 = step === "send" && (await openFirst(keys, (key) => decryptAttachmentMetadata(key, job.containerID, job.objectID, fromBase64(job.metadataCiphertext), false)).then(() => true, () => false));
  if (v2) return { kind: "send" };
  const plaintext = await openFirst(keys, (key) => decryptAttachment(key, job.containerID, job.objectID, job.payload, true));
  const file = await openFirst(keys, (key) => decryptAttachmentMetadata(key, job.containerID, job.objectID, fromBase64(job.metadataCiphertext), true));
  return { kind: "reseal", plaintext, file };
}

/** A failed queue write: the edit is kept nowhere but this tab. */
export const NOT_SAVED = "Not saved: neither the server nor this browser kept this edit. It exists only in this tab; keep the tab open and copy the edit.";
export const notSaved = (): never => { throw new Error(NOT_SAVED); };
/** A version conflict: the draft is preserved only when the local cache write succeeded. */
export const noteConflictMessage = (uncached: boolean) => uncached
  ? "This note changed on another device, and this browser could not keep a local copy of your edit. It exists only in this tab: copy or export it now, before closing or reloading."
  : "This note changed on another device. Your encrypted draft is preserved locally; review the conflict before saving again.";
