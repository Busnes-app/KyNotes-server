import { decryptObject, encryptNote, type KeyRef } from "./crypto";
import { legacyRow, openFirst, readKeys, WAITING_GENERATION, type KeyedContainer, type KeyFloor, type Keyring, type WriteKey } from "./keyring";
import type { PendingSave } from "./storage";

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
