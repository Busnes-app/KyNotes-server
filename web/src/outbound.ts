import { createComment, createUpload, finalizeUpload, saveObject, updateContainer, uploadChunk } from "./api";
import { queuedSaveStep } from "./drain";
import { floorOf } from "./floors";
import type { ReportedContainer, WriteKey } from "./keyring";

/** Ciphertext about to leave: the container it was sealed for and the generation it was sealed at. */
export type Sealed = { container: ReportedContainer; generation: number };

export class KeysWaitingError extends Error {
  constructor() {
    super("This notebook's keys changed or are not shared yet; the change stays on this device until they are.");
    this.name = "KeysWaitingError";
  }
}

/** The mounted workspace's writeKeyFor; none mounted, nothing is sent. */
let currentWrite: ((container: ReportedContainer) => WriteKey | undefined) | undefined;
export function setWriteKeySource(source: (container: ReportedContainer) => WriteKey | undefined): () => void {
  currentWrite = source;
  return () => { if (currentWrite === source) currentWrite = undefined; };
}

/**
 * The one gate in front of every container-key or login-key ciphertext upload: right before the
 * request, the sealing generation must be this tab's current write generation under the tab-wide
 * floor (queuedSaveStep "send"). Otherwise it throws KeysWaitingError and nothing is sent.
 */
export function sendCiphertext(sealed: Sealed): void {
  const write = currentWrite?.(sealed.container);
  if (queuedSaveStep(sealed.container, floorOf(sealed.container.id), sealed.generation, write) !== "send") throw new KeysWaitingError();
}

// main.tsx reaches these API calls only through the wrappers below (outbound.test.ts).
export const sendObject = (sealed: Sealed, objectID: string, bytes: Uint8Array, baseVersion: number) => {
  sendCiphertext(sealed);
  return saveObject(objectID, bytes, baseVersion, sealed.generation);
};
export const sendContainerName = (sealed: Sealed, metaCiphertext: string, baseVersion: number) => {
  sendCiphertext(sealed);
  return updateContainer(sealed.container.id, metaCiphertext, baseVersion, sealed.generation);
};
export const sendComment = (sealed: Sealed, objectID: string, bodyCiphertext: string) => {
  sendCiphertext(sealed);
  return createComment(objectID, bodyCiphertext, sealed.generation);
};
export const sendUploadStart = (sealed: Sealed, declaredBytes: number, expectedDigest: string) => {
  sendCiphertext(sealed);
  return createUpload(sealed.container.id, declaredBytes, expectedDigest);
};
export const sendUploadChunk = (sealed: Sealed, uploadID: string, index: number, bytes: Uint8Array) => {
  sendCiphertext(sealed);
  return uploadChunk(uploadID, index, bytes);
};
export const sendUploadFinal = (sealed: Sealed, uploadID: string, metadataCiphertext: string) => {
  sendCiphertext(sealed);
  return finalizeUpload(uploadID, metadataCiphertext, sealed.generation);
};
