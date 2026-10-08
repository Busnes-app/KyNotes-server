import { approveLinkRequest, collectLinkRequest, createComment, createUpload, finalizeUpload, saveObject, updateContainer, uploadChunk, type LinkState } from "./api";
import { base64 } from "./crypto";
import { queuedSaveStep } from "./drain";
import { floorOf } from "./floors";
import type { ReportedContainer, WriteKey } from "./keyring";
import { isLiveLinkKey, isTypedCheckCodeConfirmation, type CheckCodeConfirmation } from "./linking";
import type { Identity } from "./teamKeys";

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
 * The one gate in front of every ciphertext upload: right before the
 * request, the sealing generation must be this tab's current write generation under the tab-wide
 * floor (queuedSaveStep "send"). Otherwise it throws KeysWaitingError and nothing is sent.
 */
export function sendCiphertext(sealed: Sealed): void {
  const write = currentWrite?.(sealed.container);
  if (queuedSaveStep(floorOf(sealed.container.id), sealed.generation, write) !== "send") throw new KeysWaitingError();
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

/** A device-link bundle leaves only after the user typed the newcomer's check code for that request (confirmTypedCheckCode). */
export function sendLinkBundle(confirmation: CheckCodeConfirmation, requestID: string, bundle: Uint8Array): Promise<void> {
  if (!isTypedCheckCodeConfirmation(confirmation, requestID)) throw new Error("Compare the check codes on both screens first.");
  return approveLinkRequest(requestID, base64(bundle));
}

/** Collecting deletes an approved bundle: only an attempt still holding its one-time key may collect. */
export function collectLinkBundle(key: Identity, requestID: string): Promise<LinkState> {
  if (!isLiveLinkKey(key)) throw new Error("This link attempt ended. Start again on both browsers.");
  return collectLinkRequest(requestID);
}
