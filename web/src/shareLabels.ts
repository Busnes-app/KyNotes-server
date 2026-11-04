import { decryptShareLabel, encryptShareLabel, type KeyRef, type ShareLabel } from "./crypto";
import { openFirst } from "./keyring";
import { deleteNote, getNote, putNote } from "./storage";

/**
 * Which page a share link shares, kept only in the browser that made it (the server never learns it).
 * The record sits beside the cached pages, under its own key prefix, sealed with the notebook's key
 * as they are, so "Forget this device" and a lost key leave nothing readable.
 */
const cacheID = (linkID: string) => `share:${linkID}`;

export async function keepShareLabel(owner: string, linkID: string, containerID: string, write: { key: KeyRef; generation: number }, label: ShareLabel): Promise<void> {
  await putNote(owner, { id: cacheID(linkID), containerID, version: 0, payload: await encryptShareLabel(write.key, containerID, linkID, label), updatedAt: new Date().toISOString(), keyGeneration: write.generation });
}

/** none: made on another device (or before labels were kept); unreadable: made here, but its notebook's key is gone. */
export async function readShareLabel(owner: string, linkID: string, keysFor: (row: { containerID: string; keyGeneration?: number }) => KeyRef[]): Promise<ShareLabel | "none" | "unreadable"> {
  const row = await getNote(owner, cacheID(linkID)).catch(() => undefined);
  if (!row) return "none";
  return openFirst(keysFor(row), (key) => decryptShareLabel(key, row.containerID, linkID, row.payload)).catch(() => "unreadable" as const);
}

export const forgetShareLabel = (owner: string, linkID: string) => deleteNote(owner, cacheID(linkID)).catch(() => undefined);
