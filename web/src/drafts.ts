import { decryptObject, encryptNote } from "./crypto";
import { notePayload } from "./notes";
import { getQueuedSave, getNote, type PendingSave } from "./storage";
import type { Note } from "./api";
import type { WriteKey } from "./keyring";
import type { PagePayload } from "./pages";

// Compare the entire page, including placement and legacy pins, in a stable field order.
const contents = (page: PagePayload) => JSON.stringify([page.title, page.body, page.section, page.order, page.level, page.legacy]);

export const sameDraftContents = (a: PagePayload,b: PagePayload):boolean => contents(a)===contents(b);

/** Reuse the exact sealed edit on retries, even after a lost response or a reload. */
export async function prepareDraft({owner, containerID, note, write}: {owner: string; containerID: string; note: Note; write: WriteKey}): Promise<PendingSave> {
 const payload = notePayload(note);
 const queued = await getQueuedSave(owner, note.id).catch(() => undefined);
 const cached = await getNote(owner,note.id).catch(() => undefined);
 const previous = cached?.unsent && (!queued || cached.updatedAt > queued.updatedAt) ? {...cached,owner} : queued;
 if (previous && !previous.gone && !previous.previousKey && previous.containerID === containerID && previous.version === note.version && previous.keyGeneration === write.generation) {
  const opened = await decryptObject(write.key, containerID, note.id, previous.payload, true).catch(() => undefined);
  if (opened?.type === "page" && sameDraftContents(opened,payload)) return previous;
 }
 return {owner, id:note.id, containerID, version:note.version, keyGeneration:write.generation, payload:await encryptNote(write.key, containerID, note.id, payload), updatedAt:new Date().toISOString()};
}
