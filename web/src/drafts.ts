import { encryptNote, openObject } from "./crypto";
import { notePayload } from "./notes";
import { getQueuedSave, getNote, recoverDraft, sameDraft, type CachedNote, type PendingSave } from "./storage";
import type { Note } from "./api";
import type { WriteKey } from "./keyring";
import type { ObjectPayload, PagePayload } from "./pages";

// Compare every stored field in a stable order, regardless of property insertion order.
const contents = (value: ObjectPayload) => JSON.stringify(value.type === "page"
  ? [value.type, value.title, value.body, value.section, value.order, value.level, value.legacy]
  : [value.type, value.title, value.color, value.order, value.group]);
export const sameDraftContents = (a: PagePayload, b: PagePayload): boolean => contents(a) === contents(b);

export function prepareDraft({ owner, containerID, note, write }: { owner: string; containerID: string; note: Note; write: WriteKey }): Promise<PendingSave> {
  return prepareObjectDraft({ owner, containerID, id: note.id, version: note.version, content: notePayload(note), write });
}

/** Reuse the exact bound sealed edit for pages, sections and groups, including lost-response retries. */
export async function prepareObjectDraft({ owner, containerID, id, version, content, write }: { owner: string; containerID: string; id: string; version: number; content: ObjectPayload; write: WriteKey }): Promise<PendingSave> {
  const queued = await getQueuedSave(owner, id).catch(() => undefined);
  const cached = await getNote(owner, id).catch(() => undefined);
  const previous = cached?.unsent && (!queued || cached.updatedAt >= queued.updatedAt) ? { ...cached, owner } : queued;
  if (previous && !previous.gone && !previous.previousKey && previous.containerID === containerID && previous.version === version && previous.keyGeneration === write.generation) {
    const opened = await openObject(write.key, containerID, id, previous.payload, true).catch(() => undefined);
    // Local v1 remains readable, but only bound v2 bytes may be reused for an upload.
    if (opened?.payload && !opened.v1 && contents(opened.payload) === contents(content)) return previous;
  }
  return { owner, id, containerID, version, keyGeneration: write.generation, payload: await encryptNote(write.key, containerID, id, content), updatedAt: new Date().toISOString() };
}

/** Choose local text independently of an older queue entry. Export performs no recovery writes. */
export async function localDraft({ owner, id, version, mode, open, server }: {
  owner: string; id: string; version: number; mode: "recover" | "read";
  open: (copy: CachedNote) => Promise<ObjectPayload | undefined>;
  server: () => Promise<ObjectPayload | undefined>;
}): Promise<CachedNote | undefined> {
  let pending = await (mode === "recover" ? recoverDraft(owner, id) : getQueuedSave(owner, id));
  let local = await getNote(owner, id);
  // An exact-version full comparison is evidence of a legacy unsent edit, even
  // with an older pending/conflicted save. Older ordinary caches remain caches.
  while (local && !local.unsent && local.version === version && !pending?.gone && !pending?.previousKey &&
    (!pending || local.updatedAt >= pending.updatedAt)) {
    const payload = await open(local), remote = await server();
    if (payload?.type !== "page" || remote?.type !== "page" || sameDraftContents(payload, remote)) break;
    if (mode === "read") return local;
    const expected = local;
    pending = await recoverDraft(owner, id, expected);
    local = await getNote(owner, id);
    // A replacement during comparison is examined afresh, never rendered from
    // the stale snapshot or marked on the strength of another copy's plaintext.
    if (sameDraft(local, expected)) break;
  }
  const draft = pending && !pending.gone && !pending.previousKey ? pending : undefined;
  const cached = local?.unsent && (!draft || local.updatedAt >= draft.updatedAt) ? local : draft ?? local;
  return cached && (cached.unsent || cached === draft || cached.version >= version) ? cached : undefined;
}
