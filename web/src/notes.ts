import type { Note } from "./api";

type Content = Partial<Pick<Note, "title" | "body" | "section" | "order">>;

/** In-memory pages always hold the newest local content: edits and placement land here first. */
export function editEntry(notes: Note[], id: string, change: Content): Note[] {
  return notes.map((note) => (note.id === id ? { ...note, ...change } : note));
}

const sameFields = (a: Note, b: Note) => {
  const keys = Object.keys(a) as Array<keyof Note>;
  return keys.length === Object.keys(b).length && keys.every((key) => a[key] === b[key]);
};

/**
 * Edits the open page. A list entry still equal to the open page becomes `next` itself,
 * so per-object projection caches parse the edited page once per keystroke.
 */
export function editOpenEntry(notes: Note[], open: Note, next: Note, change: Content): Note[] {
  return notes.map((note) => (note.id !== open.id ? note : sameFields(note, open) ? next : { ...note, ...change }));
}

/** A server write succeeded: carry its version forward, never content, never backwards. */
export function carrySaved(notes: Note[], id: string, saved: { version: number; updatedAt?: string }): Note[] {
  return notes.map((note) => (note.id === id && saved.version > note.version
    ? { ...note, version: saved.version, updatedAt: saved.updatedAt ?? note.updatedAt }
    : note));
}

export const samePayload = (a: Note, b: Note) =>
  a.title === b.title && a.body === b.body && a.section === b.section && a.order === b.order;

/**
 * A page that is not open: another tab may hold a newer draft in the shared cache. This tab's
 * own saves leave the cache at the base version, below the carried one, so the list wins here.
 */
export function newestCopy(entry: Note, cached: { version: number; title: string; body: string } | undefined): Note {
  return cached && cached.version >= entry.version ? { ...entry, title: cached.title, body: cached.body } : entry;
}

/** Versions saved while a notebook load was reading, reapplied to its fresh list. */
export function carryAll(notes: Note[], carried: Map<string, { version: number; updatedAt?: string }>): Note[] {
  return [...carried].reduce((value, [id, saved]) => carrySaved(value, id, saved), notes);
}

/**
 * One round of flushing open page `id` before leaving it: done once it closed or matches what
 * was sent, failed when nothing was sent, otherwise edits landed during the save.
 */
export function flushRound(open: Note | null, id: string, sent: Note | undefined): "done" | "again" | "failed" {
  if (open?.id !== id) return "done";
  if (!sent) return "failed";
  return samePayload(open, sent) ? "done" : "again";
}

/**
 * Saves the open page until what was sent matches it, so edits typed during a save are sent
 * before leaving. "failed": nothing was sent; "busy": edits kept landing for `maxRounds`.
 */
export async function flushUntilStable(
  getOpen: () => Note | null,
  save: (open: Note) => Promise<Note | undefined>,
  maxRounds: number,
): Promise<"done" | "failed" | "busy"> {
  const id = getOpen()?.id;
  if (!id) return "done";
  for (let round = 0; round < maxRounds; round++) {
    const sent = await save(getOpen()!);
    const state = flushRound(getOpen(), id, sent);
    if (state !== "again") return state;
  }
  return "busy";
}
