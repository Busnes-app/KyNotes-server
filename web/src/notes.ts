import type { Note } from "./api";

type Content = Partial<Pick<Note, "title" | "body" | "section" | "order">>;

/** In-memory pages always hold the newest local content: edits and placement land here first. */
export function editEntry(notes: Note[], id: string, change: Content): Note[] {
  return notes.map((note) => (note.id === id ? { ...note, ...change } : note));
}

/** A server write succeeded: carry its version forward, never content, never backwards. */
export function carrySaved(notes: Note[], id: string, saved: { version: number; updatedAt?: string }): Note[] {
  return notes.map((note) => (note.id === id && saved.version > note.version
    ? { ...note, version: saved.version, updatedAt: saved.updatedAt ?? note.updatedAt }
    : note));
}

export const samePayload = (a: Note, b: Note) =>
  a.title === b.title && a.body === b.body && a.section === b.section && a.order === b.order;
