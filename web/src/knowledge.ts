import { documentText, structuredBlocks } from "./document";

const MAX_TASK_DEPTH = 100;

export type NoteProjection = {
  id: string;
  title: string;
  body: string;
  updatedAt: string;
  sourceBody?: string;
};

// Search reads plain text, but the editor needs the structured body, so every
// projection carries the note it was flattened from.
export type IndexedNote<T> = NoteProjection & { note: T };

// Note objects are immutable state, so projections are cached per object: an edit
// creates one new note object and only that page is parsed again.
const projections = new WeakMap<object, IndexedNote<unknown>>();
const taskCache = new WeakMap<object, string[]>();

export function indexNotes<T extends NoteProjection>(notes: T[]): IndexedNote<T>[] {
  return notes.map((note) => {
    let indexed = projections.get(note) as IndexedNote<T> | undefined;
    if (!indexed) {
      indexed = { id: note.id, title: note.title, updatedAt: note.updatedAt, body: documentText(note.body), sourceBody: note.body, note };
      projections.set(note, indexed);
    }
    return indexed;
  });
}

export function noteLinks(note: NoteProjection): string[] {
  return [...note.body.matchAll(/\[\[([^\]]+)\]\]/g)].map((match) => match[1].trim()).filter(Boolean);
}

export function noteTags(note: NoteProjection): string[] {
  return [...note.body.matchAll(/(?:^|\s)#([a-zA-Z0-9_-]+)/g)].map((match) => match[1].toLowerCase());
}

export function noteTasks(note: NoteProjection): string[] {
  let found = taskCache.get(note);
  if (!found) {
    found = parseTasks(note.sourceBody ?? note.body);
    taskCache.set(note, found);
  }
  return found;
}

function parseTasks(source: string): string[] {
  const tasks: string[] = [];
  const blocks = structuredBlocks(source);
  if (blocks) {
    const text = (content: unknown): string => Array.isArray(content)
      ? content.map((item) => typeof item === "object" && item !== null && "text" in item && typeof item.text === "string" ? item.text : "").join("")
      : typeof content === "string" ? content : "";
    const visit = (block: { type?: string; props?: Record<string, unknown>; content?: unknown; children?: unknown[] }, depth = 0) => {
      if (depth > MAX_TASK_DEPTH) return;
      if (block.type === "checkListItem" && block.props?.checked !== true) {
        const value = text(block.content).trim();
        if (value) tasks.push(value);
      }
      if (block.type === "bulletListItem") {
        const value = text(block.content).trim().match(/^\[ \] (.+)$/)?.[1];
        if (value) tasks.push(value.trim());
      }
      if (Array.isArray(block.children)) block.children.forEach((child) => visit(child as typeof block, depth + 1));
    };
    blocks.forEach((block) => visit(block as Parameters<typeof visit>[0]));
    return tasks;
  }
  return source.split("\n").filter((line) => /^\s*- \[ \] /.test(line)).map((line) => line.replace(/^\s*- \[ \] /, "").trim());
}

export function searchNotes<T extends NoteProjection>(notes: T[], query: string): T[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return notes;
  return notes.filter((note) => `${note.title}\n${note.body}`.toLowerCase().includes(needle));
}

export function openTaskNotes<T extends NoteProjection>(notes: T[]): T[] {
  return notes.filter((note) => noteTasks(note).length > 0);
}

export function contextualNotes<T extends NoteProjection>(notes: T[], active?: T): T[] {
  if (!active) return openTaskNotes(notes).slice(0, 5);
  const links = new Set(noteLinks(active));
  return notes.filter((note) => note.id !== active.id && (links.has(note.id) || noteTasks(note).length > 0 || noteTags(note).some((tag) => noteTags(active).includes(tag)))).slice(0, 5);
}

export function graphEdges(notes: NoteProjection[]): Array<{ from: string; to: string }> {
  const ids = new Set(notes.map((note) => note.id));
  return notes.flatMap((note) => noteLinks(note).filter((to) => ids.has(to)).map((to) => ({ from: note.id, to })));
}
