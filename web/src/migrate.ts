import type { Legacy } from "./pages";

/** One object as a notebook load read it; v1: its server copy is v1, or not proven v2. */
export type LoadedObject = { id: string; type: "page" | "section" | "group"; v1: boolean; legacy?: Legacy };

export type MigrationIO = {
  /** A page's v1 children that open here: ID → SHA-256 hex of the ciphertext as stored. Throws when they cannot be listed. */
  pins: (pageID: string) => Promise<Legacy>;
  /** Re-saves an object v2 (a page carrying legacy); false when it was not saved now (conflict, offline, open page). */
  savePage: (id: string, legacy: Legacy) => Promise<boolean>;
  saveStructure: (kind: "section" | "group", id: string) => Promise<boolean>;
  /** Writes the container meta v2 with the marker; false when it was not written. */
  mark: () => Promise<boolean>;
};

/**
 * One background migration pass, by a writer after a notebook load. Every object read as v1 is re-saved
 * v2, and every page without legacy (v1, or saved v2 before its children were pinned) gets its v1 children
 * pinned. Only a pass that finds or leaves every object v2 with legacy on every page, and nothing
 * unreadable, writes the marker: the commit point. A pass stopped anywhere leaves a readable mix that the
 * next load continues; a migrated notebook writes nothing.
 */
export async function migrateNotebook(objects: LoadedObject[], unreadable: number, migrated: boolean, io: MigrationIO): Promise<"migrated" | "partial"> {
  if (migrated) return "migrated";
  let complete = unreadable === 0;
  for (const object of objects) {
    if (object.type !== "page" ? !object.v1 : !object.v1 && object.legacy) continue;
    try {
      const saved = object.type === "page" ? await io.savePage(object.id, await io.pins(object.id)) : await io.saveStructure(object.type, object.id);
      complete &&= saved;
    } catch {
      // Not pinned or not saved: the next pass retries it.
      complete = false;
    }
  }
  return complete && (await io.mark()) ? "migrated" : "partial";
}
