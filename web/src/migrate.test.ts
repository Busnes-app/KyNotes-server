import { describe, expect, it } from "vitest";
import { migrateNotebook, type LoadedObject, type MigrationIO } from "./migrate";

/** A notebook on a fake server: which objects are stored v1, which pages carry legacy, and the marker. */
function notebook(objects: LoadedObject[]) {
  const server = new Map(objects.map((object) => [object.id, { ...object }]));
  const writes: string[] = [];
  let marked = false;
  let failAfter = Infinity;
  const write = (id: string, legacy?: Record<string, string>) => {
    if (writes.length >= failAfter) throw new Error("connection lost");
    writes.push(id);
    server.set(id, { ...server.get(id)!, v1: false, ...(legacy && { legacy }) });
    return true;
  };
  const io: MigrationIO = {
    pins: async (pageID): Promise<Record<string, string>> => (pageID === "obj_p1" ? { cmt_old: "a".repeat(64) } : {}),
    savePage: async (id, legacy) => write(id, legacy),
    saveStructure: async (_kind, id) => write(id),
    mark: async () => {
      writes.push("marker");
      marked = true;
      return true;
    },
  };
  // What the next load reads: the server's state now.
  const load = () => [...server.values()].map((object) => ({ ...object }));
  return { io, load, writes, server, stopAfter: (n: number) => { failAfter = n; }, marked: () => marked };
}

describe("migration pass", () => {
  const objects: LoadedObject[] = [
    { id: "obj_p1", type: "page", v1: true },
    { id: "obj_s1", type: "section", v1: true },
    { id: "obj_p2", type: "page", v1: false }, // saved v2 by an edit before its children were pinned
    { id: "obj_g1", type: "group", v1: false },
    { id: "obj_p3", type: "page", v1: false, legacy: {} },
  ];

  it("resumes after an interruption, writes the marker exactly once, and nothing after completion", async () => {
    const nb = notebook(objects);
    nb.stopAfter(1);
    expect(await migrateNotebook(nb.load(), 0, false, nb.io)).toBe("partial");
    expect(nb.writes).toEqual(["obj_p1"]);
    expect(nb.marked()).toBe(false);
    expect(nb.server.get("obj_p1")).toMatchObject({ v1: false, legacy: { cmt_old: "a".repeat(64) } });

    nb.stopAfter(Infinity);
    expect(await migrateNotebook(nb.load(), 0, false, nb.io)).toBe("migrated");
    // Already-migrated objects are not written again; the marker comes last.
    expect(nb.writes).toEqual(["obj_p1", "obj_s1", "obj_p2", "marker"]);
    expect(nb.server.get("obj_p2")).toMatchObject({ legacy: {} });

    expect(await migrateNotebook(nb.load(), 0, true, nb.io)).toBe("migrated");
    expect(nb.writes.filter((write) => write === "marker")).toHaveLength(1);
    expect(nb.writes).toHaveLength(4);
  });

  it("writes no marker while an object was unreadable, or a save was skipped", async () => {
    const nb = notebook(objects.filter((object) => object.legacy));
    expect(await migrateNotebook(nb.load(), 1, false, nb.io)).toBe("partial");
    expect(nb.writes).toEqual([]);
    const skipped = notebook(objects);
    skipped.io.saveStructure = async () => false; // a version conflict: the next load retries
    expect(await migrateNotebook(skipped.load(), 0, false, skipped.io)).toBe("partial");
    expect(skipped.marked()).toBe(false);
  });

  it("never saves a page whose children could not be listed", async () => {
    const nb = notebook([{ id: "obj_p1", type: "page", v1: true }]);
    nb.io.pins = async () => { throw new Error("offline"); };
    expect(await migrateNotebook(nb.load(), 0, false, nb.io)).toBe("partial");
    expect(nb.writes).toEqual([]);
  });
});
