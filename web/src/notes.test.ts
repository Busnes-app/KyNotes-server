import { describe, expect, it } from "vitest";
import type { Note } from "./api";
import { carrySaved, editEntry, samePayload } from "./notes";

const A = "obj_a";
const B = "obj_b";
const page = (id: string, body: string, version = 1): Note => ({ id, title: id, body, version, updatedAt: "t0", order: "i" });
const find = (notes: Note[], id: string) => notes.find((note) => note.id === id)!;

describe("page list reconciliation", () => {
  it("keeps the edited body and the new version when a saved page is moved after switching", () => {
    let notes = [page(A, "old"), page(B, "other")];
    notes = editEntry(notes, A, { body: "new" });
    notes = carrySaved(notes, A, { version: 2, updatedAt: "t1" });
    // Switching to B changes nothing in the list; the move then places A.
    notes = editEntry(notes, A, { section: "obj_s", order: "r" });
    expect(find(notes, A)).toEqual({ ...page(A, "new", 2), updatedAt: "t1", section: "obj_s", order: "r" });
  });

  it("keeps an offline edit once the queued save drains", () => {
    let notes = [page(A, "old")];
    notes = editEntry(notes, A, { title: "offline title", body: "offline" });
    notes = carrySaved(notes, A, { version: 2, updatedAt: "t1" });
    notes = editEntry(notes, A, { order: "a" });
    expect(find(notes, A)).toMatchObject({ title: "offline title", body: "offline", version: 2, order: "a" });
  });

  it("never lets a late save response overwrite newer content or an older version", () => {
    let notes = [page(A, "old")];
    notes = editEntry(notes, A, { body: "sent" });
    notes = editEntry(notes, A, { body: "typed while in flight" });
    notes = carrySaved(notes, A, { version: 2, updatedAt: "t1" });
    expect(find(notes, A)).toMatchObject({ body: "typed while in flight", version: 2 });
    notes = carrySaved(notes, A, { version: 1, updatedAt: "late" });
    expect(find(notes, A)).toMatchObject({ version: 2, updatedAt: "t1" });
  });

  it("leaves other pages untouched", () => {
    const notes = [page(A, "a"), page(B, "b")];
    expect(find(editEntry(notes, A, { body: "x" }), B)).toBe(notes[1]);
    expect(find(carrySaved(notes, A, { version: 5 }), B)).toBe(notes[1]);
  });
});

describe("samePayload", () => {
  it("compares placement as well as text", () => {
    const open = page(A, "body");
    expect(samePayload(open, { ...open, version: 9, updatedAt: "later" })).toBe(true);
    expect(samePayload(open, { ...open, section: "obj_s" })).toBe(false);
    expect(samePayload(open, { ...open, order: "z" })).toBe(false);
    expect(samePayload(open, { ...open, title: "other" })).toBe(false);
  });
});
