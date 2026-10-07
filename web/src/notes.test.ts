import { describe, expect, it } from "vitest";
import type { Note } from "./api";
import { carryAll, carrySaved, editEntry, editOpenEntry, flushRound, flushUntilStable, newestCopy, notePayload, samePayload } from "./notes";
import { parseObjectPayload } from "./pages";

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

describe("newestCopy", () => {
  const listed = { ...page(A, "list body", 2), title: "list title" };
  const draft = (version: number) => ({ version, title: "other tab", body: "other tab body" });
  it("prefers another tab's cached draft at an equal or newer version", () => {
    expect(newestCopy(listed, draft(2))).toMatchObject({ title: "other tab", body: "other tab body", version: 2 });
    expect(newestCopy(listed, draft(3))).toMatchObject({ body: "other tab body", version: 2 });
  });
  it("keeps the list when the cache is older, as after this tab's own save", () => {
    expect(newestCopy(listed, draft(1))).toBe(listed);
  });
  it("keeps the list when there is no readable cached draft", () => {
    expect(newestCopy(listed, undefined)).toBe(listed);
  });
});

describe("carryAll", () => {
  it("reapplies versions saved while a notebook was loading", () => {
    const loaded = [page(A, "draft", 1), page(B, "b", 4)];
    const carried = new Map([[A, { version: 2, updatedAt: "t1" }], [B, { version: 3 }]]);
    expect(carryAll(loaded, carried)).toEqual([{ ...page(A, "draft", 2), updatedAt: "t1" }, page(B, "b", 4)]);
  });
});

describe("open page edits", () => {
  it("shares the edited object between the open page and its list entry", () => {
    const open = page(A, "old");
    const next = { ...open, body: "new" };
    const notes = editOpenEntry([open, page(B, "other")], open, next, { body: "new" });
    expect(find(notes, A)).toBe(next);
    // Equal but separately carried copies share too.
    const copy = { ...next };
    expect(find(editOpenEntry([copy], next, { ...next, body: "newer" }, { body: "newer" }), A).body).toBe("newer");
    const later = { ...next, body: "newer" };
    expect(find(editOpenEntry([{ ...next }], next, later, { body: "newer" }), A)).toBe(later);
  });
  it("keeps a diverged list entry's own fields", () => {
    const open = page(A, "old");
    const moved = { ...open, section: "obj_s", order: "r" };
    const notes = editOpenEntry([moved], open, { ...open, body: "new" }, { body: "new" });
    expect(find(notes, A)).toEqual({ ...moved, body: "new" });
  });
});

describe("flushing the open page before leaving it", () => {
  it("is done when what was sent is what is open", () => {
    const open = page(A, "typed");
    expect(flushRound(open, A, { ...open, version: 2 })).toBe("done");
  });

  it("goes again when keystrokes landed during the save", () => {
    expect(flushRound(page(A, "typed more"), A, page(A, "typed"))).toBe("again");
  });

  it("goes again when the open page moved during the save", () => {
    expect(flushRound({ ...page(A, "typed"), order: "r" }, A, page(A, "typed"))).toBe("again");
  });

  it("fails when nothing was sent, so the page stays open and dirty", () => {
    expect(flushRound(page(A, "typed"), A, undefined)).toBe("failed");
  });

  it("is done when another selection closed the page meanwhile", () => {
    expect(flushRound(page(B, "other"), A, undefined)).toBe("done");
    expect(flushRound(null, A, undefined)).toBe("done");
  });
});

describe("flushUntilStable", () => {
  // A fake editor: `open` is the page on screen, `sent` records each save request.
  const harness = (during: (open: Note, round: number) => Note | null, result: (sent: Note) => Note | undefined = (sent) => sent) => {
    let open: Note | null = page(A, "typed");
    const sent: Note[] = [];
    const save = async (note: Note) => {
      sent.push(note);
      open = open && during(open, sent.length);
      return result(note);
    };
    return { getOpen: () => open, save, sent };
  };

  it("sends a second round carrying an edit typed during the first save", async () => {
    const h = harness((open, round) => (round === 1 ? { ...open, body: "typed late" } : open));
    expect(await flushUntilStable(h.getOpen, h.save, 5)).toBe("done");
    expect(h.sent.map((note) => note.body)).toEqual(["typed", "typed late"]);
  });

  it("gives up as busy after the round limit while edits keep landing", async () => {
    const h = harness((open, round) => ({ ...open, body: `edit ${round}` }));
    expect(await flushUntilStable(h.getOpen, h.save, 5)).toBe("busy");
    expect(h.sent).toHaveLength(5);
  });

  it("fails after one round when nothing was sent", async () => {
    const h = harness((open) => open, () => undefined);
    expect(await flushUntilStable(h.getOpen, h.save, 5)).toBe("failed");
    expect(h.sent).toHaveLength(1);
  });

  it("is done when the page closes mid-flush", async () => {
    const h = harness(() => page(B, "other"), () => undefined);
    expect(await flushUntilStable(h.getOpen, h.save, 5)).toBe("done");
    expect(h.sent).toHaveLength(1);
  });

  it("is done without saving when no page is open", async () => {
    const h = harness((open) => open);
    expect(await flushUntilStable(() => null, h.save, 5)).toBe("done");
    expect(h.sent).toHaveLength(0);
  });
});

describe("page levels", () => {
  it("keeps level through edits, saves, other-tab drafts and the payload round-trip", () => {
    let notes = [{ ...page(A, "body"), level: 1 as const }, page(B, "other")];
    notes = editEntry(notes, A, { body: "edited" });
    notes = carrySaved(notes, A, { version: 2 });
    const kept = newestCopy(find(notes, A), { version: 2, title: "t", body: "draft" });
    expect(kept.level).toBe(1);
    expect(parseObjectPayload(JSON.parse(JSON.stringify(notePayload(kept))))).toMatchObject({ type: "page", level: 1, body: "draft" });
    expect(editEntry(notes, A, { level: 2 })[0].level).toBe(2);
  });

  it("treats a level change as unsaved", () => {
    expect(samePayload(page(A, "x"), { ...page(A, "x"), level: 1 })).toBe(false);
  });
});
