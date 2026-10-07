import { describe, expect, it } from "vitest";
import { MAX_ORDER_KEY } from "./order";
import {
  QUICK_NOTES, compareOrdered, endOrder, formatRoute, pagesInSection, parseObjectPayload,
  conflictCopy, groupConflicts, parseRoute, reorder, resolveSection, sortedSections, type PagePayload, type Section,
} from "./pages";

const id = (n: number) => `obj_${String(n).padStart(26, "0")}`;
const section = (n: number, order?: string): Section => ({ id: id(n), version: 1, type: "section", title: `S${n}`, color: "blue", order });

describe("parseObjectPayload", () => {
  it("keeps legacy note payloads as pages", () => {
    expect(parseObjectPayload({ title: "Old", body: "text" })).toEqual({ type: "page", title: "Old", body: "text" });
  });
  it("parses sections with safe defaults", () => {
    expect(parseObjectPayload({ type: "section", title: 3, color: "neon", order: "a0" }))
      .toEqual({ type: "section", title: "Untitled section", color: "gray", order: undefined });
  });
  it("drops hostile placement fields instead of trusting them", () => {
    const page = parseObjectPayload({ type: "page", title: "T", body: "", section: "../etc", order: "z".repeat(MAX_ORDER_KEY + 1) });
    expect(page).toEqual({ type: "page", title: "T", body: "", section: undefined, order: undefined });
  });
  it("skips values that are not objects or have no usable body", () => {
    for (const bad of [null, "x", 4, [], { title: "no body" }, { type: "page", title: "T", body: 9 }]) {
      expect(parseObjectPayload(bad)).toBeUndefined();
    }
  });
});

describe("placement", () => {
  it("orders by key, then unordered items, ties by id", () => {
    const items = [{ id: id(3) }, { id: id(2), order: "i" }, { id: id(1), order: "i" }, { id: id(4), order: "a" }];
    expect([...items].sort(compareOrdered).map((item) => item.id)).toEqual([id(4), id(1), id(2), id(3)]);
  });
  it("puts pages with no section or a deleted section in Quick Notes", () => {
    const pages = [{ id: id(10) }, { id: id(11), section: id(99) }, { id: id(12), section: id(1) }];
    expect(pagesInSection(pages, [section(1, "i")], QUICK_NOTES).map((p) => p.id)).toEqual([id(10), id(11)]);
    expect(pagesInSection(pages, [section(1, "i")], id(1)).map((p) => p.id)).toEqual([id(12)]);
  });
  it("sorts sections by order", () => {
    expect(sortedSections([section(1, "r"), section(2, "i")]).map((s) => s.id)).toEqual([id(2), id(1)]);
  });
  it("appends after the largest valid key", () => {
    expect(endOrder([{ order: "r" }, {}, { order: "i" }]) > "r").toBe(true);
    expect(endOrder([])).toBe("i");
  });
});

describe("reorder", () => {
  const list = [{ id: id(1), order: "c" }, { id: id(2), order: "i" }, { id: id(3), order: "r" }];
  it("rewrites only the moved item when neighbours are ordered", () => {
    const [update, ...rest] = reorder(list, id(3), 0);
    expect(rest).toEqual([]);
    expect(update.id).toBe(id(3));
    expect(update.order < "c").toBe(true);
  });
  it("places an item from another list at the end", () => {
    const [update] = reorder(list, id(9), list.length);
    expect(update.order > "r").toBe(true);
  });
  it("renumbers the whole list when neighbours tie", () => {
    const tied = [{ id: id(1), order: "i" }, { id: id(2), order: "i" }];
    const updates = reorder(tied, id(9), 1);
    expect(updates.map((u) => u.id)).toEqual([id(1), id(9), id(2)]);
    expect(updates[0].order < updates[1].order && updates[1].order < updates[2].order).toBe(true);
  });
  it("renumbers when the list holds legacy unordered pages", () => {
    const updates = reorder([{ id: id(1) }, { id: id(2) }], id(2), 0);
    expect(updates.map((u) => u.id)).toEqual([id(2), id(1)]);
  });
});

describe("routes", () => {
  const cnt = `cnt_${"a".repeat(26)}`;
  it("round-trips a full route", () => {
    const route = { container: cnt, section: id(1), page: id(2) };
    expect(parseRoute(formatRoute(route))).toEqual(route);
  });
  it("accepts Quick Notes and drops garbage segments", () => {
    expect(parseRoute(`#/${cnt}/quick/<script>`)).toEqual({ container: cnt, section: QUICK_NOTES, page: undefined });
    expect(parseRoute("#/javascript:alert(1)")).toEqual({ container: undefined, section: undefined, page: undefined });
  });
  it("falls back to the first section, then Quick Notes", () => {
    expect(resolveSection(id(7), [section(2, "r"), section(1, "i")])).toBe(id(1));
    expect(resolveSection(undefined, [])).toBe(QUICK_NOTES);
    expect(resolveSection(QUICK_NOTES, [section(1, "i")])).toBe(QUICK_NOTES);
  });
});

describe("conflictCopy", () => {
  const page = (n: number, order?: string, section?: string) => ({ id: id(n), order, section });
  const rejected = { title: "Plan", body: "mine" };

  it("titles the copy and keeps the rejected body", () => {
    const { page: copy } = conflictCopy([page(1, "i")], page(1, "i"), rejected);
    expect(copy).toMatchObject({ type: "page", title: "Plan (conflicting copy)", body: "mine" });
    expect(conflictCopy([page(1, "i")], page(1, "i"), { title: "", body: "" }).page.title).toBe("Untitled page (conflicting copy)");
  });
  it("places the copy strictly between the original and the next page", () => {
    const list = [page(1, "c"), page(2, "i"), page(3, "p")];
    const { page: copy, moves } = conflictCopy(list, list[1], rejected);
    expect(copy.order! > "i" && copy.order! < "p").toBe(true);
    expect(moves).toEqual([]);
  });
  it("appends after the original when it is last", () => {
    const list = [page(1, "c"), page(2, "i")];
    expect(conflictCopy(list, list[1], rejected).page.order! > "i").toBe(true);
  });
  it("copies the original's section, including none", () => {
    const sectionID = id(5);
    const placed = page(1, "i", sectionID);
    expect(conflictCopy([placed], placed, rejected).page.section).toBe(sectionID);
    expect(conflictCopy([page(1, "i")], page(1, "i"), rejected).page.section).toBeUndefined();
  });
  it("renumbers neighbours when there is no room, returning their moves separately", () => {
    const list = [page(1, "i"), page(2, "i"), page(3)];
    const { page: copy, moves } = conflictCopy(list, list[0], rejected);
    const orders = new Map(moves.map((move) => [move.id, move.order]));
    expect(orders.has("")).toBe(false);
    expect(orders.get(id(1))! < copy.order! && copy.order! < orders.get(id(2))!).toBe(true);
  });
});

describe("groupConflicts", () => {
  const server = { title: "Plan", body: "server" };
  const rejected = (id: string, createdAt: string, body: string, extra: Partial<PagePayload> = {}) =>
    ({ id, createdAt, payload: { type: "page" as const, title: "Plan", body, ...extra } });

  it("collapses identical rejected versions into one group holding every record", () => {
    const { groups, resolveOnly } = groupConflicts(server, [rejected("c1", "t1", "mine"), rejected("c2", "t2", "mine"), rejected("c3", "t3", "mine")]);
    expect(groups).toHaveLength(1);
    expect(groups[0].ids).toEqual(["c1", "c2", "c3"]);
    expect(groups[0].payload.body).toBe("mine");
    expect(resolveOnly).toEqual([]);
  });
  it("keeps distinct versions as separate groups in createdAt order", () => {
    const { groups } = groupConflicts(server, [rejected("c2", "t2", "second"), rejected("c1", "t1", "first"), rejected("c3", "t3", "first")]);
    expect(groups.map((group) => [group.payload.body, group.ids])).toEqual([["first", ["c1", "c3"]], ["second", ["c2"]]]);
  });
  it("resolves without a copy when the text equals the server version", () => {
    const { groups, resolveOnly } = groupConflicts(server, [rejected("c1", "t1", "server"), rejected("c2", "t2", "mine")]);
    expect(resolveOnly).toEqual(["c1"]);
    expect(groups.map((group) => group.ids)).toEqual([["c2"]]);
  });
  it("ignores placement: copies always sit next to the original", () => {
    const { groups, resolveOnly } = groupConflicts(server, [
      rejected("c1", "t1", "mine", { order: "a" }), rejected("c2", "t2", "mine", { order: "b", section: id(5) }),
      rejected("c3", "t3", "server", { order: "z" }),
    ]);
    expect(groups.map((group) => group.ids)).toEqual([["c1", "c2"]]);
    expect(resolveOnly).toEqual(["c3"]);
  });
});

describe("structural payload fields", () => {
  const gid = (n: number) => `obj_${String(n).padStart(26, "0")}`;
  it("parses groups like sections, with a validated parent group", () => {
    expect(parseObjectPayload({ type: "group", title: "Work", color: "teal", order: "i", group: gid(1) }))
      .toEqual({ type: "group", title: "Work", color: "teal", order: "i", group: gid(1) });
    expect(parseObjectPayload({ type: "group", title: 5, color: "neon", group: "../x" }))
      .toEqual({ type: "group", title: "Untitled group", color: "gray", order: undefined, group: undefined });
  });
  it("gives sections an optional validated group", () => {
    expect(parseObjectPayload({ type: "section", title: "S", color: "blue", group: gid(2) })).toMatchObject({ group: gid(2) });
    expect(parseObjectPayload({ type: "section", title: "S", color: "blue", group: 7 })).toMatchObject({ group: undefined });
  });
  it("accepts only the integer levels 0, 1 and 2", () => {
    for (const level of [0, 1, 2]) expect(parseObjectPayload({ type: "page", title: "", body: "", level })).toMatchObject({ level });
    for (const level of [3, -1, 1.5, "1", null]) expect(parseObjectPayload({ type: "page", title: "", body: "", level })).toMatchObject({ level: undefined });
  });
  it("leaves legacy pages without a level", () => {
    expect(parseObjectPayload({ title: "Old", body: "x" })).toEqual({ type: "page", title: "Old", body: "x" });
  });
});
