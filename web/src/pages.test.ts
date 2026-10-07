import { describe, expect, it } from "vitest";
import { MAX_ORDER_KEY } from "./order";
import {
  QUICK_NOTES, compareOrdered, endOrder, formatRoute, pagesInSection, parseObjectPayload,
  parseRoute, reorder, resolveSection, sortedSections, type Section,
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
