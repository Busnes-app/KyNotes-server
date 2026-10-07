import { describe, expect, it } from "vitest";
import { MAX_GROUP_DEPTH, ancestors, blockRange, displayLevels, groupParents, groupPath, placeBlock, sectionGroup, shiftLevel, visibleRows } from "./outline";

const page = (id: string, level?: number, order?: string) => ({ id, level, order });

describe("displayLevels", () => {
  it("reads missing, invalid and out-of-range levels safely", () => {
    expect(displayLevels([page("a"), page("b", 1), page("c", 7), page("d", -3)])).toEqual([0, 1, 2, 0]);
  });
  it("never lets a page sit more than one level below the one before", () => {
    expect(displayLevels([page("a", 2), page("b", 2), page("c", 0), page("d", 2)])).toEqual([0, 1, 0, 1]);
  });
  it("re-reads children of a deleted parent one level up", () => {
    expect(displayLevels([page("a", 0), page("c", 2)])).toEqual([0, 1]);
  });
});

describe("blocks and rows", () => {
  const list = [page("a", 0), page("b", 1), page("c", 2), page("d", 1), page("e", 0)];
  it("finds the block under a parent", () => {
    expect(blockRange(displayLevels(list), 0)).toEqual([0, 4]);
    expect(blockRange(displayLevels(list), 1)).toEqual([1, 3]);
    expect(blockRange(displayLevels(list), 4)).toEqual([4, 5]);
  });
  it("hides pages under collapsed parents only", () => {
    const rows = visibleRows(list, new Set(["b"]));
    expect(rows.map((row) => row.item.id)).toEqual(["a", "b", "d", "e"]);
    expect(rows[1]).toMatchObject({ level: 1, hasChildren: true, collapsed: true });
    expect(rows[3]).toMatchObject({ hasChildren: false, collapsed: false });
  });
  it("ignores a collapsed mark on a page without children", () => {
    expect(visibleRows(list, new Set(["e"])).map((row) => row.item.id)).toEqual(["a", "b", "c", "d", "e"]);
  });
  it("lists the ancestors to expand for a hidden page", () => {
    expect(ancestors(list, "c")).toEqual(["b", "a"]);
    expect(ancestors(list, "e")).toEqual([]);
  });
});

describe("shiftLevel", () => {
  const levels = [0, 1, 1, 0];
  it("indents only under a page one level shallower", () => {
    expect(shiftLevel(levels, 0, 1)).toBeUndefined();
    expect(shiftLevel(levels, 2, 1)).toBe(2);
    expect(shiftLevel([0, 1, 2], 2, 1)).toBeUndefined();
    expect(shiftLevel([0, 0], 1, 1)).toBe(1);
  });
  it("outdents down to 0", () => {
    expect(shiftLevel(levels, 1, -1)).toBe(0);
    expect(shiftLevel(levels, 0, -1)).toBeUndefined();
  });
});

describe("placeBlock", () => {
  const target = [page("x", 0, "c"), page("y", 1, "i"), page("z", 0, "r")];
  it("keeps relative levels and clamps the head to its new spot", () => {
    const updates = placeBlock(target, [page("p", 1), page("q", 2)], [1, 2], 0);
    expect(updates.map((u) => [u.id, u.level])).toEqual([["p", 0], ["q", 1]]);
    expect(updates[0].order < updates[1].order && updates[1].order < "c").toBe(true);
  });
  it("can stay deep when the spot allows it", () => {
    const updates = placeBlock(target, [page("p", 2)], [2], 2);
    expect(updates).toHaveLength(1);
    expect(updates[0].level).toBe(2);
    expect(updates[0].order > "i" && updates[0].order < "r").toBe(true);
  });
  it("renumbers the whole list when neighbours tie, giving target pages order-only updates", () => {
    const tied = [page("x", 0, "i"), page("y", 0, "i")];
    const updates = placeBlock(tied, [page("p", 0)], [0], 1);
    expect(updates.map((u) => u.id)).toEqual(["x", "p", "y"]);
    expect(updates[0].level).toBeUndefined();
    expect(updates[1].level).toBe(0);
  });
});

describe("groups", () => {
  const id = (n: number) => `obj_${String(n).padStart(26, "0")}`;
  it("keeps valid nesting and roots missing parents", () => {
    const parents = groupParents([{ id: id(1) }, { id: id(2), group: id(1) }, { id: id(3), group: id(99) }]);
    expect(parents.get(id(2))).toBe(id(1));
    expect(parents.get(id(3))).toBeUndefined();
  });
  it("breaks cycles without looping", () => {
    const parents = groupParents([{ id: id(1), group: id(2) }, { id: id(2), group: id(1) }, { id: id(3), group: id(3) }]);
    expect([parents.get(id(1)), parents.get(id(2)), parents.get(id(3))]).toEqual([undefined, undefined, undefined]);
  });
  it("caps depth", () => {
    const chain = Array.from({ length: MAX_GROUP_DEPTH + 1 }, (_, i) => ({ id: id(i + 1), group: i === 0 ? undefined : id(i) }));
    const parents = groupParents(chain);
    expect(parents.get(id(MAX_GROUP_DEPTH))).toBe(id(MAX_GROUP_DEPTH - 1));
    expect(parents.get(id(MAX_GROUP_DEPTH + 1))).toBeUndefined();
  });
  it("resolves section groups and breadcrumbs", () => {
    const parents = groupParents([{ id: id(1) }, { id: id(2), group: id(1) }]);
    expect(sectionGroup({ id: id(9), group: id(2) }, parents)).toBe(id(2));
    expect(sectionGroup({ id: id(9), group: id(77) }, parents)).toBeUndefined();
    expect(groupPath(id(2), parents)).toEqual([id(1), id(2)]);
    expect(groupPath(undefined, parents)).toEqual([]);
  });
});
