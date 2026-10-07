import { describe, expect, it } from "vitest";
import { MAX_GROUP_DEPTH, ancestors, blockRange, displayLevels, dropBefore, groupMoveAllowed, groupOfSection, groupParents, groupPath, groupTargets, parseCollapsed, placeBlock, sectionGroup, shiftLevel, siblingMove, visibleRows } from "./outline";

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

describe("block moves", () => {
  // a, b(c), d, e(f)
  const levels = [0, 1, 2, 1, 0, 1];
  it("Alt+Arrow moves past the neighbouring sibling block or refuses", () => {
    expect(siblingMove(levels, 3, -1)).toBe(1);
    expect(siblingMove(levels, 1, 1)).toBe(4);
    expect(siblingMove(levels, 0, 1)).toBe(6);
    expect(siblingMove(levels, 1, -1)).toBeUndefined();
    expect(siblingMove(levels, 3, 1)).toBeUndefined();
    expect(siblingMove(levels, 4, 1)).toBeUndefined();
  });
  it("drops before the row dragging up and after its block dragging down", () => {
    expect(dropBefore(levels, 4, 1)).toBe(1);
    expect(dropBefore(levels, 0, 4)).toBe(6);
    expect(dropBefore(levels, 1, 3)).toBe(4);
    expect(dropBefore(levels, 3, 4)).toBe(6);
    expect(dropBefore(levels, 1, 2)).toBeUndefined();
    expect(dropBefore(levels, 1, 1)).toBeUndefined();
  });
});

describe("parseCollapsed", () => {
  it("reads an array of ids and treats anything else as empty", () => {
    expect([...parseCollapsed('["a","b",3]')]).toEqual(["a", "b"]);
    expect(parseCollapsed("{").size).toBe(0);
    expect(parseCollapsed('{"a":1}').size).toBe(0);
    expect(parseCollapsed(null).size).toBe(0);
  });
});

describe("group moves", () => {
  const id = (n: number) => `obj_${String(n).padStart(26, "0")}`;
  it("refuses moving a group into itself, its subtree or past the depth cap", () => {
    const parents = groupParents([{ id: id(1) }, { id: id(2), group: id(1) }, { id: id(3), group: id(2) }, { id: id(4) }]);
    expect(groupMoveAllowed(id(1), undefined, parents)).toBe(true);
    expect(groupMoveAllowed(id(1), id(1), parents)).toBe(false);
    expect(groupMoveAllowed(id(1), id(3), parents)).toBe(false);
    expect(groupMoveAllowed(id(4), id(3), parents)).toBe(true); // depth 4
    expect(groupMoveAllowed(id(1), id(4), parents)).toBe(true); // 1 + height 3
    const deep = groupParents([{ id: id(1) }, { id: id(2), group: id(1) }, { id: id(3), group: id(2) }, { id: id(4), group: id(3) }, { id: id(5) }, { id: id(6), group: id(5) }]);
    expect(groupMoveAllowed(id(5), id(4), deep)).toBe(false);
    expect(groupMoveAllowed(id(6), id(3), deep)).toBe(true);
    expect(groupMoveAllowed(id(5), id(3), deep)).toBe(false);
  });
  it("lists move targets labelled by path, without the moving group's subtree", () => {
    const groups = [{ id: id(1), title: "Work" }, { id: id(2), title: "Q4", group: id(1) }, { id: id(3), title: "Home" }];
    const parents = groupParents(groups);
    expect(groupTargets(groups, parents)).toEqual([
      { id: id(3), label: "Home" },
      { id: id(1), label: "Work" },
      { id: id(2), label: "Work › Q4" },
    ]);
    expect(groupTargets(groups, parents, id(1))).toEqual([{ id: id(3), label: "Home" }]);
  });
  it("finds the group of a routed section", () => {
    const parents = groupParents([{ id: id(1) }]);
    const sections = [{ id: id(8), group: id(1) }, { id: id(9), group: id(42) }];
    expect(groupOfSection(id(8), sections, parents)).toBe(id(1));
    expect(groupOfSection(id(9), sections, parents)).toBeUndefined();
    expect(groupOfSection("quick", sections, parents)).toBeUndefined();
  });
});
