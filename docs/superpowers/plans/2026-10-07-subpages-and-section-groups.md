# Subpages and Section Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two OneNote features in the KyNotes web client. Subpages: pages indented up to two levels, collapsible, moving with their parent. Section groups: nested tab groups with a breadcrumb.

**Architecture:**
- Each page's encrypted payload gains a `level`. The hierarchy is derived at read time from order plus level.
- A group is a new encrypted `folder` object, `{type:"group"}`. Sections and groups carry an optional `group` parent ID.
- All tree logic lives in a new pure module `web/src/outline.ts`. Payload validation stays in `web/src/pages.ts`.
- `main.tsx` and `SectionTabs.tsx` wire state and UI through the existing save machinery.

**Tech Stack:** React 19, TypeScript, vitest (node), native drag and drop / popover.

**Spec:** `docs/superpowers/specs/2026-10-07-subpages-and-section-groups-design.md`

## Global Constraints

- No server, API or migration changes. Groups use the existing object kind `folder`.
- Structural fields (`level`, `group`) live only inside `kynotes/object/v1` ciphertext. Collapse state lives only in browser localStorage, under `kynotes-collapsed-<userId>-<containerId>`, as an array of page IDs.
- Every decrypted payload goes through `parseObjectPayload`. Invalid structural fields are dropped, never thrown.
- Never rewrite a page or section the user did not act on. Normalised levels and resolved group parents are display-only.
- Levels are 0..2 (`MAX_LEVEL`). Group depth is capped at 4 (`MAX_GROUP_DEPTH`). Cycles and excess depth render at the notebook root.
- Deleting a page never deletes its subpages. Deleting a group never deletes its contents; they move up one level.
- Reuse the save machinery documented in the repo-root `AGENTS.md`: `placePage`, `writeObject`, `updateSection`, `moveChain`, `patchNotes`/`notesRef`, `patchSections`/`sectionsRef`, the conflict-recovery lock, and `flushOpenPage`. No new save path.
- Order keys compare with `<`/`>`, never `localeCompare`. Do not hand-edit `web/src/ky-ui/`.
- Checks, from `web/`: `npm test`, `npm run build`. From the root: `rsync -a --delete web/dist/ internal/web/dist/`, `diff -qr web/dist internal/web/dist` (empty), `go test ./internal/web`, `gofmt -l .` (empty).
- Commits: subject line, blank line, then `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` on its own line.

## Review Focus

1. **Hostile structure** from another device: cycles, depth > 4, levels like 7, -1 or "1". These must render without looping or throwing. Pinned in Task 1 (parse) and Task 2 (`groupParents`, `displayLevels`).
2. **Legacy pages without `level`** must display at level 0 and must not be written on open. Pinned in Task 2 (`displayLevels`) and checked in the Task 5 browser pass (no PUT).
3. **Deleting a parent page.** Its subpages must stay visible, one level up. Pinned in Task 2 (`displayLevels` after removal).
4. **Moving a block** into another section or onto a level-0 spot. The head clamps, relative levels are kept, and nothing is lost. Pinned in Task 2 (`placeBlock`) and checked in Task 5.
5. **Drop and keyboard targets while some parents are collapsed.** A move must land relative to the visible row the user aimed at, not to a hidden page. Task 3 uses page-ID targets (`beforeID`), never row indices. Checked in Task 5.

---

### Task 1: Structural payload fields

**Files:**
- Modify: `web/src/pages.ts` (types at lines 6-9, `parseObjectPayload` at about line 17)
- Test: `web/src/pages.test.ts` (append)

**Interfaces:**
- Produces:
  - `type GroupPayload = { type: "group"; title: string; color: SectionColor; order?: string; group?: string }`
  - `type Group = GroupPayload & { id: string; version: number }`
  - `SectionPayload` gains `group?: string`
  - `PagePayload` gains `level?: 0 | 1 | 2`
  - `ObjectPayload = SectionPayload | GroupPayload | PagePayload`

- [ ] **Step 1: Write the failing test.** Append to `web/src/pages.test.ts`. Keep the existing imports; `parseObjectPayload` is already imported.

```ts
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
```

- [ ] **Step 2: Run it and see it fail.** `cd web && npx vitest run src/pages.test.ts` → FAIL. The group payload is not parsed and the level is missing.

- [ ] **Step 3: Implement.** In `web/src/pages.ts`, replace the four type lines with:

```ts
export type SectionPayload = { type: "section"; title: string; color: SectionColor; order?: string; group?: string };
export type GroupPayload = { type: "group"; title: string; color: SectionColor; order?: string; group?: string };
export type PagePayload = { type: "page"; title: string; body: string; section?: string; order?: string; level?: 0 | 1 | 2 };
export type ObjectPayload = SectionPayload | GroupPayload | PagePayload;
export type Section = SectionPayload & { id: string; version: number };
export type Group = GroupPayload & { id: string; version: number };
```

Then replace the section branch of `parseObjectPayload` with:

```ts
  const group = typeof v.group === "string" && OBJECT_ID.test(v.group) ? v.group : undefined;
  if (v.type === "section" || v.type === "group") {
    return {
      type: v.type,
      title: typeof v.title === "string" ? v.title : v.type === "group" ? "Untitled group" : "Untitled section",
      color: SECTION_COLORS.includes(v.color as SectionColor) ? (v.color as SectionColor) : "gray",
      order,
      group,
    };
  }
```

Then add the level line just before `return page;`:

```ts
  if ("level" in v) page.level = v.level === 0 || v.level === 1 || v.level === 2 ? v.level : undefined;
```

`readContainerObjects` in `main.tsx` branches on `payload.type === "section"`. Group payloads now reach it, so `tsc` may need a narrowing tweak there. Task 4 handles groups properly. For this task only, skip group payloads in `readContainerObjects` (`if (payload.type === "group") return;`) and leave a comment that Task 4 replaces it.

- [ ] **Step 4: Run the checks.** `cd web && npm test && npm run build` → all pass.

- [ ] **Step 5: Commit.** `git add web/src/pages.ts web/src/pages.test.ts web/src/main.tsx` with the message "web: parse page levels and section groups".

---

### Task 2: Pure outline helpers

**Files:**
- Create: `web/src/outline.ts`
- Test: `web/src/outline.test.ts`

**Interfaces:**
- Produces:
  - `MAX_LEVEL = 2`, `MAX_GROUP_DEPTH = 4`
  - `displayLevels(list: {id; level?}[]): number[]`
  - `blockRange(levels: number[], index: number): [number, number]`
  - `type Row<T> = { item: T; level: number; hasChildren: boolean; collapsed: boolean }`
  - `visibleRows<T>(list: T[], collapsed: ReadonlySet<string>): Row<T>[]`
  - `ancestors(list, id): string[]` (nearest first)
  - `shiftLevel(levels, index, delta: 1 | -1): number | undefined`
  - `placeBlock(target, block, blockLevels, index): Array<{ id: string; order: string; level?: number }>`
  - `groupParents(groups: {id; group?}[]): Map<string, string | undefined>`
  - `sectionGroup(section, parents): string | undefined`
  - `groupPath(groupID, parents): string[]` (root first)

- [ ] **Step 1: Write the failing test.** Create `web/src/outline.test.ts`:

```ts
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
```

- [ ] **Step 2: Run it and see it fail.** `cd web && npx vitest run src/outline.test.ts` → FAIL, because `./outline` does not resolve.

- [ ] **Step 3: Implement.** Create `web/src/outline.ts`:

```ts
import { keyBetween } from "./order";

export const MAX_LEVEL = 2;
export const MAX_GROUP_DEPTH = 4;
type Leveled = { id: string; level?: number };
type Ordered = { id: string; order?: string };

const clampLevel = (level: number | undefined) => Math.min(MAX_LEVEL, Math.max(0, level ?? 0));

/** Display levels for an ordered page list: the first page is 0, each page at most one deeper than the one before. */
export function displayLevels(list: Leveled[]): number[] {
  const levels: number[] = [];
  list.forEach((page, index) => levels.push(index === 0 ? 0 : Math.min(clampLevel(page.level), levels[index - 1] + 1)));
  return levels;
}

/** [start, end) of the block headed by `index`: the page plus every following deeper page. */
export function blockRange(levels: number[], index: number): [number, number] {
  let end = index + 1;
  while (end < levels.length && levels[end] > levels[index]) end += 1;
  return [index, end];
}

export type Row<T> = { item: T; level: number; hasChildren: boolean; collapsed: boolean };

/** Rows to show: pages under a collapsed parent are hidden. */
export function visibleRows<T extends Leveled>(list: T[], collapsed: ReadonlySet<string>): Row<T>[] {
  const levels = displayLevels(list);
  const rows: Row<T>[] = [];
  let hiddenDeeperThan = Infinity;
  list.forEach((item, index) => {
    const level = levels[index];
    if (level > hiddenDeeperThan) return;
    hiddenDeeperThan = Infinity;
    const hasChildren = index + 1 < list.length && levels[index + 1] > level;
    const isCollapsed = hasChildren && collapsed.has(item.id);
    rows.push({ item, level, hasChildren, collapsed: isCollapsed });
    if (isCollapsed) hiddenDeeperThan = level;
  });
  return rows;
}

/** Ids of the pages above `id` in its outline, nearest first. */
export function ancestors(list: Leveled[], id: string): string[] {
  const levels = displayLevels(list);
  const index = list.findIndex((page) => page.id === id);
  const found: string[] = [];
  let level = levels[index];
  for (let i = index - 1; i >= 0 && level > 0; i -= 1) {
    if (levels[i] < level) {
      found.push(list[i].id);
      level = levels[i];
    }
  }
  return found;
}

/** The level `list[index]` would get from indent (+1) or outdent (-1), or undefined when not allowed. */
export function shiftLevel(levels: number[], index: number, delta: 1 | -1): number | undefined {
  const next = levels[index] + delta;
  if (next < 0 || next > MAX_LEVEL) return undefined;
  if (delta === 1 && (index === 0 || next > levels[index - 1] + 1)) return undefined;
  return next;
}

/**
 * Updates that insert `block` (with its display `blockLevels`) into `target` at `index`.
 * The block keeps its relative levels and its head is clamped to fit the new spot.
 * One key per block page when the neighbours allow it; otherwise the whole list is
 * renumbered once (target pages then get an order-only update).
 */
export function placeBlock<T extends Ordered & Leveled>(target: T[], block: T[], blockLevels: number[], index: number): Array<{ id: string; order: string; level?: number }> {
  const at = Math.max(0, Math.min(index, target.length));
  const targetLevels = displayLevels(target);
  const head = Math.min(blockLevels[0], at === 0 ? 0 : targetLevels[at - 1] + 1);
  const levels = blockLevels.map((level) => clampLevel(level - blockLevels[0] + head));
  const prev = target[at - 1]?.order ?? null;
  const next = target[at]?.order ?? null;
  if (target.every((item) => item.order) && (prev === null || next === null || prev < next)) {
    try {
      let low = prev;
      return block.map((item, i) => {
        low = keyBetween(low, next);
        return { id: item.id, order: low, level: levels[i] };
      });
    } catch { /* tie or exhausted key: renumber below */ }
  }
  let order: string | null = null;
  const merged: Array<{ id: string; level?: number }> = [
    ...target.slice(0, at).map((item) => ({ id: item.id })),
    ...block.map((item, i) => ({ id: item.id, level: levels[i] })),
    ...target.slice(at).map((item) => ({ id: item.id })),
  ];
  return merged.map((item) => {
    order = keyBetween(order, null);
    return item.level === undefined ? { id: item.id, order } : { id: item.id, order, level: item.level };
  });
}

type Grouped = { id: string; group?: string };

/**
 * Effective parent group of every group (undefined = notebook root). A missing parent,
 * a cycle or a depth over MAX_GROUP_DEPTH puts the group at the root; nothing is written.
 */
export function groupParents(groups: Grouped[]): Map<string, string | undefined> {
  const raw = new Map(groups.map((group) => [group.id, group.group]));
  const parents = new Map<string, string | undefined>();
  for (const { id, group } of groups) {
    const seen = new Set([id]);
    let depth = 1;
    let current = group;
    while (current !== undefined && raw.has(current) && !seen.has(current) && depth <= MAX_GROUP_DEPTH) {
      seen.add(current);
      depth += 1;
      current = raw.get(current);
    }
    const cyclic = current !== undefined && seen.has(current);
    parents.set(id, group !== undefined && raw.has(group) && !cyclic && depth <= MAX_GROUP_DEPTH ? group : undefined);
  }
  return parents;
}

/** Effective group of a section: its group when that group exists, otherwise the root. */
export const sectionGroup = (section: Grouped, parents: Map<string, string | undefined>) =>
  section.group !== undefined && parents.has(section.group) ? section.group : undefined;

/** Group ids from the root down to `groupID` (empty at the root). */
export function groupPath(groupID: string | undefined, parents: Map<string, string | undefined>): string[] {
  const path: string[] = [];
  let current = groupID;
  while (current !== undefined && parents.has(current) && path.length <= MAX_GROUP_DEPTH) {
    path.unshift(current);
    current = parents.get(current);
  }
  return path;
}
```

- [ ] **Step 4: Run it and see it pass.** `cd web && npx vitest run src/outline.test.ts` → PASS (16 tests). Then `npm test && npm run build`. This code and its tests ran verbatim while the plan was being written: 16/16, tsc clean.

- [ ] **Step 5: Commit** `web/src/outline.ts` and `web/src/outline.test.ts` with the message "web: pure outline helpers for subpages and section groups".

---

### Task 3: Subpages in the page list

**Files:**
- Modify: `web/src/api.ts` (the `Note` type gains `level?: 0 | 1 | 2`)
- Modify: `web/src/main.tsx`:
  - `notePayload` at about line 114
  - `readContainerObjects` page branch
  - `sectionPages` / `listEntries` at about lines 601-646
  - `movePage` at about line 1374
  - the list row render at about line 1848
  - `editor-actions` "Move page to section"
- Modify: `web/src/styles.css` (append)
- Modify: `web/src/notes.ts` only if the reconciliation helpers copy fields explicitly. Check that `editEntry`, `carrySaved` and `editOpenEntry` keep `level`.

**Interfaces:**
- Consumes: `displayLevels`, `blockRange`, `visibleRows`, `ancestors`, `shiftLevel`, `placeBlock` (Task 2) and `PagePayload.level` (Task 1).
- Produces:
  - `movePage(pageID: string, target: string, beforeID: string | null)`. It moves the block headed by `pageID` to just before page `beforeID` in the target section, or to the end when `beforeID` is null. All callers change to this signature.
  - `indentPage(pageID: string, delta: 1 | -1)`.

Requirements:

1. **Carry `level` through the save path.**
   - `notePayload` includes `level`.
   - The page branch of `readContainerObjects` copies `payload.level` into the `Note`.
   - `placePage` accepts `{ section?: string; order: string; level?: 0 | 1 | 2 }`. When `level` is undefined, keep the page's current level.

2. **Collapse state.**
   - State `collapsed: Set<string>`, loaded from `localStorage` key `kynotes-collapsed-${auth.user.id}-${selected.id}` when the notebook changes, and saved on every toggle.
   - Store a JSON array of page IDs. Ignore invalid JSON by treating it as empty.
   - Prune IDs that are no longer in `notes` when saving.

3. **List rendering.**
   - When not searching and not in queue mode, render `visibleRows(sectionPages, collapsed)` instead of the flat list.
   - Each row gets `style={{ paddingInlineStart: 12 + row.level * 16 }}` (or a `data-level` attribute with CSS rules).
   - A toggle button sits before the title only when `row.hasChildren`: `aria-expanded={!row.collapsed}`, `aria-label={`${row.collapsed ? "Expand" : "Collapse"} ${title}`}`, showing ▸/▾.
   - Search results and queue mode stay flat, as today.

4. **Indent and outdent.**
   - On a focused page row, `Tab` (without modifiers) calls `indentPage(id, 1)` and `Shift+Tab` calls `indentPage(id, -1)`. Call `preventDefault` only when the shift is allowed, so Tab still moves focus at the boundaries. A refused shift does nothing.
   - The row shows "Indent page" / "Outdent page" buttons in the `editor-actions` area for the open page, for touch users.
   - `indentPage` computes `displayLevels(sectionPages)` and then `shiftLevel`. It writes only that page's `level`, through `placePage(id, { section, order, level })` with the page's current section and order, serialized on `moveChain`.

5. **Moves carry blocks (`movePage`).**
   - On `moveChain`, read `notesRef.current` and `sectionsRef.current`. Find the source section list and the block with `blockRange(displayLevels(source), index)` (block levels come from those display levels).
   - The target list is the target section's pages minus the block. The insertion index is the position of `beforeID` in that list, or its length when `beforeID` is null.
   - Apply `placeBlock(...)` updates in order through `placePage`. Block pages get `section` = target and their `level`. Renumbered target pages keep their own section and level.
   - Callers:
     - Row drop: drop onto row R inserts before R's page when dragging up and after R's block when dragging down. Use the row's page ID and the block end to find `beforeID`.
     - Alt+ArrowUp: move before the previous visible sibling block's head.
     - Alt+ArrowDown: move after the next sibling block.
     - Drop on a section tab, or the "Move page to section" select: `beforeID = null`.

6. **Search and deep links into hidden pages.** When the selected page is hidden under collapsed ancestors (opened from search, resurfacing or a deep link), remove `ancestors(sectionPages, id)` from `collapsed`.

7. **Deleting a page** stays as it is. `displayLevels` re-reads its subpages one level up, and nothing else is written.

8. **Styles.** `.page-toggle` is a small quiet button. Keep the existing `.note-row-wrap.selected` styles.

- [ ] Implement 1–8. Add a vitest case in `web/src/notes.test.ts` if the reconciliation helpers needed changes for `level`.
- [ ] Run the checks: `npm test`, `npm run build`.
- [ ] Commit with the message "web: subpages with indent, collapse and block moves".

---

### Task 4: Section groups as tabs

**Files:**
- Modify: `web/src/main.tsx`:
  - `readContainerObjects`: replace Task 1's group skip
  - state next to `sections`
  - section handlers at about lines 1291-1372
  - the `<SectionTabs>` render at about line 1802
  - the hash route follower and `selectContainer` section resolution
- Modify: `web/src/components/SectionTabs.tsx`
- Modify: `web/src/styles.css` (append)

**Interfaces:**
- Consumes: `groupParents`, `sectionGroup`, `groupPath` (Task 2) and `Group`/`GroupPayload` (Task 1).
- Produces: `groupID: string | undefined`, the group whose tabs are shown, where undefined is the notebook root.

Requirements:

1. **Groups state.**
   - `groups: Group[]` with `groupsRef` and `patchGroups`, mirroring `sections`/`sectionsRef`/`patchSections` exactly, including the version carry in `drainQueue` and `carryDuringLoad`.
   - `readContainerObjects` returns `groups` too. `selectContainer`/`loadContainer` set them, and the stale-result guards apply.
   - `parents = useMemo(() => groupParents(groups), [groups])`.

2. **One structural write path.**
   - Generalize `updateSection(id, change)` into `updateStructure(kind: "section" | "group", id, change)`. Alternatively, add `updateGroup` with the identical chain logic, on `saveChain`, reading the ref at run time.
   - New groups are created with `createObject(selected.id, "folder")`.
   - The payload is `{type:"group", title:"New group", color, order: endOrder(siblings), group: groupID}`, with the order computed before `createObject`, as for sections.

3. **Tab strip (`SectionTabs`).**
   - New props:
     - `groups: Group[]`: child groups of the current group, sorted.
     - `path: Array<{ id: string | undefined; title: string }>`: the breadcrumb, starting with the notebook name and ending with the current group.
     - `onOpenGroup(id: string | undefined)`
     - `onCreateGroup()`
     - `onRenameGroup`, `onColorGroup`, `onMoveGroup(groupID, index)`, `onDeleteGroup(group)`
     - `onMoveIntoGroup(kind: "section" | "group", id, targetGroup: string | undefined)`
     - `allGroups: Array<{ id: string; label: string }>`: every group except the item's own subtree, labelled with its path, for the "Move into group…" select.
   - The strip shows the current group's sections, then child groups as `📁 title` tabs, then ＋. At the root, Quick Notes stays last among the sections.
   - ＋ opens a popover with "New section" and "New section group".
   - Clicking a group tab opens that group, via `onOpenGroup`.
   - The breadcrumb appears above the tabs only inside a group. Every item is a button; the last one is `aria-current="page"`.

4. **Group menu (⋯)** on the current group tab: Rename, colour swatches, Move left/right, "Move into group…" (a select), Delete group. The section ⋯ menu gains "Move into group…" too.

5. **Moving.**
   - Dropping a section tab on a group tab moves that section into the group: write its `group`, with `order = endOrder(target siblings)`.
   - Moving a group into a group is refused when the target is the group itself or inside its own subtree. Use `groupPath(target, parents).includes(id)`.

6. **Deleting a group.**
   - Confirm with: `Delete group "<title>"? Its sections and groups move up one level.`
   - First write every direct child section and group with `group = parents.get(deleted.id)`, then delete the folder object. If a child write fails, stop and keep the group. Nothing is lost.

7. **Selection.**
   - Selecting a section sets `groupID = sectionGroup(section, parents)`.
   - On notebook load and on hash routes, `groupID` comes from the routed section. Deep links stay `#/<container>/<section|quick>/<page>`, and `formatRoute`/`parseRoute` are unchanged.
   - Opening a group with no sections shows an empty strip with ＋ and a hint: "This group is empty. Add a section with ＋."

8. **Styles.** Group tabs share `.section-tab` styling, with a folder glyph and the `--tab-color` top border. `.section-breadcrumb` is a small line above the tabs. At 390px the breadcrumb wraps and the tabs scroll.

- [ ] Implement 1–8.
- [ ] Run the checks: `npm test`, `npm run build`.
- [ ] Commit with the message "web: section groups as nested tabs with a breadcrumb".

---

### Task 5: Docs, bundle and real-browser evidence

**Files:**
- `DESIGN.md`: the §3 Section/Page bullets
- `AGENTS.md`: the root `web/` bullets
- `UI-VERIFICATION.md`
- `internal/web/dist/**`
- `docs/subpages-*.png`

- [ ] **DOX.**
  - `DESIGN.md` §3: one sentence on page `level` and one on group objects and `group` fields, with the cap, cycle and missing-parent rule.
  - `AGENTS.md` `web/` bullet: subpages (`outline.ts`, display-only normalisation, block moves through `moveChain`) and groups (folder objects, `parents` resolution, delete reparents first). Name `outline.test.ts`.
- [ ] **Build and embed.** Run `npm test` and `npm run build`, then `rsync`, `diff -qr` (expect empty), `go test ./internal/web` and `gofmt`.
- [ ] **Real-browser pass.** Run Playwright against a localhost scratch server with throwaway data, at 1280×900 and 390×844, in light and dark. Check:
  - Tab/Shift+Tab and the menu indent and outdent, persisted after reload.
  - Collapse persists after reload.
  - Moving a parent by drag and by Alt+Arrow carries its block.
  - Moving a parent to another section clamps levels.
  - Deleting a parent keeps its subpages.
  - Search opens a hidden page and expands its ancestors.
  - Legacy pages open with no PUT.
  - Create nested groups three deep; the breadcrumb works.
  - Drop a section on a group tab.
  - Delete a middle group; its children move up.
  - A deep link to a section inside a group opens the right group.
  - Phone width.

  Save screenshots as `docs/subpages-{light,dark}-{desktop,mobile}.png` and `docs/section-groups.png`. Record each check's actual result in a dated `UI-VERIFICATION.md` section.
- [ ] **Commit** with the message "docs: subpages and section groups verification", including `internal/web/dist`.
