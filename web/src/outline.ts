import { keyBetween } from "./order";

export const MAX_LEVEL = 2;
export const MAX_GROUP_DEPTH = 4;
export type Level = 0 | 1 | 2;
type Leveled = { id: string; level?: number; section?: string };
type Ordered = { id: string; order?: string };

const clampLevel = (level: number | undefined) => Math.min(MAX_LEVEL, Math.max(0, level ?? 0)) as Level;

/** Pages from different stored sections (Quick Notes orphans of a deleted section) never nest under each other. */
const nests = (list: Leveled[], index: number) => index > 0 && list[index].section === list[index - 1].section;

/**
 * Display levels for an ordered page list: each page at most one deeper than the one before;
 * the first page, and a page whose stored section differs from the one before, are 0.
 */
export function displayLevels(list: Leveled[]): Level[] {
  const levels: Level[] = [];
  list.forEach((page, index) => levels.push(nests(list, index) ? Math.min(clampLevel(page.level), levels[index - 1] + 1) as Level : 0));
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
export function shiftLevel(list: Leveled[], index: number, delta: 1 | -1): Level | undefined {
  const levels = displayLevels(list);
  const next = levels[index] + delta;
  if (next < 0 || next > MAX_LEVEL) return undefined;
  if (delta === 1 && (!nests(list, index) || next > levels[index - 1] + 1)) return undefined;
  return next as Level;
}

/**
 * Updates that insert `block` (with its display `blockLevels`) into `target` at `index`.
 * The block keeps its relative levels and its head is clamped to fit the new spot.
 * One key per block page when the neighbours allow it; otherwise the whole list is
 * renumbered once (target pages then get an order-only update).
 */
export function placeBlock<T extends Ordered & Leveled>(target: T[], block: T[], blockLevels: number[], index: number): Array<{ id: string; order: string; level?: Level }> {
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
  const merged: Array<{ id: string; level?: Level }> = [
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

/** Levels of groups in the subtree headed by `id`, itself included. */
function subtreeHeight(id: string, parents: Map<string, string | undefined>): number {
  let height = 0;
  for (const [child, parent] of parents) if (parent === id) height = Math.max(height, subtreeHeight(child, parents));
  return height + 1;
}

/** Whether group `id` may move into `target` (undefined = root): not into its own subtree, not past MAX_GROUP_DEPTH. */
export function groupMoveAllowed(id: string, target: string | undefined, parents: Map<string, string | undefined>): boolean {
  const path = groupPath(target, parents);
  return !path.includes(id) && path.length + subtreeHeight(id, parents) <= MAX_GROUP_DEPTH;
}

/** "Move into group…" choices labelled "A › B", sorted by label; `moving` (a group) skips targets it may not enter. */
export function groupTargets(groups: Array<{ id: string; title: string }>, parents: Map<string, string | undefined>, moving?: string) {
  const titles = groupTitles(groups);
  return groups
    .filter((group) => moving === undefined || groupMoveAllowed(moving, group.id, parents))
    .map((group) => ({ id: group.id, label: groupPath(group.id, parents).map((id) => titles.get(id)).join(" › ") }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

/** "Move to section" choices labelled with their group path, "A › B › Section", sorted by label. */
export function sectionTargets(sections: Array<Grouped & { title: string }>, groups: Array<{ id: string; title: string }>, parents: Map<string, string | undefined>) {
  const titles = groupTitles(groups);
  return sections
    .map((section) => ({
      id: section.id,
      label: [...groupPath(sectionGroup(section, parents), parents).map((id) => titles.get(id)), section.title || "Untitled section"].join(" › "),
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

const groupTitles = (groups: Array<{ id: string; title: string }>) => new Map(groups.map((group) => [group.id, group.title || "Untitled group"]));

/** Group holding section `id`; Quick Notes and unknown sections are at the root. */
export function groupOfSection(id: string, sections: Grouped[], parents: Map<string, string | undefined>): string | undefined {
  const section = sections.find((entry) => entry.id === id);
  return section ? sectionGroup(section, parents) : undefined;
}

/** Alt+Arrow: index of the page to move the block at `index` before (list length = end), or undefined without a sibling that way. */
export function siblingMove(levels: number[], index: number, delta: 1 | -1): number | undefined {
  const level = levels[index];
  if (delta === -1) {
    let i = index - 1;
    while (i >= 0 && levels[i] > level) i -= 1;
    return i >= 0 && levels[i] === level ? i : undefined;
  }
  const next = blockRange(levels, index)[1];
  return levels[next] === level ? blockRange(levels, next)[1] : undefined;
}

/** Drop of the block at `from` onto row `at`: before it dragging up, after its block dragging down; undefined inside the dragged block. */
export function dropBefore(levels: number[], from: number, at: number): number | undefined {
  const [start, end] = blockRange(levels, from);
  if (at >= start && at < end) return undefined;
  return at < from ? at : blockRange(levels, at)[1];
}

/** Collapsed page ids saved as a JSON array; anything else is empty. */
export function parseCollapsed(raw: string | null): Set<string> {
  try {
    const value: unknown = JSON.parse(raw ?? "[]");
    return new Set(Array.isArray(value) ? value.filter((id): id is string => typeof id === "string") : []);
  } catch {
    return new Set();
  }
}
