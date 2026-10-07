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
