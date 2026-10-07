import { isOrderKey, keyBetween } from "./order";
import { blockRange, displayLevels } from "./outline";

export const QUICK_NOTES = "quick";
export const SECTION_COLORS = ["orange", "blue", "green", "purple", "red", "teal", "yellow", "gray"] as const;
export type SectionColor = (typeof SECTION_COLORS)[number];
export type SectionPayload = { type: "section"; title: string; color: SectionColor; order?: string; group?: string };
export type GroupPayload = { type: "group"; title: string; color: SectionColor; order?: string; group?: string };
export type PagePayload = { type: "page"; title: string; body: string; section?: string; order?: string; level?: 0 | 1 | 2 };
export type ObjectPayload = SectionPayload | GroupPayload | PagePayload;
export type Section = SectionPayload & { id: string; version: number };
export type Group = GroupPayload & { id: string; version: number };
type Placed = { id: string; section?: string; order?: string; level?: number };

// Crockford base32, lowercase, as minted by internal/ids.
const OBJECT_ID = /^obj_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const CONTAINER_ID = /^cnt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;

/** Decrypted object JSON is untrusted: narrow it here and nowhere else. */
export function parseObjectPayload(value: unknown): ObjectPayload | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  const order = isOrderKey(v.order) ? v.order : undefined;
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
  if (typeof v.body !== "string") return undefined;
  const page: PagePayload = { type: "page", title: typeof v.title === "string" ? v.title : "", body: v.body };
  if ("section" in v) page.section = typeof v.section === "string" && OBJECT_ID.test(v.section) ? v.section : undefined;
  if ("order" in v) page.order = order;
  if ("level" in v) page.level = v.level === 0 || v.level === 1 || v.level === 2 ? v.level : undefined;
  return page;
}

export function compareOrdered(a: { id: string; order?: string }, b: { id: string; order?: string }): number {
  if (a.order && b.order && a.order !== b.order) return a.order < b.order ? -1 : 1;
  if (Boolean(a.order) !== Boolean(b.order)) return a.order ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export const sortedSections = (sections: Section[]) => [...sections].sort(compareOrdered);

/** Quick Notes holds pages with no section or a section that no longer exists. */
export function pagesInSection<T extends Placed>(pages: T[], sections: Section[], sectionID: string): T[] {
  const known = new Set(sections.map((section) => section.id));
  return pages
    .filter((page) => (sectionID === QUICK_NOTES ? !page.section || !known.has(page.section) : page.section === sectionID))
    .sort(compareOrdered);
}

export function endOrder(list: Array<{ order?: string }>): string {
  const last = list.reduce<string | null>((max, item) => (item.order && (max === null || item.order > max) ? item.order : max), null);
  return keyBetween(last, null);
}

/**
 * Order updates that put `movedID` at `index` of `list` (its position once removed).
 * One write when the neighbours have distinct keys; otherwise the list is renumbered once,
 * which also repairs legacy unordered pages, concurrent ties and over-long keys.
 */
export function reorder<T extends { id: string; order?: string }>(list: T[], movedID: string, index: number): Array<{ id: string; order: string }> {
  const rest = list.filter((item) => item.id !== movedID);
  const at = Math.max(0, Math.min(index, rest.length));
  if (rest.every((item) => item.order)) {
    try {
      return [{ id: movedID, order: keyBetween(rest[at - 1]?.order ?? null, rest[at]?.order ?? null) }];
    } catch { /* tie or exhausted key: renumber below */ }
  }
  let order: string | null = null;
  return [...rest.slice(0, at), { id: movedID }, ...rest.slice(at)].map((item) => {
    order = keyBetween(order, null);
    return { id: item.id, order };
  });
}

/**
 * A rejected version kept as a new page right after `original` in `list` (its visible section).
 * `moves` holds any renumbered neighbours, never the copy itself.
 */
export function conflictCopy<T extends Placed>(list: T[], original: T, rejected: { title: string; body: string }) {
  // Placed before the object exists, so an exhausted key never leaves an empty page behind.
  const copyID = "";
  // After the original's whole block, at the original's level, so its subpages stay its own.
  const levels = displayLevels(list);
  const index = list.findIndex((item) => item.id === original.id);
  const updates = reorder(list, copyID, index < 0 ? list.length : blockRange(levels, index)[1]);
  const page: PagePayload = {
    type: "page",
    title: `${rejected.title || "Untitled page"} (conflicting copy)`,
    body: rejected.body,
    section: original.section,
    order: updates.find((update) => update.id === copyID)?.order,
    level: index < 0 ? undefined : levels[index] as 0 | 1 | 2,
  };
  return { page, moves: updates.filter((update) => update.id !== copyID) };
}

/**
 * One copy per distinct rejected text, oldest first; text equal to the server page needs none.
 * Placement is ignored: a copy always takes the original's, so it cannot tell copies apart.
 */
export function groupConflicts(server: { title: string; body: string }, rejected: Array<{ id: string; createdAt: string; payload: PagePayload }>) {
  const text = (page: { title: string; body: string }) => JSON.stringify([page.title, page.body]);
  const resolveOnly: string[] = [];
  const groups = new Map<string, { payload: PagePayload; ids: string[] }>();
  for (const item of [...rejected].sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))) {
    const key = text(item.payload);
    const group = groups.get(key);
    if (key === text(server)) resolveOnly.push(item.id);
    else if (group) group.ids.push(item.id);
    else groups.set(key, { payload: item.payload, ids: [item.id] });
  }
  return { resolveOnly, groups: [...groups.values()] };
}

export function resolveSection(id: string | undefined, sections: Section[]): string {
  if (id === QUICK_NOTES || (id && sections.some((section) => section.id === id))) return id;
  return sortedSections(sections)[0]?.id ?? QUICK_NOTES;
}

export type Route = { container?: string; section?: string; page?: string };

export function parseRoute(hash: string): Route {
  const [container = "", section = "", page = ""] = hash.replace(/^#\/?/, "").split("/");
  return {
    container: CONTAINER_ID.test(container) ? container : undefined,
    section: section === QUICK_NOTES || OBJECT_ID.test(section) ? section : undefined,
    page: OBJECT_ID.test(page) ? page : undefined,
  };
}

export function formatRoute({ container, section, page }: Route): string {
  if (!container) return "";
  return `#/${[container, section, section ? page : undefined].filter(Boolean).join("/")}`;
}
