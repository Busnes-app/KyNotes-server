# OneNote Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Notebooks → colored section tabs → manually ordered page list, with deep links, in the KyNotes web client.

**Architecture:** Sections are encrypted `folder` objects. Pages are encrypted `note` objects that record their own section ID and fractional order key. The client merges them at read time; there is no shared manifest. Pure logic (`order.ts`, `pages.ts`) is unit-tested. `main.tsx` only wires state and calls it. There are no server changes.

**Tech Stack:** React 19, TypeScript, Vite, vitest (node environment, no DOM library), native HTML drag-and-drop and the `popover` attribute.

**Spec:** `docs/superpowers/specs/2026-10-06-onenote-notebooks-and-canvas-pages.md`

## Global Constraints

- No server, API or migration changes. Sections use the existing frozen object kind `folder`.
- Nothing about structure reaches the server in plaintext. Section titles, colors, order keys and page placement live only inside `kynotes/object/v1` ciphertext. Routes live in the URL hash, which the browser never sends.
- Every decrypted payload is untrusted input and goes through `parseObjectPayload`. Nothing reads the raw JSON directly.
- Order keys compare with `<` / `>` (code-unit order), never `localeCompare`.
- Deleting a section never deletes or rewrites its pages. They fall into Quick Notes.
- Keep the list/editor layout (`kynotes-server/AGENTS.md` user preference). Section tabs sit above it. Selected navigation uses `ky-nav-item` and shared tokens (`--accent`, `--accent-soft`, `--line`, `--panel`, `--ink-strong`).
- Do not hand-edit `web/src/ky-ui/`.
- Verification commands, run from `web/`: `npm test`, `npm run build`. From the repo root: `go test ./internal/web` and `diff -qr web/dist internal/web/dist`.

## Review Focus

1. **A page whose section was deleted on another device.** It must appear under Quick Notes, not vanish. Pinned in Task 2 (`pagesInSection` test).
2. **Two devices insert at the same spot and produce identical order keys.** Both pages must show, ordered by ID, and a later reorder between them must still work. Pinned in Task 2 (`reorder` tie test).
3. **Malformed or hostile decrypted payloads** (wrong types, a 10 MB order string, an unknown `type`). They must parse to safe defaults or be skipped, never throw or render garbage. Pinned in Task 2 (`parseObjectPayload` tests).
4. **Moving a page that is not open and has a newer local draft** (offline queue or unsaved switch). The move must carry the draft, never resurrect the older server body. Covered by `latestLocal` in Task 3 and the manual check in Task 7.
5. **A stale or foreign deep link** (deleted page, another user's container, garbage hash). It must land on the first notebook or section without an error loop. Pinned in Task 2 (`parseRoute`/`resolveSection` tests).

---

### Task 1: Fractional order keys

**Files:**
- Create: `web/src/order.ts`
- Test: `web/src/order.test.ts`

**Interfaces:**
- Produces: `MAX_ORDER_KEY = 512`, `isOrderKey(value: unknown): value is string`, `keyBetween(before: string | null, after: string | null): string`. It throws `Error("order keys out of order")` when `before >= after` and `Error("order key limit reached")` past 512 characters.

- [ ] **Step 1: Write the failing test**

```ts
// web/src/order.test.ts
import { describe, expect, it } from "vitest";
import { MAX_ORDER_KEY, isOrderKey, keyBetween } from "./order";

describe("order keys", () => {
  it("sorts every random insertion between its neighbours", () => {
    const keys: string[] = [];
    for (let n = 0; n < 5000; n += 1) {
      const i = Math.floor(Math.random() * (keys.length + 1));
      const key = keyBetween(keys[i - 1] ?? null, keys[i] ?? null);
      expect(isOrderKey(key)).toBe(true);
      if (i > 0) expect(keys[i - 1] < key).toBe(true);
      if (i < keys.length) expect(key < keys[i]).toBe(true);
      keys.splice(i, 0, key);
    }
  });

  it("grows slowly for repeated appends and prepends", () => {
    let last: string | null = null;
    for (let n = 0; n < 2000; n += 1) last = keyBetween(last, null);
    expect(last!.length).toBeLessThan(80);
    let first: string | null = null;
    for (let n = 0; n < 2000; n += 1) first = keyBetween(null, first);
    expect(first!.length).toBeLessThan(80);
  });

  it("refuses inverted or equal bounds", () => {
    expect(() => keyBetween("b", "a")).toThrow("order keys out of order");
    expect(() => keyBetween("b", "b")).toThrow("order keys out of order");
  });

  it("stops at the length cap instead of producing an invalid key", () => {
    const low = keyBetween(null, null);
    let high = keyBetween(low, null);
    expect(() => { for (;;) high = keyBetween(low, high); }).toThrow("order key limit reached");
    expect(high.length).toBeLessThanOrEqual(MAX_ORDER_KEY);
  });

  it("rejects keys a client must never produce", () => {
    for (const bad of ["", "a0", "A", "a-b", 7, null, "z".repeat(MAX_ORDER_KEY + 1)]) expect(isOrderKey(bad)).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/order.test.ts`
Expected: FAIL, "Failed to resolve import ./order".

- [ ] **Step 3: Write minimal implementation**

```ts
// web/src/order.ts
// Fractional order keys: base-36 fractions compared as plain strings. A key never ends
// in "0", so there is always room for another key between two distinct keys.
const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";
const KEY = /^[0-9a-z]*[1-9a-z]$/;
export const MAX_ORDER_KEY = 512;

export const isOrderKey = (value: unknown): value is string =>
  typeof value === "string" && value.length <= MAX_ORDER_KEY && KEY.test(value);

/** Returns a key strictly between `before` and `after` (null = open end). */
export function keyBetween(before: string | null, after: string | null): string {
  const a = before ?? "";
  let b = after;
  if (b !== null && a >= b) throw new Error("order keys out of order");
  let out = "";
  for (let i = 0; ; i += 1) {
    const low = i < a.length ? DIGITS.indexOf(a[i]) : 0;
    const high = b === null ? DIGITS.length : DIGITS.indexOf(b[i]);
    if (low === high) { out += DIGITS[low]; continue; }
    // Step one digit at an open end so repeated appends/prepends grow keys slowly.
    const pick = before !== null && after === null ? low + 1
      : before === null && after !== null ? high - 1
      : Math.floor((low + high) / 2);
    if (pick > low && pick < high) {
      const key = out + DIGITS[pick];
      if (key.length > MAX_ORDER_KEY) throw new Error("order key limit reached");
      return key;
    }
    out += DIGITS[low];
    b = null;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run src/order.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add web/src/order.ts web/src/order.test.ts
git commit -m "web: add fractional order keys for sections and pages"
```

---

### Task 2: Page model, placement and routes (pure)

**Files:**
- Create: `web/src/pages.ts`
- Test: `web/src/pages.test.ts`

**Interfaces:**
- Consumes: `isOrderKey`, `keyBetween` (Task 1).
- Produces:
  - `QUICK_NOTES = "quick"`
  - `SECTION_COLORS` (readonly tuple) and `type SectionColor`
  - `type SectionPayload = { type: "section"; title: string; color: SectionColor; order?: string }`
  - `type PagePayload = { type: "page"; title: string; body: string; section?: string; order?: string }`
  - `type ObjectPayload = SectionPayload | PagePayload`
  - `type Section = SectionPayload & { id: string; version: number }`
  - `parseObjectPayload(value: unknown): ObjectPayload | undefined`
  - `compareOrdered(a, b): number`
  - `pagesInSection<T extends Placed>(pages: T[], sections: Section[], sectionID: string): T[]`
  - `sortedSections(sections: Section[]): Section[]`
  - `endOrder(list: Array<{ order?: string }>): string`
  - `reorder(list, movedID, index): Array<{ id: string; order: string }>`
  - `resolveSection(id: string | undefined, sections: Section[]): string`
  - `type Route = { container?: string; section?: string; page?: string }`
  - `parseRoute(hash: string): Route` and `formatRoute(route: Route): string`

- [ ] **Step 1: Write the failing test**

```ts
// web/src/pages.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/pages.test.ts`
Expected: FAIL, "Failed to resolve import ./pages".

- [ ] **Step 3: Write minimal implementation**

```ts
// web/src/pages.ts
import { isOrderKey, keyBetween } from "./order";

export const QUICK_NOTES = "quick";
export const SECTION_COLORS = ["orange", "blue", "green", "purple", "red", "teal", "yellow", "gray"] as const;
export type SectionColor = (typeof SECTION_COLORS)[number];
export type SectionPayload = { type: "section"; title: string; color: SectionColor; order?: string };
export type PagePayload = { type: "page"; title: string; body: string; section?: string; order?: string };
export type ObjectPayload = SectionPayload | PagePayload;
export type Section = SectionPayload & { id: string; version: number };
type Placed = { id: string; section?: string; order?: string };

// Crockford base32, lowercase, as minted by internal/ids.
const OBJECT_ID = /^obj_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const CONTAINER_ID = /^cnt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;

/** Decrypted object JSON is untrusted: narrow it here and nowhere else. */
export function parseObjectPayload(value: unknown): ObjectPayload | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  const order = isOrderKey(v.order) ? v.order : undefined;
  if (v.type === "section") {
    return {
      type: "section",
      title: typeof v.title === "string" ? v.title : "Untitled section",
      color: SECTION_COLORS.includes(v.color as SectionColor) ? (v.color as SectionColor) : "gray",
      order,
    };
  }
  if (typeof v.body !== "string") return undefined;
  const page: PagePayload = { type: "page", title: typeof v.title === "string" ? v.title : "", body: v.body };
  if ("section" in v) page.section = typeof v.section === "string" && OBJECT_ID.test(v.section) ? v.section : undefined;
  if ("order" in v) page.order = order;
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run src/pages.test.ts`
Expected: PASS (15 tests). Tasks 1–2 code and tests were run verbatim under this repo's vitest and `tsc` config while the plan was written: 20 tests passed and the typecheck was clean.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages.ts web/src/pages.test.ts
git commit -m "web: add section/page model, placement and hash routes"
```

---

### Task 3: Read and write sections and placed pages

Plumbing in `api.ts`, `crypto.ts` and `main.tsx`. There is no UI yet, so the app looks the same afterwards, but the payloads now carry placement. It also fixes a pre-existing loss path: switching pages within 900 ms of an edit skipped that page's server save.

**Files:**
- Modify: `web/src/api.ts` (`Note` type at line 9, `createObject` at about line 140)
- Modify: `web/src/crypto.ts` (`encryptNote` at about line 194; add `decryptObject`)
- Modify: `web/src/main.tsx` (`Workspace` state at about line 514, `readContainerNotes` at about line 767, `selectContainer` at about line 806, `openWorkQueue`, `selectNote` at about line 863, `newNote` at about line 1002, `saveNow` at about line 1027, `drainQueue` at about line 1120, `persistDraft` at about line 1170)
- Test: `web/src/crypto.test.ts`

**Interfaces:**
- Consumes: everything from Task 2.
- Produces, for Tasks 4–6, all inside `Workspace`:
  - state `sections: Section[]` (always set through `patchSections`) and `sectionID: string`
  - `notePayload(note: Note): PagePayload` (module level)
  - `writeObject(id: string, version: number, payload: ObjectPayload): Promise<number | null>`
  - `updateSection(id: string, change: Partial<SectionPayload>): Promise<void>`
  - `placePage(id: string, change: { section?: string; order: string }): Promise<void>`
  - `readContainerObjects(container): Promise<{ notes: Note[]; sections: Section[] }>`
  - `selectContainer(container, route?: Route): Promise<Note[]>`
  - `api.ts`: `Note` gains `section?: string; order?: string`, and `createObject(containerID, kind: "note" | "folder" = "note")`
  - `crypto.ts`: `decryptObject(authSecret, containerID, bytes): Promise<ObjectPayload | undefined>`

- [ ] **Step 1: Write the failing test**

Append to `web/src/crypto.test.ts` and add `decryptObject` to its existing `./crypto` import. `authSecret` is hex; the fixture is the file's existing one.

```ts
describe("object payloads", () => {
  const secret = "b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d";
  const cnt = "cnt_test";
  it("round-trips a placed page and a section through the object key", async () => {
    const page = { type: "page" as const, title: "T", body: "b", section: `obj_${"b".repeat(26)}`, order: "i" };
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, page))).toEqual(page);
    const section = { type: "section" as const, title: "S", color: "teal" as const, order: "r" };
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, section))).toEqual(section);
  });
  it("returns undefined for a payload that decrypts but is not an object payload", async () => {
    expect(await decryptObject(secret, cnt, await encryptNote(secret, cnt, [] as never))).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/crypto.test.ts`
Expected: FAIL, "decryptObject is not a function" or an import error.

- [ ] **Step 3: Implement crypto and API changes**

In `web/src/crypto.ts`, add `import { parseObjectPayload, type ObjectPayload } from "./pages";` at the top. Then replace `encryptNote`'s signature and add `decryptObject` directly below `decryptNote`:

```ts
export async function encryptNote(authSecret: string, containerID: string, note: NotePayload | ObjectPayload): Promise<Uint8Array> {
```

```ts
/** Decrypts any object (page or section); undefined when the plaintext is not a valid payload. */
export async function decryptObject(authSecret: string, containerID: string, bytes: Uint8Array): Promise<ObjectPayload | undefined> {
  return parseObjectPayload(await decryptWithInfo(authSecret, containerID, "kynotes/object/v1", bytes));
}
```

In `web/src/api.ts`:

```ts
export type Note = { id: string; title: string; body: string; version: number; updatedAt: string; section?: string; order?: string };
```

```ts
export async function createObject(containerID: string, kind: "note" | "folder" = "note") {
  return request<{ id: string; version: number; changeSeq: number }>(
    `/api/v1/containers/${encodeURIComponent(containerID)}/objects`, {
      method: "POST", body: JSON.stringify({ kind }),
    },
  );
}
```

Run: `cd web && npx vitest run src/crypto.test.ts`. Expected: PASS.

- [ ] **Step 4: Wire `main.tsx` reads**

Imports. Add `decryptObject` to the `./crypto` import list. Add:

```ts
import { QUICK_NOTES, endOrder, pagesInSection, resolveSection, type ObjectPayload, type PagePayload, type Route, type Section, type SectionPayload } from "./pages";
```

At module level, near `MAX_CHANGE_PAGES`:

```ts
const notePayload = (note: Note): PagePayload =>
  ({ type: "page", title: note.title, body: note.body, section: note.section, order: note.order });
```

State, next to `notes`:

```ts
  const [sections, setSections] = useState<Section[]>([]);
  const sectionsRef = useRef<Section[]>([]);
  // Writes read sectionsRef synchronously, so every change goes through here.
  const patchSections = (update: (value: Section[]) => Section[]) => {
    sectionsRef.current = update(sectionsRef.current);
    setSections(sectionsRef.current);
  };
  const [sectionID, setSectionID] = useState<string>(QUICK_NOTES);
  const notesRef = useRef<Note[]>([]);
  notesRef.current = notes;
```

Rename `readContainerNotes` to `readContainerObjects`. Its loop body decrypts with `decryptObject` and splits sections from pages. Replace the whole function with:

```ts
  async function readContainerObjects(container: Container): Promise<{ notes: Note[]; sections: Section[] }> {
    const loaded: Note[] = [];
    const found: Section[] = [];
    const add = (id: string, payload: ObjectPayload | undefined, version: number, updatedAt: string) => {
      if (!payload) return;
      if (payload.type === "section") found.push({ ...payload, id, version });
      else loaded.push({ id, title: payload.title, body: payload.body, section: payload.section, order: payload.order, version, updatedAt });
    };
    let since = 0;
    for (let page = 0; page < MAX_CHANGE_PAGES; page += 1) {
      const result = await changes(container.id, since);
      for (const change of result.changes.filter((entry) => entry.kind === "object" && !entry.deleted)) {
        try {
          const object = await readObject(change.id);
          const cached = await getNote(change.id);
          const useCache = Boolean(cached && cached.version >= object.version);
          const payload = await decryptObject(auth.authSecret, container.id, useCache ? cached!.payload : object.bytes);
          add(change.id, payload, useCache ? cached!.version : object.version, useCache ? cached!.updatedAt : new Date().toISOString());
        } catch {
          const cached = await getNote(change.id);
          if (cached) {
            try {
              add(change.id, await decryptObject(auth.authSecret, container.id, cached.payload), cached.version, cached.updatedAt);
            } catch {
              /* Ignore an invalid local draft. */
            }
          }
        }
      }
      if (!result.hasMore) break;
      const next = Number(result.nextCursor);
      if (!Number.isSafeInteger(next) || next <= since) break;
      since = next;
    }
    return { notes: loaded, sections: found };
  }
```

In `selectContainer`:
- Change the signature to `async function selectContainer(container: Container, route?: Route): Promise<Note[]>`.
- Replace `loaded = await readContainerNotes(container); setNotes(loaded);` with:

```ts
      const objects = await readContainerObjects(container);
      loaded = objects.notes;
      setNotes(loaded);
      patchSections(() => objects.sections);
      setSectionID(resolveSection(route?.section, objects.sections));
      const routed = route?.page ? loaded.find((note) => note.id === route.page) : undefined;
      if (routed) await selectNote(routed, container.id);
```

In `openWorkQueue`, change `notes: await readContainerNotes(container),` to `notes: (await readContainerObjects(container)).notes,`.

- [ ] **Step 5: Wire `main.tsx` writes**

In `saveNow`, replace `const payload: NotePayload = { title: note.title, body: note.body };` with `const payload = notePayload(note);`. Also change the `setNotes` match condition (`entry.body === note.body && entry.title === note.title`) to:

```ts
            entry.id === saved.id && entry.body === note.body && entry.title === note.title &&
              entry.section === note.section && entry.order === note.order
```

In `persistDraft`, replace the `{ title: note.title, body: note.body }` argument with `notePayload(note)`. Remove the now-unused `NotePayload` import from `main.tsx` only if nothing else uses it; `shareNote` still builds `{title, body}` literally, which is fine.

At the start of `selectNote`, flush the open page so a quick switch cannot strand its last edit:

```ts
    const previous = selectedNoteRef.current;
    if (previous && previous.id !== note.id && dirty) await save(previous, true);
```

In `newNote`, place the page in the current section at the end:

```ts
      const note: Note = {
        id: object.id,
        title: "Untitled page",
        body: stringifyNoteDocument(emptyNoteDocument().document),
        section: sectionID === QUICK_NOTES ? undefined : sectionID,
        order: endOrder(pagesInSection(notes, sections, sectionID)),
        version: 0,
        updatedAt: new Date().toISOString(),
      };
```

In `drainQueue`, after the existing `setNotes(...)` success line, add:

```ts
          patchSections((value) => value.map((entry) => entry.id === item.id ? { ...entry, version: result.version } : entry));
```

Add these functions inside `Workspace` after `persistDraft`:

```ts
  /** Encrypted write for an object that is not the open page (sections, moved pages). */
  async function writeObject(id: string, version: number, payload: ObjectPayload): Promise<number | null> {
    if (!selected) return null;
    const encrypted = await encryptNote(auth.authSecret, selected.id, payload);
    const updatedAt = new Date().toISOString();
    await putNote({ id, containerID: selected.id, version, payload: encrypted, updatedAt });
    try {
      const result = await saveObject(id, encrypted, version, selected.keyGeneration);
      await clearQueuedSave(id);
      return result.version;
    } catch (error) {
      if (error instanceof APIRequestError && error.code === "version_conflict") {
        setConflicted((value) => new Set(value).add(id));
        setSyncStatus("attention");
        setError("This item changed on another device. Reopen the notebook before changing it again.");
      } else {
        await queueSave({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: selected.keyGeneration });
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
      }
      return null;
    }
  }

  function updateSection(id: string, change: Partial<SectionPayload>) {
    patchSections((value) => value.map((entry) => (entry.id === id ? { ...entry, ...change } : entry)));
    const queued = saveChain.current.then(async () => {
      const current = sectionsRef.current.find((entry) => entry.id === id);
      if (!current) return;
      const { id: _id, version, ...payload } = current;
      const saved = await writeObject(id, version, payload);
      if (saved !== null) patchSections((value) => value.map((entry) => (entry.id === id ? { ...entry, version: saved } : entry)));
    });
    saveChain.current = queued.catch(() => {});
    return queued;
  }

  /** The newest local copy of a page: an offline draft may be ahead of `notes`. */
  async function latestLocal(note: Note, containerID: string): Promise<Note> {
    const cached = await getNote(note.id);
    if (!cached || cached.version < note.version) return note;
    const payload = await decryptObject(auth.authSecret, containerID, cached.payload).catch(() => undefined);
    return payload?.type === "page" ? { ...note, title: payload.title, body: payload.body } : note;
  }

  async function placePage(id: string, change: { section?: string; order: string }) {
    const open = selectedNoteRef.current;
    if (open?.id === id) {
      const next = { ...open, ...change };
      selectedNoteRef.current = next;
      setSelectedNote(next);
      setNotes((value) => value.map((entry) => (entry.id === id ? { ...entry, ...change } : entry)));
      await save(next, true);
      return;
    }
    const entry = notesRef.current.find((note) => note.id === id);
    if (!entry || !selected) return;
    const next = { ...(await latestLocal(entry, selected.id)), ...change };
    setNotes((value) => value.map((note) => (note.id === id ? next : note)));
    const saved = await writeObject(id, next.version, notePayload(next));
    if (saved !== null) setNotes((value) => value.map((note) => (note.id === id ? { ...note, version: saved } : note)));
  }
```

Replace every remaining `readContainerNotes` reference. Run `grep -n readContainerNotes web/src/main.tsx` and expect no output.

- [ ] **Step 6: Run the checks**

Run: `cd web && npm test && npm run build`
Expected: all tests pass and `tsc --noEmit` is clean (`noUnusedLocals` is on, so each task imports only the names it uses).

- [ ] **Step 7: Commit**

```bash
git add web/src/api.ts web/src/crypto.ts web/src/crypto.test.ts web/src/main.tsx
git commit -m "web: read and write sections and placed pages"
```

---

### Task 4: Section tabs

**Files:**
- Create: `web/src/components/SectionTabs.tsx`
- Modify: `web/src/main.tsx` (render between `</aside>` and `<section className="note-list">`; add section handlers)
- Modify: `web/src/styles.css` (append)

**Interfaces:**
- Consumes: `sections`, `sectionID`, `setSectionID`, `updateSection`, `patchSections`, `writeObject`, `placePage` (Task 3); `QUICK_NOTES`, `SECTION_COLORS`, `sortedSections`, `pagesInSection`, `endOrder`, `reorder` (Task 2).
- Produces: `PAGE_DRAG = "application/x-kynotes-page"`, exported from `SectionTabs.tsx`. Task 5 sets it on page rows.

- [ ] **Step 1: Create the component**

```tsx
// web/src/components/SectionTabs.tsx
import { QUICK_NOTES, SECTION_COLORS, type Section, type SectionColor } from "../pages";

export const PAGE_DRAG = "application/x-kynotes-page";
const SECTION_DRAG = "application/x-kynotes-section";

type Props = {
  sections: Section[]; // already sorted
  current: string;
  busy: boolean;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (section: Section) => void;
  onColor: (section: Section, color: SectionColor) => void;
  onDelete: (section: Section) => void;
  onMove: (sectionID: string, index: number) => void;
  onDropPage: (pageID: string, sectionID: string) => void;
};

export function SectionTabs({ sections, current, busy, onSelect, onCreate, onRename, onColor, onDelete, onMove, onDropPage }: Props) {
  const accept = (event: React.DragEvent) => {
    const types = event.dataTransfer.types;
    if (types.includes(PAGE_DRAG) || types.includes(SECTION_DRAG)) event.preventDefault();
  };
  const drop = (event: React.DragEvent, sectionID: string, index: number) => {
    const page = event.dataTransfer.getData(PAGE_DRAG);
    const section = event.dataTransfer.getData(SECTION_DRAG);
    if (page) onDropPage(page, sectionID);
    else if (section && sectionID !== QUICK_NOTES) onMove(section, index);
    event.preventDefault();
  };
  const tab = (id: string, title: string, color: SectionColor, index: number, section?: Section) => (
    <li key={id} className="section-tab-item">
      <button
        className={`ky-nav-item section-tab ${current === id ? "selected" : ""}`}
        aria-current={current === id ? "page" : undefined}
        style={{ "--tab-color": `var(--section-${color})` } as React.CSSProperties}
        draggable={Boolean(section)}
        onDragStart={(event) => event.dataTransfer.setData(SECTION_DRAG, id)}
        onDragOver={accept}
        onDrop={(event) => drop(event, id, index)}
        onClick={() => onSelect(id)}
      >
        {title || "Untitled section"}
      </button>
      {section && current === id && (
        <>
          <button className="section-tab-menu" popoverTarget={`section-menu-${id}`} aria-label={`Section options for ${title}`}>⋯</button>
          <div className="section-menu" id={`section-menu-${id}`} popover="auto">
            <button disabled={busy} onClick={() => onRename(section)}>Rename</button>
            <div className="section-colors" role="group" aria-label="Section color">
              {SECTION_COLORS.map((choice) => (
                <button
                  key={choice}
                  className="section-swatch"
                  aria-label={choice}
                  aria-pressed={section.color === choice}
                  style={{ background: `var(--section-${choice})` }}
                  onClick={() => onColor(section, choice)}
                />
              ))}
            </div>
            <button disabled={index === 0} onClick={() => onMove(id, index - 1)}>Move left</button>
            <button disabled={index === sections.length - 1} onClick={() => onMove(id, index + 1)}>Move right</button>
            <button className="danger" onClick={() => onDelete(section)}>Delete section</button>
          </div>
        </>
      )}
    </li>
  );
  return (
    <nav className="section-tabs" aria-label="Sections">
      <ul role="list">
        {sections.map((section, index) => tab(section.id, section.title, section.color, index, section))}
        {tab(QUICK_NOTES, "Quick Notes", "gray", sections.length)}
      </ul>
      <button className="section-add" disabled={busy} onClick={onCreate} aria-label="New section">＋</button>
    </nav>
  );
}
```

If `tsc` rejects `popoverTarget` or `popover` (an older `@types/react`), check `npm ls @types/react`. The plan assumes 19.2, which types both.

- [ ] **Step 2: Add the handlers in `Workspace`**

Add these after `placePage`:

```ts
  const orderedSections = useMemo(() => sortedSections(sections), [sections]);
  async function newSection() {
    if (!selected) return;
    setBusy(true);
    try {
      const object = await createObject(selected.id, "folder");
      const section: Section = {
        id: object.id, version: object.version, type: "section", title: "New section",
        color: SECTION_COLORS[sections.length % SECTION_COLORS.length], order: endOrder(sections),
      };
      patchSections((value) => [...value, section]);
      setSectionID(section.id);
      await updateSection(section.id, {});
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to create section");
    } finally {
      setBusy(false);
    }
  }
  function renameSection(section: Section) {
    const title = prompt("Section name", section.title)?.trim();
    if (title) void updateSection(section.id, { title });
  }
  async function removeSection(section: Section) {
    const count = pagesInSection(notes, sections, section.id).length;
    if (!confirm(`Delete section "${section.title}"? Its ${count} page${count === 1 ? "" : "s"} will move to Quick Notes.`)) return;
    try {
      await deleteObject(section.id);
      await deleteCachedNote(section.id);
      patchSections((value) => value.filter((entry) => entry.id !== section.id));
      setSectionID(QUICK_NOTES);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to delete section");
    }
  }
  async function moveSection(id: string, index: number) {
    for (const update of reorder(orderedSections, id, index)) await updateSection(update.id, { order: update.order });
  }
  async function movePage(pageID: string, target: string, index: number) {
    const list = pagesInSection(notes, sections, target);
    const section = target === QUICK_NOTES ? undefined : target;
    for (const update of reorder(list, pageID, index)) {
      const entry = notes.find((note) => note.id === update.id);
      await placePage(update.id, { section: update.id === pageID ? section : entry?.section, order: update.order });
    }
  }
```

Import `SectionTabs` from `./components/SectionTabs` (Task 5 adds `PAGE_DRAG` to that import). Add `SECTION_COLORS`, `reorder` and `sortedSections` to the `./pages` import.

- [ ] **Step 3: Render the tabs**

Place this between `</aside>` and `<section className="note-list">`:

```tsx
          {selected && !queueMode && (
            <SectionTabs
              sections={orderedSections}
              current={sectionID}
              busy={busy}
              onSelect={(id) => void (async () => {
                // Leaving the open page: finish its save first, as selectNote does.
                if (dirty && selectedNoteRef.current) await save(selectedNoteRef.current, true);
                setSectionID(id);
                setSelectedNote(null);
              })()}
              onCreate={() => void newSection()}
              onRename={renameSection}
              onColor={(section, color) => void updateSection(section.id, { color })}
              onDelete={(section) => void removeSection(section)}
              onMove={(id, index) => void moveSection(id, index)}
              onDropPage={(pageID, target) => void movePage(pageID, target, pagesInSection(notes, sections, target).length)}
            />
          )}
```

- [ ] **Step 4: Styles**

Append to `web/src/styles.css`:

```css
/* OneNote-style layout: notebooks | section tabs over pages + page. */
:root { --section-orange: #d9822b; --section-blue: #3f7cc4; --section-green: #4f9a5a; --section-purple: #8a63c4; --section-red: #c4523f; --section-teal: #2f9a95; --section-yellow: #c9a227; --section-gray: #8a877d; }
.workspace { grid-template-rows: auto minmax(0, 1fr); grid-template-areas: "nav tabs tabs" "nav pages page"; }
.workspace > .sidebar { grid-area: nav; }
.workspace > .section-tabs { grid-area: tabs; }
.workspace > .note-list { grid-area: pages; }
.workspace > .editor { grid-area: page; }
.section-tabs { display: flex; align-items: flex-end; gap: 6px; padding: 10px 18px 0; border-bottom: 1px solid var(--line); background: var(--panel); min-width: 0; }
.section-tabs ul { display: flex; align-items: flex-end; gap: 2px; margin: 0; padding: 0; list-style: none; overflow-x: auto; min-width: 0; }
.section-tab-item { display: flex; align-items: center; }
.section-tab { padding: 7px 14px; border-top: 4px solid var(--tab-color); border-radius: 8px 8px 0 0; background: transparent; color: var(--ink); white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
[class].section-tab.ky-nav-item[aria-current="page"] { box-shadow: inset 0 -3px var(--accent); font-weight: 600; }
.section-tab-menu, .section-add { background: transparent; color: var(--ink); padding: 6px 8px; }
.section-menu { padding: 8px; border: 1px solid var(--line); background: var(--panel); color: var(--ink-strong); display: grid; gap: 4px; min-width: 180px; }
.section-menu > button { background: transparent; color: inherit; text-align: left; padding: 8px; }
.section-colors { display: flex; flex-wrap: wrap; gap: 6px; padding: 4px 8px; }
.section-swatch { width: 20px; height: 20px; border-radius: 50%; padding: 0; }
.section-swatch[aria-pressed="true"] { outline: 2px solid var(--ink-strong); outline-offset: 2px; }
@media (max-width: 800px) { .workspace { grid-template-rows: none; grid-template-areas: "nav" "tabs" "pages" "page"; } .section-tabs { padding: 8px 12px 0; } }
```

- [ ] **Step 5: Verify**

Run: `cd web && npm test && npm run build`
Expected: PASS and a clean build. Then check in a real browser following Task 7, Step 3: create, rename, recolor, reorder and delete a section. Deleting a section that holds a page must show the page under Quick Notes.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/SectionTabs.tsx web/src/main.tsx web/src/styles.css
git commit -m "web: add colored section tabs"
```

---

### Task 5: Ordered page list, move and search across the notebook

**Files:**
- Modify: `web/src/main.tsx` (derived lists at about lines 551–616, list render at about lines 1508–1595, editor actions at about line 1647)
- Modify: `web/src/styles.css` (append)

**Interfaces:**
- Consumes: `movePage`, `orderedSections` and `PAGE_DRAG` (Task 4); `pagesInSection`, `compareOrdered` (Task 2).

- [ ] **Step 1: Replace pins and sort with manual order**

Delete these from `Workspace`:
- `sort` / `setSort`
- `pinsKey`
- `pinned`
- `togglePin`
- the `<select value={sort}…>` element
- the `pin-button` element

Replace `orderedNotes` with:

```ts
  const orderedNotes = useMemo(() => [...notes].sort(compareOrdered), [notes]);
  const sectionPages = useMemo(() => pagesInSection(notes, sections, sectionID), [notes, sections, sectionID]);
  const sectionTitle = (id?: string) => sections.find((entry) => entry.id === id)?.title ?? "Quick Notes";
```

Add `compareOrdered` to the `./pages` import and `PAGE_DRAG` to the `./components/SectionTabs` import. Replace the non-queue branch of `listEntries` so that an empty search shows the current section and a search covers the whole notebook:

```ts
  const listEntries = queueMode
    ? visibleQueueEntries
    : (query.trim() ? visibleNotes : sectionPages)
        .map((note) => ({ note, container: selected }))
        .filter((entry): entry is QueueEntry => Boolean(entry.container));
  const reorderable = !queueMode && !query.trim();
```

- [ ] **Step 2: Rows with drag, keyboard reorder and section label**

Replace the `listEntries.map(...)` row block with:

```tsx
            {listEntries.map(({ note, container }, index) => (
              <div
                className={`note-row-wrap ${selectedNote?.id === note.id ? "selected" : ""}`}
                key={note.id}
                onDragOver={(event) => { if (reorderable && event.dataTransfer.types.includes(PAGE_DRAG)) event.preventDefault(); }}
                onDrop={(event) => {
                  const pageID = event.dataTransfer.getData(PAGE_DRAG);
                  if (reorderable && pageID) void movePage(pageID, sectionID, index);
                }}
              >
                <button
                  className="note-row"
                  draggable={!queueMode}
                  onDragStart={(event) => event.dataTransfer.setData(PAGE_DRAG, note.id)}
                  onKeyDown={(event) => {
                    if (!reorderable || !event.altKey) return;
                    if (event.key === "ArrowUp" && index > 0) { event.preventDefault(); void movePage(note.id, sectionID, index - 1); }
                    if (event.key === "ArrowDown" && index < listEntries.length - 1) { event.preventDefault(); void movePage(note.id, sectionID, index + 1); }
                  }}
                  aria-keyshortcuts={reorderable ? "Alt+ArrowUp Alt+ArrowDown" : undefined}
                  onClick={() => void (queueMode ? selectQueueNote({ note, container }) : selectNote(note))}
                >
                  <strong>{note.title || "Untitled page"}</strong>
                  <span>
                    {query.trim() && !queueMode && <em className="page-section">{sectionTitle(note.section)} · </em>}
                    {(queueMode ? noteTasks(indexNotes([note])[0]).slice(0, 2).join(" · ") : documentText(note.body).slice(0, 64)) || "Empty page"}
                  </span>
                </button>
              </div>
            ))}
```

Pages dropped on a section tab move to the end of that section (Task 4). Pages dropped on a row reorder within the current section. After a keyboard move, focus stays on the moved row's button because React keeps the keyed element.

- [ ] **Step 3: "Move to section" for touch and keyboard users**

Add this in `editor-actions`, before the Delete button:

```tsx
                  <select
                    aria-label="Move page to section"
                    value={pagesInSection([selectedNote], sections, QUICK_NOTES).length ? QUICK_NOTES : selectedNote.section}
                    onChange={(event) => void movePage(selectedNote.id, event.target.value, pagesInSection(notes, sections, event.target.value).length)}
                  >
                    {orderedSections.map((entry) => <option key={entry.id} value={entry.id}>{entry.title || "Untitled section"}</option>)}
                    <option value={QUICK_NOTES}>Quick Notes</option>
                  </select>
```

- [ ] **Step 4: Styles**

Append:

```css
.note-row[draggable="true"] { cursor: grab; }
.page-section { font-style: normal; color: var(--accent); }
```

- [ ] **Step 5: Verify**

Run: `cd web && npm test && npm run build`
Expected: PASS. Then, in the browser, check the following:
- Drag-reorder pages and reload; the order persists.
- Alt+↓ moves the focused page.
- Drop a page on another tab; it moves there.
- The select moves the open page.
- Search finds pages in other sections and labels them.

- [ ] **Step 6: Commit**

```bash
git add web/src/main.tsx web/src/styles.css
git commit -m "web: ordered page list with drag, keyboard and section moves"
```

---

### Task 6: Deep links

**Files:**
- Modify: `web/src/main.tsx` (`loadContainers` at about line 739, new effect after the drain-queue effect)

**Interfaces:**
- Consumes: `parseRoute`, `formatRoute`, `resolveSection` (Task 2); `selectContainer(container, route)` (Task 3).

- [ ] **Step 1: Open the routed notebook on load**

In `loadContainers`, replace `if (loaded[0]) await selectContainer(loaded[0]);` with:

```ts
      const route = parseRoute(location.hash);
      const start = loaded.find((item) => item.id === route.container) ?? loaded[0];
      if (start) await selectContainer(start, start.id === route.container ? route : undefined);
```

- [ ] **Step 2: Keep the hash in sync and follow back/forward**

Add `parseRoute` and `formatRoute` to the `./pages` import, then add after the drain-queue effect:

```ts
  useEffect(() => {
    if (queueMode || !selected) return;
    const next = formatRoute({ container: selected.id, section: sectionID, page: selectedNote?.id });
    if (location.hash !== next) location.hash = next;
  }, [queueMode, selected?.id, sectionID, selectedNote?.id]);
  useEffect(() => {
    const follow = () => {
      const route = parseRoute(location.hash);
      const container = items.find((item) => item.id === route.container);
      // Our own hash writes match the current state and stop here.
      if (!container || (container.id === selected?.id && route.section === sectionID && route.page === selectedNote?.id)) return;
      if (container.id !== selected?.id) { void selectContainer(container, route); return; }
      setSectionID(resolveSection(route.section, sections));
      const page = notes.find((note) => note.id === route.page);
      if (page) void selectNote(page);
      else setSelectedNote(null);
    };
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, [items, selected?.id, sectionID, selectedNote?.id, notes, sections]);
```

- [ ] **Step 3: Verify**

Run: `cd web && npm test && npm run build`
Expected: PASS. In the browser:
- Open a page and copy the URL into a new tab; it opens the same notebook, section and page.
- The Back button returns to the previous page.
- A hash naming a deleted page opens its section with no page.
- A hash naming a garbage container opens the first notebook.
- Neither case loops: the network panel shows no repeated `/changes` requests.

- [ ] **Step 4: Commit**

```bash
git add web/src/main.tsx
git commit -m "web: deep-link notebooks, sections and pages through the URL hash"
```

---

### Task 7: Notebook wording, docs, embedded bundle and real-browser evidence

**Files:**
- Modify: `web/src/main.tsx` (UI copy only)
- Modify: `DESIGN.md` (§3 Product model)
- Modify: `AGENTS.md` (Child DOX Index `web/` entries)
- Modify: `UI-VERIFICATION.md`
- Modify: `internal/web/dist/**` (regenerated)

- [ ] **Step 1: Copy changes in `main.tsx`**

Change user-visible strings only; identifiers stay the same:

| Old | New |
|---|---|
| `PERSONAL` (section label) | `NOTEBOOKS` |
| `TEAMS` | `TEAM NOTEBOOKS` |
| `＋ New personal workspace` | `＋ New notebook` |
| `＋ New team workspace` | `＋ New team notebook` |
| `✎ Rename workspace` | `✎ Rename notebook` |
| prompt `"Personal workspace name", "My personal workspace"` | `"Notebook name", "My notebook"` |
| prompt `"Team workspace name", "New workspace"` | `"Notebook name", "New notebook"` |
| prompt `"Workspace name"` | `"Notebook name"` |
| `Workspace ${container.id.slice(4, 10)}` in `nameOf` | `Notebook ${container.id.slice(4, 10)}` |
| `"Team workspace"` / `"Personal workspace"` | `"Team notebook"` / `"Notebook"` |
| `"Select a workspace"` | `"Select a notebook"` |
| heading `"Notes"` | `{sectionTitle(sectionID)}` |
| `"No notes yet."` / `"Create the first one."` | `"No pages in this section."` / `"Add a page with ＋."` |
| `confirm("Delete this note?")` | `confirm("Delete this page?")` |
| `aria-label="Search notes"` | `aria-label="Search this notebook"` |

Leave the error strings ("Unable to …") as they are.

- [ ] **Step 2: Build, embed and run checks**

```bash
cd web && npm test && npm run build && cd ..
rsync -a --delete web/dist/ internal/web/dist/
diff -qr web/dist internal/web/dist
go test ./internal/web
```

Expected:
- Tests pass and the build is clean.
- `diff` prints nothing.
- `go test` reports `ok`.

- [ ] **Step 3: Real-browser verification**

Start a scratch server on isolated preview data per the README (never production data) and use the Playwright MCP tools. At 1280×900 and 390×844, in Busnes Light and Dark:
1. Create two notebooks. In one, create sections A and B and three pages in A.
2. Reorder the pages by dragging, then with Alt+↑/↓. Move one page to B by dropping it on tab B, and another with the "Move page to section" select. Reload, and confirm order and placement persist.
3. Edit page 1, then within 1 second click page 2. Reload, and confirm page 1's edit survived. This is the flush fix.
4. Go offline (DevTools network offline) and edit page 3. Switch to page 1, drag page 3 to section B, and go back online. Confirm page 3 shows the offline edit in section B after reload (Review Focus 4).
5. Delete section B. Its pages must appear under Quick Notes.
6. Deep links: copy the URL to a new tab; Back and Forward work; a garbage hash opens the first notebook.
7. At 390px, the tabs scroll horizontally and the page fits the viewport width.

Save screenshots as `docs/onenote-nav-{light,dark}-{desktop,mobile}.png`.

- [ ] **Step 4: DOX updates**

`DESIGN.md` §3 Product model: add after the Workbook/Project bullets.

```markdown
- A **Section** is an encrypted `folder` object inside a workbook. Its payload
  `{type:"section", title, color, order}` is ciphertext; the server sees only the kind.
- A **Page** is an encrypted `note` object. Its payload carries `section` (a section
  object ID) and a fractional `order` key, so each page owns its placement and no shared
  manifest is written. Pages without a live section appear in the client's virtual
  Quick Notes section; deleting a section never deletes pages.
```

`AGENTS.md`: add to the Child DOX Index.

```markdown
- `web/` presents containers as notebooks with colored section tabs (`folder` objects) and
  manually ordered pages. Placement lives in each page's encrypted payload
  (`pages.ts`, `order.ts`); decrypted payloads pass `parseObjectPayload` before use.
  Deep links use `#/<container>/<section|quick>/<page>`. Verify `order.test.ts`,
  `pages.test.ts` and the section/page browser checks in `UI-VERIFICATION.md`.
```

`UI-VERIFICATION.md`: add a dated "OneNote navigation" section listing the Step 3 checks and their actual results, plus the screenshots. Record any check that could not be run as not run.

- [ ] **Step 5: Commit**

```bash
git add web/src/main.tsx DESIGN.md AGENTS.md UI-VERIFICATION.md docs/onenote-nav-*.png internal/web/dist
git commit -m "web: notebook wording, docs and verified embedded bundle"
```
