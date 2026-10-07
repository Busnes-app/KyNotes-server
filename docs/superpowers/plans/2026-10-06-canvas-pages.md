# Canvas Pages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every KyNotes page becomes a OneNote-style surface: click anywhere to type in a positioned rich-text box, draw pressure-sensitive ink, drop images, undo ink. Existing notes open unchanged.

**Architecture:** A new encrypted body format `kynotes.canvas.v1` holds positioned BlockNote boxes and ink strokes. `document.ts` owns parsing (older formats open as one box at the origin, converted on read). `canvas.ts` owns pure editing operations. `ink.ts` turns points into SVG paths through `perfect-freehand`. `CanvasPage.tsx` is the only component with pointer logic. On screens ≤800px the boxes reflow into a readable column and ink is hidden.

**Tech Stack:** React 19, BlockNote 0.54 (one editor per box), `perfect-freehand@1.2.3` (MIT, no dependencies), Pointer Events, vitest.

**Spec:** `docs/superpowers/specs/2026-10-06-onenote-notebooks-and-canvas-pages.md`

**Depends on:** `docs/superpowers/plans/2026-10-06-onenote-navigation.md` (its section color CSS variables `--section-*` are reused for ink).

## Global Constraints

- No server, API or migration changes. Canvas JSON is plaintext only inside `kynotes/object/v1` ciphertext.
- Never rewrite a page the user did not edit. Opening a legacy page must not emit `onChange`.
- Decrypted bodies are untrusted. `openPage` clamps coordinates to `0..100000` and caps input at 500 boxes, 5,000 strokes and 10,000 points per stroke. Invalid items are dropped, never thrown.
- Refuse new ink when the serialized body exceeds 9 MiB (the server limit is 10 MiB of ciphertext). Text edits are never refused client-side.
- Ink colors are stored as names and rendered through CSS variables, so "ink" stays visible in dark mode.
- Do not hand-edit `web/src/ky-ui/`. Selected tool buttons use `aria-pressed`.
- Verification, from `web/`: `npm test` and `npm run build`. From the repo root: `rsync -a --delete web/dist/ internal/web/dist/`, `diff -qr web/dist internal/web/dist` and `go test ./internal/web`.

## Review Focus

1. **Opening a legacy BlockNote, Tiptap or Markdown page and closing it without typing.** No save, no version bump. Pinned by the Task 1 `openPage` tests (pure wrap) and the Task 6 browser check (the network panel shows no PUT).
2. **Hostile canvas JSON from a compromised teammate device** (NaN, 1e12 coordinates, a million points, duplicate box IDs). The page opens with clamped, truncated, de-duplicated content and the tab stays responsive. Pinned in Task 1.
3. **A page near the 10 MiB ceiling.** New ink is refused with a visible message, and the save loop never spins on a 413. Pinned in Task 2 (`pageFits`) and Task 4 (`commit` guard).
4. **Scrolling a page on a touch screen with the Type tool.** It must not create text boxes. Box creation uses `click`, which browsers do not fire after a scroll. Checked in the Task 6 browser pass with touch emulation.
5. **Ink undo across page switches.** Each page has its own history, because the component is keyed by page ID, so undo can never restore another page's strokes. Checked in Task 6.

---

### Task 1: Canvas body format

**Files:**
- Modify: `web/src/document.ts`
- Modify: `web/src/knowledge.ts` (`noteTasks`, about lines 36–61)
- Test: `web/src/document.test.ts`, `web/src/knowledge.test.ts`

**Interfaces:**
- Produces from `document.ts`:
  - `CANVAS_FORMAT = "kynotes.canvas.v1"` and `LEGACY_BOX = "legacy"`
  - `MAX_COORD`, `MAX_BOXES`, `MAX_STROKES`, `MAX_STROKE_POINTS`, `BOX_MIN_WIDTH`, `BOX_MAX_WIDTH`, `DEFAULT_BOX_WIDTH`
  - `INK_COLORS` and `type InkColor`
  - `type CanvasBox = { id: string; x: number; y: number; width: number; blocks: PartialBlock[] }`
  - `type CanvasStroke = { id: string; tool: "pen" | "highlighter"; color: InkColor; size: number; points: number[] }`, where `points` is flat `[x, y, pressure, …]`
  - `type CanvasPage = { format: typeof CANVAS_FORMAT; boxes: CanvasBox[]; strokes: CanvasStroke[] }`
  - `emptyCanvasPage(): CanvasPage`
  - `openPage(body: string): CanvasPage & { legacyMarkdown?: string }`
  - `stringifyCanvasPage(page: CanvasPage): string`
  - `pageBlocks(body: string): PartialBlock[]`
  - `documentText` and `isStructuredNoteBody` become canvas-aware

- [ ] **Step 1: Write the failing tests**

Append to `web/src/document.test.ts`, extending its `./document` import with `CANVAS_FORMAT, LEGACY_BOX, MAX_COORD, MAX_STROKE_POINTS, emptyCanvasPage, isStructuredNoteBody, openPage, pageBlocks, stringifyCanvasPage, type CanvasPage`:

```ts
describe("canvas pages", () => {
  it("opens a BlockNote page as one box at the origin without Markdown", () => {
    const body = stringifyNoteDocument([{ type: "paragraph", content: "Hello" }]);
    const page = openPage(body);
    expect(page.boxes).toEqual([{ id: LEGACY_BOX, x: 0, y: 0, width: 640, blocks: [{ type: "paragraph", content: "Hello" }] }]);
    expect(page.strokes).toEqual([]);
    expect(page.legacyMarkdown).toBeUndefined();
  });

  it("keeps legacy Markdown for the editor to parse", () => {
    expect(openPage("# Title\n- [ ] task").legacyMarkdown).toBe("# Title\n- [ ] task");
    expect(openPage("").legacyMarkdown).toBeUndefined();
  });

  it("round-trips a canvas page", () => {
    const page: CanvasPage = {
      format: CANVAS_FORMAT,
      boxes: [{ id: "b1", x: 40, y: 80, width: 300, blocks: [{ type: "paragraph", content: "Note" }] }],
      strokes: [{ id: "s1", tool: "pen", color: "blue", size: 4, points: [1, 2, 0.5, 3, 4, 0.6] }],
    };
    expect(openPage(stringifyCanvasPage(page))).toEqual(page);
    expect(isStructuredNoteBody(stringifyCanvasPage(page))).toBe(true);
  });

  it("clamps, truncates and de-duplicates hostile canvas input", () => {
    const body = JSON.stringify({
      format: CANVAS_FORMAT,
      boxes: [
        { id: "b1", x: Number.MAX_VALUE, y: -5, width: 1e9, blocks: [] },
        { id: "b1", x: 1, y: 1, width: 300, blocks: [] },
        { id: "../bad", x: 1, y: 1, width: 300, blocks: [] },
        "not a box",
      ],
      strokes: [
        { id: "s1", tool: "laser", color: "chartreuse", size: 900, points: [1, 2, 0.5, "x", 3, 4, 5, 6, 7] },
        { id: "s2", points: new Array(MAX_STROKE_POINTS * 3 + 30).fill(1) },
        { id: "s3", points: [] },
      ],
    });
    const page = openPage(body);
    expect(page.boxes).toHaveLength(1);
    expect(page.boxes[0]).toMatchObject({ id: "b1", x: MAX_COORD, y: 0, width: 2000 });
    expect(page.boxes[0].blocks.length).toBeGreaterThan(0);
    expect(page.strokes.map((s) => s.id)).toEqual(["s1", "s2"]);
    // The "x" triple is dropped; pressure 7 clamps to 1.
    expect(page.strokes[0]).toMatchObject({ tool: "pen", color: "ink", size: 64, points: [1, 2, 0.5, 5, 6, 1] });
    expect(page.strokes[1].points).toHaveLength(MAX_STROKE_POINTS * 3);
  });

  it("reads text from every box in reading order", () => {
    const body = stringifyCanvasPage({
      ...emptyCanvasPage(),
      boxes: [
        { id: "low", x: 0, y: 500, width: 300, blocks: [{ type: "paragraph", content: "second" }] },
        { id: "top", x: 0, y: 10, width: 300, blocks: [{ type: "paragraph", content: "first" }] },
      ],
    });
    expect(documentText(body)).toBe("first second");
    expect(pageBlocks(body)).toHaveLength(2);
  });
});
```

Append to `web/src/knowledge.test.ts`, extending its `./document` import with `stringifyCanvasPage, emptyCanvasPage`:

```ts
describe("canvas tasks", () => {
  it("finds open checklist items in any box", () => {
    const body = stringifyCanvasPage({
      ...emptyCanvasPage(),
      boxes: [
        { id: "a", x: 0, y: 0, width: 300, blocks: [{ type: "paragraph", content: "intro" }] },
        { id: "b", x: 0, y: 200, width: 300, blocks: [{ type: "checkListItem", props: { checked: false }, content: "Call Ana" }] },
      ],
    });
    expect(noteTasks({ id: "n", title: "", body, updatedAt: "" })).toEqual(["Call Ana"]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd web && npx vitest run src/document.test.ts src/knowledge.test.ts`
Expected: FAIL. The new imports (`openPage`, `CANVAS_FORMAT`, …) do not exist yet.

- [ ] **Step 3: Implement in `document.ts`**

Add after `emptyNoteDocument`:

```ts
export const CANVAS_FORMAT = "kynotes.canvas.v1";
export const LEGACY_BOX = "legacy";
export const MAX_COORD = 100_000;
export const MAX_BOXES = 500;
export const MAX_STROKES = 5_000;
export const MAX_STROKE_POINTS = 10_000;
export const BOX_MIN_WIDTH = 160;
export const BOX_MAX_WIDTH = 2_000;
export const DEFAULT_BOX_WIDTH = 640;
export const INK_COLORS = ["ink", "blue", "red", "green", "orange", "yellow"] as const;
export type InkColor = (typeof INK_COLORS)[number];
export type CanvasBox = { id: string; x: number; y: number; width: number; blocks: PartialBlock[] };
/** `points` is flat [x, y, pressure, ...] in page pixels. */
export type CanvasStroke = { id: string; tool: "pen" | "highlighter"; color: InkColor; size: number; points: number[] };
export type CanvasPage = { format: typeof CANVAS_FORMAT; boxes: CanvasBox[]; strokes: CanvasStroke[] };

const ITEM_ID = /^[A-Za-z0-9-]{1,64}$/;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const clamp = (value: unknown, min: number, max: number, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;

function parseBox(value: unknown): CanvasBox | undefined {
  if (!isRecord(value) || typeof value.id !== "string" || !ITEM_ID.test(value.id)) return undefined;
  const blocks = (Array.isArray(value.blocks) ? value.blocks.filter(isRecord) : []) as PartialBlock[];
  return {
    id: value.id,
    x: clamp(value.x, 0, MAX_COORD, 0),
    y: clamp(value.y, 0, MAX_COORD, 0),
    width: clamp(value.width, BOX_MIN_WIDTH, BOX_MAX_WIDTH, DEFAULT_BOX_WIDTH),
    // BlockNote refuses an empty initial document.
    blocks: blocks.length ? blocks : emptyNoteDocument().document,
  };
}

function parseStroke(value: unknown): CanvasStroke | undefined {
  if (!isRecord(value) || typeof value.id !== "string" || !ITEM_ID.test(value.id) || !Array.isArray(value.points)) return undefined;
  const raw = value.points.slice(0, MAX_STROKE_POINTS * 3);
  const points: number[] = [];
  for (let i = 0; i + 2 < raw.length; i += 3) {
    const [x, y, p] = [raw[i], raw[i + 1], raw[i + 2]];
    if (![x, y, p].every((n) => typeof n === "number" && Number.isFinite(n))) continue;
    points.push(clamp(x, 0, MAX_COORD, 0), clamp(y, 0, MAX_COORD, 0), clamp(p, 0, 1, 0.5));
  }
  if (!points.length) return undefined;
  return {
    id: value.id,
    tool: value.tool === "highlighter" ? "highlighter" : "pen",
    color: INK_COLORS.includes(value.color as InkColor) ? (value.color as InkColor) : "ink",
    size: clamp(value.size, 1, 64, 4),
    points,
  };
}

function parseItems<T extends { id: string }>(list: unknown, max: number, parse: (item: unknown) => T | undefined): T[] {
  const seen = new Set<string>();
  const items: T[] = [];
  for (const entry of Array.isArray(list) ? list.slice(0, max) : []) {
    const item = parse(entry);
    if (item && !seen.has(item.id)) {
      seen.add(item.id);
      items.push(item);
    }
  }
  return items;
}

export const emptyCanvasPage = (): CanvasPage => ({ format: CANVAS_FORMAT, boxes: [], strokes: [] });

/** Opens any stored page body as a canvas; older formats become one box at the origin. */
export function openPage(body: string): CanvasPage & { legacyMarkdown?: string } {
  let value: unknown;
  try { value = JSON.parse(body); } catch { /* legacy text below */ }
  if (isRecord(value) && value.format === CANVAS_FORMAT) {
    return { format: CANVAS_FORMAT, boxes: parseItems(value.boxes, MAX_BOXES, parseBox), strokes: parseItems(value.strokes, MAX_STROKES, parseStroke) };
  }
  const box: CanvasBox = { id: LEGACY_BOX, x: 0, y: 0, width: DEFAULT_BOX_WIDTH, blocks: parseNoteDocument(body).document };
  return { ...emptyCanvasPage(), boxes: [box], legacyMarkdown: body && !isStructuredNoteBody(body) ? body : undefined };
}

export const stringifyCanvasPage = ({ boxes, strokes }: CanvasPage): string =>
  JSON.stringify({ format: CANVAS_FORMAT, boxes, strokes });

/** All text blocks of a page, top-to-bottom then left-to-right. */
export function pageBlocks(body: string): PartialBlock[] {
  return [...openPage(body).boxes].sort((a, b) => a.y - b.y || a.x - b.x).flatMap((box) => box.blocks);
}
```

In `documentText`, replace `const value = parseNoteDocument(body).document;` with `const value = pageBlocks(body);`.

In `isStructuredNoteBody`, replace the `if (value.format === NOTE_DOCUMENT_FORMAT …) return true;` line with:

```ts
    if (value.format === NOTE_DOCUMENT_FORMAT && Array.isArray(value.document)) return true;
    if ((value as { format?: unknown }).format === CANVAS_FORMAT) return true;
```

- [ ] **Step 4: Implement in `knowledge.ts`**

Change the import to `import { documentText, isStructuredNoteBody, pageBlocks } from "./document";`. In `noteTasks`:
- delete the `let document …` declaration and its `try { JSON.parse … }` line;
- change the branch condition to `if (isStructuredNoteBody(source)) {`;
- replace `document.document.forEach((block) => visit(block as Parameters<typeof visit>[0]));` with:

```ts
    pageBlocks(source).forEach((block) => visit(block as Parameters<typeof visit>[0]));
```

Tiptap bodies used to fall through to the Markdown line scan. They now go through the structured visit, which finds the same checklist items and more.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd web && npm test`
Expected: all pass, including the pre-existing document and knowledge tests.

- [ ] **Step 6: Commit**

```bash
git add web/src/document.ts web/src/document.test.ts web/src/knowledge.ts web/src/knowledge.test.ts
git commit -m "web: add the kynotes.canvas.v1 page body with legacy read conversion"
```

---

### Task 2: Pure canvas editing operations

**Files:**
- Create: `web/src/canvas.ts`
- Test: `web/src/canvas.test.ts`

**Interfaces:**
- Consumes: Task 1 types and constants.
- Produces:
  - `MAX_PAGE_BYTES` and `pageFits(body: string): boolean`
  - `addBox(page, x, y, blocks?): { page: CanvasPage; id: string } | undefined`. It returns undefined at `MAX_BOXES`.
  - `updateBox(page, id, change: Partial<Omit<CanvasBox, "id">>): CanvasPage`
  - `isEmptyBox(box): boolean`
  - `pruneEmpty(page): CanvasPage`. It returns the same object when nothing is removed.
  - `eraseAt(strokes, x, y, radius): CanvasStroke[]`. It returns the same array when nothing is hit.
  - `contentExtent(page, heights?): { width: number; height: number }`
  - `freeSpot(page, heights): { x: number; y: number }`
  - `readingOrder(boxes): Map<string, number>`
  - `class History<T>` with `push`, `undo` and `redo`, capped at 100 entries

- [ ] **Step 1: Write the failing test**

```ts
// web/src/canvas.test.ts
import { describe, expect, it } from "vitest";
import { History, MAX_PAGE_BYTES, addBox, contentExtent, eraseAt, freeSpot, isEmptyBox, pageFits, pruneEmpty, readingOrder, updateBox } from "./canvas";
import { MAX_BOXES, MAX_COORD, emptyCanvasPage, type CanvasBox, type CanvasStroke } from "./document";

const box = (id: string, x: number, y: number, text = ""): CanvasBox => ({ id, x, y, width: 300, blocks: [{ type: "paragraph", content: text }] });
const stroke = (id: string, points: number[]): CanvasStroke => ({ id, tool: "pen", color: "ink", size: 4, points });

describe("boxes", () => {
  it("adds a box at clamped integer coordinates", () => {
    const added = addBox(emptyCanvasPage(), -10.4, MAX_COORD + 50)!;
    expect(added.page.boxes[0]).toMatchObject({ id: added.id, x: 0, y: MAX_COORD });
    expect(added.page.boxes[0].blocks.length).toBe(1);
  });
  it("refuses a box past the limit", () => {
    const page = { ...emptyCanvasPage(), boxes: Array.from({ length: MAX_BOXES }, (_, i) => box(`b${i}`, 0, i)) };
    expect(addBox(page, 0, 0)).toBeUndefined();
  });
  it("clamps moves and resizes", () => {
    const page = { ...emptyCanvasPage(), boxes: [box("a", 10, 10)] };
    expect(updateBox(page, "a", { x: -50, width: 5 }).boxes[0]).toMatchObject({ x: 0, width: 160 });
    expect(updateBox(page, "a", { width: 99999 }).boxes[0].width).toBe(2000);
  });
  it("prunes only empty boxes and keeps identity when there are none", () => {
    const page = { ...emptyCanvasPage(), boxes: [box("a", 0, 0), box("b", 0, 100, "keep")] };
    expect(isEmptyBox(page.boxes[0])).toBe(true);
    expect(isEmptyBox({ ...box("i", 0, 0), blocks: [{ type: "image", props: { url: "attachment://att_x" } }] })).toBe(false);
    expect(pruneEmpty(page).boxes.map((b) => b.id)).toEqual(["b"]);
    const full = { ...emptyCanvasPage(), boxes: [box("b", 0, 0, "keep")] };
    expect(pruneEmpty(full)).toBe(full);
  });
  it("orders boxes top-to-bottom, then left-to-right", () => {
    expect([...readingOrder([box("c", 50, 100), box("a", 0, 0), box("b", 0, 100)]).entries()]).toEqual([["a", 0], ["b", 1], ["c", 2]]);
  });
});

describe("ink", () => {
  it("erases strokes within reach and keeps identity on a miss", () => {
    const strokes = [stroke("near", [10, 10, 0.5, 20, 20, 0.5]), stroke("far", [500, 500, 0.5])];
    expect(eraseAt(strokes, 22, 22, 4).map((s) => s.id)).toEqual(["far"]);
    expect(eraseAt(strokes, 300, 300, 4)).toBe(strokes);
  });
});

describe("layout", () => {
  it("measures boxes and strokes", () => {
    const page = { ...emptyCanvasPage(), boxes: [box("a", 10, 20)], strokes: [stroke("s", [900, 50, 0.5])] };
    expect(contentExtent(page, { a: 80 })).toEqual({ width: 900, height: 100 });
  });
  it("places new text below existing content", () => {
    expect(freeSpot(emptyCanvasPage(), {})).toEqual({ x: 0, y: 0 });
    const page = { ...emptyCanvasPage(), boxes: [box("a", 10, 20)] };
    expect(freeSpot(page, { a: 80 })).toEqual({ x: 0, y: 124 });
  });
});

describe("history and size", () => {
  it("undoes and redoes, and a new push clears redo", () => {
    const history = new History<number>();
    history.push(1);
    history.push(2);
    expect(history.undo(3)).toBe(2);
    expect(history.redo(2)).toBe(3);
    expect(history.undo(3)).toBe(2);
    history.push(9);
    expect(history.redo(9)).toBeUndefined();
  });
  it("caps history at 100 entries", () => {
    const history = new History<number>();
    for (let i = 0; i < 150; i += 1) history.push(i);
    let last: number | undefined;
    let count = 0;
    for (let value = history.undo(-1); value !== undefined; value = history.undo(value)) { last = value; count += 1; }
    expect(count).toBe(100);
    expect(last).toBe(50);
  });
  it("measures UTF-8 bytes against the page limit", () => {
    expect(pageFits("x".repeat(MAX_PAGE_BYTES))).toBe(true);
    expect(pageFits("é".repeat(MAX_PAGE_BYTES / 2 + 1))).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/canvas.test.ts`
Expected: FAIL, "Failed to resolve import ./canvas".

- [ ] **Step 3: Write minimal implementation**

```ts
// web/src/canvas.ts
import type { PartialBlock } from "@blocknote/core";
import { BOX_MAX_WIDTH, BOX_MIN_WIDTH, DEFAULT_BOX_WIDTH, MAX_BOXES, MAX_COORD, type CanvasBox, type CanvasPage, type CanvasStroke } from "./document";

/** The server stores at most 10 MiB of ciphertext per version; keep headroom. */
export const MAX_PAGE_BYTES = 9 * 1024 * 1024;
export const pageFits = (body: string) => new TextEncoder().encode(body).length <= MAX_PAGE_BYTES;

const GAP = 24;
const DEFAULT_HEIGHT = 120;
const coord = (value: number) => Math.min(MAX_COORD, Math.max(0, Math.round(value)));

export function addBox(page: CanvasPage, x: number, y: number, blocks: PartialBlock[] = [{ type: "paragraph", content: "" }]) {
  if (page.boxes.length >= MAX_BOXES) return undefined;
  const id = crypto.randomUUID();
  return { id, page: { ...page, boxes: [...page.boxes, { id, x: coord(x), y: coord(y), width: DEFAULT_BOX_WIDTH, blocks }] } };
}

export function updateBox(page: CanvasPage, id: string, change: Partial<Omit<CanvasBox, "id">>): CanvasPage {
  return {
    ...page,
    boxes: page.boxes.map((box) => {
      if (box.id !== id) return box;
      const next = { ...box, ...change };
      return { ...next, x: coord(next.x), y: coord(next.y), width: Math.min(BOX_MAX_WIDTH, Math.max(BOX_MIN_WIDTH, Math.round(next.width))) };
    }),
  };
}

export function isEmptyBox(box: CanvasBox): boolean {
  return box.blocks.every((block) => {
    if ((block.type ?? "paragraph") !== "paragraph" || block.children?.length) return false;
    const content = block.content as unknown;
    if (content === undefined || content === "") return true;
    return Array.isArray(content) && content.every((item) => typeof item === "object" && item !== null && "text" in item && item.text === "");
  });
}

export function pruneEmpty(page: CanvasPage): CanvasPage {
  const boxes = page.boxes.filter((box) => !isEmptyBox(box));
  return boxes.length === page.boxes.length ? page : { ...page, boxes };
}

// ponytail: linear scan over every point; add per-stroke bounding boxes if large pages lag.
export function eraseAt(strokes: CanvasStroke[], x: number, y: number, radius: number): CanvasStroke[] {
  const kept = strokes.filter((stroke) => {
    const reach = (radius + stroke.size / 2) ** 2;
    for (let i = 0; i + 2 < stroke.points.length; i += 3) {
      const dx = stroke.points[i] - x;
      const dy = stroke.points[i + 1] - y;
      if (dx * dx + dy * dy <= reach) return false;
    }
    return true;
  });
  return kept.length === strokes.length ? strokes : kept;
}

export function contentExtent(page: CanvasPage, heights: Record<string, number> = {}) {
  let width = 0;
  let height = 0;
  for (const box of page.boxes) {
    width = Math.max(width, box.x + box.width);
    height = Math.max(height, box.y + (heights[box.id] ?? DEFAULT_HEIGHT));
  }
  for (const stroke of page.strokes) {
    for (let i = 0; i + 2 < stroke.points.length; i += 3) {
      width = Math.max(width, stroke.points[i]);
      height = Math.max(height, stroke.points[i + 1]);
    }
  }
  return { width, height };
}

export function freeSpot(page: CanvasPage, heights: Record<string, number>) {
  if (!page.boxes.length && !page.strokes.length) return { x: 0, y: 0 };
  return { x: 0, y: contentExtent(page, heights).height + GAP };
}

export function readingOrder(boxes: CanvasBox[]): Map<string, number> {
  const sorted = [...boxes].sort((a, b) => a.y - b.y || a.x - b.x);
  return new Map(sorted.map((box, index) => [box.id, index]));
}

export class History<T> {
  private past: T[] = [];
  private future: T[] = [];
  push(state: T) {
    this.past.push(state);
    if (this.past.length > 100) this.past.shift();
    this.future = [];
  }
  undo(current: T): T | undefined {
    const previous = this.past.pop();
    if (previous !== undefined) this.future.push(current);
    return previous;
  }
  redo(current: T): T | undefined {
    const next = this.future.pop();
    if (next !== undefined) this.past.push(current);
    return next;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run src/canvas.test.ts`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add web/src/canvas.ts web/src/canvas.test.ts
git commit -m "web: pure canvas editing operations with ink history"
```

---

### Task 3: Ink rendering

**Files:**
- Modify: `web/package.json`, `web/package-lock.json` (via npm)
- Create: `web/src/ink.ts`
- Test: `web/src/ink.test.ts`

**Interfaces:**
- Produces: `strokePath(points: number[], size: number, highlighter: boolean): string`. It returns `""` for no points, otherwise a closed SVG path `M…Z`.

- [ ] **Step 1: Add the dependency**

Run: `cd web && npm view perfect-freehand@1.2.3 license && npm install perfect-freehand@1.2.3`
Expected: `MIT`, then the package is added to `dependencies`. It replaces the stroke smoothing and pressure-outline maths we would otherwise write.

- [ ] **Step 2: Write the failing test**

```ts
// web/src/ink.test.ts
import { describe, expect, it } from "vitest";
import { strokePath } from "./ink";

describe("strokePath", () => {
  it("renders nothing without points", () => {
    expect(strokePath([], 4, false)).toBe("");
  });
  it("renders a closed outline for a dot and a line", () => {
    expect(strokePath([10, 10, 0.5], 4, false)).toMatch(/^M[\d.]+,[\d.]+(L[\d.]+,[\d.]+)+Z$/);
    expect(strokePath([0, 0, 0.5, 50, 50, 0.9, 100, 0, 0.2], 8, true)).toMatch(/^M.*Z$/);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd web && npx vitest run src/ink.test.ts`
Expected: FAIL, "Failed to resolve import ./ink".

- [ ] **Step 4: Write minimal implementation**

```ts
// web/src/ink.ts
import { getStroke } from "perfect-freehand";

/** Pressure-aware outline of a flat [x, y, pressure, ...] stroke as an SVG path. */
export function strokePath(points: number[], size: number, highlighter: boolean): string {
  const input: number[][] = [];
  for (let i = 0; i + 2 < points.length; i += 3) input.push([points[i], points[i + 1], points[i + 2]]);
  if (!input.length) return "";
  const outline = getStroke(input, {
    size,
    thinning: highlighter ? 0 : 0.6,
    smoothing: 0.5,
    streamline: 0.5,
    simulatePressure: false,
    last: true,
  });
  if (!outline.length) return "";
  return `M${outline.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join("L")}Z`;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web && npx vitest run src/ink.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/package.json web/package-lock.json web/src/ink.ts web/src/ink.test.ts
git commit -m "web: render pressure ink with perfect-freehand"
```

---

### Task 4: The canvas page component

**Files:**
- Modify: `web/src/BlockNoteEditor.tsx` (add `autoFocus`)
- Create: `web/src/CanvasPage.tsx`
- Modify: `web/src/styles.css` (append)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `export default function CanvasPage(props: { pageID: string; body: string; onChange: (body: string) => void; onError: (message: string) => void; uploadFile: (file: File) => Promise<string>; resolveFileUrl: (url: string) => Promise<string> })`. The parent must key it by page ID.

- [ ] **Step 1: `autoFocus` on `BlockNoteEditor`**

In `web/src/BlockNoteEditor.tsx`:
- Add `autoFocus?: boolean;` to `Props` and to the destructured parameters.
- In the existing mount effect, after the `legacyMarkdown` block and before `hydratedRef.current = true;`, add `if (autoFocus) editor.focus();`.
- Add `autoFocus` to that effect's dependency array.

- [ ] **Step 2: Create the component**

```tsx
// web/src/CanvasPage.tsx
import { memo, useRef, useState } from "react";
import type { Block, PartialBlock } from "@blocknote/core";
import { BlockNoteEditor } from "./BlockNoteEditor";
import {
  INK_COLORS, LEGACY_BOX, MAX_STROKE_POINTS, MAX_STROKES, openPage, stringifyCanvasPage,
  type CanvasBox, type CanvasPage as Page, type CanvasStroke, type InkColor,
} from "./document";
import { History, addBox, contentExtent, eraseAt, freeSpot, pageFits, pruneEmpty, readingOrder, updateBox } from "./canvas";
import { strokePath } from "./ink";

type Tool = "type" | "pen" | "highlighter" | "eraser";
const TOOLS: Array<[Tool, string]> = [["type", "Type"], ["pen", "Pen"], ["highlighter", "Highlighter"], ["eraser", "Eraser"]];
const SIZES = { pen: [2, 4, 8], highlighter: [12, 20, 28] } as const;
const ERASER_RADIUS = 10;
const PAGE_FULL = "This page is full. Start a new page for more ink.";
const narrow = () => window.matchMedia("(max-width: 800px)").matches;
const pressureOf = (event: PointerEvent | React.PointerEvent) =>
  event.pointerType === "pen" ? Math.round(event.pressure * 100) / 100 : 0.5;

type Actions = {
  change: (id: string, blocks: Block[]) => void;
  startDrag: (event: React.PointerEvent<HTMLElement>, id: string, mode: "move" | "resize") => void;
  dragMove: (event: React.PointerEvent<HTMLElement>) => void;
  endDrag: () => void;
  nudge: (event: React.KeyboardEvent, id: string) => void;
  uploadFile: (file: File) => Promise<string>;
  resolveFileUrl: (url: string) => Promise<string>;
};

type BoxProps = { pageID: string; box: CanvasBox; rank: number; autoFocus: boolean; legacyMarkdown?: string; actions: React.RefObject<Actions | null> };

// Memoised on the box object: typing in one box re-renders only that box.
const Box = memo(function Box({ pageID, box, rank, autoFocus, legacyMarkdown, actions }: BoxProps) {
  const act = () => actions.current!;
  return (
    <div data-box={box.id} className="canvas-box" style={{ left: box.x, top: box.y, width: box.width, order: rank }}>
      <div
        className="canvas-box-handle"
        role="button"
        tabIndex={0}
        aria-label="Move text box with arrow keys"
        onPointerDown={(event) => act().startDrag(event, box.id, "move")}
        onPointerMove={(event) => act().dragMove(event)}
        onPointerUp={() => act().endDrag()}
        onPointerCancel={() => act().endDrag()}
        onKeyDown={(event) => act().nudge(event, box.id)}
      />
      <BlockNoteEditor
        noteID={`${pageID}/${box.id}`}
        initialContent={box.blocks}
        legacyMarkdown={legacyMarkdown}
        autoFocus={autoFocus}
        onChange={(blocks) => act().change(box.id, blocks)}
        uploadFile={(file) => act().uploadFile(file)}
        resolveFileUrl={(url) => act().resolveFileUrl(url)}
      />
      <div
        className="canvas-box-resize"
        aria-hidden="true"
        onPointerDown={(event) => act().startDrag(event, box.id, "resize")}
        onPointerMove={(event) => act().dragMove(event)}
        onPointerUp={() => act().endDrag()}
        onPointerCancel={() => act().endDrag()}
      />
    </div>
  );
});

type Props = {
  pageID: string;
  body: string;
  onChange: (body: string) => void;
  onError: (message: string) => void;
  uploadFile: (file: File) => Promise<string>;
  resolveFileUrl: (url: string) => Promise<string>;
};

export default function CanvasPage({ pageID, body, onChange, onError, uploadFile, resolveFileUrl }: Props) {
  // Keyed by page ID in the parent, so the body is parsed once per page.
  const [opened] = useState(() => openPage(body));
  const [page, setPage] = useState<Page>(opened);
  const pageRef = useRef<Page>(opened);
  const [tool, setTool] = useState<Tool>("type");
  const [color, setColor] = useState<InkColor>("ink");
  const [sizeIndex, setSizeIndex] = useState(1);
  const [focusID, setFocusID] = useState<string | null>(null);
  const [, setTick] = useState(0);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const draft = useRef<number[] | null>(null);
  const eraseStart = useRef<CanvasStroke[] | null>(null);
  const penSeen = useRef(false);
  const drag = useRef<{ id: string; mode: "move" | "resize"; px: number; py: number; x: number; y: number; width: number } | null>(null);
  const history = useRef(new History<CanvasStroke[]>());
  const paths = useRef(new WeakMap<CanvasStroke, string>());
  const size = SIZES[tool === "highlighter" ? "highlighter" : "pen"][sizeIndex];

  const show = (next: Page) => {
    pageRef.current = next;
    setPage(next);
  };
  /** Shows and emits a change. `guard` refuses growth past the page byte limit (ink only). */
  const commit = (next: Page, guard = false) => {
    const serialized = stringifyCanvasPage(next);
    if (guard && !pageFits(serialized)) {
      onError(PAGE_FULL);
      return false;
    }
    show(next);
    onChange(serialized);
    return true;
  };
  const local = (event: { clientX: number; clientY: number }) => {
    const rect = surfaceRef.current!.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  };
  const heights = () => {
    const result: Record<string, number> = {};
    surfaceRef.current?.querySelectorAll<HTMLElement>("[data-box]").forEach((element) => {
      result[element.dataset.box!] = element.offsetHeight;
    });
    return result;
  };
  const placeBox = (x: number, y: number, blocks?: PartialBlock[]) => {
    const added = addBox(pruneEmpty(pageRef.current), x, y, blocks);
    if (!added) return onError("This page has the maximum number of text boxes.");
    setFocusID(added.id);
    commit(added.page);
  };

  const actions = useRef<Actions>(null);
  actions.current = {
    change: (id, blocks) => commit(updateBox(pageRef.current, id, { blocks })),
    startDrag: (event, id, mode) => {
      const box = pageRef.current.boxes.find((entry) => entry.id === id);
      if (!box || event.button !== 0) return;
      event.currentTarget.setPointerCapture(event.pointerId);
      drag.current = { id, mode, px: event.clientX, py: event.clientY, x: box.x, y: box.y, width: box.width };
    },
    dragMove: (event) => {
      const d = drag.current;
      if (!d) return;
      const dx = event.clientX - d.px;
      const dy = event.clientY - d.py;
      show(updateBox(pageRef.current, d.id, d.mode === "move" ? { x: d.x + dx, y: d.y + dy } : { width: d.width + dx }));
    },
    endDrag: () => {
      if (!drag.current) return;
      drag.current = null;
      commit(pageRef.current);
    },
    nudge: (event, id) => {
      const step = event.shiftKey ? 50 : 10;
      const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[event.key];
      const box = pageRef.current.boxes.find((entry) => entry.id === id);
      if (!delta || !box) return;
      event.preventDefault();
      commit(updateBox(pageRef.current, id, { x: box.x + delta[0], y: box.y + delta[1] }));
    },
    uploadFile,
    resolveFileUrl,
  };

  const undo = () => {
    const previous = history.current.undo(pageRef.current.strokes);
    if (previous) commit({ ...pageRef.current, strokes: previous });
  };
  const redo = () => {
    const next = history.current.redo(pageRef.current.strokes);
    if (next) commit({ ...pageRef.current, strokes: next });
  };
  const erase = (x: number, y: number) => {
    const current = pageRef.current;
    const strokes = eraseAt(current.strokes, x, y, ERASER_RADIUS);
    if (strokes !== current.strokes) show({ ...current, strokes });
  };

  const inkDown = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.pointerType === "pen") penSeen.current = true;
    else if (event.pointerType === "touch" && penSeen.current) return; // palm rejection once a pen is in use
    if (event.button !== 0) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    const { x, y } = local(event);
    if (tool === "eraser") {
      eraseStart.current = pageRef.current.strokes;
      erase(x, y);
      return;
    }
    draft.current = [Math.round(x), Math.round(y), pressureOf(event)];
    setTick((value) => value + 1);
  };
  const inkMove = (event: React.PointerEvent<SVGSVGElement>) => {
    if (eraseStart.current) {
      const { x, y } = local(event);
      erase(x, y);
      return;
    }
    const points = draft.current;
    if (!points) return;
    for (const sample of event.nativeEvent.getCoalescedEvents?.() ?? [event.nativeEvent]) {
      if (points.length >= MAX_STROKE_POINTS * 3) break;
      const { x, y } = local(sample);
      points.push(Math.round(x), Math.round(y), pressureOf(sample));
    }
    setTick((value) => value + 1);
  };
  const inkUp = () => {
    const start = eraseStart.current;
    if (start) {
      eraseStart.current = null;
      if (pageRef.current.strokes !== start) {
        history.current.push(start);
        commit(pageRef.current);
      }
      return;
    }
    const points = draft.current;
    draft.current = null;
    setTick((value) => value + 1);
    if (!points) return;
    const before = pageRef.current;
    if (before.strokes.length >= MAX_STROKES) return onError(PAGE_FULL);
    const stroke: CanvasStroke = { id: crypto.randomUUID(), tool: tool === "highlighter" ? "highlighter" : "pen", color, size, points };
    if (commit({ ...before, strokes: [...before.strokes, stroke] }, true)) history.current.push(before.strokes);
  };

  const onSurfacePointerDown = (event: React.PointerEvent) => {
    if (event.target !== surfaceRef.current) return;
    const pruned = pruneEmpty(pageRef.current);
    if (pruned !== pageRef.current) commit(pruned);
  };
  // `click` (not pointerdown) so a touch scroll never creates a box.
  const onSurfaceClick = (event: React.MouseEvent) => {
    if (tool !== "type" || event.target !== surfaceRef.current || narrow()) return;
    const { x, y } = local(event);
    placeBox(x, y);
  };
  const onDrop = async (event: React.DragEvent) => {
    if (event.target !== surfaceRef.current) return; // drops on a box belong to its editor
    const files = [...event.dataTransfer.files].filter((file) => file.type.startsWith("image/"));
    if (!files.length) return;
    event.preventDefault();
    const { x, y } = local(event);
    for (const [index, file] of files.entries()) {
      try {
        const url = await uploadFile(file);
        placeBox(x + index * 24, y + index * 24, [{ type: "image", props: { url, name: file.name } }]);
      } catch (error) {
        onError(error instanceof Error ? error.message : "Unable to add image");
      }
    }
  };
  const onKeyDown = (event: React.KeyboardEvent) => {
    if ((event.target as HTMLElement).closest(".bn-container")) return; // text undo belongs to the editor
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "z") return;
    event.preventDefault();
    if (event.shiftKey) redo();
    else undo();
  };
  const pathOf = (stroke: CanvasStroke) => {
    let path = paths.current.get(stroke);
    if (path === undefined) {
      path = strokePath(stroke.points, stroke.size, stroke.tool === "highlighter");
      paths.current.set(stroke, path);
    }
    return path;
  };

  const extent = contentExtent(page);
  const ranks = readingOrder(page.boxes);
  return (
    <div className={`canvas-page tool-${tool}`} onKeyDown={onKeyDown}>
      <div className="canvas-toolbar" role="toolbar" aria-label="Page tools">
        {TOOLS.map(([value, label]) => (
          <button key={value} className={value === "type" ? "" : "ink-tool"} aria-pressed={tool === value} onClick={() => setTool(value)}>{label}</button>
        ))}
        {(tool === "pen" || tool === "highlighter") && (
          <>
            {INK_COLORS.map((choice) => (
              <button key={choice} className={`ink-tool ink-swatch ink-${choice}`} aria-label={`${choice} ink`} aria-pressed={color === choice} onClick={() => setColor(choice)} />
            ))}
            {SIZES[tool].map((value, index) => (
              <button key={value} className="ink-tool" aria-label={`Size ${value}`} aria-pressed={sizeIndex === index} onClick={() => setSizeIndex(index)}>
                {["S", "M", "L"][index]}
              </button>
            ))}
          </>
        )}
        <button className="ink-tool" onClick={undo} aria-keyshortcuts="Control+Z">Undo ink</button>
        <button className="ink-tool" onClick={redo} aria-keyshortcuts="Control+Shift+Z">Redo ink</button>
        <button onClick={() => { const spot = freeSpot(pageRef.current, heights()); placeBox(spot.x, spot.y); }}>Add text</button>
      </div>
      {page.strokes.length > 0 && <p className="canvas-ink-note">This page has ink. Open it on a wider screen to see it.</p>}
      <div className="canvas-scroll">
        <div
          ref={surfaceRef}
          className="canvas-surface"
          style={{ width: extent.width + 400, height: extent.height + 400 }}
          onPointerDown={onSurfacePointerDown}
          onClick={onSurfaceClick}
          onDragOver={(event) => { if (event.target === surfaceRef.current && event.dataTransfer.types.includes("Files")) event.preventDefault(); }}
          onDrop={(event) => void onDrop(event)}
        >
          {page.boxes.length === 0 && <p className="canvas-hint">Click anywhere to type, or choose Add text.</p>}
          {page.boxes.map((box) => (
            <Box
              key={box.id}
              pageID={pageID}
              box={box}
              rank={ranks.get(box.id) ?? 0}
              autoFocus={box.id === focusID}
              legacyMarkdown={box.id === LEGACY_BOX ? opened.legacyMarkdown : undefined}
              actions={actions}
            />
          ))}
          <svg
            className="canvas-ink"
            aria-hidden="true"
            onPointerDown={inkDown}
            onPointerMove={inkMove}
            onPointerUp={inkUp}
            onPointerCancel={inkUp}
          >
            {page.strokes.map((stroke) => (
              <path key={stroke.id} d={pathOf(stroke)} className={`ink ink-${stroke.color} ${stroke.tool}`} />
            ))}
            {draft.current && (
              <path d={strokePath(draft.current, size, tool === "highlighter")} className={`ink ink-${color} ${tool}`} />
            )}
          </svg>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Styles**

Append to `web/src/styles.css`:

```css
/* Canvas pages: positioned text boxes under an ink layer. */
.page-canvas { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.canvas-page { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.canvas-toolbar { display: flex; flex-wrap: wrap; gap: 4px; padding: 8px 0; border-bottom: 1px solid var(--line); }
.canvas-toolbar button { background: transparent; color: var(--ink); padding: 6px 10px; border-radius: 6px; }
.canvas-toolbar button[aria-pressed="true"] { background: var(--accent-soft); color: var(--ink-strong); box-shadow: inset 0 -2px var(--accent); }
.ink-swatch { width: 26px; height: 26px; padding: 0 !important; border-radius: 50% !important; }
.canvas-scroll { flex: 1; overflow: auto; height: calc(100vh - 300px); min-height: 420px; }
.canvas-surface { position: relative; min-width: 100%; min-height: 100%; }
.canvas-hint { position: absolute; left: 24px; top: 16px; margin: 0; color: var(--ink); pointer-events: none; }
.canvas-box { position: absolute; }
.canvas-box .blocknote-editor, .canvas-box .blocknote-editor .bn-container { min-height: 0; }
.canvas-box .bn-container { border-color: transparent; background: transparent; }
.canvas-box:hover .bn-container, .canvas-box:focus-within .bn-container { border-color: var(--line); background: var(--panel); }
.canvas-box-handle { height: 10px; border-radius: 6px 6px 0 0; cursor: grab; opacity: 0; background: var(--accent-soft); }
.canvas-box:hover .canvas-box-handle, .canvas-box:focus-within .canvas-box-handle, .canvas-box-handle:focus-visible { opacity: 1; }
.canvas-box-resize { position: absolute; top: 10px; right: -4px; bottom: 0; width: 8px; cursor: ew-resize; }
.canvas-ink { position: absolute; inset: 0; width: 100%; height: 100%; z-index: 2; touch-action: none; }
.canvas-page.tool-type .canvas-ink { pointer-events: none; }
.canvas-page.tool-pen .canvas-ink, .canvas-page.tool-highlighter .canvas-ink { cursor: crosshair; }
.canvas-page.tool-eraser .canvas-ink { cursor: cell; }
.ink { stroke: none; }
.ink.highlighter { opacity: .35; }
.ink-ink { fill: var(--ink-strong); background: var(--ink-strong); }
.ink-blue { fill: var(--section-blue); background: var(--section-blue); }
.ink-red { fill: var(--section-red); background: var(--section-red); }
.ink-green { fill: var(--section-green); background: var(--section-green); }
.ink-orange { fill: var(--section-orange); background: var(--section-orange); }
.ink-yellow { fill: var(--section-yellow); background: var(--section-yellow); }
.canvas-ink-note { display: none; }
/* Phones read pages as a column of text; ink and free placement need a wider screen. */
@media (max-width: 800px) {
  .canvas-surface { display: flex; flex-direction: column; gap: 16px; width: auto !important; height: auto !important; }
  .canvas-box { position: static; width: auto !important; }
  .canvas-ink, .canvas-box-handle, .canvas-box-resize, .canvas-toolbar .ink-tool { display: none; }
  .canvas-ink-note { display: block; color: var(--ink); font-size: 13px; }
  .canvas-scroll { height: auto; }
}
```

- [ ] **Step 4: Typecheck**

Run: `cd web && npx tsc --noEmit`
Expected: clean. `CanvasPage` is not wired in yet; Task 5 does that.

- [ ] **Step 5: Commit**

```bash
git add web/src/BlockNoteEditor.tsx web/src/CanvasPage.tsx web/src/styles.css
git commit -m "web: canvas page with positioned text boxes, ink, eraser and image drop"
```

---

### Task 5: Every page opens as a canvas

**Files:**
- Modify: `web/src/main.tsx` (lazy import at about line 110, `newNote`, editor block at about lines 1636–1645, `./document` import at line 101, `Block` import at line 103)

**Interfaces:**
- Consumes: `CanvasPage` (Task 4); `emptyCanvasPage`, `stringifyCanvasPage` (Task 1).

- [ ] **Step 1: Swap the lazy editor**

Replace the `const BlockNoteEditor = lazy(...)` line with:

```ts
const CanvasPage = lazy(() => import("./CanvasPage"));
```

- [ ] **Step 2: Render the canvas**

Replace the whole `<div className="single-pane-editor">…</div>` block with:

```tsx
                <div className="page-canvas">
                  <Suspense fallback={<div className="editor-loading">Loading page…</div>}>
                    <CanvasPage
                      key={selectedNote.id}
                      pageID={selectedNote.id}
                      body={selectedNote.body}
                      onChange={editBody}
                      onError={setError}
                      uploadFile={uploadInlineFile}
                      resolveFileUrl={resolveFileUrl}
                    />
                  </Suspense>
                </div>
```

- [ ] **Step 3: New pages are empty canvases**

In `newNote`, replace `body: stringifyNoteDocument(emptyNoteDocument().document),` with `body: stringifyCanvasPage(emptyCanvasPage()),`.

Update the `./document` import to the names still used: `documentText`, `emptyCanvasPage`, `stringifyCanvasPage`. Delete `import type { Block } from "@blocknote/core";` if nothing else uses it (`grep -n "Block\[\]\|: Block\b" web/src/main.tsx`).

- [ ] **Step 4: Verify**

Run: `cd web && npm test && npm run build`
Expected: all tests pass. The build is clean and emits a separate `CanvasPage-*.js` chunk (check `ls dist/assets`).

- [ ] **Step 5: Commit**

```bash
git add web/src/main.tsx
git commit -m "web: open every page as a canvas"
```

---

### Task 6: Docs, embedded bundle and real-browser evidence

**Files:**
- Modify: `DESIGN.md` (§2 Initial scope "freehand drawing" line; §3 Product model; "Later work")
- Modify: `AGENTS.md` (Child DOX Index `web/` BlockNote entry)
- Modify: `FRONTEND_IMPLEMENTATION_PLAN.md` (only if it states the page body is BlockNote-only: `grep -n "blocknote.v1\|BlockNote" FRONTEND_IMPLEMENTATION_PLAN.md`)
- Modify: `UI-VERIFICATION.md`
- Modify: `internal/web/dist/**`

- [ ] **Step 1: Build and embed**

```bash
cd web && npm test && npm run build && cd ..
rsync -a --delete web/dist/ internal/web/dist/
diff -qr web/dist internal/web/dist
go test ./internal/web
```

Expected: tests pass, the build is clean, `diff` prints nothing and `go test` prints `ok`.

- [ ] **Step 2: Real-browser verification**

Use a scratch server on isolated preview data (never production) and the Playwright MCP tools. At 1280×900 in Busnes Light and Dark:

1. **Legacy page.** Open a page created before this change, with headings, a checklist and an image. It shows as one box with the formatting intact. Close it without typing; the network panel shows **no** `PUT /api/v1/objects/…` (Review Focus 1).
2. **Typing.** Click empty space, type, click elsewhere, then type again. There are two boxes. Click empty space inside an empty new box area and that empty box disappears. Reload; the boxes are at the same positions.
3. **Box handles.** Drag a box by its handle, resize it, and with the handle focused move it with the arrow keys. Reload; the changes persist.
4. **Ink.** In Pen mode, draw strokes in three colors and two sizes, then a highlighter stroke over text. Ctrl+Z removes the last stroke and Ctrl+Shift+Z restores it. The eraser removes a touched stroke. Switch to another page and back: undo does nothing there (Review Focus 5). In Dark theme, "ink" strokes are light.
5. **Images.** Drop an image file on empty space; a box holding the image appears and survives a reload.
6. **Work queue.** A checklist item in a second box appears in the Work queue.
7. **Touch.** Emulate a touch device at 1024×768. In Type mode a scroll gesture creates no box. In Pen mode one finger draws (Review Focus 4).
8. **Phone width (390×844).** Boxes stack in reading order at full width. Ink tools are hidden. A page with ink shows the notice. "Add text" works.
9. **Page full.** In the browser console, build a body just under 9 MiB of strokes and open it, then draw. The "page is full" message appears and no PUT is sent (Review Focus 3). If this cannot be driven from the console, record it as **not run**; `pageFits` is unit-tested.

Real stylus pressure needs a pen device. Record it as **unproven** unless a pen device was used.

Save screenshots as `docs/canvas-{light,dark}-{desktop,mobile}.png`.

- [ ] **Step 3: DOX updates**

`DESIGN.md`:
- In §2 Initial scope, move "freehand drawing" out of the deferred sentence.
- In §3, add:

```markdown
- Every page body is `kynotes.canvas.v1`: positioned rich-text boxes (BlockNote block
  arrays) plus ink strokes as flat `[x, y, pressure]` arrays, all inside the object
  ciphertext. Older BlockNote, Tiptap and Markdown bodies open as one box at the origin
  and are rewritten only when edited. Clients clamp and cap decoded canvas input and
  refuse new ink past 9 MiB of serialized body.
```

- In "Later work", remove "freehand drawing".

`AGENTS.md`: replace the sentence fragment about "a lazy-loaded BlockNote JSON editor" in the `web/` entry with:

```markdown
a lazy-loaded canvas page (`CanvasPage.tsx`): positioned BlockNote boxes and
`perfect-freehand` ink in the `kynotes.canvas.v1` body (`document.ts` parses and caps it,
`canvas.ts` holds pure edits). Legacy bodies open as one box and are not rewritten until
edited. Pages reflow to a text column at ≤800px. Verify `document.test.ts`,
`canvas.test.ts`, `ink.test.ts` and the canvas checks in `UI-VERIFICATION.md`.
```

Keep the rest of that entry (attachments, uploads, Tiptap conversion) as it is.

`UI-VERIFICATION.md`: add a dated "Canvas pages" section listing each Step 2 check with its actual result, including any marked not run or unproven, plus the screenshots.

- [ ] **Step 4: Commit**

```bash
git add DESIGN.md AGENTS.md FRONTEND_IMPLEMENTATION_PLAN.md UI-VERIFICATION.md docs/canvas-*.png internal/web/dist
git commit -m "docs: canvas pages design, DOX and verification evidence"
```
