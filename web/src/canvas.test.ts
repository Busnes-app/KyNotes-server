import { describe, expect, it } from "vitest";
import { History, MAX_PAGE_BYTES, addBox, contentExtent, eraseAt, fitBox, freeSpot, isEmptyBox, isUndoKey, pageFits, pruneEmpty, readingOrder, updateBox } from "./canvas";
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
  it("keeps the previous value for non-finite input", () => {
    const page = { ...emptyCanvasPage(), boxes: [box("a", 10, 20)] };
    expect(updateBox(page, "a", { x: NaN, y: Infinity }).boxes[0]).toMatchObject({ x: 10, y: 20 });
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

describe("box placement", () => {
  const view = (left: number, width: number) => ({ left, width });
  it("keeps the click point when the box fits the visible window", () => {
    expect(fitBox(100, 640, view(0, 1200))).toEqual({ x: 100, width: 640 });
  });
  it("narrows a box clicked near the right edge, then shifts it left", () => {
    expect(fitBox(800, 640, view(0, 1200))).toEqual({ x: 800, width: 376 });
    expect(fitBox(1150, 640, view(0, 1200))).toEqual({ x: 1016, width: 160 });
  });
  it("measures the right edge from the scroll offset", () => {
    // Scrolled 400px right: the visible window is [400, 1575).
    expect(fitBox(1350, 640, view(400, 1175))).toEqual({ x: 1350, width: 201 });
    expect(fitBox(1500, 640, view(400, 1175))).toEqual({ x: 1391, width: 160 });
  });
  it("keeps the left edge visible on a canvas narrower than a box", () => {
    expect(fitBox(50, 640, view(0, 150))).toEqual({ x: 0, width: 160 });
    expect(fitBox(450, 640, view(400, 150))).toEqual({ x: 400, width: 160 });
  });
  it("leaves placement alone without a measured window", () => {
    expect(fitBox(300, 640)).toEqual({ x: 300, width: 640 });
    expect(fitBox(300, 640, view(0, 0))).toEqual({ x: 300, width: 640 });
  });
  it("keeps an off-window spot such as Add text at the page origin", () => {
    expect(fitBox(0, 640, view(900, 1200))).toEqual({ x: 0, width: 640 });
  });
});

describe("undo key", () => {
  it("matches the letter Z on any Latin layout", () => {
    expect(isUndoKey({ key: "z", code: "KeyZ" })).toBe(true); // QWERTY
    expect(isUndoKey({ key: "Z", code: "KeyZ" })).toBe(true); // Shift
    expect(isUndoKey({ key: "z", code: "KeyW" })).toBe(true); // AZERTY
    expect(isUndoKey({ key: "z", code: "KeyY" })).toBe(true); // QWERTZ
  });
  it("ignores another Latin letter on the physical Z key", () => {
    expect(isUndoKey({ key: "w", code: "KeyZ" })).toBe(false); // AZERTY
    expect(isUndoKey({ key: "y", code: "KeyZ" })).toBe(false); // QWERTZ
  });
  it("falls back to the physical key on non-Latin layouts", () => {
    expect(isUndoKey({ key: "я", code: "KeyZ" })).toBe(true);
    expect(isUndoKey({ key: "я", code: "KeyQ" })).toBe(false);
  });
});
