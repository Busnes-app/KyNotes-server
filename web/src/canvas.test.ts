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
