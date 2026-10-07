import type { PartialBlock } from "@blocknote/core";
import { BOX_MAX_WIDTH, BOX_MIN_WIDTH, DEFAULT_BOX_WIDTH, MAX_BOXES, MAX_COORD, type CanvasBox, type CanvasPage, type CanvasStroke } from "./document";

/** The server stores at most 10 MiB of ciphertext per version; keep headroom. */
export const MAX_PAGE_BYTES = 9 * 1024 * 1024;
export const pageFits = (body: string) => new TextEncoder().encode(body).length <= MAX_PAGE_BYTES;

const GAP = 24;
const DEFAULT_HEIGHT = 120;
const coord = (value: number) => Math.min(MAX_COORD, Math.max(0, Math.round(value)));

export function addBox(page: CanvasPage, x: number, y: number, blocks: PartialBlock[] = [{ type: "paragraph", content: "" }], width = DEFAULT_BOX_WIDTH) {
  if (page.boxes.length >= MAX_BOXES) return undefined;
  const id = crypto.randomUUID();
  return { id, page: { ...page, boxes: [...page.boxes, { id, x: coord(x), y: coord(y), width, blocks }] } };
}

export function updateBox(page: CanvasPage, id: string, change: Partial<Omit<CanvasBox, "id">>): CanvasPage {
  return {
    ...page,
    boxes: page.boxes.map((box) => {
      if (box.id !== id) return box;
      const next = { ...box, ...change };
      const keep = (value: number, old: number) => (Number.isFinite(value) ? value : old);
      return {
        ...next,
        x: coord(keep(next.x, box.x)),
        y: coord(keep(next.y, box.y)),
        width: Math.min(BOX_MAX_WIDTH, Math.max(BOX_MIN_WIDTH, Math.round(keep(next.width, box.width)))),
      };
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

/**
 * Fits a box of `wanted` width at x so its resize edge stays inside the visible
 * window (`left` = scroll offset, `width` = viewport width, surface pixels).
 * A box clicked inside the window never moves past its left edge.
 */
export function fitBox(x: number, wanted: number, view?: { left: number; width: number }) {
  if (!view || view.width <= 0) return { x, width: wanted };
  const right = view.left + view.width - GAP;
  const width = Math.max(BOX_MIN_WIDTH, Math.min(wanted, right - x));
  return { x: Math.max(0, Math.min(x, view.left), Math.min(x, right - width)), width };
}

/** Ctrl/Cmd+Z by the letter on Latin layouts (AZERTY, QWERTZ), by the physical key otherwise. */
export const isUndoKey = ({ key, code }: { key: string; code: string }) =>
  /^[a-z]$/i.test(key) ? key.toLowerCase() === "z" : code === "KeyZ";

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
