import type { PartialBlock } from "@blocknote/core";

export const NOTE_DOCUMENT_FORMAT = "kynotes.blocknote.v1";

export type NoteDocument = {
  format: typeof NOTE_DOCUMENT_FORMAT;
  document: PartialBlock[];
};

type LegacyNode = {
  type?: string;
  text?: string;
  attrs?: Record<string, unknown>;
  marks?: Array<{ type?: string; attrs?: Record<string, unknown> }>;
  content?: LegacyNode[];
};

function legacyInline(nodes: LegacyNode[] = []): unknown[] {
  return nodes.flatMap((node) => {
    if (node.type === "hardBreak") return [{ type: "text", text: "\n" }];
    if (node.type !== "text" || typeof node.text !== "string") return legacyInline(node.content);
    const styles: Record<string, unknown> = {};
    let link: { href: string; content: unknown[] } | undefined;
    for (const mark of node.marks ?? []) {
      if (mark.type === "bold") styles.bold = true;
      if (mark.type === "italic") styles.italic = true;
      if (mark.type === "strike") styles.strike = true;
      if (mark.type === "code") styles.code = true;
      if (mark.type === "underline") styles.underline = true;
      if (mark.type === "link" && typeof mark.attrs?.href === "string") {
        link = { href: mark.attrs.href, content: [{ type: "text", text: node.text, styles }] };
      }
    }
    if (link) return [{ type: "link", ...link }];
    return [{ type: "text", text: node.text, styles }];
  });
}

function legacyBlocks(nodes: LegacyNode[] = []): PartialBlock[] {
  return nodes.flatMap((node): PartialBlock[] => {
    const content = legacyInline(node.content);
    switch (node.type) {
      case "paragraph": return [{ type: "paragraph", content: content as never }];
      case "heading": return [{ type: "heading", props: { level: Number(node.attrs?.level) || 1 }, content: content as never }];
      case "bulletList": return legacyList(node.content, "bulletListItem");
      case "orderedList": return legacyList(node.content, "numberedListItem");
      case "blockquote": return [{ type: "quote", children: legacyBlocks(node.content) }];
      case "codeBlock": return [{ type: "codeBlock", props: { language: typeof node.attrs?.language === "string" ? node.attrs.language : "" }, content: node.content?.map((child) => child.text ?? "").join("") ?? "" }];
      case "image": return [{ type: "image", props: { url: typeof node.attrs?.src === "string" ? node.attrs.src : "", name: typeof node.attrs?.alt === "string" ? node.attrs.alt : "" } }];
      case "horizontalRule": return [{ type: "divider" }];
      default: return node.content ? legacyBlocks(node.content) : [];
    }
  });
}

function legacyList(nodes: LegacyNode[] = [], type: "bulletListItem" | "numberedListItem"): PartialBlock[] {
  return nodes.filter((node) => node.type === "listItem").map((node) => {
    const blocks = legacyBlocks(node.content);
    const first = blocks[0] ?? { type: "paragraph", content: "" };
    return { ...first, type, children: blocks.slice(1) } as PartialBlock;
  });
}

function legacyTiptapDocument(body: string): PartialBlock[] | undefined {
  try {
    const value = JSON.parse(body) as { format?: string; document?: LegacyNode } & LegacyNode;
    const document = value.format === "kynotes.tiptap.v1" ? value.document : value;
    if (document?.type !== "doc") return undefined;
    return legacyBlocks(document.content);
  } catch {
    return undefined;
  }
}

export const emptyNoteDocument = (): NoteDocument => ({
  format: NOTE_DOCUMENT_FORMAT,
  document: [{ type: "paragraph", content: "" }],
});

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

export function parseNoteDocument(body: string): NoteDocument {
  try {
    const value = JSON.parse(body) as Partial<NoteDocument>;
    if (value.format === NOTE_DOCUMENT_FORMAT && Array.isArray(value.document)) {
      return { format: NOTE_DOCUMENT_FORMAT, document: value.document };
    }
  } catch {
    /* Empty or invalid content is treated as a new document. */
  }
  const legacy = legacyTiptapDocument(body);
  if (legacy) return { format: NOTE_DOCUMENT_FORMAT, document: legacy.length ? legacy : emptyNoteDocument().document };
  if (!body) return emptyNoteDocument();
  return {
    format: NOTE_DOCUMENT_FORMAT,
    document: [{
      type: "paragraph",
      content: body,
    }],
  };
}

export function stringifyNoteDocument(document: PartialBlock[]): string {
  return JSON.stringify({ format: NOTE_DOCUMENT_FORMAT, document });
}

export function documentText(body: string): string {
  const value = pageBlocks(body);
  const text: string[] = [];
  const visit = (node: PartialBlock) => {
    if (typeof node.content === "string") text.push(node.content);
    if (Array.isArray(node.content)) {
      node.content.forEach((inline) => {
        if (typeof inline === "object" && inline !== null && "text" in inline && typeof inline.text === "string") text.push(inline.text);
      });
    }
    if (node.type === "image" && typeof node.props?.name === "string") text.push(`[${node.props.name}]`);
    node.children?.forEach(visit);
  };
  value.forEach(visit);
  return text.join(" ");
}

export function isStructuredNoteBody(body: string): boolean {
  try {
    const value = JSON.parse(body) as Partial<NoteDocument>;
    if (value.format === NOTE_DOCUMENT_FORMAT && Array.isArray(value.document)) return true;
    if ((value as { format?: unknown }).format === CANVAS_FORMAT) return true;
  } catch {
    /* Try the legacy Tiptap envelope below. */
  }
  return legacyTiptapDocument(body) !== undefined;
}
