import { describe, expect, it } from "vitest";
import type { PartialBlock } from "@blocknote/core";
import { CANVAS_FORMAT, LEGACY_BOX, MAX_COORD, MAX_STROKE_POINTS, documentText, emptyCanvasPage, isStructuredNoteBody, openPage, pageBlocks, parseNoteDocument, stringifyCanvasPage, stringifyNoteDocument, type CanvasPage } from "./document";

describe("note document format", () => {
  it("round-trips structured content without Markdown", () => {
    const document: PartialBlock[] = [
      { type: "heading", props: { level: 2 }, content: "Launch" },
      { type: "paragraph", content: "Ship it." },
    ];
    const parsed = parseNoteDocument(stringifyNoteDocument(document));
    expect(parsed.document).toEqual(document);
    expect(documentText(stringifyNoteDocument(document))).toBe("Launch Ship it.");
  });

  it("keeps image-only documents addressable", () => {
    const document: PartialBlock[] = [{ type: "image", props: { url: "attachment://att_image", name: "diagram" } }];
    expect(parseNoteDocument(stringifyNoteDocument(document)).document).toEqual(document);
    expect(documentText(stringifyNoteDocument(document))).toBe("[diagram]");
  });

  it("round-trips inline formatting marks", () => {
    const document: PartialBlock[] = [{
      type: "paragraph",
      content: [{ type: "text", text: "Important", styles: { bold: true, italic: true } }],
    }];
    const serialized = stringifyNoteDocument(document);
    expect(parseNoteDocument(serialized).document).toEqual(document);
  });

  it("converts the previous Tiptap document format without flattening it", () => {
    const legacy = JSON.stringify({
      format: "kynotes.tiptap.v1",
      document: {
        type: "doc",
        content: [{
          type: "heading",
          attrs: { level: 2 },
          content: [{ type: "text", text: "Important", marks: [{ type: "bold" }] }],
        }],
      },
    });
    const parsed = parseNoteDocument(legacy);
    expect(parsed.document[0]).toMatchObject({ type: "heading", props: { level: 2 } });
    expect(parsed.document[0].content).toEqual([{ type: "text", text: "Important", styles: { bold: true } }]);
  });

  it("does not silently hide an unrecognized body", () => {
    expect(documentText("not Markdown")).toBe("not Markdown");
  });

  it("keeps legacy content visible until the editor imports it", () => {
    expect(documentText("# Heading\n\n**Bold**")).toContain("# Heading");
  });
});

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
