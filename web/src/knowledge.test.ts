import { describe, expect, it, vi } from "vitest";
import { contextualNotes, graphEdges, indexNotes, noteTags, noteTasks, openTaskNotes, searchNotes } from "./knowledge";
import { emptyCanvasPage, isStructuredNoteBody, stringifyCanvasPage, stringifyNoteDocument } from "./document";

const notes = [
  { id: "a", title: "Launch", body: "See [[b]] #product\n- [ ] Ship beta", updatedAt: "" },
  { id: "b", title: "Beta", body: "#product", updatedAt: "" },
];

describe("local knowledge projections", () => {
  it("indexes links, tags, tasks and context without server data", () => {
    expect(noteTags(notes[0])).toEqual(["product"]);
    expect(noteTasks(notes[0])).toEqual(["Ship beta"]);
    expect(graphEdges(notes)).toEqual([{ from: "a", to: "b" }]);
    expect(searchNotes(notes, "beta").map((note) => note.id)).toEqual(["a", "b"]);
    expect(contextualNotes(notes, notes[0]).map((note) => note.id)).toEqual(["b"]);
  });

  it("keeps the caller's ordering so the sort control survives search", () => {
    const sorted = [notes[1], notes[0]];
    expect(searchNotes(indexNotes(sorted), "").map((match) => match.note.id)).toEqual(["b", "a"]);
    expect(searchNotes(indexNotes(sorted), "product").map((match) => match.note.id)).toEqual(["b", "a"]);
  });

  it("searches flattened text but keeps the structured note it came from", () => {
    const body = stringifyNoteDocument([
      { type: "heading", props: { level: 2 }, content: "Launch" },
      { type: "paragraph", content: [{ type: "text", text: "Ship it", styles: { bold: true } }] },
    ]);
    const index = indexNotes([{ id: "a", title: "Launch", body, updatedAt: "" }]);
    const [match] = searchNotes(index, "ship it");
    expect(match.body).toBe("Launch Ship it");
    // Reopening a note from the list must not feed the editor flattened text.
    expect(match.note.body).toBe(body);
    expect(isStructuredNoteBody(match.note.body)).toBe(true);
    expect(noteTasks(index[0])).toEqual([]);
  });

  it("finds open BlockNote checklist items without exposing them to the server", () => {
    const body = stringifyNoteDocument([
      { type: "checkListItem", props: { checked: false }, content: "Ship the inbox" },
      { type: "checkListItem", props: { checked: true }, content: "Already done" },
    ]);
    expect(noteTasks({ id: "c", title: "Queue", body, updatedAt: "" })).toEqual(["Ship the inbox"]);
    expect(noteTasks(indexNotes([{ id: "c", title: "Queue", body, updatedAt: "" }])[0])).toEqual(["Ship the inbox"]);
  });

  it("keeps only notes with open tasks in the work queue", () => {
    expect(openTaskNotes(notes).map((note) => note.id)).toEqual(["a"]);
  });
});

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

describe("projection cache", () => {
  const canvas = stringifyCanvasPage({
    ...emptyCanvasPage(),
    boxes: [{ id: "b", x: 0, y: 0, width: 300, blocks: [{ type: "checkListItem", props: { checked: false }, content: "Ink later" }] }],
    strokes: [{ id: "s", tool: "pen", color: "ink", size: 4, points: [1, 2, 0.5] }],
  });
  it("projects each note object once", () => {
    const note = { id: "c", title: "", body: canvas, updatedAt: "" };
    const parse = vi.spyOn(JSON, "parse");
    try {
      const first = indexNotes([note])[0];
      expect(noteTasks(first)).toEqual(["Ink later"]);
      expect(parse).toHaveBeenCalledTimes(2); // text once, tasks once
      expect(indexNotes([note])[0]).toBe(first);
      expect(noteTasks(first)).toEqual(["Ink later"]);
      expect(parse).toHaveBeenCalledTimes(2);
      indexNotes([{ ...note }]);
      expect(parse).toHaveBeenCalledTimes(3); // an edited page is a new object
    } finally {
      parse.mockRestore();
    }
  });
});
