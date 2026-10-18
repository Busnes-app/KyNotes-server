import type { PartialBlock } from "@blocknote/core";
import { describe, expect, it } from "vitest";
import type { Note } from "./api";
import { stringifyCanvasPage, stringifyNoteDocument } from "./document";
import { buildNotebookExport, EXPORT_FORMAT, safeName, type ExportedAttachment, type NotebookInput } from "./exportNotebook";
import type { Group, Section } from "./pages";

const id = (prefix: string, c: string) => `${prefix}_${c.repeat(26)}`;
const GROUP = id("obj", "g"), SEC_A = id("obj", "a"), SEC_B = id("obj", "b");
const IMG = id("att", "1"), PDF = id("att", "2"), BAD = id("att", "3");
const text = (value: string): PartialBlock[] => [{ type: "paragraph", content: value }];
const page = (c: string, title: string, body: string, extra: Partial<Note> = {}): Note => ({ id: id("obj", c), title, body, version: 1, updatedAt: "", ...extra });
// The stub serializer shows exactly which blocks reached it.
const toMarkdown = (blocks: PartialBlock[]) => JSON.stringify(blocks);
const decode = (data: Uint8Array) => new TextDecoder().decode(data);

function input(overrides: Partial<NotebookInput<{ id: string }>> = {}, opened: string[] = []): NotebookInput<{ id: string }> {
  const groups: Group[] = [{ id: GROUP, type: "group", title: "Work", color: "blue", order: "a0", version: 1 }];
  const sections: Section[] = [
    { id: SEC_B, type: "section", title: "Plans", color: "green", order: "a1", group: GROUP, version: 1 },
    { id: SEC_A, type: "section", title: "Ideas", color: "orange", order: "a0", version: 1 },
  ];
  const notes = [
    page("2", "Second", stringifyNoteDocument(text("two")), { section: SEC_A, order: "a1", level: 1 }),
    page("1", "First", stringifyNoteDocument([{ type: "image", props: { url: `attachment://${IMG}`, name: "photo" } }]), { section: SEC_A, order: "a0" }),
    page("3", "Board", stringifyCanvasPage({ format: "kynotes.canvas.v1", boxes: [{ id: "b1", x: 0, y: 0, width: 640, blocks: text("on canvas") }], strokes: [] }), { section: SEC_B }),
    page("4", "", stringifyNoteDocument(text("quick")), {}),
  ];
  const files: Record<string, ExportedAttachment> = {
    [IMG]: { id: IMG, name: "photo one.png", type: "image/png", bytes: new Uint8Array([1, 2, 3]) },
    [PDF]: { id: PDF, name: "report.pdf", type: "application/pdf", bytes: new Uint8Array([4]) },
  };
  return {
    name: "My Notebook",
    notes, sections, groups, unreadable: 0, toMarkdown,
    attachments: {
      list: async (pageID) => (pageID === id("obj", "1") ? [{ id: IMG }, { id: IMG }, { id: BAD }] : pageID === id("obj", "2") ? [{ id: IMG }, { id: PDF }, { id: BAD }] : []),
      open: async (ref) => { opened.push(ref.id); if (!files[ref.id]) throw new Error("wrong key"); return files[ref.id]; },
    },
    ...overrides,
  };
}

describe("notebook export", () => {
  it("lays pages out as Markdown files by group and section, in notebook order", async () => {
    const result = await buildNotebookExport(input(), new Date("2026-10-17T00:00:00Z"));
    expect(result.entries.map((entry) => entry.path)).toEqual([
      "My Notebook/manifest.json",
      `My Notebook/attachments/${IMG}/photo one.png`,
      "My Notebook/Ideas/001 First.md",
      `My Notebook/attachments/${PDF}/report.pdf`,
      "My Notebook/Ideas/002 Second.md",
      "My Notebook/Work/Plans/001 Board.md",
      "My Notebook/Work/Plans/001 Board.canvas.json",
      "My Notebook/Quick Notes/001 Untitled page.md",
    ]);
    expect(result.pages).toBe(4);
    const manifest = JSON.parse(decode(result.entries[0].data));
    expect(manifest).toMatchObject({ format: EXPORT_FORMAT, notebook: "My Notebook", exportedAt: "2026-10-17T00:00:00.000Z", unreadable: 1 });
    expect(manifest.groups).toEqual([{ id: GROUP, title: "Work", color: "blue", parent: null, path: "Work" }]);
    expect(manifest.sections.map((s: { path: string; group: string | null }) => [s.path, s.group])).toEqual([["Ideas", null], ["Work/Plans", GROUP]]);
    expect(manifest.pages.map((p: { path: string; level: number; section: string | null }) => [p.path, p.level, p.section])).toEqual([
      ["Ideas/001 First.md", 0, SEC_A], ["Ideas/002 Second.md", 1, SEC_A], ["Work/Plans/001 Board.md", 0, SEC_B], ["Quick Notes/001 Untitled page.md", 0, null],
    ]);
  });

  it("points inline images at the exported file and lists every attachment, each decrypted once", async () => {
    const opened: string[] = [];
    const result = await buildNotebookExport(input({}, opened));
    expect(opened).toEqual([IMG, BAD, PDF]);
    const first = decode(result.entries.find((entry) => entry.path.endsWith("001 First.md"))!.data);
    expect(first).toContain(`"url":"../attachments/${IMG}/photo%20one.png"`);
    expect(first).not.toContain("attachment://");
    expect(first).toContain(`- [photo one.png](../attachments/${IMG}/photo%20one.png)`);
    const second = decode(result.entries.find((entry) => entry.path.endsWith("002 Second.md"))!.data);
    expect(second).toContain(`- [report.pdf](../attachments/${PDF}/report.pdf)`);
    expect(result.entries.filter((entry) => entry.path.includes(IMG))).toHaveLength(1);
    expect(result.unreadable).toBe(1);
  });

  it("keeps a canvas page as its kynotes.canvas.v1 body beside a Markdown reading copy", async () => {
    const notebook = input();
    const result = await buildNotebookExport(notebook);
    const json = result.entries.find((entry) => entry.path.endsWith(".canvas.json"))!;
    expect(decode(json.data)).toBe(notebook.notes[2].body);
    const markdown = decode(result.entries.find((entry) => entry.path.endsWith("001 Board.md"))!.data);
    expect(markdown).toContain("on canvas");
    expect(markdown).toContain("[001 Board.canvas.json](001%20Board.canvas.json)");
  });

  it("counts what it could not read instead of failing", async () => {
    const result = await buildNotebookExport(input({ unreadable: 2, attachments: { list: async () => { throw new Error("offline"); }, open: async () => { throw new Error("unused"); } } }));
    expect(result.unreadable).toBe(2 + 4);
    expect(JSON.parse(decode(result.entries[0].data)).unreadable).toBe(6);
  });

  it("never writes a path that leaves the export or collides, whatever the titles say", async () => {
    const hostile = ["../../etc/passwd", "..", "/abs", "C:\\Windows", "con", "NUL.txt", " . ", "a\u202egnp.exe", "tab\there", "same", "SAME", "x".repeat(300)];
    const sections: Section[] = hostile.map((title, i) => ({ id: id("obj", "abcdefghjkmn"[i]), type: "section", title, color: "gray", order: `a${i}`, version: 1 }));
    const notes = sections.map((section, i) => page("pqrstvwxyz01"[i], hostile[i], "", { section: section.id }));
    const result = await buildNotebookExport(input({ name: "..", sections, groups: [], notes }));
    const paths = result.entries.map((entry) => entry.path);
    expect(new Set(paths.map((path) => path.toLowerCase())).size).toBe(paths.length);
    for (const path of paths) {
      expect(path.startsWith("Notebook/"), path).toBe(true);
      for (const segment of path.split("/")) {
        expect(segment, path).not.toMatch(/^\.+$|^$|[\\:<>"|?*\u0000-\u001f\u202e]|^(con|nul)(\.|$)/i);
        expect(Array.from(segment).length, path).toBeLessThanOrEqual(120);
      }
    }
    expect(paths).toContain("Notebook/same (2)/001 same.md");
  });

  it("makes safe names", () => {
    expect(safeName("  ../a/b  ", "x")).toBe("_a_b");
    expect(safeName("...", "x")).toBe("x");
    expect(safeName("aux", "x")).toBe("_aux");
    expect(safeName("Notes: 2026?", "x")).toBe("Notes_ 2026_");
    expect(safeName("😀".repeat(150), "x")).toBe("😀".repeat(100));
  });
});
