import type { BlockNoteEditor } from "@blocknote/core";

export type TextEditor = BlockNoteEditor<any, any, any>;
export type Format = "h1" | "h2" | "h3" | "bold" | "italic" | "bullets" | "numbers" | "checklist" | "link" | "code";

export const FORMATS: Array<[Format, string]> = [
  ["h1", "Heading 1"], ["h2", "Heading 2"], ["h3", "Heading 3"],
  ["bold", "Bold"], ["italic", "Italic"],
  ["bullets", "Bulleted list"], ["numbers", "Numbered list"], ["checklist", "Checklist"],
  ["link", "Link"], ["code", "Code"],
];

const BLOCKS: Partial<Record<Format, { type: string; props?: { level: number } }>> = {
  h1: { type: "heading", props: { level: 1 } }, h2: { type: "heading", props: { level: 2 } }, h3: { type: "heading", props: { level: 3 } },
  bullets: { type: "bulletListItem" }, numbers: { type: "numberedListItem" }, checklist: { type: "checkListItem" },
};

/** The block a format turns text into, if it is a block format. */
export const blockOf = (format: Format) => BLOCKS[format];

/** A typed link address, or undefined for anything but http(s) and mailto (no javascript: or data: links). */
export function safeLinkURL(input: string | null): string | undefined {
  const text = input?.trim();
  if (!text) return undefined;
  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:/i.test(text) ? text : `https://${text}`);
    return ["http:", "https:", "mailto:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}

/** Applies one toolbar format to the selection; a block format already applied turns the blocks back into paragraphs. */
export function applyFormat(editor: TextEditor, format: Format, askLink: () => string | null) {
  editor.focus();
  if (format === "bold" || format === "italic" || format === "code") return editor.toggleStyles({ [format]: true });
  if (format === "link") {
    const url = safeLinkURL(askLink());
    if (url) editor.createLink(url, editor.getSelectedText() || url);
    return;
  }
  const target = BLOCKS[format]!;
  const blocks = editor.getSelection()?.blocks ?? [editor.getTextCursorPosition().block];
  const applied = blocks.every((block) => block.type === target.type && (!target.props || block.props.level === target.props.level));
  editor.transact(() => blocks.forEach((block) => editor.updateBlock(block, applied ? { type: "paragraph" } : target)));
}
