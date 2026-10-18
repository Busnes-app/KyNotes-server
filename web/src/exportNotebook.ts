import type { PartialBlock } from "@blocknote/core";
import type { Note } from "./api";
import { CANVAS_FORMAT, pageBlocks } from "./document";
import { displayLevels, groupParents, groupPath, sectionGroup } from "./outline";
import { compareOrdered, pagesInSection, QUICK_NOTES, sortedSections, type Group, type Section } from "./pages";
import type { ZipEntry } from "./zip";

/** docs/EXPORT.md describes this layout; bump the version when it changes. */
export const EXPORT_FORMAT = "kynotes.export.v1";
const ATTACHMENT_URL = "attachment://";
const ATTACHMENTS = "attachments";
// No fetch: browsers load no image from an unknown scheme.
const PLACEHOLDER = "kynotes-export:";
const MAX_NAME = 100;

export type ExportedAttachment = { id: string; name: string; type: string; bytes: Uint8Array };
/** Reads one page's attachments; open decrypts one, and is called once per attachment id. */
export type AttachmentSource<T extends { id: string }> = {
  list: (pageID: string) => Promise<T[]>;
  open: (ref: T) => Promise<ExportedAttachment>;
};
export type NotebookInput<T extends { id: string }> = {
  name: string;
  notes: Note[];
  sections: Section[];
  groups: Group[];
  unreadable: number;
  attachments: AttachmentSource<T>;
  toMarkdown: (blocks: PartialBlock[]) => string;
};

const UNSAFE = /[\u0000-\u001f\u007f-\u009f<>:"/\\|?*‎‏‪-‮⁦-⁩]/g;
const RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;

/** One path segment that is safe on Windows, macOS and Linux and can never climb out of the export. */
export function safeName(name: string, fallback: string): string {
  const trim = (value: string) => value.replace(/^[\s.]+|[\s.]+$/g, "");
  const cleaned = trim(Array.from(trim(name.normalize("NFC").replace(UNSAFE, "_"))).slice(0, MAX_NAME).join(""));
  if (!cleaned) return fallback;
  return RESERVED.test(cleaned) ? `_${cleaned}` : cleaned;
}

/** Hands out names unique per directory, case-insensitively, as "Name (2)". */
function namer() {
  const used = new Map<string, Set<string>>();
  return (dir: string, name: string, extension = "") => {
    const taken = used.get(dir) ?? new Set<string>();
    used.set(dir, taken);
    for (let n = 1; ; n += 1) {
      const candidate = n === 1 ? name : `${name} (${n})`;
      const keys = [candidate + extension, ...(extension === ".md" ? [`${candidate}.canvas.json`] : [])].map((key) => key.toLowerCase());
      if (keys.some((key) => taken.has(key))) continue;
      keys.forEach((key) => taken.add(key));
      return candidate;
    }
  };
}

const join = (...segments: string[]) => segments.filter(Boolean).join("/");
/** Relative, URL-encoded link from file `from` to file `to`. */
function linkTo(from: string, to: string): string {
  const dir = from.split("/").slice(0, -1), target = to.split("/");
  let shared = 0;
  while (shared < dir.length && shared < target.length - 1 && dir[shared] === target[shared]) shared += 1;
  return "../".repeat(dir.length - shared) + target.slice(shared).map(encodeURIComponent).join("/");
}

function isCanvas(body: string): boolean {
  try { return (JSON.parse(body) as { format?: unknown }).format === CANVAS_FORMAT; } catch { return false; }
}

/**
 * Markdown for one page, with inline attachment URLs pointing at the exported files (unknown ids
 * stay as they were). BlockNote's serializer renders media into the live document, which would
 * fetch any URL it sees: it gets inert placeholders and the real URLs go in afterwards.
 */
function pageMarkdown(blocks: PartialBlock[], toMarkdown: (blocks: PartialBlock[]) => string, paths: Map<string, string>, from: string): string {
  const urls: string[] = [];
  const hide = (list: PartialBlock[]): PartialBlock[] => list.map((block) => {
    const url = (block.props as { url?: unknown } | undefined)?.url;
    let placeholder: string | undefined;
    if (typeof url === "string" && url) {
      const target = url.startsWith(ATTACHMENT_URL) ? paths.get(url.slice(ATTACHMENT_URL.length)) : undefined;
      placeholder = `${PLACEHOLDER}${urls.push(target ? linkTo(from, target) : url) - 1}`;
    }
    return {
      ...block,
      ...(placeholder ? { props: { ...block.props, url: placeholder } } : {}),
      ...(block.children ? { children: hide(block.children) } : {}),
    } as PartialBlock;
  });
  return toMarkdown(hide(blocks)).replace(new RegExp(`${PLACEHOLDER}(\\d+)`, "g"), (_, index: string) => urls[Number(index)] ?? "");
}

/**
 * Builds the plaintext export of one decrypted notebook: Markdown per page, canvas pages also as
 * their kynotes.canvas.v1 JSON, attachments as files, and manifest.json. Runs in the browser only.
 */
export async function buildNotebookExport<T extends { id: string }>(input: NotebookInput<T>, exportedAt = new Date()): Promise<{ entries: ZipEntry[]; pages: number; unreadable: number }> {
  const encoder = new TextEncoder();
  const name = namer();
  const root = safeName(input.name, "Notebook");
  const entries: ZipEntry[] = [];
  let unreadable = input.unreadable;
  name(root, "manifest", ".json");
  name(root, ATTACHMENTS);

  const parents = groupParents(input.groups);
  const groupDirs = new Map<string, string>();
  const groupDir = (id: string | undefined): string => {
    if (id === undefined) return root;
    const known = groupDirs.get(id);
    if (known !== undefined) return known;
    const parentDir = groupDir(parents.get(id));
    const group = input.groups.find((entry) => entry.id === id)!;
    const dir = join(parentDir, name(parentDir, safeName(group.title, "Untitled group")));
    groupDirs.set(id, dir);
    return dir;
  };
  // Siblings get their names in notebook order, so "(2)" goes to the later one.
  [...input.groups].sort(compareOrdered).sort((a, b) => groupPath(a.id, parents).length - groupPath(b.id, parents).length).forEach((group) => groupDir(group.id));
  const sections = sortedSections(input.sections);
  const sectionDirs = new Map(sections.map((section) => {
    const parentDir = groupDir(sectionGroup(section, parents));
    return [section.id, join(parentDir, name(parentDir, safeName(section.title, "Untitled section")))] as const;
  }));

  const attachmentPaths = new Map<string, string>();
  const attachmentMeta = new Map<string, { id: string; name: string; type: string; path: string }>();
  const failed = new Set<string>();
  const pageAttachments = async (pageID: string) => {
    let refs: T[];
    try { refs = await input.attachments.list(pageID); } catch { unreadable += 1; return []; }
    const found: Array<{ id: string; name: string; type: string; path: string }> = [];
    for (const ref of refs) {
      if (failed.has(ref.id) || found.some((entry) => entry.id === ref.id)) continue;
      let meta = attachmentMeta.get(ref.id);
      if (!meta) {
        try {
          const opened = await input.attachments.open(ref);
          const dir = join(root, ATTACHMENTS, safeName(ref.id, "attachment"));
          const path = join(dir, safeName(opened.name, "file"));
          meta = { id: ref.id, name: opened.name, type: opened.type, path };
          attachmentMeta.set(ref.id, meta);
          attachmentPaths.set(ref.id, path);
          entries.push({ path, data: opened.bytes });
        } catch {
          failed.add(ref.id);
          unreadable += 1;
          continue;
        }
      }
      found.push(meta);
    }
    return found;
  };

  const manifestPages: unknown[] = [];
  const lists: Array<[string | undefined, string]> = [
    ...sections.map((section) => [section.id, sectionDirs.get(section.id)!] as [string, string]),
    [undefined, join(root, name(root, "Quick Notes"))],
  ];
  for (const [sectionID, dir] of lists) {
    const pages = pagesInSection(input.notes, input.sections, sectionID ?? QUICK_NOTES);
    const levels = displayLevels(pages);
    for (const [index, page] of pages.entries()) {
      const title = page.title.trim() || "Untitled page";
      const base = name(dir, `${String(index + 1).padStart(3, "0")} ${safeName(title, "Untitled page")}`, ".md");
      const path = join(dir, `${base}.md`);
      const attachments = await pageAttachments(page.id);
      const canvas = isCanvas(page.body);
      let markdown = `# ${title.replace(/\s+/g, " ")}\n\n${pageMarkdown(pageBlocks(page.body), input.toMarkdown, attachmentPaths, path).trim()}\n`;
      if (canvas) markdown += `\n_Canvas page: positions and ink are in [${base}.canvas.json](${linkTo(path, join(dir, `${base}.canvas.json`))})._\n`;
      if (attachments.length) markdown += `\n## Attachments\n\n${attachments.map((entry) => `- [${entry.name.replace(/[[\]\\]/g, "\\$&")}](${linkTo(path, entry.path)})`).join("\n")}\n`;
      entries.push({ path, data: encoder.encode(markdown) });
      if (canvas) entries.push({ path: join(dir, `${base}.canvas.json`), data: encoder.encode(page.body) });
      manifestPages.push({
        id: page.id,
        title: page.title,
        section: sectionID ?? null,
        level: levels[index],
        path: path.slice(root.length + 1),
        ...(canvas ? { canvas: join(dir, `${base}.canvas.json`).slice(root.length + 1) } : {}),
        attachments: attachments.map((entry) => ({ ...entry, path: entry.path.slice(root.length + 1) })),
      });
    }
  }

  const manifest = {
    format: EXPORT_FORMAT,
    notebook: input.name,
    exportedAt: exportedAt.toISOString(),
    groups: input.groups.map((group) => ({ id: group.id, title: group.title, color: group.color, parent: parents.get(group.id) ?? null, path: groupDirs.get(group.id)!.slice(root.length + 1) })),
    sections: sections.map((section) => ({ id: section.id, title: section.title, color: section.color, group: sectionGroup(section, parents) ?? null, path: sectionDirs.get(section.id)!.slice(root.length + 1) })),
    pages: manifestPages,
    unreadable,
  };
  entries.unshift({ path: join(root, "manifest.json"), data: encoder.encode(`${JSON.stringify(manifest, null, 2)}\n`) });
  return { entries, pages: manifestPages.length, unreadable };
}

/** BlockNote's own Markdown serializer, loaded only when an export runs. Needs a DOM, not a mounted editor. */
export async function blockNoteMarkdown(): Promise<(blocks: PartialBlock[]) => string> {
  const { BlockNoteEditor } = await import("@blocknote/core");
  const editor = BlockNoteEditor.create();
  return (blocks) => editor.blocksToMarkdownLossy(blocks);
}
