// web/src/CanvasPage.tsx
import { memo, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Block, PartialBlock } from "@blocknote/core";
import { BlockNoteEditor } from "./BlockNoteEditor";
import {
  DEFAULT_BOX_WIDTH, INK_COLORS, LEGACY_BOX, MAX_STROKE_POINTS, MAX_STROKES, openPage, stringifyCanvasPage,
  type CanvasBox, type CanvasPage as Page, type CanvasStroke, type InkColor,
} from "./document";
import { History, addBox, contentExtent, eraseAt, fitBox, freeSpot, isUndoKey, pageFits, pruneEmpty, readingOrder, updateBox } from "./canvas";
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
  hydrated: (id: string, blocks: Block[]) => void;
  startDrag: (event: React.PointerEvent<HTMLElement>, id: string, mode: "move" | "resize") => void;
  dragMove: (event: React.PointerEvent<HTMLElement>) => void;
  endDrag: () => void;
  nudge: (event: React.KeyboardEvent, id: string) => void;
  observe: (element: HTMLElement) => () => void;
  uploadFile: (file: File) => Promise<string>;
  resolveFileUrl: (url: string) => Promise<string>;
};

type BoxProps = { pageID: string; box: CanvasBox; rank: number; autoFocus: boolean; editable: boolean; legacyMarkdown?: string; actions: React.RefObject<Actions | null> };

// Memoised on the box object: typing in one box re-renders only that box.
const Box = memo(function Box({ pageID, box, rank, autoFocus, editable, legacyMarkdown, actions }: BoxProps) {
  const act = () => actions.current!;
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => act().observe(ref.current!), []);
  return (
    <div ref={ref} data-box={box.id} className="canvas-box" style={{ left: box.x, top: box.y, width: box.width, order: rank }}>
      <div
        className="canvas-box-handle"
        role="button"
        tabIndex={0}
        aria-label={`Move text box ${rank + 1} with arrow keys`}
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
        editable={editable}
        onChange={(blocks) => act().change(box.id, blocks)}
        onHydrated={(blocks) => act().hydrated(box.id, blocks)}
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
  editable?: boolean;
};

export default function CanvasPage({ pageID, body, onChange, onError, uploadFile, resolveFileUrl, editable = true }: Props) {
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
  const drag = useRef<{ id: string; mode: "move" | "resize"; px: number; py: number; x: number; y: number; width: number; start: Page } | null>(null);
  const activePointer = useRef<number | null>(null);
  const history = useRef(new History<CanvasStroke[]>());
  const paths = useRef(new WeakMap<CanvasStroke, string>());
  const size = SIZES[tool === "highlighter" ? "highlighter" : "pen"][sizeIndex];

  const show = (next: Page) => {
    pageRef.current = next;
    setPage(next);
  };
  // ponytail: every keystroke stringifies and encrypts the whole page, and the list/search
  // index re-parses that one page's boxes (strokes skipped, other pages cached per object).
  // Upgrade path: debounce serialization or cache the serialized strokes per ink commit.
  /** Shows and emits a change. `guard` refuses growth past the page byte limit (ink only). */
  const commit = (next: Page, guard = false) => {
    if (!editable) return false;
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
  // Measured box heights size the surface, so ink and clicks reach below long notes.
  const [heights, setHeights] = useState<Record<string, number>>({});
  const observer = useRef<ResizeObserver | null>(null);
  useEffect(() => () => observer.current?.disconnect(), []);
  const observe = (element: HTMLElement) => {
    observer.current ??= new ResizeObserver((entries) => setHeights((previous) => {
      const next = { ...previous };
      for (const entry of entries) {
        const target = entry.target as HTMLElement;
        next[target.dataset.box!] = target.offsetHeight;
      }
      return next;
    }));
    observer.current.observe(element);
    return () => observer.current?.unobserve(element);
  };
  // The visible window in surface pixels. Phone reflow ignores stored widths, so it
  // never fits (and never persists) a phone-sized width.
  const view = () => {
    const scroll = surfaceRef.current?.parentElement;
    return scroll && !narrow() ? { left: scroll.scrollLeft, width: scroll.clientWidth } : undefined;
  };
  // Narrow an unedited legacy box for display only; never emits a change.
  useLayoutEffect(() => {
    const box = pageRef.current.boxes.find((entry) => entry.id === LEGACY_BOX);
    if (!box) return;
    const { width } = fitBox(box.x, box.width, view());
    if (width < box.width) show(updateBox(pageRef.current, LEGACY_BOX, { width }));
  }, []);
  const placeBox = (x: number, y: number, blocks?: PartialBlock[]) => {
    if (!editable) return;
    const spot = fitBox(x, DEFAULT_BOX_WIDTH, view());
    const added = addBox(pruneEmpty(pageRef.current), spot.x, y, blocks, spot.width);
    if (!added) return onError("This page has the maximum number of text boxes.");
    setFocusID(added.id);
    // An empty text box is saved by its first edit, so a stray click changes nothing.
    if (blocks) commit(added.page);
    else show(added.page);
  };
  // Uploads finish after later renders; place through the latest editable/onChange.
  const placeLatest = useRef(placeBox);
  placeLatest.current = placeBox;

  const actions = useRef<Actions>(null);
  actions.current = {
    change: (id, blocks) => commit(updateBox(pageRef.current, id, { blocks })),
    // Parsed legacy markdown replaces the raw paragraph locally; no save until the user edits.
    hydrated: (id, blocks) => show(updateBox(pageRef.current, id, { blocks })),
    startDrag: (event, id, mode) => {
      if (!editable) return;
      const box = pageRef.current.boxes.find((entry) => entry.id === id);
      if (!box || event.button !== 0) return;
      event.currentTarget.setPointerCapture(event.pointerId);
      drag.current = { id, mode, px: event.clientX, py: event.clientY, x: box.x, y: box.y, width: box.width, start: pageRef.current };
    },
    dragMove: (event) => {
      if (!editable) return;
      const d = drag.current;
      if (!d) return;
      const dx = event.clientX - d.px;
      const dy = event.clientY - d.py;
      show(updateBox(pageRef.current, d.id, d.mode === "move" ? { x: d.x + dx, y: d.y + dy } : { width: d.width + dx }));
    },
    endDrag: () => {
      if (!drag.current) return;
      const { start } = drag.current;
      drag.current = null;
      if (pageRef.current !== start) commit(pageRef.current);
    },
    nudge: (event, id) => {
      if (!editable) return;
      const step = event.shiftKey ? 50 : 10;
      const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[event.key];
      const box = pageRef.current.boxes.find((entry) => entry.id === id);
      if (!delta || !box) return;
      event.preventDefault();
      commit(updateBox(pageRef.current, id, { x: box.x + delta[0], y: box.y + delta[1] }));
    },
    observe,
    uploadFile,
    resolveFileUrl,
  };

  const undo = () => {
    if (!editable) return;
    const previous = history.current.undo(pageRef.current.strokes);
    if (previous) commit({ ...pageRef.current, strokes: previous });
  };
  const redo = () => {
    if (!editable) return;
    const next = history.current.redo(pageRef.current.strokes);
    if (next) commit({ ...pageRef.current, strokes: next });
  };
  const undoKeys = useRef<(event: KeyboardEvent) => void>(() => {});
  undoKeys.current = (event) => {
    if (!(event.ctrlKey || event.metaKey) || !isUndoKey(event)) return;
    const target = event.target as HTMLElement | null;
    if (target?.closest?.(".bn-container, dialog, input, textarea, select, [contenteditable]:not([contenteditable=false])")) return; // text undo belongs to the editor
    event.preventDefault();
    if (event.shiftKey) redo();
    else undo();
  };
  useEffect(() => {
    if (!editable) return;
    const listener = (event: KeyboardEvent) => undoKeys.current(event);
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [editable]);
  useEffect(() => {
    if (editable) return;
    draft.current = null;
    eraseStart.current = null;
    drag.current = null;
    activePointer.current = null;
  }, [editable]);

  const erase = (x: number, y: number) => {
    const current = pageRef.current;
    const strokes = eraseAt(current.strokes, x, y, ERASER_RADIUS);
    if (strokes !== current.strokes) show({ ...current, strokes });
  };

  const inkDown = (event: React.PointerEvent<SVGSVGElement>) => {
    if (!editable) return;
    if (event.pointerType === "pen") penSeen.current = true;
    else if (event.pointerType === "touch" && penSeen.current) return; // palm rejection once a pen is in use
    if (event.button !== 0 || activePointer.current !== null) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    activePointer.current = event.pointerId;
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
    if (event.pointerId !== activePointer.current) return;
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
  const inkUp = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.pointerId !== activePointer.current) return;
    activePointer.current = null;
    const start = eraseStart.current;
    if (start) {
      eraseStart.current = null;
      if (pageRef.current.strokes !== start && commit(pageRef.current)) history.current.push(start);
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

  // `click` (not pointerdown) so a touch scroll never creates a box.
  const onSurfaceClick = (event: React.MouseEvent) => {
    if (!editable || tool !== "type" || event.target !== surfaceRef.current || narrow()) return;
    const { x, y } = local(event);
    placeBox(x, y);
  };
  const onDrop = async (event: React.DragEvent) => {
    if (!editable || event.target !== surfaceRef.current) return; // drops on a box belong to its editor
    const files = [...event.dataTransfer.files].filter((file) => file.type.startsWith("image/"));
    if (!files.length) return;
    event.preventDefault();
    const { x, y } = local(event);
    for (const [index, file] of files.entries()) {
      try {
        const url = await uploadFile(file);
        placeLatest.current(x + index * 24, y + index * 24, [{ type: "image", props: { url, name: file.name } }]);
      } catch (error) {
        onError(error instanceof Error ? error.message : "Unable to add image");
      }
    }
  };
  const pathOf = (stroke: CanvasStroke) => {
    let path = paths.current.get(stroke);
    if (path === undefined) {
      path = strokePath(stroke.points, stroke.size, stroke.tool === "highlighter");
      paths.current.set(stroke, path);
    }
    return path;
  };

  const extent = contentExtent(page, heights);
  const ranks = readingOrder(page.boxes);
  return (
    <div className={`canvas-page tool-${editable ? tool : "type"}`}>
      <div className="canvas-toolbar" role="toolbar" aria-label="Page tools">
        {TOOLS.map(([value, label]) => (
          <button key={value} className={value === "type" ? "quiet" : "quiet ink-tool"} aria-pressed={tool === value} disabled={!editable} onClick={() => setTool(value)}>{label}</button>
        ))}
        {(tool === "pen" || tool === "highlighter") && (
          <>
            {INK_COLORS.map((choice) => (
              <button key={choice} className={`quiet ink-tool ink-swatch ink-${choice}`} aria-label={`${choice} ink`} aria-pressed={color === choice} disabled={!editable} onClick={() => setColor(choice)} />
            ))}
            {SIZES[tool].map((value, index) => (
              <button key={value} className="quiet ink-tool" aria-label={`Size ${value}`} aria-pressed={sizeIndex === index} disabled={!editable} onClick={() => setSizeIndex(index)}>
                {["S", "M", "L"][index]}
              </button>
            ))}
          </>
        )}
        <button className="quiet ink-tool" disabled={!editable} onClick={undo} aria-keyshortcuts="Control+Z">Undo ink</button>
        <button className="quiet ink-tool" disabled={!editable} onClick={redo} aria-keyshortcuts="Control+Shift+Z">Redo ink</button>
        <button className="quiet" disabled={!editable} onClick={() => { const spot = freeSpot(pageRef.current, heights); placeBox(spot.x, spot.y); }}>Add text</button>
      </div>
      {page.strokes.length > 0 && <p className="canvas-ink-note">This page has ink. Open it on a wider screen to see it.</p>}
      <div className="canvas-scroll">
        <div
          ref={surfaceRef}
          className="canvas-surface"
          style={{ width: extent.width + 400, height: extent.height + 400 }}
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
              editable={editable}
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
