import { BlockNoteView } from "@blocknote/mantine";
import { GridSuggestionMenuController, useCreateBlockNote } from "@blocknote/react";
import { getDefaultEmojiPickerItems, type Block, type PartialBlock } from "@blocknote/core";
import { SuggestionMenu, type SuggestionMenuOptions } from "@blocknote/core/extensions";
import { useCallback, useEffect, useRef } from "react";
import "@blocknote/mantine/style.css";
import { localDate, recurrenceEdits } from "./taskDates";
import { emojiQueryReady, emojiTriggerStartsWord } from "./emoji";
import type { TextEditor } from "./format";

type Props = {
  noteID: string;
  initialContent: PartialBlock[];
  legacyMarkdown?: string;
  onChange: (document: Block[]) => void;
  uploadFile: (file: File) => Promise<string>;
  resolveFileUrl: (url: string) => Promise<string>;
  editable?: boolean;
  autoFocus?: boolean;
  onHydrated?: (document: Block[]) => void;
  /** Called with this editor while it holds focus, so the page toolbar formats the box being written in. */
  onActive?: (editor: TextEditor) => void;
};

export function BlockNoteEditor({ noteID, initialContent, legacyMarkdown, onChange, uploadFile, resolveFileUrl, editable = true, autoFocus, onHydrated, onActive }: Props) {
  const hydratedRef = useRef(false);
  const onChangeRef = useRef(onChange);
  const uploadRef = useRef(uploadFile);
  const resolveRef = useRef(resolveFileUrl);
  const hydratedCallback = useRef(onHydrated);
  hydratedCallback.current = onHydrated;
  onChangeRef.current = onChange;
  uploadRef.current = uploadFile;
  resolveRef.current = resolveFileUrl;
  const editor = useCreateBlockNote({
    initialContent: legacyMarkdown ? undefined : initialContent,
    uploadFile: (file) => uploadRef.current(file),
    resolveFileUrl: (url) => resolveRef.current(url),
  }, [noteID]);

  // Stable, so the menu does not reload its items (and drop an Enter) on every re-render.
  const emojiShouldOpen: NonNullable<SuggestionMenuOptions["shouldOpen"]> = useCallback((tr) => emojiTriggerStartsWord(tr.selection.$from.parent.textBetween(0, tr.selection.$from.parentOffset, undefined, " ")), []);
  const emojiItems = useCallback(async (query: string) => {
    if (!emojiQueryReady(query)) {
      editor.getExtension(SuggestionMenu)?.closeMenu();
      return [];
    }
    return (await getDefaultEmojiPickerItems(editor, query)).map(({ id, onItemClick }) => ({ id, onItemClick, icon: <>{id}</> }));
  }, [editor]);

  useEffect(() => {
    hydratedRef.current = false;
    if (legacyMarkdown) {
      const blocks = editor.tryParseMarkdownToBlocks(legacyMarkdown);
      if (blocks.length) {
        editor.replaceBlocks(editor.document, blocks);
        hydratedCallback.current?.(editor.document);
      }
    }
    // BlockNote may report its initial/default document while the component
    // is mounting. Do not treat that hydration event as a user edit.
    hydratedRef.current = true;
  }, [editor, legacyMarkdown]);

  useEffect(() => {
    if (autoFocus) editor.focus();
  }, [editor, autoFocus]);

  return (
    <div className="blocknote-editor" onFocus={() => onActive?.(editor)}>
      <BlockNoteView
        editor={editor}
        editable={editable}
        emojiPicker={false}
        onChange={(current) => {
          if (!hydratedRef.current) return;
          // A ticked repeating item adds its next occurrence; the edit below reports the result.
          const edits = recurrenceEdits(current.document, localDate(new Date()));
          if (!edits.length) return onChangeRef.current(current.document);
          current.transact(() => edits.forEach((edit) => {
            current.updateBlock(edit.id, { content: edit.content as PartialBlock["content"] });
            current.insertBlocks([edit.next as PartialBlock], edit.id, "after");
          }));
        }}
      >
        {/* BlockNote's own picker opens on any ':' ("due:"); this one waits for a word start and two letters. */}
        <GridSuggestionMenuController
          triggerCharacter=":"
          columns={10}
          minQueryLength={2}
          shouldOpen={emojiShouldOpen}
          getItems={emojiItems}
        />
      </BlockNoteView>
    </div>
  );
}
