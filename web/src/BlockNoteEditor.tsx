import { BlockNoteView } from "@blocknote/mantine";
import { useCreateBlockNote } from "@blocknote/react";
import type { Block, PartialBlock } from "@blocknote/core";
import { useEffect, useRef } from "react";
import "@blocknote/mantine/style.css";
import { localDate, recurrenceEdits } from "./taskDates";

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
};

export function BlockNoteEditor({ noteID, initialContent, legacyMarkdown, onChange, uploadFile, resolveFileUrl, editable = true, autoFocus, onHydrated }: Props) {
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
    <div className="blocknote-editor">
      <BlockNoteView
        editor={editor}
        editable={editable}
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
      />
    </div>
  );
}
