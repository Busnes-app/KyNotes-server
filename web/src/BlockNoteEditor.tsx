import { BlockNoteView } from "@blocknote/mantine";
import { useCreateBlockNote } from "@blocknote/react";
import type { Block, PartialBlock } from "@blocknote/core";
import { useEffect, useRef } from "react";
import "@blocknote/mantine/style.css";

type Props = {
  noteID: string;
  initialContent: PartialBlock[];
  legacyMarkdown?: string;
  onChange: (document: Block[]) => void;
  uploadFile: (file: File) => Promise<string>;
  resolveFileUrl: (url: string) => Promise<string>;
  editable?: boolean;
};

export function BlockNoteEditor({ noteID, initialContent, legacyMarkdown, onChange, uploadFile, resolveFileUrl, editable = true }: Props) {
  const hydratedRef = useRef(false);
  const onChangeRef = useRef(onChange);
  const uploadRef = useRef(uploadFile);
  const resolveRef = useRef(resolveFileUrl);
  onChangeRef.current = onChange;
  uploadRef.current = uploadFile;
  resolveRef.current = resolveFileUrl;
  const editor = useCreateBlockNote({
    initialContent: legacyMarkdown ? undefined : initialContent,
    uploadFile: (file) => uploadRef.current(file),
    resolveFileUrl: (url) => resolveRef.current(url),
  }, [noteID]);

  useEffect(() => {
    if (legacyMarkdown) {
      const blocks = editor.tryParseMarkdownToBlocks(legacyMarkdown);
      if (blocks.length) editor.replaceBlocks(editor.document, blocks);
    }
    // BlockNote may report its initial/default document while the component
    // is mounting. Do not treat that hydration event as a user edit.
    hydratedRef.current = true;
  }, [editor, legacyMarkdown]);

  return (
    <div className="blocknote-editor">
      <BlockNoteView
        editor={editor}
        editable={editable}
        onChange={(current) => {
          if (hydratedRef.current) onChangeRef.current(current.document);
        }}
      />
    </div>
  );
}
