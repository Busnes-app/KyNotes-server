import { describe, expect, it, vi } from "vitest";
import { base64, decryptAttachment, decryptObject, encryptAttachment, encryptAttachmentMetadata, encryptNote, legacyKeyRef } from "./crypto";
import { attachmentStep, NOT_SAVED, noteConflictMessage, notSaved, queuedSaveStep, readyToSend } from "./drain";
import { newContainerKey, writeKey, type KeyFloor, type KeyedContainer, type Keyring } from "./keyring";
import type { PendingSave, PendingUpload } from "./storage";

const cnt = `cnt_${"a".repeat(26)}`;
const login = legacyKeyRef("a".repeat(64));

/** The drain as main.tsx runs it: upload only what readyToSend returns. */
async function drain(item: PendingSave, container: KeyedContainer, floor: KeyFloor, ring: Keyring, upload: (save: PendingSave) => void) {
  const ready = await readyToSend(item, container, floor, writeKey(container, ring, login, floor), ring, login);
  if (ready) upload(ready);
  return ready;
}

describe("queued save drain", () => {
  it("never uploads a legacy draft once the notebook is known shared; re-seals it when the key arrives", async () => {
    const note = { title: "draft", body: "before sharing" };
    const legacyDraft: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", keyGeneration: 1, payload: await encryptNote(login, cnt, note) };
    const upload = vi.fn<(save: PendingSave) => void>();
    // This tab learns the notebook was shared (generation 2) before it has the key.
    const shared: KeyFloor = { shared: 2, generation: 2 };
    for (const container of [{ id: cnt, keyGeneration: 1, sharedGeneration: 0 }, { id: cnt, keyGeneration: 2, sharedGeneration: 2 }])
      expect(await drain(legacyDraft, container, shared, new Map(), upload)).toBeUndefined();
    expect(upload).not.toHaveBeenCalled();
    // The key arrives: the draft is re-sealed at the current generation, then uploaded.
    const key = newContainerKey();
    const ready = await drain(legacyDraft, { id: cnt, keyGeneration: 2, sharedGeneration: 2 }, shared, new Map([[2, key]]), upload);
    expect(upload).toHaveBeenCalledOnce();
    expect(ready!.keyGeneration).toBe(2);
    expect(await decryptObject(key, cnt, ready!.payload)).toMatchObject(note);
    for (const [sent] of upload.mock.calls) {
      expect(sent.payload).not.toEqual(legacyDraft.payload);
      await expect(decryptObject(login, cnt, sent.payload)).rejects.toThrow();
    }
  });

  it("re-seals this browser's own legacy and waiting edits after the closure", async () => {
    const key = newContainerKey();
    const ring = new Map([[2, key]]);
    const container = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const closed: KeyFloor = { shared: 2, generation: 2, closed: 2 };
    for (const keyGeneration of [1, 0]) {
      const item: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", keyGeneration, owner: "usr_me", payload: await encryptNote(login, cnt, { title: "mine", body: `queued at ${keyGeneration}` }) };
      const upload = vi.fn<(save: PendingSave) => void>();
      const ready = await drain(item, container, closed, ring, upload);
      expect(upload).toHaveBeenCalledOnce();
      expect(ready!.keyGeneration).toBe(2);
      expect(await decryptObject(key, cnt, ready!.payload)).toMatchObject({ body: `queued at ${keyGeneration}` });
    }
  });

  it("keeps an unstamped queue entry closed: only an owner stamp marks it as this browser's", async () => {
    const ring = new Map([[2, newContainerKey()]]);
    const container = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const item: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", keyGeneration: 1, payload: await encryptNote(login, cnt, { title: "x", body: "y" }) };
    const upload = vi.fn<(save: PendingSave) => void>();
    await expect(drain(item, container, { shared: 2, generation: 2, closed: 2 }, ring, upload)).rejects.toThrow("no content key");
    expect(upload).not.toHaveBeenCalled();
    // Open: the same entry still re-seals (the drain stamps it first in practice).
    expect(await drain(item, container, { shared: 2, generation: 2 }, ring, upload)).toBeDefined();
  });

  it("re-seals this browser's own legacy pending upload after the closure", async () => {
    const key = newContainerKey();
    const ring = new Map([[2, key]]);
    const container = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const floor: KeyFloor = { shared: 2, generation: 2, closed: 2 };
    const file = { name: "a.png", type: "image/png", size: 2 };
    const job: PendingUpload = { uploadId: "upl", containerID: cnt, objectID: "obj", objectVersion: 1, keyGeneration: 1, chunkBytes: 2, nextChunk: 0, payload: await encryptAttachment(login, cnt, new Uint8Array([1, 2])), metadataCiphertext: base64(await encryptAttachmentMetadata(login, cnt, file)), ...file };
    const step = await attachmentStep(job, container, floor, writeKey(container, ring, login, floor), ring, login);
    expect(step).toMatchObject({ kind: "reseal", file });
    if (step.kind === "reseal") expect(step.plaintext).toEqual(new Uint8Array([1, 2]));
    await expect(decryptAttachment(key, cnt, job.payload)).rejects.toThrow();
  });

  it("sends an entry as is only when it is sealed for the current write key", () => {
    const ring = new Map([[1, newContainerKey()]]);
    const unshared = { id: cnt, keyGeneration: 1, sharedGeneration: 0 };
    expect(queuedSaveStep(unshared, {}, 1, writeKey(unshared, ring, login, {}))).toBe("send");
    expect(queuedSaveStep(unshared, undefined, 1, writeKey(unshared, ring, login, {}))).toBe("wait");
    expect(queuedSaveStep(unshared, {}, 0, { key: login, generation: 0 })).toBe("reseal");
    // A server reporting a key generation below sharing: a legacy row of that generation is still re-sealed.
    const odd = { id: cnt, keyGeneration: 1, sharedGeneration: 2 };
    const floor = { shared: 2, generation: 1 };
    expect(writeKey(odd, ring, login, floor)?.generation).toBe(1);
    expect(queuedSaveStep(odd, floor, 1, writeKey(odd, ring, login, floor))).toBe("reseal");
  });
});

describe("save failure messages", () => {
  it("never claims a local copy this browser could not keep", () => {
    expect(noteConflictMessage(false)).toMatch(/preserved locally/);
    expect(noteConflictMessage(true)).not.toMatch(/preserved|saved/i);
    expect(noteConflictMessage(true)).toMatch(/exists only in this tab.*copy or export it now/i);
    expect(() => notSaved()).toThrow(NOT_SAVED);
    expect(NOT_SAVED).toMatch(/^Not saved.*only in this tab/);
  });
});

describe("pending upload provenance", () => {
  it("only the attach flow creates a pending upload, from a file the user picked", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    const writers = Object.entries(sources).filter(([, text]) => /\bputUpload\(/.test(text)).map(([name]) => name);
    expect(writers.sort()).toEqual(["./main.tsx", "./storage.ts"]);
    const main = sources["./main.tsx"];
    // sealUpload stores what it just sealed; the chunk loop only advances nextChunk on that job.
    expect(main.match(/\bputUpload\([^;]*;/g)).toEqual(["putUpload(job);", "putUpload({ ...job, nextChunk });"]);
    expect(main).toMatch(/const sealed = await sealAttachment\(write, container\.id, plaintext, file\);\n.*\n\s*const job = \{[^}]*\.\.\.sealed,/);
    // sealUpload's plaintext: the user's picked file, or a re-seal of this browser's own pending upload.
    const plaintexts = [...main.matchAll(/\bsealUpload\(\w+, [\w.]+, [\w.]+, ([^,]+?), /g)].map((match) => match[1]);
    expect(main.match(/\bsealUpload\(/g)).toHaveLength(plaintexts.length + 1); // + its definition
    expect(plaintexts.sort()).toEqual(["new Uint8Array(await file.arrayBuffer())", "plaintext"]);
    expect(main).toMatch(/resealUpload\(job, container, step\.plaintext, step\.file\)/);
  });
});
