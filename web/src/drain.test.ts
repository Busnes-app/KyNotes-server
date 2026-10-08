import { describe, expect, it, vi } from "vitest";
import { base64, decryptAttachment, decryptObject, encryptAttachment, encryptAttachmentMetadata, encryptNote } from "./crypto";
import { attachmentStep, NOT_SAVED, noteConflictMessage, notSaved, queuedSaveStep, readyToSend } from "./drain";
import { newContainerKey, WAITING_GENERATION, waitingKey, writeKey, type KeyFloor, type KeyedContainer, type Keyring } from "./keyring";
import type { PendingSave, PendingUpload } from "./storage";
import { generateIdentity } from "./teamKeys";

const cnt = `cnt_${"a".repeat(26)}`;
const waiting = waitingKey(generateIdentity());

/** The drain as main.tsx runs it: upload only what readyToSend returns. */
async function drain(item: PendingSave, container: KeyedContainer, floor: KeyFloor, ring: Keyring, upload: (save: PendingSave) => void) {
  const ready = await readyToSend(item, container, floor, writeKey(container, ring, floor), ring, waiting);
  if (ready) upload(ready);
  return ready;
}

describe("queued save drain", () => {
  it("never uploads a waiting edit while there is no write key; re-seals it when the key arrives", async () => {
    const note = { title: "draft", body: "made while keys were missing" };
    const draft: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", keyGeneration: WAITING_GENERATION, owner: "usr_me", payload: await encryptNote(waiting, cnt, note) };
    const upload = vi.fn<(save: PendingSave) => void>();
    const floor: KeyFloor = { shared: 2, generation: 2 };
    for (const container of [{ id: cnt, keyGeneration: 1, sharedGeneration: 0 }, { id: cnt, keyGeneration: 2, sharedGeneration: 2 }])
      expect(await drain(draft, container, floor, new Map(), upload)).toBeUndefined();
    expect(upload).not.toHaveBeenCalled();
    const key = newContainerKey();
    const ready = await drain(draft, { id: cnt, keyGeneration: 2, sharedGeneration: 2 }, floor, new Map([[2, key]]), upload);
    expect(upload).toHaveBeenCalledOnce();
    expect(ready!.keyGeneration).toBe(2);
    expect(await decryptObject(key, cnt, ready!.payload)).toMatchObject(note);
    await expect(decryptObject(waiting, cnt, ready!.payload)).rejects.toThrow();
  });

  it("re-seals an entry from its own generation's key, and keeps one whose key this browser lacks", async () => {
    const k2 = newContainerKey(), k3 = newContainerKey();
    const container = { id: cnt, keyGeneration: 3, sharedGeneration: 2 };
    const floor: KeyFloor = { shared: 2, generation: 3 };
    const item: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", keyGeneration: 2, owner: "usr_me", payload: await encryptNote(k2, cnt, { title: "mine", body: "queued at 2" }) };
    const upload = vi.fn<(save: PendingSave) => void>();
    const ready = await drain(item, container, floor, new Map([[2, k2], [3, k3]]), upload);
    expect(ready!.keyGeneration).toBe(3);
    expect(await decryptObject(k3, cnt, ready!.payload)).toMatchObject({ body: "queued at 2" });
    // Without generation 2's key nothing else is tried, the waiting key included: it stays queued.
    await expect(drain(item, container, floor, new Map([[3, k3]]), upload)).rejects.toThrow("no content key");
    // Below the first keyed generation there is no key at all.
    await expect(drain({ ...item, keyGeneration: 1 }, container, floor, new Map([[1, k2], [3, k3]]), upload)).rejects.toThrow("no content key");
    expect(upload).toHaveBeenCalledOnce();
  });

  it("re-seals this browser's own waiting pending upload", async () => {
    const key = newContainerKey();
    const ring = new Map([[2, key]]);
    const container = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const floor: KeyFloor = { shared: 2, generation: 2 };
    const file = { name: "a.png", type: "image/png", size: 2 };
    const job: PendingUpload = { uploadId: "upl", containerID: cnt, objectID: "obj", objectVersion: 1, keyGeneration: WAITING_GENERATION, chunkBytes: 2, nextChunk: 0, payload: await encryptAttachment(waiting, cnt, new Uint8Array([1, 2])), metadataCiphertext: base64(await encryptAttachmentMetadata(waiting, cnt, file)), ...file };
    const step = await attachmentStep(job, container, floor, writeKey(container, ring, floor), ring, waiting);
    expect(step).toMatchObject({ kind: "reseal", file });
    if (step.kind === "reseal") expect(step.plaintext).toEqual(new Uint8Array([1, 2]));
    await expect(decryptAttachment(key, cnt, job.payload)).rejects.toThrow();
  });

  it("sends an entry as is only when it is sealed for the current write key; an unkeyed notebook has none and waits", () => {
    const ring = new Map([[1, newContainerKey()]]);
    const unkeyed = { id: cnt, keyGeneration: 1, sharedGeneration: 0 };
    expect(queuedSaveStep({}, 1, writeKey(unkeyed, ring, {}))).toBe("wait");
    expect(queuedSaveStep(undefined, 1, { key: ring.get(1)!, generation: 1 })).toBe("wait");
    expect(queuedSaveStep({}, 0, { key: ring.get(1)!, generation: 1 })).toBe("reseal");
    expect(queuedSaveStep({}, 1, { key: ring.get(1)!, generation: 1 })).toBe("send");
  });
});

describe("waiting edits", () => {
  it("a waiting edit survives a password change: it opens only with the identity's waiting key", async () => {
    const page = { title: "waiting", body: "edit" };
    const k2 = newContainerKey();
    const shared = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const before: PendingSave = { id: "obj", containerID: cnt, version: 1, updatedAt: "t", owner: "usr_me", keyGeneration: WAITING_GENERATION, payload: await encryptNote(waiting, cnt, page) };
    const ready = await readyToSend(before, shared, { shared: 2, generation: 2 }, { key: k2, generation: 2 }, new Map([[2, k2]]), waiting);
    expect(ready?.keyGeneration).toBe(2);
    await expect(decryptObject(k2, cnt, ready!.payload)).resolves.toMatchObject({ title: page.title });
    // Without the waiting key (another identity, or none) it stays queued, never re-sealed from a wrong key.
    await expect(readyToSend(before, shared, { shared: 2, generation: 2 }, { key: k2, generation: 2 }, new Map([[2, k2]]))).rejects.toThrow();
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
