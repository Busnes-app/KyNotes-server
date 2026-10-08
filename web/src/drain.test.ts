import { describe, expect, it, vi } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import { NOT_SAVED, noteConflictMessage, notSaved, queuedSaveStep, readyToSend } from "./drain";
import { newContainerKey, writeKey, type KeyFloor, type KeyedContainer, type Keyring } from "./keyring";
import type { PendingSave } from "./storage";

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
