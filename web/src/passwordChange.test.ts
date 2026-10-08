import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import { PASSWORD_CHANGE_WARNING, passwordChangeProblem, resealWaitingEdits } from "./passwordChange";
import { getNote, pendingSaves, putNote, queueSave } from "./storage";

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });

describe("password change confirmation", () => {
  it("warns what becomes unreadable and what happens to waiting team edits", () => {
    expect(PASSWORD_CHANGE_WARNING).toMatch(/unreadable/i);
    expect(PASSWORD_CHANGE_WARNING).toMatch(/waiting on this browser .* re-encrypted/i);
  });

  it("requires matching passwords and an explicit acknowledgement", () => {
    expect(passwordChangeProblem("", "", true)).toBeDefined();
    expect(passwordChangeProblem("a", "b", true)).toMatch(/do not match/);
    expect(passwordChangeProblem("a", "a", false)).toMatch(/confirm/i);
    expect(passwordChangeProblem("a", "a", true)).toBeUndefined();
  });
});

describe("waiting edits across a password change", () => {
  const cnt = "cnt_0123456789abcdefghjkmnpqrs";
  const before = legacyKeyRef("a".repeat(64));
  const after = legacyKeyRef("b".repeat(64));
  const reseal = () => resealWaitingEdits("a".repeat(64), "b".repeat(64));
  const page = { type: "page" as const, title: "Waiting", body: "text" };
  const me = "usr_0123456789abcdefghjkmnpqrs";

  it("re-seals generation-0 queue entries and their drafts for the new login key, and nothing else", async () => {
    const waiting = { id: "obj_w", containerID: cnt, version: 1, payload: await encryptNote(before, cnt, page), updatedAt: "t1", keyGeneration: 0, owner: me };
    const sent = { id: "obj_s", containerID: cnt, version: 1, payload: await encryptNote(before, cnt, page), updatedAt: "t1", keyGeneration: 3, owner: me };
    await queueSave(waiting);
    await queueSave(sent);
    await putNote(me, waiting);
    expect(await reseal()).toBe(0);
    const queued = await pendingSaves();
    const resealed = queued.find((entry) => entry.id === waiting.id)!;
    expect(resealed.keyGeneration).toBe(0);
    await expect(decryptObject(after, cnt, resealed.payload)).resolves.toEqual(page);
    await expect(decryptObject(after, cnt, (await getNote(me, waiting.id))!.payload)).resolves.toEqual(page);
    // A container-key generation is untouched.
    expect(queued.find((entry) => entry.id === sent.id)!.payload).toEqual(sent.payload);
    // Running again finds nothing the old key opens, and changes nothing.
    expect(await reseal()).toBe(1);
    await expect(decryptObject(after, cnt, (await pendingSaves()).find((entry) => entry.id === waiting.id)!.payload)).resolves.toEqual(page);
  });

  it("leaves a generation-0 row that is not this browser's queued edit alone", async () => {
    // A server row labelled 0 is never queued (an edit queues at the write key), so nothing re-seals it.
    const row = { id: "obj_r", containerID: cnt, version: 2, payload: await encryptNote(before, cnt, page), updatedAt: "t2", keyGeneration: 0 };
    await putNote(me, row);
    await reseal();
    expect((await getNote(me, row.id))!.payload).toEqual(row.payload);
    expect((await pendingSaves()).some((entry) => entry.id === row.id)).toBe(false);
  });
});
