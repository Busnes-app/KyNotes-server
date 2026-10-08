import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import { legacyAtRisk, PASSWORD_CHANGE_NOTE, passwordChangeProblem, passwordChangeWarning, resealWaitingEdits } from "./passwordChange";
import { newContainerKey, WAITING_GENERATION, waitingKey, type KeyFloor } from "./keyring";
import { clearQueuedSave, getNote, pendingSaves, putNote, queueSave } from "./storage";
import { generateIdentity } from "./teamKeys";

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });

describe("password change confirmation", () => {
  it("asks for an acknowledgement only while a notebook may still hold login-key items", () => {
    const floors: Record<string, KeyFloor> = { cnt_a: { shared: 2, closed: 2 }, cnt_b: { shared: 2 }, cnt_c: {} };
    const at = (id: string) => floors[id];
    // Shared and closed here: nothing at risk. Shared but still open, or never shared: at risk.
    expect(legacyAtRisk([{ id: "cnt_a", sharedGeneration: 2 }], at)).toBe(0);
    expect(legacyAtRisk([{ id: "cnt_a", sharedGeneration: 2 }, { id: "cnt_b", sharedGeneration: 2 }, { id: "cnt_c", sharedGeneration: 0 }, { id: "cnt_d", sharedGeneration: 0 }], at)).toBe(3);
    // Never shared counts even with a closure mark: its rows have no other key.
    expect(legacyAtRisk([{ id: "cnt_e", sharedGeneration: 0 }], () => ({ closed: 2 }))).toBe(1);
    expect(passwordChangeWarning(0)).toBeUndefined();
    expect(passwordChangeWarning(2)).toMatch(/^2 notebooks may still hold items sealed with your current password/);
    expect(passwordChangeProblem("a", "a", false, 0)).toBeUndefined();
    expect(passwordChangeProblem("a", "a", false, 1)).toMatch(/confirm/i);
    expect(passwordChangeProblem("a", "a", true, 1)).toBeUndefined();
    expect(passwordChangeProblem("a", "b", true, 0)).toMatch(/do not match/);
    expect(passwordChangeProblem("", "", true, 0)).toBeDefined();
    expect(PASSWORD_CHANGE_NOTE).toMatch(/stopped opening/);
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
    const sent = { id: "obj_s", containerID: cnt, version: 1, payload: await encryptNote(newContainerKey(), cnt, page), updatedAt: "t1", keyGeneration: 3, owner: me };
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

  it("leaves edits sealed with the identity's waiting key alone, counts none of them, and moves login-key ones onto it", async () => {
    for (const entry of await pendingSaves()) await clearQueuedSave(entry.owner ?? "", entry.id);
    const waiting = waitingKey(generateIdentity());
    const underIdentity = { id: "obj_i", containerID: cnt, version: 1, payload: await encryptNote(waiting, cnt, page), updatedAt: "t1", keyGeneration: WAITING_GENERATION, owner: me };
    const underLogin = { id: "obj_l", containerID: cnt, version: 1, payload: await encryptNote(before, cnt, page), updatedAt: "t1", keyGeneration: WAITING_GENERATION, owner: me };
    await queueSave(underIdentity);
    await queueSave(underLogin);
    await putNote(me, underLogin);
    // Nothing is stranded: the identity's entry needs no re-seal, the login-key one moves to the waiting key.
    expect(await resealWaitingEdits("a".repeat(64), "b".repeat(64), waiting)).toBe(0);
    const queued = await pendingSaves();
    expect(queued.find((entry) => entry.id === underIdentity.id)!.payload).toEqual(underIdentity.payload);
    const moved = queued.find((entry) => entry.id === underLogin.id)!.payload;
    await expect(decryptObject(waiting, cnt, moved)).resolves.toEqual(page);
    // Never onto the new login key: the password is no longer what keeps it readable.
    await expect(decryptObject(after, cnt, moved)).rejects.toThrow();
    await expect(decryptObject(waiting, cnt, (await getNote(me, underLogin.id))!.payload)).resolves.toEqual(page);
  });

  it("moves a personal edit queued before P5 at a container generation onto the waiting key, so a password change never strands it (M1)", async () => {
    for (const entry of await pendingSaves()) await clearQueuedSave(entry.owner ?? "", entry.id);
    const waiting = waitingKey(generateIdentity());
    const prior = { id: "obj_p", containerID: cnt, version: 1, payload: await encryptNote(before, cnt, page), updatedAt: "t1", keyGeneration: 1, owner: me };
    await queueSave(prior);
    expect(await resealWaitingEdits("a".repeat(64), "b".repeat(64), waiting)).toBe(0);
    const moved = (await pendingSaves()).find((entry) => entry.id === prior.id)!;
    expect(moved.keyGeneration).toBe(WAITING_GENERATION);
    await expect(decryptObject(waiting, cnt, moved.payload)).resolves.toEqual(page);
  });
});
