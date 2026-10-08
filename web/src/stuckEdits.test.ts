import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { decryptObject, encryptNote } from "./crypto";
import { newContainerKey } from "./keyring";
import { deleteNote, getNote, pendingSaves, putNote, queueSave, replaceQueuedSave, type PendingSave } from "./storage";
import { exportUnsent, stuckSaves, unsentEdits } from "./stuckEdits";

const LOST = `cnt_${"a".repeat(26)}`, LIVE = `cnt_${"b".repeat(26)}`;
const key = newContainerKey(), other = newContainerKey();
const alice = "usr_aaaaaaaaaaaaaaaaaaaaaaaaaa", bob = "usr_bbbbbbbbbbbbbbbbbbbbbbbbbb";
const save = async (id: string, containerID: string, title: string, owner: string, sealedWith = key): Promise<PendingSave> =>
  ({ id, containerID, version: 1, updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 2, owner, payload: await encryptNote(sealedWith, containerID, { type: "page", title, body: "[]" }) });

describe("stuck edits", () => {
  it("are the queued edits of notebooks the server no longer lists, and none when the list is unknown", async () => {
    const queued = [await save(`obj_${"c".repeat(26)}`, LOST, "gone", alice), await save(`obj_${"d".repeat(26)}`, LIVE, "here", alice)];
    expect(stuckSaves(queued, new Set([LIVE])).map((item) => item.containerID)).toEqual([LOST]);
    expect(stuckSaves(queued, undefined)).toEqual([]);
  });

  it("lists only this account's edits for notebooks no longer listed", () => {
    const mine = { id: "obj_a", containerID: LOST, owner: "usr_me" } as PendingSave;
    const live = { id: "obj_b", containerID: LIVE, owner: "usr_me" } as PendingSave;
    const theirs = { id: "obj_c", containerID: LOST, owner: "usr_other" } as PendingSave;
    expect(unsentEdits([mine, live, theirs], new Set([LIVE]), "usr_me")).toEqual([mine]);
    expect(unsentEdits([mine], undefined, "usr_me")).toEqual([]);
  });

  it("exports what the key opens and counts the rest", async () => {
    const items = [await save(`obj_${"c".repeat(26)}`, LOST, "gone", alice), await save(`obj_${"e".repeat(26)}`, LOST, "sealed elsewhere", alice, other)];
    const file = await exportUnsent(items, (item) => decryptObject(key, item.containerID, item.payload));
    expect(file.unreadable).toBe(1);
    expect(JSON.parse(file.json)).toEqual([{ id: items[0].id, notebook: LOST, updatedAt: "2026-10-07T00:00:00Z", content: expect.objectContaining({ title: "gone" }) }]);
  });
});

describe("two accounts, one page, one browser", () => {
  vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });
  const page = `obj_${"p".repeat(26)}`;
  const hersOnly = (entries: PendingSave[]) => entries.filter((entry) => entry.owner === alice);

  it("Bob's drain and discard never touch Alice's queued edit or cached draft", async () => {
    const hers = await save(page, LOST, "alice's", alice);
    await queueSave(hers);
    await putNote(alice, hers);
    const his = { ...(await save(page, LOST, "bob's", bob, other)), updatedAt: "2026-10-07T00:09:00Z" };
    await queueSave(his);
    await putNote(bob, his);
    expect(hersOnly(await pendingSaves())).toEqual([hers]);
    // Bob's drain (main.tsx drainQueue): only his entry, and its post-send clear removes only his.
    const drain = (await pendingSaves()).filter((item) => item.owner === bob);
    expect(drain).toEqual([his]);
    expect(await replaceQueuedSave(drain[0])).toBe(true);
    expect(hersOnly(await pendingSaves())).toEqual([hers]);
    // Bob's discard (Settings, notebook lost): only his own, and only his cached draft.
    await queueSave(his);
    const unsent = unsentEdits(await pendingSaves(), new Set([LIVE]), bob);
    expect(unsent).toEqual([his]);
    for (const item of unsent) if (await replaceQueuedSave(item)) await deleteNote(bob, item.id);
    expect(await pendingSaves()).toEqual([hers]);
    expect((await getNote(alice, page))?.payload).toEqual(hers.payload);
    expect(await getNote(bob, page)).toBeUndefined();
  });
});
