import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import { deleteNote, getNote, pendingSaves, putNote, queueSave, replaceQueuedSave, type PendingSave } from "./storage";
import { drainable, exportUnsent, stuckSaves, unsentEdits } from "./stuckEdits";

const lost = `cnt_${"a".repeat(26)}`, kept = `cnt_${"b".repeat(26)}`;
const legacy = legacyKeyRef("5a".repeat(32));
const save = async (id: string, containerID: string, title: string, key = legacy, owner?: string): Promise<PendingSave> =>
  ({ id, containerID, version: 1, updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0, payload: await encryptNote(key, containerID, { type: "page", title, body: "[]" }), ...(owner ? { owner } : {}) });
const alice = "usr_aaaaaaaaaaaaaaaaaaaaaaaaaa", bob = "usr_bbbbbbbbbbbbbbbbbbbbbbbbbb";

const never = () => Promise.resolve(false);
const team = legacyKeyRef("7c".repeat(32)); // stands in for a team notebook's container key
const opener = (...keys: typeof legacy[]) => async (item: PendingSave) => {
  for (const key of keys) if (await decryptObject(key, item.containerID, item.payload).then(() => true, () => false)) return true;
  return false;
};

describe("stuck edits", () => {
  it("are the queued edits of notebooks the server no longer lists, and none when the list is unknown", async () => {
    const queued = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"d".repeat(26)}`, kept, "here")];
    expect(stuckSaves(queued, new Set([kept])).map((item) => item.containerID)).toEqual([lost]);
    expect(stuckSaves(queued, undefined)).toEqual([]);
  });

  it("are the signed-in account's own; an unstamped entry is offered for export only when this account's key opens it", async () => {
    const opens = (item: PendingSave) => decryptObject(legacy, item.containerID, item.payload).then(() => true, () => false);
    const mine = await save(`obj_${"c".repeat(26)}`, lost, "mine", legacy, alice);
    const theirs = await save(`obj_${"d".repeat(26)}`, lost, "theirs", legacyKeyRef("6b".repeat(32)), bob);
    const oldMine = await save(`obj_${"e".repeat(26)}`, lost, "old mine");
    const oldTheirs = await save(`obj_${"f".repeat(26)}`, lost, "old theirs", legacyKeyRef("6b".repeat(32)));
    const live = await save(`obj_${"g".repeat(26)}`, kept, "live", legacy, alice);
    const queued = [mine, theirs, oldMine, oldTheirs, live];
    expect(await unsentEdits(queued, new Set([kept]), alice, opens, opens)).toEqual({ owned: [mine], unowned: [oldMine], unknown: [], sealed: 1 });
    // Bob sees only his own edit; Alice's stamped edit is never his to discard.
    expect(await unsentEdits(queued, new Set([kept]), bob, never, never)).toEqual({ owned: [theirs], unowned: [], unknown: [], sealed: 2 });
    expect(await unsentEdits(queued, undefined, alice, opens, opens)).toEqual({ owned: [], unowned: [], unknown: [], sealed: 1 });
  });

  it("exports what the key opens and counts the rest", async () => {
    const items = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"e".repeat(26)}`, lost, "sealed elsewhere", legacyKeyRef("6b".repeat(32)))];
    const file = await exportUnsent(items, (item) => decryptObject(legacy, item.containerID, item.payload));
    expect(file.unreadable).toBe(1);
    expect(JSON.parse(file.json)).toEqual([{ id: items[0].id, notebook: lost, updatedAt: "2026-10-07T00:00:00Z", content: expect.objectContaining({ title: "gone" }) }]);
  });
});

describe("drainable", () => {
  it("sends only this account's edits: another account's never, an unstamped one only if this account's legacy key opens it", async () => {
    const opens = (item: PendingSave) => decryptObject(legacy, item.containerID, item.payload).then(() => true);
    // Both accounts may share this team notebook, so the server would accept either upload.
    const mine = await save(`obj_${"c".repeat(26)}`, kept, "mine", legacy, alice);
    const theirs = await save(`obj_${"d".repeat(26)}`, kept, "theirs", legacy, bob);
    const oldMine = await save(`obj_${"e".repeat(26)}`, kept, "old mine");
    const oldTheirs = await save(`obj_${"f".repeat(26)}`, kept, "old theirs", legacyKeyRef("6b".repeat(32)));
    expect((await drainable([mine, theirs, oldMine, oldTheirs], alice, opens)).drain).toEqual([mine, { ...oldMine, owner: alice }]);
    expect((await drainable([mine, theirs, oldMine, oldTheirs], bob, never)).drain).toEqual([theirs]);
  });

  it("stamps an unstamped edit with this account once its legacy key opens it", async () => {
    const oldMine = await save(`obj_${"e".repeat(26)}`, kept, "old mine");
    const { drain, stamp } = await drainable([oldMine], alice, opener(legacy));
    // stamp: the stored entries to rewrite with the owner; drain carries it, so a re-key keeps it.
    expect(stamp).toEqual([oldMine]);
    expect(drain).toEqual([{ ...oldMine, owner: alice }]);
    // Once re-keyed to a team key the legacy key no longer opens it, but the stamp still claims it.
    const rekeyed = { ...drain[0], payload: (await save(oldMine.id, kept, "old mine", team)).payload, keyGeneration: 2 };
    expect(await drainable([rekeyed], alice, opener(legacy))).toEqual({ drain: [rekeyed], stamp: [], superseded: [] });
  });

  it("supersedes a proven unstamped edit when this account queued the same page since", async () => {
    const oldMine = await save(`obj_${"e".repeat(26)}`, kept, "old mine");
    const newer = { ...(await save(oldMine.id, kept, "newer", legacy, alice)), version: 2 };
    expect(await drainable([oldMine, newer], alice, opener(legacy))).toEqual({ drain: [newer], stamp: [], superseded: [oldMine] });
  });
});

describe("two accounts, one page, one browser", () => {
  vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });
  const page = `obj_${"p".repeat(26)}`;
  const theirs = (entries: PendingSave[]) => entries.filter((entry) => entry.owner === alice);

  it("Bob's drain and discard never touch Alice's queued edit or cached draft", async () => {
    const hers = await save(page, lost, "alice's", legacy, alice);
    await queueSave({ ...hers, owner: alice });
    await putNote(alice, hers);
    const his = { ...(await save(page, lost, "bob's", legacyKeyRef("6b".repeat(32)), bob)), updatedAt: "2026-10-07T00:09:00Z" };
    await queueSave({ ...his, owner: bob });
    await putNote(bob, his);
    expect(theirs(await pendingSaves())).toEqual([hers]);
    // Bob's drain: only his entry, and its post-send clear removes only his.
    const { drain } = await drainable(await pendingSaves(), bob, never);
    expect(drain).toEqual([his]);
    expect(await replaceQueuedSave(drain[0])).toBe(true);
    expect(theirs(await pendingSaves())).toEqual([hers]);
    // Bob's discard (Settings, notebook lost): only his own, and only his cached draft.
    await queueSave({ ...his, owner: bob });
    const unsent = await unsentEdits(await pendingSaves(), new Set([kept]), bob, never, never);
    expect(unsent.owned).toEqual([his]);
    for (const item of unsent.owned) if (await replaceQueuedSave(item)) await deleteNote(bob, item.id);
    expect(await pendingSaves()).toEqual([hers]);
    expect((await getNote(alice, page))?.payload).toEqual(hers.payload);
    expect(await getNote(bob, page)).toBeUndefined();
  });
});

describe("edits whose owner is unknown", () => {
  it("are never sent or discarded, and are listed export-only when a key this browser holds opens them", async () => {
    // Queued before stamping, sealed with a team key: the legacy key proves nothing about whose it is.
    const shared = { ...(await save(`obj_${"h".repeat(26)}`, kept, "shared old", team)), keyGeneration: 2 };
    const unreadable = { ...(await save(`obj_${"i".repeat(26)}`, lost, "elsewhere", legacyKeyRef("6b".repeat(32)))), keyGeneration: 2 };
    const queued = [shared, unreadable];
    expect((await drainable(queued, alice, opener(legacy))).drain).toEqual([]);
    const unsent = await unsentEdits(queued, new Set([kept]), alice, opener(legacy), opener(legacy, team));
    expect(unsent).toEqual({ owned: [], unowned: [], unknown: [shared], sealed: 1 });
    // Listed even while the notebook list is unavailable: they never drain, so nothing else shows them.
    expect((await unsentEdits(queued, undefined, alice, opener(legacy), opener(legacy, team))).unknown).toEqual([shared]);
    const file = await exportUnsent(unsent.unknown, (item) => decryptObject(team, item.containerID, item.payload));
    expect(JSON.parse(file.json)).toEqual([expect.objectContaining({ id: shared.id, content: expect.objectContaining({ title: "shared old" }) })]);
  });
});
