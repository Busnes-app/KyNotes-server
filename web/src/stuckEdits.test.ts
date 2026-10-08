import { describe, expect, it } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import type { PendingSave } from "./storage";
import { drainable, exportUnsent, stuckSaves, unsentEdits } from "./stuckEdits";

const lost = `cnt_${"a".repeat(26)}`, kept = `cnt_${"b".repeat(26)}`;
const legacy = legacyKeyRef("5a".repeat(32));
const save = async (id: string, containerID: string, title: string, key = legacy, owner?: string): Promise<PendingSave> =>
  ({ id, containerID, version: 1, updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0, payload: await encryptNote(key, containerID, { type: "page", title, body: "[]" }), ...(owner ? { owner } : {}) });
const alice = "usr_aaaaaaaaaaaaaaaaaaaaaaaaaa", bob = "usr_bbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    expect(await unsentEdits(queued, new Set([kept]), alice, opens)).toEqual({ owned: [mine], unowned: [oldMine] });
    // Bob sees only his own edit; Alice's stamped edit is never his to discard.
    expect(await unsentEdits(queued, new Set([kept]), bob, () => Promise.resolve(false))).toEqual({ owned: [theirs], unowned: [] });
    expect(await unsentEdits(queued, undefined, alice, opens)).toEqual({ owned: [], unowned: [] });
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
    expect(await drainable([mine, theirs, oldMine, oldTheirs], alice, opens)).toEqual([mine, oldMine]);
    expect(await drainable([mine, theirs, oldMine, oldTheirs], bob, () => Promise.resolve(false))).toEqual([theirs]);
  });
});
