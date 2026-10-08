import { describe, expect, it } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import type { PendingSave } from "./storage";
import { exportUnsent, stuckSaves } from "./stuckEdits";

const lost = `cnt_${"a".repeat(26)}`, kept = `cnt_${"b".repeat(26)}`;
const legacy = legacyKeyRef("5a".repeat(32));
const save = async (id: string, containerID: string, title: string, key = legacy): Promise<PendingSave> =>
  ({ id, containerID, version: 1, updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0, payload: await encryptNote(key, containerID, { type: "page", title, body: "[]" }) });

describe("stuck edits", () => {
  it("are the queued edits of notebooks the server no longer lists, and none when the list is unknown", async () => {
    const queued = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"d".repeat(26)}`, kept, "here")];
    expect(stuckSaves(queued, new Set([kept])).map((item) => item.containerID)).toEqual([lost]);
    expect(stuckSaves(queued, undefined)).toEqual([]);
  });

  it("exports what the key opens and counts the rest", async () => {
    const items = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"e".repeat(26)}`, lost, "sealed elsewhere", legacyKeyRef("6b".repeat(32)))];
    const file = await exportUnsent(items, (item) => decryptObject(legacy, item.containerID, item.payload));
    expect(file.unreadable).toBe(1);
    expect(JSON.parse(file.json)).toEqual([{ id: items[0].id, notebook: lost, updatedAt: "2026-10-07T00:00:00Z", content: expect.objectContaining({ title: "gone" }) }]);
  });
});
