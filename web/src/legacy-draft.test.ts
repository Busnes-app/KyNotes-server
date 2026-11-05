import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { encryptNote, openObject } from "./crypto";
import { localDraft, prepareDraft } from "./drafts";
import { newContainerKey } from "./keyring";
import { getNote, getQueuedSave, putDraft, putNote, queueSave, settleDraft, type CachedNote } from "./storage";

const owner = "usr_owner", containerID = "cnt_notebook", id = "obj_page";
const key = newContainerKey(), remote = { type: "page" as const, title: "Server", body: "body" };
const open = async (copy: CachedNote) => (await openObject(key, containerID, id, copy.payload, true)).payload;
const read = (mode: "recover" | "read" = "recover", server = async () => remote) => localDraft({ owner, id, version: 3, mode, open, server });
const copy = async (title: string, version = 3, updatedAt = "2") => ({ id, containerID, version, keyGeneration: 2, updatedAt,
  payload: await encryptNote(key, containerID, id, { ...remote, title }) });

beforeEach(() => vi.stubGlobal("indexedDB", new IDBFactory()));
afterEach(() => vi.unstubAllGlobals());

for (const version of [2, 3]) for (const timestamp of ["1", "2"]) for (const conflicted of [false, true]) {
  it(`recovers mixed cache over base${version}/time${timestamp}/held${conflicted} and survives prepare/settle/reload`, async () => {
    await putDraft({ ...await copy("Older pending", version, timestamp), owner, ...(conflicted ? { conflicted: true as const } : {}) });
    const latest = await copy("LATEST"); await putNote(owner, latest);
    const selected = await read(); expect(selected?.payload).toEqual(latest.payload);
    expect(await getNote(owner, id)).toMatchObject({ unsent: true, payload: latest.payload });
    expect(await getQueuedSave(owner, id)).toMatchObject({ payload: latest.payload });
    expect((await getQueuedSave(owner, id))?.conflicted).toBeUndefined();
    const prepared = await prepareDraft({ owner, containerID, note: { ...remote, id, title: "LATEST", version: 3, updatedAt: "2" }, write: { key, generation: 2 } });
    expect(prepared.payload).toEqual(latest.payload); await putDraft(prepared); await settleDraft(prepared, 4);
    expect(await localDraft({ owner, id, version: 4, mode: "recover", open, server: async () => ({ ...remote, title: "LATEST" }) })).toMatchObject({ version: 4, payload: latest.payload });
    expect(await getQueuedSave(owner, id)).toBeUndefined();
  });
}

it.each([true, false])("renders a concurrent replacement, marked=%s, without applying stale plaintext proof", async marked => {
  await queueSave({ ...await copy("Older pending", 2, "1"), owner });
  const original = await copy("First legacy"), replacement = { ...await copy("Concurrent latest", 3, "3"), ...(marked ? { unsent: true as const } : {}) };
  await putNote(owner, original);
  let calls = 0;
  const selected = await read("recover", async () => { if (calls++ === 0) await putNote(owner, replacement); return remote; });
  expect(selected?.payload).toEqual(replacement.payload);
  expect((await getQueuedSave(owner, id))?.payload).toEqual(replacement.payload);
  expect(calls).toBe(marked ? 1 : 2);
});

it("does not mark a concurrent replacement whose plaintext equals the server", async () => {
  const queued = { ...await copy("Older pending", 2, "1"), owner };
  await queueSave(queued); await putNote(owner, await copy("First legacy"));
  let calls = 0;
  await read("recover", async () => { if (calls++ === 0) await putNote(owner, await copy("Server", 3, "3")); return remote; });
  expect((await getNote(owner, id))?.unsent).toBeUndefined();
  expect(await getQueuedSave(owner, id)).toEqual(queued);
});

it.each(["older ordinary", "equal server", "gone", "previousKey", "other account"])("preserves %s recovery boundary", async variant => {
  const queued = { ...await copy("Older pending", 2, "1"), owner,
    ...(variant === "gone" ? { gone: true as const } : {}), ...(variant === "previousKey" ? { previousKey: true as const } : {}) };
  if (variant === "gone" || variant === "previousKey") await queueSave(queued);
  const local = await copy(variant === "equal server" ? "Server" : "LATEST", variant === "older ordinary" ? 2 : 3);
  await putNote(variant === "other account" ? "usr_other" : owner, local);
  const selected = await read();
  if (variant === "older ordinary" || variant === "other account") expect(selected).toBeUndefined();
  expect((await getNote(owner, id))?.unsent).toBeUndefined();
  expect(await getQueuedSave(owner, id)).toEqual(variant === "gone" || variant === "previousKey" ? queued : undefined);
});

it("read-only selection exports latest mixed text without changing either store", async () => {
  const queued = { ...await copy("Older pending", 2, "1"), owner, conflicted: true as const };
  const latest = await copy("LATEST"); await queueSave(queued); await putNote(owner, latest);
  expect((await read("read"))?.payload).toEqual(latest.payload);
  expect(await getQueuedSave(owner, id)).toEqual(queued); expect(await getNote(owner, id)).toEqual(latest);
});
