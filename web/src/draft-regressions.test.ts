import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encryptNote, hkdfSha256, openObject, type KeyRef } from "./crypto";
import { prepareDraft } from "./drafts";
import { readyToSend } from "./drain";
import { clearFloors, floorOf, raiseFloorIn } from "./floors";
import { keysAllowed, newContainerKey, waitingKey, writeKey, type KeyedContainer } from "./keyring";
import { KeysWaitingError, sendObject, setWriteKeySource } from "./outbound";
import { getNote, putDraft, putNote, recoverDraft, replaceQueuedSave, settleDraft } from "./storage";
import { generateIdentity } from "./teamKeys";
import type { Note } from "./api";

const owner = "usr_test", cnt = `cnt_${"a".repeat(26)}`, id = `obj_${"a".repeat(26)}`;
const page = { type: "page" as const, title: "Unsent", body: "text", legacy: {} };
const note: Note = { id, ...page, version: 3, updatedAt: "t" };
async function legacyObject(key: KeyRef) {
  const enc = new TextEncoder();
  const material = hkdfSha256(key, 32, enc.encode(cnt), enc.encode("kynotes/object/v1"));
  const aes = await crypto.subtle.importKey("raw", new Uint8Array(material).buffer, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bytes = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, enc.encode(JSON.stringify(page)));
  return new Uint8Array([...iv, ...new Uint8Array(bytes)]);
}

beforeEach(() => { vi.stubGlobal("indexedDB", new IDBFactory()); clearFloors(); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); clearFloors(); });

it.each(["queued", "cache-only"])("converts a matching local v1 %s to bound v2 once and reuses it", async (source) => {
  const key = newContainerKey();
  const item = { owner, id, containerID: cnt, version: 3, keyGeneration: 2, updatedAt: "t", payload: await legacyObject(key) };
  if (source === "queued") await putDraft(item);
  else await putNote(owner, { ...item, unsent: true });
  const prepared = await prepareDraft({ owner, containerID: cnt, note, write: { key, generation: 2 } });
  await expect(openObject(key, cnt, id, prepared.payload, false)).resolves.toEqual({ payload: page, v1: false });
  await expect(openObject(key, cnt, "obj_other", prepared.payload, false)).rejects.toThrow();
  await putDraft(prepared);
  const retry = await prepareDraft({ owner, containerID: cnt, note, write: { key, generation: 2 } });
  expect(retry.payload).toEqual(prepared.payload);
});

for (const generation of [0, 2]) {
  it.each(["saved", "conflict"])(`keeps generation${generation} queue/cache conversion atomic through %s and reload`, async (outcome) => {
    const old = generation === 0 ? waitingKey(generateIdentity()) : newContainerKey(), key = newContainerKey();
    const item = { owner, id, containerID: cnt, version: 3, keyGeneration: generation, updatedAt: "t", payload: await encryptNote(old, cnt, id, page) };
    await putDraft(item);
    const container: KeyedContainer = { id: cnt, keyGeneration: 3, sharedGeneration: 2 };
    const floor = { shared: 2, generation: 3 };
    const ring = new Map([[2, old], [3, key]]);
    const ready = await readyToSend(item, container, floor, { key, generation: 3 }, ring, old);
    if (!ready) throw new Error("missing re-sealed draft");
    expect(await replaceQueuedSave(item, ready)).toBe(true);
    expect.soft((await getNote(owner, id))?.payload).toEqual(ready.payload);
    expect.soft((await recoverDraft(owner, id))?.payload).toEqual(ready.payload);
    if (outcome === "saved") {
      await settleDraft(ready, 4);
      expect(await recoverDraft(owner, id)).toBeUndefined();
      expect(await getNote(owner, id)).toMatchObject({ version: 4, keyGeneration: 3 });
      expect((await getNote(owner, id))?.unsent).toBeUndefined();
    } else {
      expect(await replaceQueuedSave(ready, { ...ready, conflicted: true })).toBe(true);
      expect(await recoverDraft(owner, id)).toMatchObject({ conflicted: true, keyGeneration: 3 });
    }
  });
}

it("preserves a different same-timestamp cache through conversion and settlement", async () => {
  const key = newContainerKey();
  const item = { owner, id, containerID: cnt, version: 3, keyGeneration: 2, updatedAt: "t", payload: await encryptNote(key, cnt, id, page) };
  await putDraft(item);
  const newer = { ...item, unsent: true as const, payload: await encryptNote(key, cnt, id, { ...page, title: "Newer" }) };
  await putNote(owner, newer);
  const prepared = await prepareDraft({ owner, containerID: cnt, note: { ...note, title: "Newer" }, write: { key, generation: 2 } });
  expect(prepared.payload).toEqual(newer.payload);
  const ready = { ...item, keyGeneration: 3, payload: new Uint8Array([2]) };
  expect(await replaceQueuedSave(item, ready)).toBe(true);
  await settleDraft(ready, 4);
  expect((await getNote(owner, id))?.payload).toEqual(newer.payload);
  expect((await recoverDraft(owner, id))?.payload).toEqual(newer.payload);
});

describe("object digest before the final outbound gate", () => {
  it.each(["floor", "unmount"])("refuses a send after %s changes while hashing", async (change) => {
    const key = newContainerKey(), container = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };
    raiseFloorIn(cnt, { shared: 2, generation: 2 });
    const unregister = setWriteKeySource(c => { const floor = floorOf(c.id); return floor && keysAllowed(c, floor) ? writeKey(c, new Map([[2, key]]), floor) : undefined; });
    const requests: RequestInit[] = [];
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { if (init) requests.push(init); return new Response('{"version":4}'); });
    const hash = await crypto.subtle.digest("SHA-256", new Uint8Array([1]));
    let release = (_value: ArrayBuffer) => {};
    const held = new Promise<ArrayBuffer>(resolve => { release = resolve; });
    vi.spyOn(crypto.subtle, "digest").mockImplementation(() => held);
    try {
      const result = sendObject({ container, generation: 2 }, id, new Uint8Array([1]), 3);
      if (change === "floor") raiseFloorIn(cnt, { shared: 2, generation: 3 });
      else unregister();
      release(hash);
      await expect(result).rejects.toBeInstanceOf(KeysWaitingError);
      expect(requests).toHaveLength(0);
    } finally { release(hash); unregister(); }
  });
});
