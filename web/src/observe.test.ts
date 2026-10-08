import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { localKey, newContainerKey, WAITING_GENERATION, waitingKey, writeKey, type KeyFloor } from "./keyring";
import { generateIdentity } from "./teamKeys";
import { clearFloors, floorOf, raiseFloorIn } from "./floors";
import { createKeyed, NOT_CREATED, observeContainer, type FloorSink } from "./observe";
import { clearAllDeviceKeys, getKeyState, storeDeviceKey, storeKeyState } from "./storage";

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });
const cnt = `cnt_${"a".repeat(26)}`, me = `usr_${"b".repeat(26)}`;
const seal = waitingKey(generateIdentity());

/** main.tsx's wiring: the vault's key memory; floors go to the tab-wide store. */
const sink = (load: (id: string) => Promise<KeyFloor> = (id) => getKeyState("me", me, id)): FloorSink => ({
  load,
  save: (id, state) => storeKeyState("me", me, id, state),
});

describe("observeContainer", () => {
  beforeEach(async () => { clearFloors(); await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });

  it("raises the stored and in-memory floor when a name refresh sees a generation with no key", async () => {
    const old = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    await storeKeyState("me", me, cnt, { mark: 2, digests: {}, shared: 2, generation: 2 });
    raiseFloorIn(cnt, { shared: 2, generation: 2 });
    const ring = new Map([[2, newContainerKey()]]);
    expect(writeKey(old, ring, floorOf(cnt)!)).toBeDefined();
    await observeContainer(sink(), { ...old, keyGeneration: 3 });
    expect(await getKeyState("me", me, cnt)).toMatchObject({ shared: 2, generation: 3, mark: 2 });
    expect(floorOf(cnt)).toMatchObject({ shared: 2, generation: 3 });
    expect(writeKey(old, ring, floorOf(cnt)!)).toBeUndefined();
  });

  it("never lowers a floor, and an unkeyed report after a keyed one pauses writes", async () => {
    await storeKeyState("me", me, cnt, { mark: 0, digests: {}, shared: 4, generation: 5 });
    await observeContainer(sink(), { id: cnt, keyGeneration: 1, sharedGeneration: 0 });
    expect(floorOf(cnt)).toMatchObject({ shared: 4, generation: 5 });
    expect(await getKeyState("me", me, cnt)).toMatchObject({ shared: 4, generation: 5 });
    await observeContainer(sink(), { id: "other", keyGeneration: 2, sharedGeneration: 2 });
    expect(writeKey({ id: "other", keyGeneration: 1, sharedGeneration: 0 }, new Map(), floorOf("other")!)).toBeUndefined();
  });

  it("raises memory when storage cannot be read, but leaves an unknown floor unknown", async () => {
    const failing = async (): Promise<KeyFloor> => { throw new Error("no storage"); };
    raiseFloorIn(cnt, { shared: 2, generation: 2 });
    await observeContainer(sink(failing), { id: cnt, keyGeneration: 3, sharedGeneration: 2 });
    expect(floorOf(cnt)).toMatchObject({ generation: 3 });
    await observeContainer(sink(failing), { id: "other", keyGeneration: 3, sharedGeneration: 2 });
    expect(floorOf("other")).toBeUndefined();
    // Persisted anyway, add-only.
    expect(await getKeyState("me", me, "other")).toMatchObject({ shared: 2, generation: 3 });
  });

  it("an admin list that sees first sharing leaves the workspace's stale unshared copy without a write key", async () => {
    // The workspace loaded the team container unshared and still holds that object: never-shared, so no write key.
    const held = { id: cnt, keyGeneration: 1, sharedGeneration: 0 };
    await observeContainer(sink(), held);
    expect(writeKey(held, new Map(), floorOf(cnt)!)).toBeUndefined();
    // The admin page (its own component, the same tab-wide store) lists the team as shared.
    await observeContainer(sink(), { id: cnt, kind: "team", ownerUserId: me, keyGeneration: 2, sharedGeneration: 2 });
    expect(writeKey(held, new Map(), floorOf(cnt)!)).toBeUndefined();
    // The edit stays local under the waiting seal, which the queue never sends.
    expect(localKey(held, new Map(), seal, floorOf(cnt)!).generation).toBe(WAITING_GENERATION);
  });

  it("keeps exactly one floor map: main.tsx reads floors only through floors.ts", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    expect(main).not.toMatch(/Record<string, KeyFloor>|floorsRef|putFloor/);
  });

  it("is the only path to the raw container fetchers", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./api.ts", "!./observe.ts", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./main.tsx", "./components/UnsentEdits.tsx"]));
    const raw = /\b(containers|createContainer|adminTeams|createAdminTeam)\b/;
    const imports = (text: string) => [...text.matchAll(/import\s*\{([^}]*)\}\s*from\s*"[./]*\/?api"/g)].flatMap((match) => match[1].split(",").map((name) => name.trim()));
    expect(Object.entries(sources).filter(([, text]) => imports(text).some((name) => raw.test(name))).map(([name]) => name)).toEqual([]);
  });
});

describe("createKeyed", () => {
  const made = { id: "cnt_new" };
  it("deletes the empty container when keying or naming fails, and says it was not created (M2)", async () => {
    const remove = vi.fn(async () => {});
    await expect(createKeyed(async () => made, async () => { throw new Error("not keyed"); }, remove)).rejects.toThrow(NOT_CREATED);
    expect(remove).toHaveBeenCalledWith("cnt_new");
  });

  it("keeps the setup error when the delete is refused, and deletes nothing that was set up", async () => {
    await expect(createKeyed(async () => made, async () => { throw new Error("not keyed"); }, async () => { throw new Error("forbidden"); })).rejects.toThrow("not keyed");
    const remove = vi.fn(async () => {});
    await expect(createKeyed(async () => made, async (created) => ({ ...created, named: true }), remove)).resolves.toEqual({ id: "cnt_new", named: true });
    expect(remove).not.toHaveBeenCalled();
  });

  it("creates nothing to delete when create itself fails", async () => {
    const remove = vi.fn(async () => {});
    await expect(createKeyed(async () => { throw new Error("offline"); }, async (c: { id: string }) => c, remove)).rejects.toThrow("offline");
    expect(remove).not.toHaveBeenCalled();
  });
});
