import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { legacyKeyRef } from "./crypto";
import { newContainerKey, writeKey, type KeyFloor } from "./keyring";
import { nextFloor, observeContainer, type FloorSink } from "./observe";
import { clearAllDeviceKeys, getKeyState, storeDeviceKey, storeKeyState } from "./storage";

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });
const cnt = `cnt_${"a".repeat(26)}`, me = `usr_${"b".repeat(26)}`;
const login = legacyKeyRef("a".repeat(64));

/** main.tsx's wiring: the vault's key memory and an in-memory floor map. */
const sink = (memory: Record<string, KeyFloor>, load: (id: string) => Promise<KeyFloor> = (id) => getKeyState("me", me, id)): FloorSink => ({
  load,
  save: (id, state) => storeKeyState("me", me, id, state),
  publish: (id, floor, loaded) => { const next = nextFloor(memory[id], floor, loaded); if (next) memory[id] = next; },
});

describe("observeContainer", () => {
  beforeEach(async () => { await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });

  it("raises the stored and in-memory floor when a name refresh sees a generation with no key", async () => {
    const old = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    await storeKeyState("me", me, cnt, { mark: 2, digests: {}, shared: 2, generation: 2 });
    const memory: Record<string, KeyFloor> = { [cnt]: { shared: 2, generation: 2 } };
    const ring = new Map([[2, newContainerKey()]]);
    expect(writeKey(old, ring, login, memory[cnt])).toBeDefined();
    await observeContainer(sink(memory), { ...old, keyGeneration: 3 });
    expect(await getKeyState("me", me, cnt)).toMatchObject({ shared: 2, generation: 3, mark: 2 });
    expect(memory[cnt]).toMatchObject({ shared: 2, generation: 3 });
    expect(writeKey(old, ring, login, memory[cnt])).toBeUndefined();
  });

  it("never lowers a floor, and a first-sharing report stops the login key", async () => {
    await storeKeyState("me", me, cnt, { mark: 0, digests: {}, shared: 4, generation: 5 });
    const memory: Record<string, KeyFloor> = {};
    await observeContainer(sink(memory), { id: cnt, keyGeneration: 1, sharedGeneration: 0 });
    expect(memory[cnt]).toMatchObject({ shared: 4, generation: 5 });
    expect(await getKeyState("me", me, cnt)).toMatchObject({ shared: 4, generation: 5 });
    const fresh: Record<string, KeyFloor> = {};
    await observeContainer(sink(fresh), { id: "other", keyGeneration: 2, sharedGeneration: 2 });
    expect(writeKey({ id: "other", keyGeneration: 1, sharedGeneration: 0 }, new Map(), login, fresh.other)).toBeUndefined();
  });

  it("raises memory when storage cannot be read, but leaves an unknown floor unknown", async () => {
    const failing = async (): Promise<KeyFloor> => { throw new Error("no storage"); };
    const memory: Record<string, KeyFloor> = { [cnt]: { shared: 2, generation: 2 } };
    await observeContainer(sink(memory, failing), { id: cnt, keyGeneration: 3, sharedGeneration: 2 });
    expect(memory[cnt]).toMatchObject({ generation: 3 });
    await observeContainer(sink(memory, failing), { id: "other", keyGeneration: 3, sharedGeneration: 2 });
    expect(memory.other).toBeUndefined();
    // Persisted anyway, add-only.
    expect(await getKeyState("me", me, "other")).toMatchObject({ shared: 2, generation: 3 });
  });

  it("is the only path from main.tsx to the raw container fetchers", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    const api = main.match(/import \{([^}]*)\} from "\.\/api";/)![1].split(",").map((name: string) => name.trim());
    for (const raw of ["containers", "createContainer", "adminTeams", "createAdminTeam"]) expect(api).not.toContain(raw);
  });
});
