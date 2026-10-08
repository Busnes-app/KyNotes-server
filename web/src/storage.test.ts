import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearQueuedSave, pendingSaves, queueSave, replaceQueuedSave, clearDeviceKey, getDeviceKey, getIdentityKey, getKeyState, getPins, rememberAfter, storeConfirmedPin, storeDeviceKey, storeIdentityKey, storeKeyState, storePins } from "./storage";
import { confirmFingerprintChange, PinConfirmation } from "./pins";

const userID = "usr_0123456789abcdefghjkmnpqrs";
const held = { deviceId: "dev_00000000000000000000000000", publicKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) };

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });

describe("keys vault identity", () => {
  beforeEach(clearAllDeviceKeys);

  it("caches the identity beside the auth secret for reloads", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    expect(await getIdentityKey("alice", userID)).toEqual(held);
    expect(await getDeviceKey("alice")).toBe("a".repeat(64));
  });

  it("returns nothing for another user under the same name", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    expect(await getIdentityKey("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toBeUndefined();
  });

  it("does not create a vault record on its own", async () => {
    await storeIdentityKey("alice", userID, held);
    expect(await getIdentityKey("alice", userID)).toBeUndefined();
  });

  it("keeps the identity when the auth secret is replaced", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getIdentityKey("alice", userID)).toEqual(held);
    expect(await getDeviceKey("alice")).toBe("b".repeat(64));
  });

  it("forget this device removes it", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    await clearDeviceKey("alice");
    expect(await getIdentityKey("alice", userID)).toBeUndefined();
    await storeDeviceKey("bob", "b".repeat(64));
    await storeIdentityKey("bob", userID, held);
    await clearAllDeviceKeys();
    expect(await getIdentityKey("bob", userID)).toBeUndefined();
  });
});

describe("vault writes follow the server and never fail it", () => {
  beforeEach(clearAllDeviceKeys);

  it("a refused sign-in leaves the vault, identity included, untouched", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    await expect(rememberAfter(() => Promise.reject(new Error("invalid credentials")), "alice", "b".repeat(64))).rejects.toThrow("invalid credentials");
    expect(await getDeviceKey("alice")).toBe("a".repeat(64));
    expect(await getIdentityKey("alice", userID)).toEqual(held);
  });

  it("stores after a successful call, with the re-wrapped identity", async () => {
    expect(await rememberAfter(async () => "ok", "alice", "b".repeat(64), { userID, identity: held })).toBe("ok");
    expect(await getDeviceKey("alice")).toBe("b".repeat(64));
    expect(await getIdentityKey("alice", userID)).toEqual(held);
  });

  it("succeeds when IndexedDB is unavailable", async () => {
    const real = globalThis.indexedDB;
    vi.stubGlobal("indexedDB", undefined);
    try {
      expect(await rememberAfter(async () => "ok", "alice", "b".repeat(64), { userID, identity: held })).toBe("ok");
    } finally {
      vi.stubGlobal("indexedDB", real);
    }
  });
});

describe("pin and key-mark writes never downgrade", () => {
  beforeEach(clearAllDeviceKeys);
  const cnt = "cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa";
  it("adds first-contact pins without overwriting, and replaces one only through a confirmation", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    const key = (fill: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(fill)));
    expect(await storePins("alice", userID, { usr_b: "old" })).toEqual({ ok: true });
    // A different key for a pinned member is a conflict, and nothing in that proposal is written.
    expect(await storePins("alice", userID, { usr_b: "server", usr_c: "new" })).toEqual({ ok: false, conflicts: ["usr_b"] });
    expect(await getPins("alice", userID)).toEqual({ usr_b: "old" });
    expect(await storePins("alice", userID, { usr_b: "old", usr_c: "new" })).toEqual({ ok: true });
    expect(await getPins("alice", userID)).toEqual({ usr_b: "old", usr_c: "new" });
    const member = { userId: "usr_b", username: "b", role: "editor", identity: { deviceId: "dev", publicKey: key(7) } };
    expect(await storeConfirmedPin("alice", userID, confirmFingerprintChange({}, member))).toBe(true);
    expect(await getPins("alice", userID)).toEqual({ usr_b: key(7), usr_c: "new" });
    // @ts-expect-error a raw key is not a confirmation
    expect(await storeConfirmedPin("alice", userID, key(8))).toBe(false);
    // @ts-expect-error nor is a look-alike object
    expect(await storeConfirmedPin("alice", userID, { userId: "usr_b", key: key(8), pins: {} })).toBe(false);
    const forged = Object.assign(Object.create(PinConfirmation.prototype), { userId: "usr_b", key: key(9), pins: {} });
    expect(await storeConfirmedPin("alice", userID, forged)).toBe(false);
    expect((await getPins("alice", userID)).usr_b).toBe(key(7));
  });
  it("keeps the highest key mark and first key digests per container, and reports when it cannot", async () => {
    expect(await storeKeyState("alice", userID, cnt, { mark: 3, digests: {} })).toBe(false);
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 0, digests: {} });
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await storeKeyState("alice", userID, cnt, { mark: 3, digests: { 2: "aa" } })).toBe(true);
    expect(await storeKeyState("alice", userID, cnt, { mark: 2, digests: { 2: "bb", 3: "cc" } })).toBe(true);
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 3, digests: { 2: "aa", 3: "cc" }, shared: 0, generation: 0 });
    expect(await getKeyState("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz", cnt)).toEqual({ mark: 0, digests: {} });
    await clearDeviceKey("alice");
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 0, digests: {} });
  });
  it("keeps the highest sharing state seen across a reload, so a rollback stays visible", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await storeKeyState("alice", userID, cnt, { mark: 3, digests: {}, shared: 2, generation: 3 })).toBe(true);
    // A later pass that saw a rolled-back server never lowers it.
    expect(await storeKeyState("alice", userID, cnt, { mark: 0, digests: {}, shared: 0, generation: 1 })).toBe(true);
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ shared: 2, generation: 3 });
  });
});

describe("colleague key pins", () => {
  beforeEach(clearAllDeviceKeys);
  it("keeps pins per signed-in user and clears them with the device", async () => {
    expect(await storePins("alice", userID, { usr_b: "key" })).toEqual({ ok: false, conflicts: [] }); // no vault record: not kept
    expect(await getPins("alice", userID)).toEqual({});
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await storePins("alice", userID, { usr_b: "key" })).toEqual({ ok: true });
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    expect(await getPins("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toEqual({});
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    await clearDeviceKey("alice");
    expect(await getPins("alice", userID)).toEqual({});
  });
});

describe("queued saves", () => {
  const item = { id: "obj_1", containerID: "cnt_1", version: 3, payload: new Uint8Array([1]), updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0 };

  it("replaces only the entry the caller read", async () => {
    await queueSave(item);
    expect(await replaceQueuedSave(item, { ...item, payload: new Uint8Array([2]), keyGeneration: 2 })).toBe(true);
    expect((await pendingSaves()).find((entry) => entry.id === item.id)?.keyGeneration).toBe(2);
    // A newer save replaced it meanwhile: a stale re-seal or a stale clear leaves it alone.
    const newer = { ...item, version: 4, updatedAt: "2026-10-07T00:01:00Z", keyGeneration: 2 };
    await queueSave(newer);
    expect(await replaceQueuedSave({ ...item, keyGeneration: 2 }, item)).toBe(false);
    expect(await replaceQueuedSave({ ...item, keyGeneration: 2 })).toBe(false);
    expect((await pendingSaves()).find((entry) => entry.id === item.id)).toEqual(newer);
    expect(await replaceQueuedSave(newer)).toBe(true);
    expect((await pendingSaves()).find((entry) => entry.id === item.id)).toBeUndefined();
  });

  it("does not resurrect a cleared entry", async () => {
    await queueSave(item);
    await clearQueuedSave(item.id);
    expect(await replaceQueuedSave(item, { ...item, keyGeneration: 2 })).toBe(false);
    expect(await pendingSaves()).toEqual([]);
  });
});
