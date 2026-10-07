import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearDeviceKey, getDeviceKey, getIdentityKey, getKeyState, getPins, rememberAfter, storeConfirmedPin, storeDeviceKey, storeIdentityKey, storeKeyState, storePins } from "./storage";
import { confirmFingerprintChange } from "./pins";

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
    expect(await storePins("alice", userID, { usr_b: "old" })).toBe(true);
    expect(await storePins("alice", userID, { usr_b: "server", usr_c: "new" })).toBe(true);
    expect(await getPins("alice", userID)).toEqual({ usr_b: "old", usr_c: "new" });
    const member = { userId: "usr_b", username: "b", role: "editor", identity: { deviceId: "dev", publicKey: key(7) } };
    expect(await storeConfirmedPin("alice", userID, confirmFingerprintChange({}, member))).toBe(true);
    expect(await getPins("alice", userID)).toEqual({ usr_b: key(7), usr_c: "new" });
    // @ts-expect-error a raw key is not a confirmation
    expect(await storeConfirmedPin("alice", userID, key(8))).toBe(false);
    // @ts-expect-error nor is a look-alike object
    expect(await storeConfirmedPin("alice", userID, { userId: "usr_b", key: key(8), pins: {} })).toBe(false);
    expect((await getPins("alice", userID)).usr_b).toBe(key(7));
  });
  it("keeps the highest key mark and first key digests per container, and reports when it cannot", async () => {
    expect(await storeKeyState("alice", userID, cnt, { mark: 3, digests: {} })).toBe(false);
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 0, digests: {} });
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await storeKeyState("alice", userID, cnt, { mark: 3, digests: { 2: "aa" } })).toBe(true);
    expect(await storeKeyState("alice", userID, cnt, { mark: 2, digests: { 2: "bb", 3: "cc" } })).toBe(true);
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 3, digests: { 2: "aa", 3: "cc" } });
    expect(await getKeyState("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz", cnt)).toEqual({ mark: 0, digests: {} });
    await clearDeviceKey("alice");
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 0, digests: {} });
  });
});

describe("colleague key pins", () => {
  beforeEach(clearAllDeviceKeys);
  it("keeps pins per signed-in user and clears them with the device", async () => {
    expect(await storePins("alice", userID, { usr_b: "key" })).toBe(false); // no vault record: not kept
    expect(await getPins("alice", userID)).toEqual({});
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await storePins("alice", userID, { usr_b: "key" })).toBe(true);
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    expect(await getPins("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toEqual({});
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    await clearDeviceKey("alice");
    expect(await getPins("alice", userID)).toEqual({});
  });
});
