import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearDeviceKey, getDeviceKey, getIdentityKey, getPins, rememberAfter, storeDeviceKey, storeIdentityKey, storePins } from "./storage";

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

describe("colleague key pins", () => {
  beforeEach(clearAllDeviceKeys);
  it("keeps pins per signed-in user and clears them with the device", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storePins("alice", userID, { usr_b: "key" });
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    expect(await getPins("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toEqual({});
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    await clearDeviceKey("alice");
    expect(await getPins("alice", userID)).toEqual({});
  });
});
