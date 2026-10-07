import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearDeviceKey, getDeviceKey, getIdentityKey, storeDeviceKey, storeIdentityKey } from "./storage";

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

  it("drops the identity when the auth secret is replaced", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getIdentityKey("alice", userID)).toBeUndefined();
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
