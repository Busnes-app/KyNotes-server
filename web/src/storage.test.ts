import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearQueuedSave, closeLegacyStored, deleteNote, getNote, pendingSaves, putNote, queueSave, replaceQueuedSave, clearDeviceKey, getDeviceKey, getIdentityKey, getKeyState, getPins, identityStorage, loadIdentityRecord, rememberAfter, reopenLegacy, storeConfirmedPin, storeDeviceKey, storeIdentityKey, storeKeyState, storePins, vaultReady } from "./storage";
import { generateIdentity } from "./teamKeys";
import { confirmFingerprintChange, PinConfirmation } from "./pins";
import { confirmReopenLegacy, ReopenConfirmation, type KeyState } from "./keyring";
import { clearFloors, raiseFloorIn } from "./floors";
import { mayAutoClose } from "./migration";
import { closeLegacy } from "./observe";
import type { CachedNote, PendingSave } from "./storage";

const shared = indexedDB;
/** Writes rows as a version 4 browser left them: under the owner-unknown key. */
async function seedLegacy(rows: { pending?: PendingSave[]; notes?: CachedNote[] }) {
  await pendingSaves(); // opens (and upgrades) the database
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.open("kynotes-web");
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(["pending", "notes"], "readwrite");
      for (const row of rows.pending ?? []) transaction.objectStore("pending").put({ ...row, owner: "" });
      for (const row of rows.notes ?? []) transaction.objectStore("notes").put({ ...row, owner: "" });
      transaction.oncomplete = () => { db.close(); resolve(); };
      transaction.onerror = () => reject(transaction.error);
    };
    request.onerror = () => reject(request.error);
  });
}

const userID = "usr_0123456789abcdefghjkmnpqrs";
const held = { deviceId: "dev_00000000000000000000000000", ...generateIdentity() };

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
    // With an expected previous pin, the replacement happens only while that pin is still stored.
    const next = { ...member, identity: { deviceId: "dev", publicKey: key(10) } };
    expect(await storeConfirmedPin("alice", userID, confirmFingerprintChange({}, next), key(6))).toBe(false);
    expect((await getPins("alice", userID)).usr_b).toBe(key(7));
    expect(await storeConfirmedPin("alice", userID, confirmFingerprintChange({}, next), key(7))).toBe(true);
    expect((await getPins("alice", userID)).usr_b).toBe(key(10));
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
  it("keeps the legacy closure add-only, and only closeLegacyStored raises it", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    // A key-memory write never sets a closure, whatever it carries.
    await storeKeyState("alice", userID, cnt, { mark: 0, digests: {}, shared: 2, generation: 2, closed: 2 });
    expect(await getKeyState("alice", userID, cnt)).not.toHaveProperty("closed");
    expect(await closeLegacyStored("alice", userID, cnt, 2, false)).toBe("closed");
    await storeKeyState("alice", userID, cnt, { mark: 0, digests: {}, shared: 2, generation: 3 });
    await storeKeyState("alice", userID, cnt, { mark: 0, digests: {}, shared: 2, generation: 3, closed: 0 });
    expect(await closeLegacyStored("alice", userID, cnt, 1, false)).toBe("closed");
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ closed: 2, generation: 3 });
  });

  it("lowers the legacy closure only through a reopen confirmation for that container", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeKeyState("alice", userID, cnt, { mark: 1, digests: { 1: "d1" }, shared: 2, generation: 3 });
    await closeLegacyStored("alice", userID, cnt, 2, false);
    const otherUser = "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz";
    for (const forged of [{ userID, containerID: cnt }, Object.create(ReopenConfirmation.prototype), confirmReopenLegacy(userID, `cnt_${"b".repeat(26)}`), confirmReopenLegacy(otherUser, cnt), undefined])
      expect(await reopenLegacy("alice", userID, cnt, forged as ReopenConfirmation)).toBe(false);
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ closed: 2 });
    const confirmed = confirmReopenLegacy(userID, cnt);
    expect(await reopenLegacy("alice", userID, cnt, confirmed)).toBe(true);
    // Back to the pre-closure state, marked reopened; the rest of the key memory is untouched.
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 1, digests: { 1: "d1" }, shared: 2, generation: 3, reopened: true });
    // Closing again sticks, and the kept confirmation cannot reopen a second time.
    await closeLegacyStored("alice", userID, cnt, 2, false);
    expect(await reopenLegacy("alice", userID, cnt, confirmed)).toBe(false);
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ closed: 2 });
  });

  it("keeps a reopen across reloads, tabs and key-memory writes; only a user's close clears it (I1, M1)", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    const tab = () => mayAutoClose(() => getKeyState("alice", userID, cnt)); // what any tab's check reads, after any reload
    await closeLegacyStored("alice", userID, cnt, 2, false);
    expect(await reopenLegacy("alice", userID, cnt, confirmReopenLegacy(userID, cnt))).toBe(true);
    expect(await tab()).toBe(false);
    // Key passes and observed floors keep the mark, even one carrying a stale closure; a write cannot set it.
    await storeKeyState("alice", userID, cnt, { mark: 2, digests: { 2: "d2" }, shared: 2, generation: 3, closed: 2 });
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ reopened: true, generation: 3 });
    expect(await getKeyState("alice", userID, cnt)).not.toHaveProperty("closed");
    // An automatic close is refused in the closing transaction, even after a check that read no mark (M1).
    expect(await closeLegacyStored("alice", userID, cnt, 2, true)).toBe("reopened");
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ reopened: true });
    expect(await getKeyState("alice", userID, cnt)).not.toHaveProperty("closed");
    // "Stop opening pre-sharing items" (closeLegacy) clears it.
    clearFloors();
    raiseFloorIn(cnt, { shared: 2, generation: 3 });
    expect(await closeLegacy({ close: (id, closed, auto) => closeLegacyStored("alice", userID, id, closed, auto) }, cnt)).toBe("closed");
    expect(await getKeyState("alice", userID, cnt)).not.toHaveProperty("reopened");
    expect(await tab()).toBe(true);
    clearFloors();
    await storeKeyState("alice", userID, cnt, { mark: 0, digests: {}, reopened: true } as KeyState);
    expect(await getKeyState("alice", userID, cnt)).not.toHaveProperty("reopened");
    expect(await mayAutoClose(() => Promise.reject(new Error("IndexedDB")))).toBe(false);
  });

  it("closes and reopens on a browser with no vault record by creating one that holds no device key (I4)", async () => {
    expect(await getDeviceKey("alice")).toBeUndefined();
    expect(await closeLegacyStored("alice", userID, cnt, 2, true)).toBe("closed");
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ closed: 2 });
    expect(await reopenLegacy("alice", userID, cnt, confirmReopenLegacy(userID, cnt))).toBe(true);
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ reopened: true });
    expect(await closeLegacyStored("alice", userID, cnt, 2, true)).toBe("reopened");
    // The record it made is not a device key: no quick sign-in, and no identity is kept in it.
    expect(await getDeviceKey("alice")).toBeUndefined();
    expect(await vaultReady("alice")).toBe(false);
    expect(await storeIdentityKey("alice", userID, held)).toBe(false);
    // A later sign-in adds the device key beside the closure state.
    await storeDeviceKey("alice", "a".repeat(64));
    expect(await getKeyState("alice", userID, cnt)).toMatchObject({ reopened: true });
    expect(await vaultReady("alice")).toBe(true);
  });

  it("never closes by itself where IndexedDB is unusable (I4)", async () => {
    const real = globalThis.indexedDB;
    vi.stubGlobal("indexedDB", undefined);
    try {
      expect(await closeLegacyStored("alice", userID, cnt, 2, true)).toBe("unsaved");
      expect(await reopenLegacy("alice", userID, cnt, confirmReopenLegacy(userID, cnt))).toBe(false);
      expect(await mayAutoClose(() => getKeyState("alice", userID, cnt))).toBe(false);
    } finally {
      vi.stubGlobal("indexedDB", real);
    }
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
  const item = { id: "obj_1", containerID: "cnt_1", version: 3, payload: new Uint8Array([1]), updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0, owner: userID };
  const other = "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz";
  const mine = (entries: PendingSave[], owner = userID) => entries.filter((entry) => entry.owner === owner);
  beforeEach(async () => { for (const entry of await pendingSaves()) await replaceQueuedSave(entry); });

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
    await clearQueuedSave(userID, item.id);
    expect(await replaceQueuedSave(item, { ...item, keyGeneration: 2 })).toBe(false);
    expect(await pendingSaves()).toEqual([]);
  });

  it("keeps another account's queued save of the same page through this account's save, clear and replace", async () => {
    const theirs = { ...item, owner: other, payload: new Uint8Array([9]), updatedAt: "2026-10-07T00:05:00Z" };
    await queueSave(theirs);
    await queueSave(item);
    expect(mine(await pendingSaves(), other)).toEqual([theirs]);
    await queueSave({ ...item, version: 4 });
    expect(mine(await pendingSaves(), other)).toEqual([theirs]);
    expect(await replaceQueuedSave({ ...item, version: 4 })).toBe(true);
    await clearQueuedSave(userID, item.id);
    expect(await pendingSaves()).toEqual([theirs]);
  });

  it("moves a proven owner-unknown entry to its owner, but never over that owner's newer save", async () => {
    const { owner: _owner, ...unknown } = item;
    await seedLegacy({ pending: [unknown] });
    expect(await pendingSaves()).toEqual([unknown]);
    expect(await replaceQueuedSave(unknown, { ...unknown, owner: userID })).toBe(true);
    expect(await pendingSaves()).toEqual([item]);
    await seedLegacy({ pending: [unknown] });
    await queueSave({ ...item, version: 4 });
    expect(await replaceQueuedSave(unknown, { ...unknown, owner: userID })).toBe(false);
    expect((await pendingSaves()).map((entry) => [entry.owner, entry.version])).toEqual([[undefined, 3], [userID, 4]]);
  });
});

describe("note cache", () => {
  const note = { id: "obj_1", containerID: "cnt_1", version: 3, payload: new Uint8Array([1]), updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 2 };
  const other = "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz";

  it("never returns, replaces or deletes another account's copy of the same page", async () => {
    await putNote(other, { ...note, payload: new Uint8Array([9]) });
    expect(await getNote(userID, note.id, async () => true)).toBeUndefined();
    await putNote(userID, note);
    await deleteNote(userID, note.id);
    expect(await getNote(other, note.id)).toEqual({ ...note, payload: new Uint8Array([9]) });
    await deleteNote(other, note.id);
  });

  it("returns a copy cached before owners were recorded only to the account whose key opens it, and claims it", async () => {
    await seedLegacy({ notes: [note] });
    expect(await getNote(other, note.id, async () => false)).toBeUndefined();
    expect(await getNote(userID, note.id)).toBeUndefined();
    expect(await getNote(userID, note.id, async () => true)).toEqual(note);
    // Claimed: now this account's copy, and gone from the owner-unknown key.
    expect(await getNote(userID, note.id)).toEqual(note);
    expect(await getNote(other, note.id, async () => true)).toBeUndefined();
    await deleteNote(userID, note.id);
  });
});

describe("version 4 upgrade", () => {
  it("re-keys the cache and the queue by owner and keeps every entry readable", async () => {
    const factory = new IDBFactory();
    vi.stubGlobal("indexedDB", factory);
    try {
      const stamped = { id: "obj_s", containerID: "cnt_1", version: 1, payload: new Uint8Array([1]), updatedAt: "t1", keyGeneration: 2, owner: userID };
      const unstamped = { id: "obj_u", containerID: "cnt_1", version: 1, payload: new Uint8Array([2]), updatedAt: "t1", keyGeneration: 0 };
      const cached = { id: "obj_c", containerID: "cnt_1", version: 1, payload: new Uint8Array([3]), updatedAt: "t1", keyGeneration: 0 };
      await new Promise<void>((resolve, reject) => {
        const request = factory.open("kynotes-web", 4);
        request.onupgradeneeded = () => {
          const db = request.result;
          db.createObjectStore("notes", { keyPath: "id" }).put(cached);
          const pending = db.createObjectStore("pending", { keyPath: "id" });
          pending.put(stamped); pending.put(unstamped);
          db.createObjectStore("uploads", { keyPath: "uploadId" });
          db.createObjectStore("keys", { keyPath: "username" }).put({ username: "alice", authSecret: "s" });
        };
        request.onsuccess = () => { request.result.close(); resolve(); };
        request.onerror = () => reject(request.error);
      });
      expect(await pendingSaves()).toEqual([unstamped, stamped]);
      expect(await getNote(userID, cached.id, async () => true)).toEqual(cached);
      expect(await getDeviceKey("alice")).toBe("s");
    } finally {
      vi.stubGlobal("indexedDB", shared);
    }
  });
});

const vaultRow = (username: string) => new Promise<Record<string, any> | undefined>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const request = open.result.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => { open.result.close(); resolve(request.result); };
    request.onerror = () => reject(request.error);
  };
});
const putVaultRow = (row: Record<string, unknown>) => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction("keys", "readwrite");
    tx.objectStore("keys").put(row);
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
});
const contains = (haystack: Uint8Array, needle: Uint8Array) => haystack.some((_, i) => needle.every((byte, j) => haystack[i + j] === byte));

describe("the identity at rest", () => {
  const me = `usr_${"b".repeat(26)}`;
  const held = () => ({ ...generateIdentity(), deviceId: `dev_${"c".repeat(26)}` });
  beforeEach(async () => { vi.stubGlobal("isSecureContext", true); await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });
  // Not unstubAllGlobals: that would also drop the file-level localStorage stub.
  afterEach(() => { vi.stubGlobal("isSecureContext", undefined); });

  it("keeps the private key sealed under a non-extractable device key, never raw", async () => {
    const identity = held();
    expect(identityStorage()).toBe("wrapped");
    expect(await storeIdentityKey("me", me, identity)).toBe(true);
    const stored = (await vaultRow("me"))!.identity;
    expect(stored.privateKey).toBeUndefined();
    expect(stored.deviceKey.extractable).toBe(false);
    expect(contains(stored.sealed, identity.privateKey)).toBe(false);
    expect(await getIdentityKey("me", me)).toEqual(identity);
  });

  it("seals a raw copy an earlier version wrote, on first read", async () => {
    const identity = held();
    const row = (await vaultRow("me"))!;
    await putVaultRow({ ...row, identity: { ...identity, userID: me } });
    expect(await getIdentityKey("me", me)).toEqual(identity);
    const stored = (await vaultRow("me"))!.identity;
    expect(stored.privateKey).toBeUndefined();
    expect(stored.deviceKey.extractable).toBe(false);
  });

  it("keeps the raw key on a plain-HTTP origin, where there is no WebCrypto, and says so", async () => {
    vi.stubGlobal("isSecureContext", false);
    const identity = held();
    expect(identityStorage()).toBe("plain");
    expect(await storeIdentityKey("me", me, identity)).toBe(true);
    expect((await vaultRow("me"))!.identity.privateKey).toEqual(identity.privateKey);
    expect(await getIdentityKey("me", me)).toEqual(identity);
  });

  it("returns nothing for a sealed copy its device key cannot open, or one that is not its public key's", async () => {
    const identity = held();
    await storeIdentityKey("me", me, identity);
    const row = (await vaultRow("me"))!;
    const otherKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await putVaultRow({ ...row, identity: { ...row.identity, deviceKey: otherKey } });
    expect(await getIdentityKey("me", me)).toBeUndefined();
    await storeIdentityKey("me", me, { ...identity, publicKey: generateIdentity().publicKey });
    expect(await getIdentityKey("me", me)).toBeUndefined();
  });

  it("binds the sealed copy to its user and device ID", async () => {
    await storeIdentityKey("me", me, held());
    const row = (await vaultRow("me"))!;
    const other = `usr_${"z".repeat(26)}`;
    await putVaultRow({ ...row, identity: { ...row.identity, userID: other } });
    expect(await loadIdentityRecord("me", other)).toBeUndefined();
    await putVaultRow({ ...row, identity: { ...row.identity, deviceId: `dev_${"e".repeat(26)}` } });
    expect(await loadIdentityRecord("me", me)).toBeUndefined();
  });

  it("seals each write under a fresh device key and IV", async () => {
    const identity = held();
    await storeIdentityKey("me", me, identity);
    const first = (await vaultRow("me"))!.identity;
    await storeIdentityKey("me", me, identity);
    const second = (await vaultRow("me"))!.identity;
    expect(first.sealed.slice(0, 12)).not.toEqual(second.sealed.slice(0, 12));
    expect(first.deviceKey).not.toBe(second.deviceKey);
    await expect(crypto.subtle.exportKey("raw", second.deviceKey)).rejects.toThrow();
  });

  it("writes with an expected identity only while the vault still holds it", async () => {
    const first = held(), second = held();
    expect(await storeIdentityKey("me", me, first, null)).toBe(true);
    expect(await storeIdentityKey("me", me, second, null)).toBe(false);
    expect(await storeIdentityKey("me", me, second, held())).toBe(false);
    expect(await getIdentityKey("me", me)).toEqual(first);
    expect(await storeIdentityKey("me", me, second, first)).toBe(true);
    expect(await getIdentityKey("me", me)).toEqual(second);
  });

  it("lets exactly one of two racing creates keep its identity", async () => {
    const a = held(), b = held();
    const results = await Promise.all([storeIdentityKey("me", me, a, null), storeIdentityKey("me", me, b, null)]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await getIdentityKey("me", me)).toEqual(results[0] ? a : b);
  });

  it("hides a pending identity (no device ID yet) from use, but returns it for reconciliation", async () => {
    const pending = { ...held(), deviceId: "" };
    await storeIdentityKey("me", me, pending);
    expect(await getIdentityKey("me", me)).toBeUndefined();
    expect(await loadIdentityRecord("me", me)).toEqual(pending);
  });

  it("forget this device deletes the sealed identity and its device key together", async () => {
    await storeIdentityKey("me", me, held());
    await clearDeviceKey("me");
    expect(await vaultRow("me")).toBeUndefined();
    expect(await getIdentityKey("me", me)).toBeUndefined();
  });

  it("forget this device also deletes pins and key memory with the record", async () => {
    await storeIdentityKey("me", me, held());
    await storePins("me", me, { usr_b: "key" });
    await storeKeyState("me", me, "cnt_1", { mark: 3, digests: { 3: "d" } });
    await clearDeviceKey("me");
    expect(await vaultRow("me")).toBeUndefined();
    expect(await getPins("me", me)).toEqual({});
    expect(await getKeyState("me", me, "cnt_1")).toEqual({ mark: 0, digests: {} });
  });

  it("keeps nothing, and says so, without a vault record", async () => {
    await clearAllDeviceKeys();
    expect(await vaultReady("me")).toBe(false);
    expect(await storeIdentityKey("me", me, held())).toBe(false);
    await storeDeviceKey("me", "a".repeat(64));
    expect(await vaultReady("me")).toBe(true);
  });

  it("fails closed without IndexedDB: no identity is kept or read", async () => {
    const real = globalThis.indexedDB;
    vi.stubGlobal("indexedDB", undefined);
    try {
      expect(await vaultReady("me")).toBe(false);
      expect(await storeIdentityKey("me", me, held())).toBe(false);
      await expect(loadIdentityRecord("me", me)).rejects.toThrow();
    } finally {
      vi.stubGlobal("indexedDB", real);
    }
  });
});

describe("a vault write the browser aborts", () => {
  const me = `usr_${"b".repeat(26)}`;
  beforeEach(async () => { vi.stubGlobal("isSecureContext", true); await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });
  afterEach(() => { vi.restoreAllMocks(); vi.stubGlobal("isSecureContext", undefined); });

  // A put that throws (DataCloneError here; QuotaExceededError in a browser) aborts the transaction.
  const uncloneable = () => {
    vi.spyOn(crypto.subtle, "generateKey").mockResolvedValue({ notCloneable: () => 1 } as never);
    vi.spyOn(crypto.subtle, "encrypt").mockResolvedValue(new ArrayBuffer(48));
  };

  it("keeps nothing and says so, rather than hanging", { timeout: 2000 }, async () => {
    uncloneable();
    expect(await storeIdentityKey("me", me, { ...generateIdentity(), deviceId: `dev_${"c".repeat(26)}` })).toBe(false);
  });

  it("still returns a raw copy whose re-seal could not be kept", { timeout: 2000 }, async () => {
    const identity = { ...generateIdentity(), deviceId: `dev_${"c".repeat(26)}` };
    vi.stubGlobal("isSecureContext", false);
    await storeIdentityKey("me", me, identity);
    vi.stubGlobal("isSecureContext", true);
    uncloneable();
    expect(await getIdentityKey("me", me)).toEqual(identity);
    expect((await vaultRow("me"))!.identity.privateKey).toEqual(identity.privateKey);
  });

  it("rejects a queued-save replacement whose write aborts", { timeout: 2000 }, async () => {
    const entry = { id: "obj_abort", containerID: "cnt_1", version: 1, payload: new Uint8Array([1]), updatedAt: "2026-10-08T00:00:00Z", keyGeneration: 0, owner: me };
    await queueSave(entry);
    await expect(replaceQueuedSave(entry, { ...entry, version: 2, payload: (() => 1) as never })).rejects.toThrow();
    await clearQueuedSave(me, entry.id);
  });
});
