import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAllDeviceKeys, clearQueuedSave, deleteNote, getNote, pendingSaves, pendingUploads, putNote, putUpload, clearUpload, queueSave, replaceQueuedSave, clearDeviceKey, getDeviceKey, getIdentityKey, getKeyState, getPins, identityStorage, loadIdentityRecord, rememberAfter, storeConfirmedPin, storeDeviceKey, storeIdentityKey, storeKeyState, storePins, vaultReady } from "./storage";
import { generateIdentity } from "./teamKeys";
import { confirmFingerprintChange, PinConfirmation } from "./pins";
import type { KeyState } from "./keyring";
import type { PendingSave, PendingUpload } from "./storage";

const shared = indexedDB;
const userID = "usr_0123456789abcdefghjkmnpqrs";
const held = { deviceId: "dev_00000000000000000000000000", ...generateIdentity() };

const local = new Map<string, string>();
vi.stubGlobal("localStorage", { getItem: (key: string) => local.get(key) ?? null, setItem: (key: string, value: string) => { local.set(key, value); }, removeItem: (key: string) => { local.delete(key); } });

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
  it("key memory keeps only generations, mark and digests", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storeKeyState("alice", "usr_0123456789abcdefghjkmnpqrs", cnt, { mark: 2, digests: { 2: "aa" }, shared: 2, generation: 2, closed: 2, reopened: true } as KeyState);
    expect(await getKeyState("alice", "usr_0123456789abcdefghjkmnpqrs", cnt)).toEqual({ mark: 2, digests: { 2: "aa" }, shared: 2, generation: 2 });
  });

  it("ignores a closure and reopen mark an older build stored, and drops them on the next write", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    const row = await vaultRow("alice");
    await putVaultRow({ ...row, keyStates: { userID, byContainer: { [cnt]: { mark: 1, digests: { 1: "d1" }, shared: 2, generation: 3, closed: 2, reopened: true } } } });
    expect(await getKeyState("alice", userID, cnt)).toEqual({ mark: 1, digests: { 1: "d1" }, shared: 2, generation: 3 });
    await storeKeyState("alice", userID, cnt, { mark: 1, digests: {} });
    expect((await vaultRow("alice"))?.keyStates.byContainer[cnt]).toEqual({ mark: 1, digests: { 1: "d1" }, shared: 2, generation: 3 });
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
});

describe("note cache", () => {
  const note = { id: "obj_1", containerID: "cnt_1", version: 3, payload: new Uint8Array([1]), updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 2 };
  const other = "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz";

  it("never returns, replaces or deletes another account's copy of the same page", async () => {
    await putNote(other, { ...note, payload: new Uint8Array([9]) });
    expect(await getNote(userID, note.id)).toBeUndefined();
    await putNote(userID, note);
    await deleteNote(userID, note.id);
    expect(await getNote(other, note.id)).toEqual({ ...note, payload: new Uint8Array([9]) });
    await deleteNote(other, note.id);
  });
});

describe("pending uploads", () => {
  const job = (uploadId: string, owner: string): PendingUpload => ({ uploadId, owner, containerID: "cnt_1", objectID: "obj_1", objectVersion: 1, keyGeneration: 2, chunkBytes: 1, nextChunk: 0, payload: new Uint8Array([1]), metadataCiphertext: "AA==", name: "secret.pdf", type: "application/pdf", size: 1 });
  const other = "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz";

  it("are listed and cleared only for the account that started them; one without an owner is nobody's", async () => {
    await putUpload(job("upl_mine", userID));
    await putUpload(job("upl_theirs", other));
    const { owner: _owner, ...unowned } = job("upl_unowned", "");
    await writeRaw("uploads", unowned); // as no build of v6 writes it
    expect((await pendingUploads(userID)).map((entry) => entry.uploadId)).toEqual(["upl_mine"]);
    expect((await pendingUploads(other)).map((entry) => entry.uploadId)).toEqual(["upl_theirs"]);
    expect(await pendingUploads("")).toEqual([]);
    // Another account's clear changes nothing.
    await clearUpload(other, "upl_mine");
    expect((await pendingUploads(userID)).map((entry) => entry.uploadId)).toEqual(["upl_mine"]);
    await clearUpload(userID, "upl_mine");
    await clearUpload(other, "upl_theirs");
    expect(await pendingUploads(userID)).toEqual([]);
  });
});

describe("version 6 upgrade", () => {
  const CID = `cnt_${"a".repeat(26)}`;
  /** A v5 database as earlier builds left it: an owner-unknown cached page, a queue entry, an upload and a vault record. */
  const seedV5 = (factory: IDBFactory) => new Promise<void>((resolve, reject) => {
    const open = factory.open("kynotes-web", 5);
    open.onupgradeneeded = () => {
      const db = open.result;
      db.createObjectStore("notes", { keyPath: ["owner", "id"] }).put({ owner: "", id: "obj_a", containerID: CID, version: 1, payload: new Uint8Array(1), updatedAt: "t" });
      db.createObjectStore("pending", { keyPath: ["owner", "id"] }).put({ owner: "usr_x", id: "obj_b", containerID: CID, version: 1, payload: new Uint8Array(1), updatedAt: "t", keyGeneration: 0 });
      db.createObjectStore("uploads", { keyPath: "uploadId" }).put({ uploadId: "upl_c" });
      db.createObjectStore("keys", { keyPath: "username" }).put({ username: "alice", authSecret: "a".repeat(64), updatedAt: "t", pins: { userID, keys: { usr_b: "pin" } }, keyStates: { userID, byContainer: { [CID]: { mark: 2, digests: { 2: "d2" }, shared: 2, generation: 2 } } } });
    };
    open.onsuccess = () => { open.result.close(); resolve(); };
    open.onerror = () => reject(open.error);
  });
  const fresh = async (run: () => Promise<void>) => {
    const factory = new IDBFactory();
    vi.stubGlobal("indexedDB", factory);
    try { await seedV5(factory); await run(); } finally { vi.stubGlobal("indexedDB", shared); local.clear(); }
  };

  it("a v5 database opens at v6 with empty stores and its vault", () => fresh(async () => {
    localStorage.setItem("kynotes-pending-saves", "{}");
    expect(await pendingSaves()).toEqual([]);
    expect(await pendingUploads(userID)).toEqual([]);
    expect(await getNote("", "obj_a")).toBeUndefined();
    expect(await getDeviceKey("alice")).toBe("a".repeat(64));
    expect(await getPins("alice", userID)).toEqual({ usr_b: "pin" });
    expect(await getKeyState("alice", userID, CID)).toEqual({ mark: 2, digests: { 2: "d2" }, shared: 2, generation: 2 });
    expect(localStorage.getItem("kynotes-pending-saves")).toBeNull();
  }));

  it("opens where site storage is disabled: the upgrade never depends on localStorage", () => fresh(async () => {
    vi.stubGlobal("localStorage", { getItem: () => { throw new DOMException("denied", "SecurityError"); }, removeItem: () => { throw new DOMException("denied", "SecurityError"); } });
    try {
      expect(await pendingSaves()).toEqual([]);
      expect(await getDeviceKey("alice")).toBe("a".repeat(64));
    } finally {
      vi.stubGlobal("localStorage", { getItem: (key: string) => local.get(key) ?? null, setItem: (key: string, value: string) => { local.set(key, value); }, removeItem: (key: string) => { local.delete(key); } });
    }
  }));

  it("clears once: entries written after the upgrade survive every later open", () => fresh(async () => {
    const save = { id: "obj_d", containerID: CID, version: 1, payload: new Uint8Array([4]), updatedAt: "t", keyGeneration: 2, owner: userID };
    await queueSave(save);
    await putNote(userID, save);
    localStorage.setItem("kynotes-pending-saves", "{}"); // only the upgrade removes it
    expect(await pendingSaves()).toEqual([save]);
    const { owner: _owner, ...cached } = save;
    expect(await getNote(userID, save.id)).toEqual(cached);
    expect(localStorage.getItem("kynotes-pending-saves")).toBe("{}");
  }));
});

/** Writes a row as stored, bypassing the typed API. */
const writeRaw = (name: string, row: Record<string, unknown>) => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction(name, "readwrite");
    tx.objectStore(name).put(row);
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
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
