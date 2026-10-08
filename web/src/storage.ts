import type { HeldIdentity } from "./identity";
import type { KeyState } from "./keyring";
import { isPinConfirmation, sameKey, type PinConfirmation, type Pins } from "./pins";
const databaseName = "kynotes-web";
const storeName = "notes";

export type CachedNote = { id: string; containerID: string; version: number; payload: Uint8Array; updatedAt: string; keyGeneration?: number };
/** owner: the user ID that queued it; absent on entries queued before stamping. */
export type PendingSave = CachedNote & { owner?: string };
export type PendingUpload = { uploadId: string; containerID: string; objectID: string; objectVersion: number; keyGeneration: number; chunkBytes: number; nextChunk: number; payload: Uint8Array; metadataCiphertext: string; name: string; type: string; size: number };

/**
 * The note cache and the save queue are keyed by [owner, id], so one account's entry for a page is
 * never read, replaced or deleted by another account's. UNKNOWN is the owner of entries written
 * before owners were recorded: nothing proves whose they are.
 */
const UNKNOWN = "";
const OWNED = ["owner", "id"];
const keyOf = (entry: { id: string; owner?: string }) => [entry.owner ?? UNKNOWN, entry.id];
const toRow = <T extends { owner?: string }>(entry: T) => ({ ...entry, owner: entry.owner ?? UNKNOWN });
function fromRow<T extends { owner?: string }>(row: T): T {
  if (row.owner !== UNKNOWN) return row;
  const { owner: _unknown, ...rest } = row;
  return rest as T;
}

/** Version 5 re-keys the note cache and the save queue by [owner, id]; existing rows keep their owner or get UNKNOWN. */
function ownerKeyed(db: IDBDatabase, upgrade: IDBTransaction, name: string) {
  if (!db.objectStoreNames.contains(name)) { db.createObjectStore(name, { keyPath: OWNED }); return; }
  if (Array.isArray(upgrade.objectStore(name).keyPath)) return;
  const read = upgrade.objectStore(name).getAll();
  read.onsuccess = () => {
    db.deleteObjectStore(name);
    const store = db.createObjectStore(name, { keyPath: OWNED });
    for (const row of read.result as Array<{ owner?: string }>) store.put(toRow(row));
  };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 5);
    request.onupgradeneeded = () => {
      const db = request.result;
      ownerKeyed(db, request.transaction!, storeName);
      ownerKeyed(db, request.transaction!, "pending");
      if (!db.objectStoreNames.contains("uploads")) db.createObjectStore("uploads", { keyPath: "uploadId" });
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys", { keyPath: "username" });
    };
    request.onsuccess = () => {
      const db = request.result;
      const legacy = localStorage.getItem("kynotes-pending-saves");
      if (!legacy) { resolve(db); return; }
      try {
        const queue = JSON.parse(legacy) as Record<string, Omit<PendingSave, "payload"> & { payload: string }>;
        const transaction = db.transaction("pending", "readwrite");
        const store = transaction.objectStore("pending");
        for (const note of Object.values(queue)) {
          store.put(toRow({ ...note, payload: Uint8Array.from(atob(note.payload), (char) => char.charCodeAt(0)) }));
        }
        transaction.oncomplete = () => { localStorage.removeItem("kynotes-pending-saves"); resolve(db); };
        transaction.onerror = () => resolve(db);
      } catch { resolve(db); }
    };
    request.onerror = () => reject(request.error ?? new Error("Unable to open local note store"));
  });
}

export async function putNote(owner: string, note: CachedNote): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(storeName, "readwrite").objectStore(storeName).put({ ...note, owner });
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

async function getRow(key: string[]): Promise<CachedNote | undefined> {
  const db = await openDatabase();
  const row = await new Promise<(CachedNote & { owner: string }) | undefined>((resolve, reject) => {
    const request = db.transaction(storeName).objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  db.close();
  if (!row) return undefined;
  const { owner: _owner, ...note } = row;
  return note;
}

/**
 * owner's cached copy of id. Without one, a copy cached before owners were recorded is returned
 * only when opensLegacy (this account's login-derived key) opens it, and is then claimed for owner;
 * otherwise it is never read here.
 */
export async function getNote(owner: string, id: string, opensLegacy?: (note: CachedNote) => Promise<boolean>): Promise<CachedNote | undefined> {
  const own = await getRow([owner, id]);
  if (own || !opensLegacy || owner === UNKNOWN) return own;
  const legacy = await getRow([UNKNOWN, id]);
  if (!legacy || !(await opensLegacy(legacy).catch(() => false))) return undefined;
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(storeName, "readwrite");
    const store = transaction.objectStore(storeName);
    const read = store.get([owner, id]);
    read.onsuccess = () => {
      if (!read.result) store.put({ ...legacy, owner });
      store.delete([UNKNOWN, id]);
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
  return legacy;
}

export async function deleteNote(owner: string, id: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(storeName, "readwrite").objectStore(storeName).delete([owner, id]);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function queueSave(note: PendingSave & { owner: string }): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("pending", "readwrite").objectStore("pending").put(note);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

/** Every account's queued saves; owner is absent on entries queued before owners were recorded. */
export async function pendingSaves(): Promise<PendingSave[]> {
  const db = await openDatabase();
  const result = await new Promise<PendingSave[]>((resolve, reject) => {
    const request = db.transaction("pending").objectStore("pending").getAll();
    request.onsuccess = () => resolve((request.result as PendingSave[]).map(fromRow));
    request.onerror = () => reject(request.error);
  });
  db.close();
  return result;
}

export async function clearQueuedSave(owner: string, id: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("pending", "readwrite").objectStore("pending").delete([owner, id]);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

/**
 * Replaces (or, with next undefined, deletes) the queued save expected (its owner and id) only while
 * it is still the entry the caller read: a save that replaced it meanwhile is never overwritten.
 * A next with an owner claims an owner-unknown entry: it moves to that owner's key, unless the owner
 * queued a save of the same page meanwhile, which then stays and the claim is refused.
 */
export async function replaceQueuedSave(expected: PendingSave, next?: PendingSave): Promise<boolean> {
  const db = await openDatabase();
  const replaced = await new Promise<boolean>((resolve, reject) => {
    const transaction = db.transaction("pending", "readwrite");
    const store = transaction.objectStore("pending");
    const from = keyOf(expected);
    let same = false;
    const read = store.get(from);
    read.onsuccess = () => {
      const current = read.result as PendingSave | undefined;
      same = Boolean(current && current.updatedAt === expected.updatedAt && current.version === expected.version && current.keyGeneration === expected.keyGeneration);
      if (!same) return;
      if (!next) { store.delete(from); return; }
      const to = keyOf(next);
      if (indexedDB.cmp(from, to) === 0) { store.put(toRow(next)); return; }
      const taken = store.get(to);
      taken.onsuccess = () => {
        if (taken.result) { same = false; return; }
        store.put(toRow(next));
        store.delete(from);
      };
    };
    transaction.oncomplete = () => resolve(same);
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
  return replaced;
}

export async function putUpload(upload: PendingUpload): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => { const request = db.transaction("uploads", "readwrite").objectStore("uploads").put(upload); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); });
  db.close();
}
export async function pendingUploads(): Promise<PendingUpload[]> {
  const db = await openDatabase();
  const result = await new Promise<PendingUpload[]>((resolve, reject) => { const request = db.transaction("uploads").objectStore("uploads").getAll(); request.onsuccess = () => resolve(request.result as PendingUpload[]); request.onerror = () => reject(request.error); });
  db.close(); return result;
}
export async function clearUpload(uploadId: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => { const request = db.transaction("uploads", "readwrite").objectStore("uploads").delete(uploadId); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); });
  db.close();
}

/** Merges into the vault record so a cached identity survives a new auth secret. */
export async function storeDeviceKey(username: string, authSecret: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const read = store.get(username);
    read.onsuccess = () => store.put({ ...read.result, username, authSecret, updatedAt: new Date().toISOString() });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
}

/** Runs the server call, then caches its keys best-effort: the vault is a convenience and never fails a sign-in. */
export async function rememberAfter<T>(call: () => Promise<T>, username: string, authSecret: string, held?: { userID: string; identity: HeldIdentity }): Promise<T> {
  const result = await call();
  try {
    await storeDeviceKey(username, authSecret);
    if (held) await storeIdentityKey(username, held.userID, held.identity);
  } catch { /* no IndexedDB: the next visit prompts for the password again */ }
  return result;
}

export async function getDeviceKey(username: string): Promise<string | undefined> {
  const db = await openDatabase();
  const result = await new Promise<{ username: string; authSecret: string } | undefined>((resolve, reject) => {
    const request = db.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return result?.authSecret;
}

type VaultRecord = { username: string; authSecret: string; updatedAt: string; identity?: HeldIdentity & { userID: string }; pins?: { userID: string; keys: Pins }; keyStates?: { userID: string; byContainer: Record<string, KeyState> } };

/** Adds the unwrapped identity to an existing vault record, so "Forget this device" stays one delete. */
export async function storeIdentityKey(username: string, userID: string, identity: HeldIdentity): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const read = store.get(username);
    read.onsuccess = () => {
      const record = read.result as VaultRecord | undefined;
      if (record) store.put({ ...record, identity: { ...identity, userID } });
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
}

export async function getIdentityKey(username: string, userID: string): Promise<HeldIdentity | undefined> {
  const db = await openDatabase();
  const record = await new Promise<VaultRecord | undefined>((resolve, reject) => {
    const request = db.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  if (record?.identity?.userID !== userID) return undefined;
  const { deviceId, publicKey, privateKey } = record.identity;
  return { deviceId, publicKey, privateKey };
}

async function readRecord(username: string): Promise<VaultRecord | undefined> {
  const db = await openDatabase();
  const record = await new Promise<VaultRecord | undefined>((resolve, reject) => {
    const request = db.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return record;
}

/** Read-modify-write of an existing vault record in one transaction. False: nothing kept (no record, no IndexedDB). */
/** change returning undefined leaves the record as it is, and the result is false. */
async function updateRecord(username: string, change: (record: VaultRecord) => VaultRecord | undefined): Promise<boolean> {
  try {
    const db = await openDatabase();
    const kept = await new Promise<boolean>((resolve, reject) => {
      const transaction = db.transaction("keys", "readwrite");
      const store = transaction.objectStore("keys");
      let found = false;
      const read = store.get(username);
      read.onsuccess = () => {
        const record = read.result as VaultRecord | undefined;
        const next = record && change(record);
        if (next) { found = true; store.put(next); }
      };
      transaction.oncomplete = () => resolve(found);
      transaction.onerror = () => reject(transaction.error);
    });
    db.close();
    return kept;
  } catch {
    return false;
  }
}

const pinsOf = (record: VaultRecord, userID: string): Pins => (record.pins?.userID === userID ? record.pins.keys : {});

/** Colleague key pins live in the vault record, so "Forget this device" clears them too. */
export async function getPins(username: string, userID: string): Promise<Pins> {
  const record = await readRecord(username);
  return record ? pinsOf(record, userID) : {};
}

/**
 * ok: every proposed pin is now stored (a proposal equal to the stored pin is fine). Otherwise
 * nothing was written: conflicts names members already pinned here to a different key (another
 * pass won; the caller must not wrap for them), and is empty when pins are not kept at all.
 */
export type PinsStored = { ok: true } | { ok: false; conflicts: string[] };

/** Adds first-contact pins, compared with the stored pins in the same transaction; never overwrites. */
export async function storePins(username: string, userID: string, keys: Pins): Promise<PinsStored> {
  try {
    const db = await openDatabase();
    const result = await new Promise<PinsStored>((resolve, reject) => {
      const transaction = db.transaction("keys", "readwrite");
      const store = transaction.objectStore("keys");
      let outcome: PinsStored = { ok: false, conflicts: [] };
      const read = store.get(username);
      read.onsuccess = () => {
        const record = read.result as VaultRecord | undefined;
        if (!record) return;
        const stored = pinsOf(record, userID);
        const conflicts = Object.keys(keys).filter((member) => stored[member] !== undefined && stored[member] !== keys[member] && !sameKey(stored[member], keys[member]));
        if (conflicts.length) { outcome = { ok: false, conflicts }; return; }
        store.put({ ...record, pins: { userID, keys: { ...keys, ...stored } } });
        outcome = { ok: true };
      };
      transaction.oncomplete = () => resolve(outcome);
      transaction.onerror = () => reject(transaction.error);
    });
    db.close();
    return result;
  } catch {
    return { ok: false, conflicts: [] };
  }
}

/**
 * Replaces one pin; only a confirmFingerprintChange result is accepted. With expected, only while
 * the stored pin is still that key (the "was" the user saw), checked in the same transaction.
 */
export async function storeConfirmedPin(username: string, userID: string, confirmation: PinConfirmation, expected?: string): Promise<boolean> {
  if (!isPinConfirmation(confirmation)) return false;
  return updateRecord(username, (record) => {
    const keys = pinsOf(record, userID);
    const stored = keys[confirmation.userId];
    if (expected !== undefined && (stored === undefined || !sameKey(stored, expected))) return undefined;
    return { ...record, pins: { userID, keys: { ...keys, [confirmation.userId]: confirmation.key } } };
  });
}

const statesOf = (record: VaultRecord, userID: string): Record<string, KeyState> => (record.keyStates?.userID === userID ? record.keyStates.byContainer : {});

/** This device's key memory for containerID (high-water mark, digests of accepted keys); empty when unknown. */
export async function getKeyState(username: string, userID: string, containerID: string): Promise<KeyState> {
  const record = await readRecord(username);
  return (record && statesOf(record, userID)[containerID]) || { mark: 0, digests: {} };
}

/** Merges key memory: the mark only rises and a stored digest is never replaced. False means it is not kept. */
export async function storeKeyState(username: string, userID: string, containerID: string, state: KeyState): Promise<boolean> {
  return updateRecord(username, (record) => {
    const byContainer = statesOf(record, userID);
    const prior: KeyState = byContainer[containerID] ?? { mark: 0, digests: {} };
    const next: KeyState = {
      mark: Math.max(prior.mark, state.mark),
      digests: { ...state.digests, ...prior.digests },
      // The sharing state this device has seen (KeyFloor) never goes backwards either.
      shared: Math.max(prior.shared ?? 0, state.shared ?? 0),
      generation: Math.max(prior.generation ?? 0, state.generation ?? 0),
    };
    return { ...record, keyStates: { userID, byContainer: { ...byContainer, [containerID]: next } } };
  });
}

export async function clearDeviceKey(username: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("keys", "readwrite").objectStore("keys").delete(username);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function clearAllDeviceKeys(): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("keys", "readwrite").objectStore("keys").clear();
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
  db.close();
}
