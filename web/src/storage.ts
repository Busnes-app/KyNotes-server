import type { HeldIdentity } from "./identity";
import type { Pins } from "./pins";
const databaseName = "kynotes-web";
const storeName = "notes";

export type CachedNote = { id: string; containerID: string; version: number; payload: Uint8Array; updatedAt: string; keyGeneration?: number };
export type PendingSave = CachedNote;
export type PendingUpload = { uploadId: string; containerID: string; objectID: string; objectVersion: number; keyGeneration: number; chunkBytes: number; nextChunk: number; payload: Uint8Array; metadataCiphertext: string; name: string; type: string; size: number };

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 4);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) request.result.createObjectStore(storeName, { keyPath: "id" });
      if (!request.result.objectStoreNames.contains("pending")) request.result.createObjectStore("pending", { keyPath: "id" });
      if (!request.result.objectStoreNames.contains("uploads")) request.result.createObjectStore("uploads", { keyPath: "uploadId" });
      if (!request.result.objectStoreNames.contains("keys")) request.result.createObjectStore("keys", { keyPath: "username" });
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
          store.put({ ...note, payload: Uint8Array.from(atob(note.payload), (char) => char.charCodeAt(0)) });
        }
        transaction.oncomplete = () => { localStorage.removeItem("kynotes-pending-saves"); resolve(db); };
        transaction.onerror = () => resolve(db);
      } catch { resolve(db); }
    };
    request.onerror = () => reject(request.error ?? new Error("Unable to open local note store"));
  });
}

export async function putNote(note: CachedNote): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(storeName, "readwrite").objectStore(storeName).put(note);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function getNote(id: string): Promise<CachedNote | undefined> {
  const db = await openDatabase();
  const result = await new Promise<CachedNote | undefined>((resolve, reject) => {
    const request = db.transaction(storeName).objectStore(storeName).get(id);
    request.onsuccess = () => resolve(request.result as CachedNote | undefined); request.onerror = () => reject(request.error);
  });
  db.close(); return result;
}

export async function deleteNote(id: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(storeName, "readwrite").objectStore(storeName).delete(id);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function queueSave(note: PendingSave): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("pending", "readwrite").objectStore("pending").put(note);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function pendingSaves(): Promise<PendingSave[]> {
  const db = await openDatabase();
  const result = await new Promise<PendingSave[]>((resolve, reject) => {
    const request = db.transaction("pending").objectStore("pending").getAll();
    request.onsuccess = () => resolve(request.result as PendingSave[]);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return result;
}

export async function clearQueuedSave(id: string): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction("pending", "readwrite").objectStore("pending").delete(id);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
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

type VaultRecord = { username: string; authSecret: string; updatedAt: string; identity?: HeldIdentity & { userID: string }; pins?: { userID: string; keys: Pins } };

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

/** Colleague key pins live in the vault record, so "Forget this device" clears them too. */
export async function getPins(username: string, userID: string): Promise<Pins> {
  const db = await openDatabase();
  const record = await new Promise<VaultRecord | undefined>((resolve, reject) => {
    const request = db.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return record?.pins?.userID === userID ? record.pins.keys : {};
}

/** Replaces the pins of an existing vault record; without one (no IndexedDB) pins are not kept. */
export async function storePins(username: string, userID: string, keys: Pins): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const read = store.get(username);
    read.onsuccess = () => {
      const record = read.result as VaultRecord | undefined;
      if (record) store.put({ ...record, pins: { userID, keys } });
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
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
