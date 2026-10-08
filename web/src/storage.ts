import { x25519 } from "@noble/curves/ed25519.js";
import type { HeldIdentity } from "./identity";
import { closedOf, consumeReopenConfirmation, type KeyState, type ReopenConfirmation } from "./keyring";
import { isPinConfirmation, sameKey, type PinConfirmation, type Pins } from "./pins";
import { sameBytes } from "./teamKeys";
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
        transaction.onabort = () => resolve(db);
      } catch { resolve(db); }
    };
    request.onerror = () => reject(request.error ?? new Error("Unable to open local note store"));
  });
}

/** Settles when the transaction commits, and rejects when it errors or aborts, so a write never hangs. */
function committed<T>(transaction: IDBTransaction, result: () => T): Promise<T> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve(result());
    transaction.onerror = () => reject(transaction.error ?? new Error("Local store write failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("Local store write aborted"));
  });
}

/** A request callback that aborts its transaction when it throws (DataCloneError, quota), instead of leaving it open. */
const guarded = (transaction: IDBTransaction, callback: () => void) => () => {
  try { callback(); } catch { transaction.abort(); }
};

/** One write to one store, resolved only once it commits. */
async function write(name: string, work: (store: IDBObjectStore) => void): Promise<void> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(name, "readwrite");
    const done = committed(transaction, () => undefined);
    guarded(transaction, () => work(transaction.objectStore(name)))();
    await done;
  } finally {
    db.close();
  }
}

export async function putNote(owner: string, note: CachedNote): Promise<void> {
  await write(storeName, (store) => store.put({ ...note, owner }));
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
  await write(storeName, (store) => {
    const read = store.get([owner, id]);
    read.onsuccess = guarded(store.transaction, () => {
      if (!read.result) store.put({ ...legacy, owner });
      store.delete([UNKNOWN, id]);
    });
  });
  return legacy;
}

/** Cached pages written before owners were recorded and not claimed since. */
export async function ownerUnknownNotes(): Promise<CachedNote[]> {
  const db = await openDatabase();
  const rows = await new Promise<Array<CachedNote & { owner: string }>>((resolve, reject) => {
    const request = db.transaction(storeName).objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  db.close();
  return rows.filter((row) => row.owner === UNKNOWN).map(({ owner: _owner, ...note }) => note);
}

export async function deleteNote(owner: string, id: string): Promise<void> {
  await write(storeName, (store) => store.delete([owner, id]));
}

export async function queueSave(note: PendingSave & { owner: string }): Promise<void> {
  await write("pending", (store) => store.put(note));
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
  await write("pending", (store) => store.delete([owner, id]));
}

/**
 * Replaces (or, with next undefined, deletes) the queued save expected (its owner and id) only while
 * it is still the entry the caller read: a save that replaced it meanwhile is never overwritten.
 * A next with an owner claims an owner-unknown entry: it moves to that owner's key, unless the owner
 * queued a save of the same page meanwhile, which then stays and the claim is refused.
 */
export async function replaceQueuedSave(expected: PendingSave, next?: PendingSave): Promise<boolean> {
  let same = false;
  await write("pending", (store) => {
    const from = keyOf(expected);
    const read = store.get(from);
    read.onsuccess = guarded(store.transaction, () => {
      const current = read.result as PendingSave | undefined;
      same = Boolean(current && current.updatedAt === expected.updatedAt && current.version === expected.version && current.keyGeneration === expected.keyGeneration);
      if (!same) return;
      if (!next) { store.delete(from); return; }
      const to = keyOf(next);
      if (indexedDB.cmp(from, to) === 0) { store.put(toRow(next)); return; }
      const taken = store.get(to);
      taken.onsuccess = guarded(store.transaction, () => {
        if (taken.result) { same = false; return; }
        store.put(toRow(next));
        store.delete(from);
      });
    });
  });
  return same;
}

export async function putUpload(upload: PendingUpload): Promise<void> {
  await write("uploads", (store) => store.put(upload));
}
export async function pendingUploads(): Promise<PendingUpload[]> {
  const db = await openDatabase();
  const result = await new Promise<PendingUpload[]>((resolve, reject) => { const request = db.transaction("uploads").objectStore("uploads").getAll(); request.onsuccess = () => resolve(request.result as PendingUpload[]); request.onerror = () => reject(request.error); });
  db.close(); return result;
}
export async function clearUpload(uploadId: string): Promise<void> {
  await write("uploads", (store) => store.delete(uploadId));
}

/** Merges into the vault record so a cached identity survives a new auth secret. */
export async function storeDeviceKey(username: string, authSecret: string): Promise<void> {
  await write("keys", (store) => {
    const read = store.get(username);
    read.onsuccess = guarded(store.transaction, () => store.put({ ...read.result, username, authSecret, updatedAt: new Date().toISOString() }));
  });
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

/**
 * The identity as the vault keeps it. Secure contexts: the private key sealed (AES-256-GCM, AAD
 * kynotes/device-identity/v1|<userID>|<deviceId>) under deviceKey, a non-extractable WebCrypto key
 * kept in the same record, so "Forget this device" stays one delete. This only keeps the raw key out
 * of the record's plain values: it is not at-rest protection (the browser writes deviceKey's bytes
 * to the same profile) and page script can call decrypt. Plain-HTTP origins have no WebCrypto and
 * keep the raw key, as before. deviceId "" marks an identity created here that the server has not
 * confirmed yet (settleSSOIdentity).
 */
type SealedIdentity = { userID: string; deviceId: string; publicKey: Uint8Array; sealed: Uint8Array; deviceKey: CryptoKey };
type RawIdentity = { userID: string; deviceId: string; publicKey: Uint8Array; privateKey: Uint8Array };
type VaultIdentity = SealedIdentity | RawIdentity;
type VaultRecord = { username: string; authSecret?: string; updatedAt: string; identity?: VaultIdentity; pins?: { userID: string; keys: Pins }; keyStates?: { userID: string; byContainer: Record<string, KeyState> } };

/**
 * How the vault stores the private key, not how well it is protected. "wrapped": sealed under a
 * non-exportable key stored beside it in the same profile (not at-rest protection). "plain": a
 * plain-HTTP origin has no WebCrypto and stores the raw key.
 */
export const identityStorage = (): "wrapped" | "plain" =>
  globalThis.isSecureContext === true && typeof globalThis.crypto?.subtle?.generateKey === "function" ? "wrapped" : "plain";

const identityAAD = (userID: string, deviceId: string) => new TextEncoder().encode(`kynotes/device-identity/v1|${userID}|${deviceId}`);

async function sealForDevice(userID: string, identity: HeldIdentity): Promise<VaultIdentity> {
  const base = { userID, deviceId: identity.deviceId, publicKey: identity.publicKey.slice() };
  if (identityStorage() === "plain") return { ...base, privateKey: identity.privateKey.slice() };
  const deviceKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: identityAAD(userID, identity.deviceId) }, deviceKey, identity.privateKey.slice()));
  const sealed = new Uint8Array(12 + body.length);
  sealed.set(iv);
  sealed.set(body, 12);
  return { ...base, sealed, deviceKey };
}

/** The held identity, or undefined when the copy does not open or is not its public key's. */
async function openForDevice(stored: VaultIdentity): Promise<HeldIdentity | undefined> {
  try {
    const privateKey = "privateKey" in stored ? stored.privateKey
      : new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.sealed.slice(0, 12), additionalData: identityAAD(stored.userID, stored.deviceId) }, stored.deviceKey, stored.sealed.slice(12)));
    return sameBytes(x25519.getPublicKey(privateKey), stored.publicKey) ? { deviceId: stored.deviceId, publicKey: stored.publicKey, privateKey } : undefined;
  } catch {
    return undefined;
  }
}

/** True when the record holds expected for userID (null: holds none), compared by public key. */
const holds = (record: VaultRecord, userID: string, expected: HeldIdentity | null) => {
  const current = record.identity?.userID === userID ? record.identity : undefined;
  return expected === null ? !current : current !== undefined && sameBytes(current.publicKey, expected.publicKey);
};

/**
 * Keeps the identity in the existing vault record. expected makes it a compare-and-swap inside one
 * IndexedDB transaction (sealing happens before it, because WebCrypto awaits would end the
 * transaction): another tab's key is never overwritten. False: nothing was kept (no record, no
 * IndexedDB, or the record no longer holds expected).
 */
export async function storeIdentityKey(username: string, userID: string, identity: HeldIdentity, expected?: HeldIdentity | null): Promise<boolean> {
  const stored = await sealForDevice(userID, identity).catch(() => undefined);
  // Only beside a device key: a record closeLegacyStored created alone never starts keeping an identity.
  return stored ? updateRecord(username, (record) => (record.authSecret !== undefined && (expected === undefined || holds(record, userID, expected)) ? { ...record, identity: stored } : undefined)) : false;
}

/** This browser's identity for userID, a pending one (deviceId "") included. Throws when the vault cannot be read. */
export async function loadIdentityRecord(username: string, userID: string): Promise<HeldIdentity | undefined> {
  const stored = (await readRecord(username))?.identity;
  if (!stored || stored.userID !== userID) return undefined;
  const held = await openForDevice(stored);
  if (held && "privateKey" in stored && identityStorage() === "wrapped") {
    // Written raw by an earlier version: sealed now, only while the record still holds that copy.
    const upgraded = await sealForDevice(userID, held).catch(() => undefined);
    if (upgraded) await updateRecord(username, (record) => (record.identity && "privateKey" in record.identity && sameBytes(record.identity.privateKey, stored.privateKey) ? { ...record, identity: upgraded } : undefined));
  }
  return held;
}

/** The identity this browser may use: a finished one only. */
export async function getIdentityKey(username: string, userID: string): Promise<HeldIdentity | undefined> {
  const held = await loadIdentityRecord(username, userID);
  return held?.deviceId ? held : undefined;
}

/** True when this browser can keep an identity: IndexedDB opens and the signed-in account has a vault record with a device key. */
export async function vaultReady(username: string): Promise<boolean> {
  try { return (await readRecord(username))?.authSecret !== undefined; } catch { return false; }
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
  let found = false;
  try {
    await write("keys", (store) => {
      const read = store.get(username);
      read.onsuccess = guarded(store.transaction, () => {
        const record = read.result as VaultRecord | undefined;
        const next = record && change(record);
        if (next) { store.put(next); found = true; }
      });
    });
    return found;
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
  let outcome: PinsStored = { ok: false, conflicts: [] };
  try {
    await write("keys", (store) => {
      const read = store.get(username);
      read.onsuccess = guarded(store.transaction, () => {
        const record = read.result as VaultRecord | undefined;
        if (!record) return;
        const stored = pinsOf(record, userID);
        const conflicts = Object.keys(keys).filter((member) => stored[member] !== undefined && stored[member] !== keys[member] && !sameKey(stored[member], keys[member]));
        if (conflicts.length) { outcome = { ok: false, conflicts }; return; }
        store.put({ ...record, pins: { userID, keys: { ...keys, ...stored } } });
        outcome = { ok: true };
      });
    });
    return outcome;
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

/**
 * Merges key memory: the mark only rises and a stored digest is never replaced. False means it is
 * not kept. The legacy closure and the reopen mark are never taken from state: whatever is stored
 * stays, in the same transaction, so a pass that read them before a reopen or a close cannot undo
 * it. Only closeLegacyStored and reopenLegacy write them.
 */
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
      ...(prior.closed !== undefined ? { closed: prior.closed } : {}),
      ...(prior.reopened ? { reopened: true as const } : {}),
    };
    return { ...record, keyStates: { userID, byContainer: { ...byContainer, [containerID]: next } } };
  });
}

/**
 * Read-modify-write of this user's key memory for one container, creating the vault record when
 * this browser has none yet (a record without authSecret: getDeviceKey and vaultReady still see no
 * device key). change returning undefined writes nothing. Throws when IndexedDB is unusable.
 */
async function updateKeyState(username: string, userID: string, containerID: string, change: (prior: KeyState) => KeyState | undefined): Promise<boolean> {
  let kept = false;
  await write("keys", (store) => {
    const read = store.get(username);
    read.onsuccess = guarded(store.transaction, () => {
      const record: VaultRecord = (read.result as VaultRecord | undefined) ?? { username, updatedAt: new Date().toISOString() };
      const byContainer = statesOf(record, userID);
      const next = change(byContainer[containerID] ?? { mark: 0, digests: {} });
      if (!next) return;
      store.put({ ...record, keyStates: { userID, byContainer: { ...byContainer, [containerID]: next } } });
      kept = true;
    });
  });
  return kept;
}

/**
 * closed: stored; reopened: auto and the user reopened this container, so nothing was written;
 * unsaved: storage could not keep it.
 */
export type ClosureStored = "closed" | "reopened" | "unsaved";
/**
 * The one write that raises this device's legacy closure (observe.ts closeLegacy). A user's close
 * (auto false) also clears the reopen mark. An automatic close is refused, in the same transaction,
 * while the mark is set, so a reopen in another tab during a long check is never closed over.
 */
export async function closeLegacyStored(username: string, userID: string, containerID: string, closed: number, auto: boolean): Promise<ClosureStored> {
  let refused = false;
  try {
    const kept = await updateKeyState(username, userID, containerID, (prior) => {
      if (auto && prior.reopened) { refused = true; return undefined; }
      const { reopened: _, ...rest } = prior;
      return { ...rest, closed: Math.max(closedOf(prior), closedOf({ closed })) };
    });
    return refused ? "reopened" : kept ? "closed" : "unsaved";
  } catch {
    return "unsaved";
  }
}

/**
 * The one way this device's legacy closure falls: this user confirmed "Show pre-sharing items
 * again" for this container. The confirmation is used up even if the write fails. It also marks
 * the container reopened until a user close (closeLegacyStored) clears it; everything else in the
 * key memory stays. Call floors.ts reopenFloorIn after a true result: it lowers this tab and tells
 * the others to re-read storage; without it the tabs stay closed until a reload.
 */
export async function reopenLegacy(username: string, userID: string, containerID: string, confirmation: ReopenConfirmation): Promise<boolean> {
  if (!consumeReopenConfirmation(confirmation, userID, containerID)) return false;
  // Persisted beside the floor, so no reload or other tab closes it again by itself (closeLegacyStored).
  return updateKeyState(username, userID, containerID, ({ closed: _, ...open }) => ({ ...open, reopened: true })).catch(() => false);
}

export async function clearDeviceKey(username: string): Promise<void> {
  await write("keys", (store) => store.delete(username));
}

export async function clearAllDeviceKeys(): Promise<void> {
  await write("keys", (store) => store.clear());
}
