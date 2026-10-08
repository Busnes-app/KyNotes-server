import { WAITING_GENERATION } from "./keyring";
import type { CachedNote, PendingSave } from "./storage";

/**
 * Queued edits whose notebook the server no longer lists for this account: they can never be
 * sent. An unknown list (offline, server error) yields none, so an outage never offers sendable
 * work for deletion.
 */
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[] {
  return live ? queued.filter((item) => !live.has(item.containerID)) : [];
}

/**
 * The signed-in account's edits that will not be sent: its own, for notebooks no longer listed.
 * ponytail: queued saves only; pending uploads for lost notebooks are not listed. Upgrade: list them the same way.
 */
export const unsentEdits = (queued: PendingSave[], live: ReadonlySet<string> | undefined, owner: string): PendingSave[] =>
  stuckSaves(queued.filter((item) => item.owner === owner), live);

/** A JSON export of the edits open() reads; the rest are counted, never guessed at. */
export async function exportUnsent<T extends CachedNote>(items: T[], open: (item: T) => Promise<unknown>): Promise<{ json: string; unreadable: number }> {
  const out: Array<{ id: string; notebook: string; updatedAt: string; content: unknown }> = [];
  let unreadable = 0;
  for (const item of items) {
    const content = await open(item).catch(() => undefined);
    if (content === undefined) unreadable += 1;
    else out.push({ id: item.id, notebook: item.containerID, updatedAt: item.updatedAt, content });
  }
  return { json: JSON.stringify(out, null, 2), unreadable };
}

/**
 * After a reset (M5): this account's waiting edits were sealed for the replaced key. Each is marked
 * previousKey, so the queue never sends it, and re-sealed under the new key when reseal can (this browser
 * held the old one), so it can still be exported. replace changes only an entry still as it was read.
 */
export async function retireWaiting(queued: PendingSave[], owner: string, reseal: (item: PendingSave) => Promise<Uint8Array | undefined>, replace: (expected: PendingSave, next: PendingSave) => Promise<boolean>): Promise<void> {
  for (const item of queued) {
    if (item.owner !== owner || item.keyGeneration !== WAITING_GENERATION || item.previousKey) continue;
    const payload = await reseal(item).catch(() => undefined);
    await replace(item, { ...item, ...(payload && { payload }), previousKey: true });
  }
}

/**
 * This account's edits for listed notebooks that will never be sent: marked previousKey at a reset here,
 * or waiting edits the waiting key this browser holds does not open (a reset elsewhere). opens is false
 * when no key this browser holds opens the entry; it is asked only while a waiting key is held.
 */
export async function previousKeyEdits(queued: PendingSave[], owner: string, waitingHeld: boolean, opens: (item: PendingSave) => Promise<boolean>): Promise<PendingSave[]> {
  const out: PendingSave[] = [];
  for (const item of queued) {
    if (item.owner !== owner) continue;
    if (item.previousKey || (waitingHeld && item.keyGeneration === WAITING_GENERATION && !(await opens(item)))) out.push(item);
  }
  return out;
}
