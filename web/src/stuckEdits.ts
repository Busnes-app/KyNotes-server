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
export async function exportUnsent(items: CachedNote[], open: (item: CachedNote) => Promise<unknown>): Promise<{ json: string; unreadable: number }> {
  const out: Array<{ id: string; notebook: string; updatedAt: string; content: unknown }> = [];
  let unreadable = 0;
  for (const item of items) {
    const content = await open(item).catch(() => undefined);
    if (content === undefined) unreadable += 1;
    else out.push({ id: item.id, notebook: item.containerID, updatedAt: item.updatedAt, content });
  }
  return { json: JSON.stringify(out, null, 2), unreadable };
}
