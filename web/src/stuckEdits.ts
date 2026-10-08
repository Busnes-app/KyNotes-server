import type { PendingSave } from "./storage";

/**
 * Queued edits whose notebook the server no longer lists for this account: they can never be
 * sent. An unknown list (offline, server error) yields none, so an outage never offers sendable
 * work for deletion.
 */
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[] {
  return live ? queued.filter((item) => !live.has(item.containerID)) : [];
}

/**
 * The signed-in account's unsendable edits. owned: stamped with owner, so export and discard.
 * unowned: queued before stamping, offered for export only when opens() proves this account's key
 * reads them; never discarded. Another account's entries are never offered.
 */
export async function unsentEdits(queued: PendingSave[], live: ReadonlySet<string> | undefined, owner: string, opens: (item: PendingSave) => Promise<boolean>): Promise<{ owned: PendingSave[]; unowned: PendingSave[] }> {
  const stuck = stuckSaves(queued, live);
  const unowned: PendingSave[] = [];
  for (const item of stuck) if (item.owner === undefined && await opens(item).catch(() => false)) unowned.push(item);
  return { owned: stuck.filter((item) => item.owner === owner), unowned };
}

/**
 * The queued edits this session may upload: stamped with owner, or unstamped and opened by
 * opensLegacy (this account's login-derived key). Another account may share the notebook, so the
 * server would accept its edit under this session, misattributed; those wait for their owner.
 */
export async function drainable(queued: PendingSave[], owner: string, opensLegacy: (item: PendingSave) => Promise<boolean>): Promise<PendingSave[]> {
  const out: PendingSave[] = [];
  for (const item of queued) {
    if (item.owner === owner || (item.owner === undefined && await opensLegacy(item).catch(() => false))) out.push(item);
  }
  return out;
}

/** A JSON export of the edits open() reads; the rest are counted, never guessed at. */
export async function exportUnsent(items: PendingSave[], open: (item: PendingSave) => Promise<unknown>): Promise<{ json: string; unreadable: number }> {
  const out: Array<{ id: string; notebook: string; updatedAt: string; content: unknown }> = [];
  let unreadable = 0;
  for (const item of items) {
    const content = await open(item).catch(() => undefined);
    if (content === undefined) unreadable += 1;
    else out.push({ id: item.id, notebook: item.containerID, updatedAt: item.updatedAt, content });
  }
  return { json: JSON.stringify(out, null, 2), unreadable };
}
