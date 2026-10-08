import type { CachedNote, PendingSave } from "./storage";

/**
 * Queued edits whose notebook the server no longer lists for this account: they can never be
 * sent. An unknown list (offline, server error) yields none, so an outage never offers sendable
 * work for deletion.
 */
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[] {
  return live ? queued.filter((item) => !live.has(item.containerID)) : [];
}

/** Edits the card shows; see unsentEdits. sealed counts owner-unknown edits nothing here opens. */
export type Unsent = { owned: PendingSave[]; unowned: PendingSave[]; unknown: PendingSave[]; sealed: number };

/**
 * The signed-in account's edits that will not be sent, so none is silently lost:
 * - owned: stamped with owner, notebook no longer listed: export and discard.
 * - unowned: unstamped, opensLegacy (this account's login-derived key) opens it, notebook no longer
 *   listed: export only. The drain stamps these (drainable).
 * - unknown: unstamped and not opened by opensLegacy, so nothing proves whose it is. Never sent or
 *   discarded, wherever its notebook is; listed for export when opens (any key this browser holds)
 *   reads it, otherwise counted in sealed.
 * Another account's stamped entries are never offered.
 * ponytail: queued saves only; pending uploads (pendingUploads) for lost notebooks are not listed.
 * Upgrade: stamp uploads with their owner and list them here the same way.
 */
export async function unsentEdits(queued: PendingSave[], live: ReadonlySet<string> | undefined, owner: string, opensLegacy: (item: PendingSave) => Promise<boolean>, opens: (item: PendingSave) => Promise<boolean>): Promise<Unsent> {
  const out: Unsent = { owned: [], unowned: [], unknown: [], sealed: 0 };
  const lost = new Set(stuckSaves(queued, live));
  for (const item of queued) {
    if (item.owner !== undefined) { if (item.owner === owner && lost.has(item)) out.owned.push(item); continue; }
    if (await opensLegacy(item).catch(() => false)) { if (lost.has(item)) out.unowned.push(item); continue; }
    if (await opens(item).catch(() => false)) out.unknown.push(item);
    else out.sealed += 1;
  }
  return out;
}

/**
 * The queued edits this session may upload: stamped with owner, or unstamped and opened by
 * opensLegacy. That key is this account's alone, so opening proves ownership: such entries come back
 * in stamp (persist the owner on them) and in drain already stamped, so a re-key keeps the claim.
 * Another account may share the notebook, so the server would accept its edit under this session,
 * misattributed; those wait for their owner. Unstamped entries nothing proves are left alone.
 * superseded: proven entries for a page this account has queued since; that save replaces them.
 */
export async function drainable(queued: PendingSave[], owner: string, opensLegacy: (item: PendingSave) => Promise<boolean>): Promise<{ drain: PendingSave[]; stamp: PendingSave[]; superseded: PendingSave[] }> {
  const drain: PendingSave[] = [], stamp: PendingSave[] = [], superseded: PendingSave[] = [];
  const owned = new Set(queued.filter((item) => item.owner === owner).map((item) => item.id));
  for (const item of queued) {
    if (item.owner === owner) drain.push(item);
    else if (item.owner === undefined && await opensLegacy(item).catch(() => false)) {
      if (owned.has(item.id)) { superseded.push(item); continue; }
      stamp.push(item);
      drain.push({ ...item, owner });
    }
  }
  return { drain, stamp, superseded };
}

/**
 * Cached drafts written before owners were recorded that this account's login-derived key does not
 * open (it would claim them, getNote) but another key this browser holds does: whose they are is
 * unknown, so they are listed for export only, never sent or discarded. A page that also has an
 * owner-unknown queued edit is listed once, there.
 */
export async function unknownDrafts(cached: CachedNote[], queued: PendingSave[], opensLegacy: (note: CachedNote) => Promise<boolean>, opens: (note: CachedNote) => Promise<boolean>): Promise<CachedNote[]> {
  const listed = new Set(queued.filter((item) => item.owner === undefined).map((item) => item.id));
  const out: CachedNote[] = [];
  for (const note of cached) {
    if (listed.has(note.id) || await opensLegacy(note).catch(() => false)) continue;
    if (await opens(note).catch(() => false)) out.push(note);
  }
  return out;
}

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
