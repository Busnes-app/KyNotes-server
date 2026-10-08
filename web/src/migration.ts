import type { LegacyRows } from "./api";
import { decryptAttachment, decryptAttachmentMetadata, decryptComment, decryptObject, fromBase64, type KeyRef } from "./crypto";
import type { AttachmentFile } from "./drain";
import { legacyKeys, openFirst, readKeys, type KeyFloor, type ReportedContainer } from "./keyring";
import type { ObjectPayload, PagePayload } from "./pages";

/**
 * A row written before this notebook was shared that this user's login key opens: theirs, or a server
 * forgery. It holds the decrypted content the dialog shows; sharing seals exactly this, never a re-read.
 */
export type MigrationItem =
  | { kind: "object"; id: string; version: number; payload: ObjectPayload }
  | { kind: "comment"; id: string; objectId: string; comment: { body: string; section?: string } }
  | { kind: "attachment"; id: string; objectIds: string[]; generation: number; file: AttachmentFile; plaintext: Uint8Array }
  | { kind: "conflict"; id: string; objectId: string; payload: PagePayload };
/**
 * mine: rows this user's login key opens, to review; others: listed rows it does not open (another
 * author's, or unreadable); refused: comments that open with this key but name another author, which
 * only a forgery does; complete: the server listed everything and every listed row could be fetched
 * with a valid generation; shared: the sharing generation this review covered (0: never shared).
 */
export type LegacyReview = { mine: MigrationItem[]; others: number; refused: number; complete: boolean; shared: number };
/** The notebook's legacy reads closed on this device (or its floor is not loaded) while a review ran. */
export class LegacyClosedError extends Error {
  constructor() { super("Pre-sharing items are no longer read on this device."); this.name = "LegacyClosedError"; }
}
export type ReviewAPI = {
  /** Rejects on any failed check (429, 500, no network): never an empty list, so nothing auto-closes. */
  legacyRows: (containerID: string) => Promise<LegacyRows>;
  readObject: (objectID: string) => Promise<{ bytes: Uint8Array; version: number; keyGeneration?: number }>;
  conflictBytes: (conflictID: string) => Promise<Uint8Array>;
  downloadAttachment: (attachmentID: string) => Promise<Uint8Array>;
};
/** floorNow: this tab's current floor for the container (floors.ts floorOf), read before every decrypt. */
export type ReviewInput = { container: ReportedContainer; floorNow: () => KeyFloor | undefined; legacy: KeyRef; userId: string };

/**
 * The pre-sharing rows of a shared notebook as this user can see them. Each row is opened with the
 * key readKeys picks for its generation and nothing else: the login key for a row below sharing
 * (until this device closes), none otherwise. The server's list only says where to look.
 * Rejects when the list cannot be fetched (an unfinished check), and with LegacyClosedError once the
 * closure rises mid-review: no row is decrypted after that.
 */
export async function reviewLegacy(api: ReviewAPI, input: ReviewInput): Promise<LegacyReview> {
  const { container, floorNow, legacy, userId } = input;
  const floor = floorNow();
  if (!floor) throw new LegacyClosedError();
  const shared = Math.max(container.sharedGeneration, floor.shared ?? 0);
  const review: LegacyReview = { mine: [], others: 0, refused: 0, complete: true, shared };
  if (shared === 0) return review;
  const rows = await api.legacyRows(container.id);
  review.complete = rows.complete;
  // Closed on this device: nothing opens with the login key, so every listed row is someone else's to share.
  if (!legacyKeys(floor, legacy).length) return { ...review, others: rows.objects.length + rows.comments.length + rows.attachments.length + rows.conflicts.length };
  const opened = async <T>(generation: number | undefined, open: (key: KeyRef) => Promise<T>) => {
    // Another tab may close while rows are fetched: stop rather than open one more with the login key.
    const now = floorNow();
    if (!now || !legacyKeys(now, legacy).length) throw new LegacyClosedError();
    return openFirst(readKeys(container, new Map(), legacy, generation, now), open).catch(() => undefined);
  };

  for (const row of rows.objects) {
    // The current version, re-read: the listed one may have been re-sealed meanwhile.
    const current = await api.readObject(row.id).catch(() => undefined);
    // Unfetched, or no valid generation to pick a key with: the row is unaccounted for.
    if (!current || current.keyGeneration === undefined) { review.complete = false; continue; }
    const payload = await opened(current.keyGeneration, (key) => decryptObject(key, container.id, current.bytes));
    if (payload) review.mine.push({ kind: "object", id: row.id, version: current.version, payload });
    else if (current.keyGeneration < shared) review.others += 1;
  }
  for (const row of rows.comments) {
    const comment = await opened(row.keyGeneration, (key) => decryptComment(key, container.id, fromBase64(row.bodyCiphertext)));
    if (!comment) review.others += 1;
    // Before sharing only its author's key sealed a comment: another author's name on one this key opens is forged.
    else if (row.authorUserId !== userId) review.refused += 1;
    else review.mine.push({ kind: "comment", id: row.id, objectId: row.objectId, comment });
  }
  for (const row of rows.attachments) {
    const file = await opened(row.keyGeneration, (key) => decryptAttachmentMetadata(key, container.id, fromBase64(row.metadataCiphertext)));
    if (!file || row.keyGeneration === undefined || !row.objectIds.length) { review.others += 1; continue; }
    // ponytail: every listed attachment of this user is held decrypted for the review. Upgrade: pin a
    // SHA-256 of the plaintext here and stream it again at sharing, refusing a different digest.
    const bytes = await api.downloadAttachment(row.id).catch(() => undefined);
    const plaintext = bytes && (await opened(row.keyGeneration, (key) => decryptAttachment(key, container.id, bytes)));
    if (!plaintext) { review.complete = false; continue; } // metadata is this user's, the bytes are missing or not
    review.mine.push({ kind: "attachment", id: row.id, objectIds: row.objectIds, generation: row.keyGeneration, file, plaintext });
  }
  for (const row of rows.conflicts) {
    const bytes = await api.conflictBytes(row.id).catch(() => undefined);
    if (!bytes) { review.complete = false; continue; }
    const payload = await opened(row.keyGeneration, (key) => decryptObject(key, container.id, bytes));
    if (payload?.type === "page") review.mine.push({ kind: "conflict", id: row.id, objectId: row.objectId, payload });
    else review.others += 1;
  }
  return review;
}

/**
 * This device may stop opening legacy rows by itself: the server answered complete:true, every
 * listed row was fetched, nothing in it is this user's, and the notebook is still shared at exactly
 * the generation reviewed (current: floorOf now). A failed check never reaches here; any sharing
 * change since needs a fresh review.
 */
export const autoCloses = (review: LegacyReview, current: KeyFloor | undefined): boolean =>
  review.shared > 0 && (current?.shared ?? 0) === review.shared && review.complete === true && review.mine.length === 0;

/** What the review dialog shows for an item. */
export function itemLabel(item: MigrationItem): string {
  switch (item.kind) {
    case "object": return `${item.payload.type === "page" ? "Page" : item.payload.type === "section" ? "Section" : "Section group"}: ${item.payload.title || "Untitled"}`;
    case "comment": return `Comment: ${item.comment.body.slice(0, 80)}`;
    case "attachment": return `Attachment: ${item.file.name} (${Math.max(1, Math.ceil(item.file.size / 1024))} KB)`;
    case "conflict": return `Conflicting version: ${item.payload.title || "Untitled"}`;
  }
}
