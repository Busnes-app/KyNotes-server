import type { LegacyRows } from "./api";
import { base64, decryptAttachment, decryptAttachmentMetadata, decryptComment, decryptObject, encryptComment, encryptNote, fromBase64, type KeyRef } from "./crypto";
import type { AttachmentFile } from "./drain";
import { closedOf, legacyKeys, legacyRow, openFirst, readKeys, type KeyFloor, type Keyring, type ReportedContainer, type WriteKey } from "./keyring";
import type { Sealed } from "./outbound";
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
/** Reviews reviewLegacy returned: the only ones approveMigration accepts. */
const reviews = new WeakSet<LegacyReview>();
const branded = (review: LegacyReview) => { reviews.add(review); return review; };
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
  if (shared === 0) return branded(review);
  const rows = await api.legacyRows(container.id);
  review.complete = rows.complete;
  // Closed on this device: nothing opens with the login key, so every listed row is someone else's to share.
  if (!legacyKeys(floor, legacy).length) return branded({ ...review, others: rows.objects.length + rows.comments.length + rows.attachments.length + rows.conflicts.length });
  const opened = async <T>(generation: number | undefined, open: (key: KeyRef) => Promise<T>) => {
    // Another tab may close while rows are fetched: stop rather than open one more with the login key.
    const now = floorNow();
    if (!now || !legacyKeys(now, legacy).length) throw new LegacyClosedError();
    return openFirst(readKeys(container, new Map(), legacy, generation, now), open).catch(() => undefined);
  };

  // ponytail: every open of a notebook that has not closed re-reads every listed page, other
  // authors' included, one GET each. Upgrade: keep each row's review by version for the session.
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
    // No valid generation to pick a key with: unaccounted for, as for pages.
    if (row.keyGeneration === undefined) { review.complete = false; continue; }
    const file = await opened(row.keyGeneration, (key) => decryptAttachmentMetadata(key, container.id, fromBase64(row.metadataCiphertext)));
    if (!file) { review.others += 1; continue; }
    // This user's key opens it, but with no page it cannot be shared: unaccounted for, never someone else's.
    if (!row.objectIds.length) { review.complete = false; continue; }
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
  return branded(review);
}

/**
 * This device may stop opening legacy rows by itself: the server answered complete:true, every
 * listed row was fetched, nothing in it is this user's, and the notebook is still shared at exactly
 * the generation reviewed (current: floorOf now). A failed check never reaches here; any sharing
 * change since needs a fresh review.
 */
export const autoCloses = (review: LegacyReview, current: KeyFloor | undefined): boolean =>
  review.shared > 0 && (current?.shared ?? 0) === review.shared && review.complete === true && review.mine.length === 0;

/**
 * Whether the check may close a notebook by itself: not while this user's stored key memory says it
 * was reopened (storage.ts reopenLegacy), read fresh from storage so every tab and reload agrees.
 * An unreadable store counts as reopened.
 */
export const mayAutoClose = (load: () => Promise<{ reopened?: true }>): Promise<boolean> => load().then((stored) => !stored.reopened, () => false);

/** The workspace's check of one notebook: the review, or why it did not finish (never an empty review). */
export type LegacyCheck = { review: LegacyReview; autoClosed: boolean } | { failed: unknown };
/**
 * Runs the review and, only on a review that finished, closes legacy reads by itself when autoCloses
 * allows it at the floor current now, the device is still open, and autoClose is on (off for a
 * notebook the user just reopened). A rejected review is handed back as failed, never closed on.
 */
export async function checkLegacyRows(run: () => Promise<LegacyReview>, floorNow: () => KeyFloor | undefined, close: () => Promise<boolean>, autoClose = true): Promise<LegacyCheck> {
  let review: LegacyReview;
  try { review = await run(); } catch (failed) { return { failed }; }
  const floor = floorNow();
  const autoClosed = autoClose && closedOf(floor) === 0 && autoCloses(review, floor) && (await close().catch(() => false));
  return { review, autoClosed };
}

/** "attachment://att_…" references in a payload; IDs are fixed-length, so no ID is a prefix of another. */
const references = (value: unknown): string[] => [...JSON.stringify(value).matchAll(/attachment:\/\/(att_[0-9a-hjkmnp-tv-z]{26})/g)].map((match) => match[1]);
const sizeText = (bytes: number) => `${bytes} byte${bytes === 1 ? "" : "s"}`;
const fileText = (file: AttachmentFile) => `${file.name} (${file.type || "unknown type"}, ${sizeText(file.size)})`;
/** BlockNote's unstyled defaults: nothing a reader would see. */
const COSMETIC = new Set(["default", "left"]);

/**
 * Everything a tick seals, as plain text (React renders it as text, never HTML): every string in
 * the payload with its field name, link targets and table cells included, and each attachment
 * reference with the name, type and size of the reviewed copy (files: the review's attachments).
 * A page body that is JSON is walked too, whatever its format. Numbers and flags are left out:
 * they carry no text.
 */
export function reviewText(item: MigrationItem, files: ReadonlyMap<string, AttachmentFile>): string {
  if (item.kind === "attachment") return `Attachment: ${fileText(item.file)}`;
  const lines: string[] = [];
  const show = (key: string, text: string) => {
    if (!text || (COSMETIC.has(text) && /color|alignment/i.test(key))) return;
    const refs = references(text).map((id) => (files.has(id) ? `attachment ${fileText(files.get(id)!)}` : `an attachment not in this review (${id})`));
    lines.push(`${key === "text" ? "" : `${key}: `}${text}${refs.length ? ` → ${refs.join(", ")}` : ""}`);
  };
  /** Every string under value, for one table cell. */
  const strings = (value: unknown): string[] => (typeof value === "string" ? [value] : value && typeof value === "object" ? Object.entries(value).flatMap(([key, inner]) => (key === "type" ? [] : strings(inner))) : []);
  const walk = (key: string, value: unknown) => {
    if (typeof value === "string") {
      if (key === "body") {
        try {
          const parsed: unknown = JSON.parse(value);
          if (parsed && typeof parsed === "object") { walk("", parsed); return; }
        } catch { /* plain text: shown as it is */ }
      }
      if (key === "type" && value === "text") return;
      show(key, value);
    } else if (Array.isArray(value)) {
      // A table row: its cells on one line.
      if (key === "cells") { lines.push(value.map((cell) => strings(cell).join(" ")).join(" | ")); return; }
      for (const entry of value) walk(key, entry);
    } else if (value && typeof value === "object") {
      for (const [inner, entry] of Object.entries(value)) walk(inner, entry);
    }
  };
  walk("", item.kind === "comment" ? item.comment : item.payload);
  return lines.join("\n");
}

/** Reviewed attachments a ticked page or conflicting version uses but the user left unticked: sharing that page would point members at a copy only this login key opens. */
export function attachmentsLeftBehind(review: LegacyReview, ticked: ReadonlySet<string>): Array<{ id: string; title: string; attachment: string; name: string }> {
  const attachments = new Map(review.mine.flatMap((item) => (item.kind === "attachment" ? [[item.id, item.file.name] as const] : [])));
  return review.mine.flatMap((item) => {
    if ((item.kind !== "object" && item.kind !== "conflict") || !ticked.has(item.id)) return [];
    return [...new Set(references(item.payload))].filter((id) => attachments.has(id) && !ticked.has(id)).map((id) => ({ id: item.id, title: item.payload.title, attachment: id, name: attachments.get(id)! }));
  });
}

/** What the review dialog shows for an item. */
export function itemLabel(item: MigrationItem): string {
  switch (item.kind) {
    case "object": return `${item.payload.type === "page" ? "Page" : item.payload.type === "section" ? "Section" : "Section group"}: ${item.payload.title || "Untitled"}`;
    case "comment": return `Comment: ${item.comment.body.slice(0, 80)}`;
    case "attachment": return `Attachment: ${item.file.name} (${Math.max(1, Math.ceil(item.file.size / 1024))} KB)`;
    case "conflict": return `Conflicting version: ${item.payload.title || "Untitled"}`;
  }
}

const approvals = new WeakSet<MigrationApproval>();
/**
 * Each approval's own copy of the ticked items, plus the titles of the reviewed pages left unticked;
 * nothing outside this module holds it, and migrateLegacy deletes it when it takes it.
 */
const approvedItems = new WeakMap<MigrationApproval, { items: readonly MigrationItem[]; untickedPages: ReadonlyMap<string, { title: string; text: string }> }>();
let mint: (userID: string, containerID: string, review: LegacyReview, ticked: ReadonlySet<string>, hideConfirmed: number) => MigrationApproval;
/**
 * One user's ticked items of one notebook's review, as the dialog showed them, at the sharing
 * generation that review covered. The content is a structuredClone taken at approval: what is sealed
 * is what was shown, whatever the review object or the server hold later. It exposes no content; the
 * dialog reads the review it shows. complete: the review saw the whole list; unticked: the reviewed
 * items left out, which closing hides on this device; hideConfirmed: the count the user confirmed
 * hiding. Only approveMigration makes one; migrateLegacy spends it.
 */
export class MigrationApproval {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mint = (userID, containerID, review, ticked, hideConfirmed) => {
      const items = review.mine.filter((item) => ticked.has(item.id));
      const approval = new MigrationApproval(userID, containerID, review.shared, review.complete === true, review.mine.length - items.length, hideConfirmed);
      // Frozen wrapper: a holder cannot re-target it. The items are not frozen (Uint8Array cannot be) but private.
      Object.freeze(approval);
      // Unticked reviewed rows, as decrypted: only their own text can show that they use an attachment.
      const untickedPages = new Map(review.mine.flatMap((item) => (item.kind === "object" && !ticked.has(item.id) ? [[item.id, { title: item.payload.title, text: JSON.stringify(item.payload) }] as const] : [])));
      approvedItems.set(approval, { items: structuredClone(items), untickedPages });
      approvals.add(approval);
      return approval;
    };
  }
  private constructor(readonly userID: string, readonly containerID: string, readonly shared: number, readonly complete: boolean, readonly unticked: number, readonly hideConfirmed: number) {}
}
/**
 * Call only from the review dialog's submit (components/LegacyReview.tsx; migration.test.ts pins the
 * identifier): review is the one the dialog shows (from reviewLegacy), ticked the IDs the user ticked,
 * hideConfirmed the unticked count the user confirmed hiding.
 */
export const approveMigration = (userID: string, containerID: string, review: LegacyReview, ticked: Iterable<string>, hideConfirmed: number): MigrationApproval => {
  if (!reviews.has(review)) throw new Error("Review this notebook's items first.");
  const picked = new Set(ticked);
  if (attachmentsLeftBehind(review, picked).length) throw new Error("A ticked page uses an attachment you did not tick. Tick the attachment too, or untick the page.");
  return mint(userID, containerID, review, picked, hideConfirmed);
};
export const isMigrationApproval = (value: unknown, userID: string, containerID: string): value is MigrationApproval =>
  typeof value === "object" && value !== null && approvals.has(value as MigrationApproval) &&
  (value as MigrationApproval).userID === userID && (value as MigrationApproval).containerID === containerID;

const ATTACHMENT_ID = /^att_[0-9a-hjkmnp-tv-z]{26}$/;
/** payload with every attachment://old pointing at renamed[old]; the same object when nothing changed. IDs are fixed-length, so no ID is a prefix of another. */
export function rewriteRefs<T extends ObjectPayload>(payload: T, renamed: Readonly<Record<string, string>>): T {
  const text = JSON.stringify(payload);
  let next = text;
  for (const [old, replacement] of Object.entries(renamed))
    if (ATTACHMENT_ID.test(old) && ATTACHMENT_ID.test(replacement)) next = next.split(`attachment://${old}`).join(`attachment://${replacement}`);
  return next === text ? payload : (JSON.parse(next) as T);
}

export type MigrationAPI = {
  readObject: ReviewAPI["readObject"];
  /** outbound.ts sendObject. A stale base version is refused (409) and the server keeps the re-seal as a conflict record. */
  sendObject: (sealed: Sealed, objectID: string, bytes: Uint8Array, baseVersion: number) => Promise<{ version: number }>;
  /** outbound.ts sendCommentRewrite. */
  sendCommentRewrite: (sealed: Sealed, commentID: string, bodyCiphertext: string) => Promise<void>;
  /** Seals plaintext for the current key, uploads it through outbound.ts and attaches it to objectID; the new attachment ID. */
  uploadAttachment: (objectID: string, objectVersion: number, plaintext: Uint8Array, file: AttachmentFile) => Promise<string>;
  attach: (objectID: string, attachmentID: string, objectVersion: number) => Promise<void>;
  /** api.ts detachAttachment. Called only after the page was re-saved pointing at the new copy. */
  detach: (objectID: string, attachmentID: string) => Promise<void>;
  /** Saves a rejected page version (sealed through outbound.ts) as a copy next to its page; false when it could not. */
  copyConflict: (objectID: string, conflictID: string, payload: PagePayload) => Promise<boolean>;
  /** api.ts resolveConflict. Called only after copyConflict placed the copy. */
  resolve: (conflictID: string) => Promise<void>;
};
/** ring: this tab's keys for the container (pages that only point at a replaced attachment). */
export type MigrationInput = ReviewInput & { write: WriteKey; ring: Keyring; approval: MigrationApproval };
/**
 * shared: approved rows now sealed with the container key; failed: approved rows (or pages pointing
 * at them) that were not; closed: close() ran and kept. Why it did not close, for the dialog:
 * incomplete: the review did not see the whole list, so nothing closes (Stop is the explicit path);
 * blockedBy: reviewed pages left unticked whose own text uses an attachment that was shared (tick them too, or keep
 * the notebook open), with the title the review showed.
 */
export type Migrated = { shared: string[]; failed: Array<{ id: string; reason: string }>; closed: boolean; incomplete: boolean; blockedBy: Array<{ id: string; title: string; attachment: string }> };

/**
 * Re-seals the approved pre-sharing items under the current container key, exactly as the review
 * decrypted them, through the injected outbound sends, and only then calls close (closeLegacy):
 * when nothing failed, the floor still has the reviewed sharing generation, and the user confirmed
 * hiding exactly the unticked items. The approval is spent first, so it never runs twice; one from
 * before a sharing change is refused before anything is sent. Order matters: attachments get a new
 * copy first; every page pointing at an old copy is re-saved to point at the new one; the old copy
 * leaves a page only after that page's re-save; a conflict is resolved only after its copy exists.
 * Re-running it is safe: a re-sealed row is no longer listed, so the next review does not offer it.
 * ponytail: a run that dies between attaching a new copy and detaching the old one leaves the old
 * copy listed, and the next run uploads it again (a duplicate attachment, never lost content).
 * Upgrade: record the source attachment ID in the new copy's metadata and skip it on the next run.
 */
export async function migrateLegacy(api: MigrationAPI, input: MigrationInput, close: () => Promise<boolean>): Promise<Migrated> {
  const { container, floorNow, legacy, userId, write, ring, approval } = input;
  if (!isMigrationApproval(approval, userId, container.id) || !approvals.delete(approval)) throw new Error("Choose the items to share in the review first.");
  // Taken once and released: the plaintext lives no longer than this run.
  const { items, untickedPages } = approvedItems.get(approval)!;
  approvedItems.delete(approval);
  const sameSharing = () => approval.shared > 0 && floorNow()?.shared === approval.shared;
  if (!sameSharing()) throw new Error("This notebook's sharing changed since the review. Review its items again.");
  const sealed: Sealed = { container, generation: write.generation };
  const shared: string[] = [];
  const failed: Migrated["failed"] = [];
  const attempt = async (id: string, run: () => Promise<unknown>, counts = true) => {
    try { await run(); if (counts) shared.push(id); return true; }
    catch (error) { failed.push({ id, reason: error instanceof Error ? error.message : "failed" }); return false; }
  };

  // 1. Attachments: a new copy of the reviewed bytes under the container key, attached beside the old one on every page.
  const renamed: Record<string, string> = {};
  const replaced: Array<{ old: string; objectIds: string[] }> = [];
  for (const item of items) {
    if (item.kind !== "attachment") continue;
    await attempt(item.id, async () => {
      const versions = await Promise.all(item.objectIds.map(async (objectID) => (await api.readObject(objectID)).version));
      const next = await api.uploadAttachment(item.objectIds[0], versions[0], item.plaintext, item.file);
      for (let i = 1; i < item.objectIds.length; i += 1) await api.attach(item.objectIds[i], next, versions[i]);
      renamed[item.id] = next;
      replaced.push({ old: item.id, objectIds: item.objectIds });
    });
  }

  // 2. Pages, sections and groups: approved rows, and every page that points at a replaced attachment.
  const approvedObjects = new Map(items.flatMap((item) => (item.kind === "object" ? [[item.id, item] as const] : [])));
  const pointing = new Set(replaced.flatMap((entry) => entry.objectIds));
  const notRewritten = new Set<string>();
  const blockedBy: Migrated["blockedBy"] = [];
  for (const objectID of new Set([...approvedObjects.keys(), ...pointing])) {
    const approved = approvedObjects.get(objectID);
    let skipped = false;
    const ok = await attempt(objectID, async () => {
      let version: number;
      let payload: ObjectPayload | undefined;
      if (approved) ({ version, payload } = approved);
      else {
        // Not ticked: only a row this browser already reads with a container key may be rewritten.
        const current = await api.readObject(objectID);
        const floor = floorNow();
        if (!floor || legacyRow(container, current.keyGeneration, floor)) {
          // The server's attachment list is a claim: a page blocks closing only when its reviewed text
          // uses the attachment. Any other listed page is left alone, old copy and all.
          const page = untickedPages.get(objectID);
          const uses = replaced.filter((entry) => entry.objectIds.includes(objectID) && page?.text.includes(`attachment://${entry.old}`));
          if (!uses.length) { skipped = true; return; }
          for (const entry of uses) blockedBy.push({ id: objectID, title: page!.title, attachment: entry.old });
          throw new Error("written before sharing and not ticked");
        }
        payload = await openFirst(readKeys(container, ring, legacy, current.keyGeneration, floor), (key) => decryptObject(key, container.id, current.bytes));
        version = current.version;
      }
      if (!payload) throw new Error("could not be opened");
      const next = rewriteRefs(payload, renamed);
      if (!approved && next === payload) return;
      await api.sendObject(sealed, objectID, await encryptNote(write.key, container.id, next), version);
    }, Boolean(approved));
    if (!ok || skipped) notRewritten.add(objectID);
  }

  // 3. The old copy leaves each page that now points at the new one.
  for (const entry of replaced)
    for (const objectID of entry.objectIds)
      if (!notRewritten.has(objectID)) await attempt(`${entry.old}:${objectID}`, () => api.detach(objectID, entry.old), false);

  // 4. Comments, by their author (the server refuses anyone else).
  for (const item of items) {
    if (item.kind !== "comment") continue;
    await attempt(item.id, async () => api.sendCommentRewrite(sealed, item.id, base64(await encryptComment(write.key, container.id, item.comment.body, item.comment.section ?? ""))));
  }
  // 5. Conflicting versions become copies next to their page; the record is resolved only after.
  for (const item of items) {
    if (item.kind !== "conflict") continue;
    await attempt(item.id, async () => {
      if (!(await api.copyConflict(item.objectId, item.id, item.payload))) throw new Error("could not be placed next to its page");
      await api.resolve(item.id);
    });
  }
  // Closing hides every unticked row on this device: only after everything ticked was shared, from a
  // review that saw the whole list, at the reviewed sharing generation, and with the user's
  // confirmation of exactly that many hidden items.
  const closed = failed.length === 0 && approval.complete && approval.hideConfirmed === approval.unticked && sameSharing() && (await close().catch(() => false));
  return { shared, failed, closed, incomplete: !approval.complete, blockedBy };
}
