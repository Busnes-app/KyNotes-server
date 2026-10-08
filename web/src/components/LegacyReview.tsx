import { useEffect, useRef, useState } from "react";
import { APIRequestError } from "../api";
import { documentText } from "../document";
import { confirmReopenLegacy, type ReopenConfirmation } from "../keyring";
import { approveMigration, itemLabel, type LegacyReview as Review, type MigrationApproval, type Migrated, type MigrationItem } from "../migration";

const items = (n: number) => `${n} item${n === 1 ? "" : "s"}`;
export const legacyMine = (n: number) => `${items(n)} you wrote before this notebook was shared ${n === 1 ? "is" : "are"} not end-to-end verified yet. Review and share them with members, or stop opening them here.`;
export const legacyOthers = (n: number) => `${items(n)} written before this notebook was shared can be opened only by ${n === 1 ? "its author" : "their authors"}.`;
export const legacyRefused = (n: number) => `${items(n)} written before this notebook was shared ${n === 1 ? "was" : "were"} refused: sealed with your key but naming another author, which only a server that altered ${n === 1 ? "it" : "them"} does.`;
export const legacyLeave = (n: number) => `${items(n)} you did not tick will stay on the server, and this browser will stop opening them. Share the ticked items and stop opening the rest?`;
export const LEGACY_CHECKING = "Checking the items written before this notebook was shared…";
export const LEGACY_INCOMPLETE = "This browser could not check every item written before this notebook was shared.";
export const LEGACY_UNCHECKED = "This browser could not list the items written before this notebook was shared.";
export const LEGACY_INTRO = "Open each item and tick only what you recognise as your own. Ticked items are sealed with this notebook's key exactly as shown here, so every member can read them. Unticked items stay on the server, and this browser stops opening them.";
export const LEGACY_CLOSED = "This browser no longer opens items written before this notebook was shared.";
export const STOP_LEGACY = "Stop opening items written before this notebook was shared? This browser will no longer open any of them, including your own that you have not shared. They stay on the server.";
export const LEGACY_LABEL = "Written before sharing; not end-to-end verified";
export const LEGACY_SHARE_INCOMPLETE = "Some items couldn't be checked; the notebook stays open.";
export const LEGACY_BLOCKED = "These pages use attachments you're sharing; tick them too, or keep the notebook open:";
export const REOPEN_LEGACY = "Show pre-sharing items again";
export const REOPEN_CONFIRM = "Show items written before this notebook was shared again? They are not end-to-end verified: the server could have written or changed any of them. This browser opens them with your login key until you stop again.";
export const STOP_BUTTON = "Stop opening pre-sharing items";
export const SHARE_BUTTON = "Share ticked items";
export const TICK_THESE = "Tick these too";

/** Why the /legacy check did not finish (migration.ts reviewLegacy rejected). Never an empty list. */
export function checkFailure(error: unknown): string {
  if (error instanceof APIRequestError && error.status === 429) return "The server is limiting these checks; try again in a minute.";
  if (error instanceof APIRequestError) return `The server could not list them (${error.status ?? "error"}).`;
  return "This browser could not reach the server.";
}

/** What the workspace reports after a share run (migration.ts migrateLegacy). */
export function shareOutcomeText(result: Migrated): string {
  const n = result.shared.length;
  if (result.failed.length) return `${result.failed.length} of the ticked items could not be shared (${result.failed[0].reason}). This browser still opens items written before this notebook was shared; try again.`;
  if (result.closed) return `Shared ${items(n)}. ${LEGACY_CLOSED}`;
  if (result.incomplete) return `Shared ${items(n)}. ${LEGACY_SHARE_INCOMPLETE}`;
  return `Shared ${items(n)}. This browser still opens the rest; it checks again after a reload.`;
}

/** The review items "Tick these too" ticks: blocked pages and the attachments they keep, if the review still offers them. */
export function tickThese(review: Review, blockedBy: Migrated["blockedBy"]): Set<string> {
  const offered = new Set(review.mine.map((item) => item.id));
  return new Set(blockedBy.flatMap((entry) => [entry.id, entry.attachment]).filter((id) => offered.has(id)));
}

/**
 * The dialog's submit, and the only place an approval is minted (migration.test.ts pins the
 * identifier). review is the branded review the dialog shows; content is never read back from the
 * approval. With unticked items, the user confirms hiding exactly that many, and that count is minted in.
 */
export async function submitShare(input: { userID: string; containerID: string; review: Review; picked: ReadonlySet<string>; ask: (text: string) => boolean; onShare: (approval: MigrationApproval) => Promise<void> }): Promise<boolean> {
  const ticked = input.review.mine.filter((item) => input.picked.has(item.id)).map((item) => item.id);
  if (!ticked.length) return false;
  const hide = input.review.mine.length - ticked.length;
  if (hide > 0 && !input.ask(legacyLeave(hide))) return false;
  await input.onShare(approveMigration(input.userID, input.containerID, input.review, ticked, hide));
  return true;
}

/** "Show pre-sharing items again": the only place a ReopenConfirmation is minted, and only after the user's confirm. */
export async function submitReopen(userID: string, containerID: string, ask: (text: string) => boolean, onReopen: (confirmation: ReopenConfirmation) => Promise<void>): Promise<boolean> {
  if (!ask(REOPEN_CONFIRM)) return false;
  await onReopen(confirmReopenLegacy(userID, containerID));
  return true;
}

const PREVIEWABLE = /^image\/(png|jpeg|gif|webp|avif)$/;
/** The decrypted bytes the review holds, shown as an image (raster types only). */
function ImagePreview({ item }: { item: Extract<MigrationItem, { kind: "attachment" }> }) {
  const [url] = useState(() => URL.createObjectURL(new Blob([item.plaintext.slice().buffer as ArrayBuffer], { type: item.file.type })));
  useEffect(() => () => URL.revokeObjectURL(url), [url]);
  return <img className="legacy-image" src={url} alt={item.file.name} />;
}

/** The text a tick vouches for, shown in full: a page's or conflicting version's title and text, a comment's body. */
function content(item: MigrationItem): string {
  if (item.kind === "comment") return item.comment.body;
  if ((item.kind === "object" || item.kind === "conflict") && item.payload.type === "page") return documentText(item.payload.body);
  return "";
}

/** The dialog's list and actions, from the review the dialog opened with. */
export function LegacyItems({ items: shown, picked, busy, onToggle, onSelectAll, onCancel, onShare }: { items: readonly MigrationItem[]; picked: ReadonlySet<string>; busy: boolean; onToggle: (id: string) => void; onSelectAll: () => void; onCancel: () => void; onShare: () => void }) {
  return (
    <>
      <ul>
        {shown.map((item) => (
          <li key={item.id}>
            <label><input type="checkbox" checked={picked.has(item.id)} onChange={() => onToggle(item.id)} /> {itemLabel(item)}</label>
            <div className="legacy-label">{LEGACY_LABEL}</div>
            {content(item) && <p className="legacy-preview">{content(item)}</p>}
            {item.kind === "attachment" && PREVIEWABLE.test(item.file.type) && <ImagePreview item={item} />}
          </li>
        ))}
      </ul>
      <div className="link-actions">
        <button disabled={busy} onClick={onSelectAll}>Select all</button>
        <button className="quiet" disabled={busy} onClick={onCancel}>Cancel</button>
        <button disabled={busy || picked.size === 0} onClick={onShare}>{SHARE_BUTTON}</button>
      </div>
    </>
  );
}

/**
 * One notebook's pre-sharing items (migration.ts reviewLegacy). checking: the review is still running,
 * and Stop shows anyway. failure: why the check did not finish (never shown as an empty list).
 * closed: this device stopped opening them; only counts and "Show pre-sharing items again" show.
 * outcome: the last share run, for what blocked closing. The dialog lists the review it opened with.
 */
export function LegacyReview({ userID, containerID, review, checking, failure, closed, outcome, onShare, onStop, onReopen }: {
  userID: string; containerID: string; review: Review | undefined; checking: boolean; failure?: string; closed: boolean; outcome?: Migrated;
  onShare: (approval: MigrationApproval) => Promise<void>; onStop: () => Promise<void>; onReopen: (confirmation: ReopenConfirmation) => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [shown, setShown] = useState<Review>();
  const [picked, setPicked] = useState<ReadonlySet<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const mine = review?.mine ?? [];
  const others = review?.others ?? 0;
  const refused = review?.refused ?? 0;
  const unfinished = !checking && (!review || !review.complete);
  const open = !closed && (checking || unfinished || mine.length > 0);
  const blocked = outcome?.blockedBy ?? [];
  const run = async (work: () => Promise<unknown>) => { setBusy(true); try { await work(); } finally { setBusy(false); } };
  const openDialog = (ticked: ReadonlySet<string>) => { if (!review) return; setShown(review); setPicked(ticked); dialog.current?.showModal(); };
  const toggle = (id: string) => setPicked((value) => { const next = new Set(value); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  return (
    <>
      {open && (
        <div className="conflict-banner legacy-banner" role="status">
          {checking ? LEGACY_CHECKING : !review ? `${LEGACY_UNCHECKED} ${failure ?? ""}` : mine.length ? legacyMine(mine.length) : LEGACY_INCOMPLETE}
          {!checking && review && mine.length > 0 && !review.complete && <> {LEGACY_INCOMPLETE}</>}
          {outcome?.incomplete && <div>{LEGACY_SHARE_INCOMPLETE}</div>}
          {blocked.length > 0 && (
            <div>
              {LEGACY_BLOCKED}
              <ul>{blocked.map((entry) => <li key={`${entry.id}:${entry.attachment}`}>{entry.title || "Untitled page"}</li>)}</ul>
              {review && <button disabled={busy} onClick={() => openDialog(tickThese(review, blocked))}>{TICK_THESE}</button>}
            </div>
          )}
          {!checking && mine.length > 0 && <button disabled={busy} onClick={() => openDialog(new Set())}>Review and share…</button>}
          <button disabled={busy} onClick={() => void run(async () => { if (confirm(STOP_LEGACY)) await onStop(); })}>{STOP_BUTTON}</button>
        </div>
      )}
      {closed && (
        <div className="workspace-kind" role="status">
          {LEGACY_CLOSED}{" "}
          <button className="quiet" disabled={busy} onClick={() => void run(() => submitReopen(userID, containerID, (text) => confirm(text), onReopen))}>{REOPEN_LEGACY}</button>
        </div>
      )}
      {refused > 0 && <div className="workspace-kind" role="status">{legacyRefused(refused)}</div>}
      {others > 0 && <div className="workspace-kind" role="status">{legacyOthers(others)}</div>}
      <dialog ref={dialog} className="legacy-review" aria-labelledby="legacy-review-title">
        <h2 id="legacy-review-title">Items written before sharing</h2>
        <p>{LEGACY_INTRO}</p>
        {shown && !shown.complete && <p>{LEGACY_INCOMPLETE}</p>}
        <LegacyItems items={shown?.mine ?? []} picked={picked} busy={busy} onToggle={toggle}
          onSelectAll={() => setPicked(new Set((shown?.mine ?? []).map((item) => item.id)))}
          onCancel={() => dialog.current?.close()}
          onShare={() => void run(async () => {
            if (shown && (await submitShare({ userID, containerID, review: shown, picked, ask: (text) => confirm(text), onShare }))) dialog.current?.close();
          })} />
      </dialog>
    </>
  );
}
