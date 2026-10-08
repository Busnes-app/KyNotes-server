import { useEffect, useState } from "react";
import { decryptObject, type KeyRef } from "../crypto";
import { downloadFile } from "../download";
import { openFirst, type KeyState } from "../keyring";
import { listContainers } from "../observe";
import { deleteNote, getKeyState, ownerUnknownNotes, pendingSaves, replaceQueuedSave, storeKeyState, type CachedNote, type PendingSave } from "../storage";
import { exportUnsent, unknownDrafts, unsentEdits, type Unsent } from "../stuckEdits";

type Listed = Unsent & { drafts: CachedNote[] };
const NONE: Listed = { owned: [], unowned: [], unknown: [], sealed: 0, drafts: [] };

/**
 * Edits queued on this device that will not be sent (unsentEdits), and nothing here sends them:
 * this account's for notebooks it can no longer open (export; discard its own), and older edits
 * whose owner is unknown, queued or cached drafts (export only, never discarded). Export decrypts in this browser, only on
 * a click; discard asks first. teamKeys: the keys this browser holds for an edit's notebook and
 * generation (readKeys), tried after the login-derived key.
 */
export function UnsentEdits({ legacyKey, username, userID, teamKeys }: { legacyKey: KeyRef; username: string; userID: string; teamKeys: (item: PendingSave) => KeyRef[] }) {
  const [unsent, setUnsent] = useState<Listed>(NONE);
  const decrypt = (keys: KeyRef[]) => (item: CachedNote) => openFirst(keys, (key) => decryptObject(key, item.containerID, item.payload));
  const open = (item: CachedNote) => decrypt([legacyKey, ...teamKeys(item)])(item);
  const opens = (read: (item: CachedNote) => Promise<unknown>) => (item: CachedNote) => read(item).then((content) => content !== undefined);
  async function find(): Promise<Listed> {
    // Through the observer, like every container read: the generations it reports raise this device's floor.
    const sink = { load: (id: string) => getKeyState(username, userID, id), save: (id: string, state: KeyState) => storeKeyState(username, userID, id, state) };
    const live = await listContainers(sink).then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    const queued = await pendingSaves().catch(() => []);
    const drafts = await unknownDrafts(await ownerUnknownNotes().catch(() => []), queued, opens(decrypt([legacyKey])), opens(open));
    return { ...(await unsentEdits(queued, live, userID, opens(decrypt([legacyKey])), opens(open))), drafts };
  }
  const load = async () => setUnsent(await find());
  useEffect(() => { void load(); }, [userID]);
  const all: CachedNote[] = [...unsent.owned, ...unsent.unowned, ...unsent.unknown, ...unsent.drafts];
  if (!all.length && !unsent.sealed) return null;
  async function exportAll() {
    const file = await exportUnsent(all, open);
    if (file.unreadable === all.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    downloadFile("kynotes-unsent-edits.json", file.json, "application/json");
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    const owned = unsent.owned;
    if (!confirm(`Delete ${owned.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const still = new Set((await find()).owned.map((item) => item.id));
    for (const item of owned) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(userID, item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      {unsent.owned.length > 0 && <p className="config-muted">{unsent.owned.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>}
      {unsent.unknown.length > 0 && <p className="config-muted">Unsent edit, owner unknown: {unsent.unknown.length} edit(s) on this device were saved before edits were tied to an account and are sealed with a notebook key, so they are never sent or deleted here. You can export them.</p>}
      {unsent.drafts.length > 0 && <p className="config-muted">Draft, owner unknown: {unsent.drafts.length} draft(s) on this device were cached before drafts were tied to an account and are sealed with a notebook key, so they are never sent or deleted here. You can export them.</p>}
      {unsent.sealed > 0 && <p className="config-muted">{unsent.sealed} more unsent edit(s), owner unknown, cannot be opened in this browser. They stay on this device.</p>}
      {unsent.unowned.length > 0 && <p className="config-muted">{unsent.unowned.length} older edit(s) on this device open with your key but were saved before edits were tied to an account. You can export them; they are not deleted here.</p>}
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      {all.length > 0 && <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>}
      {unsent.owned.length > 0 && <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>}
    </section>
  );
}
