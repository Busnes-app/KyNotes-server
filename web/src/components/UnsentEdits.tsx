import { useEffect, useState } from "react";
import { containers } from "../api";
import { decryptObject, type KeyRef } from "../crypto";
import { deleteNote, pendingSaves, replaceQueuedSave, type PendingSave } from "../storage";
import { exportUnsent, unsentEdits } from "../stuckEdits";

type Unsent = { owned: PendingSave[]; unowned: PendingSave[] };
const NONE: Unsent = { owned: [], unowned: [] };

/**
 * Edits queued on this device for notebooks this account can no longer open. They can never be
 * sent, and nothing here sends them. Only this account's edits are listed: its own (export and
 * discard) and unstamped older ones its login-derived key opens (export only). Export decrypts in
 * this browser, only on a click; discard asks first. Nothing shows while the notebook list is unavailable.
 */
export function UnsentEdits({ legacyKey, userID }: { legacyKey: KeyRef; userID: string }) {
  const [unsent, setUnsent] = useState<Unsent>(NONE);
  const open = (item: PendingSave) => decryptObject(legacyKey, item.containerID, item.payload);
  async function find(): Promise<Unsent> {
    const live = await containers().then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    return unsentEdits(await pendingSaves().catch(() => []), live, userID, (item) => open(item).then((content) => content !== undefined));
  }
  const load = async () => setUnsent(await find());
  useEffect(() => { void load(); }, [userID]);
  const all = [...unsent.owned, ...unsent.unowned];
  if (!all.length) return null;
  async function exportAll() {
    const file = await exportUnsent(all, open);
    if (file.unreadable === all.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    const url = URL.createObjectURL(new Blob([file.json], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "kynotes-unsent-edits.json";
    document.body.append(link); link.click(); link.remove();
    // Revoked after the download has started; revoking in the same tick can cancel it.
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    const owned = unsent.owned;
    if (!confirm(`Delete ${owned.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const still = new Set((await find()).owned.map((item) => item.id));
    for (const item of owned) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      {unsent.owned.length > 0 && <p className="config-muted">{unsent.owned.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>}
      {unsent.unowned.length > 0 && <p className="config-muted">{unsent.unowned.length} older edit(s) on this device open with your key but were saved before edits were tied to an account. You can export them; they are not deleted here.</p>}
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      {unsent.owned.length > 0 && <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>}
    </section>
  );
}
