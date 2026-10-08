import { useEffect, useState } from "react";
import { decryptObject, type KeyRef } from "../crypto";
import { downloadFile } from "../download";
import { openFirst, type KeyState } from "../keyring";
import { listContainers } from "../observe";
import { deleteNote, getKeyState, pendingSaves, replaceQueuedSave, storeKeyState, type PendingSave } from "../storage";
import { exportUnsent, unsentEdits } from "../stuckEdits";

/**
 * This account's edits queued on this device for notebooks it can no longer open: export (decrypted in
 * this browser, only on a click) and discard (asks first). keysFor: the keys this browser holds for an
 * edit (its notebook's container key for that generation, or the waiting key for a waiting edit).
 */
export function UnsentEdits({ username, userID, keysFor }: { username: string; userID: string; keysFor: (item: PendingSave) => KeyRef[] }) {
  const [unsent, setUnsent] = useState<PendingSave[]>([]);
  const open = (item: PendingSave) => openFirst(keysFor(item), (key) => decryptObject(key, item.containerID, item.payload));
  async function find(): Promise<PendingSave[]> {
    // Through the observer, like every container read: the generations it reports raise this device's floor.
    const sink = { load: (id: string) => getKeyState(username, userID, id), save: (id: string, state: KeyState) => storeKeyState(username, userID, id, state) };
    const live = await listContainers(sink).then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    return unsentEdits(await pendingSaves().catch(() => []), live, userID);
  }
  const load = async () => setUnsent(await find());
  useEffect(() => { void load(); }, [userID]);
  if (!unsent.length) return null;
  async function exportAll() {
    const file = await exportUnsent(unsent, (item) => open(item as PendingSave));
    if (file.unreadable === unsent.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    downloadFile("kynotes-unsent-edits.json", file.json, "application/json");
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    if (!confirm(`Delete ${unsent.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const still = new Set((await find()).map((item) => item.id));
    for (const item of unsent) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(userID, item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      <p className="config-muted">{unsent.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>
    </section>
  );
}
