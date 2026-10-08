import { useEffect, useState } from "react";
import { decryptObject, type KeyRef } from "../crypto";
import { downloadFile } from "../download";
import { openFirst, type KeyState } from "../keyring";
import { listContainers } from "../observe";
import { deleteNote, getKeyState, pendingSaves, replaceQueuedSave, storeKeyState, type PendingSave } from "../storage";
import { exportUnsent, previousKeyEdits, unsentEdits } from "../stuckEdits";

/**
 * This account's edits queued on this device that will never be sent: for notebooks it can no longer
 * open, or sealed under the key a reset replaced (M5). Export (decrypted in this browser, only on a
 * click) and discard (asks first). keysFor: the keys this browser holds for an edit (its notebook's
 * container key for that generation, or the waiting key for a waiting edit); waitingHeld: a waiting key is held.
 */
export const PREVIOUS_KEY = "sealed under your previous key";

export function UnsentEdits({ username, userID, keysFor, waitingHeld }: { username: string; userID: string; keysFor: (item: PendingSave) => KeyRef[]; waitingHeld: boolean }) {
  const [lost, setLost] = useState<PendingSave[]>([]);
  const [previous, setPrevious] = useState<PendingSave[]>([]);
  const unsent = [...lost, ...previous];
  const open = (item: PendingSave) => openFirst(keysFor(item), (key) => decryptObject(key, item.containerID, item.payload));
  async function find(): Promise<{ lost: PendingSave[]; previous: PendingSave[] }> {
    // Through the observer, like every container read: the generations it reports raise this device's floor.
    const sink = { load: (id: string) => getKeyState(username, userID, id), save: (id: string, state: KeyState) => storeKeyState(username, userID, id, state) };
    const live = await listContainers(sink).then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    const queued = (await pendingSaves().catch(() => [])).filter((item) => item.owner === userID);
    const lost = unsentEdits(queued, live, userID);
    const gone = new Set(lost.map((item) => item.id));
    return { lost, previous: await previousKeyEdits(queued.filter((item) => !gone.has(item.id)), userID, waitingHeld, (item) => open(item).then(() => true, () => false)) };
  }
  const load = async () => { const found = await find(); setLost(found.lost); setPrevious(found.previous); };
  useEffect(() => { void load(); }, [userID, waitingHeld]);
  if (!unsent.length) return null;
  async function exportAll() {
    const file = await exportUnsent(unsent, open);
    if (file.unreadable === unsent.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    downloadFile("kynotes-unsent-edits.json", file.json, "application/json");
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    if (!confirm(`Delete ${unsent.length} unsent edit(s) from this browser? They can never be sent and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const found = await find();
    const still = new Set([...found.lost, ...found.previous].map((item) => item.id));
    for (const item of unsent) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(userID, item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      {lost.length > 0 && <p className="config-muted">{lost.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>}
      {previous.length > 0 && <p className="config-muted">{previous.length} edit(s) on this device are {PREVIOUS_KEY}: they were waiting for a notebook's key when your encryption key was reset, so they are never sent. Export them to keep their content.</p>}
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>
    </section>
  );
}
