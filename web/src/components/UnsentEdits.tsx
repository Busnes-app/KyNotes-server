import { useEffect, useState } from "react";
import { containers } from "../api";
import { decryptObject, type KeyRef } from "../crypto";
import { deleteNote, pendingSaves, replaceQueuedSave, type PendingSave } from "../storage";
import { exportUnsent, stuckSaves } from "../stuckEdits";

/** Queued edits of notebooks the server no longer lists; none while the list is unavailable. */
async function findStuck(): Promise<PendingSave[]> {
  const live = await containers().then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
  return stuckSaves(await pendingSaves().catch(() => []), live);
}

/**
 * Edits queued on this device for notebooks this account can no longer open. They can never be
 * sent, and nothing here sends them. Export decrypts, in this browser and only on a click, what the
 * login-derived key opens (edits made while waiting for keys); discard deletes them after a
 * confirmation. Nothing shows while the notebook list is unavailable.
 */
export function UnsentEdits({ legacyKey }: { legacyKey: KeyRef }) {
  const [stuck, setStuck] = useState<PendingSave[]>([]);
  const load = async () => setStuck(await findStuck());
  useEffect(() => { void load(); }, []);
  if (!stuck.length) return null;
  async function exportAll() {
    const file = await exportUnsent(stuck, (item) => decryptObject(legacyKey, item.containerID, item.payload));
    if (file.unreadable === stuck.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    const url = URL.createObjectURL(new Blob([file.json], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "kynotes-unsent-edits.json"; link.click();
    URL.revokeObjectURL(url);
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    if (!confirm(`Delete ${stuck.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const still = new Set((await findStuck()).map((item) => item.id));
    for (const item of stuck) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      <p className="config-muted">{stuck.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>
    </section>
  );
}
