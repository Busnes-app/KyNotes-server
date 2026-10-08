import { useEffect, useState } from "react";
import { userIdentity } from "../api";
import type { PublicIdentity } from "../identity";
import { confirmFingerprintChange, fingerprint, pinLabel, pinRows, retrustMessage, retrustTarget, type PinRow } from "../pins";
import { getPins, storeConfirmedPin } from "../storage";

type Shown = PinRow & { pinnedPrint: string; currentPrint?: string };
const UNREADABLE = "unreadable key";
const print = (key: string) => fingerprint(key).catch(() => UNREADABLE);

/**
 * Colleagues this browser pinned, with fingerprints computed here from the keys. A changed key is
 * re-trusted only after the user confirms the exact key shown, through confirmFingerprintChange and
 * storeConfirmedPin: the same path as the wrap prompt (spec §6). Pins are never deleted here.
 * names come from this session's key passes; a colleague not seen yet shows by user ID.
 */
export function PinnedKeys({ username, userID, names }: { username: string; userID: string; names: Record<string, string> }) {
  const [rows, setRows] = useState<Shown[] | undefined>(undefined);
  const [problem, setProblem] = useState("");
  const nameOf = (row: Shown) => names[row.userId] ?? row.userId;
  async function load() {
    try {
      const pins = await getPins(username, userID);
      // ponytail: one identity request per pin. Upgrade: a batch identity route.
      const seen: Record<string, PublicIdentity | undefined> = Object.fromEntries(await Promise.all(Object.keys(pins).map(async (id) => [id, await userIdentity(id).catch(() => undefined)] as const)));
      const current = Object.fromEntries(Object.entries(seen).map(([id, identity]) => [id, identity?.publicKey]));
      setRows(await Promise.all(pinRows(pins, current).map(async (row) => ({
        ...row,
        pinnedPrint: await print(row.pinned),
        currentPrint: row.current === undefined ? undefined : await print(row.current),
      }))));
    } catch {
      setProblem("This browser could not read the colleague keys it saved.");
    }
  }
  useEffect(() => { void load(); }, [username, userID]);
  async function trust(row: Shown) {
    if (row.current === undefined || row.currentPrint === undefined || row.currentPrint === UNREADABLE) return;
    // Fresh read for this user ID; it must be the key whose fingerprint is on screen.
    const target = retrustTarget(row.userId, row.current, await userIdentity(row.userId).catch(() => undefined));
    if (!target) {
      setProblem("That colleague's key changed again or could not be read. Check the fingerprint shown now.");
      await load();
      return;
    }
    if (!confirm(retrustMessage({ userId: row.userId, name: nameOf(row), newPrint: row.currentPrint, oldPrint: row.pinnedPrint }))) return;
    try {
      const confirmation = confirmFingerprintChange(await getPins(username, userID), target);
      if (!(await storeConfirmedPin(username, userID, confirmation))) throw new Error("not stored");
    } catch {
      setProblem("This browser could not save the new key. Allow site storage and try again.");
      return;
    }
    setProblem("");
    await load();
  }
  return (
    <section id="colleague-keys" className="config-card">
      <h2>Colleague keys</h2>
      <p className="config-muted">Keys this browser trusts when sharing team notebooks. Fingerprints are computed here, not taken from the server.</p>
      {problem && <p className="config-muted" role="alert">{problem}</p>}
      {rows?.length === 0 && <p className="config-muted">No colleague keys yet. A key is saved the first time you share a team notebook with someone.</p>}
      {rows?.map((row) => (
        <div className="pin-row" key={row.userId}>
          <strong>{pinLabel(row.userId, nameOf(row))}</strong>
          <code>{row.pinnedPrint}</code>
          {row.state === "same" && <span className="config-muted">matches the server</span>}
          {row.state === "unseen" && <span className="config-muted">not visible now (no shared notebook, or no key yet)</span>}
          {row.state === "changed" && (
            <>
              <span className="config-muted">changed to <code>{row.currentPrint}</code></span>
              {row.currentPrint !== UNREADABLE && <button type="button" className="secondary" onClick={() => void trust(row)}>Trust new key</button>}
            </>
          )}
        </div>
      ))}
    </section>
  );
}
