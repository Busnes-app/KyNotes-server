import { useEffect, useState } from "react";
import { listShareLinks, revokeShareLink, type ShareLinkSummary } from "../api";
import type { KeyRef, ShareLabel } from "../crypto";
import { forgetShareLabel, readShareLabel } from "../shareLabels";

type Labelled = ShareLinkSummary & { label: ShareLabel | "none" | "unreadable" };

/**
 * This account's live encrypted share links. The server holds only their ciphertext and never the key,
 * so it cannot say which page a link shares; the browser that made a link keeps that, sealed
 * (shareLabels.ts), and other links say they were made on another device. Revoking stops the link
 * working at once, for everyone who has it.
 */
export function ShareLinks({ userID, keysFor }: { userID: string; keysFor: (row: { containerID: string; keyGeneration?: number }) => KeyRef[] }) {
  const [links, setLinks] = useState<Labelled[] | undefined>();
  const [error, setError] = useState("");
  const load = () => listShareLinks()
    .then((list) => Promise.all(list.map(async (link) => ({ ...link, label: await readShareLabel(userID, link.id, keysFor) }))))
    .then((list) => { setLinks(list); setError(""); }, () => setError("Unable to load your share links."));
  useEffect(() => { void load(); }, []);
  async function revoke(link: Labelled) {
    if (!confirm(`Revoke the share link ${describe(link)}? Anyone who has it can no longer open it. This cannot be undone.`)) return;
    try {
      await revokeShareLink(link.id);
      await forgetShareLabel(userID, link.id);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Unable to revoke the link.");
    }
    await load();
  }
  return (
    <section id="share-links" className="config-card">
      <h2>Share links</h2>
      <p className="config-muted">Links you made with Share. Each holds an encrypted copy of the page as it was then, counts toward your storage and stops working when it expires (30 days at most). The server cannot read them; only the browser that made a link knows which page it shares.</p>
      {error && <p className="error" role="alert">{error}</p>}
      {links?.length === 0 && <p className="config-muted">You have no live share links.</p>}
      {links?.map((link) => (
        <div className="pin-row" key={link.id}>
          <span>{title(link)}: made {when(link.createdAt)}, expires {when(link.expiresAt)} ({Math.max(1, Math.round(link.bytes / 1024))} KB)</span>
          <button type="button" className="secondary danger" onClick={() => void revoke(link)}>Revoke</button>
        </div>
      ))}
    </section>
  );
}

const when = (iso: string) => new Date(iso).toLocaleString();
const title = ({ label }: Labelled) =>
  label === "none" ? "Made on another device" : label === "unreadable" ? "Made in this browser, page no longer readable" : `"${label.title}" in ${label.notebook}`;
const describe = (link: Labelled) => (typeof link.label === "object" ? `for "${link.label.title}"` : `made ${when(link.createdAt)}`);
